//! sctp_association - async SCTP association

use super::Message;
use super::sctp_bindings::*;
use super::sock_opt;
use super::try_io::try_io;
use anyhow::bail;
use anyhow::{Result, anyhow};
use async_io::Async;
use async_io::Timer;
use async_stream::try_stream;
use futures_core::stream::Stream;
use futures_lite::future::FutureExt;
use io::Error;
use libc::bind;
use libc::{AF_INET, IPPROTO_SCTP, SOCK_STREAM, connect, getpeername, read, socket, socklen_t};
use os_socketaddr::OsSocketAddr;
use slog::{Logger, warn};
use std::net::SocketAddr;
use std::time::Duration;
use std::{io, mem};

/// An SCTP assocation.
// Cannot be Cloned since it is the owner of the fd.  Instead use Arc.
#[derive(Debug)]
pub struct SctpAssociation {
    pub fd: i32,
    ppid: u32,
    pub remote_address: SocketAddr,
}

impl Drop for SctpAssociation {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl SctpAssociation {
    // Establish an association as a client
    pub async fn establish(
        remote_address: SocketAddr,
        bind_addr: SocketAddr,
        ppid: u32,
        logger: &Logger,
    ) -> Result<SctpAssociation> {
        // Get a socket and immediately wrap it in an SctpAssociation to ensure it gets closed
        // properly in the drop function if something fails later in this function.
        let fd = try_io!(socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP), "socket")?;
        let assoc = SctpAssociation {
            fd,
            ppid,
            remote_address,
        };

        // Bind.  This is useful when there are multiple local addresses available to ensure that the remote
        // end of the connection sees the IP address we want it to.
        let addr: OsSocketAddr = bind_addr.into();
        try_io!(bind(fd, addr.as_ptr(), addr.len()), "bind")?;

        // Connect
        // See https://cr.yp.to/docs/connect.html.
        let async_fd = Async::new(fd)?;
        let addr: OsSocketAddr = assoc.remote_address.into();
        let rc = unsafe { connect(fd, addr.as_ptr(), addr.len()) };
        let errno = errno::errno();
        if (rc < 0) && (errno.0 != libc::EINPROGRESS) && (errno.0 != libc::EWOULDBLOCK) {
            return Err(anyhow!("connect() {:?}", errno));
        }
        async_fd
            .writable()
            .or(async {
                Timer::after(Duration::from_secs(5)).await;
                Err(std::io::ErrorKind::TimedOut.into())
            })
            .await?;
        let mut address = unsafe { std::mem::zeroed::<libc::sockaddr>() };
        let mut address_len = std::mem::size_of::<libc::sockaddr>() as socklen_t;
        let rc = unsafe { getpeername(fd, &mut address as _, &mut address_len as *mut _ as _) };
        if rc == 0 {
            assoc.set_sock_opts(logger)?;
            Ok(assoc)
        } else {
            let mut buf = [0u8; 1];
            try_io!(read(fd, &mut buf as *mut _ as _, 1), "connect")?;
            Err(anyhow!("Connect failure followed by read success")) // Unhittable
        }
    }

    pub fn from_accepted(
        fd: i32,
        ppid: u32,
        remote_address: SocketAddr,
        logger: &Logger,
    ) -> Result<SctpAssociation> {
        let assoc = SctpAssociation {
            fd,
            ppid,
            remote_address,
        };
        assoc.set_sock_opts(logger)?;
        Ok(assoc)
    }

    fn set_sock_opts(&self, logger: &Logger) -> Result<()> {
        let fd = self.fd;

        sock_opt::enable_sctp_heartbeat(fd, 1000).unwrap_or_else(|e| {
            warn!(logger, "Carrying on without heartbeat - {}", e);
        });
        // It's not clear if this socket option definitely achieves anything - RFC6458 is
        // very vague.
        // sock_opt::enable_sock_opt(fd, SCTP_NODELAY as _).unwrap_or_else(|e| {
        //     warn!(logger, "Carrying on without NODELAY - {}", e);
        // });
        sock_opt::enable_sock_opt(fd, SCTP_RECVRCVINFO as _)?;
        Ok(())
    }

    pub fn recv_msg_stream(&self) -> impl Stream<Item = Result<Message>> {
        let fd = self.fd;
        try_stream! {
            loop {
                Async::new(fd)?.readable().await?;
                let message = recv(fd)?;
                yield message;
            }
        }
    }

    pub async fn send_msg(&self, mut message: Message) -> Result<()> {
        // Wait for the socket to become writable
        //Async::new(self.fd)?.writable().await?;

        #[repr(C)]
        #[derive(Debug)]
        // A libc::cmsghdr glued onto a sctp_c_bindings::sctp_sndinfo.
        struct Sndinfo {
            pub cmsg_len: libc::size_t,
            pub cmsg_level: ::std::os::raw::c_int,
            pub cmsg_type: ::std::os::raw::c_int,
            pub snd_sid: libc::__u16,
            pub snd_flags: libc::__u16,
            pub snd_ppid: libc::__u32,
            pub snd_context: libc::__u32,
            pub snd_assoc_id: sctp_assoc_t,
        }

        let mut sndinfo = Sndinfo {
            cmsg_len: mem::size_of::<Sndinfo>(),
            cmsg_level: IPPROTO_SCTP,
            cmsg_type: sctp_cmsg_type_SCTP_SNDINFO as _,
            snd_sid: 0,
            snd_flags: 0,
            snd_ppid: self.ppid.to_be(),
            snd_context: 0,
            snd_assoc_id: 0,
        };

        let msg_iov = &mut libc::iovec {
            iov_base: message.as_mut_ptr() as _,
            iov_len: message.len(),
        };
        let msghdr = make_msghdr(&mut sndinfo, msg_iov);

        let bytes_sent = try_io!(
            libc::sendmsg(self.fd, &msghdr, libc::MSG_DONTWAIT),
            "sendmsg"
        )?;
        if bytes_sent == message.len() as isize {
            Ok(())
        } else {
            // TODO Back pressure partial send
            bail!("Partial send {} bytes of {}", bytes_sent, message.len());
        }
    }
}

fn recv(fd: i32) -> Result<Message> {
    let mut message: Message = vec![0; 1500];
    let mut iov = libc::iovec {
        iov_base: message.as_mut_ptr() as _,
        iov_len: message.len(),
    };
    let msg_iov = &mut iov;

    let mut msghdr = make_msghdr(&mut sctp_rcvinfo::default(), msg_iov);
    let bytes_received = try_io!(libc::recvmsg(fd, &mut msghdr, 0), "recvmsg")?;
    if bytes_received > 0 {
        message.resize(bytes_received as _, 0);
        Ok(message)
    } else {
        Err(anyhow!("Connection terminated"))
    }
}

fn make_msghdr<T>(msg_control: &mut T, msg_iov: &mut libc::iovec) -> libc::msghdr {
    libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov,
        msg_iovlen: 1,
        msg_control: msg_control as *mut _ as _,
        msg_controllen: mem::size_of::<T>(),
        msg_flags: 0,
    }
}
