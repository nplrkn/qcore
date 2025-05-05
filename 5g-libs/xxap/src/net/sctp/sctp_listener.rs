//! sctp_listener - async listener for SCTP connections that produces SCTP associations

use super::SctpAssociation;
use super::try_io::try_io;
use anyhow::{Result, anyhow};
use async_io::Async;
use libc::{AF_INET, IPPROTO_SCTP, SOCK_STREAM, accept, bind, listen, socket};
use os_socketaddr::OsSocketAddr;
use slog::Logger;
use std::io::Error;
use std::net::SocketAddr;

pub struct Listener {
    fd: i32,
}

impl Listener {
    pub fn new(addr: SocketAddr, backlog: i32) -> Result<Self> {
        let addr: OsSocketAddr = addr.into();
        let fd = try_io!(socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP), "socket")?;
        try_io!(bind(fd, addr.as_ptr(), addr.len()), "bind")
            .and_then(|_| try_io!(listen(fd, backlog), "listen"))
            .inspect_err(|_| unsafe {
                libc::close(fd);
            })?;

        Ok(Listener { fd })
    }

    pub async fn accept(&self, ppid: u32, logger: Logger) -> Result<SctpAssociation> {
        Async::new(self.fd)?.readable().await?;
        let mut addr = OsSocketAddr::new();
        let mut len = addr.capacity();
        let assoc_fd = try_io!(accept(self.fd, addr.as_mut_ptr(), &mut len), "accept")?;
        let addr = addr.into_addr().ok_or(anyhow!("Not IPv4 or IPv6"))?;
        SctpAssociation::from_accepted(assoc_fd, ppid, addr, &logger)
    }

    pub fn close(mut self) {
        unsafe {
            libc::close(self.fd);
        };
        self.fd = -1;
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if self.fd != -1 {
            panic!("Listener dropped without being closed");
        }
    }
}
