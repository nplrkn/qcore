// This file is not currently used but kept around as a reference just in case.
// It shows how to get a UDP IP_FREEBIND socket.  This might be an option for
// intercepting packets sent to UEs (e.g. DHCP).
//
// Initial testing with the eBPF downlink program set to return ACT_TC_OK for the packets
// of interest showed the kernel dropping these packets because they were labelled with
// OTHERHOST.  To fix this it might work to use bpf_skb_change_type().

use anyhow::{Result, anyhow};
use libc::{AF_INET, IP_FREEBIND, IPPROTO_UDP, SOCK_DGRAM, SOL_IP, bind, setsockopt, socket};
use os_socketaddr::OsSocketAddr;
use smol::net::UdpSocket;
use std::{
    io::Error,
    mem,
    net::SocketAddr,
    os::fd::{FromRawFd, OwnedFd},
};

macro_rules! try_io {
    ( $x:expr, $operation_name:expr  ) => {{
        let rc = unsafe { $x };
        if rc < 0 {
            Err(anyhow!(format!(
                "{} during {}",
                Error::last_os_error(),
                $operation_name
            )))
        } else {
            Ok(rc)
        }
    }};
}

pub fn new_freebind_udp_socket(bind_addr: SocketAddr) -> Result<UdpSocket> {
    let fd = try_io!(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), "socket")?;
    let addr: OsSocketAddr = bind_addr.into();
    try_io!(
        setsockopt(
            fd,
            SOL_IP as _,
            IP_FREEBIND,
            &1 as *const _ as _,
            mem::size_of::<libc::c_int>() as _
        ),
        "setsockopt"
    )?;

    try_io!(bind(fd, addr.as_ptr(), addr.len()), "bind")?;

    let rust_socket = unsafe {
        let fd = OwnedFd::from_raw_fd(fd);
        UdpSocket::try_from(fd)
    }?;
    Ok(rust_socket)
}
