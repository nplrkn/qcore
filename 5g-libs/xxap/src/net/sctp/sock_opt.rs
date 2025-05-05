//! sock_opts - setsockops related helper functions

use super::sctp_bindings::*;
use super::try_io::try_io;
use anyhow::{anyhow, Result};
use io::Error;
use libc::setsockopt;
use std::{io, mem};

pub fn enable_sctp_heartbeat(fd: i32, interval_ms: u32) -> Result<()> {
    // SCTP_PEER_ADDR_PARAMS - heartbeat so that we rapidly detect peer failures.
    let mut sctp_paddrparams = unsafe { mem::zeroed::<sctp_paddrparams>() };
    sctp_paddrparams.spp_address.ss_family = libc::AF_INET as _;
    sctp_paddrparams.spp_hbinterval = interval_ms;
    sctp_paddrparams.spp_flags = sctp_spp_flags_SPP_HB_ENABLE;

    try_io!(
        setsockopt(
            fd,
            SOL_SCTP as _,
            SCTP_PEER_ADDR_PARAMS as _,
            &sctp_paddrparams as *const _ as _,
            mem::size_of::<sctp_paddrparams>() as _,
        ),
        "setsockopt"
    )?;
    Ok(())
}

pub fn enable_sock_opt(fd: i32, name: libc::c_int) -> Result<()> {
    let enabled = &1 as *const _ as _;
    let enabled_len = mem::size_of::<libc::c_int>() as _;
    try_io!(
        setsockopt(fd, SOL_SCTP as _, name, enabled, enabled_len),
        "setsockopt"
    )?;
    Ok(())
}
