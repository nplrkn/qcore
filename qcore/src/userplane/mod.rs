mod dhcp;
mod downlink_buffer;
pub mod netlink;
mod packet_processor;
mod stats;
mod ue_ip_allocator;

//mod aya_log;
//mod freebind_socket;

pub use downlink_buffer::{DownlinkBufferController, PagingApi};
pub use packet_processor::PacketProcessor;

use anyhow::{Result, bail};
use libc::if_nametoindex;
use std::ffi::CString;

const MAX_UES: usize = 254;

pub fn get_if_index(interface_name: &str) -> Result<u32> {
    let c_str_if_name = CString::new(interface_name)?;
    let c_if_name = c_str_if_name.as_ptr();
    let if_index = unsafe { if_nametoindex(c_if_name) };
    if if_index == 0 {
        bail!(
            "Interface {} does not exist - did you run the setup-routing script?",
            interface_name
        )
    }
    Ok(if_index)
}
