mod downlink_buffer;
mod netlink_route;
mod packet_processor;
mod stats;
mod ue_ip_allocator;

pub use downlink_buffer::{DownlinkBufferController, PagingApi};
pub use packet_processor::PacketProcessor;
//mod aya_log;

const MAX_UES: usize = 254;
