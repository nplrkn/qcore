mod downlink_buffer;
mod packet_processor;
mod stats;
pub use downlink_buffer::{DownlinkBufferController, PagingApi};
pub use packet_processor::PacketProcessor;
//mod aya_log;

const MAX_UES: usize = 254;
