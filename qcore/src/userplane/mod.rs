mod downlink_pipeline;
mod packet_processor;
mod uplink_pipeline;

use downlink_pipeline::{DownlinkForwardingTable, DownlinkPipeline};
use uplink_pipeline::{UplinkForwardingTable, UplinkPipeline};

pub use packet_processor::PacketProcessor;

const GTP_HEADER_LEN: usize = 8;
const SDAP_HEADER_LEN: usize = 1;
const PDCP_HEADER_LEN: usize = 2;
const IPV4_HEADER_LEN: usize = 20;
const INNER_PACKET_OFFSET: usize = GTP_HEADER_LEN + SDAP_HEADER_LEN + PDCP_HEADER_LEN;
const GTP_MESSAGE_TYPE_GPU: u8 = 255; // TS29.281, table 6.1-1
const GTPU_PORT: u16 = 2152; // TS29.281

const MAX_UES: usize = 254;
