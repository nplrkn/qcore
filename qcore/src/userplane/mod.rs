mod downlink_pipeline;
mod packet_processor;
mod uplink_pipeline;

use downlink_pipeline::{DownlinkForwardingTable, DownlinkPipeline};
use uplink_pipeline::{UplinkForwardingTable, UplinkPipeline};

pub use packet_processor::PacketProcessor;

const GTP_BASE_HEADER_LEN: usize = 8;
const GTP_EXTENDED_HEADER_LEN: usize = 12;
const GTP_EXT_HEADER_LEN_NRUP_DL_USER_DATA: usize = 8;
const PDCP_HEADER_LEN: usize = 2;
const SDAP_HEADER_LEN: usize = 1;
const IPV4_HEADER_LEN: usize = 20;

// Downlink direction - inner packet starts at offset 22
const DOWNLINK_INNER_PACKET_OFFSET: usize =
    GTP_EXTENDED_HEADER_LEN + GTP_EXT_HEADER_LEN_NRUP_DL_USER_DATA + PDCP_HEADER_LEN;

const GTP_MESSAGE_TYPE_GPDU: u8 = 255; // TS29.281, table 6.1-1
const GTPU_PORT: u16 = 2152; // TS29.281

const MAX_UES: usize = 254;
