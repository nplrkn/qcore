#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UlForwardingEntry {
    pub teid_top_bytes: [u8; 3],

    // PDCP header length in bytes.  Only used in F1 mode.
    // Set to 2 to use 12 bit PDCP sequence numbers
    // Set to 3 to use 18 bit PDCP sequence numbers
    pub pdcp_header_length: u8,

    // Egress interface for Ethernet userplane packets.
    pub egress_if_index: u32,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for UlForwardingEntry {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DlForwardingEntry {
    // PDCP + NR sequence numbers.  Only used in F1 mode.
    pub next_pdcp_seq_num: u64,
    pub next_nr_seq_num: u64,

    // TEID in HOST byte order
    // A zero value indicates that downlink packets should be dropped.
    // Otherwise the action depends on the remote_gtp_addr field.
    pub teid: u32,

    // Remote IP in HOST byte order
    // The value 0xffffffff means that packets should be sent up to the controller application
    // rather than forwarded, otherwise they should be GTP encapsulated and forwarded to this address
    // using the teid.
    pub remote_gtp_addr: u32,

    // PDCP header length in bytes.  Only used in F1 mode.
    // Set to 2 to use 12 bit PDCP sequence numbers
    // Set to 3 to use 18 bit PDCP sequence numbers
    pub pdcp_header_length: u8,
}

impl DlForwardingEntry {
    pub fn deactivated() -> Self {
        Self {
            teid: 0xffffffff,
            remote_gtp_addr: 0xffffffff,
            ..DlForwardingEntry::default()
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DlForwardingEntry {}

#[cfg(feature = "user")]
use strum_macros::EnumString;

// The Strum derives create a str array constant called CounterIndex::VARIANTS
#[cfg_attr(
    feature = "user",
    derive(Debug, EnumString, strum_macros::VariantNames)
)]
pub enum CounterIndex {
    // Counters from which rates are computed
    UlPayloadBytes, // IP bytes passed through from UE to N6
    DlPayloadBytes, // IP bytes passed through from N6 to UE

    // Normal counters
    UlRxPkts,           // All packets matching GTP-U address/port.
    DlRxPkts,           // All packets received on ue tun device
    UlRxHeaderBytes,    // Header (overhead) bytes from valid uplink packets.
    UlRxStatusOnlyPkts, // DL DELIVERY STATUS with no payload.

    // Problem counters
    UlDropTooShort,
    UlDropGtpMessageType,
    UlDropTooShortExt,
    UlDropExtLength,
    UlDropPdcpControl,
    UlDropSdapControl,
    UlDropNotIpv4,
    UlDropUnknownTeid1,
    UlDropUnknownTeid2,
    UlDropUnsupportedExt,
    UlDropGtpExtMissing,
    UlInternalError,

    DlDropIpv4Header,
    DlDropUnknownUe,
    DlInternalError,
    DlSeqNumContention,

    NumCounters,
}

pub const MAX_GTP_EXTENSION_HEADERS: usize = 2;
pub const SDAP_HEADER_LEN: usize = 1;
pub const GTP_MESSAGE_TYPE_GPDU: u8 = 255; // TS29.281, table 6.1-1
pub const GTPU_PORT: u16 = 2152; // TS29.281
pub const FORWARDING_TABLE_SIZE: u32 = 256;
