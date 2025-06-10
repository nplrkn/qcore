use core::mem;

// TS29.281, 5.1
#[repr(C, packed)]
pub struct GtpHdr {
    pub byte0: u8,
    pub message_type: u8,
    pub message_length: [u8; 2],
    pub teid: [u8; 4],
}

impl GtpHdr {
    pub const LEN: usize = mem::size_of::<GtpHdr>();
    pub const GTP_VERSION_1_WITHOUT_OPTIONAL_FIELDS: u8 = 0x30;
}
#[repr(C, packed)]
pub struct GtpHdrOptionalFields {
    pub sequence_number: [u8; 2],
    pub npdu_number: u8,
    pub next_extension_header_type: u8,
}
impl GtpHdrOptionalFields {
    pub const LEN: usize = mem::size_of::<GtpHdrOptionalFields>();
}

pub const GTP_EXT_NR_RAN_CONTAINER: u8 = 0x84;

// DL USER DATA (TS38.425 - 5.5.2.1), wrapped in a GTP NR Ran Container extension header.
#[repr(C, packed)]
pub struct GtpExtDlUserData {
    pub len_div_4: u8,
    // PDU type ; spare; discard blocks; flush; report polling
    pub byte1: u8,
    // spare; request out of seq; report delivered; user data; assistance info; transmission
    pub byte2: u8,
    pub nr_seq_num: [u8; 3],
    pub pad: u8,
    pub next_extension_header_type: u8,
}
impl GtpExtDlUserData {
    pub const LEN: usize = mem::size_of::<GtpExtDlUserData>();
}

// DL DATA DELIVERY STATUS - 5.5.2.1
// This is a potentially much larger structure so this will likely
// need to be more flexible in future.
pub const GTP_EXT_DL_DATA_DELIVERY_STATUS_LEN: usize = 12;

// PDCP - TS38.323
// 6.2.2.2 - Data PDU for DRBs with 12 bits PDCP SN
#[repr(C, packed)]
pub struct PdcpHdr12BitSn(pub [u8; 2]);
impl PdcpHdr12BitSn {
    pub const LEN: usize = mem::size_of::<PdcpHdr12BitSn>();
}

// 6.2.2.3 - Data PDU for DRBs with 18 bits PDCP SN
#[repr(C, packed)]
pub struct PdcpHdr18BitSn(pub [u8; 3]);
impl PdcpHdr18BitSn {
    pub const LEN: usize = mem::size_of::<PdcpHdr18BitSn>();
}
