use aya_ebpf::macros::map;
use aya_ebpf::maps::Array;
use ebpf_common::{DlForwardingEntry, UlForwardingEntry, FORWARDING_TABLE_SIZE};

// TODO - hide this and provide ul_forwarding_table_lookup()?
// Move stuff that doesn't require TcContext or XdpContext out - e.g. lookup entry
#[map]
pub static mut UL_FORWARDING_TABLE: Array<UlForwardingEntry> =
    Array::with_max_entries(FORWARDING_TABLE_SIZE, 0);

// TODO - replace with a N3 variant that has QFI in
#[map]
pub static mut DL_FORWARDING_TABLE: Array<DlForwardingEntry> =
    Array::with_max_entries(FORWARDING_TABLE_SIZE, 0);

// This array is used to convert from an veth if index to a forwarding entry index.
const MAX_IF_INDEX: u32 = (FORWARDING_TABLE_SIZE * 2) + 100;
#[map]
pub static mut DL_ETH_IF_INDEX_LOOKUP: Array<u16> = Array::with_max_entries(MAX_IF_INDEX, 0);
