use aya_ebpf::maps::Array;
use aya_ebpf::maps::PerCpuArray;
use aya_ebpf::{helpers::r#gen::bpf_map_lookup_elem, macros::map};
use ebpf_common::CounterIndex::NumCounters;
use ebpf_common::{DlForwardingEntry, UlForwardingEntry, FORWARDING_TABLE_SIZE};

#[inline(always)]
// This avoids the Rust compiler warning from aya-rs's lookup() method.
pub unsafe fn map_lookup<T, V>(map: *mut T, k: u32) -> *mut V {
    let ptr = bpf_map_lookup_elem(map as *mut _, &k as *const _ as *const core::ffi::c_void);
    ptr as *mut V
}

#[map]
pub static mut COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(NumCounters as u32, 0);

#[map]
pub static mut UL_FORWARDING_TABLE: Array<UlForwardingEntry> =
    Array::with_max_entries(FORWARDING_TABLE_SIZE, 0);

#[map]
pub static mut DL_FORWARDING_TABLE: Array<DlForwardingEntry> =
    Array::with_max_entries(FORWARDING_TABLE_SIZE, 0);

// Convert from an veth if index to a forwarding entry index.
const MAX_IF_INDEX: u32 = (FORWARDING_TABLE_SIZE * 2) + 100;
#[map]
pub static mut DL_ETH_IF_INDEX_LOOKUP: Array<u16> = Array::with_max_entries(MAX_IF_INDEX, 0);
