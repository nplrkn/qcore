use super::maps::{map_lookup, COUNTERS};
use ebpf_common::CounterIndex::{self};

#[inline(always)]
pub unsafe fn inc(stat_id: CounterIndex) {
    add(stat_id, 1)
}

#[inline(always)]
pub unsafe fn add(stat_id: CounterIndex, amount: u64) {
    let ptr: *mut u64 = map_lookup(&raw mut COUNTERS, stat_id as u32);
    if !ptr.is_null() {
        *ptr += amount;
    }
}
