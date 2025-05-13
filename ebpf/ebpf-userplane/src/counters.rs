use super::utils::map_lookup;
use aya_ebpf::{macros::map, maps::PerCpuArray};
use ebpf_common::CounterIndex::{self, NumCounters};

#[map]
static mut COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(NumCounters as u32, 0);

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

// Drop the current packet and increment the given counter if the condition is not met.
macro_rules! ensure {
    ($cond:expr, $stat:ident) => {
        if !$cond {
            inc($stat);
            return aya_ebpf::bindings::TC_ACT_SHOT;
        }
    };
}
