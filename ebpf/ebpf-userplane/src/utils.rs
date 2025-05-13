use aya_ebpf::{helpers::r#gen::bpf_map_lookup_elem, programs::TcContext};

#[inline(always)]
pub fn is_long_enough(ctx: &TcContext, length: usize) -> bool {
    ctx.data() + length <= ctx.data_end()
}

// Unsafe pointer lookup.  Must be preceded by a call to is_long_enough() otherwise
// the eBPF verifier will reject the program.
#[inline(always)]
pub fn ptr_at<T>(ctx: &TcContext, offset: usize) -> *mut T {
    (ctx.data() + offset) as *mut T
}

#[inline(always)]
pub unsafe fn byte_at(ctx: &TcContext, offset: usize) -> u8 {
    *ptr_at::<u8>(ctx, offset)
}

#[inline(always)]
// This avoids the Rust compiler warning from aya-rs's lookup() method.
pub unsafe fn map_lookup<T, V>(map: *mut T, k: u32) -> *mut V {
    let ptr = bpf_map_lookup_elem(map as *mut _, &k as *const _ as *const core::ffi::c_void);
    ptr as *mut V
}
