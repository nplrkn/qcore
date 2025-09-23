use aya_ebpf::programs::XdpContext;

#[inline(always)]
pub fn is_long_enough(ctx: &XdpContext, length: usize) -> bool {
    ctx.data() + length <= ctx.data_end()
}

#[inline(always)]
pub unsafe fn byte_at(ctx: &XdpContext, offset: usize) -> u8 {
    *ptr_at::<u8>(ctx, offset)
}

// This must be preceded by a call to is_long_enough() otherwise
// the eBPF verifier will reject the program.
#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> *mut T {
    (ctx.data() + offset) as *mut T
}

macro_rules! xdp_ensure {
    ($cond:expr, $stat:ident) => {
        if !$cond {
            inc($stat);
            return Err(XDP_DROP);
        }
    };
}
