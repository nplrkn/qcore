use aya_ebpf::programs::TcContext;

#[inline(always)]
pub fn is_long_enough(ctx: &TcContext, length: usize) -> bool {
    ctx.data() + length <= ctx.data_end()
}

// This must be preceded by a call to is_long_enough() otherwise
// the eBPF verifier will reject the program.
#[inline(always)]
pub fn ptr_at<T>(ctx: &TcContext, offset: usize) -> *mut T {
    (ctx.data() + offset) as *mut T
}

macro_rules! tc_ensure {
    ($cond:expr, $stat:ident) => {
        if !$cond {
            inc($stat);
            return Err(TC_ACT_SHOT);
        }
    };
}
