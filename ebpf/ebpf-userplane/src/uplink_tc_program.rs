use crate::globals::*;
use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use aya_log_ebpf::info;
//use aya_log_ebpf::info;

#[classifier]
pub fn tc_uplink_redirect(ctx: TcContext) -> i32 {
    unsafe {
        let meta = (*ctx.skb.skb).data_meta as usize;

        if meta + 4 > ctx.data() {
            return TC_ACT_OK;
        }
        let meta: *const u32 = meta as *const u32;

        if (*meta) == 34759 {
            info!(&ctx, "Redirecting an uplink packet to Linux routing");
            redirect_to_linux_routing()
        } else {
            TC_ACT_OK
        }
    }
}
