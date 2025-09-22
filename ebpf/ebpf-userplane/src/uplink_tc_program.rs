use crate::globals::*;
use aya_ebpf::bindings::bpf_adj_room_mode::BPF_ADJ_ROOM_MAC;
use aya_ebpf::bindings::{BPF_CSUM_LEVEL_RESET, BPF_F_ADJ_ROOM_NO_CSUM_RESET, TC_ACT_OK};
use aya_ebpf::helpers::gen::bpf_skb_adjust_room;
use aya_ebpf::helpers::r#gen::{bpf_csum_level, bpf_skb_change_proto};
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
            ctx.adjust_room(1, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_NO_CSUM_RESET as u64);
            ctx.adjust_room(-1, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_NO_CSUM_RESET as u64);
            redirect_to_linux_routing()
        } else {
            TC_ACT_OK
        }
    }
}
