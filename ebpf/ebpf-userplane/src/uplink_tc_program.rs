use crate::globals::*;
use crate::uplink_xdp_program::XDP_TO_TC_MAGIC_NUMBER;
use aya_ebpf::bindings::bpf_adj_room_mode::BPF_ADJ_ROOM_MAC;
use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
//use aya_log_ebpf::info;

#[classifier]
pub fn tc_uplink_redirect(ctx: TcContext) -> i32 {
    unsafe {
        // Look for the magic number which indicates that our XDP program has acted on this packet.
        let meta = (*ctx.skb.skb).data_meta as usize;
        if meta + size_of::<u32>() > ctx.data() {
            return TC_ACT_OK;
        }
        if *(meta as *const u32) == XDP_TO_TC_MAGIC_NUMBER {
            //info!(&ctx, "Redirecting an uplink packet to Linux routing");

            // Work around kernel BUG "offset (-5) >= skb_headlen() (43)" at line
            // https://elixir.bootlin.com/linux/v6.6.87/source/net/core/dev.c#L3351.
            //
            // It is presumably caused by the call to bpf_xdp_adjust_head() that has
            // the effect of moving the original checksum location before the start
            // of the packet, in combination with driver checksum offload.
            //
            // Since -5 is not in fact >= 43, is this a C signed / unsigned comparison bug?
            //
            // The point of the workaround is to invalidate the checksum offload fields.  The
            // only way I have found to do this is via the two calls below, but perhaps there
            // is a better way.  An XDP program does not appear to let you touch this part of the
            // packet buffer or invalidate the hardware checksum.  These calls trigger some
            // needless memmoves.
            //
            // The relevant code that invalidates the checksum is probably skb_postpull_rcsum().
            // Experimentation with BPF_F_ADJ_ROOM_NO_CSUM_RESET indicated that
            // __skb_reset_checksum_unnecessary(skb) is not relevant.
            let _ = ctx.adjust_room(1, BPF_ADJ_ROOM_MAC, 0);
            let _ = ctx.adjust_room(-1, BPF_ADJ_ROOM_MAC, 0);
            redirect_to_linux_routing()
        } else {
            TC_ACT_OK
        }
    }
}
