use crate::counters::*;
use crate::globals::*;
use crate::headers::*;
use crate::utils::*;
use aya_ebpf::bindings::{bpf_adj_room_mode::BPF_ADJ_ROOM_MAC, TC_ACT_OK};
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::Array;
use aya_ebpf::programs::TcContext;
//use aya_log_ebpf::info;
use ebpf_common::CounterIndex::*;
use ebpf_common::*;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[map]
static mut UL_FORWARDING_TABLE: Array<UlForwardingEntry> =
    Array::with_max_entries(FORWARDING_TABLE_SIZE, 0);

/// This classifier is attached to the lo interface and handles incoming Ethernet packets
/// directed to QCore's F1-U GTP port.
#[classifier]
pub fn tc_uplink(ctx: TcContext) -> i32 {
    unsafe {
        if !is_long_enough(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) {
            return TC_ACT_OK;
        }

        let ethhdr: *const EthHdr = ptr_at(&ctx, 0);
        match (*ethhdr).ether_type {
            EtherType::Ipv4 => {}
            _ => return TC_ACT_OK,
        }

        let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN);
        match (*ipv4hdr).proto {
            IpProto::Udp => {}
            _ => return TC_ACT_OK,
        }
        let ip_len = (*ipv4hdr).total_len();

        if (*ipv4hdr).dst_addr != read_local_ipv4() {
            return TC_ACT_OK;
        }

        let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN);
        if (*udphdr).dest() != GTPU_PORT {
            return TC_ACT_OK;
        }

        // This packet is addressed to our GTP-U port.
        inc(UlRxPkts);

        // The shortest valid packet is a DL Data Report.
        ensure!(
            is_long_enough(
                &ctx,
                EthHdr::LEN
                    + Ipv4Hdr::LEN
                    + UdpHdr::LEN
                    + GtpHdr::LEN
                    + GtpHdrOptionalFields::LEN
                    + GTP_EXT_DL_DATA_DELIVERY_STATUS_LEN
            ),
            UlDropTooShort
        );

        let mut offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;
        let gtphdr: *const GtpHdr = ptr_at(&ctx, offset);
        ensure!(
            (*gtphdr).message_type == GTP_MESSAGE_TYPE_GPDU,
            UlDropGtpMessageType
        );
        offset += GtpHdr::LEN;

        // Look up by TEID, using the least significant byte as the index into the forwarding table.
        let forwarding_idx = (*gtphdr).teid[3] as u32;
        let entry: *const UlForwardingEntry =
            map_lookup(&raw mut UL_FORWARDING_TABLE, forwarding_idx);
        ensure!(!entry.is_null(), UlInternalError);
        let pdcp_header_length = (*entry).pdcp_header_length as usize;

        // Optimization - use u32 operations.
        ensure!((*entry).teid_top_bytes != [0, 0, 0], UlDropUnknownTeid1);
        ensure!(
            (&(*gtphdr).teid)[0..3] == (*entry).teid_top_bytes,
            UlDropUnknownTeid2
        );

        // This is for a known TEID.

        if (*gtphdr).byte0 != GtpHdr::GTP_VERSION_1_WITHOUT_OPTIONAL_FIELDS {
            // Process optional fields

            // This should not be needed, but the verifier seems to have forgotten about
            // the previous check - perhaps because it reused registers in the intervening
            // code.
            ensure!(
                is_long_enough(
                    &ctx,
                    offset + GtpHdrOptionalFields::LEN + GTP_EXT_DL_DATA_DELIVERY_STATUS_LEN
                ),
                UlDropTooShort
            );

            let gtp_ext: *const GtpHdrOptionalFields = ptr_at(&ctx, offset);
            let mut extension_type = (*gtp_ext).next_extension_header_type;
            offset += GtpHdrOptionalFields::LEN;

            // We support 0 or 1 extension header of type NR RAN container and
            // length 12.
            if extension_type == GTP_EXT_NR_RAN_CONTAINER {
                ensure!(
                    byte_at(&ctx, offset) <= (GTP_EXT_DL_DATA_DELIVERY_STATUS_LEN / 4) as u8,
                    UlDropExtLength
                );

                offset += GTP_EXT_DL_DATA_DELIVERY_STATUS_LEN;
                extension_type = byte_at(&ctx, offset - 1);
            }

            // If this fails then
            // - either the first extension is not an NR RAN extension header.
            // - or there is a second extension following an NR RAN extension header.
            ensure!(extension_type == 0, UlDropUnsupportedExtension);

            // If we just reached the end of the packet, then record an status only packet and
            // drop.
            ensure!(
                u16::from_be_bytes((*gtphdr).message_length)
                    != (GtpHdrOptionalFields::LEN + GTP_EXT_DL_DATA_DELIVERY_STATUS_LEN) as u16,
                UlRxStatusOnlyPkts
            );
        }

        ensure!(
            is_long_enough(&ctx, offset + PdcpHdr18BitSn::LEN + SDAP_HEADER_LEN,),
            UlDropTooShortExt
        );

        // Now for the PDCP header, TS38.323, 6.2.1.
        // This starts with the D/C bit.  PDCP control packets are not implemented.
        ensure!(byte_at(&ctx, offset) & 0x80 != 0, UlDropPdcpControl);

        // Skip over the PDCP header.
        if pdcp_header_length == 2 {
            offset += PdcpHdr12BitSn::LEN;
        } else {
            offset += PdcpHdr18BitSn::LEN;
        }

        // 1-byte UL SDAP header - TS37.624, 6.2.2.3
        // | D/C |  R  |              QFI                 |
        // SDAP control packets are not implemented
        ensure!(byte_at(&ctx, offset) & 0x80 != 0, UlDropSdapControl);

        // Skip over the SDAP header.
        offset += SDAP_HEADER_LEN;

        // Inner IPv4 header.
        ensure!(
            is_long_enough(&ctx, offset + Ipv4Hdr::LEN,),
            UlDropTooShortExt
        );
        let inner_ip_hdr: *const Ipv4Hdr = ptr_at(&ctx, offset);
        ensure!((*inner_ip_hdr).version() == 4, UlDropNotIpv4);

        // The packet is well formed.

        // TODO - check that inner_ip_hdr's source IP is indeed the IP of the UE.  This requires
        // the UE IP prefix to be programmed (global / map) and we can then derive the suffix
        // from the GTP TEID.

        // All clear to forward this.

        // Remove the outer packet encapsulation, meaning that the original Ethernet header
        // now sits on top of the inner IP header.
        //
        // This is inefficient because it involves a memmove under the covers (bpf_skb_generic_pop())
        // as part of the guardrails that eBPF imposes on TC programs.
        let new_ethhdr_offset = (offset - EthHdr::LEN) as i32;
        let ret = ctx.adjust_room(-new_ethhdr_offset, BPF_ADJ_ROOM_MAC, 0);
        ensure!(ret.is_ok(), UlInternalError);

        // We don't need to update the Ethernet header.  This is going out a tun interface
        // and it seems Linux only looks at the L3 header part of the SKB.

        // In our bandwidth counters we distinguish between
        // - header bytes: the outer IP, UDP, GTP, and PDCP headers - i.e. the overhead that we have just
        //   stripped off
        // - payload bytes: the IP packet as sent out on N6
        add(UlRxHeaderBytes, new_ethhdr_offset as u64);
        add(UlPayloadBytes, ip_len as u64);

        // Emit the packet as if it comes from the "ue" tun.
        // Even though this has an Ethernet header - which is wrong for an L3 interface - Linux is ok to process it
        redirect_to_linux_routing()
    }
}
