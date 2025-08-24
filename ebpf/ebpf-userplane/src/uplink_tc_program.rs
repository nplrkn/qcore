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

const GTP_TEID_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + 4;

/// This classifier is attached to the interface connected to the RAN and handles incoming Ethernet packets
/// directed to QCore's F1-U GTP port.
#[classifier]
pub fn tc_uplink_f1u(ctx: TcContext) -> i32 {
    match try_tc_uplink_f1u(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc,
    }
}

/// This classifier is attached to the interface connected to the RAN and handles incoming Ethernet packets
/// directed to QCore's N3 GTP port.
#[classifier]
pub fn tc_uplink_n3(ctx: TcContext) -> i32 {
    match try_uplink_n3(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc,
    }
}

#[inline(always)]
pub fn try_tc_uplink_f1u(ctx: TcContext) -> Result<i32, i32> {
    unsafe {
        check_udp_dest_port(&ctx)?;
        let extension_header_type = parse_gtp_header(&ctx)?;
        let entry = lookup_entry(&ctx)?;
        let offset = process_gtp_extension_headers(&ctx, extension_header_type)?;
        let offset = process_pdcp_and_sdap_headers(&ctx, (*entry).pdcp_header_length, offset)?;
        output_inner_ipv4_packet(&ctx, offset)
    }
}

#[inline(always)]
fn try_uplink_n3(ctx: TcContext) -> Result<i32, i32> {
    check_udp_dest_port(&ctx)?;
    let extension_header_type = parse_gtp_header(&ctx)?;
    let _entry = lookup_entry(&ctx)?;
    let offset = parse_gtp_ext_pdu_session_container(&ctx, extension_header_type)?;
    output_inner_ipv4_packet(&ctx, offset)
}

#[inline(always)]
fn check_udp_dest_port(ctx: &TcContext) -> Result<(), i32> {
    unsafe {
        if !is_long_enough(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) {
            return Err(TC_ACT_OK);
        }

        let ethhdr: *const EthHdr = ptr_at(ctx, 0);
        match (*ethhdr).ether_type {
            EtherType::Ipv4 => {}
            _ => return Err(TC_ACT_OK),
        }

        let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN);
        match (*ipv4hdr).proto {
            IpProto::Udp => {}
            _ => return Err(TC_ACT_OK),
        }

        if (*ipv4hdr).dst_addr != read_local_ipv4() {
            return Err(TC_ACT_OK);
        }

        let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN);
        if (*udphdr).dest() != GTPU_PORT {
            return Err(TC_ACT_OK);
        }

        // This packet was sent to us.
        inc(UlRxPkts);
    }
    Ok(())
}

#[inline(always)]
// Returns extension_header_type on success
fn parse_gtp_header(ctx: &TcContext) -> Result<u8, i32> {
    unsafe {
        ensure!(
            is_long_enough(&ctx, GTP_EXTENSION_HEADER_OFFSET),
            UlDropTooShort
        );

        let gtphdr: *const GtpExtendedHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN);
        ensure!(
            (*gtphdr).base.message_type == GTP_MESSAGE_TYPE_GPDU,
            UlDropGtpMessageType
        );

        let extension_header_type =
            if (*gtphdr).base.byte0 != GtpHdr::GTP_VERSION_1_WITHOUT_OPTIONAL_FIELDS {
                (*gtphdr).optional.next_extension_header_type
            } else {
                0
            };

        Ok(extension_header_type)
    }
}

#[inline(always)]
fn lookup_entry(ctx: &TcContext) -> Result<*const UlForwardingEntry, i32> {
    unsafe {
        ensure!(is_long_enough(ctx, GTP_TEID_OFFSET + 3), UlDropTooShort);
        let teid_byte0 = byte_at(ctx, GTP_TEID_OFFSET + 0);
        let teid_byte1 = byte_at(ctx, GTP_TEID_OFFSET + 1);
        let teid_byte2 = byte_at(ctx, GTP_TEID_OFFSET + 2);
        let teid_byte3 = byte_at(ctx, GTP_TEID_OFFSET + 3);

        // Look up by TEID, using the least significant byte as the index into the forwarding table.
        let entry: *const UlForwardingEntry =
            map_lookup(&raw mut UL_FORWARDING_TABLE, teid_byte3 as u32);
        ensure!(!entry.is_null(), UlInternalError);

        // Optimization - use u32 operations.
        ensure!((*entry).teid_top_bytes != [0, 0, 0], UlDropUnknownTeid1);
        ensure!(
            teid_byte0 == (*entry).teid_top_bytes[0]
                && teid_byte1 == (*entry).teid_top_bytes[1]
                && teid_byte2 == (*entry).teid_top_bytes[2],
            UlDropUnknownTeid2
        );
        Ok(entry)
    }
}

#[inline(always)]
fn process_pdcp_and_sdap_headers(
    ctx: &TcContext,
    pdcp_header_length: u8,
    mut offset: usize,
) -> Result<usize, i32> {
    unsafe {
        ensure!(
            is_long_enough(ctx, offset + PdcpHdr18BitSn::LEN + SDAP_HEADER_LEN),
            UlDropTooShortExt
        );

        // Skip over the PDCP header. TS38.323, 6.2.1.
        // This starts with the D/C bit.  PDCP control packets are not implemented.
        ensure!(byte_at(ctx, offset) & 0x80 != 0, UlDropPdcpControl);
        if pdcp_header_length == 2 {
            offset += PdcpHdr12BitSn::LEN;
        } else {
            offset += PdcpHdr18BitSn::LEN;
        }

        // Skip over the 1-byte UL SDAP header - TS37.624, 6.2.2.3
        // | D/C |  R  |              QFI                 |
        // SDAP control packets are not implemented
        ensure!(byte_at(ctx, offset) & 0x80 != 0, UlDropSdapControl);
        offset += SDAP_HEADER_LEN;
        Ok(offset)
    }
}

#[inline(always)]
fn parse_gtp_ext_pdu_session_container(
    ctx: &TcContext,
    extension_header_type: u8,
) -> Result<usize, i32> {
    unsafe {
        const INNER_IP_OFFSET: usize = GTP_EXTENSION_HEADER_OFFSET + GtpExtPduSessionContainer::LEN;
        ensure!(
            extension_header_type == GTP_EXT_PDU_SESSION_CONTAINER,
            UlDropGtpExtMissing
        );

        ensure!(is_long_enough(ctx, INNER_IP_OFFSET), UlDropTooShort);
        let session_container: *const GtpExtPduSessionContainer =
            ptr_at(ctx, GTP_EXTENSION_HEADER_OFFSET);
        ensure!(
            (*session_container).len_div_4 == (GtpExtPduSessionContainer::LEN / 4) as u8,
            UlDropExtLength
        );
        ensure!(
            (*session_container).next_extension_header_type == 0,
            UlDropUnsupportedExt
        );
        Ok(INNER_IP_OFFSET)
    }
}

#[inline(always)]
// Returns PDCP header offset, if caller should continue processing
fn process_gtp_extension_headers(ctx: &TcContext, extension_header_type: u8) -> Result<usize, i32> {
    unsafe {
        const PDCP_HEADER_OFFSET: usize =
            GTP_EXTENSION_HEADER_OFFSET + GtpExtDlDataDeliveryStatus::LEN;

        if extension_header_type == 0 {
            return Ok(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpHdr::LEN);
        };

        ensure!(
            extension_header_type == GTP_EXT_NR_RAN_CONTAINER,
            UlDropUnsupportedExt
        );

        ensure!(is_long_enough(ctx, PDCP_HEADER_OFFSET), UlDropTooShort);
        let delivery_status: *const GtpExtDlDataDeliveryStatus =
            ptr_at(ctx, GTP_EXTENSION_HEADER_OFFSET);
        ensure!(
            (*delivery_status).len_div_4 == (GtpExtDlDataDeliveryStatus::LEN / 4) as u8,
            UlDropExtLength
        );
        ensure!(
            (*delivery_status).next_extension_header_type == 0,
            UlDropUnsupportedExt
        );

        // If we just reached the end of the packet, then record an status only packet and
        // drop.
        ensure!(
            is_long_enough(ctx, PDCP_HEADER_OFFSET + 1),
            UlRxStatusOnlyPkts
        );

        Ok(PDCP_HEADER_OFFSET)
    }
}

#[inline(always)]
pub fn output_inner_ipv4_packet(ctx: &TcContext, offset: usize) -> Result<i32, i32> {
    unsafe {
        // Inner IPv4 header.
        ensure!(
            is_long_enough(ctx, offset + Ipv4Hdr::LEN),
            UlDropTooShortExt
        );
        let inner_ip_hdr: *const Ipv4Hdr = ptr_at(&ctx, offset);
        ensure!((*inner_ip_hdr).version() == 4, UlDropNotIpv4);

        // TODO - check that inner_ip_hdr's source IP is indeed the IP of the UE.  This requires
        // the UE IP prefix to be programmed (global / map) and we can then derive the suffix
        // from the GTP TEID.

        // The packet is well formed - all clear to forward it.

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
        add(UlPayloadBytes, ctx.len() as u64 - EthHdr::LEN as u64);

        // Emit the packet as if it comes from the "ue" tun.
        // Even though this has an Ethernet header - which is wrong for an L3 interface - Linux is ok to process it
        Ok(redirect_to_linux_routing())
    }
}
