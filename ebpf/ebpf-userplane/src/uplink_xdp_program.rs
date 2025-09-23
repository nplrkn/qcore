use super::xdp_utils::{byte_at, is_long_enough, ptr_at};
use crate::counters::*;
use crate::globals::*;
use crate::headers::*;
use crate::maps::{map_lookup, UL_FORWARDING_TABLE};
use aya_ebpf::bindings::xdp_action::XDP_ABORTED;
use aya_ebpf::bindings::xdp_action::XDP_DROP;
use aya_ebpf::bindings::xdp_action::XDP_PASS;
use aya_ebpf::bindings::xdp_md;
use aya_ebpf::helpers::gen::bpf_xdp_adjust_meta;
use aya_ebpf::helpers::r#gen::bpf_redirect;
use aya_ebpf::helpers::r#gen::bpf_xdp_adjust_head;
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
//use aya_log_ebpf::info;
use ebpf_common::CounterIndex::*;
use ebpf_common::*;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

pub const XDP_TO_TC_MAGIC_NUMBER: u32 = 34759;
const GTP_TEID_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + 4;

/// This classifier is attached to the interface connected to the RAN and handles incoming Ethernet packets
/// directed to QCore's GTP port.
#[xdp]
pub fn xdp_uplink_n3(ctx: XdpContext) -> u32 {
    match try_uplink_n3(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc,
    }
}

#[xdp]
pub fn xdp_uplink_f1u(ctx: XdpContext) -> u32 {
    match try_uplink_f1u(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc,
    }
}

#[inline(always)]
fn try_uplink_n3(ctx: XdpContext) -> Result<u32, u32> {
    unsafe {
        check_udp_dest_port(&ctx)?;
        //info!(&ctx, "Got a packet to the GTP port");
        let extension_header_type = parse_gtp_header(&ctx)?;
        let entry = lookup_entry(&ctx)?;
        let payload_offset = parse_gtp_ext_pdu_session_container(&ctx, extension_header_type)?;
        output_inner_packet(&ctx, payload_offset, (*entry).egress_if_index)
    }
}

#[inline(always)]
pub fn try_uplink_f1u(ctx: XdpContext) -> Result<u32, u32> {
    unsafe {
        check_udp_dest_port(&ctx)?;
        let extension_header_type = parse_gtp_header(&ctx)?;
        let entry = lookup_entry(&ctx)?;
        let offset = process_gtp_extension_headers(&ctx, extension_header_type)?;
        let payload_offset =
            process_pdcp_and_sdap_headers(&ctx, (*entry).pdcp_header_length, offset)?;
        output_inner_packet(&ctx, payload_offset, (*entry).egress_if_index)
    }
}

#[inline(always)]
fn check_udp_dest_port(ctx: &XdpContext) -> Result<(), u32> {
    unsafe {
        if !is_long_enough(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN) {
            return Err(XDP_PASS);
        }

        let ethhdr: *const EthHdr = ptr_at(ctx, 0);
        match (*ethhdr).ether_type {
            EtherType::Ipv4 => {}
            _ => return Err(XDP_PASS),
        }

        let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN);
        match (*ipv4hdr).proto {
            IpProto::Udp => {}
            _ => return Err(XDP_PASS),
        }

        if (*ipv4hdr).dst_addr != read_local_ipv4() {
            return Err(XDP_PASS);
        }

        let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN);
        if (*udphdr).dest() != GTPU_PORT {
            return Err(XDP_PASS);
        }

        // This packet was sent to us.
        inc(UlRxPkts);
    }
    Ok(())
}

#[inline(always)]
// Returns extension_header_type on success
fn parse_gtp_header(ctx: &XdpContext) -> Result<u8, u32> {
    unsafe {
        xdp_ensure!(
            is_long_enough(&ctx, GTP_EXTENSION_HEADER_OFFSET),
            UlDropTooShort
        );

        let gtphdr: *const GtpExtendedHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN);
        xdp_ensure!(
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
fn lookup_entry(ctx: &XdpContext) -> Result<*const UlForwardingEntry, u32> {
    unsafe {
        xdp_ensure!(is_long_enough(ctx, GTP_TEID_OFFSET + 3), UlDropTooShort);
        let teid_byte0 = byte_at(ctx, GTP_TEID_OFFSET + 0);
        let teid_byte1 = byte_at(ctx, GTP_TEID_OFFSET + 1);
        let teid_byte2 = byte_at(ctx, GTP_TEID_OFFSET + 2);
        let teid_byte3 = byte_at(ctx, GTP_TEID_OFFSET + 3);

        // Look up by TEID, using the least significant byte as the index into the forwarding table.
        let entry: *const UlForwardingEntry =
            map_lookup(&raw mut UL_FORWARDING_TABLE, teid_byte3 as u32);
        xdp_ensure!(!entry.is_null(), UlInternalError);

        // Optimization - use u32 operations.
        xdp_ensure!((*entry).teid_top_bytes != [0, 0, 0], UlDropUnknownTeid1);
        xdp_ensure!(
            teid_byte0 == (*entry).teid_top_bytes[0]
                && teid_byte1 == (*entry).teid_top_bytes[1]
                && teid_byte2 == (*entry).teid_top_bytes[2],
            UlDropUnknownTeid2
        );
        Ok(entry)
    }
}

#[inline(always)]
// Returns PDCP header offset, if caller should continue processing
fn process_gtp_extension_headers(
    ctx: &XdpContext,
    extension_header_type: u8,
) -> Result<usize, u32> {
    unsafe {
        const PDCP_HEADER_OFFSET: usize =
            GTP_EXTENSION_HEADER_OFFSET + GtpExtDlDataDeliveryStatus::LEN;

        if extension_header_type == 0 {
            return Ok(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpHdr::LEN);
        };

        xdp_ensure!(
            extension_header_type == GTP_EXT_NR_RAN_CONTAINER,
            UlDropUnsupportedExt
        );

        xdp_ensure!(is_long_enough(ctx, PDCP_HEADER_OFFSET), UlDropTooShort);
        let delivery_status: *const GtpExtDlDataDeliveryStatus =
            ptr_at(ctx, GTP_EXTENSION_HEADER_OFFSET);
        xdp_ensure!(
            (*delivery_status).len_div_4 == (GtpExtDlDataDeliveryStatus::LEN / 4) as u8,
            UlDropExtLength
        );
        xdp_ensure!(
            (*delivery_status).next_extension_header_type == 0,
            UlDropUnsupportedExt
        );

        // If we just reached the end of the packet, then record an status only packet and
        // drop.
        xdp_ensure!(
            is_long_enough(ctx, PDCP_HEADER_OFFSET + 1),
            UlRxStatusOnlyPkts
        );

        Ok(PDCP_HEADER_OFFSET)
    }
}

const PAYLOAD_OFFSET: usize = GTP_EXTENSION_HEADER_OFFSET + GtpExtPduSessionContainer::LEN;

#[inline(always)]
fn parse_gtp_ext_pdu_session_container(
    ctx: &XdpContext,
    extension_header_type: u8,
) -> Result<usize, u32> {
    unsafe {
        xdp_ensure!(
            extension_header_type == GTP_EXT_PDU_SESSION_CONTAINER,
            UlDropGtpExtMissing
        );

        xdp_ensure!(is_long_enough(ctx, PAYLOAD_OFFSET), UlDropTooShort);
        let session_container: *const GtpExtPduSessionContainer =
            ptr_at(ctx, GTP_EXTENSION_HEADER_OFFSET);
        xdp_ensure!(
            (*session_container).len_div_4 == (GtpExtPduSessionContainer::LEN / 4) as u8,
            UlDropExtLength
        );
        xdp_ensure!(
            (*session_container).next_extension_header_type == 0,
            UlDropUnsupportedExt
        );
        Ok(PAYLOAD_OFFSET)
    }
}

#[inline(always)]
fn process_pdcp_and_sdap_headers(
    ctx: &XdpContext,
    pdcp_header_length: u8,
    mut offset: usize,
) -> Result<usize, u32> {
    unsafe {
        xdp_ensure!(
            is_long_enough(ctx, offset + PdcpHdr18BitSn::LEN + SDAP_HEADER_LEN),
            UlDropTooShortExt
        );

        // Skip over the PDCP header. TS38.323, 6.2.1.
        // This starts with the D/C bit.  PDCP control packets are not implemented.
        xdp_ensure!(byte_at(ctx, offset) & 0x80 != 0, UlDropPdcpControl);
        if pdcp_header_length == 2 {
            offset += PdcpHdr12BitSn::LEN;
        } else {
            offset += PdcpHdr18BitSn::LEN;
        }

        // Skip over the 1-byte UL SDAP header - TS37.624, 6.2.2.3
        // | D/C |  R  |              QFI                 |
        // SDAP control packets are not implemented
        xdp_ensure!(byte_at(ctx, offset) & 0x80 != 0, UlDropSdapControl);
        offset += SDAP_HEADER_LEN;
        Ok(offset)
    }
}

#[inline(always)]
pub fn output_inner_packet(ctx: &XdpContext, mut offset: usize, if_index: u32) -> Result<u32, u32> {
    unsafe {
        // If this is an IP packet, add an empty Ethernet header just before the inner packet.
        if if_index == 0 {
            offset = offset - EthHdr::LEN;
            xdp_ensure!(is_long_enough(ctx, offset + EthHdr::LEN), UlDropTooShort);
            let ethhdr: *mut EthHdr = ptr_at(ctx, offset);
            (*ethhdr).dst_addr = [0, 0, 0, 0, 0, 0];
            (*ethhdr).src_addr = [0, 0, 0, 0, 0, 0];
            (*ethhdr).ether_type = EtherType::Ipv4;
        }

        // Advance to the start of the inner packet.
        let ret = bpf_xdp_adjust_head(ctx.ctx as *mut xdp_md, offset as i32);
        xdp_ensure!(ret == 0, UlInternalError);

        // In our bandwidth counters we distinguish between
        // - header bytes: the outer IP, UDP, GTP, and PDCP headers - i.e. the overhead that we have just
        //   stripped off
        // - payload bytes
        add(UlRxHeaderBytes, offset as u64);
        add(UlPayloadBytes, (ctx.data_end() - ctx.data()) as u64);

        // For an IP packet we redirect to qcoretun device ingress.  This is done by a simple TC program
        // (since an XDP program can only redirect to a device egress).  We add a magic
        // number to the metadata so that the TC program can identify the packet.

        // TODO: why do we need the TC program and the redirect?  Provide we disable rp filtering (and set up NAT)
        // on the ran interface, surely packet from this device will be routed by Linux?
        if if_index == 0 {
            bpf_xdp_adjust_meta(ctx.ctx as *mut xdp_md, -(size_of::<u32>() as i32));
            if ctx.metadata() + 4 > ctx.metadata_end() {
                return Err(XDP_ABORTED);
            }
            let meta: *mut u32 = ctx.metadata() as *mut u32;
            *meta = XDP_TO_TC_MAGIC_NUMBER;
            Ok(XDP_PASS)
        } else {
            Ok(bpf_redirect(if_index, 0) as u32)
        }
    }
}
