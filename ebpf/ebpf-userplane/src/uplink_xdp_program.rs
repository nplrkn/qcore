use crate::counters::*;
use crate::globals::*;
use crate::headers::*;
use crate::maps::UL_FORWARDING_TABLE;
use crate::utils::map_lookup;
use aya_ebpf::bindings::xdp_action::XDP_ABORTED;
use aya_ebpf::bindings::xdp_action::XDP_PASS;
//use crate::utils::*;
use aya_ebpf::bindings::xdp_md;
use aya_ebpf::helpers::r#gen::bpf_redirect;
use aya_ebpf::helpers::r#gen::bpf_xdp_adjust_head;
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use ebpf_common::CounterIndex::*;
use ebpf_common::*;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[inline(always)]
pub fn is_long_enough(ctx: &XdpContext, length: usize) -> bool {
    ctx.data() + length <= ctx.data_end()
}

// Unsafe pointer lookup.  Must be preceded by a call to is_long_enough() otherwise
// the eBPF verifier will reject the program.
#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> *mut T {
    (ctx.data() + offset) as *mut T
}

#[inline(always)]
pub unsafe fn byte_at(ctx: &XdpContext, offset: usize) -> u8 {
    *ptr_at::<u8>(ctx, offset)
}

const GTP_TEID_OFFSET: usize = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + 4;

/// This classifier is attached to the interface connected to the RAN and handles incoming Ethernet packets
/// directed to QCore's N3 GTP port.
#[xdp]
pub fn xdp_uplink_n3(ctx: XdpContext) -> u32 {
    match try_uplink_n3(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc,
    }
}

#[inline(always)]
fn try_uplink_n3(ctx: XdpContext) -> Result<u32, u32> {
    unsafe {
        check_udp_dest_port(&ctx)?;
        info!(&ctx, "Got a packet to the port");
        let extension_header_type = parse_gtp_header(&ctx)?;
        let entry = lookup_entry(&ctx)?;
        let payload_offset = parse_gtp_ext_pdu_session_container(&ctx, extension_header_type)?;
        output_inner_ethernet_frame(&ctx, payload_offset, (*entry).egress_if_index)
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
        ensure!(
            is_long_enough(&ctx, GTP_EXTENSION_HEADER_OFFSET),
            UlDropTooShort
        );

        let gtphdr: *const GtpExtendedHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN);
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
fn lookup_entry(ctx: &XdpContext) -> Result<*const UlForwardingEntry, u32> {
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
const PAYLOAD_OFFSET: usize = GTP_EXTENSION_HEADER_OFFSET + GtpExtPduSessionContainer::LEN;

#[inline(always)]
fn parse_gtp_ext_pdu_session_container(
    ctx: &XdpContext,
    extension_header_type: u8,
) -> Result<usize, u32> {
    unsafe {
        ensure!(
            extension_header_type == GTP_EXT_PDU_SESSION_CONTAINER,
            UlDropGtpExtMissing
        );

        ensure!(is_long_enough(ctx, PAYLOAD_OFFSET), UlDropTooShort);
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
        Ok(PAYLOAD_OFFSET)
    }
}

#[inline(always)]
pub fn output_inner_ethernet_frame(
    ctx: &XdpContext,
    offset: usize,
    if_index: u32,
) -> Result<u32, u32> {
    unsafe {
        info!(ctx, "About to adjust head by {}", offset);
        // Reset the head of the packet to the start of the inner Ethernet frame.
        let ret = bpf_xdp_adjust_head(ctx.ctx as *mut xdp_md, offset as i32);

        info!(
            ctx,
            "Adjust head ret {}, now will emit to device {}", ret, if_index
        );

        // Redirect to this UE's veth device.
        Ok(bpf_redirect(if_index, 0) as u32)
    }
}
