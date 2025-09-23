use crate::counters::*;
use crate::globals::*;
use crate::headers::*;
use crate::maps::{map_lookup, DL_ETH_IF_INDEX_LOOKUP, DL_FORWARDING_TABLE};
use crate::xdp_utils::*;
use aya_ebpf::bindings::xdp_action::XDP_DROP;
use aya_ebpf::bindings::xdp_action::XDP_PASS;
use aya_ebpf::bindings::xdp_md;
use aya_ebpf::helpers::r#gen::bpf_csum_diff;
use aya_ebpf::helpers::r#gen::bpf_xdp_adjust_head;
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use network_types::eth::EtherType;
//use aya_log_ebpf::info;
use ebpf_common::CounterIndex::*;
use ebpf_common::*;
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[xdp]
pub fn xdp_downlink_n3_eth(ctx: XdpContext) -> u32 {
    match try_xdp_downlink_n3_eth(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc,
    }
}

#[inline(always)]
fn try_xdp_downlink_n3_eth(ctx: XdpContext) -> Result<u32, u32> {
    unsafe {
        inc(DlRxPkts);
        let payload_length = ctx.data_end() - ctx.data();

        // info!(
        //     &ctx,
        //     "Eth frame in on if index {}",
        //     (*ctx.ctx).ingress_ifindex
        // );
        let forwarding_idx: *mut u16 =
            map_lookup(&raw mut DL_ETH_IF_INDEX_LOOKUP, (*ctx.ctx).ingress_ifindex);
        xdp_ensure!(!forwarding_idx.is_null(), DlDropUnknownUe);

        //info!(&ctx, "Maps to forwarding index {}", *forwarding_idx);
        let entry: *mut DlForwardingEntry =
            map_lookup(&raw mut DL_FORWARDING_TABLE, *forwarding_idx as u32);
        xdp_ensure!(!entry.is_null(), DlDropUnknownUe);

        let teid = (*entry).teid;
        xdp_ensure!(teid != 0, DlDropUnknownUe);
        let remote_ip = (*entry).remote_gtp_addr;
        xdp_ensure!(remote_ip != 0, DlDropUnknownUe);

        // TODO: Ethernet downlink buffering / paging not currently supported

        // Pass the packet up to the controller application if requested to do so.
        // if remote_ip == 0xffffffff {
        //     return Ok(redirect_to_controller());
        // }

        push_common_outer_headers(
            &ctx,
            payload_length as u16,
            GtpExtPduSessionContainer::LEN as i32,
            remote_ip,
            teid,
            GTP_EXT_PDU_SESSION_CONTAINER,
        )?;
        add_n3_encapsulation(&ctx)?;
        add(DlPayloadBytes, payload_length as u64);

        Ok(XDP_PASS)
    }
}

#[inline(always)]
fn push_common_outer_headers(
    ctx: &XdpContext,
    payload_length: u16,
    inner_packet_offset_from_gtp_header: i32,
    remote_ip: u32,
    teid: u32,
    next_extension_header_type: u8,
) -> Result<(), u32> {
    unsafe {
        let outer_header_length =
            GTP_EXTENSION_HEADER_OFFSET as i32 + inner_packet_offset_from_gtp_header;

        let ret = bpf_xdp_adjust_head(ctx.ctx as *mut xdp_md, -outer_header_length as i32);
        xdp_ensure!(ret == 0, DlInternalError);

        // Populate the outer Ethernet, IP, UDP, GTP.
        const COMMON_HEADERS_LEN: usize =
            EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpHdr::LEN + GtpHdrOptionalFields::LEN;
        xdp_ensure!(is_long_enough(&ctx, COMMON_HEADERS_LEN), DlInternalError);

        let ethhdr: *mut EthHdr = ptr_at(&ctx, 0);
        let ipv4hdr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN);
        let udphdr: *mut UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN);
        let gtphdr: *mut GtpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN);
        let gtpexthdr: *mut GtpHdrOptionalFields =
            ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpHdr::LEN);

        // We can zero the addresses, as Linux will regenerate them on forward.
        (*ethhdr).dst_addr = [0, 0, 0, 0, 0, 0];
        (*ethhdr).src_addr = [0, 0, 0, 0, 0, 0];
        (*ethhdr).ether_type = EtherType::Ipv4;

        (*ipv4hdr).set_version(4);
        (*ipv4hdr).set_ihl(5);
        (*ipv4hdr).tos = 0;
        (*ipv4hdr)
            .set_total_len((outer_header_length as usize - EthHdr::LEN) as u16 + payload_length);
        (*ipv4hdr).set_id(0);
        (*ipv4hdr).frag_off = [0, 0];
        (*ipv4hdr).ttl = 64;
        (*ipv4hdr).proto = IpProto::Udp;
        (*ipv4hdr).check = [0, 0];
        (*ipv4hdr).src_addr = read_local_ipv4();
        (*ipv4hdr).dst_addr = remote_ip.to_be_bytes();

        // Do the IP checksum.
        // Optimization: the only thing that varies is the length.  We can precompute the rest
        // of the checksum in a global.
        let x = bpf_csum_diff(
            0 as *mut u32,
            0,
            ipv4hdr as *mut u32,
            Ipv4Hdr::LEN as u32,
            0,
        );

        let csum = (x & 0xffff) + (x >> 16);
        let csum = (csum & 0xffff) + (csum >> 16);
        let csum = !(csum as u16);

        // The checksum was calculated without running `ntohs` on each u16, so equally the result
        // doesn't need `htons` to be called on it.  In Rust terms that means we want a 'native enddianness'
        // u16->byte conversion.
        (*ipv4hdr).check = csum.to_ne_bytes();

        // UDP header
        (*udphdr).set_len(
            payload_length + (outer_header_length as usize - Ipv4Hdr::LEN - EthHdr::LEN) as u16,
        );
        (*udphdr).set_source(GTPU_PORT);
        (*udphdr).set_dest(GTPU_PORT);
        (*udphdr).set_check(0);

        // --- GTP header with optional fields present
        (*gtphdr).byte0 = 0b001_1_0_1_0_0; // version=1, PT=1, R, E=1, S=0, PN=0
        (*gtphdr).message_type = GTP_MESSAGE_TYPE_GPDU;
        let gtp_payload_length = payload_length
            + GtpHdrOptionalFields::LEN as u16
            + inner_packet_offset_from_gtp_header as u16;
        (*gtphdr).message_length = gtp_payload_length.to_be_bytes();
        (*gtphdr).teid = teid.to_be_bytes();
        (*gtpexthdr).sequence_number = [0, 0];
        (*gtpexthdr).npdu_number = 0;
        // Next extension header type = 0x84 = NR RAN container (TS29.281, 5.2.1.3)
        (*gtpexthdr).next_extension_header_type = next_extension_header_type;

        Ok(())
    }
}

#[inline(always)]
fn add_n3_encapsulation(ctx: &XdpContext) -> Result<(), u32> {
    unsafe {
        // --- GTP extension header - Pdu Session Container ---
        xdp_ensure!(
            is_long_enough(
                &ctx,
                GTP_EXTENSION_HEADER_OFFSET + GtpExtPduSessionContainer::LEN
            ),
            DlInternalError
        );
        let session_container: *mut GtpExtPduSessionContainer =
            ptr_at(&ctx, GTP_EXTENSION_HEADER_OFFSET);
        (*session_container).len_div_4 = (GtpExtPduSessionContainer::LEN / 4) as u8;
        (*session_container).byte1 = 0b0000_0_0_0_0; // PDU type = DL PDU SESSION INFORMATION, QMP, SNP, MSNP, Spare
        (*session_container).byte2 = 0b0_0_000001; // PPP, RQI, QFI=1,
        (*session_container).next_extension_header_type = 0;
        Ok(())
    }
}
