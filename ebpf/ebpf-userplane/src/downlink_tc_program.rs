use crate::counters::*;
use crate::globals::*;
use crate::headers::*;
use crate::maps::map_lookup;
use crate::maps::DL_FORWARDING_TABLE;
use crate::tc_utils::*;
use aya_ebpf::bindings::bpf_adj_room_mode::BPF_ADJ_ROOM_MAC;
//use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::bindings::TC_ACT_SHOT;
use aya_ebpf::helpers::r#gen::bpf_csum_diff;
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
//use aya_log_ebpf::info;
use core::intrinsics::{atomic_cxchg, AtomicOrdering};
use ebpf_common::CounterIndex::*;
use ebpf_common::*;
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

/// This classifier is attached to an Ethernet device ingress and handles downlink IPv4 packets addressed to UEs
#[classifier]
pub fn tc_downlink_f1u(ctx: TcContext) -> i32 {
    match try_tc_downlink_f1u(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc,
    }
}

#[classifier]
pub fn tc_downlink_n3(ctx: TcContext) -> i32 {
    match try_tc_downlink_n3(ctx) {
        Ok(rc) => rc,
        Err(rc) => rc,
    }
}

// This program is installed on a UE veth and runs downstream of the XDP program.  The XDP program is responsible for
// GTP encapsulation, and this one just redirects the GTP packet to qcoretun for routing to the RAN.
#[classifier]
pub fn tc_downlink_eth_redirect(_ctx: TcContext) -> i32 {
    //info!(&ctx, "Redirecting a packet on a veth to Linux routing");
    unsafe { redirect_to_linux_routing() }
}

#[inline(always)]
fn try_tc_downlink_n3(ctx: TcContext) -> Result<i32, i32> {
    unsafe {
        //info!(&ctx, "Downlink N3 packet");
        inc(DlRxPkts);
        let inner_ip_length = (ctx.len() - EthHdr::LEN as u32) as u16;
        let entry = lookup_entry_by_dest_ip(&ctx)?;
        let teid = (*entry).teid;
        tc_ensure!(teid != 0, DlDropUnknownUe);
        let remote_ip = (*entry).remote_gtp_addr;
        tc_ensure!(remote_ip != 0, DlDropUnknownUe);

        // Pass the packet up to the controller application if requested to do so.
        if remote_ip == 0xffffffff {
            return Ok(redirect_to_controller());
        }

        push_common_outer_headers(
            &ctx,
            inner_ip_length,
            GtpExtPduSessionContainer::LEN as i32,
            remote_ip,
            teid,
            GTP_EXT_PDU_SESSION_CONTAINER,
        )?;
        add_n3_encapsulation(&ctx)?;
        add(DlPayloadBytes, inner_ip_length as u64);
        Ok(redirect_to_linux_routing())
    }
}

#[inline(always)]
pub fn try_tc_downlink_f1u(ctx: TcContext) -> Result<i32, i32> {
    unsafe {
        //info!(&ctx, "Downlink F1U packet");
        inc(DlRxPkts);
        let entry = lookup_entry_by_dest_ip(&ctx)?;
        let inner_ip_length = (ctx.len() - EthHdr::LEN as u32) as u16;

        let pdcp_header_length = (*entry).pdcp_header_length as usize;
        let teid = (*entry).teid;
        tc_ensure!(teid != 0, DlDropUnknownUe);
        let remote_ip = (*entry).remote_gtp_addr;
        tc_ensure!(remote_ip != 0, DlDropUnknownUe);
        let (pdcp_seq_num, nr_seq_num) = get_pdcp_nr_seq_nums(entry);

        push_common_outer_headers(
            &ctx,
            inner_ip_length,
            (GtpExtDlUserData::LEN + pdcp_header_length) as i32,
            remote_ip,
            teid,
            GTP_EXT_NR_RAN_CONTAINER,
        )?;

        add_f1u_encapsulation(&ctx, pdcp_seq_num, nr_seq_num, pdcp_header_length)?;
        add(DlPayloadBytes, inner_ip_length as u64);
        Ok(redirect_to_linux_routing())
    }
}

#[inline(always)]
fn get_pdcp_nr_seq_nums(entry: *mut DlForwardingEntry) -> (u64, u64) {
    unsafe {
        // The situation with sequence numbers is problematic because of maturity issue with the BPF tooling.
        // The correct function to use is BPF atomic_fetch_add.  But see https://github.com/aya-rs/aya/issues/1268.
        // We can sort-of get by with CAS but this requires retries in the case of contention, and means we need to use
        // 64 rather than 32 bit values.

        // Get a PDCP sequence number.
        let retries = 5;
        let seq_num_ptr: *mut u64 = (&raw mut (*entry).next_pdcp_seq_num);
        let mut pdcp_seq_num = *seq_num_ptr;
        for _ in 0..retries {
            let (swapped_value, ok) = atomic_cxchg::<
                u64,
                { AtomicOrdering::Relaxed },
                { AtomicOrdering::Relaxed },
            >(seq_num_ptr, pdcp_seq_num, pdcp_seq_num + 1);
            if ok {
                break;
            }
            inc(DlSeqNumContention);
            pdcp_seq_num = swapped_value;
        }

        // Get an NR sequence number.
        let seq_num_ptr: *mut u64 = (&raw mut (*entry).next_nr_seq_num);
        let mut nr_seq_num = *seq_num_ptr;
        for _ in 0..retries {
            let (swapped_value, ok) = atomic_cxchg::<
                u64,
                { AtomicOrdering::Relaxed },
                { AtomicOrdering::Relaxed },
            >(seq_num_ptr, nr_seq_num, nr_seq_num + 1);
            if ok {
                break;
            }
            inc(DlSeqNumContention);
            nr_seq_num = swapped_value;
        }
        (pdcp_seq_num, nr_seq_num)
    }
}

#[inline(always)]
fn lookup_entry_by_dest_ip(ctx: &TcContext) -> Result<*mut DlForwardingEntry, i32> {
    unsafe {
        tc_ensure!(
            is_long_enough(&ctx, EthHdr::LEN + Ipv4Hdr::LEN),
            DlInternalError
        );
        let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN);
        tc_ensure!((*ipv4hdr).version() == 4, DlDropIpv4Header);
        let forwarding_idx = (*ipv4hdr).dst_addr[3] as u32;
        let entry: *mut DlForwardingEntry =
            map_lookup(&raw mut DL_FORWARDING_TABLE, forwarding_idx);
        tc_ensure!(!entry.is_null(), DlDropUnknownUe);
        Ok(entry)
    }
}

#[inline(always)]
fn push_common_outer_headers(
    ctx: &TcContext,
    payload_length: u16,
    inner_packet_offset_from_gtp_header: i32,
    remote_ip: u32,
    teid: u32,
    next_extension_header_type: u8,
) -> Result<(), i32> {
    unsafe {
        let outer_header_length = (GTP_EXTENSION_HEADER_OFFSET - EthHdr::LEN) as i32
            + inner_packet_offset_from_gtp_header;

        tc_ensure!(
            ctx.adjust_room(outer_header_length, BPF_ADJ_ROOM_MAC, 0)
                .is_ok(),
            DlInternalError
        );

        // The original Ethernet header is still in place at the start of the packet.
        // Populate the outer IP, UDP, GTP.
        const COMMON_HEADERS_LEN: usize =
            EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpHdr::LEN + GtpHdrOptionalFields::LEN;
        tc_ensure!(is_long_enough(&ctx, COMMON_HEADERS_LEN), DlInternalError);

        let ipv4hdr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN);
        let udphdr: *mut UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN);
        let gtphdr: *mut GtpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN);
        let gtpexthdr: *mut GtpHdrOptionalFields =
            ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpHdr::LEN);

        (*ipv4hdr).set_version(4);
        (*ipv4hdr).set_ihl(5);
        (*ipv4hdr).tos = 0;
        (*ipv4hdr).set_total_len(outer_header_length as u16 + payload_length);
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
        (*udphdr).set_len(payload_length + (outer_header_length as usize - Ipv4Hdr::LEN) as u16);
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
fn add_n3_encapsulation(ctx: &TcContext) -> Result<(), i32> {
    unsafe {
        // --- GTP extension header - Pdu Session Container ---
        tc_ensure!(
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

#[inline(always)]
fn add_f1u_encapsulation(
    ctx: &TcContext,
    pdcp_seq_num: u64,
    nr_seq_num: u64,
    pdcp_header_length: usize,
) -> Result<(), i32> {
    unsafe {
        // Note 1 byte larger than required in the case of a 12bit sequence number.
        const REQUIRED_MIN_LEN: usize =
            GTP_EXTENSION_HEADER_OFFSET + GtpExtDlUserData::LEN + PdcpHdr18BitSn::LEN;

        // --- GTP extension header - NR RAN Container - Downlink User Data ---
        // See TS29.281, 5.2.2.6 and TS38.425, 5.5.2.1
        tc_ensure!(is_long_enough(&ctx, REQUIRED_MIN_LEN), DlInternalError);
        let nr_ran_container: *mut GtpExtDlUserData = ptr_at(&ctx, GTP_EXTENSION_HEADER_OFFSET);

        (*nr_ran_container).len_div_4 = (GtpExtDlUserData::LEN / 4) as u8;
        // PDU type 0 = DL User Data; spare; discard blocks; flush; report polling
        (*nr_ran_container).byte1 = 0b0000_0_0_0_0;
        // spare; request out of seq; report delivered; user data; assistance info; transmission
        (*nr_ran_container).byte2 = 0b0000_0_0_0_0;
        let nr_seq_num = (nr_seq_num as u32).to_be_bytes();
        (*nr_ran_container).nr_seq_num[0] = nr_seq_num[1];
        (*nr_ran_container).nr_seq_num[1] = nr_seq_num[2];
        (*nr_ran_container).nr_seq_num[2] = nr_seq_num[3];
        (*nr_ran_container).pad = 0;
        (*nr_ran_container).next_extension_header_type = 0;

        // Add a 2 or 3 byte PDCP header.
        tc_ensure!(is_long_enough(&ctx, REQUIRED_MIN_LEN), DlInternalError);
        if pdcp_header_length == 2 {
            let pdcphdr: *mut PdcpHdr12BitSn =
                ptr_at(&ctx, GTP_EXTENSION_HEADER_OFFSET + GtpExtDlUserData::LEN);
            (*pdcphdr).0[0] = 0b1_0_0_0_0000 | (((pdcp_seq_num & 0x0f00) >> 8) as u8); // D/C, R,R,R, SN
            (*pdcphdr).0[1] = (pdcp_seq_num & 0xff) as u8; // SN cont
        } else {
            let pdcphdr: *mut PdcpHdr18BitSn =
                ptr_at(&ctx, GTP_EXTENSION_HEADER_OFFSET + GtpExtDlUserData::LEN);
            (*pdcphdr).0[0] = 0b1_0_0_0_0_0_00 | (((pdcp_seq_num & 0x03000) >> 16) as u8); // D/C, R,R,R,R,R, SN
            (*pdcphdr).0[1] = ((pdcp_seq_num & 0xff00) >> 8) as u8; // SN cont
            (*pdcphdr).0[2] = (pdcp_seq_num & 0xff) as u8; // SN cont
        }
        Ok(())
    }
}
