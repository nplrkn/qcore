use core::intrinsics::{atomic_cxchg, AtomicOrdering};
use crate::counters::*;
use crate::globals::*;
use crate::headers::*;
use crate::utils::*;
use aya_ebpf::bindings::bpf_adj_room_mode::BPF_ADJ_ROOM_MAC;
use aya_ebpf::helpers::r#gen::bpf_csum_diff;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::Array;
use aya_ebpf::programs::TcContext;
//use aya_log_ebpf::info;
use ebpf_common::CounterIndex::*;
use ebpf_common::*;
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

// TODO - replace with a N3 variant that has QFI in
#[map]
static mut DL_FORWARDING_TABLE: Array<DlForwardingEntry> =
    Array::with_max_entries(FORWARDING_TABLE_SIZE, 0);

/// This classifier is attached to an Ethernet device ingress and handles downlink IPv4 packets addressed to UEs
#[classifier]
pub fn tc_downlink(ctx: TcContext) -> i32 {
    unsafe {
        inc(DlRxPkts);

        ensure!(
            is_long_enough(&ctx, EthHdr::LEN + Ipv4Hdr::LEN),
            DlInternalError
        );
        let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN);
        ensure!((*ipv4hdr).version() == 4, DlDropIpv4Header);
        let inner_ip_length = (*ipv4hdr).total_len();

        let forwarding_idx = (*ipv4hdr).dst_addr[3] as u32;
        let entry: *mut DlForwardingEntry =
            map_lookup(&raw mut DL_FORWARDING_TABLE, forwarding_idx);
        ensure!(!entry.is_null(), DlDropUnknownUe);
        let pdcp_header_length = (*entry).pdcp_header_length as u16;

        const OUTER_HEADERS_EXCL_PDCP_LEN: u16 = (Ipv4Hdr::LEN
            + UdpHdr::LEN
            + GtpHdr::LEN
            + GtpHdrOptionalFields::LEN
            + GtpExtDlUserData::LEN) as u16;

        // This is 1 byte larger than required in the case of a 12bit sequence number.
        const REQUIRED_MIN_LEN: usize =
            OUTER_HEADERS_EXCL_PDCP_LEN as usize + PdcpHdr18BitSn::LEN + EthHdr::LEN;

        let outer_header_length = OUTER_HEADERS_EXCL_PDCP_LEN + pdcp_header_length;

        ensure!(
            ctx.adjust_room(outer_header_length as i32, BPF_ADJ_ROOM_MAC, 0)
                .is_ok(),
            DlInternalError
        );

        // Get TEID and remote address.
        let teid = (*entry).teid;
        ensure!(teid != 0, DlDropUnknownUe);

        let remote_ip = (*entry).remote_gtp_addr;
        ensure!(remote_ip != 0, DlDropUnknownUe);

        // Generate sequence numbers.
        // The situation with sequence numbers is problematic because of maturity issue with the BPF tooling.
        // The correct function to use is BPF atomic_fetch_add.  But see https://github.com/aya-rs/aya/issues/1268.
        // We can sort-of get by with CAS but this requires retries in the case of contention, and means we need to use
        // 64 rather than 32 bit values.

        // Get a PDCP sequence number.
        let retries = 5;
        let seq_num_ptr: *mut u64 = (&raw mut (*entry).next_pdcp_seq_num);
        let mut pdcp_seq_num = *seq_num_ptr;
        for _ in 0..retries {
            let (swapped_value, ok) =
                atomic_cxchg::<u64, {AtomicOrdering::Relaxed},{AtomicOrdering::Relaxed}>(seq_num_ptr, pdcp_seq_num, pdcp_seq_num + 1);
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
            let (swapped_value, ok) =
                atomic_cxchg::<u64, {AtomicOrdering::Relaxed},{AtomicOrdering::Relaxed}>(seq_num_ptr, nr_seq_num, nr_seq_num + 1);
            if ok {
                break;
            }
            inc(DlSeqNumContention);
            nr_seq_num = swapped_value;
        }

        // We now need to populate the outer IP, UDP, GTP and PDCP headers.

        // Optimization: it is already memset to 0, so don't set 0s

        // Optimization: is it more efficient to fill this by writing u64 or u32?

        // Optimization: avoid repeating this test by using a single pointer to fill in all of
        // the new fields.
        ensure!(is_long_enough(&ctx, REQUIRED_MIN_LEN), DlInternalError);

        // The original Ethernet header is still in place at the start of the
        // packet, but this packet is going on out a tun device so it is going to get ignored.

        let ipv4hdr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN);
        (*ipv4hdr).set_version(4);
        (*ipv4hdr).set_ihl(5);
        (*ipv4hdr).tos = 0;
        (*ipv4hdr).set_total_len(outer_header_length + inner_ip_length);
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
        ensure!(is_long_enough(&ctx, REQUIRED_MIN_LEN), DlInternalError);
        let udphdr: *mut UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN);
        (*udphdr).set_len(inner_ip_length + outer_header_length - Ipv4Hdr::LEN as u16);
        (*udphdr).set_source(GTPU_PORT);
        (*udphdr).set_dest(GTPU_PORT);
        (*udphdr).set_check(0);

        // --- GTP header with optional fields present
        ensure!(is_long_enough(&ctx, REQUIRED_MIN_LEN), DlInternalError);
        let gtphdr: *mut GtpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN);
        (*gtphdr).byte0 = 0b001_1_0_1_0_0; // version=1, PT=1, R, E=1, S=0, PN=0
        (*gtphdr).message_type = GTP_MESSAGE_TYPE_GPDU;
        let gtp_payload_length = inner_ip_length
            + (GtpHdrOptionalFields::LEN + GtpExtDlUserData::LEN) as u16
            + pdcp_header_length;
        (*gtphdr).message_length = gtp_payload_length.to_be_bytes();
        (*gtphdr).teid = teid.to_be_bytes();
        ensure!(is_long_enough(&ctx, REQUIRED_MIN_LEN), DlInternalError);
        let gtpexthdr: *mut GtpHdrOptionalFields =
            ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpHdr::LEN);
        (*gtpexthdr).sequence_number = [0, 0];
        (*gtpexthdr).npdu_number = 0;
        // Next extension header type = 0x84 = NR RAN container (TS29.281, 5.2.1.3)
        (*gtpexthdr).next_extension_header_type = GTP_EXT_NR_RAN_CONTAINER;

        // --- GTP extension header - NR RAN Container - Downlink User Data ---
        // See TS29.281, 5.2.2.6 and TS38.425, 5.5.2.1
        ensure!(is_long_enough(&ctx, REQUIRED_MIN_LEN), DlInternalError);
        let nr_ran_container: *mut GtpExtDlUserData = ptr_at(
            &ctx,
            EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpHdr::LEN + GtpHdrOptionalFields::LEN,
        );
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
        ensure!(is_long_enough(&ctx, REQUIRED_MIN_LEN), DlInternalError);
        if pdcp_header_length == 2 {
            let pdcphdr: *mut PdcpHdr12BitSn = ptr_at(
                &ctx,
                EthHdr::LEN
                    + Ipv4Hdr::LEN
                    + UdpHdr::LEN
                    + GtpHdr::LEN
                    + GtpHdrOptionalFields::LEN
                    + GtpExtDlUserData::LEN,
            );
            (*pdcphdr).0[0] = 0b1_0_0_0_0000 | (((pdcp_seq_num & 0x0f00) >> 8) as u8); // D/C, R,R,R, SN
            (*pdcphdr).0[1] = (pdcp_seq_num & 0xff) as u8; // SN cont
        } else {
            let pdcphdr: *mut PdcpHdr18BitSn = ptr_at(
                &ctx,
                EthHdr::LEN
                    + Ipv4Hdr::LEN
                    + UdpHdr::LEN
                    + GtpHdr::LEN
                    + GtpHdrOptionalFields::LEN
                    + GtpExtDlUserData::LEN,
            );
            (*pdcphdr).0[0] = 0b1_0_0_0_0_0_00 | (((pdcp_seq_num & 0x03000) >> 16) as u8); // D/C, R,R,R,R,R, SN
            (*pdcphdr).0[1] = ((pdcp_seq_num & 0xff00) >> 8) as u8; // SN cont
            (*pdcphdr).0[2] = (pdcp_seq_num & 0xff) as u8; // SN cont
        }

        add(DlPayloadBytes, inner_ip_length as u64);

        redirect_to_linux_routing()
    }
}

#[classifier]
pub fn tc_downlink_n3(ctx: TcContext) -> i32 {
    unsafe {
        inc(DlRxPkts);

        ensure!(
            is_long_enough(&ctx, EthHdr::LEN + Ipv4Hdr::LEN),
            DlInternalError
        );
        let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN);
        ensure!((*ipv4hdr).version() == 4, DlDropIpv4Header);
        let inner_ip_length = (*ipv4hdr).total_len();

        let forwarding_idx = (*ipv4hdr).dst_addr[3] as u32;
        let entry: *mut DlForwardingEntry =
            map_lookup(&raw mut DL_FORWARDING_TABLE, forwarding_idx);
        ensure!(!entry.is_null(), DlDropUnknownUe);

        const OUTER_HEADERS_LEN: usize = Ipv4Hdr::LEN
            + UdpHdr::LEN
            + GtpHdr::LEN
            + GtpHdrOptionalFields::LEN
            + GtpExtPduSessionContainer::LEN;

        const INNER_PACKET_OFFSET: usize = EthHdr::LEN + OUTER_HEADERS_LEN;

        ensure!(
            ctx.adjust_room(OUTER_HEADERS_LEN as i32, BPF_ADJ_ROOM_MAC, 0)
                .is_ok(),
            DlInternalError
        );

        // Get TEID and remote address.
        let teid = (*entry).teid;
        ensure!(teid != 0, DlDropUnknownUe);

        let remote_ip = (*entry).remote_gtp_addr;
        ensure!(remote_ip != 0, DlDropUnknownUe);

        // We now need to populate the outer IP, UDP, GTP and PDCP headers.
        // Optimization: avoid repeating this test by using a single pointer to fill in all of
        // the new fields.
        ensure!(is_long_enough(&ctx, INNER_PACKET_OFFSET), DlInternalError);

        // The original Ethernet header is still in place at the start of the packet.

        let ipv4hdr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN);
        (*ipv4hdr).set_version(4);
        (*ipv4hdr).set_ihl(5);
        (*ipv4hdr).tos = 0;
        (*ipv4hdr).set_total_len(OUTER_HEADERS_LEN as u16 + inner_ip_length);
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
        ensure!(is_long_enough(&ctx, INNER_PACKET_OFFSET), DlInternalError);
        let udphdr: *mut UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN);
        (*udphdr).set_len(inner_ip_length + (OUTER_HEADERS_LEN - Ipv4Hdr::LEN) as u16);
        (*udphdr).set_source(GTPU_PORT);
        (*udphdr).set_dest(GTPU_PORT);
        (*udphdr).set_check(0);

        // --- GTP header with optional fields present
        ensure!(is_long_enough(&ctx, INNER_PACKET_OFFSET), DlInternalError);
        let gtphdr: *mut GtpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN);
        (*gtphdr).byte0 = 0b001_1_0_1_0_0; // version=1, PT=1, R, E=1, S=0, PN=0
        (*gtphdr).message_type = GTP_MESSAGE_TYPE_GPDU;
        let gtp_payload_length =
            inner_ip_length + (GtpHdrOptionalFields::LEN + GtpExtPduSessionContainer::LEN) as u16;
        (*gtphdr).message_length = gtp_payload_length.to_be_bytes();
        (*gtphdr).teid = teid.to_be_bytes();
        ensure!(is_long_enough(&ctx, INNER_PACKET_OFFSET), DlInternalError);
        let gtpexthdr: *mut GtpHdrOptionalFields =
            ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpHdr::LEN);
        (*gtpexthdr).sequence_number = [0, 0];
        (*gtpexthdr).npdu_number = 0;
        // Next extension header type = 0x84 = NR RAN container (TS29.281, 5.2.1.3)
        (*gtpexthdr).next_extension_header_type = GTP_EXT_PDU_SESSION_CONTAINER;

        // --- GTP extension header - Pdu Session Container ---
        ensure!(is_long_enough(&ctx, INNER_PACKET_OFFSET), DlInternalError);
        let session_container: *mut GtpExtPduSessionContainer = ptr_at(
            &ctx,
            EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN + GtpHdr::LEN + GtpHdrOptionalFields::LEN,
        );
        (*session_container).len_div_4 = (GtpExtPduSessionContainer::LEN / 4) as u8;
        (*session_container).byte1 = 0b0000_0_0_0_0; // PDU type = DL PDU SESSION INFORMATION, QMP, SNP, MSNP, Spare
        (*session_container).byte2 = 0b0_0_000001; // PPP, RQI, QFI=1,
        (*session_container).next_extension_header_type = 0;

        add(DlPayloadBytes, inner_ip_length as u64);

        redirect_to_linux_routing()
    }
}
