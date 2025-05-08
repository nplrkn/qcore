#![allow(clippy::unusual_byte_groupings)]

use crate::userplane::{
    DOWNLINK_INNER_PACKET_OFFSET, GTP_BASE_HEADER_LEN, GTP_EXT_HEADER_LEN_NRUP_DL_USER_DATA,
};

use super::{GTP_MESSAGE_TYPE_GPU, GTPU_PORT, IPV4_HEADER_LEN, MAX_UES};
use anyhow::Result;
use async_std::{
    io::ReadExt,
    net::{IpAddr, UdpSocket},
    sync::Mutex,
    task::{self, JoinHandle},
};
use async_tun::Tun;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use xxap::GtpTunnel;

//pub type ForwardingRule = (u32, ForwardingAction);

// TODO - this could be compressed to use a 1-byte DU index to avoid heavy duplication of remote GTP address.
// Right now, IP addr is also deterministic from the table slot ID.
#[derive(Clone)]
struct DownlinkForwardingRule {
    pub remote_tunnel_info: GtpTunnel,
    pub ue_ip_addr: IpAddr,
    pub pdcp_seq_num: u16,
    pub nr_seq_num: u32,
}

// TODO - these could be converted to an atomic rather than locked structure
#[derive(Clone)]
pub struct DownlinkForwardingTable(Arc<Mutex<Vec<Option<DownlinkForwardingRule>>>>);

impl DownlinkForwardingTable {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(vec![None; MAX_UES])))
    }
    pub async fn add_rule(&self, remote_tunnel_info: GtpTunnel, ue_ipv4: Ipv4Addr) {
        let idx = downlink_table_index_from_ip(ue_ipv4);

        self.0.lock().await[idx] = Some(DownlinkForwardingRule {
            remote_tunnel_info,
            ue_ip_addr: IpAddr::V4(ue_ipv4),
            pdcp_seq_num: 0,
            nr_seq_num: 0,
        });
    }
    pub async fn remove_rule(&self, ue_ipv4: Ipv4Addr) {
        let idx = downlink_table_index_from_ip(ue_ipv4);
        self.0.lock().await[idx] = None;
    }
}

pub struct DownlinkPipeline {
    f1u_socket: UdpSocket,
    n6_tun_device: Tun,
    downlink_forwarding_table: DownlinkForwardingTable,
}

impl DownlinkPipeline {
    pub fn new(
        f1u_socket: UdpSocket,
        n6_tun_device: Tun,
        downlink_forwarding_table: DownlinkForwardingTable,
    ) -> Self {
        Self {
            f1u_socket,
            n6_tun_device,
            downlink_forwarding_table,
        }
    }

    pub fn run(self) -> JoinHandle<()> {
        task::spawn(async move {
            let mut buf = [0u8; 2000];
            while self.handle_next_downlink_packet(&mut buf).await.is_ok() {}
        })
    }

    async fn handle_next_downlink_packet(&self, buf: &mut [u8; 2000]) -> Result<()> {
        let bytes_read = self
            .n6_tun_device
            .reader()
            .read(&mut buf[DOWNLINK_INNER_PACKET_OFFSET..2000])
            .await?;

        if bytes_read < IPV4_HEADER_LEN {
            // TODO - update stat 'too short packet'
            return Ok(());
        }
        let ip_header =
            &buf[DOWNLINK_INNER_PACKET_OFFSET..DOWNLINK_INNER_PACKET_OFFSET + IPV4_HEADER_LEN];
        // TODO: check IP type
        let ue_ip_addr = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);

        let idx = downlink_table_index_from_ip(ue_ip_addr);
        //println!("Incoming packet on UE tun if with dst IP {:x?}", ue_ip_addr);

        // -- critical section --
        let Some(ref mut entry) = self.downlink_forwarding_table.0.lock().await[idx] else {
            // TODO - update stat 'no forwarding action'
            //println!("No forwarding table entry for this IP (missing index)");
            return Ok(());
        };
        if ue_ip_addr != entry.ue_ip_addr {
            // TODO - update stat 'IP mismatch'
            //println!("No forwarding table entry for this IP (addr mismatch)");
            return Ok(());
        }
        let du_ip = entry.remote_tunnel_info.transport_layer_address.clone();

        let pdcp_seq_num = entry.pdcp_seq_num;
        entry.pdcp_seq_num += 1;
        let nr_seq_num = entry.nr_seq_num;
        entry.nr_seq_num += 1;
        // -- end critical section --

        // The payload is the message length following the inital 8 byte GTP header.
        let gtp_payload_length = ((bytes_read + DOWNLINK_INNER_PACKET_OFFSET - GTP_BASE_HEADER_LEN)
            as u16)
            .to_be_bytes();
        //println!("GTP length {:x?}", gtp_payload_length);

        // Add the GTP, PDCP and SDAP headers.

        // ---- GTP header, TS29.281, 5.2.1 ----
        buf[0] = 0b001_1_0_1_0_0; // version=1, PT=1, R, E=1, S=0, PN=0
        buf[1] = GTP_MESSAGE_TYPE_GPU;
        buf[2] = gtp_payload_length[0];
        buf[3] = gtp_payload_length[1];

        // TEID
        buf[4] = entry.remote_tunnel_info.gtp_teid.0[0];
        buf[5] = entry.remote_tunnel_info.gtp_teid.0[1];
        buf[6] = entry.remote_tunnel_info.gtp_teid.0[2];
        buf[7] = entry.remote_tunnel_info.gtp_teid.0[3];

        // Since E=1 above, this is an extended GTP header with 4 extra bytes.
        // Sequence + PDU number - ignored since their bit is set to 0 above
        buf[8] = 0;
        buf[9] = 0;
        buf[10] = 0;

        // Next extension header type = 0x84 = NR RAN container (TS29.281, 5.2.1.3)
        buf[11] = 0x84;

        // --- GTP extension header - NR RAN Container - Downlink User Data ---
        // See TS29.281, 5.2.2.6 and TS38.425, 5.5.2.1

        // Extension header length / 4.  (TS29.281, 5.2.1)
        buf[12] = (GTP_EXT_HEADER_LEN_NRUP_DL_USER_DATA / 4) as u8;

        // PDU type 0; spare; discard blocks; flush; report polling
        buf[13] = 0b0000_0_0_0_0;

        // spare; request out of seq; report delivered; user data; assistance info; transmission
        buf[14] = 0b000_0_0_0_0_0;

        // 3 bytes of NR seq num
        let nr_seq_num = nr_seq_num.to_be_bytes();
        buf[15] = nr_seq_num[1];
        buf[16] = nr_seq_num[2];
        buf[17] = nr_seq_num[3];

        // Pad extension header to multiple of four bytes
        buf[18] = 0;

        // Next extension header type = None
        buf[19] = 0;

        // --- PDCP Data PDU for DRB with 12 bit PDCP SN ---
        buf[20] = 0b1_0_0_0_0000 | (((pdcp_seq_num & 0x0f00) >> 8) as u8); // D/C, R,R,R, SN
        buf[21] = (pdcp_seq_num & 0xff) as u8; // SN

        assert!(DOWNLINK_INNER_PACKET_OFFSET == 22);

        // Not supported by SRS UE
        // // ---- SDAP DOWNLINK DATA PDU ----
        // buf[23] = 0b0_0_000001; // RDI, RQI, QFI - see TS37.324

        let du_ip = IpAddr::try_from(du_ip)?;
        self.f1u_socket
            .send_to(
                &buf[0..(bytes_read + DOWNLINK_INNER_PACKET_OFFSET)],
                SocketAddr::new(du_ip, GTPU_PORT),
            )
            .await?;

        Ok(())
    }
}

fn downlink_table_index_from_ip(ue_ip: Ipv4Addr) -> usize {
    // TODO - for now, we just use the last byte of the IP address.
    let last_byte = ue_ip.octets()[3];
    last_byte as usize
}
