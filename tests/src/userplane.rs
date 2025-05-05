#![allow(clippy::unusual_byte_groupings)]
use anyhow::Result;
use async_net::{IpAddr, SocketAddr, UdpSocket};
use async_std::future;
use pnet_packet::{ipv4::MutableIpv4Packet, udp::MutableUdpPacket};
use slog::{Logger, info};
use std::time::Duration;
use xxap::GtpTeid;

const GTPU_PORT: u16 = 2152; // TS29.281

pub struct MockUserplane {
    gtpu_socket: UdpSocket,
    logger: Logger,
}

impl MockUserplane {
    pub async fn new(local_ip: &str, logger: Logger) -> Result<Self> {
        let transport_address = format!("{}:{}", local_ip, GTPU_PORT);
        info!(logger, "Serving GTP-U on {transport_address}");
        let gtpu_socket = UdpSocket::bind(transport_address).await?;
        Ok(MockUserplane {
            gtpu_socket,
            logger,
        })
    }

    pub async fn send_f1u_data_packet(
        &self,
        remote_gtpu_ip: IpAddr,
        gtp_teid: GtpTeid,
        ipv4_udp_address_bytes: &[u8],
    ) -> Result<()> {
        let addr = SocketAddr::new(remote_gtpu_ip, GTPU_PORT);
        let gtp_teid = gtp_teid.0;
        const GTP_MESSAGE_TYPE_GPU: u8 = 255; // TS29.281, table 6.1-1

        let mut packet = vec![
            // ---- GTP header ----
            0b001_1_0_0_0_0,      // version, PT, R, E, S, PN
            GTP_MESSAGE_TYPE_GPU, // message type
            0,
            31, // length of payload
            gtp_teid[0],
            gtp_teid[1],
            gtp_teid[2],
            gtp_teid[3], // TEID
            // ---- PDCP Data PDU for DRB with 12 bit PDCP SN ----
            0b1_0_0_0_0000, // D/C, R,R,R, SN
            0b00000001,     // SN
            // ---- SDAP UPLINK DATA PDU ----
            0b1_0_000001, // D/C, R, QFI - see TS37.324
            // ---- Inner IP header ----
            0b0100_0101, // version and header length
            0x00,        // differentiated services
            0x00,
            // This is a 1-byte UDP packet, so IP length is 29 and UDP length is 9.
            29, // total length
            0x00,
            0x00, // identification
            0x00,
            0x00, // flags + fragment offset,
            0x40, // TTL = 64,
            17,   // protocol = 17 = UDP,
            0x00,
            0x00, // IP header checksum
        ];

        packet.extend_from_slice(ipv4_udp_address_bytes);
        packet.extend_from_slice(&[
            0x00, 0x09, // Length = 9
            0x00, 0x00, // Checksum
            0x42, // Data
        ]);

        let mut ipv4_packet = MutableIpv4Packet::new(&mut packet[11..31]).unwrap();
        let src = ipv4_packet.get_source();
        let dst = ipv4_packet.get_destination();
        let checksum = pnet_packet::ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);

        let mut udp_packet = MutableUdpPacket::new(&mut packet[31..]).unwrap();
        let checksum = pnet_packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src, &dst);
        udp_packet.set_checksum(checksum);

        info!(
            self.logger,
            "Send F1U data packet with TEID {:?}, inner UDP {}:{}->{}:{}",gtp_teid, src, udp_packet.get_source(), dst, udp_packet.get_destination();
        );

        let _bytes_sent = self.gtpu_socket.send_to(&packet, addr).await?;
        Ok(())
    }

    pub async fn recv_data_packet(&self, _gtp_teid: &GtpTeid) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 2000];
        let future_result = self.gtpu_socket.recv_from(&mut buf);
        let (bytes_received, _source_address) =
            future::timeout(Duration::from_secs(1), future_result).await??;
        info!(self.logger, "Received GTP-U packet for UE");

        // TODO - check the TEID is as expected (at [4..8])

        // Extract and return the inner IP packet.  This is at offset 11, after
        // - an 8-byte GTP header
        // - a 2-byte PDCP header
        // - a 1-byte SDAP header
        let inner = buf[11..bytes_received].to_vec();

        Ok(inner)
    }
}
