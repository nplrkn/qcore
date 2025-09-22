#![allow(clippy::unusual_byte_groupings)]
use anyhow::Result;
use async_net::{IpAddr, SocketAddr, UdpSocket};
use async_std::future;
use slog::{Logger, info};
use std::time::Duration;
use xxap::GtpTeid;

use crate::packet::Packet;

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

    /// Adds 8-byte GTP header and sends.  The caller is responsible for
    /// the extended bytes of the GTP header plus any GTP extension headers.
    async fn send_gtp(
        &self,
        mut pkt: Packet,
        remote_gtpu_ip: IpAddr,
        gtp_teid: &[u8; 4],
        extended: bool,
    ) -> Result<()> {
        let payload_len: [u8; 2] = (pkt.len() as u16).to_be_bytes();

        // TODO commmonize with QCore
        const GTP_MESSAGE_TYPE_GPU: u8 = 255; // TS29.281, table 6.1-1

        // version, PT, R, E, S, PN
        let byte1 = if extended {
            0b001_1_0_1_0_0
        } else {
            0b001_1_0_0_0_0
        };

        pkt.prepend(&[
            // ---- GTP header ----
            byte1,
            GTP_MESSAGE_TYPE_GPU, // message type
            payload_len[0],
            payload_len[1], // length of payload
            gtp_teid[0],
            gtp_teid[1],
            gtp_teid[2],
            gtp_teid[3], // TEID
        ])?;

        let _ = self
            .gtpu_socket
            .send_to(&pkt, SocketAddr::new(remote_gtpu_ip, GTPU_PORT))
            .await?;
        Ok(())
    }

    pub async fn send_n3_data_packet(
        &self,
        mut pkt: Packet,
        remote_gtpu_ip: IpAddr,
        gtp_teid: &[u8; 4],
    ) -> Result<()> {
        info!(
            self.logger,
            "Send N3 data packet with TEID {:08}",
            GtpTeid(*gtp_teid)
        );

        pkt.prepend(&[
            0,          // Sequence number
            0,          // Sequence number
            0,          // N-PDU number
            0b10000101, // next extension = PDU Session Container - see TS29.281, figure 5.2.1-3
            // ---- PDU session container, TS38.415 ----
            1,              // length of PDU session container = 4 bytes
            0b0001_0_0_0_0, // PDU type = UL PDU SESSION INFORMATION, QMP, DL delay, UL delay, SNP
            0b0_0_000001,   // N3 delay, new IE, QFI=1,
            0,              // next extension type = none
        ])?;

        self.send_gtp(pkt, remote_gtpu_ip, gtp_teid, true).await
    }

    pub async fn send_f1u_data_packet(
        &self,
        mut pkt: Packet,
        remote_gtpu_ip: IpAddr,
        gtp_teid: &[u8; 4],
    ) -> Result<()> {
        info!(
            self.logger,
            "Send F1U data packet with TEID {:08}",
            GtpTeid(*gtp_teid)
        );

        // Prepend the PDCP and SDAP headers using the provided headroom
        pkt.prepend(&[
            // ---- PDCP Data PDU for DRB with 12 bit PDCP SN ----
            0b1_0_0_0_0000, // D/C, R,R,R, SN
            0b00000001,     // SN
            // ---- SDAP UPLINK DATA PDU ----
            0b1_0_000001, // D/C, R, QFI - see TS37.324
        ])?;
        self.send_gtp(pkt, remote_gtpu_ip, gtp_teid, false).await
    }

    pub async fn recv_gtp(&self, _gtp_teid: &GtpTeid) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 2000];
        let future_result = self.gtpu_socket.recv_from(&mut buf);

        // The benefit of waiting 10 seconds is that it gives a chance for the stats output loop to kick in.
        let (bytes_received, _source_address) =
            future::timeout(Duration::from_secs(10), future_result).await??;
        info!(self.logger, "Received GTP-U packet for UE");

        // TODO - check the TEID is as expected (at [4..8])

        Ok(buf[0..bytes_received].to_vec())
    }
}
