#![allow(clippy::unusual_byte_groupings)]
use super::{IPV4_HEADER_LEN, MAX_UES};
use crate::userplane::{GTP_HEADER_LEN, INNER_PACKET_OFFSET, GTP_MESSAGE_TYPE_GPU};
use anyhow::Result;
use async_std::{
    fs::File,
    io::WriteExt,
    net::UdpSocket,
    sync::Mutex,
    task::{self, JoinHandle},
};
use slog::{Logger, info};
use std::{net::Ipv4Addr, sync::Arc};

#[derive(Clone)]
struct UplinkForwardingRule {
    pub local_teid: [u8; 4],
}

#[derive(Clone)]
pub struct UplinkForwardingTable(Arc<Mutex<Vec<Option<UplinkForwardingRule>>>>);
impl UplinkForwardingTable {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(vec![None; MAX_UES])))
    }
    pub async fn add_rule(&self, ue_ipv4: Ipv4Addr, teid: [u8; 4]) {
        let idx = ue_ipv4.octets()[3] as usize;
        assert_eq!(uplink_table_index_from_gtp_teid(&teid), idx);
        self.0.lock().await[idx] = Some(UplinkForwardingRule { local_teid: teid });
    }
    pub async fn remove_rule(&self, teid: [u8; 4]) {
        let idx = uplink_table_index_from_gtp_teid(&teid);
        self.0.lock().await[idx] = None;
    }
}

pub struct UplinkPipeline {
    f1u_socket: UdpSocket,
    n6_tun_device: File,
    uplink_forwarding_table: UplinkForwardingTable,
}

impl UplinkPipeline {
    pub fn new(
        f1u_socket: UdpSocket,
        n6_tun_device: File,
        uplink_forwarding_table: UplinkForwardingTable,
    ) -> Self {
        Self {
            f1u_socket,
            n6_tun_device,
            uplink_forwarding_table,
        }
    }
    pub fn run(mut self, logger: Logger) -> JoinHandle<()> {
        task::spawn(async move {
            let mut buf = [0u8; 2000];
            loop {
                if let Err(e) = self.handle_next_uplink_packet(&mut buf).await {
                    info!(logger, "Exiting uplink pipeline with error {e}");
                    break;
                }
            }
        })
    }
    async fn handle_next_uplink_packet(&mut self, buf: &mut [u8; 2000]) -> Result<()> {
        let (bytes_read, _peer) = self.f1u_socket.recv_from(buf).await?;

        if bytes_read < INNER_PACKET_OFFSET + IPV4_HEADER_LEN {
            // TODO - update stat 'too short packet'
            return Ok(());
        }

        // Check that the GTP flags are as expected - meaning that there are no additional headers
        // that will invalidate the inner packet offsets we are about to use.
        if buf[0] != 0x30 || buf[1] != GTP_MESSAGE_TYPE_GPU {
            //println!("Unhandled GTP header values {:x}{:x}", buf[0], buf[1]);
            // TODO - update stat 'unhandled GTP header values'
            return Ok(());
        }

        // Get the TEID.
        let gtp_teid = &buf[4..8];
        // println!(
        //     "Packet in, length {bytes_read}, teid {:x?}, data {:x?}",
        //     gtp_teid,
        //     &buf[0..(GTP_HEADER_LEN + IPV4_HEADER_LEN)]
        // );
        let mut offset = GTP_HEADER_LEN;

        // Then a PDCP header, which starts with the D/C bit.  TS38.323, 6.2.1.
        if (buf[offset] & 0x80) == 0 {
            // Control packet - not implemented
            //println!("Unhandled UL PDCP control packet");
            return Ok(());
        }

        // This is a PDCP Data PDU for DRBs with 12 bit sequence number - TS38.323, 6.2.2.2.
        // This is a 2-byte header.
        offset += 2;

        // Next we are expecting a 1-byte UL SDAP header - TS37.624, 6.2.2.3
        // | D/C |  R  |              QFI                 |
        if (buf[offset] & 0x80) == 0 {
            // Control packet - not implemented
            //println!("Unhandled UL SDAP control packet");
            return Ok(());
        }
        offset += 1;

        // Next we are expecting an IPv4 header.
        if buf[offset] & 0xf0 != 0x40 {
            //println!("Not IPv4 - first byte of IP header {:x}", buf[offset]);
            return Ok(());
        }

        // Drop the packet if this is an unknown TEID
        let idx = uplink_table_index_from_gtp_teid(gtp_teid);

        // -- critical section --
        let Some(ref entry) = self.uplink_forwarding_table.0.lock().await[idx] else {
            // TODO - update stat 'no forwarding action'
            return Ok(());
        };
        if gtp_teid != entry.local_teid {
            // TODO - update stat unknown TEID
            return Ok(());
        }
        // TODO check source IP
        // -- end critical section --

        //println!("Output uplink inner packet to tun device from offset {offset}");

        // Skip over the GTP, SDAP and PDCP headers to get to the inner IP packet.
        let inner_ip_packet = &buf[offset..bytes_read];
        self.n6_tun_device.write(inner_ip_packet).await?;
        self.n6_tun_device.flush().await?;

        Ok(())
    }
}

fn uplink_table_index_from_gtp_teid(teid: &[u8]) -> usize {
    // TODO - for now, we just use the last byte.
    teid[3] as usize
}
