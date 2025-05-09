#![allow(clippy::unusual_byte_groupings)]
use super::{
    GTP_BASE_HEADER_LEN, GTP_EXTENDED_HEADER_LEN, IPV4_HEADER_LEN, MAX_UES, PDCP_HEADER_LEN,
    SDAP_HEADER_LEN,
};
use crate::userplane::GTP_MESSAGE_TYPE_GPDU;
use anyhow::Result;
use async_std::{
    fs::File,
    io::WriteExt,
    net::UdpSocket,
    sync::Mutex,
    task::{self, JoinHandle},
};
use atomic_counter::{AtomicCounter, RelaxedCounter};
use derive_deref::Deref;
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
    forwarding_table: UplinkForwardingTable,
    counters: Arc<UplinkCounters>,
}

pub mod uplink_counter_indices {
    pub const UL_RX_PKTS: usize = 0;
    pub const UL_RX_BYTES: usize = 1;
    pub const UL_DROP_TOO_SHORT: usize = 2;
    pub const UL_DROP_GTP_MESSAGE_TYPE: usize = 3;
    pub const UL_DROP_TOO_SHORT_EXT: usize = 4;
    pub const UL_DROP_PDCP_CONTROL: usize = 5;
    pub const UL_DROP_SDAP_CONTROL: usize = 6;
    pub const UL_DROP_NOT_IPV4: usize = 7;
    pub const UL_DROP_UNKNOWN_TEID_1: usize = 8;
    pub const UL_DROP_UNKNOWN_TEID_2: usize = 9;
    pub const UL_NUM_COUNTERS: usize = 10;
}
use uplink_counter_indices::*;

#[derive(Default, Deref)]
pub struct UplinkCounters([RelaxedCounter; UL_NUM_COUNTERS]);

impl UplinkPipeline {
    pub fn new(
        f1u_socket: UdpSocket,
        n6_tun_device: File,
        forwarding_table: UplinkForwardingTable,
        counters: Arc<UplinkCounters>,
    ) -> Self {
        Self {
            f1u_socket,
            n6_tun_device,
            forwarding_table,
            counters,
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
        let counters = &self.counters;
        let (bytes_read, _peer) = self.f1u_socket.recv_from(buf).await?;
        counters[UL_RX_PKTS].inc();
        counters[UL_RX_BYTES].add(bytes_read);

        if bytes_read < GTP_BASE_HEADER_LEN + PDCP_HEADER_LEN + SDAP_HEADER_LEN + IPV4_HEADER_LEN {
            counters[UL_DROP_TOO_SHORT].inc();
            return Ok(());
        }

        if buf[1] != GTP_MESSAGE_TYPE_GPDU {
            //println!("Unhandled GTP message type {:x}", buf[1]);
            counters[UL_DROP_GTP_MESSAGE_TYPE].inc();
            return Ok(());
        }

        // Check if this is an extended GTP header and set offsets accordingly.
        let mut offset;
        if buf[0] == 0x30 {
            offset = GTP_BASE_HEADER_LEN;
        } else {
            offset = GTP_EXTENDED_HEADER_LEN;
            while buf[offset - 1] != 0 {
                // There is an extension header.  Skip it.
                offset += buf[offset] as usize * 4;

                if bytes_read < offset + PDCP_HEADER_LEN + SDAP_HEADER_LEN + IPV4_HEADER_LEN {
                    counters[UL_DROP_TOO_SHORT_EXT].inc();
                    return Ok(());
                }
            }
        }

        // Get the TEID.
        let gtp_teid = &buf[4..8];
        // println!(
        //     "Packet in, length {bytes_read}, teid {:x?}, data {:x?}",
        //     gtp_teid,
        //     &buf[0..(GTP_BASE_HEADER_LEN + IPV4_HEADER_LEN)]
        // );
        //let mut offset = GTP_BASE_HEADER_LEN;

        // Then a PDCP header, which starts with the D/C bit.  TS38.323, 6.2.1.
        if (buf[offset] & 0x80) == 0 {
            // Control packet - not implemented
            counters[UL_DROP_PDCP_CONTROL].inc();
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
            counters[UL_DROP_SDAP_CONTROL].inc();
            //println!("Unhandled UL SDAP control packet");
            return Ok(());
        }
        offset += 1;

        // Next we are expecting an IPv4 header.
        if buf[offset] & 0xf0 != 0x40 {
            counters[UL_DROP_NOT_IPV4].inc();
            //println!("Not IPv4 - first byte of IP header {:x}", buf[offset]);
            return Ok(());
        }

        // Drop the packet if this is an unknown TEID
        let idx = uplink_table_index_from_gtp_teid(gtp_teid);

        // -- critical section --
        let Some(ref entry) = self.forwarding_table.0.lock().await[idx] else {
            counters[UL_DROP_UNKNOWN_TEID_1].inc();
            // TODO - update stat 'no forwarding action'
            return Ok(());
        };
        if gtp_teid != entry.local_teid {
            // TODO - update stat unknown TEID
            counters[UL_DROP_UNKNOWN_TEID_2].inc();
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
