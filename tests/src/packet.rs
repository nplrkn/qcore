use std::{net::Ipv4Addr, ops::Deref};

use anyhow::{Result, ensure};
use pnet_packet::{ipv4::MutableIpv4Packet, udp::MutableUdpPacket};

/// A prependable packet buffer
pub struct Packet {
    packet: Vec<u8>,
    start: usize,
}

impl Deref for Packet {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.packet[self.start..]
    }
}

// impl AsRef<[u8]> for Packet {
//     fn as_ref(&self) -> &[u8] {
//         &self.packet[self.start..]
//     }
// }

impl Packet {
    pub fn len(&self) -> usize {
        self.packet.len() - self.start
    }
    pub fn new_ue_udp(src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr, src_port: u16, dst_port: u16) -> Self {
        let src_ip = src_ip.octets();
        let dst_ip = dst_ip.octets();
        let src_port = src_port.to_be_bytes();
        let dst_port = dst_port.to_be_bytes();
        let ipv4_udp_address_bytes = [
            src_ip[0],
            src_ip[1],
            src_ip[2],
            src_ip[3],
            dst_ip[0],
            dst_ip[1],
            dst_ip[2],
            dst_ip[3],
            src_port[0],
            src_port[1],
            dst_port[0],
            dst_port[1],
        ];

        const HEADROOM: usize = 40;
        let mut packet = vec![0u8; HEADROOM];

        packet.extend_from_slice(&[
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
        ]);

        // We are now halfway through the inner IP header.  Finish the IP header and UDP header and payload.
        packet.extend(ipv4_udp_address_bytes);
        packet.extend_from_slice(&[
            0x00, 0x09, // Length = 9
            0x00, 0x00, // Checksum
            0x42, // Data
        ]);

        let mut ipv4_packet = MutableIpv4Packet::new(&mut packet[HEADROOM..HEADROOM + 20]).unwrap();
        let src = ipv4_packet.get_source();
        let dst = ipv4_packet.get_destination();
        let checksum = pnet_packet::ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);

        let mut udp_packet = MutableUdpPacket::new(&mut packet[HEADROOM + 20..]).unwrap();
        let checksum = pnet_packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &src, &dst);
        udp_packet.set_checksum(checksum);
        Packet {
            packet,
            start: HEADROOM,
        }
    }

    pub fn prepend(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(self.start >= bytes.len(), "Insufficient headroom");
        let new_start = self.start - bytes.len();
        self.packet[new_start..self.start].copy_from_slice(bytes);
        self.start = new_start;
        Ok(())
    }
}
