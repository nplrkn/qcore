use crate::data::PdcpSequenceNumberLength;
use bincode::{Decode, Encode};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Decode, Encode)]
pub struct UserplaneSession {
    pub qfi: u8,
    pub five_qi: u8,
    pub uplink_gtp_teid: [u8; 4],
    pub remote_ip: Option<IpAddr>,
    pub remote_teid: Option<[u8; 4]>,
    pub payload: Payload,
    pub pdcp_sn_length: PdcpSequenceNumberLength,
}

#[derive(Debug, Encode, Decode)]
pub enum Payload {
    Ipv4(Ipv4SessionParams),
    Ethernet(EthernetSesssionParams),
}
impl std::fmt::Display for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Payload::Ipv4(params) => write!(f, "UE IP {}", params.ue_ip_addr),
            Payload::Ethernet(params) => write!(f, "ethernet interface {}", params.if_index),
        }
    }
}

#[derive(Debug, Encode, Decode)]
pub struct Ipv4SessionParams {
    pub ue_ip_addr: Ipv4Addr,
}

#[derive(Debug, Encode, Decode)]
pub struct EthernetSesssionParams {
    pub if_index: u32,
}

impl std::fmt::Display for UserplaneSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.payload, format_teid(&self.uplink_gtp_teid))
    }
}

pub fn format_teid(teid: &[u8; 4]) -> String {
    format!("{:02}{:02}{:02}{:02}", teid[0], teid[1], teid[2], teid[3])
}
