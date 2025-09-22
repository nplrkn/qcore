use crate::data::PdcpSequenceNumberLength;
use std::net::Ipv4Addr;
use xxap::{GtpTeid, GtpTunnel};

#[derive(Debug)]
pub struct UserplaneSession {
    pub qfi: u8,
    pub five_qi: u8,
    pub uplink_gtp_teid: GtpTeid,
    pub remote_tunnel_info: Option<GtpTunnel>,
    pub payload: Payload,
    pub pdcp_sn_length: PdcpSequenceNumberLength,
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Ipv4SessionParams {
    pub ue_ip_addr: Ipv4Addr,
}

#[derive(Debug)]
pub struct EthernetSesssionParams {
    pub if_index: u32,
}

impl std::fmt::Display for UserplaneSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{:08}", self.payload, self.uplink_gtp_teid)
    }
}
