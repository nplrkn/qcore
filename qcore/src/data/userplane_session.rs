use crate::data::PdcpSequenceNumberLength;
use std::net::IpAddr;
use xxap::{GtpTeid, GtpTunnel};

#[derive(Debug)]
pub struct UserplaneSession {
    pub qfi: u8,
    pub five_qi: u8,
    pub uplink_gtp_teid: GtpTeid,
    pub remote_tunnel_info: Option<GtpTunnel>,
    pub ue_ip_addr: IpAddr,
    pub pdcp_sn_length: PdcpSequenceNumberLength,
}

impl std::fmt::Display for UserplaneSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{:08}", self.ue_ip_addr, self.uplink_gtp_teid)
    }
}
