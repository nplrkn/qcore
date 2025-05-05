use std::net::IpAddr;
use xxap::GtpTeid;

#[derive(Debug)]
pub struct UserplaneSession {
    pub qfi: u8,
    pub uplink_gtp_teid: GtpTeid,
    pub ue_ip_addr: IpAddr,
}

impl std::fmt::Display for UserplaneSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({},{})", self.uplink_gtp_teid, self.ue_ip_addr)
    }
}
