use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub struct Config {
    // The F1 IP address, used for both F1AP and F1-U.
    pub ip_addr: IpAddr,

    // Human readable gNB-CU name signaled in F1SetupResponse
    pub name: Option<String>,

    // PLMN
    pub plmn: [u8; 3],

    // Serving network name
    pub serving_network_name: String,

    // The SST of the one and only slice (SNSSAI).  SD is not implemented.
    pub sst: u8,

    // Test flags
    pub skip_ue_authentication_check: bool,

    // AMF IDs (AMF region / AMF set / AMF pointer)
    pub amf_ids: [u8; 3],

    // Name of the N6 tun device
    pub n6_tun_name: String,

    // /24 UE subnet.
    pub ue_subnet: Ipv4Addr,
}
