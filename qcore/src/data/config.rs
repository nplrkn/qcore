use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
};

use asn1_per::*;
use ngap::{AmfPointer, AmfRegionId, AmfSetId};
use xxap::PlmnIdentity;

use crate::protocols::nas::AmfIds;

#[derive(Debug, Clone)]
pub struct Config {
    // The F1 IP address, used for both F1AP and F1-U.
    pub ip_addr: IpAddr,

    // Human readable gNB-CU name signaled in F1SetupResponse
    pub name: Option<String>,

    // PLMN
    pub plmn: PlmnIdentity,

    // Serving network name
    pub serving_network_name: String,

    // The SST of the one and only slice (SNSSAI).  SD is not implemented.
    pub sst: u8,

    // Test flags
    pub skip_ue_authentication_check: bool,

    // AMF IDs (AMF region / AMF set / AMF pointer)
    pub amf_ids: AmfIds,

    // Name of the F1U ethernet device
    pub ran_interface_name: String,

    // Name of the N6 ethernet device
    pub n6_interface_name: String,

    // Name of the qcore tun device
    pub tun_interface_name: String,

    // /24 UE subnet.
    pub ue_subnet: Ipv4Addr,

    // PDCP sequence number length
    pub pdcp_sn_length: PdcpSequenceNumberLength,

    // 5QI
    pub five_qi: u8,
}

#[derive(Debug, Clone, Copy)]
pub enum PdcpSequenceNumberLength {
    TwelveBits,
    EighteenBits,
}
impl Display for PdcpSequenceNumberLength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TwelveBits => write!(f, "12"),
            Self::EighteenBits => write!(f, "18"),
        }
    }
}

impl Config {
    pub fn guami(&self) -> ngap::Guami {
        let amf_id_bits: &BitSlice<u8, Msb0> = self.amf_ids.view_bits::<Msb0>();

        ngap::Guami {
            plmn_identity: self.plmn.clone(),
            amf_region_id: AmfRegionId(amf_id_bits[0..8].into()),
            amf_set_id: AmfSetId(amf_id_bits[8..18].into()),
            amf_pointer: AmfPointer(amf_id_bits[18..24].into()),
        }
    }
}
