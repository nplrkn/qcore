use crate::{NasContext, PduSession, nas::Tmsi};
use f1ap::{GnbDuUeF1apId, NrCgi};
use ngap::{AmfUeNgapId, RanUeNgapId};
use pdcp::PdcpTx;

// 5G encryption and integrity capabilities in NAS format.
pub type UeSecurityCapabilities = [u8; 2];

#[derive(Debug)]
pub struct UeContext {
    pub key: u32,
    pub tmsi: Option<Tmsi>,
    pub kamf: [u8; 32],
    pub pdu_sessions: Vec<PduSession>,
    pub nr_cgi: Option<NrCgi>,
    pub nas: NasContext,
    pub ran_ue_id: u32,
    pub security_capabilities: UeSecurityCapabilities,

    // CU only data
    pub pdcp_tx: PdcpTx,
}

impl UeContext {
    pub fn new(ue_id: u32) -> Self {
        UeContext {
            key: ue_id,
            tmsi: None,
            kamf: [0u8; 32],
            pdu_sessions: vec![],
            nr_cgi: None,
            nas: NasContext::default(),
            ran_ue_id: 0,
            pdcp_tx: PdcpTx::default(),
            security_capabilities: UeSecurityCapabilities::default(),
        }
    }

    pub fn amf_ue_ngap_id(&self) -> AmfUeNgapId {
        AmfUeNgapId(self.key as u64)
    }

    pub fn gnb_du_ue_f1ap_id(&self) -> GnbDuUeF1apId {
        GnbDuUeF1apId(self.ran_ue_id)
    }
    pub fn ran_ue_ngap_id(&self) -> RanUeNgapId {
        RanUeNgapId(self.ran_ue_id)
    }
}
