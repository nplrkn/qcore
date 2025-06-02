use crate::{NasContext, PduSession, nas::Tmsi};
use f1ap::{GnbDuUeF1apId, NrCgi};
use pdcp::PdcpTx;

#[derive(Debug)]
pub struct UeContext {
    pub key: u32,
    pub gnb_du_ue_f1ap_id: GnbDuUeF1apId,
    pub tmsi: Option<Tmsi>,
    pub kamf: [u8; 32],
    pub pdu_sessions: Vec<PduSession>,
    pub pdcp_tx: PdcpTx,
    pub nr_cgi: NrCgi,
    pub nas: NasContext,
}

impl UeContext {
    pub fn new(ue_id: u32, gnb_du_ue_f1ap_id: GnbDuUeF1apId, nr_cgi: NrCgi) -> Self {
        UeContext {
            key: ue_id,
            gnb_du_ue_f1ap_id,
            tmsi: None,
            kamf: [0u8; 32],
            pdu_sessions: vec![],
            pdcp_tx: PdcpTx::default(),
            nr_cgi,
            nas: NasContext::default(),
        }
    }
}
