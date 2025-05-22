use super::nas_context::NasContext;
use crate::PduSession;
use f1ap::{GnbDuUeF1apId, NrCgi};
use pdcp::PdcpTx;

#[derive(Debug)]
pub struct UeContext {
    pub key: u32,
    pub gnb_du_ue_f1ap_id: GnbDuUeF1apId,
    pub sqn: [u8; 6],
    pub tmsi: [u8; 4],
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
            sqn: [0u8; 6],
            tmsi: rand::random(), // TODO: 0xffffffff is not a valid TMSI (TS23.003, 2.4)
            pdu_sessions: vec![],
            pdcp_tx: PdcpTx::default(),
            nr_cgi,
            nas: NasContext::default(),
        }
    }
    pub fn inc_sqn(&mut self) {
        let mut scratch = [0u8; 8];
        scratch[2..8].clone_from_slice(&self.sqn);
        let mut s = u64::from_be_bytes(scratch);
        s += 1;
        let scratch = s.to_be_bytes();
        self.sqn.clone_from_slice(&scratch[2..8]);
    }
}
