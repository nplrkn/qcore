use crate::{NasContext, PduSession, nas::Tmsi};
use derive_deref::Deref;
use f1ap::GnbDuUeF1apId;
use ngap::{AmfUeNgapId, RanUeNgapId};
use pdcp::PdcpTx;
use xxap::NrCgi;

// 5G encryption and integrity capabilities in NAS format.
pub type UeSecurityCapabilities = [u8; 2];

#[derive(Debug, Deref)]
pub struct Ksi(pub u8);
impl Default for Ksi {
    fn default() -> Self {
        Self(Self::MAX_VALUE)
    }
}
impl Ksi {
    const MAX_VALUE: u8 = 6;
    pub fn inc(&mut self) {
        self.0 = (self.0 + 1) % 7
    }
}

#[derive(Debug, Default)]
pub struct UeContext5GC {
    // 5G Core UE context data, indexed by TMSI
    // This data is independent of the RAN context and persists when the UE is idle.
    pub kamf: [u8; 32],
    pub ksi: Ksi,
    pub pdu_sessions: Vec<PduSession>,
    pub nas: NasContext,
    pub security_capabilities: UeSecurityCapabilities,
    pub tac: [u8; 3],
}

#[derive(Debug, Default)]
pub struct UeContext {
    pub tmsi: Option<Tmsi>,
    pub core: UeContext5GC,

    // RAN UE context data, indexed by the local_ran_ue_id = NGAP AMF UE ID or F1AP CU UE ID as appropriate
    // This data is tied to the RAN channel and only exists when the UE is connected.
    pub local_ran_ue_id: u32,
    pub remote_ran_ue_id: u32,
    pub nr_cgi: Option<NrCgi>,

    // CU only RAN data
    pub pdcp_tx: PdcpTx,
    pub rat_capabilities: Option<Vec<u8>>, // ASN.1 encoded Rrc UE-CapabilityRAT-ContainerList
}

impl UeContext {
    pub fn new(ue_id: u32) -> Self {
        UeContext {
            local_ran_ue_id: ue_id,
            ..UeContext::default()
        }
    }

    pub fn amf_ue_ngap_id(&self) -> AmfUeNgapId {
        AmfUeNgapId(self.local_ran_ue_id as u64)
    }

    pub fn gnb_du_ue_f1ap_id(&self) -> GnbDuUeF1apId {
        GnbDuUeF1apId(self.remote_ran_ue_id)
    }
    pub fn ran_ue_ngap_id(&self) -> RanUeNgapId {
        RanUeNgapId(self.remote_ran_ue_id)
    }

    pub fn reset_nas_security(&mut self) {
        // Leave ksi as it is, to ensure that it differs
        // between successive authentication requests for a given
        // TMSI.
        self.core.nas = NasContext::default();
        self.core.kamf = [0u8; 32];
        self.tmsi = None;
    }
}
