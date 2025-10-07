use super::{Ksi, UeSecurityCapabilities};
use crate::{PduSession, nas::Tmsi};
use bincode::{Decode, Encode};
use nas::NasContext;

#[derive(Debug, Default, Decode, Encode)]
pub struct UeContext5GC {
    pub imsi: String,
    pub tmsi: Option<Tmsi>,

    // 5G Core UE context data, indexed by TMSI
    // This data is independent of the RAN context and persists when the UE is idle.
    pub kamf: [u8; 32],
    pub ksi: Ksi,
    pub pdu_sessions: Vec<PduSession>,
    pub nas: NasContext,
    pub security_capabilities: UeSecurityCapabilities,
}

impl UeContext5GC {
    pub fn reset_nas_security(&mut self) {
        // Leave ksi as it is, to ensure that it differs
        // between successive authentication requests for a given
        // TMSI.
        self.nas = NasContext::default();
        self.kamf = [0u8; 32];
        self.tmsi = None;
    }
}
