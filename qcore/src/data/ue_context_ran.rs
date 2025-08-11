use f1ap::GnbDuUeF1apId;
use ngap::{AmfUeNgapId, RanUeNgapId};
use xxap::NrCgi;

#[derive(Debug, Default)]
pub struct UeContextRan {
    // RAN UE context data, indexed by the local_ran_ue_id = NGAP AMF UE ID or F1AP CU UE ID as appropriate
    // This data is tied to the RAN channel and only exists when the UE is connected.
    pub local_ran_ue_id: u32,
    pub remote_ran_ue_id: u32,
    pub nr_cgi: Option<NrCgi>,
    pub tac: [u8; 3],

    // // CU only RAN data
    pub rat_capabilities: Option<Vec<u8>>, // ASN.1 encoded Rrc UE-CapabilityRAT-ContainerList
}

impl UeContextRan {
    pub fn new(ue_id: u32) -> Self {
        UeContextRan {
            local_ran_ue_id: ue_id,
            ..UeContextRan::default()
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
}
