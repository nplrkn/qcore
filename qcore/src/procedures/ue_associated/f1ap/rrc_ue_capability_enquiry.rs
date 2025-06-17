use super::prelude::*;
use asn1_per::SerDes;
use f1ap::SrbId;
use rrc::{
    C1_6, CriticalExtensions33, UeCapabilityInformation, UeCapabilityInformationIEs, UlDcchMessage,
    UlDcchMessageType,
};

define_ue_procedure!(RrcUeCapabilityEnquiryProcedure);

impl<'a, A: HandlerApi> RrcUeCapabilityEnquiryProcedure<'a, A> {
    pub async fn run(mut self) -> Result<UeProcedure<'a, A>> {
        let r = crate::rrc::build::ue_capability_enquiry(1);
        self.log_message("<< Rrc UeCapabilityEnquiry");
        let response = self.rrc_request(SrbId(1), &r).await?;
        match *response {
            UlDcchMessage {
                message:
                    UlDcchMessageType::C1(C1_6::UeCapabilityInformation(UeCapabilityInformation {
                        critical_extensions:
                            CriticalExtensions33::UeCapabilityInformation(UeCapabilityInformationIEs {
                                ue_capability_rat_container_list,
                                ..
                            }),
                        ..
                    })),
            } => {
                self.log_message(">> Rrc UeCapabilityInformation");
                if let Some(capabilities) = ue_capability_rat_container_list {
                    self.ue.rat_capabilities = Some(capabilities.as_bytes()?);
                }
                Ok(self.0)
            }
            m => bail!("Expected UeCapabilityInformation, received {:?}", m),
        }
    }
}
