mod rrc_security_mode;
mod rrc_setup;
mod ue_context_release;
mod ul_information_transfer;
use asn1_per::SerDes;
use rrc::UlDcchMessage;
pub use rrc_security_mode::RrcSecurityModeProcedure;
pub use rrc_setup::RrcSetupProcedure;
pub use ue_context_release::UeContextReleaseProcedure;
pub use ul_information_transfer::UlInformationTransferProcedure;

use anyhow::Result;
use f1ap::SrbId;

pub trait F1apBase {
    async fn rrc_request<T: Send + SerDes>(
        &mut self,
        srb_id: SrbId,
        rrc: &T,
    ) -> Result<Box<UlDcchMessage>>;
    async fn rrc_indication<T: Send + SerDes>(&mut self, srb: SrbId, rrc: &T) -> Result<()>;
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::F1apBase;
}
