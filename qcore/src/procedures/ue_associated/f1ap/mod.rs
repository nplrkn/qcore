mod f1ap_mode_session_release;
mod rrc_reconfiguration;
mod rrc_security_mode;
mod rrc_setup;
mod ue_context_release;
mod ue_context_setup;
mod ul_information_transfer;
pub use f1ap_mode_session_release::*;
pub use rrc_reconfiguration::*;
pub use rrc_security_mode::*;
pub use rrc_setup::*;
pub use ue_context_release::*;
pub use ue_context_setup::*;
pub use ul_information_transfer::*;

use anyhow::Result;
use asn1_per::SerDes;
use f1ap::SrbId;
use rrc::UlDcchMessage;

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
