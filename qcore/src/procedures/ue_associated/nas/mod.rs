mod deregistration;
pub use deregistration::DeregistrationProcedure;
mod registration;
use oxirush_nas::Nas5gsMessage;
pub use registration::RegistrationProcedure;
mod pdu_session_establishment;
pub use pdu_session_establishment::SessionEstablishmentProcedure;
mod uplink_nas;
pub use uplink_nas::UplinkNasProcedure;

use anyhow::Result;
pub trait NasBase {
    async fn nas_request(&mut self, nas: Box<Nas5gsMessage>) -> Result<Box<Nas5gsMessage>>;
    async fn nas_indication(&mut self, nas: Box<Nas5gsMessage>) -> Result<()>;
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::NasBase;
}
