mod rrc_reconfiguration;
mod rrc_security_mode;
mod rrc_setup;
mod rrc_ue_capability_enquiry;
mod ul_information_transfer;
pub use rrc_reconfiguration::*;
pub use rrc_security_mode::*;
pub use rrc_setup::*;
pub use rrc_ue_capability_enquiry::*;
pub use ul_information_transfer::*;

use anyhow::Result;
use asn1_per::SerDes;
use f1ap::SrbId;
use rrc::UlDcchMessage;

pub trait RrcBase {
    async fn rrc_request<T: Send + SerDes, F>(
        &mut self,
        srb_id: SrbId,
        rrc: &T,
        filter: fn(Box<UlDcchMessage>) -> Result<F, Box<UlDcchMessage>>,
        expected: &str,
    ) -> Result<F>;
    async fn rrc_indication<T: Send + SerDes>(&mut self, srb: SrbId, rrc: &T) -> Result<()>;
    async fn receive_rrc<T>(
        &mut self,
        filter: fn(Box<UlDcchMessage>) -> Result<T, Box<UlDcchMessage>>,
        expected: &str,
    ) -> Result<T>;
}

#[macro_export]
macro_rules! rrc_filter {
    ($m:ident) => {{
        |m| match *m {
            UlDcchMessage {
                message: UlDcchMessageType::C1(C1_6::$m(message)),
            } => Ok(message),
            _ => Err(m),
        }
    }};
}

#[macro_export]
macro_rules! rrc_request_filter {
    ($s:ident, $f:ident) => {{
        |m| match *m {
            UlDcchMessage {
                message: UlDcchMessageType::C1(C1_6::$s(message)),
            } => Ok(Ok(message)),

            UlDcchMessage {
                message: UlDcchMessageType::C1(C1_6::$f(message)),
            } => Ok(Err(message)),

            _ => Err(m),
        }
    }};
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::RrcBase;
}
