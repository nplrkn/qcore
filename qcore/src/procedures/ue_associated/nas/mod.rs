mod deregistration;
pub use deregistration::*;
mod registration;
pub use registration::*;
mod session_establishment;
pub use session_establishment::*;
mod uplink_nas;
pub use uplink_nas::*;
mod session_release;
pub use session_release::*;
mod service;
pub use service::*;

use crate::{data::DecodedNas, protocols::nas::Tmsi};
use anyhow::Result;
use oxirush_nas::{
    Nas5gsMessage, Nas5gsmMessage, NasFGsMobileIdentity, messages::Nas5gsSecurityHeader,
};

pub trait NasBase {
    async fn nas_request<T>(
        &mut self,
        nas: Box<Nas5gsMessage>,
        filter: fn(DecodedNas) -> Result<T, DecodedNas>, // use nas_request_filter! macro
        expected: &str,
    ) -> Result<T>;

    async fn nas_indication(&mut self, nas: Box<Nas5gsMessage>) -> Result<()>;

    async fn receive_nas<T>(
        &mut self,
        filter: fn(DecodedNas) -> Result<T, DecodedNas>, // use nas_request_filter! macro
        expected: &str,
    ) -> Result<T>;

    async fn receive_nas_sm<T>(
        &mut self,
        filter: fn(Nas5gsmMessage) -> Option<T>,
        expected: &str,
    ) -> Result<T>;

    async fn allocate_tmsi(&mut self) -> NasFGsMobileIdentity;

    // Matches the UE TMSI, retrieves the NAS layer data and attaches it to this UE context.
    // If the UE has switched to a new RAN context, the old one will be cleaned up.
    // Ok(true) if identity request is needed, Ok(false) if no action is needed, and
    // Err(cause code) if we should reject the registration
    // TODO: invert the OK values
    async fn retrieve_ue(
        &mut self,
        amf_region: Option<u8>,
        amf_set_and_pointer: &[u8],
        tmsi: &Tmsi,
        security_header: Option<Nas5gsSecurityHeader>,
    ) -> Result<bool, u8>;

    async fn reconcile_sessions(
        &mut self,
        uplink_data_status: u16,
        pdu_session_status: u16,
    ) -> Result<u16>;
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::NasBase;
}

#[macro_export]
macro_rules! nas_request_filter {
    ($s:ident, $f:ident) => {{
        |m| match *m.0 {
            oxirush_nas::Nas5gsMessage::Gmm(_header, oxirush_nas::Nas5gmmMessage::$s(message)) => {
                Ok(Ok(message))
            }
            oxirush_nas::Nas5gsMessage::Gmm(_header, oxirush_nas::Nas5gmmMessage::$f(message)) => {
                Ok(Err(message))
            }
            _ => Err(m),
        }
    }};
}

#[macro_export]
macro_rules! nas_filter {
    ($m:ident) => {{
        |m| match *m.0 {
            oxirush_nas::Nas5gsMessage::Gmm(_header, oxirush_nas::Nas5gmmMessage::$m(message)) => {
                Ok(message)
            }
            _ => Err(m),
        }
    }};
}
