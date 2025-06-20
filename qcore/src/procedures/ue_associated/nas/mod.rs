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

use crate::data::DecodedNas;
use anyhow::Result;
use oxirush_nas::{Nas5gsMessage, Nas5gsmMessage};

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
