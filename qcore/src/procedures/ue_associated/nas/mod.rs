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

use anyhow::Result;
use oxirush_nas::Nas5gsMessage;

pub trait NasBase {
    async fn nas_request(&mut self, nas: Box<Nas5gsMessage>) -> Result<Box<Nas5gsMessage>>;
    async fn nas_indication(&mut self, nas: Box<Nas5gsMessage>) -> Result<()>;
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::NasBase;
}
