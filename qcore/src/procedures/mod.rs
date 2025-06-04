mod f1ap_handler;
mod handler_api;
mod interface_management;
mod ngap_handler;
mod procedure;
mod ue_associated;

pub use f1ap_handler::F1apHandler;
pub use handler_api::{HandlerApi, UeMessage};
pub use ngap_handler::NgapHandler;
pub use procedure::Procedure;
pub use ue_associated::UeMessageHandler;

// Used to reduce boilerplate at the start of procedure implementation modules.
mod prelude {
    pub use super::{HandlerApi, Procedure};
    pub use anyhow::{Result, anyhow, bail};
    pub use derive_deref::{Deref, DerefMut};
    pub use slog::{Logger, debug, error, info, warn};
}
