mod f1ap_handler;
mod handler_api;
mod interface_management;
mod ngap_handler;
mod ue_associated;

pub use f1ap_handler::F1apHandler;
pub use handler_api::HandlerApi;
pub use ngap_handler::NgapHandler;
pub use ue_associated::{UeMessage, UeMessageHandler};

// Reduces procedure boilerplate by compressing common 'use' directives to a single line.
mod prelude {
    pub use super::HandlerApi;
    pub use anyhow::{Result, anyhow, bail};
    pub use slog::{Logger, debug, info, warn};
}
