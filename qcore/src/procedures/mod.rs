mod entrypoints;
mod handler_api;
mod interface_management;
mod ue_associated;

pub use entrypoints::*;
pub use handler_api::HandlerApi;
pub use ue_associated::{UeMessage, UeMessageHandler};

// Reduces procedure boilerplate by compressing common 'use' directives to a single line.
mod prelude {
    pub use super::HandlerApi;
    pub use anyhow::{Result, anyhow, bail};
    pub use slog::{Logger, debug, info, warn};
}
