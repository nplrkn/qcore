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

// Reduces procedure boilerplate by compressing common 'use' directives to a single line.
mod prelude {
    pub use super::{HandlerApi, Procedure};
    pub use crate::define_procedure;
    pub use anyhow::{Result, anyhow, bail};
    pub use derive_deref::{Deref, DerefMut};
    pub use slog::{Logger, debug, error, info, warn};
}

// Reduce procedure boilerplate by defining the newtype struct and the new() function.
#[macro_export]
macro_rules! define_procedure {
    ($t:ident) => {
        #[derive(Deref, DerefMut)]
        pub struct $t<'a, A: HandlerApi>(Procedure<'a, A>);
        impl<'a, A: HandlerApi> $t<'a, A> {
            pub fn new(inner: Procedure<'a, A>) -> Self {
                $t(inner)
            }
        }
    };
}
