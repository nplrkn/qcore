mod f1ap;
mod nas;
mod ngap;
mod ue_message_handler;
pub use f1ap::*;
pub use nas::*;
pub use ngap::*;
pub mod ue_message;
mod ue_procedure;

pub use ue_message::UeMessage;
pub use ue_message_handler::UeMessageHandler;
pub use ue_procedure::UeProcedure;

// Used to reduce boilerplate at the start of UE procedure implementation modules.
mod prelude {
    pub use super::super::prelude::*;
    pub use super::UeProcedure;
    pub use crate::define_ue_procedure;
}

// Reduce procedure boilerplate by defining the newtype struct and the new() function.
#[macro_export]
macro_rules! define_ue_procedure {
    ($t:ident) => {
        #[derive(Deref, DerefMut)]
        pub struct $t<'a, A: HandlerApi>(UeProcedure<'a, A>);
        impl<'a, A: HandlerApi> $t<'a, A> {
            pub fn new(inner: UeProcedure<'a, A>) -> Self {
                $t(inner)
            }
        }
    };
}
