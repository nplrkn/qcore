mod initial_context_setup;
pub use initial_context_setup::InitialContextSetupProcedure;
mod initial_ue_message;
pub use initial_ue_message::InitialUeMessageProcedure;

//pub trait NgapBase {}

mod prelude {
    pub use super::super::prelude::*;
}
