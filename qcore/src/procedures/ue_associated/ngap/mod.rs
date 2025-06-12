mod initial_context_setup;
pub use initial_context_setup::InitialContextSetupProcedure;
mod initial_ue_message;
pub use initial_ue_message::InitialUeMessageProcedure;
mod uplink_nas_transport;
pub use uplink_nas_transport::UplinkNasTransportProcedure;
mod pdu_session_resource_setup;
pub use pdu_session_resource_setup::PduSessionResourceSetupProcedure;

//pub trait NgapBase {}

mod prelude {
    pub use super::super::prelude::*;
}
