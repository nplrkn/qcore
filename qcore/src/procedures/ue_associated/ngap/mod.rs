mod initial_context_setup;
use asn1_per::SerDes;
pub use initial_context_setup::InitialContextSetupProcedure;
mod initial_ue_message;
pub use initial_ue_message::InitialUeMessageProcedure;
mod uplink_nas_transport;
use ngap::{PduSessionResourceSetupResponseTransfer, UpTransportLayerInformation};
pub use uplink_nas_transport::UplinkNasTransportProcedure;
mod pdu_session_resource_setup;
pub use pdu_session_resource_setup::PduSessionResourceSetupProcedure;
mod ran_session_release;
pub use ran_session_release::RanSessionReleaseProcedure as NgapRanSessionReleaseProcedure;
mod ue_context_release;
pub use ue_context_release::UeContextReleaseProcedure as NgapUeContextReleaseProcedure;

use crate::data::PduSession;

mod prelude {
    pub use super::super::prelude::*;
}

use anyhow::Result;

fn connect_session_downlink(
    pdu_session_resource_setup_response_transfer_bytes: &[u8],
    session: &mut PduSession,
) -> Result<()> {
    let pdu_session_resource_setup_response_transfer =
        PduSessionResourceSetupResponseTransfer::from_bytes(
            pdu_session_resource_setup_response_transfer_bytes,
        )?;

    let UpTransportLayerInformation::GtpTunnel(gtp_tunnel) =
        pdu_session_resource_setup_response_transfer
            .dl_qos_flow_per_tnl_information
            .up_transport_layer_information;

    session.userplane_info.remote_tunnel_info = Some(gtp_tunnel);
    Ok(())
}
