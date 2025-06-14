use anyhow::ensure;
use asn1_per::SerDes;
use ngap::{
    PduSessionResourceSetupListSuRes, PduSessionResourceSetupResponseTransfer,
    UpTransportLayerInformation,
};

use crate::data::PduSession;

use super::prelude::*;

define_ue_procedure!(PduSessionResourceSetupProcedure);
impl<'a, A: HandlerApi> PduSessionResourceSetupProcedure<'a, A> {
    pub async fn run(
        self,
        pdu_session: &mut PduSession,
        nas: Vec<u8>,
    ) -> Result<UeProcedure<'a, A>> {
        let req = crate::ngap::build::pdu_session_resource_setup_request(
            self.ue.amf_ue_ngap_id(),
            self.ue.ran_ue_ngap_id(),
            pdu_session,
            self.config().ip_addr.into(),
            nas,
        )?;
        self.log_message("<< Ngap PduSessionResourceSetupRequest");
        let rsp = self
            .xxap_request::<ngap::PduSessionResourceSetupProcedure>(req, self.logger)
            .await?;
        self.log_message(">> Ngap PduSessionResourceSetupResponse");
        match rsp.pdu_session_resource_setup_list_su_res {
            Some(PduSessionResourceSetupListSuRes(x)) => {
                if x.len() > 1 {
                    warn!(self.logger, "Multiple session setup not implemented");
                }
                ensure!(
                    x.first().pdu_session_id.0 == pdu_session.id,
                    "GNB setup session ID {}, expected {}",
                    x.first().pdu_session_id.0,
                    pdu_session.id
                );
                let pdu_session_resource_setup_response_transfer =
                    PduSessionResourceSetupResponseTransfer::from_bytes(
                        &x.first().pdu_session_resource_setup_response_transfer,
                    )?;

                let UpTransportLayerInformation::GtpTunnel(gtp_tunnel) =
                    pdu_session_resource_setup_response_transfer
                        .dl_qos_flow_per_tnl_information
                        .up_transport_layer_information;

                pdu_session.userplane_info.remote_tunnel_info = Some(gtp_tunnel);
            }
            None => bail!("GNB failed session set up"),
        }
        Ok(self.0)
    }
}
