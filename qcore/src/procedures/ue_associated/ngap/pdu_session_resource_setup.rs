use anyhow::ensure;
use ngap::PduSessionResourceSetupListSuRes;

use super::prelude::*;

define_ue_procedure!(PduSessionResourceSetupProcedure);
impl<'a, A: HandlerApi> PduSessionResourceSetupProcedure<'a, A> {
    pub async fn run(mut self, nas: Vec<u8>) -> Result<UeProcedure<'a, A>> {
        // TODO - support > 1 session
        let session_index = 0usize;
        let pdu_session = &self.ue.core.pdu_sessions[session_index];

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

                // TODO: commonize setting of remote tunnel info and error handling in Ngap PduSessionResourceSetupResponse,
                // Ngap InitialContextSetupResponse and F1ap UeContextSetupResponse
                super::connect_session_downlink(
                    &x.first().pdu_session_resource_setup_response_transfer,
                    &mut self.ue.core.pdu_sessions[session_index],
                )?;
            }
            None => bail!("GNB failed session set up"),
        }
        Ok(self.0)
    }
}
