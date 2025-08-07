use anyhow::ensure;
use ngap::PduSessionResourceSetupListSuRes;

use crate::data::PduSession;

use super::prelude::*;

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn pdu_session_resource_setup(
        &mut self,
        nas: Vec<u8>,
        pdu_session: &mut PduSession,
    ) -> Result<()> {
        // TODO - support > 1 session
        // let session_index = 0usize;
        // let pdu_session = &self.ue.core.pdu_sessions[session_index];

        let req = crate::ngap::build::pdu_session_resource_setup_request(
            self.ue.amf_ue_ngap_id(),
            self.ue.ran_ue_ngap_id(),
            pdu_session,
            self.api.config().ip_addr.into(),
            nas,
        )?;
        self.log_message("<< Ngap PduSessionResourceSetupRequest");
        let rsp = self
            .api
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
                    pdu_session,
                )?;
            }
            None => bail!("GNB failed session set up"),
        }
        Ok(())
    }
}
