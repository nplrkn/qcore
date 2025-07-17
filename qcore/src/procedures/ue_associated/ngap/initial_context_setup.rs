use ngap::InitialContextSetupResponse;

use crate::data::PduSession;

use super::prelude::*;

define_ue_procedure!(InitialContextSetupProcedure);

impl<'a, A: HandlerApi> InitialContextSetupProcedure<'a, A> {
    pub async fn run(
        mut self,
        kgnb: &[u8; 32],
        nas_pdu: Option<Vec<u8>>,
    ) -> Result<UeProcedure<'a, A>> {
        let initial_context_setup_request = crate::ngap::build::initial_context_setup_request(
            self.config().guami(),
            kgnb,
            self.config().sst,
            nas_pdu,
            &self.ue,
            self.config().ip_addr.into(),
        )?;
        self.log_message("<< Ngap InitialContextSetupRequest");
        let rsp = self
            .xxap_request::<ngap::InitialContextSetupProcedure>(
                initial_context_setup_request,
                self.logger,
            )
            .await?;
        self.log_message(">> Ngap InitialContextSetupResponse");

        // Go through each PDU session on the UE reactivating it.  Delete if the reactivation failed.
        let sessions = std::mem::take(&mut self.ue.core.pdu_sessions);
        for mut session in sessions.into_iter() {
            match self.connect_matching_session(&mut session, &rsp) {
                Ok(()) => self.ue.core.pdu_sessions.push(session),
                Err(e) => {
                    warn!(
                        self.logger,
                        "Failed to reactivate session {} - {e}", session.id
                    );
                    self.delete_userplane_session(&session.userplane_info, self.logger)
                        .await;
                }
            }
        }

        Ok(self.0)
    }

    fn connect_matching_session(
        &self,
        session: &mut PduSession,
        rsp: &InitialContextSetupResponse,
    ) -> Result<()> {
        if let Some(ref list) = rsp.pdu_session_resource_setup_list_cxt_res {
            if let Some(matching_item) = list
                .0
                .iter()
                .find(|item| item.pdu_session_id.0 == session.id)
            {
                super::connect_session_downlink(
                    &matching_item.pdu_session_resource_setup_response_transfer,
                    session,
                )?;
                return Ok(());
            }
        }
        bail!("GNB did not supply resource setup response")
    }
}
