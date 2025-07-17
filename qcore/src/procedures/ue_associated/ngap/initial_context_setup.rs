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

        let reactivated_session_count = rsp
            .pdu_session_resource_setup_list_cxt_res
            .as_ref()
            .map(|x| x.0.len())
            .unwrap_or_default();
        if reactivated_session_count != self.ue.core.pdu_sessions.len() {
            warn!(
                self.logger,
                "Reactivated session count {reactivated_session_count}, expected {}",
                self.ue.core.pdu_sessions.len()
            );
        }

        // Enable downlink forwarding on any reactivated sessions.
        if let Some(list) = rsp.pdu_session_resource_setup_list_cxt_res {
            for item in list.0.iter() {
                let id = item.pdu_session_id.0;
                if let Some(pdu_session) = self.ue.core.pdu_sessions.iter_mut().find(|x| x.id == id)
                {
                    match super::connect_session_downlink(
                        &item.pdu_session_resource_setup_response_transfer,
                        pdu_session,
                    ) {
                        Ok(_) => debug!(self.logger, "Reactivated session {id}"),
                        Err(e) => warn!(self.logger, "Failed to reactivate session {id} - {e}"),
                    }
                } else {
                    warn!(
                        self.logger,
                        "Unknown session {id} in InitialContextSetupResponse"
                    )
                }
            }
        }

        Ok(self.0)
    }
}
