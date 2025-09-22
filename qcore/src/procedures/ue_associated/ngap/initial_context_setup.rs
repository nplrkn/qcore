use super::prelude::*;
use asn1_per::SerDes;
use ngap::{InitialContextSetupResponse, PduSessionResourceSetupUnsuccessfulTransfer};

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    // Returns if the UE was previously paged
    pub async fn initial_context_setup(
        &mut self,
        kgnb: &[u8; 32],
        nas_pdu: Vec<u8>,
        session_list: &mut Vec<PduSession>,
        ue_security_capabilities: &[u8; 2],
    ) -> Result<bool> {
        let initial_context_setup_request = crate::ngap::build::initial_context_setup_request(
            self.api.config(),
            kgnb,
            Some(nas_pdu),
            self.ue,
            session_list,
            ue_security_capabilities,
        )?;
        self.log_message("<< Ngap InitialContextSetupRequest");
        let rsp = self
            .api
            .xxap_request::<ngap::InitialContextSetupProcedure>(
                initial_context_setup_request,
                &self.logger,
            )
            .await?;
        self.log_message(">> Ngap InitialContextSetupResponse");

        // Go through each PDU session on the UE reactivating it.  Delete if the reactivation failed.
        // TODO: commonize setting of remote tunnel info and error handling in Ngap PduSessionResourceSetupResponse,
        // Ngap InitialContextSetupResponse and F1ap UeContextSetupResponse

        let mut ue_was_paged = false;
        let sessions = std::mem::take(session_list);
        for mut session in sessions.into_iter() {
            match self.connect_matching_session(&mut session, &rsp).await {
                Ok(downlink_data_sent) => {
                    ue_was_paged = ue_was_paged || downlink_data_sent;
                    session_list.push(session);
                }

                Err(e) => {
                    warn!(
                        self.logger,
                        "Failed to reactivate session {} - {e}", session.id
                    );
                    self.api
                        .delete_userplane_session(&session.userplane, &self.logger)
                        .await;
                }
            }
        }

        // Log any errors returned by the gNB.
        for item in rsp
            .pdu_session_resource_failed_to_setup_list_cxt_res
            .map(|x| x.0)
            .iter()
            .flatten()
        {
            let xfer = PduSessionResourceSetupUnsuccessfulTransfer::from_bytes(
                &item.pdu_session_resource_setup_unsuccessful_transfer,
            )?;
            warn!(
                self.logger,
                "gNB error for session {}: {:?}", item.pdu_session_id.0, xfer.cause
            );
        }

        Ok(ue_was_paged)
    }

    async fn connect_matching_session(
        &mut self,
        session: &mut PduSession,
        rsp: &InitialContextSetupResponse,
    ) -> Result<bool> {
        if let Some(ref list) = rsp.pdu_session_resource_setup_list_cxt_res {
            if let Some(matching_item) = list
                .0
                .iter()
                .find(|item| item.pdu_session_id.0 == session.id)
            {
                return self
                    .connect_session_downlink(
                        &matching_item.pdu_session_resource_setup_response_transfer,
                        session,
                    )
                    .await;
            }
        }
        bail!("gNB did not supply resource setup response")
    }
}
