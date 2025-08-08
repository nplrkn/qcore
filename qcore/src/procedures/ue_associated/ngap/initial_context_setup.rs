use asn1_per::SerDes;
use ngap::{InitialContextSetupResponse, PduSessionResourceSetupUnsuccessfulTransfer};

use crate::data::PduSession;

use super::prelude::*;

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn initial_context_setup(
        &self,
        kgnb: &[u8; 32],
        nas_pdu: Vec<u8>,
        session_list: &mut Vec<PduSession>,
        ue_security_capabilities: &[u8; 2],
    ) -> Result<()> {
        let initial_context_setup_request = crate::ngap::build::initial_context_setup_request(
            self.api.config().guami(),
            kgnb,
            self.api.config().sst,
            Some(nas_pdu),
            self.ue,
            self.api.config().ip_addr.into(),
            session_list,
            ue_security_capabilities,
        )?;
        self.log_message("<< Ngap InitialContextSetupRequest");
        let rsp = self
            .api
            .xxap_request::<ngap::InitialContextSetupProcedure>(
                initial_context_setup_request,
                self.logger,
            )
            .await?;
        self.log_message(">> Ngap InitialContextSetupResponse");

        // Go through each PDU session on the UE reactivating it.  Delete if the reactivation failed.
        // TODO: commonize setting of remote tunnel info and error handling in Ngap PduSessionResourceSetupResponse,
        // Ngap InitialContextSetupResponse and F1ap UeContextSetupResponse
        let sessions = std::mem::take(session_list);
        for mut session in sessions.into_iter() {
            match self.connect_matching_session(&mut session, &rsp) {
                Ok(()) => {
                    self.api
                        .commit_userplane_session(&session.userplane_info, self.logger)
                        .await?;
                    session_list.push(session);
                }

                Err(e) => {
                    warn!(
                        self.logger,
                        "Failed to reactivate session {} - {e}", session.id
                    );
                    self.api
                        .delete_userplane_session(&session.userplane_info, self.logger)
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
                "GNB error for session {}: {:?}", item.pdu_session_id.0, xfer.cause
            );
        }

        Ok(())
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
