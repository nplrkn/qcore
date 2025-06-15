use super::prelude::*;
use crate::protocols::nas::FGSM_CAUSE_REGULAR_DEACTIVATION;
use oxirush_nas::messages::{Nas5gsmHeader, NasPduSessionReleaseRequest};

define_ue_procedure!(SessionReleaseProcedure);

impl<'a, A: HandlerApi> SessionReleaseProcedure<'a, A> {
    pub async fn ue_requested(
        self,
        hdr: Nas5gsmHeader,
        _r: &NasPduSessionReleaseRequest,
    ) -> Result<UeProcedure<'a, A>> {
        self.log_message(">> Nas PduSessionReleaseRequest");
        self.perform_session_release(hdr.pdu_session_identity).await
    }

    async fn perform_session_release(mut self, session_id: u8) -> Result<UeProcedure<'a, A>> {
        let position = self
            .ue
            .pdu_sessions
            .iter()
            .position(|session| session.id == session_id)
            .ok_or_else(|| anyhow!("Session id {session_id} not found"))?;
        let released_session = self.ue.pdu_sessions.swap_remove(position);
        let pdu_session_release_command = crate::nas::build::pdu_session_release_command(
            &released_session,
            FGSM_CAUSE_REGULAR_DEACTIVATION,
        )?;
        let nas = self.ue.nas.encode(pdu_session_release_command)?;
        self.0.ran_session_release(&released_session, nas).await
    }
}
