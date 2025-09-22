use super::prelude::*;
use crate::protocols::nas::FGSM_CAUSE_REGULAR_DEACTIVATION;
use oxirush_nas::{
    Nas5gsmMessage,
    messages::{Nas5gsmHeader, NasPduSessionReleaseRequest},
};

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn ue_requested_session_release(
        &mut self,
        hdr: Nas5gsmHeader,
        _r: &NasPduSessionReleaseRequest,
    ) -> Result<()> {
        self.log_message(">> Nas PduSessionReleaseRequest");
        self.perform_session_release(hdr.pdu_session_identity).await
    }

    async fn perform_session_release(&mut self, session_id: u8) -> Result<()> {
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
        self.log_message("<< Nas PduSessionReleaseCommand");
        let pdu_session_release_command = self.ue.nas.encode_dl(pdu_session_release_command)?;
        self.api
            .ran_session_release(&released_session, pdu_session_release_command)
            .await?;
        self.api
            .delete_userplane_session(&released_session.userplane)
            .await;

        let _pdu_session_release_complete = self
            .receive_nas_sm(
                |nas| match nas {
                    Nas5gsmMessage::PduSessionReleaseComplete(x) => Some(x),
                    _ => None,
                },
                "Nas PduSessionReleaseComplete",
            )
            .await?;
        self.log_message(">> Nas PduSessionReleaseComplete");

        // TODO check session identity

        Ok(())
    }
}
