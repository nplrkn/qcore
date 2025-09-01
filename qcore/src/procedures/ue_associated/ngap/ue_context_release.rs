use super::prelude::*;
use ngap::{Cause, UeContextReleaseComplete};

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn ue_context_release(&mut self, cause: Cause) {
        if let Err(e) = self.ue_context_release_inner(cause).await {
            warn!(self.logger, "Failed to release RAN context: {e}");
        }
    }

    async fn ue_context_release_inner(&mut self, cause: Cause) -> Result<()> {
        let ue_context_release_command = crate::ngap::build::ue_context_release_command(
            self.ue.amf_ue_ngap_id(),
            self.ue.ran_ue_ngap_id(),
            cause,
        );
        self.log_message("<< Ngap UeContextReleaseCommand");
        let rsp = self
            .api
            .xxap_request::<ngap::UeContextReleaseProcedure>(
                ue_context_release_command,
                &self.logger,
            )
            .await?;
        self.log_message(">> Ngap UeContextReleaseComplete");
        self.check_ue_context_release_complete(&rsp)
    }

    fn check_ue_context_release_complete(
        &self,
        _ue_context_release_complete: &UeContextReleaseComplete,
    ) -> Result<()> {
        // TODO
        Ok(())
    }
}
