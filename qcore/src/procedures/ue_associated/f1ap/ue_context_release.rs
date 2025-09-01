use super::prelude::*;
use f1ap::UeContextReleaseComplete;

impl<'a, B: RanUeBase> F1apUeProcedure<'a, B> {
    pub async fn ue_context_release(&mut self, cause: f1ap::Cause) {
        if let Err(e) = self.ue_context_release_inner(cause).await {
            warn!(self.logger, "Failed to release RAN context: {e}");
        }
    }

    async fn ue_context_release_inner(&mut self, cause: f1ap::Cause) -> Result<()> {
        let ue_context_release_command =
            crate::f1ap::build::ue_context_release_command(self.ue, cause);
        self.log_message("<< F1ap UeContextReleaseCommand");
        let rsp = self
            .api
            .xxap_request::<f1ap::UeContextReleaseProcedure>(
                ue_context_release_command,
                &self.logger,
            )
            .await?;
        self.log_message(">> F1ap UeContextReleaseComplete");
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
