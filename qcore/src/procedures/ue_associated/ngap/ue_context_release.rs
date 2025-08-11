use super::prelude::*;
use ngap::UeContextReleaseComplete;

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn ue_context_release(&mut self) {
        if let Err(e) = self.ue_context_release_inner().await {
            warn!(self.logger, "Failed to release RAN context: {e}");
        }
    }

    async fn ue_context_release_inner(&mut self) -> Result<()> {
        // TODO: are we also meant to RRC Release the UE?

        let ue_context_release_command = crate::ngap::build::ue_context_release_command(
            self.ue.amf_ue_ngap_id(),
            self.ue.ran_ue_ngap_id(),
            self.release_cause.clone(),
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
