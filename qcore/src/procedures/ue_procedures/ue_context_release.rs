use anyhow::Result;
use derive_deref::{Deref, DerefMut};
use f1ap::{Cause, UeContextReleaseComplete, UeContextReleaseRequest};
use slog::info;

use crate::HandlerApi;

use super::UeProcedure;

#[derive(Deref, DerefMut)]
pub struct UeContextReleaseProcedure<'a, A: HandlerApi>(UeProcedure<'a, A>);

impl<'a, A: HandlerApi> UeContextReleaseProcedure<'a, A> {
    pub fn new(ue_procedure: UeProcedure<'a, A>) -> Self {
        UeContextReleaseProcedure(ue_procedure)
    }
    pub async fn cu_initiated(&mut self, cause: Cause) -> Result<()> {
        self.perform_f1_ue_context_release(cause).await
    }

    pub async fn du_initiated(&mut self, r: UeContextReleaseRequest) -> Result<()> {
        self.log_message(">> F1ap UeContextReleaseRequest");
        info!(
            self.logger,
            "DU initiated context release, cause {:?}", r.cause
        );
        self.perform_f1_ue_context_release(r.cause).await
    }

    async fn perform_f1_ue_context_release(&self, cause: Cause) -> Result<()> {
        // TODO: are we also meant to RRC Release the UE?

        let ue_context_release_command =
            crate::f1ap::build::ue_context_release_command(self.ue, cause);
        self.log_message("<< UeContextReleaseCommand");
        let rsp = self
            .f1ap_request::<f1ap::UeContextReleaseProcedure>(
                ue_context_release_command,
                self.logger,
            )
            .await?;
        self.log_message(">> UeContextReleaseComplete");
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
