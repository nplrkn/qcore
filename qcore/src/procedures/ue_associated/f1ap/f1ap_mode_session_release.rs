use super::prelude::*;
use crate::{data::PduSession, procedures::ue_associated::RrcReconfigurationProcedure};
use f1ap::UeContextModificationResponse;

define_ue_procedure!(F1apModeSessionReleaseProcedure);
impl<'a, A: HandlerApi> F1apModeSessionReleaseProcedure<'a, A> {
    pub async fn run(
        self,
        released_session: &PduSession,
        nas: Vec<u8>,
    ) -> Result<UeProcedure<'a, A>> {
        // Send a UE context modification to delete the DRB.
        let rsp = self
            .perform_f1_ue_context_modification(released_session)
            .await?;
        RrcReconfigurationProcedure::new(self.0)
            .delete_session(
                nas,
                released_session,
                rsp.du_to_cu_rrc_information.map(|x| x.cell_group_config.0),
            )
            .await
    }

    async fn perform_f1_ue_context_modification(
        &self,
        released_session: &PduSession,
    ) -> Result<Box<UeContextModificationResponse>> {
        let ue_context_modification_request =
            crate::f1ap::build::ue_context_modification_request(self.ue, released_session);
        self.log_message("<< UeContextModificationRequest");
        let rsp = Box::new(
            self.xxap_request::<f1ap::UeContextModificationProcedure>(
                ue_context_modification_request,
                self.logger,
            )
            .await?,
        );
        self.log_message(">> UeContextModificationResponse");
        Ok(rsp)
    }
}
