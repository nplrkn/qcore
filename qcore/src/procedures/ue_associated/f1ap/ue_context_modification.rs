use super::prelude::*;

impl<'a, B: RanUeBase> F1apUeProcedure<'a, B> {
    pub async fn ue_context_modification(
        &self,
        released_session: &PduSession,
    ) -> Result<Option<Vec<u8>>> {
        let ue_context_modification_request =
            crate::f1ap::build::ue_context_modification_request(self.ue, released_session);
        self.log_message("<< UeContextModificationRequest");
        let rsp = Box::new(
            self.api
                .xxap_request::<f1ap::UeContextModificationProcedure>(
                    ue_context_modification_request,
                    &self.logger,
                )
                .await?,
        );
        self.log_message(">> UeContextModificationResponse");
        let cell_group_config = rsp.du_to_cu_rrc_information.map(|x| x.cell_group_config.0);
        Ok(cell_group_config)
    }
}
