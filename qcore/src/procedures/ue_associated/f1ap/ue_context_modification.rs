use super::prelude::*;
use crate::data::PduSession;
use f1ap::UeContextModificationResponse;

impl<'a, B: RanUeBase> F1apUeProcedure<'a, B> {
    pub async fn ue_context_modification(
        &self,
        released_session: &PduSession,
    ) -> Result<Box<UeContextModificationResponse>> {
        let ue_context_modification_request =
            crate::f1ap::build::ue_context_modification_request(self.ue, released_session);
        self.log_message("<< UeContextModificationRequest");
        let rsp = Box::new(
            self.api
                .xxap_request::<f1ap::UeContextModificationProcedure>(
                    ue_context_modification_request,
                    self.logger,
                )
                .await?,
        );
        self.log_message(">> UeContextModificationResponse");
        Ok(rsp)
    }
}
