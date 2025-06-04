use super::prelude::*;

define_ue_procedure!(InitialContextSetupProcedure);

impl<'a, A: HandlerApi> InitialContextSetupProcedure<'a, A> {
    pub async fn run(self, kgnb: &[u8; 32]) -> Result<UeProcedure<'a, A>> {
        let initial_context_setup_request = crate::ngap::build::initial_context_setup_request(
            self.ue.amf_ue_ngap_id(),
            self.ue.ran_ue_ngap_id(),
            self.config().guami(),
            kgnb,
            self.config().sst,
            &self.ue.security_capabilities,
        );
        self.log_message("<< NGAP InitialContextSetupRequest");
        let _rsp = self
            .xxap_request::<ngap::InitialContextSetupProcedure>(
                initial_context_setup_request,
                self.logger,
            )
            .await?;
        self.log_message(">> NGAP InitialContextSetupResponse");
        Ok(self.0)
    }
}
