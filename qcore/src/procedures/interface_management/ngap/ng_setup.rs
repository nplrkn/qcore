use super::prelude::*;
use ngap::{NgSetupFailure, NgSetupRequest, NgSetupResponse};
use xxap::{RequestError, ResponseAction};

define_procedure!(NgSetupProcedure);

impl<'a, A: HandlerApi> NgSetupProcedure<'a, A> {
    // Ng Setup Procedure
    // 1.    Ngap NgSetupRequest >>
    // 2.    Ngap NgSetupResponse <<
    pub async fn run(
        &self,
        r: NgSetupRequest,
    ) -> Result<ResponseAction<NgSetupResponse>, RequestError<NgSetupFailure>> {
        self.log_message(">> NgSetupRequest");
        let gnb_name = if let Some(ref x) = r.ran_node_name {
            x.0.clone()
        } else {
            "<none>".to_string()
        };
        info!(
            self.logger,
            "NG setup with GNB name:{gnb_name}, id:{:?}", r.global_ran_node_id
        );
        let response = crate::ngap::build::ng_setup_response(
            &self.config().guami(),
            &self.config().plmn,
            self.config().sst,
        )?;
        self.log_message("<< NgSetupResponse");
        Ok((response, None))
    }
}
