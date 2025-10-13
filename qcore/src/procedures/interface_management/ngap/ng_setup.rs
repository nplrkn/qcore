use super::prelude::*;
use ngap::{NgSetupFailure, NgSetupRequest, NgSetupResponse};
use xxap::{RequestError, ResponseAction};

impl<'a, A: ProcedureBase> Procedure<'a, A> {
    // Ng Setup Procedure
    // 1.    Ngap NgSetupRequest >>
    // 2.    Ngap NgSetupResponse <<
    pub async fn ng_setup(
        &self,
        r: NgSetupRequest,
    ) -> Result<ResponseAction<NgSetupResponse>, RequestError<NgSetupFailure>> {
        self.log_message(">> Ngap NgSetupRequest");
        let gnb_name = if let Some(ref x) = r.ran_node_name {
            x.0.clone()
        } else {
            "<none>".to_string()
        };
        info!(self.logger, "NGAP setup with gNB: {gnb_name}");
        debug!(
            self.logger,
            "GNB global RAN node id:{:?}", r.global_ran_node_id
        );
        let response = crate::ngap::build::ng_setup_response(
            &self.api.config().guami(),
            &self.api.config().plmn,
            self.api.config().sst,
        )?;
        self.log_message("<< Ngap NgSetupResponse");
        Ok((response, None))
    }
}
