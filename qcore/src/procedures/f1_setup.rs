//! f1_setup - the initial handshake that establishes an instance of the F1 reference point between GNB-CU and GNB-DU

use crate::{HandlerApi, Procedure};
use anyhow::Result;
use derive_deref::{Deref, DerefMut};
use f1ap::{F1SetupFailure, F1SetupRequest, F1SetupResponse};
use slog::{Logger, info};
use xxap::{RequestError, ResponseAction};

#[derive(Deref, DerefMut)]
pub struct F1SetupProcedure<'a, A: HandlerApi>(Procedure<'a, A>);

impl<'a, A: HandlerApi> F1SetupProcedure<'a, A> {
    pub fn new(api: &'a A, logger: &'a Logger) -> Self {
        F1SetupProcedure(Procedure::new(api, logger))
    }

    // F1 Setup Procedure
    // 1.    F1ap F1SetupRequest >>
    // 2.    F1ap F1SetupResponse <<
    pub async fn run(
        &self,
        r: F1SetupRequest,
    ) -> Result<ResponseAction<F1SetupResponse>, RequestError<F1SetupFailure>> {
        self.log_message(">> F1SetupRequest");
        let gnb_du_name = if let Some(ref x) = r.gnb_du_name {
            x.0.clone()
        } else {
            "<none>".to_string()
        };
        info!(
            self.logger,
            "F1 setup with DU name:{gnb_du_name}, id:{:x}", r.gnb_du_id.0
        );
        let response = crate::f1ap::build::f1_setup_response(r, self.config().clone().name)?;
        self.log_message("<< F1SetupResponse");
        Ok((response, None))
    }
}
