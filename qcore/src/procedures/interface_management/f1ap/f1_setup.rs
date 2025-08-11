//! f1_setup - the initial handshake that establishes an instance of the F1 reference point between GNB-CU and GNB-DU
use super::prelude::*;
use f1ap::{F1SetupFailure, F1SetupRequest, F1SetupResponse, GnbDuServedCellsItem};
use xxap::{RequestError, ResponseAction};

impl<'a, A: ProcedureBase> Procedure<'a, A> {
    // F1 Setup Procedure
    // 1.    F1ap F1SetupRequest >>
    // 2.    F1ap F1SetupResponse <<
    pub async fn f1_setup(
        &self,
        r: F1SetupRequest,
    ) -> Result<ResponseAction<F1SetupResponse>, RequestError<F1SetupFailure>> {
        self.log_message(">> F1ap SetupRequest");
        let gnb_du_name = if let Some(ref x) = r.gnb_du_name {
            x.0.clone()
        } else {
            "<none>".to_string()
        };
        info!(
            self.logger,
            "F1 setup with DU name:{gnb_du_name}, id:{:x}", r.gnb_du_id.0
        );

        // Filter out the served cells not in the PLMN.
        let gnb_du_served_cells_list: Vec<GnbDuServedCellsItem> = r
            .gnb_du_served_cells_list
            .map(|x| x.0)
            .into_iter()
            .flatten()
            .filter(|x| x.served_cell_information.nr_cgi.plmn_identity == self.api.config().plmn)
            .collect();

        let response = crate::f1ap::build::f1_setup_response(
            r.transaction_id,
            self.api.config().clone().name,
            &gnb_du_served_cells_list,
        )?;

        self.api
            .served_cells()
            .lock()
            .await
            .insert(r.gnb_du_id.0, gnb_du_served_cells_list);

        self.log_message("<< F1ap SetupResponse");
        Ok((response, None))
    }
}
