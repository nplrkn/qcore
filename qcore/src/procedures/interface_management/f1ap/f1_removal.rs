use super::prelude::*;
use f1ap::{F1RemovalFailure, F1RemovalRequest, F1RemovalResponse};
use xxap::{RequestError, ResponseAction};

define_procedure!(F1RemovalProcedure);

impl<'a, A: HandlerApi> F1RemovalProcedure<'a, A> {
    pub async fn run(
        &self,
        r: F1RemovalRequest,
    ) -> Result<ResponseAction<F1RemovalResponse>, RequestError<F1RemovalFailure>> {
        self.log_message(">> F1RemovalRequest");

        info!(self.logger, "F1 removal");

        // TS38.473, 8.2.8.2: "After receiving the F1 REMOVAL RESPONSE message, the gNB-DU may initiate removal of
        // the TNL association towards the gNB-CU, if applicable, and may remove all resources
        // associated with that signaling connection. The gNB-CU may then remove all resources
        // associated with that interface instance."

        // Exit UE message handlers (which will tear down UP sessions).
        // TODO - the UP sessions ought to be deactivated rather than deleted.  This is because the DU might reconnect
        // meaning the UE can then be paged and downlink data can be delivered to it.
        // TODO - this ought to be qualified by F1AP instance (for the case of multiple DUs).
        self.api.delete_ue_channels();

        let response = F1RemovalResponse {
            transaction_id: r.transaction_id,
            criticality_diagnostics: None,
        };
        Ok((response, None))
    }
}
