use super::prelude::*;
use ngap::{NgReset, NgResetAcknowledge};
use xxap::{RequestError, ResponseAction};

impl<'a, A: ProcedureBase> Procedure<'a, A> {
    pub async fn ng_reset(
        &self,
        _r: NgReset,
    ) -> Result<ResponseAction<NgResetAcknowledge>, RequestError<()>> {
        self.log_message(">> Ngap NgReset");

        info!(self.logger, "NG reset - disconnecting UEs");
        // TODO - this ought to be qualified by NGAP instance (for the case of multiple gNBs).
        self.api.disconnect_ues().await;

        let response = NgResetAcknowledge {
            ue_associated_logical_ng_connection_list: None,
            criticality_diagnostics: None,
        };

        self.log_message("<< Ngap NgResetAcknowledge");
        Ok((response, None))
    }
}
