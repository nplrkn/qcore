//! f1_setup - the initial handshake that establishes an instance of the F1 reference point between GNB-CU and GNB-DU

use super::prelude::*;
use f1ap::*;
use xxap::{RequestError, ResponseAction};

define_procedure!(GnbDuConfigurationUpdateProcedure);

impl<'a, A: HandlerApi> GnbDuConfigurationUpdateProcedure<'a, A> {
    // F1 Setup Procedure
    // 1.    F1ap GnbDuConfigurationUpdate >>
    // 2.    F1ap GnbDuConfigurationUpdateAcknowledge <<
    pub async fn run(
        &self,
        r: GnbDuConfigurationUpdate,
    ) -> Result<
        ResponseAction<GnbDuConfigurationUpdateAcknowledge>,
        RequestError<GnbDuConfigurationUpdateFailure>,
    > {
        self.log_message(">> GnbDuConfigurationUpdate");

        if r.served_cells_to_add_list.is_some()
            || r.served_cells_to_modify_list.is_some()
            || r.served_cells_to_delete_list.is_some()
        {
            debug!(
                self.logger,
                "Changes to served cells on GnbDuConfigurationUpdate - not implemented and ignored"
            )
        }

        self.log_message("<< GnbDuConfigurationUpdateAcknowledge");
        let ack = crate::f1ap::build::gnb_du_configuration_update_acknowledge(r.transaction_id);
        Ok((ack, None))
    }
}
