use super::prelude::*;
use oxirush_nas::messages::NasDeregistrationRequestFromUe;

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn deregistration_from_ue(
        &mut self,
        _r: NasDeregistrationRequestFromUe,
    ) -> Result<()> {
        self.log_message(">> Nas DeregistrationRequestFromUe");

        info!(self.logger, "UE deregistration");

        let response = crate::nas::build::deregistration_accept_from_ue();
        self.log_message("<< Nas DeregistrationAcceptFromUe");
        self.send_nas(response).await?;

        // Clear the TMSI - meaning that the 5GC context will not be persisted.
        match self.ue.tmsi.take() {
            Some(tmsi) => self.api.delete_tmsi(tmsi.0).await,
            None => warn!(self.logger, "No TMSI to delete"),
        }

        self.api.disconnect_ue();
        Ok(())
    }
}
