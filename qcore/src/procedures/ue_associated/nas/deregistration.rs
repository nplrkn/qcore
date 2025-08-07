use super::prelude::*;
use oxirush_nas::messages::NasDeregistrationRequestFromUe;

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn deregistration_from_ue(&self, _r: NasDeregistrationRequestFromUe) -> Result<()> {
        self.log_message(">> Nas DeregistrationRequestFromUe");

        info!(self.logger, "UE deregistration");

        // TODO - send NAS deregistration accept (UE originating de-registration).
        // Is this piggy-backed in the RRC Container on the F1 Context Release Command?

        // Return an error to get the UE message handler to self-destruct
        // and free up the userplane sessions and channel.
        bail!("Normal deregistration")
    }
}
