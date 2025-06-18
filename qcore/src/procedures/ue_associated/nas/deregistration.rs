use super::prelude::*;
use oxirush_nas::messages::NasDeregistrationRequestFromUe;

define_ue_procedure!(DeregistrationProcedure);

impl<'a, A: HandlerApi> DeregistrationProcedure<'a, A> {
    pub async fn run(self, _r: NasDeregistrationRequestFromUe) -> Result<()> {
        self.log_message(">> DeregistrationRequestFromUe");

        info!(self.logger, "UE deregistration");

        // TODO - send NAS deregistration accept (UE originating de-registration).
        // Is this piggy-backed in the RRC Container on the F1 Context Release Command?

        // Return an error to get the UE message handler to self-destruct
        // and free up the userplane sessions and channel.
        bail!("Normal deregistration")
    }
}
