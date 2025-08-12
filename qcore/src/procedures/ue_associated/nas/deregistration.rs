use super::prelude::*;
use oxirush_nas::messages::NasDeregistrationRequestFromUe;

impl<'a, B: NasBase> NasProcedure<'a, B> {
    pub async fn deregistration_from_ue(
        &mut self,
        _r: NasDeregistrationRequestFromUe,
    ) -> Result<()> {
        self.log_message(">> Nas DeregistrationRequestFromUe");

        info!(self.logger, "UE deregistration");

        // TODO - send NAS deregistration accept (UE originating de-registration).
        // Is this piggy-backed in the RRC Container on the F1 Context Release Command?

        // TODO - should we release the RAN context, or is that up to the lower layers?
        // TODO - we should destroy the UE's 5GC state at this point, whereas in fact we
        // will currently store it off against the TMSI.
        self.api.disconnect_ue();
        Ok(())
    }
}
