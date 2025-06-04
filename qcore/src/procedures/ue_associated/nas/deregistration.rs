use super::super::UeContextReleaseProcedure;
use super::prelude::*;
use f1ap::{Cause, CauseRadioNetwork};
use oxirush_nas::messages::NasDeregistrationRequestFromUe;

define_ue_procedure!(DeregistrationProcedure);

impl<'a, A: HandlerApi> DeregistrationProcedure<'a, A> {
    pub async fn run(self, _r: NasDeregistrationRequestFromUe) -> Result<()> {
        self.log_message(">> DeregistrationRequestFromUe");

        info!(self.logger, "UE deregisters - perform context release");

        // TODO - send NAS deregistration accept (UE originating de-registration).
        // Is this piggy-backed in the RRC Container on the F1 Context Release Command?

        // TODO add NGAP mode
        UeContextReleaseProcedure::new(self.0)
            .cu_initiated(Cause::RadioNetwork(CauseRadioNetwork::NormalRelease))
            .await?;

        // Return an error to get the UE message handler to self-destruct
        // and free up the userplane sessions and channel.
        bail!("Normal deregistration")
    }
}
