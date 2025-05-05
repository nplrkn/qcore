use anyhow::{Result, bail};
use derive_deref::{Deref, DerefMut};
use f1ap::{Cause, CauseRadioNetwork};
use oxirush_nas::messages::NasDeregistrationRequestFromUe;
use slog::info;
use crate::{HandlerApi};
use super::UeContextReleaseProcedure;

use super::UeProcedure;

#[derive(Deref, DerefMut)]
pub struct DeregistrationProcedure<'a, A: HandlerApi>(UeProcedure<'a, A>);

impl<'a, A: HandlerApi> DeregistrationProcedure<'a, A> {
    pub fn new(inner: UeProcedure<'a, A>) -> Self {
        DeregistrationProcedure(inner)
    }

    pub async fn run(self, _r: NasDeregistrationRequestFromUe) -> Result<()> {
        info!(self.logger, "UE deregisters - perform context release");

        // TODO - send NAS deregistration accept (UE originating de-registration).
        // Is this piggy-backed in the RRC Container on the F1 Context Release Command?

        UeContextReleaseProcedure::new(self.0)
            .cu_initiated(Cause::RadioNetwork(CauseRadioNetwork::NormalRelease))
            .await?;

        // Return an error to get the UE message handler to self-destruct
        // and free up the userplane sessions and channel.
        bail!("Normal deregistration")
    }
}
