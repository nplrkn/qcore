use super::{UeProcedure, UplinkNasProcedure, HandlerApi};
use anyhow::{Result, bail};
use derive_deref::{Deref, DerefMut};
use rrc::{
    CriticalExtensions37, DedicatedNasMessage, UlInformationTransfer, UlInformationTransferIEs,
};

#[derive(Deref, DerefMut)]
pub struct UlInformationTransferProcedure<'a, A: HandlerApi>(UeProcedure<'a, A>);

impl<'a, A: HandlerApi> UlInformationTransferProcedure<'a, A> {
    pub fn new(ue_procedure: UeProcedure<'a, A>) -> Self {
        UlInformationTransferProcedure(ue_procedure)
    }

    pub async fn run(self, ul_information_transfer: UlInformationTransfer) -> Result<()> {
        self.log_message(">> UlInformationTransfer");
        let UlInformationTransfer {
            critical_extensions:
                CriticalExtensions37::UlInformationTransfer(UlInformationTransferIEs {
                    dedicated_nas_message: Some(DedicatedNasMessage(nas_bytes)),
                    ..
                }),
        } = ul_information_transfer
        else {
            bail!("Expected NAS message in UlInformationTransfer, got {ul_information_transfer:?}");
        };
        UplinkNasProcedure::new(self.0).run(nas_bytes).await
    }
}
