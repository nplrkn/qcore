use super::super::UplinkNasProcedure;
use super::prelude::*;
use rrc::{
    CriticalExtensions37, DedicatedNasMessage, UlInformationTransfer, UlInformationTransferIEs,
};

define_ue_procedure!(UlInformationTransferProcedure);

impl<'a, A: HandlerApi> UlInformationTransferProcedure<'a, A> {
    pub async fn run(self, ul_information_transfer: UlInformationTransfer) -> Result<()> {
        self.log_message(">> Rrc UlInformationTransfer");
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
