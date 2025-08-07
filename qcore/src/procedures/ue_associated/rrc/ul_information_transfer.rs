use super::prelude::*;
use crate::{data::UeContext5GC, procedures::ue_associated::NasProcedure};
use rrc::{
    CriticalExtensions37, DedicatedNasMessage, UlInformationTransfer, UlInformationTransferIEs,
};

impl<'a, B: RrcBase> RrcProcedure<'a, B> {
    pub async fn ul_information_transfer(
        &mut self,
        ul_information_transfer: UlInformationTransfer,
        core_context: &mut UeContext5GC,
    ) -> Result<()> {
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

        NasProcedure {
            ue: core_context,
            logger: &self.logger.clone(),
            api: self,
        }
        .uplink_nas(nas_bytes)
        .await
    }
}
