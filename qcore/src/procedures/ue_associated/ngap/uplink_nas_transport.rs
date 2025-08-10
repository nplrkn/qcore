use super::prelude::*;
use crate::{data::UeContext5GC, procedures::ue_associated::NasProcedure};
use ngap::UplinkNasTransport;

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn uplink_nas_transport(
        &mut self,
        uplink_nas_transport: Box<UplinkNasTransport>,
        core_context: &mut UeContext5GC,
    ) -> Result<()> {
        self.log_message(">> Ngap UplinkNasTransport");
        NasProcedure {
            ue: core_context,
            logger: &self.logger.clone(),
            api: self,
        }
        .uplink_nas(uplink_nas_transport.nas_pdu.0)
        .await
    }
}
