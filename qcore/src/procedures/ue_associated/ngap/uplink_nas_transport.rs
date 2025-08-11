use super::prelude::*;
use ngap::UplinkNasTransport;

impl<'a, B: RanUeBase> NgapUeProcedure<'a, B> {
    pub async fn uplink_nas_transport(
        &mut self,
        uplink_nas_transport: Box<UplinkNasTransport>,
        core_context: &'a mut UeContext5GC,
    ) -> Result<()> {
        self.log_message(">> Ngap UplinkNasTransport");
        self.nas_procedure(core_context)
            .uplink_nas(uplink_nas_transport.nas_pdu.0)
            .await
    }
}
