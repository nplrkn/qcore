use ngap::UplinkNasTransport;

use super::super::UplinkNasProcedure;
use super::prelude::*;

define_ue_procedure!(UplinkNasTransportProcedure);

impl<'a, A: HandlerApi> UplinkNasTransportProcedure<'a, A> {
    pub async fn run(self, uplink_nas_transport: Box<UplinkNasTransport>) -> Result<()> {
        self.log_message(">> Ngap UplinkNasTransport");
        UplinkNasProcedure::new(self.0)
            .run(uplink_nas_transport.nas_pdu.0)
            .await
    }
}
