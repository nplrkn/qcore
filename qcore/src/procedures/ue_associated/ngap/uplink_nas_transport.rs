use ngap::UplinkNasTransport;

use super::super::UplinkNasProcedure;
use super::prelude::*;

define_ue_procedure!(UplinkNasTransportProcedure);

impl<'a, A: HandlerApi> UplinkNasTransportProcedure<'a, A> {
    pub async fn run(mut self, uplink_nas_transport: Box<UplinkNasTransport>) -> Result<()> {
        self.log_message(">> Ngap UplinkNasTransport");
        let nas = self.nas_decode(&uplink_nas_transport.nas_pdu.0)?;
        UplinkNasProcedure::new(self.0).run(nas).await
    }
}
