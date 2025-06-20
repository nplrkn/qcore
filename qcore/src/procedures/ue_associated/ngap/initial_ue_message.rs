use super::prelude::*;
use crate::procedures::ue_associated::UplinkNasProcedure;
use ngap::InitialUeMessage;

define_ue_procedure!(InitialUeMessageProcedure);

impl<'a, A: HandlerApi> InitialUeMessageProcedure<'a, A> {
    pub async fn run(mut self, r: Box<InitialUeMessage>) -> Result<()> {
        self.log_message(">> Ngap InitialUeMessage");
        let nas = self.nas_decode(&r.nas_pdu.0)?;
        UplinkNasProcedure::new(self.0).run(nas).await
    }
}
