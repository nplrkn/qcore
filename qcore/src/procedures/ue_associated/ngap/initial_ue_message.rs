use super::super::RegistrationProcedure;
use super::prelude::*;
use crate::expect_nas;
use ngap::InitialUeMessage;

define_ue_procedure!(InitialUeMessageProcedure);

impl<'a, A: HandlerApi> InitialUeMessageProcedure<'a, A> {
    pub async fn run(mut self, r: Box<InitialUeMessage>) -> Result<()> {
        let nas_bytes = r.nas_pdu.0;
        if let Ok((nas_message, security_header)) = self.nas_decode_with_security_header(&nas_bytes)
        {
            if let Ok(registration_request) = expect_nas!(RegistrationRequest, nas_message) {
                RegistrationProcedure::new(self.0)
                    .run(Box::new(registration_request), security_header)
                    .await?;
            }
        }

        Ok(())
    }
}
