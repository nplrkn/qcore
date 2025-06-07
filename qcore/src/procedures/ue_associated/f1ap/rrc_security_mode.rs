use super::prelude::*;
use f1ap::SrbId;
use rrc::{C1_6, UlDcchMessage, UlDcchMessageType};

define_ue_procedure!(RrcSecurityModeProcedure);

impl<'a, A: HandlerApi> RrcSecurityModeProcedure<'a, A> {
    pub async fn run(mut self, kgnb: &[u8; 32]) -> Result<UeProcedure<'a, A>> {
        self.configure_rrc_security(kgnb);
        let r = crate::rrc::build::security_mode_command(1);
        self.log_message("<< RrcSecurityModeCommand");
        let response = self.rrc_request(SrbId(1), &r).await?;
        match *response {
            UlDcchMessage {
                message: UlDcchMessageType::C1(C1_6::SecurityModeComplete(_)),
            } => {
                self.log_message(">> RrcSecurityModeComplete");
                Ok(self.0)
            }
            m => bail!("Expected Rrc SecurityModeComplete, received {:?}", m),
        }
    }

    fn configure_rrc_security(&mut self, kgnb: &[u8; 32]) {
        let krrcint = security::derive_krrcint(kgnb);

        // Tell the PDCP layer to add NIA2 integrity protection henceforth.
        self.ue.pdcp_tx.enable_security(krrcint);
    }
}
