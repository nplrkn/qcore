use super::prelude::*;
use rrc::{C1_6, UlDcchMessage, UlDcchMessageType};

impl<'a, B: RrcBase> RrcProcedure<'a, B> {
    pub async fn security_mode(&mut self, kgnb: &[u8; 32]) -> Result<()> {
        self.configure_rrc_security(kgnb);
        let r = crate::rrc::build::security_mode_command(1);
        self.log_message("<< Rrc SecurityModeCommand");

        // TODO: this is a case for a filter that fails rather than queues.
        match self
            .rrc_request(
                SrbId(1),
                &r,
                rrc_request_filter!(SecurityModeComplete, SecurityModeFailure),
                "Security mode response",
            )
            .await?
        {
            Ok(_) => {
                self.log_message(">> Rrc SecurityModeComplete");
                Ok(())
            }
            Err(_) => {
                self.log_message(">> Rrc SecurityModeFailure");
                bail!("Rrc Security Mode Failure")
            }
        }
    }

    fn configure_rrc_security(&mut self, kgnb: &[u8; 32]) {
        let krrcint = security::derive_krrcint(kgnb);

        // Tell the PDCP layer to add NIA2 integrity protection henceforth.
        self.ue.pdcp_tx.enable_security(krrcint);
    }
}
