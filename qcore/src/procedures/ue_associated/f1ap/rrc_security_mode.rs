use super::prelude::*;
use f1ap::SrbId;

define_ue_procedure!(RrcSecurityModeProcedure);

impl<'a, A: HandlerApi> RrcSecurityModeProcedure<'a, A> {
    pub async fn run(mut self, kgnb: &[u8; 32]) -> Result<UeProcedure<'a, A>> {
        self.configure_rrc_security(kgnb);
        let r = crate::rrc::build::security_mode_command(1);
        self.log_message("<< RrcSecurityModeCommand");
        let _rrc_security_mode_complete = self.rrc_request(SrbId(1), &r).await;
        self.log_message(">> RRcSecurityModeComplete");
        Ok(self.0)
    }

    fn configure_rrc_security(&mut self, kgnb: &[u8; 32]) {
        let krrcint = security::derive_krrcint(kgnb);

        // Tell the PDCP layer to add NIA2 integrity protection henceforth.
        self.ue.pdcp_tx.enable_security(krrcint);
    }
}
