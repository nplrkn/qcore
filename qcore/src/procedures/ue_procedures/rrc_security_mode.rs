use anyhow::Result;
use derive_deref::{Deref, DerefMut};
use f1ap::SrbId;
use slog::debug;

use crate::procedures::{HandlerApi, ue_procedures::UeProcedure};

#[derive(Deref, DerefMut)]
pub struct RrcSecurityModeProcedure<'a, A: HandlerApi>(UeProcedure<'a, A>);

impl<'a, A: HandlerApi> RrcSecurityModeProcedure<'a, A> {
    pub fn new(inner: UeProcedure<'a, A>) -> Self {
        RrcSecurityModeProcedure(inner)
    }

    pub async fn run(mut self) -> Result<UeProcedure<'a, A>> {
        let uplink_nas_count = self.ue.nas.ul_nas_count();
        debug!(
            self.logger,
            "Activating RRC security, uplink_nas_count: {}", uplink_nas_count
        );
        self.configure_rrc_security(uplink_nas_count);
        let r = crate::rrc::build::security_mode_command(1);
        self.log_message("<< RrcSecurityModeCommand");
        let _rrc_security_mode_complete = self.rrc_request(SrbId(1), &r).await;
        self.log_message(">> RRcSecurityModeComplete");
        Ok(self.0)
    }

    fn configure_rrc_security(&mut self, uplink_nas_count: u32) {
        // Derive Kgnb, and from that kRRCInt.

        /* TS33.501, 6.8.1.1.2.3: "The NAS (uplink and downlink) COUNTs are set to start
        values, and the start value of the uplink NAS COUNT shall be used as freshness parameter in the KgNB derivation from
        the fresh KAMF (after primary authentication) when UE receives AS SMC the KgNB is derived from the current 5G NAS
        security context, i.e., the fresh KAMF is used to derive the KgNB." */

        /* 6.8.1.1.2.2: When the UE receives the AS SMC without having received a NAS Security Mode Command after the Registration Request
        with "PDU session(s) to be re-activated", it shall use the uplink NAS COUNT of the Registration Request message that
        triggered the AS SMC to be sent as freshness parameter in the derivation of the initial KgNB/KeNB.           */
        let kgnb = security::derive_kgnb(&self.ue.kamf, uplink_nas_count);
        let krrcint = security::derive_krrcint(&kgnb);

        // Tell the PDCP layer to add NIA2 integrity protection henceforth.
        self.ue.pdcp_tx.enable_security(krrcint);
    }
}
