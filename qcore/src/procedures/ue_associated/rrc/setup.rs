use super::prelude::*;
use rrc::{
    C1_6, CriticalExtensions22, Ng5gSTmsi, Ng5gSTmsiValue, RrcSetupComplete, RrcSetupRequest,
    UlDcchMessageType,
};

impl<'a, B: RrcBase> RrcProcedure<'a, B> {
    pub async fn setup(
        &mut self,
        _r: Box<RrcSetupRequest>,
        cell_group_config: Vec<u8>,
        core_context: &'a mut UeContext5GC,
    ) -> Result<()> {
        self.log_message(">> Rrc SetupRequest");

        let rrc_setup = crate::rrc::build::setup(0, cell_group_config);
        self.log_message("<< Rrc Setup");

        // We use a filter that allows any message because the only valid message at this point is an RrcSetupComplete
        // and we don't want to queue an unexpected message.
        // TODO: provide a different style of filter that fails rather than queues?
        let response = self.rrc_request(SrbId(0), &rrc_setup, Ok, "").await?;
        let UlDcchMessageType::C1(C1_6::RrcSetupComplete(RrcSetupComplete {
            critical_extensions: CriticalExtensions22::RrcSetupComplete(rrc_setup_complete_ies),
            ..
        })) = response.message
        else {
            bail!("Expected Rrc SetupComplete, got {:?}", response)
        };
        self.log_message(">> Rrc SetupComplete");

        let stmsi: Option<Vec<u8>> = if let Some(Ng5gSTmsiValue::Ng5gSTmsi(Ng5gSTmsi(x))) =
            rrc_setup_complete_ies.ng_5g_s_tmsi_value
        {
            Some(x.into())
        } else {
            None
        };

        self.nas_procedure(core_context)
            .initial_nas(
                rrc_setup_complete_ies.dedicated_nas_message.0,
                stmsi.as_deref(),
            )
            .await
    }
}
