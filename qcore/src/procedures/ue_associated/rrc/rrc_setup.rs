use super::prelude::*;
use crate::procedures::ue_associated::UplinkNasProcedure;
use f1ap::SrbId;
use rrc::{C1_6, CriticalExtensions22, RrcSetupComplete, RrcSetupRequest, UlDcchMessageType};

define_ue_procedure!(RrcSetupProcedure);

impl<'a, A: HandlerApi> RrcSetupProcedure<'a, A> {
    pub async fn run(mut self, _r: Box<RrcSetupRequest>, cell_group_config: Vec<u8>) -> Result<()> {
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
            bail!("Expected Rrc Setup complete, got {:?}", response)
        };

        self.log_message(">> Rrc SetupComplete");
        let nas = self.nas_decode(&rrc_setup_complete_ies.dedicated_nas_message.0)?;
        UplinkNasProcedure::new(self.0).run(nas).await
    }
}
