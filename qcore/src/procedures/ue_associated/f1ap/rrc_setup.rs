use super::prelude::*;
use crate::procedures::ue_associated::UplinkNasProcedure;
use asn1_per::SerDes;
use f1ap::{DuToCuRrcContainer, InitialUlRrcMessageTransfer, SrbId};
use rrc::{
    C1_4, C1_6, CriticalExtensions22, RrcSetupComplete, RrcSetupRequest, UlCcchMessage,
    UlCcchMessageType, UlDcchMessage, UlDcchMessageType,
};

define_ue_procedure!(RrcSetupProcedure);

impl<'a, A: HandlerApi> RrcSetupProcedure<'a, A> {
    pub async fn run(mut self, r: Box<InitialUlRrcMessageTransfer>) -> Result<()> {
        self.ue.ran_ue_id = r.gnb_du_ue_f1ap_id.0;
        self.ue.nr_cgi = Some(r.nr_cgi.clone());
        let nas_bytes = self.handle_rrc_setup(r).await?;
        let nas = self.nas_decode(&nas_bytes)?;
        UplinkNasProcedure::new(self.0).run(nas).await
    }

    async fn handle_rrc_setup(&mut self, r: Box<InitialUlRrcMessageTransfer>) -> Result<Vec<u8>> {
        let cell_group_config = self.check_initial_transfer(*r)?;
        self.log_message(">> RrcSetupRequest");
        let rrc_setup = crate::rrc::build::setup(0, cell_group_config);
        self.log_message("<< RrcSetup");

        // We use a filter that allows any message because the only valid message at this point is an RrcSetupComplete
        // and we don't want to queue an unexpected message.
        // TODO: provide a different style of filter that fails rather than queues?
        let response = self.rrc_request(SrbId(0), &rrc_setup, Ok, "").await?;
        let nas_bytes = self.check_rrc_setup_complete(response)?;
        self.log_message(">> RrcSetupComplete");
        Ok(nas_bytes)
    }

    fn check_initial_transfer(&self, r: InitialUlRrcMessageTransfer) -> Result<Vec<u8>> {
        let Some(DuToCuRrcContainer(cell_group_config)) = r.du_to_cu_rrc_container else {
            bail!("Missing DuToCuRrcContainer on initial UL RRC message")
        };

        let _rrc_setup_request = self.check_rrc_setup_request(&r.rrc_container.0)?;
        Ok(cell_group_config)
    }

    fn check_rrc_setup_request(&self, message: &[u8]) -> Result<RrcSetupRequest> {
        match UlCcchMessage::from_bytes(message)? {
            UlCcchMessage {
                message: UlCcchMessageType::C1(C1_4::RrcSetupRequest(x)),
            } => Ok(x),
            m => bail!("Initial RRC message is not Rrc Setup {:?}", m),
        }
    }

    fn check_rrc_setup_complete(&self, m: Box<UlDcchMessage>) -> Result<Vec<u8>> {
        let UlDcchMessageType::C1(C1_6::RrcSetupComplete(RrcSetupComplete {
            critical_extensions: CriticalExtensions22::RrcSetupComplete(rrc_setup_complete_ies),
            ..
        })) = m.message
        else {
            bail!("Expected Rrc Setup complete, got {:?}", m)
        };
        Ok(rrc_setup_complete_ies.dedicated_nas_message.0)
    }
}
