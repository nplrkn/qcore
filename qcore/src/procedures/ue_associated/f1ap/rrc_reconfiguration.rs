use super::prelude::*;
use asn1_per::nonempty;
use f1ap::SrbId;
use rrc::{C1_6, UlDcchMessage, UlDcchMessageType};

define_ue_procedure!(RrcReconfigurationProcedure);

impl<'a, A: HandlerApi> RrcReconfigurationProcedure<'a, A> {
    pub async fn run(
        mut self,
        nas: Vec<u8>,
        session_index: usize,
        cell_group_config: Vec<u8>,
    ) -> Result<()> {
        let session = &mut self.ue.pdu_sessions[session_index];
        let rrc_reconfiguration =
            crate::rrc::build::reconfiguration(0, Some(nonempty![nas]), session, cell_group_config);
        self.log_message("<< RrcReconfiguration(Nas)");
        let response = self.rrc_request(SrbId(1), &rrc_reconfiguration).await?;
        self.check_rrc_reconfiguration_complete(&response)?;
        self.log_message(">> RrcReconfigurationComplete");
        Ok(())
    }

    fn check_rrc_reconfiguration_complete(&self, message: &UlDcchMessage) -> Result<()> {
        let UlDcchMessage {
            message: UlDcchMessageType::C1(C1_6::RrcReconfigurationComplete(_response)),
        } = message
        else {
            bail!("Expected RrcReconfigurationComplete, got {:?}", message);
        };
        // TODO: check more thoroughly
        Ok(())
    }
}
