use super::prelude::*;
use crate::{data::PduSession, rrc_filter};
use asn1_per::nonempty;
use f1ap::SrbId;
use rrc::{C1_6, DlDcchMessage, UlDcchMessage, UlDcchMessageType};

define_ue_procedure!(RrcReconfigurationProcedure);

impl<'a, A: HandlerApi> RrcReconfigurationProcedure<'a, A> {
    pub async fn add_session(
        self,
        nas: Vec<u8>,
        session_index: usize,
        cell_group_config: Vec<u8>,
    ) -> Result<UeProcedure<'a, A>> {
        let session = &self.ue.pdu_sessions[session_index];
        let rrc_reconfiguration = crate::rrc::build::reconfiguration(
            0,
            Some(nonempty![nas]),
            Some(session),
            None,
            Some(cell_group_config),
        );
        self.run(rrc_reconfiguration).await
    }

    pub async fn delete_session(
        self,
        nas: Vec<u8>,
        session: &PduSession,
        cell_group_config: Option<Vec<u8>>,
    ) -> Result<UeProcedure<'a, A>> {
        let rrc_reconfiguration = crate::rrc::build::reconfiguration(
            0,
            Some(nonempty![nas]),
            None,
            Some(session),
            cell_group_config,
        );
        self.run(rrc_reconfiguration).await
    }

    async fn run(mut self, rrc_reconfiguration: Box<DlDcchMessage>) -> Result<UeProcedure<'a, A>> {
        self.log_message("<< Rrc Reconfiguration");
        let _response = self
            .rrc_request(
                SrbId(1),
                &rrc_reconfiguration,
                rrc_filter!(RrcReconfigurationComplete),
                "Rrc ReconfigurationComplete",
            )
            .await?;
        self.log_message(">> Rrc ReconfigurationComplete");
        Ok(self.0)
    }
}
