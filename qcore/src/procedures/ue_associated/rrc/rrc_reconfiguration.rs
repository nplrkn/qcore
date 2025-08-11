use super::prelude::*;
use asn1_per::nonempty;
use rrc::{C1_6, DlDcchMessage, UlDcchMessage, UlDcchMessageType};

impl<'a, B: RrcBase> RrcProcedure<'a, B> {
    pub async fn reconfiguration_add_session(
        &mut self,
        session: &PduSession,
        nas: Vec<u8>,
        cell_group_config: Vec<u8>,
    ) -> Result<()> {
        let rrc_reconfiguration = crate::rrc::build::reconfiguration(
            0,
            Some(nonempty![nas]),
            Some(session),
            None,
            Some(cell_group_config),
        );
        self.reconfiguration(rrc_reconfiguration).await
    }

    pub async fn reconfiguration_delete_session(
        &mut self,
        nas: Vec<u8>,
        session: &PduSession,
        cell_group_config: Option<Vec<u8>>,
    ) -> Result<()> {
        let rrc_reconfiguration = crate::rrc::build::reconfiguration(
            0,
            Some(nonempty![nas]),
            None,
            Some(session),
            cell_group_config,
        );
        self.reconfiguration(rrc_reconfiguration).await
    }

    async fn reconfiguration(&mut self, rrc_reconfiguration: Box<DlDcchMessage>) -> Result<()> {
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
        Ok(())
    }
}
