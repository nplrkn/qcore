use asn1_per::SerDes;
use f1ap::{DuToCuRrcContainer, InitialUlRrcMessageTransfer};
use rrc::{C1_4, UlCcchMessage, UlCcchMessageType};

use crate::procedures::ue_associated::RrcSetupProcedure;

use super::prelude::*;

define_ue_procedure!(InitialUlRrcMessageTransferProcedure);
impl<'a, A: HandlerApi> InitialUlRrcMessageTransferProcedure<'a, A> {
    pub async fn run(mut self, r: Box<InitialUlRrcMessageTransfer>) -> Result<()> {
        self.log_message(">> F1ap InitialUlRrcMessageTransfer");

        self.ue.ran_ue_id = r.gnb_du_ue_f1ap_id.0;
        self.ue.nr_cgi = Some(r.nr_cgi);
        self.ue.tac = [0, 0, 1]; // TODO

        let Some(DuToCuRrcContainer(cell_group_config)) = r.du_to_cu_rrc_container else {
            bail!("Missing DuToCuRrcContainer on initial UL RRC message")
        };

        let rrc = UlCcchMessage::from_bytes(&r.rrc_container.0)?;
        let UlCcchMessage {
            message: UlCcchMessageType::C1(C1_4::RrcSetupRequest(rrc_setup_request)),
        } = rrc
        else {
            bail!("Initial RRC message is not Rrc Setup {:?}", rrc);
        };

        RrcSetupProcedure::new(self.0)
            .run(Box::new(rrc_setup_request), cell_group_config)
            .await
    }
}
