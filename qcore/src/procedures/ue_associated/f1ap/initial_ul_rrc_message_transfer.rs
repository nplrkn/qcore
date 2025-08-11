use super::prelude::*;
use asn1_per::SerDes;
use f1ap::{DuToCuRrcContainer, InitialUlRrcMessageTransfer};
use rrc::{C1_4, UlCcchMessage, UlCcchMessageType};

impl<'a, B: RanUeBase> F1apUeProcedure<'a, B> {
    pub async fn initial_ul_rrc_message_transfer(
        &mut self,
        r: Box<InitialUlRrcMessageTransfer>,
        rrc_context: &'a mut UeContextRrc,
        core_context: &'a mut UeContext5GC,
    ) -> Result<()> {
        self.log_message(">> F1ap InitialUlRrcMessageTransfer");

        self.ue.remote_ran_ue_id = r.gnb_du_ue_f1ap_id.0;
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

        self.rrc_procedure(rrc_context)
            .setup(Box::new(rrc_setup_request), cell_group_config, core_context)
            .await
    }
}
