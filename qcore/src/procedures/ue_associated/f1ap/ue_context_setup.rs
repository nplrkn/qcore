use super::prelude::*;
use f1ap::{
    CellGroupConfig, DlUpTnlInformationToBeSetupItem, DuToCuRrcInformation, UeContextSetupResponse,
    UpTransportLayerInformation,
};
use xxap::GtpTunnel;

impl<'a, B: RanUeBase> F1apUeProcedure<'a, B> {
    pub async fn ue_context_setup(&mut self, session: &mut PduSession) -> Result<Vec<u8>> {
        // TODO - support >1 session
        let ue_context_setup_request = crate::f1ap::build::ue_context_setup_request(
            self.ue,
            self.api.config().ip_addr.into(),
            session,
        )?;
        self.log_message("<< F1ap UeContextSetupRequest");
        let rsp = self
            .api
            .xxap_request::<f1ap::UeContextSetupProcedure>(ue_context_setup_request, &self.logger)
            .await?;
        self.log_message(">> F1ap UeContextSetupResponse");

        // TODO: commonize setting of remote tunnel info and error handling in Ngap PduSessionResourceSetupResponse,
        // Ngap InitialContextSetupResponse and F1ap UeContextSetupResponse
        let (cell_group_config, gtp_tunnel) = self.check_ue_context_setup_response(rsp)?;
        session.userplane_info.remote_tunnel_info = Some(gtp_tunnel);
        self.api
            .commit_userplane_session(&session.userplane_info, &self.logger)
            .await?;

        Ok(cell_group_config.0)
    }

    fn check_ue_context_setup_response(
        &self,
        ue_context_setup_response: UeContextSetupResponse,
    ) -> Result<(CellGroupConfig, GtpTunnel)> {
        // TODO further checking of message - e.g. was SRB2 confirmed?

        // TS38.473, 8.3.1.2: "If the CellGroupConfig IE is included in the DU to CU RRC Information IE contained
        // in the UE CONTEXT SETUP RESPONSE message, the gNB-CU shall perform RRC Reconfiguration or RRC connection
        // resume as described in TS 38.331 [8]. The CellGroupConfig IE shall transparently be signaled to the UE
        //as specified in TS 38.331 [8]."
        let UeContextSetupResponse {
            du_to_cu_rrc_information:
                DuToCuRrcInformation {
                    cell_group_config, ..
                },
            drbs_setup_list: Some(drbs_setup_list),
            ..
        } = ue_context_setup_response
        else {
            bail!("UeContextSetupResponse missed expected information");
        };
        let DlUpTnlInformationToBeSetupItem {
            dl_up_tnl_information: UpTransportLayerInformation::GtpTunnel(remote_tunnel_info),
        } = drbs_setup_list
            .0
            .head
            .dl_up_tnl_information_to_be_setup_list
            .0
            .head;

        Ok((cell_group_config, remote_tunnel_info))
    }
}
