use super::UeProcedure;
use crate::{HandlerApi, PduSession};
use anyhow::{Result, bail};
use asn1_per::nonempty;
use derive_deref::{Deref, DerefMut};
use f1ap::{
    CellGroupConfig, DlUpTnlInformationToBeSetupItem, DuToCuRrcInformation, SrbId,
    UeContextSetupProcedure, UeContextSetupResponse, UpTransportLayerInformation,
};
use oxirush_nas::messages::{Nas5gsmHeader, NasPduSessionEstablishmentRequest};
use rrc::{C1_6, UlDcchMessage, UlDcchMessageType};
use xxap::{GtpTunnel, Snssai};

#[derive(Deref, DerefMut)]
pub struct SessionEstablishmentProcedure<'a, A: HandlerApi>(UeProcedure<'a, A>);

impl<'a, A: HandlerApi> SessionEstablishmentProcedure<'a, A> {
    pub fn new(ue_procedure: UeProcedure<'a, A>) -> Self {
        SessionEstablishmentProcedure(ue_procedure)
    }
    
    pub async fn run(
        &mut self,
        hdr: Nas5gsmHeader,
        _r: NasPduSessionEstablishmentRequest,
    ) -> Result<()> {
        self.log_message(">> NasPduSessionEstablishmentRequest");
        // TODO: check request
        let session_id = hdr.pdu_session_identity;
        let session = PduSession {
            id: session_id,
            snssai: Snssai(self.config().sst, None),
            userplane_info: self.api.reserve_userplane_session(&self.logger).await?,
        };

        let (cell_group_config, remote_tunnel_info) =
            self.perform_f1_ue_context_setup(&session).await?;

        let accept = crate::nas::build::pdu_session_establishment_accept(
            &session,
            hdr.procedure_transaction_identity,
        )?;
        let accept = self.ue.nas.encode(accept)?;

        self.commit_userplane_session(&session.userplane_info, remote_tunnel_info, &self.logger)
            .await?;
        self.ue.pdu_sessions.push(session);

        self.log_message("<< NasPduSessionEstablishmentAccept");
        self.perform_rrc_reconfiguration(accept, cell_group_config, session_id)
            .await
    }

    async fn perform_f1_ue_context_setup(
        &self,
        session: &PduSession,
    ) -> Result<(CellGroupConfig, GtpTunnel)> {
        let ue_context_setup_request = crate::f1ap::build::ue_context_setup_request(
            self.ue,
            self.config().ip_addr.into(),
            session,
        )?;
        self.log_message("<< UeContextSetupRequest");
        let rsp = self
            .f1ap_request::<UeContextSetupProcedure>(ue_context_setup_request, self.logger)
            .await?;
        self.log_message(">> UeContextSetupResponse");
        self.check_ue_context_setup_response(rsp)
    }

    async fn perform_rrc_reconfiguration(
        &mut self,
        nas: Vec<u8>,
        cell_group_config: CellGroupConfig,
        pdu_session_id: u8,
    ) -> Result<()> {
        let rrc_reconfiguration = crate::rrc::build::reconfiguration(
            0,
            Some(nonempty![nas]),
            cell_group_config.0,
            pdu_session_id,
        );
        self.log_message("<< RrcReconfiguration(Nas)");
        let response = self.rrc_request(SrbId(1), rrc_reconfiguration).await?;
        self.check_rrc_reconfiguration_complete(response)?;
        self.log_message(">> RrcReconfigurationComplete");
        Ok(())
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

    fn check_rrc_reconfiguration_complete(&self, message: UlDcchMessage) -> Result<()> {
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
