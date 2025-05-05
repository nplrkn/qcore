use anyhow::{Result, anyhow, bail};
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, NasPduAddress, NasPduSessionType,
    decode_nas_5gs_message,
    messages::{NasDlNasTransport, NasPduSessionEstablishmentAccept},
};
use rrc::*;
use slog::{Logger, info, o};
use std::net::{IpAddr, Ipv4Addr};
mod build_nas;
mod build_rrc;
use crate::{DuUeContext, MockDu};

pub struct MockUe<'a> {
    imsi: String,
    du: &'a MockDu,
    pub du_ue_context: DuUeContext,
    pub ipv4_addr: Ipv4Addr,
    logger: Logger,
}

impl<'a> MockUe<'a> {
    pub async fn new(
        imsi: String,
        ue_id: u32,
        du: &'a MockDu,
        cu_ip_addr: &IpAddr,
        logger: &Logger,
    ) -> Result<Self> {
        Ok(MockUe {
            imsi,
            du,
            du_ue_context: du.new_ue_context(ue_id, cu_ip_addr).await?,
            ipv4_addr: Ipv4Addr::UNSPECIFIED,
            logger: logger.new(o!("ue" => ue_id)),
        })
    }

    pub async fn perform_rrc_setup(&mut self) -> Result<()> {
        let rrc_setup_request = build_rrc::setup_request();
        self.du
            .send_initial_ul_rrc(&self.du_ue_context, rrc_setup_request)
            .await?;
        let message = self.du.receive_rrc_dl_ccch(&mut self.du_ue_context).await?;
        let DlCcchMessageType::C1(C1_1::RrcSetup(rrc_setup)) = message else {
            bail!("Unexpected RRC message {:?}", message)
        };
        info!(&self.logger, "DlRrcMessageTransfer(RrcSetup) <<");
        let registration_request = build_nas::registration_request(&self.imsi)?;
        let rrc_setup_complete =
            build_rrc::setup_complete(rrc_setup.rrc_transaction_identifier, registration_request);
        info!(
            &self.logger,
            "Rrc SetupComplete + NAS Registration Request >>"
        );
        self.du
            .send_ul_rrc(&mut self.du_ue_context, rrc_setup_complete)
            .await
    }

    pub async fn handle_nas_authentication(&mut self) -> Result<()> {
        let _nas_authentication_request = self.receive_nas().await?;
        info!(&self.logger, "NAS Authentication request >>");
        let nas_authentication_response = build_nas::authentication_response()?;
        info!(&self.logger, "NAS Authentication response <<");
        self.send_nas(nas_authentication_response).await
    }

    pub async fn handle_nas_security_mode(&mut self) -> Result<()> {
        let _nas_security_mode_command = self.receive_nas().await?;
        info!(&self.logger, "NAS Security mode command <<");
        let nas_security_mode_complete = build_nas::security_mode_complete()?;
        info!(&self.logger, "NAS Security mode complete >>");
        self.send_nas(nas_security_mode_complete).await
    }

    pub async fn handle_rrc_security_mode(&mut self) -> Result<()> {
        let message = self.du.receive_rrc_dl_dcch(&self.du_ue_context).await?;
        let DlDcchMessageType::C1(C1_2::SecurityModeCommand(security_mode_command)) = message
        else {
            bail!("Expected security mode command - got {:?}", message)
        };
        info!(&self.logger, "Rrc SecurityModeCommand <<");
        let security_mode_complete =
            build_rrc::security_mode_complete(security_mode_command.rrc_transaction_identifier);
        info!(&self.logger, "Rrc SecurityModeComplete >>");
        self.du
            .send_ul_rrc(&mut self.du_ue_context, security_mode_complete)
            .await
    }

    pub async fn handle_nas_registration_accept(&mut self) -> Result<()> {
        let _nas_registration_accept = self.receive_nas().await?;
        info!(&self.logger, "NAS Registration Accept <<");
        let nas_registration_complete = build_nas::registration_complete()?;
        info!(&self.logger, "NAS Registration Complete >>");
        self.send_nas(nas_registration_complete).await
    }

    pub async fn send_nas_pdu_session_establishment_request(&mut self) -> Result<()> {
        let nas_session_establishment_request = build_nas::pdu_session_establishment_request()?;
        info!(&self.logger, "NAS PDU session establishment request >>");
        self.send_nas(nas_session_establishment_request).await
    }

    pub async fn handle_rrc_reconfiguration_with_session_accept(&mut self) -> Result<()> {
        let nas_bytes = self.handle_rrc_reconfiguration().await?;
        let nas = decode_nas_5gs_message(&nas_bytes)?;
        let Nas5gsMessage::SecurityProtected(_header, nas_gmm) = nas else {
            bail!("Expected security protected message, got {nas:?}")
        };
        let Nas5gsMessage::Gmm(
            _header,
            Nas5gmmMessage::DlNasTransport(NasDlNasTransport {
                payload_container, ..
            }),
        ) = *nas_gmm
        else {
            bail!("Expected NasDlNasTransport, got {nas_gmm:?}")
        };

        let nas_gsm = decode_nas_5gs_message(&payload_container.value)?;
        let Nas5gsMessage::Gsm(
            _header,
            Nas5gsmMessage::PduSessionEstablishmentAccept(NasPduSessionEstablishmentAccept {
                selected_pdu_session_type: NasPduSessionType { value: 1, .. },
                pdu_address:
                    Some(NasPduAddress {
                        value: nas_pdu_address_ie,
                        ..
                    }),
                ..
            }),
        ) = nas_gsm
        else {
            bail!("Expected NasPduSessionEstablishmentAccept, got {nas_gsm:?}");
        };

        self.ipv4_addr = Ipv4Addr::new(
            nas_pdu_address_ie[1],
            nas_pdu_address_ie[2],
            nas_pdu_address_ie[3],
            nas_pdu_address_ie[4],
        );
        Ok(())
    }

    async fn handle_rrc_reconfiguration(&mut self) -> Result<Vec<u8>> {
        let rrc = self.du.receive_rrc_dl_dcch(&self.du_ue_context).await?;
        let nas_messages = match rrc {
            DlDcchMessageType::C1(C1_2::RrcReconfiguration(RrcReconfiguration {
                critical_extensions:
                    CriticalExtensions15::RrcReconfiguration(RrcReconfigurationIEs {
                        non_critical_extension:
                            Some(RrcReconfigurationV1530IEs {
                                dedicated_nas_message_list: Some(x),
                                ..
                            }),
                        ..
                    }),
                ..
            })) => {
                info!(
                    &self.logger,
                    "DlRrcMessageTransfer(RrcReconfiguration(Nas)) <<"
                );
                Ok(x)
            }
            _ => Err(anyhow!(
                "Couldn't find NAS message list in Rrc Reconfiguration"
            )),
        }?;
        let nas = nas_messages.head.0;

        let rrc_reconfiguration_complete =
            build_rrc::reconfiguration_complete(RrcTransactionIdentifier(0));
        info!(&self.logger, "Rrc ReconfigurationComplete >>");
        self.du
            .send_ul_rrc(&mut self.du_ue_context, rrc_reconfiguration_complete)
            .await?;

        Ok(nas)
    }

    async fn send_nas(&mut self, nas_bytes: Vec<u8>) -> Result<()> {
        let rrc = build_rrc::ul_information_transfer(nas_bytes);
        info!(&self.logger, "UlInformationTransfer(Nas) >>");
        self.du.send_ul_rrc(&mut self.du_ue_context, rrc).await
    }

    pub async fn receive_nas(&self) -> Result<Vec<u8>> {
        match self.du.receive_rrc_dl_dcch(&self.du_ue_context).await? {
            DlDcchMessageType::C1(C1_2::DlInformationTransfer(DlInformationTransfer {
                critical_extensions:
                    CriticalExtensions4::DlInformationTransfer(DlInformationTransferIEs {
                        dedicated_nas_message: Some(x),
                        ..
                    }),
                ..
            })) => {
                info!(
                    &self.logger,
                    "DlRrcMessageTransfer(DlInformationTransfer(Nas)) <<"
                );
                Ok(x.0)
            }
            x => Err(anyhow!("Unexpected RRC message {:?}", x)),
        }
    }

    pub async fn send_nas_deregistration_request(&mut self) -> Result<()> {
        let nas_deregistration_request = build_nas::deregistration_request()?;
        info!(&self.logger, "NAS deregistration request >>");
        self.send_nas(nas_deregistration_request).await
    }

    pub async fn send_f1u_data_packet(
        &self,
        dst_ip: &Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<()> {
        self.du
            .send_f1u_data_packet(
                &self.du_ue_context,
                &self.ipv4_addr,
                dst_ip,
                src_port,
                dst_port,
            )
            .await
    }

    pub async fn recv_f1u_data_packet(&self) -> Result<Vec<u8>> {
        self.du.recv_f1u_data_packet(&self.du_ue_context).await
    }
}
