use crate::{
    DuUeContext, MockDu, MockUe,
    mock_ue::{Transport, build_rrc},
    packet::Packet,
};
use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use rrc::*;
use slog::{Logger, info};
use std::{
    net::{IpAddr, Ipv4Addr},
    ops::{Deref, DerefMut},
};

pub struct MockUeF1ap<'a> {
    base: MockUe<UeF1apMode<'a>>,
}
impl<'a> Deref for MockUeF1ap<'a> {
    type Target = MockUe<UeF1apMode<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}
impl DerefMut for MockUeF1ap<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}
pub struct UeF1apMode<'a> {
    du: &'a MockDu,
    pub du_ue_context: DuUeContext,
}
impl<'a> UeF1apMode<'a> {
    pub fn new(du: &'a MockDu, du_ue_context: DuUeContext) -> Self {
        UeF1apMode { du, du_ue_context }
    }

    async fn send_initial_ul_rrc(&mut self, rrc_setup_request: UlCcchMessage) -> Result<()> {
        self.du
            .send_initial_ul_rrc(&mut self.du_ue_context, rrc_setup_request)
            .await
    }

    async fn receive_rrc_dl_ccch(&mut self) -> Result<Box<DlCcchMessageType>> {
        self.du.receive_rrc_dl_ccch(&mut self.du_ue_context).await
    }

    async fn send_ul_rrc(&mut self, rrc: &UlDcchMessage) -> Result<()> {
        self.du.send_ul_rrc(&mut self.du_ue_context, rrc).await
    }

    async fn receive_rrc_dl_dcch(&mut self) -> Result<Box<DlDcchMessageType>> {
        self.du.receive_rrc_dl_dcch(&mut self.du_ue_context).await
    }
}

#[async_trait]
impl<'a> Transport for UeF1apMode<'a> {
    async fn send_nas(&mut self, nas_bytes: Vec<u8>, logger: &Logger) -> Result<()> {
        let rrc = build_rrc::ul_information_transfer(nas_bytes);
        info!(logger, "UlInformationTransfer(Nas) >>");
        self.du.send_ul_rrc(&mut self.du_ue_context, &rrc).await
    }

    async fn receive_nas(&mut self, logger: &Logger) -> Result<Vec<u8>> {
        match *self.du.receive_rrc_dl_dcch(&mut self.du_ue_context).await? {
            DlDcchMessageType::C1(C1_2::DlInformationTransfer(DlInformationTransfer {
                critical_extensions:
                    CriticalExtensions4::DlInformationTransfer(DlInformationTransferIEs {
                        dedicated_nas_message: Some(x),
                        ..
                    }),
                ..
            })) => {
                info!(
                    logger,
                    "DlRrcMessageTransfer(DlInformationTransfer(Nas)) <<"
                );
                Ok(x.0)
            }
            x => Err(anyhow!("Unexpected RRC message {:?}", x)),
        }
    }

    async fn send_userplane_packet(
        &self,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<()> {
        let packet = Packet::new_ue_udp(src_ip, dst_ip, src_port, dst_port);
        self.du
            .send_f1u_data_packet(&self.du_ue_context, packet)
            .await
    }
    async fn receive_userplane_packet(&self) -> Result<Vec<u8>> {
        self.du.recv_f1u_data_packet(&self.du_ue_context).await
    }
}

impl<'a> MockUeF1ap<'a> {
    pub async fn new(
        imsi: String,
        ue_id: u32,
        du: &'a MockDu,
        cu_ip_addr: &IpAddr,
        logger: &Logger,
    ) -> Result<Self> {
        let transport = UeF1apMode {
            du,
            du_ue_context: du.new_ue_context(ue_id, cu_ip_addr).await?,
        };
        Ok(MockUeF1ap {
            base: MockUe::new(imsi, ue_id, transport, logger),
        })
    }

    pub fn du_ue_context(&mut self) -> &mut DuUeContext {
        &mut self.base.transport.du_ue_context
    }

    pub async fn perform_rrc_setup(&mut self) -> Result<()> {
        let rrc_setup_request = build_rrc::setup_request();
        self.transport
            .send_initial_ul_rrc(rrc_setup_request)
            .await?;
        let message = self.transport.receive_rrc_dl_ccch().await?;
        let DlCcchMessageType::C1(C1_1::RrcSetup(rrc_setup)) = *message else {
            bail!("Unexpected RRC message {:?}", message)
        };
        info!(&self.logger, "DlRrcMessageTransfer(RrcSetup) <<");

        // This currently assumes that the UE wants to register.
        let registration_request = self.build_register_request()?;
        let rrc_setup_complete =
            build_rrc::setup_complete(rrc_setup.rrc_transaction_identifier, registration_request);
        info!(
            &self.logger,
            "Rrc SetupComplete + NAS Registration Request >>"
        );
        self.transport.send_ul_rrc(&rrc_setup_complete).await
    }

    pub async fn handle_rrc_security_mode(&mut self) -> Result<()> {
        let message = self.transport.receive_rrc_dl_dcch().await?;
        let DlDcchMessageType::C1(C1_2::SecurityModeCommand(security_mode_command)) = *message
        else {
            bail!("Expected security mode command - got {:?}", message)
        };
        info!(&self.logger, "Rrc SecurityModeCommand <<");
        let security_mode_complete = Box::new(build_rrc::security_mode_complete(
            security_mode_command.rrc_transaction_identifier,
        ));
        info!(&self.logger, "Rrc SecurityModeComplete >>");
        self.transport.send_ul_rrc(&security_mode_complete).await
    }

    pub async fn handle_rrc_reconfiguration_with_session_accept(&mut self) -> Result<()> {
        let rrc = self.transport.receive_rrc_dl_dcch().await?;
        let nas = self.handle_rrc_reconfiguration(rrc, Some(1), None).await?;
        self.handle_session_accept(nas)
    }

    pub async fn handle_rrc_reconfiguration_with_session_release(&mut self) -> Result<()> {
        let rrc = self.transport.receive_rrc_dl_dcch().await?;
        let nas = self.handle_rrc_reconfiguration(rrc, None, Some(1)).await?;
        self.handle_session_release(nas).await
    }

    async fn handle_rrc_reconfiguration(
        &mut self,
        rrc: Box<DlDcchMessageType>,
        added_drb_id: Option<u8>,
        released_drb_id: Option<u8>,
    ) -> Result<Vec<u8>> {
        let DlDcchMessageType::C1(C1_2::RrcReconfiguration(RrcReconfiguration {
            critical_extensions:
                CriticalExtensions15::RrcReconfiguration(RrcReconfigurationIEs {
                    radio_bearer_config:
                        Some(RadioBearerConfig {
                            drb_to_add_mod_list,
                            drb_to_release_list,
                            ..
                        }),
                    non_critical_extension:
                        Some(RrcReconfigurationV1530IEs {
                            dedicated_nas_message_list: Some(nas_messages),
                            ..
                        }),
                    ..
                }),
            ..
        })) = *rrc
        else {
            bail!("Couldn't find NAS message list or RadioBearerConfig in Rrc Reconfiguration")
        };
        info!(
            &self.logger,
            "DlRrcMessageTransfer(RrcReconfiguration(Nas)) <<"
        );

        match (added_drb_id, drb_to_add_mod_list) {
            (Some(x), Some(y)) => assert_eq!(x, y.0.first().drb_identity.0),
            (None, None) => (),
            _ => bail!("Added DRBs unexpected"),
        }
        match (released_drb_id, drb_to_release_list) {
            (Some(x), Some(y)) => assert_eq!(x, y.0.first().0),
            (None, None) => (),
            _ => bail!("Released DRBs unexpected"),
        }

        let nas = nas_messages.head.0;
        let rrc_reconfiguration_complete = Box::new(build_rrc::reconfiguration_complete(
            RrcTransactionIdentifier(0),
        ));
        info!(&self.logger, "Rrc ReconfigurationComplete >>");
        self.transport
            .send_ul_rrc(&rrc_reconfiguration_complete)
            .await?;

        Ok(nas)
    }
}
