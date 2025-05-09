//! mock_du - enables a test script to assume the role of the GNB-DU on the F1 reference point

use super::userplane::MockUserplane;
use crate::mock::{Mock, Pdu, ReceivedPdu};
use anyhow::{Result, anyhow, bail, ensure};
use asn1_per::SerDes;
use async_net::IpAddr;
use f1ap::*;
use pdcp::{PdcpPdu, PdcpTx};
use rrc::{
    DlCcchMessage, DlCcchMessageType, DlDcchMessage, DlDcchMessageType, UlCcchMessage,
    UlDcchMessage,
};
use slog::{Logger, debug, info, o};
use std::{
    net::Ipv4Addr,
    ops::{Deref, DerefMut},
};
use xxap::*;
mod build_f1ap;

const F1AP_SCTP_PPID: u32 = 62;
const F1AP_BIND_PORT: u16 = 38472;

impl Pdu for F1apPdu {}

pub struct MockDu {
    mock: Mock<F1apPdu>,
    local_ip: String,
    userplane: MockUserplane,
}

pub struct UeContext {
    ue_id: u32,
    gnb_cu_ue_f1ap_id: Option<GnbCuUeF1apId>,
    pub binding: Binding,
    drb: Option<Drb>,
    pdcp_tx: PdcpTx,
}

pub struct Drb {
    remote_tunnel_info: GtpTunnel,
    local_teid: GtpTeid,
    drb_id: DrbId,
}

impl Deref for MockDu {
    type Target = Mock<F1apPdu>;

    fn deref(&self) -> &Self::Target {
        &self.mock
    }
}

impl DerefMut for MockDu {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mock
    }
}

impl MockDu {
    pub async fn new(local_ip: &str, logger: &Logger) -> Result<MockDu> {
        let logger = logger.new(o!("du" => 1));
        let mock = Mock::new(logger.clone()).await;
        Ok(MockDu {
            mock,
            local_ip: local_ip.to_string(),
            userplane: MockUserplane::new(local_ip, logger.clone()).await?,
        })
    }

    pub async fn terminate(self) {
        self.mock.terminate().await
    }

    pub async fn new_ue_context(&self, ue_id: u32, worker_ip: &IpAddr) -> Result<UeContext> {
        Ok(UeContext {
            ue_id,
            binding: self
                .transport
                .new_ue_binding_from_ip(&worker_ip.to_string())
                .await?,
            gnb_cu_ue_f1ap_id: None,
            drb: None,
            pdcp_tx: PdcpTx::default(),
        })
    }

    pub async fn perform_f1_setup(&mut self, worker_ip: &IpAddr) -> Result<()> {
        let transport_address = format!("{}:{}", worker_ip, F1AP_BIND_PORT);
        let bind_address = self.local_ip.clone();
        info!(self.logger, "Connect to CU {}", transport_address);
        self.connect(&transport_address, &bind_address, F1AP_SCTP_PPID)
            .await;
        let pdu = build_f1ap::f1_setup_request();
        info!(self.logger, "F1SetupRequest >>");
        self.send(pdu, None).await;
        self.receive_f1_setup_response().await
    }

    async fn receive_f1_setup_response(&self) -> Result<()> {
        let pdu = self.receive_pdu().await?;
        let F1apPdu::SuccessfulOutcome(SuccessfulOutcome::F1SetupResponse(_)) = pdu else {
            bail!("Unexpected F1ap message {:?}", pdu)
        };
        info!(self.logger, "F1SetupResponse <<");
        Ok(())
    }

    pub async fn perform_f1_removal(&mut self) -> Result<()> {
        let pdu = build_f1ap::f1_removal_request();
        info!(self.logger, "F1RemovalRequest >>");
        self.send(pdu, None).await;
        self.receive_f1_removal_response().await
    }

    async fn receive_f1_removal_response(&self) -> Result<()> {
        let pdu = self.receive_pdu().await?;
        let F1apPdu::SuccessfulOutcome(SuccessfulOutcome::F1RemovalResponse(_)) = pdu else {
            bail!("Unexpected F1ap message {:?}", pdu)
        };
        info!(self.logger, "F1RemovalResponse <<");
        Ok(())
    }

    pub async fn send_initial_ul_rrc(
        &self,
        ue: &UeContext,
        initial_rrc: UlCcchMessage,
    ) -> Result<()> {
        let f1_indication =
            build_f1ap::initial_ul_rrc_message_transfer(ue.ue_id, initial_rrc.into_bytes()?);

        info!(
            self.logger,
            "InitialUlRrcMessageTransfer(RrcSetupRequest) >>"
        );
        self.send(f1_indication, Some(ue.binding.assoc_id)).await;

        Ok(())
    }

    pub async fn receive_rrc_dl_ccch(&self, ue: &mut UeContext) -> Result<DlCcchMessageType> {
        // Receive DL Rrc Message Transfer and extract RRC Setup
        let pdu = self.receive_pdu().await?;
        let F1apPdu::InitiatingMessage(InitiatingMessage::DlRrcMessageTransfer(
            dl_rrc_message_transfer,
        )) = pdu
        else {
            bail!("Unexpected F1ap message {:?}", pdu)
        };

        // A Rrc Setup flows as a DlCcchMessage on SRB0 (non PDCP encapsulated).  Check this is indeed for SRB0.
        assert_eq!(dl_rrc_message_transfer.srb_id.0, 0);

        ue.gnb_cu_ue_f1ap_id = Some(dl_rrc_message_transfer.gnb_cu_ue_f1ap_id);
        let rrc_message_bytes = dl_rrc_message_transfer.rrc_container.0;

        Ok(DlCcchMessage::from_bytes(&rrc_message_bytes)?.message)
    }

    pub async fn send_ul_rrc(&self, ue: &mut UeContext, rrc: UlDcchMessage) -> Result<()> {
        let gnb_cu_ue_f1ap_id = ue.gnb_cu_ue_f1ap_id.unwrap();

        // Encapsulate RRC message in PDCP PDU.
        let rrc_bytes = rrc.into_bytes()?;
        let srb_id = 0; // TODO
        let pdcp_pdu = ue.pdcp_tx.encode(srb_id, rrc_bytes);

        // Wrap it in an UL Rrc Message Transfer
        let f1_indication =
            build_f1ap::ul_rrc_message_transfer(gnb_cu_ue_f1ap_id, ue.ue_id, pdcp_pdu.into());

        self.send(f1_indication, Some(ue.binding.assoc_id)).await;
        Ok(())
    }

    pub async fn receive_rrc_dl_dcch(&self, ue: &UeContext) -> Result<DlDcchMessageType> {
        let ReceivedPdu { pdu, assoc_id } = self.receive_pdu_with_assoc_id().await.unwrap();

        // Check that the PDU arrived on the expected binding.
        assert_eq!(assoc_id, ue.binding.assoc_id);

        let F1apPdu::InitiatingMessage(InitiatingMessage::DlRrcMessageTransfer(
            dl_rrc_message_transfer,
        )) = pdu
        else {
            bail!("Unexpected F1ap message {:?}", pdu)
        };

        assert_eq!(dl_rrc_message_transfer.gnb_du_ue_f1ap_id.0, ue.ue_id);

        // TODO: check UE context to see if SRB2 is set up.  If so this should arrive on
        // SRB2 rather than SRB1.
        assert_eq!(dl_rrc_message_transfer.srb_id.0, 1);

        let pdcp_pdu = PdcpPdu(dl_rrc_message_transfer.rrc_container.0);
        let rrc_message_bytes = pdcp_pdu.view_inner()?;
        let m = DlDcchMessage::from_bytes(rrc_message_bytes)?;
        Ok(m.message)
    }

    pub async fn handle_f1_ue_context_setup(&self, ue: &mut UeContext) -> Result<()> {
        let ReceivedPdu { pdu, assoc_id } = self.receive_pdu_with_assoc_id().await?;
        self.check_and_store_ue_context_setup_request(pdu, ue)?;
        info!(&self.logger, "UeContextSetupRequest <<");
        let ue_setup_response = build_f1ap::ue_context_setup_response(ue, &self.local_ip)?;
        info!(&self.logger, "UeContextSetupResponse >>");
        self.send(ue_setup_response, Some(assoc_id)).await;

        Ok(())
    }

    fn check_and_store_ue_context_setup_request(
        &self,
        pdu: F1apPdu,
        ue: &mut UeContext,
    ) -> Result<()> {
        let F1apPdu::InitiatingMessage(InitiatingMessage::UeContextSetupRequest(ue_setup_request)) =
            pdu
        else {
            bail!("Unexpected F1ap message {:?}", pdu)
        };

        ensure!(
            matches!(ue_setup_request.gnb_du_ue_f1ap_id, Some(GnbDuUeF1apId(x)) if x == ue.ue_id),
            "Bad Ue Id"
        );
        // TODO - SRB2 should also be set up .  Enforce this.  See 38.331, 5.3.1.1:
        // "A configuration with SRB2 without DRB or with DRB without SRB2 is not supported
        // (i.e., SRB2 and at least one DRB must be configured in the same RRC Reconfiguration
        // message, and it is not allowed to release all the DRBs without releasing the RRC
        // Connection)."

        ensure!(ue.drb.is_none());
        let Some(drbs_to_be_setup_list) = ue_setup_request.drbs_to_be_setup_list else {
            bail!("No Drbs supplied")
        };

        let first_drb = &drbs_to_be_setup_list.0[0];
        let first_tnl_of_first_drb = &first_drb.ul_up_tnl_information_to_be_setup_list.0[0];
        let UpTransportLayerInformation::GtpTunnel(remote_tunnel_info) =
            &first_tnl_of_first_drb.ul_up_tnl_information;

        // Check we have been given a real IP address.
        let Ok(_ip_addr) = IpAddr::try_from(remote_tunnel_info.transport_layer_address.clone())
        else {
            bail!(
                "Bad remote transport layer address in {:?}",
                first_tnl_of_first_drb
            );
        };

        ue.drb = Some(Drb {
            drb_id: first_drb.drb_id,
            remote_tunnel_info: remote_tunnel_info.clone(),
            local_teid: GtpTeid(rand::random()),
        });

        Ok(())
    }

    pub async fn send_ue_context_release_request(&self, ue: &UeContext) -> Result<()> {
        let pdu = build_f1ap::ue_context_release_request(ue);
        info!(self.logger, "UeContextReleaseRequest >>");
        self.send(pdu, Some(ue.binding.assoc_id)).await;
        Ok(())
    }

    pub async fn handle_ue_context_release(&self, ue: &UeContext) -> Result<()> {
        // Receive release command
        let ReceivedPdu { pdu, assoc_id } = self.receive_pdu_with_assoc_id().await?;
        let F1apPdu::InitiatingMessage(InitiatingMessage::UeContextReleaseCommand(r)) = pdu else {
            bail!("Unexpected F1ap message {:?}", pdu)
        };
        info!(&self.logger, "UeContextReleaseCommand <<");

        ensure!(ue.ue_id == r.gnb_du_ue_f1ap_id.0);

        // Send release complete
        let ue_release_complete = F1apPdu::SuccessfulOutcome(
            SuccessfulOutcome::UeContextReleaseComplete(UeContextReleaseComplete {
                gnb_cu_ue_f1ap_id: r.gnb_cu_ue_f1ap_id,
                gnb_du_ue_f1ap_id: r.gnb_du_ue_f1ap_id,
                criticality_diagnostics: None,
            }),
        );

        info!(&self.logger, "UeContextReleaseComplete >>");
        self.send(ue_release_complete, Some(assoc_id)).await;
        Ok(())
    }

    pub async fn handle_cu_configuration_update(
        &mut self,
        expected_addr_string: &str,
    ) -> Result<()> {
        let expected_address = expected_addr_string.try_into()?;
        let (transaction_id, assoc_id) = self
            .receive_gnb_cu_configuration_update(&expected_address)
            .await?;
        let transport_address = format!("{}:{}", expected_addr_string, F1AP_BIND_PORT);
        info!(self.logger, "Connect to CU {}", transport_address);
        self.connect(&transport_address, "0.0.0.0", F1AP_SCTP_PPID)
            .await;
        let pdu = build_f1ap::build_gnb_cu_configuration_update_acknowledge(
            transaction_id,
            expected_address,
        );
        info!(self.logger, "GnbCuConfigurationUpdateAcknowledge >>");
        self.send(pdu, Some(assoc_id)).await;
        Ok(())
    }

    async fn receive_gnb_cu_configuration_update(
        &self,
        expected_address: &TransportLayerAddress,
    ) -> Result<(TransactionId, u32)> {
        debug!(self.logger, "Wait for Cu Configuration Update");
        let ReceivedPdu { pdu, assoc_id } = self.receive_pdu_with_assoc_id().await?;

        let F1apPdu::InitiatingMessage(InitiatingMessage::GnbCuConfigurationUpdate(
            cu_configuration_update,
        )) = pdu
        else {
            bail!("Expected GnbCuConfigurationUpdate, got {:?}", pdu)
        };
        info!(self.logger, "GnbCuConfigurationUpdate <<");

        let gnb_cu_tnl_association_to_add_list = cu_configuration_update
            .gnb_cu_tnl_association_to_add_list
            .expect("Expected gnb_cu_cp_tnla_to_add_list to be present");
        match &gnb_cu_tnl_association_to_add_list
            .0
            .first()
            .tnl_association_transport_layer_address
        {
            CpTransportLayerAddress::EndpointIpAddress(x) => {
                assert_eq!(x.0, expected_address.0);
            }
            CpTransportLayerAddress::EndpointIpAddressAndPort(_) => {
                panic!("Alsoran CU-CP doesn't specify a port")
            }
        };

        Ok((cu_configuration_update.transaction_id, assoc_id))
    }

    pub async fn perform_du_configuration_update(&self) -> Result<()> {
        let pdu = build_f1ap::gnb_du_configuration_update();
        info!(self.logger, "GnbDuConfigurationUpdate >>");
        self.send(pdu, None).await;
        let pdu = self.receive_pdu().await?;
        let F1apPdu::SuccessfulOutcome(SuccessfulOutcome::GnbDuConfigurationUpdateAcknowledge(_)) =
            pdu
        else {
            bail!("Unexpected F1ap message {:?}", pdu)
        };
        info!(self.logger, "GnbDuConfigurationUpdateAcknowledge <<");
        Ok(())
    }

    pub async fn send_f1u_data_packet(
        &self,
        ue: &UeContext,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<()> {
        let drb = ue.drb.as_ref().ok_or(anyhow!("No pdu session"))?;

        let GtpTunnel {
            transport_layer_address,
            gtp_teid,
        } = &drb.remote_tunnel_info;

        let transport_layer_address = transport_layer_address.clone().try_into()?;
        let src_ip = src_ip.octets();
        let dst_ip = dst_ip.octets();
        let src_port = src_port.to_be_bytes();
        let dst_port = dst_port.to_be_bytes();
        let ipv4_udp_address_bytes = [
            src_ip[0],
            src_ip[1],
            src_ip[2],
            src_ip[3],
            dst_ip[0],
            dst_ip[1],
            dst_ip[2],
            dst_ip[3],
            src_port[0],
            src_port[1],
            dst_port[0],
            dst_port[1],
        ];
        self.userplane
            .send_f1u_data_packet(
                transport_layer_address,
                gtp_teid.clone(),
                &ipv4_udp_address_bytes,
            )
            .await?;

        Ok(())
    }

    pub async fn recv_f1u_data_packet(&self, ue: &UeContext) -> Result<Vec<u8>> {
        let drb = ue.drb.as_ref().ok_or(anyhow!("No pdu session"))?;
        self.userplane.recv_data_packet(&drb.local_teid).await
    }
}
