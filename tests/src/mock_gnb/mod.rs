//! mock_du - enables a test script to assume the role of the GNB-DU on the F1 reference point

use super::userplane::MockUserplane;
use crate::mock::{Mock, Pdu};
use anyhow::{Result, bail};
use asn1_per::{Msb0, bitvec};
use async_net::IpAddr;
use ngap::*;
use slog::{Logger, info, o};
use std::ops::{Deref, DerefMut};
use xxap::*;
mod build_ngap;

pub const NGAP_SCTP_PPID: u32 = 60;
pub const NGAP_BIND_PORT: u16 = 38412;

impl Pdu for NgapPdu {}

pub struct MockGnb {
    mock: Mock<NgapPdu>,
    local_ip: String,
    _userplane: MockUserplane,
}

pub struct UeContext {
    ue_id: u32,
    amf_ue_ngap_id: Option<AmfUeNgapId>,
    pub binding: Binding,
}

impl Deref for MockGnb {
    type Target = Mock<NgapPdu>;

    fn deref(&self) -> &Self::Target {
        &self.mock
    }
}

impl DerefMut for MockGnb {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mock
    }
}

impl MockGnb {
    pub async fn new(local_ip: &str, logger: &Logger) -> Result<MockGnb> {
        let logger = logger.new(o!("gnb" => 1));
        let mock = Mock::new(logger.clone()).await;
        Ok(MockGnb {
            mock,
            local_ip: local_ip.to_string(),
            _userplane: MockUserplane::new(local_ip, logger.clone()).await?,
        })
    }

    pub fn plmn(&self) -> PlmnIdentity {
        PlmnIdentity([0, 0, 0])
    }

    pub async fn disconnect(&mut self) {
        self.mock.disconnect().await
    }

    pub async fn new_ue_context(&self, ue_id: u32, worker_ip: &IpAddr) -> Result<UeContext> {
        Ok(UeContext {
            ue_id,
            amf_ue_ngap_id: None,
            binding: self
                .transport
                .new_ue_binding_from_ip(&worker_ip.to_string())
                .await?,
        })
    }

    pub async fn perform_ng_setup(&mut self, worker_ip: &IpAddr) -> Result<()> {
        let transport_address = format!("{}:{}", worker_ip, NGAP_BIND_PORT);
        let bind_address = self.local_ip.clone();
        info!(self.logger, "Connect to AMF {}", transport_address);
        self.connect(&transport_address, &bind_address, NGAP_SCTP_PPID)
            .await;
        let pdu = build_ngap::ng_setup_request();
        info!(self.logger, "NgSetupRequest >>");
        self.send(&pdu, None).await;
        self.receive_ng_setup_response().await
    }

    async fn receive_ng_setup_response(&self) -> Result<()> {
        let pdu = self.receive_pdu().await?;
        let NgapPdu::SuccessfulOutcome(SuccessfulOutcome::NgSetupResponse(_)) = *pdu else {
            bail!("Unexpected Ngap message {:?}", pdu)
        };
        info!(self.logger, "NgSetupResponse <<");
        Ok(())
    }

    pub async fn send_nas(
        &self,
        ue: &UeContext,
        nas_bytes: Vec<u8>,
        logger: &Logger,
    ) -> Result<()> {
        // Use an NG Initial UE Message or NG Uplink NAS transport depending on whether we have a NGAP UE
        // app ID yet.
        let ran_ue_ngap_id = RanUeNgapId(ue.ue_id);
        let nas_pdu = NasPdu(nas_bytes);
        let user_location_information =
            UserLocationInformation::UserLocationInformationNr(UserLocationInformationNr {
                nr_cgi: NrCgi {
                    plmn_identity: self.plmn(),
                    nr_cell_identity: NrCellIdentity(bitvec![u8,Msb0;0;36]),
                },
                tai: Tai {
                    plmn_identity: self.plmn(),
                    tac: Tac([0, 0, 0]),
                },
                time_stamp: None,
                ps_cell_information: None,
                nid: None,
            });

        let pdu = if let Some(amf_ue_ngap_id) = ue.amf_ue_ngap_id {
            info!(logger, "Ngap UplinkNasTransport >>");
            build_ngap::uplink_nas_transport(
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                nas_pdu,
                user_location_information,
            )
        } else {
            info!(logger, "Ngap InitialUeMessage >>");
            build_ngap::initial_ue_message(ran_ue_ngap_id, nas_pdu, user_location_information)
        };
        self.send(&pdu, Some(ue.binding.assoc_id)).await;
        Ok(())
    }

    pub async fn receive_nas(&self, ue: &mut UeContext, logger: &Logger) -> Result<Vec<u8>> {
        let pdu = self.receive_pdu().await?;
        let NgapPdu::InitiatingMessage(InitiatingMessage::DownlinkNasTransport(
            DownlinkNasTransport {
                amf_ue_ngap_id,
                nas_pdu,
                ..
            },
        )) = *pdu
        else {
            bail!("Unexpected Ngap message {:?}", pdu);
        };
        info!(logger, "Ngap DownlinkNasTransport <<");

        if ue.amf_ue_ngap_id.is_none() {
            ue.amf_ue_ngap_id = Some(amf_ue_ngap_id);
        } else {
            assert_eq!(ue.amf_ue_ngap_id, Some(amf_ue_ngap_id));
        }
        Ok(nas_pdu.0)
    }

    // pub async fn handle_f1_ue_context_setup(&self, ue: &mut UeContext) -> Result<()> {
    //     let ReceivedPdu { pdu, assoc_id } = self.receive_pdu_with_assoc_id().await?;
    //     self.check_and_store_ue_context_setup_request(pdu, ue)?;
    //     info!(&self.logger, "UeContextSetupRequest <<");
    //     let ue_setup_response = build_f1ap::ue_context_setup_response(ue, &self.local_ip)?;
    //     info!(&self.logger, "UeContextSetupResponse >>");
    //     self.send(&ue_setup_response, Some(assoc_id)).await;

    //     Ok(())
    // }

    // fn check_and_store_ue_context_setup_request(
    //     &self,
    //     pdu: Box<F1apPdu>,
    //     ue: &mut UeContext,
    // ) -> Result<()> {
    //     let F1apPdu::InitiatingMessage(InitiatingMessage::UeContextSetupRequest(ue_setup_request)) =
    //         *pdu
    //     else {
    //         bail!("Unexpected F1ap message {:?}", pdu)
    //     };

    //     ensure!(
    //         matches!(ue_setup_request.gnb_du_ue_f1ap_id, Some(GnbDuUeF1apId(x)) if x == ue.ue_id),
    //         "Bad Ue Id"
    //     );
    //     // TODO - SRB2 should also be set up .  Enforce this.  See 38.331, 5.3.1.1:
    //     // "A configuration with SRB2 without DRB or with DRB without SRB2 is not supported
    //     // (i.e., SRB2 and at least one DRB must be configured in the same RRC Reconfiguration
    //     // message, and it is not allowed to release all the DRBs without releasing the RRC
    //     // Connection)."

    //     ensure!(ue.drb.is_none());
    //     let Some(drbs_to_be_setup_list) = ue_setup_request.drbs_to_be_setup_list else {
    //         bail!("No Drbs supplied")
    //     };

    //     let first_drb = &drbs_to_be_setup_list.0[0];
    //     let first_tnl_of_first_drb = &first_drb.ul_up_tnl_information_to_be_setup_list.0[0];
    //     let UpTransportLayerInformation::GtpTunnel(remote_tunnel_info) =
    //         &first_tnl_of_first_drb.ul_up_tnl_information;

    //     // Check we have been given a real IP address.
    //     let Ok(_ip_addr) = IpAddr::try_from(remote_tunnel_info.transport_layer_address.clone())
    //     else {
    //         bail!(
    //             "Bad remote transport layer address in {:?}",
    //             first_tnl_of_first_drb
    //         );
    //     };

    //     Ok(())
    // }
}
