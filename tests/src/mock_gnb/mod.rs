//! mock_du - enables a test script to assume the role of the GNB-DU on the F1 reference point

use super::userplane::MockUserplane;
use crate::{
    mock::{Mock, Pdu, ReceivedPdu},
    packet::Packet,
};
use anyhow::{Result, bail};
use asn1_per::{Msb0, NonEmpty, SerDes, bitvec};
use async_net::IpAddr;
use ngap::*;
use slog::{Logger, info};
use std::ops::{Deref, DerefMut};
use xxap::*;
mod build_ngap;

pub const NGAP_SCTP_PPID: u32 = 60;
pub const NGAP_BIND_PORT: u16 = 38412;

impl Pdu for NgapPdu {}

pub struct MockGnb {
    mock: Mock<NgapPdu>,
    local_ip: String,
    userplane: MockUserplane,
}

pub struct UeContext {
    ue_id: u32,
    amf_ue_ngap_id: Option<AmfUeNgapId>,
    pub binding: Binding,
    pub session: Option<Session>,
    nas: Option<Vec<u8>>,
}

impl AsRef<UeContext> for UeContext {
    fn as_ref(&self) -> &UeContext {
        self
    }
}

pub struct Session {
    pdu_session_id: PduSessionId,
    remote_tunnel_info: GtpTunnel,
    local_teid: GtpTeid,
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
    pub async fn new(local_ip: &str, logger: Logger) -> Result<MockGnb> {
        let mock = Mock::new(logger.clone()).await;
        Ok(MockGnb {
            mock,
            local_ip: local_ip.to_string(),
            userplane: MockUserplane::new(local_ip, logger.clone()).await?,
        })
    }

    pub fn plmn(&self) -> PlmnIdentity {
        PlmnIdentity([0x00, 0xf1, 0x10])
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
            session: None,
            nas: None,
        })
    }

    pub async fn reset_ue_context<T: AsMut<UeContext>>(
        &self,
        ue: &mut T,
        worker_ip: &IpAddr,
    ) -> Result<UeContext> {
        let ue = ue.as_mut();
        let mut other = self.new_ue_context(ue.ue_id, worker_ip).await?;
        std::mem::swap(ue, &mut other);
        Ok(other)
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

    pub async fn handle_pdu_session_resource_setup<T: AsMut<UeContext>>(
        &self,
        ue: &mut T,
    ) -> Result<()> {
        let ue = ue.as_mut();
        let pdu = self.receive_pdu().await?;
        let NgapPdu::InitiatingMessage(InitiatingMessage::PduSessionResourceSetupRequest(
            PduSessionResourceSetupRequest {
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                pdu_session_resource_setup_list_su_req:
                    PduSessionResourceSetupListSuReq(NonEmpty {
                        head:
                            PduSessionResourceSetupItemSuReq {
                                pdu_session_id,
                                pdu_session_nas_pdu: Some(NasPdu(nas_bytes)),
                                pdu_session_resource_setup_request_transfer,
                                ..
                            },
                        tail: _,
                    }),
                ..
            },
        )) = *pdu
        else {
            bail!(
                "Unexpected Ngap PduSessionResourceSetupRequest with Nas Pdu, got {:?}",
                pdu
            )
        };
        info!(self.logger, "Ngap PduSessionResourceSetupRequest <<");

        self.update_session(
            pdu_session_id,
            ue,
            &pdu_session_resource_setup_request_transfer,
        )?;

        let pdu = build_ngap::pdu_session_resource_setup_response(
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            &self.local_ip,
            &ue.session.as_ref().unwrap().local_teid.0,
        )?;

        info!(self.logger, "Ngap PduSessionResourceSetupResponse >>");
        self.send(&pdu, None).await;
        ue.nas = Some(nas_bytes);
        Ok(())
    }

    fn update_session(
        &self,
        pdu_session_id: PduSessionId,
        ue: &mut UeContext,
        pdu_session_resource_setup_request_transfer_bytes: &[u8],
    ) -> Result<()> {
        let xfer = PduSessionResourceSetupRequestTransfer::from_bytes(
            pdu_session_resource_setup_request_transfer_bytes,
        )?;
        let UpTransportLayerInformation::GtpTunnel(remote_tunnel_info) =
            xfer.ul_ngu_up_tnl_information;
        let local_teid = [0, 1, 0, 1];
        ue.session = Some(Session {
            pdu_session_id,
            remote_tunnel_info,
            local_teid: GtpTeid(local_teid),
        });
        Ok(())
    }

    pub async fn handle_pdu_session_resource_release<T: AsMut<UeContext>>(
        &self,
        ue: &mut T,
    ) -> Result<()> {
        let ue = ue.as_mut();
        let pdu = self.receive_pdu().await?;
        let NgapPdu::InitiatingMessage(InitiatingMessage::PduSessionResourceReleaseCommand(
            PduSessionResourceReleaseCommand {
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                nas_pdu: Some(nas),
                ..
            },
        )) = *pdu
        else {
            bail!(
                "Expected Ngap PduSessionResourceReleaseCommand with Nas Pdu, got {:?}",
                pdu
            )
        };
        info!(self.logger, "Ngap PduSessionResourceReleaseCommand <<");

        let Some(session) = ue.session.take() else {
            bail!("UE should have a session");
        };

        let pdu = build_ngap::pdu_session_resource_release_response(
            amf_ue_ngap_id,
            ran_ue_ngap_id,
            session.pdu_session_id,
        )?;
        info!(self.logger, "Ngap PduSessionResourceReleaseResponse >>");
        self.send(&pdu, None).await;
        ue.nas = Some(nas.0);

        Ok(())
    }

    pub async fn receive_paging(&self, expected_tmsi: &[u8]) -> Result<()> {
        let pdu = self.receive_pdu().await?;
        let NgapPdu::InitiatingMessage(InitiatingMessage::Paging(Paging {
            ue_paging_identity: UePagingIdentity::FiveGSTmsi(ref tmsi),
            ..
        })) = *pdu
        else {
            bail!("Expected Ngap Paging, got {:?}", pdu)
        };
        info!(self.logger, "Ngap Paging <<");

        assert_eq!(expected_tmsi, &tmsi.five_g_tmsi.0);

        Ok(())
    }

    pub async fn send_nas(
        &self,
        ue: &UeContext,
        nas_bytes: Vec<u8>,
        guti: &Option<[u8; 10]>,
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
                    tac: Tac([0, 0, 1]),
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
            build_ngap::initial_ue_message(ran_ue_ngap_id, nas_pdu, guti, user_location_information)
        };
        self.send(&pdu, Some(ue.binding.assoc_id)).await;
        Ok(())
    }

    pub async fn receive_nas(&self, ue: &mut UeContext, logger: &Logger) -> Result<Vec<u8>> {
        if let Some(nas) = std::mem::take(&mut ue.nas) {
            return Ok(nas);
        }

        let pdu = self.receive_pdu().await?;
        let NgapPdu::InitiatingMessage(InitiatingMessage::DownlinkNasTransport(
            DownlinkNasTransport {
                amf_ue_ngap_id,
                ran_ue_ngap_id,
                nas_pdu,
                ..
            },
        )) = *pdu
        else {
            bail!("Unexpected Ngap message {:?}", pdu);
        };
        info!(logger, "Ngap DownlinkNasTransport <<");
        assert_eq!(ran_ue_ngap_id.0, ue.ue_id);

        if ue.amf_ue_ngap_id.is_none() {
            ue.amf_ue_ngap_id = Some(amf_ue_ngap_id);
        } else {
            assert_eq!(ue.amf_ue_ngap_id, Some(amf_ue_ngap_id));
        }
        Ok(nas_pdu.0)
    }

    pub async fn handle_initial_context_setup_with_session<T: AsMut<UeContext>>(
        &self,
        ue: &mut T,
    ) -> Result<()> {
        self.handle_initial_context_setup_common(ue.as_mut(), true)
            .await
    }

    pub async fn handle_initial_context_setup<T: AsMut<UeContext>>(
        &self,
        ue: &mut T,
    ) -> Result<()> {
        self.handle_initial_context_setup_common(ue.as_mut(), false)
            .await
    }

    async fn handle_initial_context_setup_common(
        &self,
        ue: &mut UeContext,
        session: bool,
    ) -> Result<()> {
        let ReceivedPdu { pdu, assoc_id } = self.receive_pdu_with_assoc_id().await?;
        let nas_pdu = self.check_and_store_initial_context_setup_request(pdu, ue, session)?;
        info!(&self.logger, "Ngap InitialContextSetupRequest <<");

        let teid = if session {
            Some(&ue.session.as_ref().unwrap().local_teid.0)
        } else {
            None
        };

        let ue_setup_response = build_ngap::initial_context_setup_response(
            ue.amf_ue_ngap_id.unwrap(),
            RanUeNgapId(ue.ue_id),
            &self.local_ip,
            teid,
        );
        info!(&self.logger, "Ngap InitialContextSetupResponse >>");
        self.send(&ue_setup_response, Some(assoc_id)).await;
        ue.nas = nas_pdu.map(|x| x.0);
        Ok(())
    }

    pub async fn send_ue_radio_capability_info<T: AsMut<UeContext>>(
        &self,
        ue: &mut T,
    ) -> Result<()> {
        let ue = ue.as_mut();
        let pdu = build_ngap::ue_radio_capability_info_indication(
            ue.amf_ue_ngap_id.unwrap(),
            RanUeNgapId(ue.ue_id),
        );
        info!(self.logger, "Ngap UeRadioCapabilityInfoIndication >>");
        self.send(&pdu, Some(ue.binding.assoc_id)).await;
        Ok(())
    }

    fn check_and_store_initial_context_setup_request(
        &self,
        pdu: Box<NgapPdu>,
        ue: &mut UeContext,
        session_reactivation: bool,
    ) -> Result<Option<NasPdu>> {
        let NgapPdu::InitiatingMessage(InitiatingMessage::InitialContextSetupRequest(
            InitialContextSetupRequest {
                amf_ue_ngap_id,
                pdu_session_resource_setup_list_cxt_req,
                mut nas_pdu,
                ..
            },
        )) = *pdu
        else {
            bail!("Unexpected Ngap message {:?}", pdu)
        };
        if ue.amf_ue_ngap_id.is_none() {
            ue.amf_ue_ngap_id = Some(amf_ue_ngap_id);
        } else {
            assert_eq!(ue.amf_ue_ngap_id, Some(amf_ue_ngap_id));
        }

        // Store off the uplink GTP information in the case of a session being reactivated.
        if let Some(pdu_session_resource_setup_list_cxt_req) =
            pdu_session_resource_setup_list_cxt_req
        {
            // We can only cope with a single session right now.
            assert_eq!(pdu_session_resource_setup_list_cxt_req.0.len(), 1);
            assert!(session_reactivation);
            let item = pdu_session_resource_setup_list_cxt_req.0.head;

            self.update_session(
                item.pdu_session_id,
                ue,
                &item.pdu_session_resource_setup_request_transfer,
            )?;
            if let Some(per_session_nas_pdu) = item.nas_pdu {
                // The test framework can't currently cope with a NAS PDU both at message level and at session level.
                assert!(nas_pdu.is_none());
                nas_pdu = Some(per_session_nas_pdu);
            }
        } else {
            assert!(!session_reactivation);
        }

        Ok(nas_pdu)
    }

    pub async fn send_ue_context_release_request<T: AsRef<UeContext>>(&self, ue: &T) -> Result<()> {
        let ue = ue.as_ref();
        let pdu = build_ngap::ue_context_release_request(
            ue.amf_ue_ngap_id.unwrap(),
            RanUeNgapId(ue.ue_id),
        );
        info!(self.logger, "Ngap UeContextReleaseRequest >>");
        self.send(&pdu, Some(ue.binding.assoc_id)).await;
        Ok(())
    }

    pub async fn handle_ue_context_release<T: AsRef<UeContext>>(&self, ue: &T) -> Result<()> {
        let ue = ue.as_ref();
        let pdu = self.receive_pdu().await?;
        let NgapPdu::InitiatingMessage(InitiatingMessage::UeContextReleaseCommand(
            UeContextReleaseCommand { .. },
        )) = *pdu
        else {
            bail!("Unexpected Ngap message {:?}", pdu);
        };
        info!(self.logger, "Ngap UeContextReleaseCommand <<");
        let pdu = build_ngap::ue_context_release_complete(
            ue.amf_ue_ngap_id.unwrap(),
            RanUeNgapId(ue.ue_id),
        );
        info!(self.logger, "Ngap UeContextReleaseComplete >>");
        self.send(&pdu, Some(ue.binding.assoc_id)).await;
        Ok(())
    }

    pub async fn send_n3_data_packet(&self, ue: &UeContext, pkt: Packet) -> Result<()> {
        let Some(Session {
            remote_tunnel_info:
                GtpTunnel {
                    ref transport_layer_address,
                    gtp_teid,
                },
            ..
        }) = ue.session
        else {
            bail!("Session missing");
        };

        let transport_layer_address = transport_layer_address.clone().try_into()?;
        self.userplane
            .send_n3_data_packet(pkt, transport_layer_address, &gtp_teid.0)
            .await?;

        Ok(())
    }

    pub async fn recv_n3_data_packet<T: AsRef<UeContext>>(&self, ue: &T) -> Result<Vec<u8>> {
        self.userplane
            .recv_gtp(&ue.as_ref().session.as_ref().unwrap().local_teid)
            .await
    }
}
