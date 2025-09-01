mod mock_ue_5gc;
pub use mock_ue_5gc::*;

use anyhow::{Result, anyhow, bail, ensure};
use async_trait::async_trait;
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, NasPduAddress, NasPduSessionReactivationResult,
    NasPduSessionStatus, NasPduSessionType, decode_nas_5gs_message,
    messages::{
        NasAuthenticationRequest, NasDlNasTransport, NasPduSessionEstablishmentAccept,
        NasPduSessionReleaseCommand,
    },
};
use qcore::SubscriberAuthParams;
use slog::{Logger, info, o};
use std::net::Ipv4Addr;

pub use crate::mock_ue::build_nas::{NGKSI_IN_USE, SYNCH_FAILURE};

// TODO: commonize with QCore
#[macro_export]
macro_rules! ensure_nas {
    ($t:ident, $boxed_nas:expr) => {
        match *$boxed_nas {
            oxirush_nas::Nas5gsMessage::Gmm(_header, oxirush_nas::Nas5gmmMessage::$t(message)) => {
                message
            }
            m => bail!("Expected Nas {} but got {:?}", stringify!($t), m),
        }
    };
}

mod build_nas;
mod build_rrc;
pub mod mock_ue_f1ap;
pub mod mock_ue_ngap;

#[async_trait]
pub trait Transport {
    async fn send_nas(
        &mut self,
        nas_bytes: Vec<u8>,
        guti: &Option<[u8; 10]>,
        logger: &Logger,
    ) -> Result<()>;
    async fn receive_nas(&mut self, logger: &Logger) -> Result<Vec<u8>>;
    async fn send_userplane_packet(
        &self,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<()>;
    async fn receive_userplane_packet(&self) -> Result<Vec<u8>>;
}

pub struct MockUe<T: Transport> {
    pub data: MockUe5GCData,
    transport: T,
    logger: Logger,
    use_wrong_imsi: bool,
}

impl<T: Transport> MockUe<T> {
    pub fn new(
        imsi: String,
        sub_auth_params: SubscriberAuthParams,
        ue_id: u32,
        transport: T,
        logger: &Logger,
    ) -> Self {
        MockUe {
            data: MockUe5GCData::new(imsi, sub_auth_params),
            transport,
            logger: logger.new(o!("ue" => ue_id)),
            use_wrong_imsi: false,
        }
    }

    pub fn new_from_base(data: MockUe5GCData, ue_id: u32, transport: T, logger: &Logger) -> Self {
        MockUe {
            data,
            transport,
            logger: logger.new(o!("ue" => ue_id)),
            use_wrong_imsi: false,
        }
    }

    pub fn disconnect(self) -> MockUe5GCData {
        self.data
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn use_guti(&mut self, guti: [u8; 10]) {
        self.data.guti = Some(guti);
    }

    // Use the wrong imsi on the next IdentityResponse
    pub fn use_wrong_imsi(&mut self) {
        self.use_wrong_imsi = true;
    }

    pub fn use_dnn(&mut self, dnn: &'static [u8]) {
        self.data.dnn = Some(dnn);
    }

    async fn send_nas(&mut self, nas_bytes: Vec<u8>) -> Result<()> {
        self.transport
            .send_nas(nas_bytes, &self.data.guti, &self.logger)
            .await
    }

    async fn send_nas_no_outer_stmsi(&mut self, nas_bytes: Vec<u8>) -> Result<()> {
        self.transport
            .send_nas(nas_bytes, &None, &self.logger)
            .await
    }

    async fn receive_nas(&mut self) -> Result<Box<Nas5gsMessage>> {
        let nas = self.transport.receive_nas(&self.logger).await?;
        self.decode_nas(nas)
    }

    fn decode_nas(&mut self, nas: Vec<u8>) -> Result<Box<Nas5gsMessage>> {
        let outer = Box::new(
            decode_nas_5gs_message(&nas)
                .map_err(|e| anyhow!("Nas decode error - {e} - message bytes: {:?}", nas))?,
        );
        let (nas, _security_header) = match *outer {
            Nas5gsMessage::Gmm(_, _) => (outer, None),
            Nas5gsMessage::SecurityProtected(hdr, bx) => (bx, Some(hdr)),
            Nas5gsMessage::Gsm(_, _) => bail!("Unexpected Nas SM message {:?} ", outer),
        };

        Ok(nas)
    }

    fn build_register_request_for_nas_security_mode(&self) -> Result<Vec<u8>> {
        let include_session_1 = self.data.ipv4_addr != Ipv4Addr::UNSPECIFIED;
        assert!(self.data.guti.is_none());
        build_nas::registration_request(
            build_nas::mobile_identity_supi(&self.data.imsi),
            include_session_1,
        )
    }

    fn build_register_request(&mut self) -> Result<Vec<u8>> {
        let include_session_1 = self.data.ipv4_addr != Ipv4Addr::UNSPECIFIED;
        if let Some(guti) = self.data.guti {
            if include_session_1 {
                build_nas::guti_registration_request_with_inner_session_activation(
                    build_nas::mobile_identity_guti(&guti),
                    &mut self.data.nas_context,
                )
            } else {
                build_nas::registration_request(build_nas::mobile_identity_guti(&guti), false)
            }
        } else {
            build_nas::registration_request(
                build_nas::mobile_identity_supi(&self.data.imsi),
                include_session_1,
            )
        }
    }

    fn build_service_request(&mut self) -> Result<Vec<u8>> {
        if let Some(guti) = self.data.guti {
            build_nas::service_request(
                build_nas::mobile_identity_stmsi(&guti),
                &mut self.data.nas_context,
            )
        } else {
            bail!("GUTI missing")
        }
    }

    // Register outside of an RRC Setup Complete on an existing RRC channel
    pub async fn reregister(&mut self) -> Result<()> {
        let nas_bytes = self.build_register_request()?;
        self.send_nas(nas_bytes).await
    }

    pub async fn receive_nas_authentication_request(&mut self) -> Result<NasAuthenticationRequest> {
        let nas = ensure_nas!(AuthenticationRequest, self.receive_nas().await?);
        info!(&self.logger, "Nas AuthenticationRequest >>");
        Ok(nas)
    }

    pub async fn handle_nas_authentication(&mut self) -> Result<()> {
        let NasAuthenticationRequest {
            authentication_parameter_rand: Some(rand),
            authentication_parameter_autn: Some(autn),
            ..
        } = self.receive_nas_authentication_request().await?
        else {
            bail!("Missing RAND or AUTN in AuthenticationRequest");
        };
        let Ok(rand) = rand.value.try_into() else {
            bail!("RAND wrong length");
        };
        let Ok(autn) = autn.value.try_into() else {
            bail!("AUTN wrong length");
        };

        let (xres_star, kseaf) = security::respond_to_challenge_insecure(
            &self.data.sub_auth_params.sim_creds.ki,
            &self.data.sub_auth_params.sim_creds.opc,
            "5G:mnc001.mcc001.3gppnetwork.org".as_bytes(),
            &rand,
            &autn,
        );
        let nas_authentication_response = build_nas::authentication_response(&xres_star)?;
        info!(&self.logger, "Nas AuthenticationResponse <<");
        self.send_nas(nas_authentication_response).await?;

        // This should actually be done on receipt of SecurityModeCommand as we are about to
        // send SecurityModeComplete.
        let kamf = security::derive_kamf(&kseaf, self.data.imsi.as_bytes());
        let knasint = security::derive_knasint(&kamf);
        self.data.nas_context.enable_security(knasint);

        Ok(())
    }

    pub async fn handle_nas_security_mode(&mut self) -> Result<()> {
        ensure_nas!(SecurityModeCommand, self.receive_nas().await?);
        info!(&self.logger, "Nas SecurityModeCommand <<");
        let register_request = self.build_register_request_for_nas_security_mode()?;
        let nas_security_mode_complete =
            build_nas::security_mode_complete(register_request, &mut self.data.nas_context)?;
        info!(&self.logger, "Nas SecurityModeComplete >>");
        self.send_nas(nas_security_mode_complete).await
    }

    pub async fn handle_identity_procedure(&mut self) -> Result<()> {
        ensure_nas!(IdentityRequest, self.receive_nas().await?);
        info!(&self.logger, "Nas IdentityRequest <<");
        let imsi = if self.use_wrong_imsi {
            self.use_wrong_imsi = false;
            "543938298342342"
        } else {
            &self.data.imsi
        };
        let nas_identity_response = build_nas::identity_response(imsi)?;
        info!(&self.logger, "Nas IdentityResponse >>");
        self.send_nas(nas_identity_response).await
    }

    pub async fn handle_nas_registration_accept(&mut self) -> Result<()> {
        let message = ensure_nas!(RegistrationAccept, self.receive_nas().await?);
        info!(&self.logger, "Nas RegistrationAccept <<");

        let Some(guti_ie) = message.fg_guti else {
            bail!("Expected GUTI in registration accept")
        };
        let guti = &guti_ie.value[1..11];
        info!(&self.logger, "UE was assigned GUTI {:02x?}", guti);
        self.use_guti(guti.try_into().unwrap());

        self.check_session_reactivation(
            &message.pdu_session_reactivation_result,
            &message.pdu_session_status,
        )?;

        let nas_registration_complete = build_nas::registration_complete()?;
        info!(&self.logger, "Nas RegistrationComplete >>");
        self.send_nas(nas_registration_complete).await
    }

    fn check_session_reactivation(
        &self,
        reactivation_result: &Option<NasPduSessionReactivationResult>,
        session_status: &Option<NasPduSessionStatus>,
    ) -> Result<()> {
        if self.data.ipv4_addr != Ipv4Addr::UNSPECIFIED {
            match reactivation_result {
                None => bail!("Reactivation result missing"),
                Some(x) => {
                    ensure!(
                        x.value == vec![0, 0],
                        "Expecting no reactivation result failures"
                    );
                }
            }
            match session_status {
                None => bail!("Session status missing"),
                Some(x) => {
                    ensure!(
                        x.value == vec![2, 0],
                        "Expecting session 1 to be reactivated"
                    );
                }
            }
        }
        Ok(())
    }

    pub async fn receive_nas_configuration_update_command(&mut self) -> Result<()> {
        let message = ensure_nas!(ConfigurationUpdateCommand, self.receive_nas().await?);
        info!(&self.logger, "Nas ConfigurationUpdateCommand <<");
        if let Some(guti_ie) = message.fg_guti {
            let guti = &guti_ie.value[1..11];
            info!(&self.logger, "UE was assigned GUTI {:02x?}", guti);
            self.use_guti(guti.try_into().unwrap());
        }
        Ok(())
    }

    pub async fn send_nas_configuration_update_complete(&mut self) -> Result<()> {
        let configuration_update_complete =
            build_nas::configuration_update_complete(&mut self.data.nas_context)?;
        info!(&self.logger, "Nas ConfigurationUpdateComplete >>");
        self.send_nas(configuration_update_complete).await
    }

    pub async fn handle_nas_configuration_update(&mut self) -> Result<()> {
        self.receive_nas_configuration_update_command().await?;
        self.send_nas_configuration_update_complete().await
    }

    pub async fn send_nas_pdu_session_establishment_request(&mut self) -> Result<()> {
        let nas_session_establishment_request = build_nas::pdu_session_establishment_request(
            self.data.dnn,
            &mut self.data.nas_context,
        )?;
        info!(&self.logger, "Nas PduSessionEstablishmentRequest >>");
        self.send_nas(nas_session_establishment_request).await
    }

    pub async fn perform_nas_deregistration(&mut self) -> Result<()> {
        self.send_nas_deregistration_request().await?;
        self.receive_nas_deregistration_accept().await
    }

    pub async fn send_nas_deregistration_request(&mut self) -> Result<()> {
        let nas_deregistration_request =
            build_nas::deregistration_request(&mut self.data.nas_context)?;
        self.data.guti = None;
        info!(&self.logger, "Nas DeregistrationRequest >>");
        self.send_nas(nas_deregistration_request).await
    }

    pub async fn receive_nas_deregistration_accept(&mut self) -> Result<()> {
        ensure_nas!(DeregistrationAcceptFromUe, self.receive_nas().await?);
        info!(&self.logger, "Nas DeregistrationAccept <<");
        Ok(())
    }

    pub async fn send_nas_service_request(&mut self) -> Result<()> {
        // Potential fields needed in the InitialUeMessage:
        // - UEContextRequest
        let nas_bytes = self.build_service_request()?;
        self.send_nas(nas_bytes).await
    }

    pub async fn send_userplane_packet(
        &self,
        dst_ip: &Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<()> {
        self.transport
            .send_userplane_packet(&self.data.ipv4_addr, dst_ip, src_port, dst_port)
            .await
    }

    pub async fn recv_f1u_data_packet(&self) -> Result<Vec<u8>> {
        self.transport.receive_userplane_packet().await
    }

    pub async fn fail_nas_authentication(&mut self, cause: u8) -> Result<()> {
        ensure_nas!(AuthenticationRequest, self.receive_nas().await?);
        info!(&self.logger, "Nas AuthenticationRequest <<");
        let nas_authentication_failure = build_nas::authentication_failure(cause)?;
        info!(&self.logger, "Nas AuthenticationFailure >>");
        self.send_nas(nas_authentication_failure).await
    }

    pub async fn receive_nas_registration_reject(&mut self) -> Result<()> {
        ensure_nas!(RegistrationReject, self.receive_nas().await?);
        Ok(())
    }

    pub async fn receive_nas_5gmm_status(&mut self) -> Result<()> {
        ensure_nas!(FGmmStatus, self.receive_nas().await?);
        Ok(())
    }

    pub async fn receive_nas_session_accept(&mut self) -> Result<()> {
        let nas = self.receive_nas().await?;
        let message = decode_security_protected_sm(nas)?;
        let Nas5gsmMessage::PduSessionEstablishmentAccept(NasPduSessionEstablishmentAccept {
            selected_pdu_session_type: NasPduSessionType { value: 1, .. },
            pdu_address:
                Some(NasPduAddress {
                    value: nas_pdu_address_ie,
                    ..
                }),
            ..
        }) = message
        else {
            bail!("Expected NasPduSessionEstablishmentAccept, got {message:?}");
        };

        info!(&self.logger, "Nas PduSessionEstablishmentAccept <<");

        self.data.ipv4_addr = Ipv4Addr::new(
            nas_pdu_address_ie[1],
            nas_pdu_address_ie[2],
            nas_pdu_address_ie[3],
            nas_pdu_address_ie[4],
        );
        Ok(())
    }

    pub async fn receive_nas_service_accept(&mut self) -> Result<()> {
        let message = ensure_nas!(ServiceAccept, self.receive_nas().await?);
        info!(&self.logger, "Nas ServiceAccept <<");
        self.check_session_reactivation(
            &message.pdu_session_reactivation_result,
            &message.pdu_session_status,
        )
    }

    pub async fn send_nas_pdu_session_release_request(&mut self) -> Result<()> {
        let nas_session_release_request =
            build_nas::pdu_session_release_request(&mut self.data.nas_context)?;
        info!(&self.logger, "Nas PduSessionReleaseRequest >>");
        self.send_nas(nas_session_release_request).await
    }

    pub async fn receive_nas_session_release_command(&mut self) -> Result<()> {
        let nas = self.receive_nas().await?;
        let message = decode_security_protected_sm(nas)?;
        let Nas5gsmMessage::PduSessionReleaseCommand(NasPduSessionReleaseCommand { .. }) = message
        else {
            bail!("Expected NasPduSessionReleaseCommand, got {message:?}");
        };
        info!(&self.logger, "Nas PduSessionReleaseCommand <<");
        Ok(())
    }

    pub async fn handle_nas_session_release(&mut self) -> Result<()> {
        self.receive_nas_session_release_command().await?;
        let nas_session_release_complete =
            build_nas::pdu_session_release_complete(&mut self.data.nas_context)?;
        info!(&self.logger, "Nas PduSessionReleaseComplete >>");
        self.send_nas(nas_session_release_complete).await
    }
}

pub fn decode_security_protected_sm(nas: Box<Nas5gsMessage>) -> Result<Nas5gsmMessage> {
    let Nas5gsMessage::Gmm(
        _header,
        Nas5gmmMessage::DlNasTransport(NasDlNasTransport {
            payload_container, ..
        }),
    ) = *nas
    else {
        bail!("Expected NasDlNasTransport, got {nas:?}")
    };

    let nas_gsm = decode_nas_5gs_message(&payload_container.value)?;
    let Nas5gsMessage::Gsm(_header, message) = nas_gsm else {
        bail!("Expected Gsm message, got {nas_gsm:?}");
    };
    Ok(message)
}
