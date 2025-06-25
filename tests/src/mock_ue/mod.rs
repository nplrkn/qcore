use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, NasPduAddress, NasPduSessionType,
    decode_nas_5gs_message,
    messages::{
        NasAuthenticationRequest, NasDlNasTransport, NasPduSessionEstablishmentAccept,
        NasPduSessionReleaseCommand,
    },
};
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
    async fn send_nas(&mut self, nas_bytes: Vec<u8>, logger: &Logger) -> Result<()>;
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
    imsi: String,
    guti: Option<[u8; 10]>,
    pub ipv4_addr: Ipv4Addr,
    dnn: Option<&'static [u8]>,
    transport: T,
    logger: Logger,
    use_wrong_imsi: bool,
}

impl<T: Transport> MockUe<T> {
    pub fn new(imsi: String, ue_id: u32, transport: T, logger: &Logger) -> Self {
        MockUe {
            imsi,
            guti: None,
            ipv4_addr: Ipv4Addr::UNSPECIFIED,
            dnn: None,
            transport,
            logger: logger.new(o!("ue" => ue_id)),
            use_wrong_imsi: false,
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn use_guti(&mut self, guti: [u8; 10]) {
        self.guti = Some(guti);
    }

    // Use the wrong imsi on the next IdentityResponse
    pub fn use_wrong_imsi(&mut self) {
        self.use_wrong_imsi = true;
    }

    pub fn use_dnn(&mut self, dnn: &'static [u8]) {
        self.dnn = Some(dnn);
    }

    async fn send_nas(&mut self, nas_bytes: Vec<u8>) -> Result<()> {
        self.transport.send_nas(nas_bytes, &self.logger).await
    }

    async fn receive_nas(&mut self) -> Result<Box<Nas5gsMessage>> {
        let nas_bytes = self.transport.receive_nas(&self.logger).await?;
        let outer = Box::new(
            decode_nas_5gs_message(&nas_bytes)
                .map_err(|e| anyhow!("NAS decode error - {e} - message bytes: {:?}", nas_bytes))?,
        );
        let (nas, _security_header) = match *outer {
            Nas5gsMessage::Gmm(_, _) => (outer, None),
            Nas5gsMessage::SecurityProtected(hdr, bx) => (bx, Some(hdr)),
            Nas5gsMessage::Gsm(_, _) => bail!("Unexpected Nas SM message {:?} ", outer),
        };

        Ok(nas)
    }

    fn build_register_request(&self) -> Result<Vec<u8>> {
        if let Some(guti) = self.guti {
            build_nas::registration_request(build_nas::mobile_identity_guti(&guti))
        } else {
            build_nas::registration_request(build_nas::mobile_identity_supi(&self.imsi))
        }
    }

    // Register outside of an RRC Setup Complete on an existing RRC channel
    pub async fn reregister(&mut self) -> Result<()> {
        self.send_nas(self.build_register_request()?).await
    }

    pub async fn receive_nas_authentication_request(&mut self) -> Result<NasAuthenticationRequest> {
        let nas = ensure_nas!(AuthenticationRequest, self.receive_nas().await?);
        info!(&self.logger, "NAS Authentication request >>");
        Ok(nas)
    }

    pub async fn handle_nas_authentication(&mut self) -> Result<()> {
        let _ = self.receive_nas_authentication_request().await?;
        let nas_authentication_response = build_nas::authentication_response()?;
        info!(&self.logger, "NAS Authentication response <<");
        self.send_nas(nas_authentication_response).await
    }

    pub async fn handle_nas_security_mode(&mut self) -> Result<()> {
        ensure_nas!(SecurityModeCommand, self.receive_nas().await?);
        info!(&self.logger, "NAS Security mode command <<");
        let nas_security_mode_complete = build_nas::security_mode_complete()?;
        info!(&self.logger, "NAS Security mode complete >>");
        self.send_nas(nas_security_mode_complete).await
    }

    pub async fn handle_identity_procedure(&mut self) -> Result<()> {
        ensure_nas!(IdentityRequest, self.receive_nas().await?);
        info!(&self.logger, "NAS Identity Request <<");
        let imsi = if self.use_wrong_imsi {
            self.use_wrong_imsi = false;
            "543938298342342"
        } else {
            &self.imsi
        };
        let nas_identity_response = build_nas::identity_response(imsi)?;
        info!(&self.logger, "NAS Identity Response >>");
        self.send_nas(nas_identity_response).await
    }

    pub async fn handle_nas_registration_accept(&mut self) -> Result<()> {
        let message = ensure_nas!(RegistrationAccept, self.receive_nas().await?);
        let Some(guti_ie) = message.fg_guti else {
            bail!("Expected GUTI in registration accept")
        };
        let guti = &guti_ie.value[1..11];
        info!(&self.logger, "UE was assigned GUTI {:02x?}", guti);
        self.use_guti(guti.try_into().unwrap());

        let nas_registration_complete = build_nas::registration_complete()?;
        info!(&self.logger, "NAS Registration Complete >>");
        self.send_nas(nas_registration_complete).await
    }

    pub async fn send_nas_pdu_session_establishment_request(&mut self) -> Result<()> {
        let nas_session_establishment_request =
            build_nas::pdu_session_establishment_request(self.dnn)?;
        info!(&self.logger, "NAS PDU session establishment request >>");
        self.send_nas(nas_session_establishment_request).await
    }

    pub async fn send_nas_deregistration_request(&mut self) -> Result<()> {
        let nas_deregistration_request = build_nas::deregistration_request()?;
        self.guti = None;
        info!(&self.logger, "NAS deregistration request >>");
        self.send_nas(nas_deregistration_request).await
    }

    pub async fn send_userplane_packet(
        &self,
        dst_ip: &Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<()> {
        self.transport
            .send_userplane_packet(&self.ipv4_addr, dst_ip, src_port, dst_port)
            .await
    }

    pub async fn recv_f1u_data_packet(&self) -> Result<Vec<u8>> {
        self.transport.receive_userplane_packet().await
    }

    pub async fn fail_nas_authentication(&mut self, cause: u8) -> Result<()> {
        ensure_nas!(AuthenticationRequest, self.receive_nas().await?);
        info!(&self.logger, "NAS Authentication request <<");
        let nas_authentication_failure = build_nas::authentication_failure(cause)?;
        info!(&self.logger, "NAS Authentication failure >>");
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

    pub fn handle_session_accept(&mut self, nas_bytes: Vec<u8>) -> Result<()> {
        let message = decode_security_protected_sm(nas_bytes)?;
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

        self.ipv4_addr = Ipv4Addr::new(
            nas_pdu_address_ie[1],
            nas_pdu_address_ie[2],
            nas_pdu_address_ie[3],
            nas_pdu_address_ie[4],
        );
        Ok(())
    }

    pub async fn send_nas_pdu_session_release_request(&mut self) -> Result<()> {
        let nas_session_release_request = build_nas::pdu_session_release_request()?;
        info!(&self.logger, "Nas PduSessionReleaseRequest >>");
        self.send_nas(nas_session_release_request).await
    }

    pub async fn handle_session_release(&mut self, nas_bytes: Vec<u8>) -> Result<()> {
        let message = decode_security_protected_sm(nas_bytes)?;
        let Nas5gsmMessage::PduSessionReleaseCommand(NasPduSessionReleaseCommand { .. }) = message
        else {
            bail!("Expected NasPduSessionReleaseCommand, got {message:?}");
        };
        info!(&self.logger, "Nas PduSessionReleaseCommand <<");
        let nas_session_release_complete = build_nas::pdu_session_release_complete()?;
        info!(&self.logger, "Nas PduSessionReleaseComplete >>");
        self.send_nas(nas_session_release_complete).await
    }
}

pub fn decode_security_protected_sm(nas_bytes: Vec<u8>) -> Result<Nas5gsmMessage> {
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
    let Nas5gsMessage::Gsm(_header, message) = nas_gsm else {
        bail!("Expected Gsm message, got {nas_gsm:?}");
    };
    Ok(message)
}
