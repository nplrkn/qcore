use anyhow::{Result, bail};
use async_trait::async_trait;
use oxirush_nas::{Nas5gmmMessage, Nas5gsMessage, decode_nas_5gs_message};
use slog::{Logger, info, o};
use std::net::Ipv4Addr;

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
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn use_guti(&mut self, guti: [u8; 10]) {
        self.guti = Some(guti);
    }

    pub fn use_dnn(&mut self, dnn: &'static [u8]) {
        self.dnn = Some(dnn);
    }

    async fn send_nas(&mut self, nas_bytes: Vec<u8>) -> Result<()> {
        self.transport.send_nas(nas_bytes, &self.logger).await
    }

    async fn receive_nas(&mut self) -> Result<Vec<u8>> {
        self.transport.receive_nas(&self.logger).await
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

    pub async fn handle_nas_registration_accept(&mut self) -> Result<()> {
        let nas_registration_accept = self.receive_nas().await?;
        info!(&self.logger, "NAS Registration Accept <<");
        let nas = decode_nas_5gs_message(&nas_registration_accept)?;
        let Nas5gsMessage::SecurityProtected(_header, message) = nas else {
            bail!("Expected security protected message, got {nas:?}")
        };
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(message)) = *message else {
            bail!("Expected security protected registration accept")
        };
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

    pub async fn send_f1u_data_packet(
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

    pub async fn handle_nas_authentication_sync_failure(&mut self) -> Result<()> {
        let _nas_authentication_request = self.receive_nas().await?;
        info!(&self.logger, "NAS Authentication request <<");
        let nas_authentication_failure = build_nas::authentication_failure()?;
        info!(
            &self.logger,
            "NAS Authentication failure (synch failure) >>"
        );
        self.send_nas(nas_authentication_failure).await
    }

    pub async fn receive_nas_registration_reject(&mut self) -> Result<()> {
        match decode_nas_5gs_message(&mut self.receive_nas().await?)? {
            Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationReject(_)) => Ok(()),
            m => bail!("Expected reject, got {:?}", m),
        }
    }

    async fn receive_security_protected_nas(&mut self) -> Result<Nas5gmmMessage> {
        let nas = decode_nas_5gs_message(&mut self.receive_nas().await?)?;
        let Nas5gsMessage::SecurityProtected(_, message) = nas else {
            bail!("Expected security protected message, got bytes: {:?}", nas);
        };
        match *message {
            Nas5gsMessage::Gmm(_, nas_gmm) => Ok(nas_gmm),
            _ => bail!("Expected 5GMM message, got GSM message"),
        }
    }

    pub async fn receive_nas_5gmm_status(&mut self) -> Result<()> {
        match self.receive_security_protected_nas().await? {
            Nas5gmmMessage::FGmmStatus(_) => Ok(()),
            m => bail!("Expected 5GMM status, got {:?}", m),
        }
    }
}
