use anyhow::Result;
use async_trait::async_trait;
use qcore::SubscriberAuthParams;
use slog::Logger;
use std::{
    net::IpAddr,
    ops::{Deref, DerefMut},
};

use crate::{
    GnbUeContext, MockGnb, MockUe,
    mock_ue::{MockUe5GCData, Transport},
    packet::Packet,
};

pub struct MockUeNgap<'a> {
    pub base: MockUe<UeNgapMode<'a>>,
}
impl<'a> Deref for MockUeNgap<'a> {
    type Target = MockUe<UeNgapMode<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}
impl DerefMut for MockUeNgap<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

impl From<MockUeNgap<'_>> for MockUe5GCData {
    fn from(val: MockUeNgap<'_>) -> Self {
        val.base.data
    }
}

pub struct UeNgapMode<'a> {
    gnb: &'a MockGnb,
    pub gnb_ue_context: GnbUeContext,
}
impl<'a> UeNgapMode<'a> {
    pub fn new(gnb: &'a MockGnb, gnb_ue_context: GnbUeContext) -> Self {
        UeNgapMode {
            gnb,
            gnb_ue_context,
        }
    }
}

#[async_trait]
impl<'a> Transport for UeNgapMode<'a> {
    async fn send_nas(
        &mut self,
        nas_bytes: Vec<u8>,
        guti: &Option<[u8; 10]>,
        logger: &Logger,
    ) -> Result<()> {
        self.gnb
            .send_nas(&self.gnb_ue_context, nas_bytes, guti, logger)
            .await
    }

    async fn receive_nas(&mut self, logger: &Logger) -> Result<Vec<u8>> {
        self.gnb.receive_nas(&mut self.gnb_ue_context, logger).await
    }

    async fn send_userplane_packet(&self, packet: Packet) -> Result<()> {
        self.gnb
            .send_n3_data_packet(&self.gnb_ue_context, packet)
            .await
    }

    async fn receive_userplane_packet(&self) -> Result<Vec<u8>> {
        self.gnb.recv_n3_data_packet(&self.gnb_ue_context).await
    }
}

impl<'a> MockUeNgap<'a> {
    pub async fn new_from_base(
        data: MockUe5GCData,
        ue_id: u32,
        gnb: &'a MockGnb,
        amf_ip_addr: &IpAddr,
        logger: &Logger,
    ) -> Result<Self> {
        let transport = UeNgapMode {
            gnb,
            gnb_ue_context: gnb.new_ue_context(ue_id, amf_ip_addr).await?,
        };
        Ok(MockUeNgap {
            base: MockUe::new_from_base(data, ue_id, transport, logger),
        })
    }

    pub async fn new(
        (imsi, sub_auth_params): (String, SubscriberAuthParams),
        ue_id: u32,
        gnb: &'a MockGnb,
        amf_ip_addr: &IpAddr,
        logger: &Logger,
    ) -> Result<Self> {
        let transport = UeNgapMode {
            gnb,
            gnb_ue_context: gnb.new_ue_context(ue_id, amf_ip_addr).await?,
        };
        Ok(MockUeNgap {
            base: MockUe::new(imsi, sub_auth_params, ue_id, transport, logger),
        })
    }

    pub async fn register(&mut self, gnb: &'a MockGnb) -> Result<()> {
        self.send_nas_register_request().await?;
        self.handle_nas_authentication().await?;
        self.handle_nas_security_mode().await?;
        gnb.handle_initial_context_setup(self).await?;
        gnb.send_ue_radio_capability_info(self).await?;
        self.handle_nas_registration_accept().await?;
        self.handle_nas_configuration_update().await
    }

    pub async fn establish_session(&mut self, gnb: &'a MockGnb) -> Result<()> {
        self.send_nas_pdu_session_establishment_request().await?;
        gnb.handle_pdu_session_resource_setup(self).await?;
        self.receive_nas_session_accept().await
    }

    pub async fn send_nas_register_request(&mut self) -> Result<()> {
        let nas_bytes = self.build_register_request()?;

        // On a GUTI register request, the UE does not include the STMSI in its Rrc Setup Complete
        // so it is not available to look up the NAS context.
        self.send_nas_no_outer_stmsi(nas_bytes).await
    }
}

impl<'a> AsRef<GnbUeContext> for MockUeNgap<'a> {
    fn as_ref(&self) -> &GnbUeContext {
        &self.base.transport.gnb_ue_context
    }
}

impl<'a> AsMut<GnbUeContext> for MockUeNgap<'a> {
    fn as_mut(&mut self) -> &mut GnbUeContext {
        &mut self.base.transport.gnb_ue_context
    }
}
