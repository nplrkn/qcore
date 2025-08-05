use anyhow::Result;
use async_trait::async_trait;
use slog::Logger;
use std::{
    net::{IpAddr, Ipv4Addr},
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

    async fn send_userplane_packet(
        &self,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<()> {
        let packet = Packet::new_ue_udp(src_ip, dst_ip, src_port, dst_port);
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
        imsi: String,
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
            base: MockUe::new(imsi, ue_id, transport, logger),
        })
    }

    pub async fn new_registered(
        imsi: String,
        ue_id: u32,
        gnb: &'a MockGnb,
        cu_ip_addr: &IpAddr,
        logger: &Logger,
    ) -> Result<Self> {
        let mut ue = MockUeNgap::new(imsi, ue_id, gnb, cu_ip_addr, logger).await?;
        ue.send_nas_register_request().await?;
        ue.handle_nas_authentication().await?;
        ue.handle_nas_security_mode().await?;
        gnb.handle_initial_context_setup(ue.gnb_ue_context())
            .await?;
        gnb.send_ue_radio_capability_info(ue.gnb_ue_context())
            .await?;
        ue.handle_nas_registration_accept().await?;
        ue.handle_nas_configuration_update().await?;
        Ok(ue)
    }

    pub async fn new_with_session(
        imsi: String,
        ue_id: u32,
        gnb: &'a MockGnb,
        cu_ip_addr: &IpAddr,
        logger: &Logger,
    ) -> Result<Self> {
        let mut ue = MockUeNgap::new_registered(imsi, ue_id, gnb, cu_ip_addr, logger).await?;

        // UE establishes PDU session
        ue.send_nas_pdu_session_establishment_request().await?;
        gnb.handle_pdu_session_resource_setup(ue.gnb_ue_context())
            .await?;
        ue.receive_nas_session_accept().await?;
        Ok(ue)
    }

    pub fn gnb_ue_context(&mut self) -> &mut GnbUeContext {
        &mut self.base.transport.gnb_ue_context
    }

    pub async fn send_nas_register_request(&mut self) -> Result<()> {
        let nas_bytes = self.build_register_request()?;

        // On a GUTI register request, the UE does not include the STMSI in its Rrc Setup Complete
        // so it is not available to look up the NAS context.
        self.send_nas_no_outer_stmsi(nas_bytes).await
    }
}
