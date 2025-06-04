use anyhow::Result;
use async_trait::async_trait;
use slog::Logger;
use std::{
    net::{IpAddr, Ipv4Addr},
    ops::{Deref, DerefMut},
};

use crate::{GnbUeContext, MockGnb, MockUe, mock_ue::Transport};

pub struct MockUeNgap<'a> {
    base: MockUe<UeNgapMode<'a>>,
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
    async fn send_nas(&mut self, nas_bytes: Vec<u8>, logger: &Logger) -> Result<()> {
        self.gnb
            .send_nas(&self.gnb_ue_context, nas_bytes, logger)
            .await
    }

    async fn receive_nas(&mut self, logger: &Logger) -> Result<Vec<u8>> {
        self.gnb.receive_nas(&mut self.gnb_ue_context, logger).await
    }

    async fn send_userplane_packet(
        &self,
        _src_ip: &Ipv4Addr,
        _dst_ip: &Ipv4Addr,
        _src_port: u16,
        _dst_port: u16,
    ) -> Result<()> {
        todo!()
    }
    async fn receive_userplane_packet(&self) -> Result<Vec<u8>> {
        todo!()
    }
}

impl<'a> MockUeNgap<'a> {
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

    pub fn gnb_ue_context(&mut self) -> &mut GnbUeContext {
        &mut self.base.transport.gnb_ue_context
    }

    pub async fn send_nas_register_request(&mut self) -> Result<()> {
        let nas_bytes = self.build_register_request()?;
        self.send_nas(nas_bytes).await
    }
}
