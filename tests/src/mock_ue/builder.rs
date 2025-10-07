use crate::{MockDu, MockGnb, MockUeF1ap, MockUeNgap, framework::nth_imsi};
use anyhow::Result;
use async_std::sync::Mutex;
use qcore::SubscriberDb;
use slog::Logger;
use std::net::IpAddr;

pub struct UeBuilder {
    ethernet: bool,
    qc_ip_addr: IpAddr,
    pub sims: SubscriberDb,
    logger: Logger,
    next_sim_id: Mutex<usize>,
    pub dnn: Option<&'static [u8]>,
}

impl UeBuilder {
    pub fn new(sims: SubscriberDb, qc_ip_addr: IpAddr, logger: Logger) -> Self {
        Self {
            ethernet: false,
            qc_ip_addr,
            sims,
            logger,
            next_sim_id: Mutex::new(0),
            dnn: None,
        }
    }

    pub fn use_ethernet(&mut self) -> &mut Self {
        self.ethernet = true;
        self
    }

    pub fn use_dnn(&mut self, dnn: &'static [u8]) -> &mut Self {
        self.dnn = Some(dnn);
        self
    }

    pub fn reset(&mut self) -> &mut Self {
        self.ethernet = false;
        self.dnn = None;
        self
    }

    pub async fn reset_ue_index(&mut self) -> &mut Self {
        *self.next_sim_id.lock().await = 0;
        self
    }

    pub fn ngap_ue<'a>(&'a self, gnb: &'a MockGnb) -> NgapUeBuilder<'a> {
        NgapUeBuilder { gnb, builder: self }
    }

    pub fn f1ap_ue<'a>(&'a self, du: &'a MockDu) -> F1apUeBuilder<'a> {
        F1apUeBuilder { du, builder: self }
    }

    async fn new_ngap_ue<'a>(&self, gnb: &'a MockGnb) -> Result<MockUeNgap<'a>> {
        let mut ue = MockUeNgap::new(
            nth_imsi(*self.next_sim_id.lock().await, &self.sims),
            1,
            gnb,
            &self.qc_ip_addr,
            &self.logger,
        )
        .await?;
        *self.next_sim_id.lock().await += 1;
        if self.ethernet {
            ue.use_ethernet();
        }
        if let Some(dnn) = self.dnn {
            ue.use_dnn(dnn);
        }
        Ok(ue)
    }

    async fn new_f1ap_ue<'a>(&self, du: &'a MockDu) -> Result<MockUeF1ap<'a>> {
        let mut ue = MockUeF1ap::new(
            nth_imsi(*self.next_sim_id.lock().await, &self.sims),
            1,
            du,
            &self.qc_ip_addr,
            &self.logger,
        )
        .await?;
        *self.next_sim_id.lock().await += 1;
        if self.ethernet {
            ue.use_ethernet();
        }
        if let Some(dnn) = self.dnn {
            ue.use_dnn(dnn);
        }
        Ok(ue)
    }
}

pub struct NgapUeBuilder<'a> {
    gnb: &'a MockGnb,
    builder: &'a UeBuilder,
}

impl<'a> NgapUeBuilder<'a> {
    pub async fn build(self) -> Result<MockUeNgap<'a>> {
        self.builder.new_ngap_ue(self.gnb).await
    }

    pub async fn registered(self) -> Result<MockUeNgap<'a>> {
        let mut ue = self.builder.new_ngap_ue(self.gnb).await?;
        ue.register(self.gnb).await?;
        Ok(ue)
    }

    pub async fn with_session(self) -> Result<MockUeNgap<'a>> {
        let mut ue = self.builder.new_ngap_ue(self.gnb).await?;
        ue.register(self.gnb).await?;
        ue.establish_session(self.gnb).await?;
        Ok(ue)
    }
}

pub struct F1apUeBuilder<'a> {
    du: &'a MockDu,
    builder: &'a UeBuilder,
}

impl<'a> F1apUeBuilder<'a> {
    pub async fn build(self) -> Result<MockUeF1ap<'a>> {
        self.builder.new_f1ap_ue(self.du).await
    }

    pub async fn registered(self) -> Result<MockUeF1ap<'a>> {
        let mut ue = self.builder.new_f1ap_ue(self.du).await?;
        ue.register().await?;
        Ok(ue)
    }

    pub async fn with_session(self) -> Result<MockUeF1ap<'a>> {
        let mut ue = self.builder.new_f1ap_ue(self.du).await?;
        ue.register().await?;
        ue.establish_session(self.du).await?;
        Ok(ue)
    }
}
