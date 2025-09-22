use crate::{
    MockDu, MockGnb, MockUeF1ap, MockUeNgap,
    framework::{nth_imsi, wait_until_idle},
};
use anyhow::Result;
use async_std::sync::Mutex;
use qcore::{QCore, SubscriberDb};
use slog::Logger;
use std::net::IpAddr;

pub struct UeBuilder {
    register: bool,
    session: bool,
    ethernet: bool,
    qc_ip_addr: IpAddr,
    sims: SubscriberDb,
    logger: Logger,
    next_sim_id: Mutex<usize>,
    pub dnn: Option<&'static [u8]>,
}

impl UeBuilder {
    pub fn new(sims: SubscriberDb, qc_ip_addr: IpAddr, logger: Logger) -> Self {
        Self {
            register: false,
            session: false,
            ethernet: false,
            qc_ip_addr,
            sims,
            logger,
            next_sim_id: Mutex::new(0),
            dnn: None,
        }
    }
    pub fn registered(&mut self) -> &mut Self {
        self.register = true;
        return self;
    }

    pub fn use_ethernet(&mut self) -> &mut Self {
        self.ethernet = true;
        return self;
    }

    pub fn use_dnn(&mut self, dnn: &'static [u8]) -> &mut Self {
        self.dnn = Some(dnn);
        return self;
    }

    pub fn with_session(&mut self) -> &mut Self {
        self.session = true;
        return self.registered();
    }

    pub fn with_ethernet_session(&mut self) -> &mut Self {
        self.ethernet = true;
        return self.with_session();
    }

    pub fn reset(&mut self) -> &mut Self {
        self.ethernet = false;
        self.session = false;
        self.register = false;
        return self;
    }

    pub async fn reset_ue_index(&mut self) -> &mut Self {
        *self.next_sim_id.lock().await = 0;
        return self;
    }

    pub async fn new_ngap_ue_no_wait<'a>(&self, gnb: &'a MockGnb) -> Result<MockUeNgap<'a>> {
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
        if self.register {
            ue.register(gnb).await?;
        }
        if self.session {
            ue.establish_session(gnb).await?;
        }
        Ok(ue)
    }

    pub async fn new_ngap_ue<'a>(&self, gnb: &'a MockGnb, qc: &'a QCore) -> Result<MockUeNgap<'a>> {
        let ue = self.new_ngap_ue_no_wait(gnb).await?;
        wait_until_idle(qc).await?;
        Ok(ue)
    }

    pub async fn new_f1ap_ue<'a>(&self, du: &'a MockDu, qc: &'a QCore) -> Result<MockUeF1ap<'a>> {
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
        if self.register {
            ue.register().await?;
        }
        if self.session {
            ue.establish_session(du).await?;
        }
        wait_until_idle(qc).await?;
        Ok(ue)
    }
}
