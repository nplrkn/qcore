use crate::f1ap::{F1AP_BIND_PORT, F1AP_SCTP_PPID};
use crate::procedures::{F1apHandler, UeMessageHandler};
use crate::userplane::PacketProcessor;
use crate::{Config, HandlerApi, UserplaneSession};
use crate::{SimCreds, SimTable};
use anyhow::{Result, bail};
use async_channel::Sender;
use async_std::sync::Mutex;
use async_trait::async_trait;
use dashmap::DashMap;
use f1ap::F1apPdu;
use slog::{Logger, info, o};
use std::net::IpAddr;
use std::sync::Arc;
use xxap::{
    GtpTunnel, Indication, IndicationHandler, Procedure, RequestError, RequestProvider,
    SctpTransportProvider, ShutdownHandle, Stack,
};

#[derive(Clone)]
pub struct QCore {
    config: Config,
    f1ap: Stack,
    logger: Logger,
    server_handle: Arc<Mutex<Option<ShutdownHandle>>>,
    packet_processor: PacketProcessor,
    ue_tasks: Arc<DashMap<u32, Sender<F1apPdu>>>,
    sim_auth_data: &'static SimTable,
}

impl QCore {
    pub async fn start(
        config: Config,
        logger: Logger,
        sim_auth_data: &'static SimTable,
    ) -> Result<Self> {
        let mut qc = Self::new(config, logger, sim_auth_data).await?;
        qc.run().await.expect("Startup failure");
        Ok(qc)
    }

    async fn new(config: Config, logger: Logger, sim_auth_data: &'static SimTable) -> Result<Self> {
        let local_ip = config.ip_addr;
        let packet_processor = PacketProcessor::new(
            local_ip,
            &config.n6_tun_name,
            config.ue_subnet.clone(),
            &logger,
        )
        .await?;
        Ok(Self {
            config,
            f1ap: Stack::new(SctpTransportProvider::new()),
            logger,
            server_handle: Arc::new(Mutex::new(None)),
            ue_tasks: Arc::new(DashMap::new()),
            packet_processor,
            sim_auth_data,
        })
    }

    async fn run(&mut self) -> Result<()> {
        let f1_listen_address = format!("{}:{}", self.config.ip_addr, F1AP_BIND_PORT);
        info!(
            &self.logger,
            "Listen for connection from DU on {}", f1_listen_address
        );

        let handle = self
            .f1ap
            .listen(
                f1_listen_address,
                F1AP_SCTP_PPID,
                F1apHandler::new_f1ap_application(self.clone()),
                self.logger.clone(),
            )
            .await?;
        *self.server_handle.lock().await = Some(handle);

        Ok(())
    }

    pub async fn graceful_shutdown(self) {
        info!(&self.logger, "Shutting down");
        self.f1ap.graceful_shutdown().await;
        if let Some(h) = self.server_handle.lock().await.take() {
            h.graceful_shutdown().await;
        }
    }

    pub fn ip_addr(&self) -> &IpAddr {
        &self.config.ip_addr
    }
}

#[async_trait]
impl HandlerApi for QCore {
    fn config(&self) -> &Config {
        &self.config
    }

    fn lookup_sim(&self, imsi: &str) -> Option<&'static SimCreds> {
        self.sim_auth_data.get(imsi)
    }

    fn spawn_ue_message_handler(&self) -> u32 {
        let mut ue_id = rand::random::<u32>();
        while self.ue_tasks.contains_key(&ue_id) {
            ue_id = rand::random::<u32>();
        }

        let sender =
            UeMessageHandler::spawn(ue_id, self.clone(), self.logger.new(o!("ue_id" => ue_id)));
        self.ue_tasks.insert(ue_id, sender);
        ue_id
    }

    async fn dispatch_ue_message(&self, ue_id: u32, message: F1apPdu) -> Result<()> {
        if let Some(sender) = self.ue_tasks.get(&ue_id) {
            sender.send(message).await?;
        } else {
            bail!("UE {ue_id} not found");
        }
        Ok(())
    }

    fn delete_ue_channel(&self, ue_id: u32) {
        self.ue_tasks.remove(&ue_id);
    }

    async fn f1ap_request<P: Procedure>(
        &self,
        r: P::Request,
        logger: &Logger,
    ) -> Result<P::Success, RequestError<P::Failure>> {
        <Stack as RequestProvider<P>>::request(&self.f1ap, r, logger)
            .await
            .map(|(x, _)| x)
    }
    async fn f1ap_indication<P: Indication>(&self, r: P::Request, logger: &Logger) {
        <Stack as IndicationHandler<P>>::handle(&self.f1ap, r, logger).await
    }

    async fn reserve_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession> {
        self.packet_processor
            .reserve_userplane_session(logger)
            .await
    }

    async fn commit_userplane_session(
        &self,
        session: &UserplaneSession,
        remote_tunnel_info: GtpTunnel,
        logger: &Logger,
    ) -> Result<()> {
        self.packet_processor
            .commit_userplane_session(session, remote_tunnel_info, logger)
            .await
    }

    async fn delete_userplane_session(&self, session: &UserplaneSession, logger: &Logger) {
        self.packet_processor
            .delete_userplane_session(session, logger)
            .await
    }
}
