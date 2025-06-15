use crate::f1ap::{F1AP_BIND_PORT, F1AP_SCTP_PPID};
use crate::nas::Tmsi;
use crate::ngap::{NGAP_BIND_PORT, NGAP_SCTP_PPID};
use crate::procedures::{F1apHandler, NgapHandler, UeMessage, UeMessageHandler};
use crate::userplane::PacketProcessor;
use crate::{
    Config, HandlerApi, NasContext, Sqn, SubscriberAuthParams, SubscriberDb, UserplaneSession,
};
use anyhow::{Result, anyhow, bail};
use async_std::{
    channel::{self, Sender},
    sync::Mutex,
    task::block_on,
};
use async_trait::async_trait;
use aya::Ebpf;
use dashmap::DashMap;
use slog::{Logger, info, o, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use xxap::{
    Indication, IndicationHandler, Procedure, RequestError, RequestProvider, SctpTransportProvider,
    ShutdownHandle, Stack,
};

#[derive(Clone)]
pub struct QCore {
    config: Config,
    stack: Stack,
    logger: Logger,
    server_handle: Arc<Mutex<Option<ShutdownHandle>>>,
    packet_processor: PacketProcessor,
    ue_tasks: Arc<DashMap<u32, Sender<UeMessage>>>,
    sub_db: Arc<Mutex<SubscriberDb>>,
    tmsis: Arc<Mutex<HashMap<Tmsi, NasContextLocator>>>,
    ngap_mode: bool,
}

enum NasContextLocator {
    Stored(NasContext),
    OwnedByUeTask(u32),
}

pub struct ProgramHandle {
    _ebpf: Ebpf,
    qc: Box<QCore>,
}
impl Deref for ProgramHandle {
    type Target = QCore;

    fn deref(&self) -> &Self::Target {
        &self.qc
    }
}
impl Drop for ProgramHandle {
    fn drop(&mut self) {
        block_on(self.qc.graceful_shutdown());
    }
}

impl QCore {
    pub async fn start(
        config: Config,
        logger: Logger,
        sub_db: SubscriberDb,
        ngap_mode: bool,
    ) -> Result<ProgramHandle> {
        let local_ip = config.ip_addr;
        let mut ebpf = PacketProcessor::install_ebpf(
            ngap_mode,
            local_ip,
            &config.f1u_interface_name,
            &config.n6_interface_name,
            &config.tun_interface_name,
            &logger,
        )?;
        info!(
            &logger,
            "Serving network name {}", config.serving_network_name
        );
        info!(&logger, "SST {}", config.sst);

        let packet_processor = PacketProcessor::new(config.ue_subnet, &mut ebpf, &logger).await?;

        let mut qc =
            Box::new(Self::new(config, packet_processor, logger, sub_db, ngap_mode).await?);
        qc.run().await.expect("Startup failure");
        Ok(ProgramHandle { qc, _ebpf: ebpf })
    }

    async fn new(
        config: Config,
        packet_processor: PacketProcessor,
        logger: Logger,
        sub_db: SubscriberDb,
        ngap_mode: bool,
    ) -> Result<Self> {
        Ok(Self {
            config,
            stack: Stack::new(SctpTransportProvider::new()),
            logger,
            server_handle: Arc::new(Mutex::new(None)),
            ue_tasks: Arc::new(DashMap::new()),
            packet_processor,
            sub_db: Arc::new(Mutex::new(sub_db)),
            tmsis: Arc::new(Mutex::new(HashMap::new())),
            ngap_mode,
        })
    }

    async fn run(&mut self) -> Result<()> {
        let port = if self.ngap_mode {
            NGAP_BIND_PORT
        } else {
            F1AP_BIND_PORT
        };
        let listen_address = format!("{}:{}", self.config.ip_addr, port);
        info!(
            &self.logger,
            "Listen for connection from RAN on {}", listen_address
        );

        let handle = if self.ngap_mode {
            self.stack
                .listen(
                    listen_address,
                    NGAP_SCTP_PPID,
                    NgapHandler::new_ngap_application(self.clone()),
                    self.logger.clone(),
                )
                .await?
        } else {
            self.stack
                .listen(
                    listen_address,
                    F1AP_SCTP_PPID,
                    F1apHandler::new_f1ap_application(self.clone()),
                    self.logger.clone(),
                )
                .await?
        };

        *self.server_handle.lock().await = Some(handle);

        Ok(())
    }

    pub async fn graceful_shutdown(&mut self) {
        info!(&self.logger, "Shutting down");
        self.stack.reset().await;
        if let Some(h) = self.server_handle.lock().await.take() {
            h.graceful_shutdown().await;
        }
    }

    /// Testability API to wait until all UE message handlers have processed all pending
    /// procedures.
    pub async fn wait_until_idle(&self) {
        let tasks = self.ue_tasks.iter();
        for task in tasks {
            let (sender, receiver) = channel::bounded(1);
            let _ = task.send(UeMessage::Ping(sender)).await;
            let _ = receiver.recv().await;
        }
    }

    pub fn ip_addr(&self) -> &IpAddr {
        &self.config.ip_addr
    }

    async fn put_tmsi(
        &self,
        tmsi: Tmsi,
        v: NasContextLocator,
        op: &str,
        ue_id: u32,
        logger: &Logger,
    ) {
        let old = self.tmsis.lock().await.insert(tmsi.clone(), v);

        match old {
            Some(NasContextLocator::Stored(_)) => {
                warn!(logger, "Duplicate {tmsi} {op} (stored)");
            }
            Some(NasContextLocator::OwnedByUeTask(old_ue_id)) if old_ue_id != ue_id => {
                warn!(logger, "Duplicate {tmsi} {op} - (owned by {old_ue_id})");
            }
            _ => {}
        }
    }
}

#[async_trait]
impl HandlerApi for QCore {
    fn config(&self) -> &Config {
        &self.config
    }

    fn ngap_mode(&self) -> bool {
        self.ngap_mode
    }

    async fn lookup_subscriber_creds_and_inc_sqn(
        &self,
        imsi: &str,
    ) -> Option<SubscriberAuthParams> {
        self.sub_db.lock().await.get_mut(imsi).map(|entry| {
            let pre_increment = entry.clone();
            entry.sqn.inc();
            pre_increment
        })
    }

    async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()> {
        let mut sqn = Sqn(sqn);

        // After a resync we need to add 1 to both the IND and SEQ parts of the SQN.  See TS33.102.
        const RESYNC_SQN_INCREMENT: u8 = 33;
        sqn.add(RESYNC_SQN_INCREMENT);

        self.sub_db
            .lock()
            .await
            .get_mut(imsi)
            .ok_or(anyhow!("IMSI not found"))
            .map(|entry| entry.sqn = sqn)
    }

    async fn take_nas_context(&self, tmsi: &Tmsi) -> Option<NasContext> {
        let entry = self.tmsis.lock().await.remove(tmsi)?;

        match entry {
            NasContextLocator::Stored(c) => Some(c),
            NasContextLocator::OwnedByUeTask(ue_id) => {
                let (sender, receiver) = channel::bounded(1);
                if self
                    .dispatch_ue_message(ue_id, UeMessage::TakeContext(sender))
                    .await
                    .is_err()
                {
                    return None;
                }
                let nas_context = receiver.recv().await;
                nas_context.ok()
            }
        }
    }

    async fn put_nas_context(
        &self,
        tmsi: Tmsi,
        ue_id: u32,
        c: NasContext,
        _ttl_secs: u32,
        logger: &Logger,
    ) {
        self.put_tmsi(tmsi, NasContextLocator::Stored(c), "put", ue_id, logger)
            .await
    }

    async fn register_new_tmsi(&self, tmsi: Tmsi, ue_id: u32, logger: &Logger) {
        self.put_tmsi(
            tmsi,
            NasContextLocator::OwnedByUeTask(ue_id),
            "register",
            ue_id,
            logger,
        )
        .await
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

    async fn dispatch_ue_message(&self, ue_id: u32, message: UeMessage) -> Result<()> {
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

    fn delete_ue_channels(&self) {
        self.ue_tasks.clear();
    }

    async fn xxap_request<P: Procedure>(
        &self,
        r: Box<P::Request>,
        logger: &Logger,
    ) -> Result<P::Success, RequestError<P::Failure>> {
        <Stack as RequestProvider<P>>::request(&self.stack, *r, logger)
            .await
            .map(|(x, _)| x)
    }
    async fn xxap_indication<P: Indication>(&self, r: Box<P::Request>, logger: &Logger) {
        <Stack as IndicationHandler<P>>::handle(&self.stack, *r, logger).await
    }

    async fn reserve_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession> {
        self.packet_processor
            .reserve_userplane_session(self.config().five_qi, self.config().pdcp_sn_length, logger)
            .await
    }

    async fn commit_userplane_session(
        &self,
        session: &UserplaneSession,
        logger: &Logger,
    ) -> Result<()> {
        self.packet_processor
            .commit_userplane_session(session, logger)
            .await
    }

    async fn delete_userplane_session(&self, session: &UserplaneSession, logger: &Logger) {
        self.packet_processor
            .delete_userplane_session(session, logger)
            .await
    }
}
