use crate::data::{NasContext, Sqn};
use crate::f1ap::{F1AP_BIND_PORT, F1AP_SCTP_PPID};
use crate::procedures::{F1apHandler, UeMessage, UeMessageHandler};
use crate::protocols::nas::Tmsi;
use crate::userplane::PacketProcessor;
use crate::{Config, HandlerApi, SubscriberAuthParams, SubscriberDb, UserplaneSession};
use anyhow::{Result, anyhow, bail};
use async_std::channel::{self, Sender};
use async_std::sync::Mutex;
use async_std::task::block_on;
use async_trait::async_trait;
use aya::Ebpf;
use dashmap::DashMap;
use slog::{Logger, info, o, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Deref;
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
    ue_tasks: Arc<DashMap<u32, Sender<UeMessage>>>,
    sub_db: Arc<Mutex<SubscriberDb>>,
    tmsis: Arc<Mutex<HashMap<Tmsi, NasContextLocator>>>,
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
    ) -> Result<ProgramHandle> {
        let local_ip = config.ip_addr;
        let mut ebpf = PacketProcessor::install_ebpf(
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

        let mut qc = Box::new(Self::new(config, packet_processor, logger, sub_db).await?);
        qc.run().await.expect("Startup failure");
        Ok(ProgramHandle { qc, _ebpf: ebpf })
    }

    async fn new(
        config: Config,
        packet_processor: PacketProcessor,
        logger: Logger,
        sub_db: SubscriberDb,
    ) -> Result<Self> {
        Ok(Self {
            config,
            f1ap: Stack::new(SctpTransportProvider::new()),
            logger,
            server_handle: Arc::new(Mutex::new(None)),
            ue_tasks: Arc::new(DashMap::new()),
            packet_processor,
            sub_db: Arc::new(Mutex::new(sub_db)),
            tmsis: Arc::new(Mutex::new(HashMap::new())),
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

    pub async fn graceful_shutdown(&mut self) {
        info!(&self.logger, "Shutting down");
        self.f1ap.reset().await;
        if let Some(h) = self.server_handle.lock().await.take() {
            h.graceful_shutdown().await;
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

        // Testing with Samsung phone indicates that we need to do a double
        // increment after receiving the resync SQN.
        sqn.add(2);

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

    async fn f1ap_request<P: Procedure>(
        &self,
        r: Box<P::Request>,
        logger: &Logger,
    ) -> Result<P::Success, RequestError<P::Failure>> {
        <Stack as RequestProvider<P>>::request(&self.f1ap, *r, logger)
            .await
            .map(|(x, _)| x)
    }
    async fn f1ap_indication<P: Indication>(&self, r: Box<P::Request>, logger: &Logger) {
        <Stack as IndicationHandler<P>>::handle(&self.f1ap, *r, logger).await
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
