use super::subscriber_db::SubscriberDb;
use super::userplane::PacketProcessor;
use crate::f1ap::{F1AP_BIND_PORT, F1AP_SCTP_PPID};
use crate::ngap::{NGAP_BIND_PORT, NGAP_SCTP_PPID};
use crate::procedures::{F1apHandler, NgapHandler, UeMessage, UeMessageHandler};
use crate::{Config, ProcedureBase, Sqn, SubscriberAuthParams, UeContext5GC, UserplaneSession};
use anyhow::{Result, anyhow, bail};
use async_std::{
    channel::{self, Sender},
    sync::Mutex,
    task::block_on,
};
use async_trait::async_trait;
use aya::Ebpf;
use f1ap::GnbDuServedCellsItem;
use slog::{Logger, debug, info, o, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use xxap::{
    Indication, IndicationHandler, Procedure, RequestError, RequestProvider, SctpTransportProvider,
    ShutdownHandle, Stack,
};

pub type DuServedCells = Vec<GnbDuServedCellsItem>;
pub type DuId = u64;
pub type ServedCellsMap = Arc<Mutex<HashMap<DuId, DuServedCells>>>;

#[derive(Clone)]
pub struct QCore {
    config: Config,
    stack: Stack,
    logger: Logger,
    server_handle: Arc<Mutex<Option<ShutdownHandle>>>,
    packet_processor: PacketProcessor,
    ue_tasks: Arc<Mutex<HashMap<u32, Sender<UeMessage>>>>,
    sub_db: Arc<Mutex<SubscriberDb>>,
    tmsis: Arc<Mutex<HashMap<[u8; 4], CoreContextLocator>>>,
    served_cells: ServedCellsMap,
    ngap_mode: bool,
}

enum CoreContextLocator {
    Stored(UeContext5GC),
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
        userplane_stats: bool,
    ) -> Result<ProgramHandle> {
        let local_ip = config.ip_addr;
        let mut ebpf = PacketProcessor::install_ebpf(
            ngap_mode,
            local_ip,
            &config.ran_interface_name,
            &config.n6_interface_name,
            &config.tun_interface_name,
            &logger,
        )?;
        info!(
            &logger,
            "Serving network name {}", config.serving_network_name
        );
        info!(&logger, "Supported slice SST {}", config.sst);

        let packet_processor =
            PacketProcessor::new(config.ue_subnet, &mut ebpf, userplane_stats, &logger).await?;

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
            ue_tasks: Arc::new(Mutex::new(HashMap::new())),
            packet_processor,
            sub_db: Arc::new(Mutex::new(sub_db)),
            tmsis: Arc::new(Mutex::new(HashMap::new())),
            served_cells: Arc::new(Mutex::new(HashMap::new())),
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
        debug!(self.logger, "Wait until idle");

        // Make a copy of the task IDs, to avoid holding a lock when iterating waiting for replies below.
        let task_ids: Vec<u32> = self.ue_tasks.lock().await.iter().map(|x| *x.0).collect();

        // Ping each task
        for task_id in task_ids.into_iter() {
            debug!(self.logger, "Ping UE task");
            let (sender, receiver) = channel::bounded(1);
            if self
                .dispatch_ue_message(task_id, UeMessage::Ping(sender))
                .await
                .is_ok()
            {
                let _ = receiver.recv().await;
            }
            debug!(self.logger, "Ping UE task done");
        }
    }

    pub fn ip_addr(&self) -> &IpAddr {
        &self.config.ip_addr
    }

    async fn put_tmsi(
        &self,
        tmsi: [u8; 4],
        v: CoreContextLocator,
        op: &str,
        ue_id: u32,
        logger: &Logger,
    ) {
        let old = self.tmsis.lock().await.insert(tmsi, v);

        match old {
            Some(CoreContextLocator::Stored(_)) => {
                warn!(logger, "Duplicate {tmsi:?} {op} (stored)");
            }
            Some(CoreContextLocator::OwnedByUeTask(old_ue_id)) if old_ue_id != ue_id => {
                warn!(logger, "Duplicate {tmsi:?} {op} - (owned by {old_ue_id})");
            }
            _ => {}
        }
    }
}

#[async_trait]
impl ProcedureBase for QCore {
    fn config(&self) -> &Config {
        &self.config
    }

    fn ngap_mode(&self) -> bool {
        self.ngap_mode
    }

    fn served_cells(&self) -> &ServedCellsMap {
        &self.served_cells
    }

    async fn lookup_subscriber_creds_and_inc_sqn(
        &self,
        imsi: &str,
    ) -> Option<SubscriberAuthParams> {
        self.sub_db.lock().await.0.get_mut(imsi).map(|entry| {
            let pre_increment = entry.clone();
            entry.sqn.inc();
            pre_increment
        })
    }

    async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()> {
        let mut sqn = Sqn(sqn);

        // After a resync we need to add 1 to both the IND and SEQ parts of the SQN.  See TS33.102.
        const RESYNC_SQN_INCREMENT: u8 = 32; // temp hack
        sqn.add(RESYNC_SQN_INCREMENT);

        self.sub_db
            .lock()
            .await
            .0
            .get_mut(imsi)
            .ok_or(anyhow!("IMSI not found"))
            .map(|entry| entry.sqn = sqn)
    }

    async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC> {
        loop {
            let entry = self.tmsis.lock().await.remove(tmsi)?;

            match entry {
                CoreContextLocator::Stored(c) => return Some(c),

                CoreContextLocator::OwnedByUeTask(ue_id) => {
                    let (sender, receiver) = channel::bounded(1);
                    if self
                        .dispatch_ue_message(ue_id, UeMessage::TakeContext(sender))
                        .await
                        .is_ok()
                    {
                        if let Ok(nas_context) = receiver.recv().await {
                            return Some(nas_context);
                        }
                    }

                    // Continue loop to retry
                    // There is a timing window where, if a UE message handler is simultaneously shutting down,
                    // we can remove the TMSI entry from the tmsis map, just before the
                    // UE message handler puts its context back into the map as a new Stored entry.
                    // Therefore, if the TakeContext message fails, we should retry.

                    // This requires the UE message handler to convert the TMSI entry to Stored
                    // before it closes down its channel.  That guarantees that if the channel operation fails
                    // the TMSI entry will be back in the map on the next iteration.
                }
            }
        }
    }

    async fn put_core_context(
        &self,
        tmsi: [u8; 4],
        ue_id: u32,
        c: UeContext5GC,
        _ttl_secs: u32,
        logger: &Logger,
    ) {
        self.put_tmsi(tmsi, CoreContextLocator::Stored(c), "put", ue_id, logger)
            .await
    }

    async fn register_new_tmsi(&self, ue_id: u32, logger: &Logger) -> [u8; 4] {
        let tmsi: [u8; 4] = rand::random(); // TODO: 0xffffffff is not a valid TMSI (TS23.003, 2.4))
        debug!(self.logger, "Assigned {:?}", tmsi);

        self.put_tmsi(
            tmsi.clone(),
            CoreContextLocator::OwnedByUeTask(ue_id),
            "register",
            ue_id,
            logger,
        )
        .await;
        tmsi
    }

    async fn spawn_ue_message_handler(&self) -> u32 {
        let mut ue_id = rand::random::<u32>();

        while self.ue_tasks.lock().await.contains_key(&ue_id) {
            ue_id = rand::random::<u32>();
        }

        let sender =
            UeMessageHandler::spawn(ue_id, self.clone(), self.logger.new(o!("ue_id" => ue_id)));
        self.ue_tasks.lock().await.insert(ue_id, sender);
        ue_id
    }

    async fn dispatch_ue_message(&self, ue_id: u32, message: UeMessage) -> Result<()> {
        if let Some(sender) = self.ue_tasks.lock().await.get(&ue_id) {
            sender.send(message).await?;
        } else {
            bail!("UE {ue_id} not found");
        }
        Ok(())
    }

    async fn delete_ue_channel(&self, ue_id: u32) {
        self.ue_tasks.lock().await.remove(&ue_id);
    }

    async fn disconnect_ues(&self) {
        let task_ids: Vec<u32> = self.ue_tasks.lock().await.iter().map(|x| *x.0).collect();
        for task_id in task_ids {
            let _ = self
                .dispatch_ue_message(task_id, UeMessage::Disconnect)
                .await;
        }
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

    async fn allocate_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession> {
        self.packet_processor
            .allocate_userplane_session(self.config().five_qi, self.config().pdcp_sn_length, logger)
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

    async fn deactivate_userplane_session(&self, session: &UserplaneSession, logger: &Logger) {
        self.packet_processor
            .deactivate_userplane_session(session, logger)
            .await
    }
}
