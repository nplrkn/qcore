// QCore Cluster protocol
//
// Cluster members serve a defined TCP port on their cluster interface local address.
//
// Cluster members establish replication connections to each other.  Each replication
// connection has a sender and receiver.
// -  The receiver connects to the sender from an ephemeral port and sends a hello message.
// -  The sender then sends an infinite stream of UE contexts on the connection.
//
// The same IP address is used for send and receive.  So, on receipt of a hello message,
// an instance without an active receiver connection sets one up.

// Connection maintenance
//
// TBD - don't just keep retrying

use crate::{ClusterConfig, data::UeContext5GC};
use anyhow::{Result, ensure};
use async_std::{sync::Mutex, task::JoinHandle};
use futures_lite::prelude::*;
use slog::{Logger, debug, info, warn};
use smol::net::{TcpListener, TcpStream};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

// pub struct HelloMessage {
//     protocol_version: u32,
// }

// pub struct ReplicationMessage {
//     pub placeholder: u32,
// }

#[derive(Clone)]
pub struct ClusterMember {
    sender: Arc<Mutex<Option<TcpStream>>>,
    cluster_tcp_port: u16,
    local_ip: IpAddr,
    peer_ip: Option<IpAddr>,
    receiver: Arc<Mutex<Option<JoinHandle<()>>>>,
}

#[derive(Clone)]
pub struct ClusterHandler<H: ReplicationHandler> {
    base: Arc<ClusterMember>,
    handler: Arc<H>,
}

const MAX_LENGTH: usize = 1024;

impl ClusterMember {
    pub async fn new(config: &ClusterConfig, _logger: &Logger) -> Result<Self> {
        let member = ClusterMember {
            sender: Arc::new(Mutex::new(None)),
            cluster_tcp_port: config.cluster_tcp_port,
            local_ip: config.local_ip,
            peer_ip: config.peer_ip,
            receiver: Arc::new(Mutex::new(None)),
        };

        Ok(member)
    }

    pub async fn handle<H: ReplicationHandler>(&self, handler: H, logger: &Logger) -> Result<()> {
        let handler = ClusterHandler {
            base: Arc::new(self.clone()),
            handler: Arc::new(handler),
        };

        // Join an existing cluster if we were configured with an IP address.
        if let Some(peer) = self.peer_ip {
            info!(logger, "Connect to existing cluster");
            handler.start_receiver(peer, logger.clone()).await;
        }

        // Accept incoming connections.
        handler.start_accepter(logger.clone()).await
    }

    // Warning: this can take a long time to return if the connection is congested or broken.
    pub async fn replicate_ue_context(&self, cxt: &UeContext5GC, logger: &Logger) -> Result<()> {
        // We clone the TcpStream to avoid holding the mutex during the transmission.
        let sender = self.sender.lock().await.clone();

        let Some(mut sender) = sender else {
            // No receiver attached right now.
            return Ok(());
        };

        let bytes = bincode::encode_to_vec(cxt, bincode::config::standard())?;
        let length = bytes.len() as u16;

        if sender.write(&length.to_be_bytes()).await.is_ok() && sender.write(&bytes).await.is_ok() {
            debug!(
                logger,
                "Successfully wrote UE context to replication stream"
            )
        } else {
            // TODO - sender is down, but it is a false assumption that self.sender is down.  It might have changed
            // since we took the clone of it above, so we might be killing a perfectly good connection.
            // That said, the other side should retry, so we should recover if we hit this timing window.
            *self.sender.lock().await = None;
            info!(
                logger,
                "Replication send channel down - now waiting for new connection"
            );
        }

        Ok(())
    }
}

impl<H: ReplicationHandler> ClusterHandler<H> {
    async fn start_receiver(&self, peer: IpAddr, logger: Logger) {
        let mut receiver = self.base.receiver.lock().await;
        let self_clone = self.clone();
        if receiver.is_none() {
            let join_handle = async_std::task::spawn(async move {
                if let Err(e) = self_clone.connect_and_receive_task(peer, &logger).await {
                    warn!(logger, "Receive task exited with error {:#}", e);
                }
            });
            *receiver = Some(join_handle);
        }
    }

    async fn start_accepter(&self, logger: Logger) -> Result<()> {
        let sockaddr = SocketAddr::new(self.base.local_ip, self.base.cluster_tcp_port);
        info!(
            logger,
            "My cluster port     : {}:{}", self.base.local_ip, self.base.cluster_tcp_port
        );
        let listener = TcpListener::bind(sockaddr).await?;

        let logger = logger.clone();
        let self_clone = self.clone();

        let _incoming_connection_task =
            async_std::task::spawn(async move { self_clone.accept_task(listener, logger).await });
        Ok(())
    }

    async fn accept_task(self, listener: TcpListener, logger: Logger) -> Result<()> {
        debug!(logger, "Starting accept thread");
        loop {
            let (connection, peer) = listener.accept().await?;
            let mut sender = self.base.sender.lock().await;
            if sender.is_none() {
                *sender = Some(connection);
                debug!(logger, "Accepted replication connection from {peer}");
                self.handler.new_receiver();
            } else {
                warn!(
                    logger,
                    "New cluster connection from {peer} dropped - already connected"
                )
            }
            self.start_receiver(peer.ip(), logger.clone()).await;
        }
    }

    async fn connect_and_receive_task(&self, peer_ip: IpAddr, logger: &Logger) -> Result<()> {
        let peer_sockaddr = SocketAddr::new(peer_ip, self.base.cluster_tcp_port);

        // TODO: Make sure our outgoing connections emanate from the same local address that we are
        // listening on.
        //
        // Do this in a spawn_blocking thread??
        //
        // let local_sockaddr = std::net::SocketAddr::new(self.local_ip, 0);
        // let socket = Socket::new(socket2::Domain::IPV4, Type::STREAM, None)?;
        // socket.bind(&local_sockaddr.into())?;

        loop {
            let connection = TcpStream::connect(peer_sockaddr).await;
            if let Ok(mut connection) = connection {
                self.send_hello(&connection, logger).await;
                self.receive_ue_contexts(&mut connection, logger).await?;
            } else {
                warn!(logger, "Couldn't connect to cluster peer {}", peer_ip);
            }

            // We hit an error, or the connection was terminated by the remote side, or it never connected
            // in the first place.
            //
            // Just keep trying.  TODO.
            async_std::task::sleep(Duration::from_secs(10)).await;
        }
    }

    async fn send_hello(&self, _connection: &TcpStream, logger: &Logger) {
        debug!(logger, "Send hello placeholder");
    }

    async fn receive_ue_contexts(&self, connection: &mut TcpStream, logger: &Logger) -> Result<()> {
        let mut length_buf = [0u8; 2];
        loop {
            // Receive the length.
            connection.read_exact(&mut length_buf).await?;
            let length = u16::from_be_bytes(length_buf) as usize;
            ensure!(
                length < MAX_LENGTH,
                "Illegal protocol operation - length too long"
            );
            let mut buf = vec![0u8; length as usize];
            connection.read_exact(&mut buf).await?;

            // TODO Make this generic?
            // TODO use decode_from_std_read()?  See https://docs.rs/bincode/2.0.1/bincode/
            let (ue_context, _len): (UeContext5GC, usize) =
                bincode::decode_from_slice(&buf[..], bincode::config::standard())?;
            debug!(
                logger,
                "Received replicated UE context for TMSI {:?}", ue_context.tmsi
            );
            self.handler.store_replicated_ue_context(ue_context).await;
        }
    }
}

pub trait ReplicationHandler: Clone + Send + Sync + 'static {
    fn store_replicated_ue_context(
        &self,
        c: UeContext5GC,
    ) -> impl std::future::Future<Output = ()> + std::marker::Send;

    fn new_receiver(&self);
}
