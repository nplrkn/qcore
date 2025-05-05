//! transport_provider - trait encapsulating the transport services needed by the RAN protocol stacks

use crate::{Message, ShutdownHandle, TnlaEventHandler};
use anyhow::Result;
use async_net::SocketAddr;
use async_trait::async_trait;
use slog::Logger;

pub type AssocId = u32;
pub struct Binding {
    pub assoc_id: AssocId,
    pub remote_ip: String,
    // stream will go here
}

/// The TransportProvider trait abstracts the transport, for example, to allow a non-SCTP test transport to be used.
#[async_trait]
pub trait TransportProvider: Send + Sync + 'static {
    async fn send_message(
        &self,
        message: Message,
        assoc_id: Option<u32>,
        logger: &Logger,
    ) -> Result<()>;

    async fn serve<H>(
        self,
        listen_addr: String,
        ppid: u32,
        handler: H,
        logger: Logger,
    ) -> Result<ShutdownHandle>
    where
        H: TnlaEventHandler;

    async fn connect<H>(
        self,
        connect_addr_string: &str,
        bind_addr_string: &str,
        ppid: u32,
        handler: H,
        logger: Logger,
    ) -> Result<()>
    where
        H: TnlaEventHandler;

    // Pick a new UE binding.
    async fn new_ue_binding(&self, seed: u32) -> Result<Binding>;
    async fn new_ue_binding_from_assoc(&self, assoc_id: &AssocId) -> Result<Binding>;
    async fn new_ue_binding_from_ip(&self, ip_addr: &str) -> Result<Binding>;

    // Return the set of TNLA remote address to which we are currently connected
    async fn remote_tnla_addresses(&self) -> Vec<(AssocId, SocketAddr)>;
}
