//! sctp_transport_provider - the standard TransportProvider used for SCTP-based protocols NGAP, F1AP and E1AP

use super::sctp_tnla_pool::SctpTnlaPool;
use super::tnla_event_handler::TnlaEventHandler;
use super::{AssocId, Binding, Listener, Message, SctpAssociation};
use crate::{ShutdownHandle, TransportProvider};
use anyhow::{Result, anyhow, bail};
use async_std::sync::Arc;
use async_std::task;
use async_trait::async_trait;
use futures::{FutureExt, pin_mut, select};
use slog::{Logger, info, warn};
use std::net::SocketAddr;
use stop_token::StopSource;

#[derive(Clone)]
pub struct SctpTransportProvider {
    tnla_pool: SctpTnlaPool,
}

impl SctpTransportProvider {
    pub fn new() -> SctpTransportProvider {
        SctpTransportProvider {
            tnla_pool: SctpTnlaPool::new(),
        }
    }
    pub async fn graceful_shutdown(self) {
        self.tnla_pool.graceful_shutdown().await
    }
}

impl Default for SctpTransportProvider {
    fn default() -> Self {
        Self::new()
    }
}

async fn resolve_and_connect(
    connect_addr_string: &str,
    bind_addr_string: &str,
    ppid: u32,
    logger: &Logger,
) -> Result<SctpAssociation> {
    let connect_addr = async_net::resolve(connect_addr_string)
        .await?
        .into_iter()
        .next()
        .ok_or(anyhow!("Address resolved to empty array"))?; // Don't know if this is actually hittable
    let bind_addr = format!("{}:0", bind_addr_string).parse()?;
    SctpAssociation::establish(connect_addr, bind_addr, ppid, logger).await
}

#[async_trait]
impl TransportProvider for SctpTransportProvider {
    async fn send_message(
        &self,
        message: Message,
        assoc_id: Option<u32>,
        logger: &Logger,
    ) -> Result<()> {
        self.tnla_pool.send_message(message, assoc_id, logger).await
    }

    async fn connect<H>(
        self,
        connect_addr_string: &str,
        bind_addr_string: &str,
        ppid: u32,
        handler: H,
        logger: Logger,
    ) -> Result<()>
    where
        H: TnlaEventHandler,
    {
        //let connect_addr_string = connect_addr_string.clone();
        let assoc =
            resolve_and_connect(connect_addr_string, bind_addr_string, ppid, &logger).await?;
        //let logger = logger.new(o!("connection" => assoc_id));
        self.tnla_pool
            .add_and_handle(
                assoc.fd as u32,
                Arc::new(assoc),
                handler.clone(),
                logger.clone(),
            )
            .await;

        Ok(())
    }

    // Pick a new UE binding.
    async fn new_ue_binding(&self, seed: u32) -> Result<Binding> {
        self.tnla_pool.new_ue_binding(seed).await
    }

    async fn new_ue_binding_from_assoc(&self, assoc_id: &AssocId) -> Result<Binding> {
        self.tnla_pool.new_ue_binding_from_assoc(assoc_id).await
    }

    async fn new_ue_binding_from_ip(&self, ip_addr: &str) -> Result<Binding> {
        if let Some((assoc_id, _)) = self
            .remote_tnla_addresses()
            .await
            .iter()
            .find(|(_, x)| x.ip().to_string() == ip_addr)
        {
            self.new_ue_binding_from_assoc(assoc_id).await
        } else {
            bail!("No such remote ip addr");
        }
    }

    // Return the set of TNLA remote address to which we are currently connected
    async fn remote_tnla_addresses(&self) -> Vec<(AssocId, SocketAddr)> {
        self.tnla_pool.remote_addresses().await
    }

    async fn serve<H>(
        self,
        listen_addr: String,
        ppid: u32,
        handler: H,
        logger: Logger,
    ) -> Result<ShutdownHandle>
    where
        H: TnlaEventHandler,
    {
        let addr = async_net::resolve(&listen_addr).await.map(|vec| vec[0])?;
        let stop_source = StopSource::new();
        let stop_token = stop_source.token();
        let listener = Listener::new(addr, MAX_LISTEN_BACKLOG)?;
        let join_handle = task::spawn(async move {
            let stop_token = stop_token.fuse();
            pin_mut!(stop_token);
            loop {
                let next_assoc = listener.accept(ppid, logger.clone()).fuse();
                pin_mut!(next_assoc);
                select!(
                    _ = stop_token => {
                         info!(logger, "End listen {}", listen_addr);
                         break;
                        },
                    assoc = next_assoc => {
                        match assoc {
                            Ok(assoc) => {
                                self.tnla_pool
                                .clone()
                                .add_and_handle(
                                    assoc.fd as u32,
                                    Arc::new(assoc),
                                    handler.clone(),
                                    logger.clone(),
                                )
                                .await;
                            }
                            Err(e)=> warn!(logger, "Error on incoming connection - {:?}", e),
                        }
                    },
                );
            }
            listener.close();
            self.tnla_pool.graceful_shutdown().await;
        });
        Ok(ShutdownHandle::new(join_handle, stop_source))
    }
}

const MAX_LISTEN_BACKLOG: i32 = 5;
