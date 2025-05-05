//! sctp_tnla_pool - global connection pool enabling a suitable TNLA to be selected for an outgoing message

use crate::ShutdownHandle;
use crate::{AssocId, Binding, TnlaEvent, TnlaEventHandler};
use crate::{Message, SctpAssociation};
use anyhow::{Result, bail, ensure};
use async_std::sync::{Arc, Mutex};
use dashmap::DashMap;
use futures::pin_mut;
use futures::stream::StreamExt;
use slog::Logger;
use std::net::SocketAddr;
use stop_token::{StopSource, StopToken};
type SharedAssocHash = Arc<DashMap<AssocId, Arc<SctpAssociation>>>;

#[derive(Clone)]
pub struct SctpTnlaPool {
    assocs: SharedAssocHash,
    tasks: Arc<Mutex<Vec<ShutdownHandle>>>,
}

impl SctpTnlaPool {
    pub fn new() -> SctpTnlaPool {
        SctpTnlaPool {
            assocs: Arc::new(DashMap::new()),
            tasks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn graceful_shutdown(self) {
        for task in self.tasks.lock().await.drain(..) {
            task.graceful_shutdown().await;
        }
    }

    pub async fn remote_addresses(&self) -> Vec<(AssocId, SocketAddr)> {
        self.assocs
            .iter()
            .map(|x| (*x.key(), x.value().remote_address))
            .collect()
    }

    /// Picks a new binding (association and in future stream ID).  
    /// To load balance among different associations, use a different seed.
    pub async fn new_ue_binding(&self, seed: u32) -> Result<Binding> {
        let len = self.assocs.len();
        ensure!(len > 0, "No associations up");
        let nth = seed as usize % len;
        let item = self.assocs.iter().nth(nth).unwrap();
        Ok(Binding {
            assoc_id: *item.key(),
            remote_ip: item.value().remote_address.ip().to_string(),
        })
    }

    pub async fn new_ue_binding_from_assoc(&self, assoc_id: &AssocId) -> Result<Binding> {
        if let Some(assoc) = self.assocs.get(assoc_id) {
            Ok(Binding {
                assoc_id: *assoc_id,
                remote_ip: assoc.remote_address.ip().to_string(),
            })
        } else {
            bail!("No such association")
        }
    }

    pub async fn send_message(
        &self,
        message: Message,
        assoc_id: Option<u32>,
        _logger: &Logger,
    ) -> Result<()> {
        let Some(assoc) = assoc_id
            .and_then(|x| self.assocs.get(&x).map(|x| x.clone()))
            .or(self.assocs.iter().next().map(|x| x.clone()))
        else {
            bail!("No association found")
        };
        assoc.send_msg(message).await
    }

    pub async fn add_and_handle<H>(
        &self,
        assoc_id: u32,
        assoc: Arc<SctpAssociation>,
        handler: H,
        logger: Logger,
    ) where
        H: TnlaEventHandler,
    {
        let stop_source = StopSource::new();
        let stop_token = stop_source.token();
        let self_clone = self.clone();
        self.assocs.insert(assoc_id, assoc.clone());
        let shutdown_handle = ShutdownHandle::new(
            async_std::task::spawn(async move {
                self_clone
                    .handle_assoc(assoc_id, assoc, handler, stop_token, logger)
                    .await;
            }),
            stop_source,
        );
        self.tasks.lock().await.push(shutdown_handle);
    }

    async fn handle_assoc<H>(
        &self,
        assoc_id: AssocId,
        assoc: Arc<SctpAssociation>,
        handler: H,
        stop_token: StopToken,
        logger: Logger,
    ) where
        H: TnlaEventHandler,
    {
        // Notify new association establishment.
        handler
            .handle_event(
                TnlaEvent::Established(assoc.remote_address),
                assoc_id,
                &logger,
            )
            .await;

        let message_stream = assoc.recv_msg_stream().take_until(stop_token);
        pin_mut!(message_stream);
        loop {
            match message_stream.next().await {
                // TODO - this does not implement graceful shutdown.  For one thing, the Terminated events below
                // may overtake message events.  For another, graceful shutdown implies that procedures currently underway
                // will allowed to complete sucessfully, which means we need to keep receiving on the association until
                // they are complete.  But above, we just cut off the stream as soon as the stop token fired.

                // Local shutdown
                None => {
                    handler
                        .handle_event(TnlaEvent::Terminated, assoc_id, &logger)
                        .await;
                    break;
                }
                // Remote end terminated connection
                Some(Err(_)) => {
                    handler
                        .handle_event(TnlaEvent::Terminated, assoc_id, &logger)
                        .await;
                    break;
                }
                // Received a message
                Some(Ok(message)) => {
                    //debug!(logger, "Received message on assoc {}", assoc_id);
                    handler.handle_message(message, assoc_id, &logger).await
                }
            }
        }

        self.assocs.remove(&assoc_id);
    }
}
