// stack - transaction layer allowing application business logic to await a response to its ??AP requests

use super::{AssocId, TnlaEventHandler};
use super::{Message, SctpTransportProvider, TnlaEvent, TransportProvider};
use crate::{
    Indication, IndicationHandler, Procedure, RequestError, RequestMessageHandler, RequestProvider,
    ResponseAction, ShutdownHandle,
};
use anyhow::Result;
use async_channel::Sender;
use async_net::SocketAddr;
use async_std::sync::{Arc, Mutex};
use async_trait::async_trait;
use slog::{Logger, debug, warn};

type TransactionMatchFn = Box<dyn Fn(&Message) -> bool + Send + Sync>;
type SharedTransactions = Arc<Mutex<Box<Vec<(TransactionMatchFn, Sender<Message>)>>>>;

#[derive(Clone)]
pub struct Stack {
    pending_requests: SharedTransactions,
    transport_provider: SctpTransportProvider,
}

#[async_trait]
pub trait EventHandler: Clone + Send + Sync + 'static {
    async fn handle_event(&self, event: TnlaEvent, tnla_id: u32, logger: &Logger);
}

pub trait Application: EventHandler + RequestMessageHandler {}

impl Stack {
    pub fn new(transport_provider: SctpTransportProvider) -> Self {
        Self {
            transport_provider,
            pending_requests: Arc::new(Mutex::new(Box::default())),
        }
    }

    pub async fn connect<A: Application>(
        &self,
        connect_address: &str,
        bind_address: &str,
        ppid: u32,
        application: A,
        logger: Logger,
    ) -> Result<()> {
        let receiver = StackReceiver {
            application,
            transport_provider: self.transport_provider.clone(),
            pending_requests: self.pending_requests.clone(),
        };
        self.transport_provider
            .clone()
            .connect(connect_address, bind_address, ppid, receiver, logger)
            .await
    }

    pub async fn listen<A: Application>(
        &self,
        listen_address: String,
        ppid: u32,
        application: A,
        logger: Logger,
    ) -> Result<ShutdownHandle> {
        let receiver = StackReceiver {
            application,
            transport_provider: self.transport_provider.clone(),
            pending_requests: self.pending_requests.clone(),
        };

        self.transport_provider
            .clone()
            .serve(listen_address, ppid, receiver, logger)
            .await
    }

    pub async fn remote_tnla_addresses(&self) -> Vec<(u32, SocketAddr)> {
        self.transport_provider.remote_tnla_addresses().await
    }

    pub async fn graceful_shutdown(self) {
        self.transport_provider.graceful_shutdown().await
    }
}

#[async_trait]
impl<P: Procedure> RequestProvider<P> for Stack {
    async fn request(
        &self,
        r: P::Request,
        logger: &Logger,
    ) -> Result<ResponseAction<P::Success>, RequestError<P::Failure>> {
        let bytes = P::encode_request(r)?;

        // Create a channel to receive the response.
        let (sender, receiver) = async_channel::bounded::<Vec<u8>>(1);
        let match_fn = |m: &Message| ((m[0] != 0) && (m[1] == P::CODE));
        self.pending_requests
            .lock()
            .await
            .push((Box::new(match_fn), sender));

        self.transport_provider
            .send_message(bytes, None, logger)
            .await?;

        // TODO - timeout
        let msg = receiver.recv().await?;
        P::decode_response(&msg).map(|x| (x, None))
    }
}

#[async_trait]
impl<I: Indication> IndicationHandler<I> for Stack {
    async fn handle(&self, i: I::Request, logger: &Logger) {
        match I::encode_request(i) {
            Ok(m) => match self.transport_provider.send_message(m, None, logger).await {
                Ok(()) => (),
                Err(e) => warn!(logger, "Error sending indication - {:?}", e),
            },
            Err(e) => warn!(logger, "Error encoding indication - {:?}", e),
        }
    }
}

#[derive(Clone)]
struct StackReceiver<A: Application> {
    application: A,
    transport_provider: SctpTransportProvider,
    pending_requests: SharedTransactions,
}

impl<A: Application> StackReceiver<A> {
    fn spawn_procedure_task(&self, message: Message, tnla_id: AssocId, logger: &Logger) {
        let application = self.application.clone();
        let logger = logger.clone();
        let transport_provider = self.transport_provider.clone();
        async_std::task::spawn(async move {
            let response_action = application.handle_request(&message, &logger).await;
            if let Some((response, future)) = response_action {
                if let Err(e) = transport_provider
                    .send_message(response, Some(tnla_id), &logger)
                    .await
                {
                    warn!(logger, "Failed to send response - {}", e);
                } else if let Some(future) = future {
                    debug!(logger, "Post response action - run it");
                    future.await;
                }
            }
        });
    }
}

#[async_trait]
impl<A: Application> TnlaEventHandler for StackReceiver<A> {
    async fn handle_event(&self, event: TnlaEvent, tnla_id: u32, logger: &Logger) {
        if let TnlaEvent::Terminated = event {
            // Drop all pending requests - which will fail all the procedures in progress
            let mut found_request = false;
            for r in self.pending_requests.lock().await.drain(..) {
                drop(r);
                found_request = true
            }

            // Note that current blanket implementation may drop requests on other TNLAs that could have survived
            if found_request {
                warn!(
                    logger,
                    "Failing all requests because of TNLA {} termination", tnla_id
                );
            }
        }
        self.application.handle_event(event, tnla_id, logger).await
    }

    async fn handle_message(&self, message: Message, tnla_id: u32, logger: &Logger) {
        // TODO figure out if it is a response and warn / drop if there are no matches

        // If it matches a pending request, route it back over the response channel.

        let position = self
            .pending_requests
            .lock()
            .await
            .iter()
            .position(|(matches, _)| matches(&message));

        match position {
            Some(index) => {
                // Response - send it to the existing task that is waiting for it.
                let (_, response_channel) = self.pending_requests.lock().await.swap_remove(index);
                response_channel
                    .send(message)
                    .await
                    .unwrap_or_else(|_| warn!(logger, "Internal response channel down"));
                // TODO - don't unwrap
            }
            _ => {
                // New request - spawn a new task to handle it.
                self.spawn_procedure_task(message, tnla_id, logger);
            }
        }
    }
}
