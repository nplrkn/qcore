//! tnla_event_handler - trait for dispatch of inbound messages and events to the user of a TransportProvider  

use super::Message;
use async_net::SocketAddr;
use async_trait::async_trait;
use slog::Logger;

#[async_trait]
pub trait TnlaEventHandler: 'static + Send + Sync + Clone {
    async fn handle_event(&self, event: TnlaEvent, tnla_id: u32, logger: &Logger);

    // TODO indicate whether it is UE or non UE associated?
    async fn handle_message(&self, message: Message, tnla_id: u32, logger: &Logger);
}

#[derive(Debug)]
pub enum TnlaEvent {
    Established(SocketAddr),
    Terminated,
}
