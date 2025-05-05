//! mock - 'base class' for the mocks

use anyhow::{Result, bail};
use async_channel::{Receiver, Sender};
use async_trait::async_trait;
use slog::{Logger, debug, info};
use std::fmt::Debug;
use xxap::{
    Binding, SctpTransportProvider, TransportProvider, ShutdownHandle, TnlaEvent, TnlaEventHandler,
};
use asn1_per::SerDes;

pub trait Pdu: SerDes + 'static + Send + Sync + Clone + Debug {}

/// Base struct for building mocks
pub struct Mock<P: Pdu> {
    pub transport: SctpTransportProvider,
    receiver: Receiver<MockEvent<P>>,
    pub logger: Logger,
    handler: Handler<P>,
    transport_tasks: Vec<ShutdownHandle>,
    disable_receive_timeouts: bool,
}

pub enum MockEvent<P: Pdu> {
    Pdu(ReceivedPdu<P>),
    Connection,
}

pub struct ReceivedPdu<P: Pdu> {
    pub pdu: P,
    pub assoc_id: u32,
}

#[derive(Debug, Clone)]
pub struct Handler<P: Pdu>(pub Sender<MockEvent<P>>);

// struct DebugReceiver<P: Pdu>(pub Receiver<MockEvent<P>>, Logger);
// impl<P: Pdu> Drop for DebugReceiver<P> {
//     fn drop(&mut self) {
//         info!(self.1, "Dropped");
//     }
// }
// impl<P: Pdu> std::ops::Deref for DebugReceiver<P> {
//     type Target = Receiver<MockEvent<P>>;

//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

impl<P: Pdu> Mock<P> {
    pub async fn new(logger: Logger) -> Self {
        let (sender, receiver) = async_channel::unbounded();
        //let receiver = DebugReceiver(receiver, logger.clone());
        let transport = SctpTransportProvider::new();

        Mock {
            transport,
            receiver,
            logger,
            handler: Handler(sender),
            transport_tasks: Vec::new(),
            disable_receive_timeouts: false,
        }
    }

    pub fn disable_receive_timeouts(&mut self) -> &mut Self {
        self.disable_receive_timeouts = true;
        self
    }

    pub async fn serve(&mut self, address: String, ppid: u32) -> Result<()> {
        let transport_tasks = self
            .transport
            .clone()
            .serve(address, ppid, self.handler.clone(), self.logger.clone())
            .await?;
        self.transport_tasks.push(transport_tasks);
        Ok(())
    }

    pub async fn connect(&mut self, connect_address: &str, bind_address: &str, ppid: u32) {
        self.transport
            .clone()
            .connect(
                connect_address,
                bind_address,
                ppid,
                self.handler.clone(),
                self.logger.clone(),
            )
            .await
            .expect("Connect failed");

        // Wait for the connection to be accepted.
        debug!(self.logger, "Wait for connection to be accepted");
        self.expect_connection_established().await;
    }

    pub async fn terminate(mut self) {
        for t in self.transport_tasks.drain(..) {
            t.graceful_shutdown().await;
        }
        self.transport.graceful_shutdown().await;
        info!(self.logger, "Termination complete");
    }

    /// Wait for connection to be established or terminated.
    pub async fn expect_connection_established(&self) {
        debug!(self.logger, "Wait for connection from worker");
        match self.receiver.recv().await.expect("Failed mock recv") {
            MockEvent::Pdu(x) => panic!("Expected connection, got {:?}", x.pdu),
            MockEvent::Connection => {
                debug!(
                    self.logger,
                    "Association list is now {:?}",
                    self.transport.remote_tnla_addresses().await
                );
            }
        }
    }

    pub async fn send<T: SerDes>(&self, pdu: T, assoc_id: Option<u32>) {
        let message = pdu.into_bytes().unwrap();
        self.transport
            .send_message(message, assoc_id, &self.logger)
            .await
            .expect("Failed to send message");
    }

    /// Receive a Pdu, with a 0.5s timeout.
    pub async fn receive_pdu(&self) -> Result<P> {
        self.receive_pdu_with_assoc_id().await.map(|r| r.pdu)
    }

    /// Receive a Pdu, with a 0.5s timeout.
    pub async fn receive_pdu_with_assoc_id(&self) -> Result<ReceivedPdu<P>> {
        let f = self.receiver.recv();
        let event = if self.disable_receive_timeouts {
            f.await
        } else {
            async_std::future::timeout(std::time::Duration::from_millis(500), f).await?
        }?;
        match event {
            MockEvent::Pdu(p) => Ok(p),
            MockEvent::Connection => bail!("Expected Pdu but got connection"),
        }
    }

    pub async fn rebind(&self, binding: &mut Binding, ip_addr: &str) -> Result<()> {
        *binding = self.transport.new_ue_binding_from_ip(ip_addr).await?;
        Ok(())
    }
}

#[async_trait]
impl<P: Pdu> TnlaEventHandler for Handler<P> {
    async fn handle_event(&self, event: TnlaEvent, tnla_id: u32, logger: &Logger) {
        match event {
            TnlaEvent::Established(_addr) => self
                .0
                .send(MockEvent::Connection)
                .await
                .expect("Channel closed"),
            TnlaEvent::Terminated => info!(logger, "TNLA {} closed", tnla_id),
        }
    }

    async fn handle_message(&self, message: Vec<u8>, tnla_id: u32, _logger: &Logger) {
        self.0
            .send(MockEvent::Pdu(ReceivedPdu {
                pdu: P::from_bytes(&message).unwrap(),
                assoc_id: tnla_id,
            }))
            .await
            .unwrap();
    }
}
