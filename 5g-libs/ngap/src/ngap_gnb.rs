//! ngap_gnb - Collects together the procedures that are served by a GNB on the NG reference point.

use super::top_pdu::*;
use crate::{InitiatingMessage, NgapPdu};
use async_trait::async_trait;
use slog::{Logger, error};
use xxap::*;

#[derive(Clone)]
pub struct NgapGnb<T>(T);

impl<T> NgapGnb<T> {
    pub fn new(inner: T) -> Self {
        NgapGnb(inner)
    }
}

#[async_trait]
impl<T> EventHandler for NgapGnb<T>
where
    T: EventHandler,
{
    async fn handle_event(&self, event: TnlaEvent, tnla_id: u32, logger: &Logger) {
        self.0.handle_event(event, tnla_id, logger).await;
    }
}

impl<T> Application for NgapGnb<T> where
    T: RequestProvider<NgSetupProcedure>
        + EventHandler
        + Clone
        + IndicationHandler<DownlinkNasTransportProcedure>
        + RequestProvider<InitialContextSetupProcedure>
        + IndicationHandler<AmfStatusIndicationProcedure>
        + RequestProvider<PduSessionResourceSetupProcedure>
        + RequestProvider<PduSessionResourceReleaseProcedure>
{
}

#[async_trait]
impl<T> InterfaceProvider for NgapGnb<T>
where
    T: Send
        + Sync
        + RequestProvider<NgSetupProcedure>
        + IndicationHandler<DownlinkNasTransportProcedure>
        + RequestProvider<InitialContextSetupProcedure>
        + IndicationHandler<AmfStatusIndicationProcedure>
        + RequestProvider<PduSessionResourceSetupProcedure>
        + RequestProvider<PduSessionResourceReleaseProcedure>,
{
    type TopPdu = NgapPdu;
    async fn route_request(&self, p: NgapPdu, logger: &Logger) -> Option<ResponseAction<NgapPdu>> {
        let initiating_message = match p {
            NgapPdu::InitiatingMessage(m) => m,
            x => {
                error!(logger, "Not a request! {:?}", x);
                return None;
            }
        };
        match initiating_message {
            InitiatingMessage::NgSetupRequest(req) => {
                NgSetupProcedure::call_provider(&self.0, req, logger).await
            }
            InitiatingMessage::DownlinkNasTransport(req) => {
                DownlinkNasTransportProcedure::call_provider(&self.0, req, logger).await;
                None
            }
            InitiatingMessage::InitialContextSetupRequest(req) => {
                InitialContextSetupProcedure::call_provider(&self.0, req, logger).await
            }
            InitiatingMessage::AmfStatusIndication(req) => {
                AmfStatusIndicationProcedure::call_provider(&self.0, req, logger).await;
                None
            }
            InitiatingMessage::PduSessionResourceSetupRequest(req) => {
                PduSessionResourceSetupProcedure::call_provider(&self.0, req, logger).await
            }
            InitiatingMessage::PduSessionResourceReleaseCommand(req) => {
                PduSessionResourceReleaseProcedure::call_provider(&self.0, req, logger).await
            }
            _ => todo!(),
        }
    }
}
