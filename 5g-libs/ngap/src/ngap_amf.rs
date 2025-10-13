//! ngap_amf - Collects together the procedures that are served by an AMF on the NG reference point.

use std::ops::Deref;

use super::top_pdu::*;
use crate::{InitiatingMessage, NgapPdu};
use async_trait::async_trait;
use slog::{Logger, error};
use xxap::*;

#[derive(Clone, Debug)]
pub struct NgapAmf<T>(pub T);

impl<T> Deref for NgapAmf<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Application for NgapAmf<T> where
    T: RequestProvider<NgSetupProcedure>
        + RequestProvider<NgResetProcedure>
        + RequestProvider<RanConfigurationUpdateProcedure>
        + IndicationHandler<InitialUeMessageProcedure>
        + IndicationHandler<UplinkNasTransportProcedure>
        + IndicationHandler<UeRadioCapabilityInfoIndicationProcedure>
        + IndicationHandler<UeContextReleaseRequestProcedure>
        + EventHandler
{
}

#[async_trait]
impl<T> EventHandler for NgapAmf<T>
where
    T: EventHandler + Clone,
{
    async fn handle_event(&self, event: TnlaEvent, tnla_id: u32, logger: &Logger) {
        self.0.handle_event(event, tnla_id, logger).await;
    }
}

#[async_trait]
impl<T> InterfaceProvider for NgapAmf<T>
where
    T: Send
        + Sync
        + RequestProvider<NgSetupProcedure>
        + RequestProvider<NgResetProcedure>
        + RequestProvider<RanConfigurationUpdateProcedure>
        + IndicationHandler<InitialUeMessageProcedure>
        + IndicationHandler<UplinkNasTransportProcedure>
        + IndicationHandler<UeRadioCapabilityInfoIndicationProcedure>
        + IndicationHandler<UeContextReleaseRequestProcedure>
        + EventHandler,
{
    type TopPdu = NgapPdu;
    async fn route_request(&self, p: NgapPdu, logger: &Logger) -> Option<ResponseAction<NgapPdu>> {
        match p {
            NgapPdu::InitiatingMessage(InitiatingMessage::RanConfigurationUpdate(req)) => {
                RanConfigurationUpdateProcedure::call_provider(&self.0, req, logger).await
            }
            NgapPdu::InitiatingMessage(InitiatingMessage::NgSetupRequest(req)) => {
                NgSetupProcedure::call_provider(&self.0, req, logger).await
            }
            NgapPdu::InitiatingMessage(InitiatingMessage::InitialUeMessage(req)) => {
                InitialUeMessageProcedure::call_provider(&self.0, req, logger).await;
                None
            }
            NgapPdu::InitiatingMessage(InitiatingMessage::UplinkNasTransport(req)) => {
                UplinkNasTransportProcedure::call_provider(&self.0, req, logger).await;
                None
            }
            NgapPdu::InitiatingMessage(InitiatingMessage::UeRadioCapabilityInfoIndication(req)) => {
                UeRadioCapabilityInfoIndicationProcedure::call_provider(&self.0, req, logger).await;
                None
            }
            NgapPdu::InitiatingMessage(InitiatingMessage::UeContextReleaseRequest(req)) => {
                UeContextReleaseRequestProcedure::call_provider(&self.0, req, logger).await;
                None
            }
            NgapPdu::InitiatingMessage(InitiatingMessage::NgReset(req)) => {
                NgResetProcedure::call_provider(&self.0, req, logger).await
            }
            m => {
                error!(logger, "Unhandled Ngap message {:?}", m);
                return None;
            }
        }
    }
}
