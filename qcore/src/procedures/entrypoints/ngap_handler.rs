use super::prelude::*;
use crate::procedures::{UeMessage, interface_management::Procedure};
use async_trait::async_trait;
use ngap::{
    InitialUeMessage, InitiatingMessage, NgSetupFailure, NgSetupRequest, NgSetupResponse, NgapAmf,
    NgapPdu, RanConfigurationUpdate, RanConfigurationUpdateAcknowledge,
    RanConfigurationUpdateFailure, RanConfigurationUpdateProcedure,
    UeRadioCapabilityInfoIndication, UplinkNasTransport,
};
use xxap::{
    EventHandler, IndicationHandler, RequestError, RequestProvider, ResponseAction, TnlaEvent,
};

#[derive(Clone)]
pub struct NgapHandler<A: ProcedureBase>(A);

impl<A: ProcedureBase> NgapHandler<A> {
    pub fn new_ngap_application(api: A) -> NgapAmf<NgapHandler<A>> {
        NgapAmf(NgapHandler(api))
    }
    async fn dispatch_ue_message(&self, ue_id: u32, message: UeMessage) -> Result<()> {
        self.0.dispatch_ue_message(ue_id, message).await
    }
}

#[async_trait]
impl<A: ProcedureBase> RequestProvider<ngap::NgSetupProcedure> for NgapHandler<A> {
    async fn request(
        &self,
        r: NgSetupRequest,
        logger: &Logger,
    ) -> Result<ResponseAction<NgSetupResponse>, RequestError<NgSetupFailure>> {
        Procedure::new(&self.0, logger).ng_setup(r).await
    }
}

#[async_trait]
impl<A: ProcedureBase> IndicationHandler<ngap::InitialUeMessageProcedure> for NgapHandler<A> {
    async fn handle(&self, i: InitialUeMessage, logger: &Logger) {
        let id = self.0.spawn_ue_message_handler().await;
        if let Err(e) = self
            .dispatch_ue_message(
                id,
                UeMessage::Ngap(Box::new(NgapPdu::InitiatingMessage(
                    InitiatingMessage::InitialUeMessage(i),
                ))),
            )
            .await
        {
            warn!(logger, "Failed to dispatch InitialUeMessage - {}", e);
        }
    }
}

#[async_trait]
impl<A: ProcedureBase> IndicationHandler<ngap::UplinkNasTransportProcedure> for NgapHandler<A> {
    async fn handle(&self, i: UplinkNasTransport, logger: &Logger) {
        if let Err(e) = self
            .dispatch_ue_message(
                i.amf_ue_ngap_id.0 as u32,
                UeMessage::Ngap(Box::new(NgapPdu::InitiatingMessage(
                    InitiatingMessage::UplinkNasTransport(i),
                ))),
            )
            .await
        {
            warn!(logger, "Failed to dispatch UplinkNasTransport - {}", e);
        }
    }
}

#[async_trait]
impl<A: ProcedureBase> IndicationHandler<ngap::UeContextReleaseRequestProcedure>
    for NgapHandler<A>
{
    async fn handle(&self, i: ngap::UeContextReleaseRequest, logger: &Logger) {
        if let Err(e) = self
            .dispatch_ue_message(
                i.amf_ue_ngap_id.0 as u32,
                UeMessage::Ngap(Box::new(NgapPdu::InitiatingMessage(
                    InitiatingMessage::UeContextReleaseRequest(i),
                ))),
            )
            .await
        {
            warn!(logger, "Failed to dispatch UplinkNasTransport - {}", e);
        }
    }
}

#[async_trait]
impl<A: ProcedureBase> RequestProvider<RanConfigurationUpdateProcedure> for NgapHandler<A> {
    async fn request(
        &self,
        _r: RanConfigurationUpdate,
        logger: &Logger,
    ) -> Result<
        ResponseAction<RanConfigurationUpdateAcknowledge>,
        RequestError<RanConfigurationUpdateFailure>,
    > {
        warn!(logger, "RAN configuration update procedure not implemented");
        Err(RequestError::Other(
            "RAN configuration update procedure not implemented".to_string(),
        ))
    }
}

#[async_trait]
impl<A: ProcedureBase> EventHandler for NgapHandler<A> {
    async fn handle_event(&self, event: TnlaEvent, _tnla_id: u32, logger: &Logger) {
        match event {
            TnlaEvent::Established(addr) => {
                info!(
                    logger,
                    "NGAP SCTP association established from gNB {}", addr
                )
            }
            TnlaEvent::Terminated => {
                // Treat this as equivalent to NG termination.
                // TODO - in the case of multiple TNLAs or multiple gNBs, this is too broad.
                info!(logger, "NGAP SCTP connection with gNB closed");
                self.0.disconnect_ues().await;
            }
        };
    }
}

#[async_trait]
impl<A: ProcedureBase> IndicationHandler<ngap::UeRadioCapabilityInfoIndicationProcedure>
    for NgapHandler<A>
{
    async fn handle(&self, i: UeRadioCapabilityInfoIndication, logger: &Logger) {
        if let Err(e) = self
            .dispatch_ue_message(
                i.amf_ue_ngap_id.0 as u32,
                UeMessage::Ngap(Box::new(NgapPdu::InitiatingMessage(
                    InitiatingMessage::UeRadioCapabilityInfoIndication(i),
                ))),
            )
            .await
        {
            warn!(logger, "Failed to dispatch UplinkNasTransport - {}", e);
        }
    }
}
