use super::interface_management::NgSetupProcedure;
use super::prelude::*;
use crate::procedures::UeMessage;
use async_trait::async_trait;
use ngap::{
    InitialUeMessage, InitiatingMessage, NgSetupFailure, NgSetupRequest, NgSetupResponse, NgapAmf,
    NgapPdu, RanConfigurationUpdate, RanConfigurationUpdateAcknowledge,
    RanConfigurationUpdateFailure, RanConfigurationUpdateProcedure, UplinkNasTransport,
};
use xxap::{
    EventHandler, IndicationHandler, RequestError, RequestProvider, ResponseAction, TnlaEvent,
};

#[derive(Clone, Deref)]
pub struct NgapHandler<A: HandlerApi>(A);

impl<A: HandlerApi> NgapHandler<A> {
    pub fn new_ngap_application(api: A) -> NgapAmf<NgapHandler<A>> {
        NgapAmf(NgapHandler(api))
    }
}

#[async_trait]
impl<A: HandlerApi> RequestProvider<ngap::NgSetupProcedure> for NgapHandler<A> {
    async fn request(
        &self,
        r: NgSetupRequest,
        logger: &Logger,
    ) -> Result<ResponseAction<NgSetupResponse>, RequestError<NgSetupFailure>> {
        NgSetupProcedure::new(Procedure::new(&self.0, logger))
            .run(r)
            .await
    }
}

#[async_trait]
impl<A: HandlerApi> IndicationHandler<ngap::InitialUeMessageProcedure> for NgapHandler<A> {
    async fn handle(&self, i: InitialUeMessage, logger: &Logger) {
        let id = self.0.spawn_ue_message_handler();
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
impl<A: HandlerApi> IndicationHandler<ngap::UplinkNasTransportProcedure> for NgapHandler<A> {
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
impl<A: HandlerApi> RequestProvider<RanConfigurationUpdateProcedure> for NgapHandler<A> {
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
impl<A: HandlerApi> EventHandler for NgapHandler<A> {
    async fn handle_event(&self, event: TnlaEvent, tnla_id: u32, logger: &Logger) {
        match event {
            TnlaEvent::Established(addr) => {
                info!(logger, "NGAP TNLA {} established with DU {}", tnla_id, addr)
            }
            TnlaEvent::Terminated => info!(logger, "NGAP TNLA {} closed", tnla_id),
        };
    }
}
