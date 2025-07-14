//! f1ap - F1AP entry points
use crate::procedures::UeMessage;

use super::interface_management::{
    F1RemovalProcedure, F1SetupProcedure, GnbDuConfigurationUpdateProcedure,
};
use super::prelude::*;
use async_trait::async_trait;
use f1ap::{
    self, F1RemovalFailure, F1RemovalRequest, F1RemovalResponse, F1SetupFailure, F1SetupRequest,
    F1SetupResponse, F1apCu, F1apPdu, GnbDuConfigurationUpdate,
    GnbDuConfigurationUpdateAcknowledge, GnbDuConfigurationUpdateFailure,
    InitialUlRrcMessageTransfer, InitialUlRrcMessageTransferProcedure, InitiatingMessage,
    UeContextReleaseRequest, UeContextReleaseRequestProcedure, UlRrcMessageTransfer,
    UlRrcMessageTransferProcedure,
};
use slog::Logger;
use xxap::{
    EventHandler, IndicationHandler, RequestError, RequestProvider, ResponseAction, TnlaEvent,
};

#[derive(Clone, Deref)]
pub struct F1apHandler<A: HandlerApi>(A);

impl<A: HandlerApi> F1apHandler<A> {
    pub fn new_f1ap_application(api: A) -> F1apCu<F1apHandler<A>> {
        F1apCu::new(F1apHandler(api))
    }
}

#[async_trait]
impl<A: HandlerApi> RequestProvider<f1ap::F1SetupProcedure> for F1apHandler<A> {
    async fn request(
        &self,
        r: F1SetupRequest,
        logger: &Logger,
    ) -> Result<ResponseAction<F1SetupResponse>, RequestError<F1SetupFailure>> {
        F1SetupProcedure::new(Procedure::new(&self.0, logger))
            .run(r)
            .await
    }
}

#[async_trait]
impl<A: HandlerApi> RequestProvider<f1ap::F1RemovalProcedure> for F1apHandler<A> {
    async fn request(
        &self,
        r: F1RemovalRequest,
        logger: &Logger,
    ) -> Result<ResponseAction<F1RemovalResponse>, RequestError<F1RemovalFailure>> {
        F1RemovalProcedure::new(Procedure::new(&self.0, logger))
            .run(r)
            .await
    }
}

#[async_trait]
impl<A: HandlerApi> RequestProvider<f1ap::GnbDuConfigurationUpdateProcedure> for F1apHandler<A> {
    async fn request(
        &self,
        r: GnbDuConfigurationUpdate,
        logger: &Logger,
    ) -> Result<
        ResponseAction<GnbDuConfigurationUpdateAcknowledge>,
        RequestError<GnbDuConfigurationUpdateFailure>,
    > {
        GnbDuConfigurationUpdateProcedure::new(Procedure::new(&self.0, logger))
            .run(r)
            .await
    }
}

#[async_trait]
impl<A: HandlerApi> IndicationHandler<InitialUlRrcMessageTransferProcedure> for F1apHandler<A> {
    async fn handle(&self, r: InitialUlRrcMessageTransfer, logger: &Logger) {
        let id = self.0.spawn_ue_message_handler().await;
        if let Err(e) = self
            .dispatch_ue_message(
                id,
                UeMessage::F1ap(Box::new(F1apPdu::InitiatingMessage(
                    InitiatingMessage::InitialUlRrcMessageTransfer(r),
                ))),
            )
            .await
        {
            warn!(
                logger,
                "Failed to dispatch InitialUlRrcMessageTransfer - {}", e
            );
        }
    }
}

#[async_trait]
impl<A: HandlerApi> IndicationHandler<UlRrcMessageTransferProcedure> for F1apHandler<A> {
    async fn handle(&self, r: UlRrcMessageTransfer, _logger: &Logger) {
        if let Err(e) = self
            .dispatch_ue_message(
                r.gnb_cu_ue_f1ap_id.0,
                UeMessage::F1ap(Box::new(F1apPdu::InitiatingMessage(
                    InitiatingMessage::UlRrcMessageTransfer(r),
                ))),
            )
            .await
        {
            warn!(_logger, "Failed to dispatch UlRrcMessageTransfer - {}", e);
        }
    }
}

#[async_trait]
impl<A: HandlerApi> IndicationHandler<UeContextReleaseRequestProcedure> for F1apHandler<A> {
    async fn handle(&self, r: UeContextReleaseRequest, _logger: &Logger) {
        if let Err(e) = self
            .dispatch_ue_message(
                r.gnb_cu_ue_f1ap_id.0,
                UeMessage::F1ap(Box::new(F1apPdu::InitiatingMessage(
                    InitiatingMessage::UeContextReleaseRequest(r),
                ))),
            )
            .await
        {
            warn!(
                _logger,
                "Failed to dispatch UeContextReleaseRequest - {}", e
            );

            // TODO just delete it anyway?
        }
    }
}

#[async_trait]
impl<A: HandlerApi> EventHandler for F1apHandler<A> {
    async fn handle_event(&self, event: TnlaEvent, tnla_id: u32, logger: &Logger) {
        match event {
            TnlaEvent::Established(addr) => {
                info!(logger, "F1AP TNLA {} established with DU {}", tnla_id, addr)
            }
            TnlaEvent::Terminated => info!(logger, "F1AP TNLA {} closed", tnla_id),
        };
    }
}
