use super::handler_api::UeMessage;
use super::ng_setup::NgSetupProcedure;
use crate::HandlerApi;
use anyhow::Result;
use async_trait::async_trait;
use derive_deref::Deref;
use ngap::RanConfigurationUpdateProcedure;
use ngap::{
    NgSetupFailure, NgSetupRequest, NgSetupResponse, NgapAmf, RanConfigurationUpdate,
    RanConfigurationUpdateAcknowledge, RanConfigurationUpdateFailure,
};
use slog::{Logger, info, warn};
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
        NgSetupProcedure::new(&self.0, logger).run(r).await
    }
}

#[async_trait]
impl<A: HandlerApi> RequestProvider<RanConfigurationUpdateProcedure> for NgapHandler<A> {
    async fn request(
        &self,
        r: RanConfigurationUpdate,
        logger: &Logger,
    ) -> Result<
        ResponseAction<RanConfigurationUpdateAcknowledge>,
        RequestError<RanConfigurationUpdateFailure>,
    > {
        warn!(logger, "RAN configuration update procedure not implemented");
        todo!()
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
