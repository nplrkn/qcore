mod initial_ul_rrc_message_transfer;
mod ran_session_release;
mod ue_context_release;
mod ue_context_setup;
use super::prelude::*;
use f1ap::{Cause, DlRrcMessageTransferProcedure, F1apPdu, RrcContainer};
use rrc::UlDcchMessage;
use slog::debug;
use xxap::NrCgi;

use crate::{
    Config,
    data::{
        DecodedNas, PduSession, SubscriberAuthParams, UeContext5GC, UeRrcContext, UserplaneSession,
    },
    procedures::ue_associated::{RrcBase, RrcProcedure},
    protocols::nas::Tmsi,
    qcore::ServedCellsStore,
};

pub struct F1apUeProcedure<'a, B: RanUeBase> {
    pub ue: &'a mut crate::UeRanContext,
    pub logger: &'a Logger,
    pub api: B,
    pub release_cause: Cause,
}

impl<'a, B: RanUeBase> F1apUeProcedure<'a, B> {
    pub async fn dispatch(
        &mut self,
        pdu: Box<F1apPdu>,
        rrc_context: &mut UeRrcContext,
        core_context: &mut UeContext5GC,
    ) -> Result<()> {
        match *pdu {
            F1apPdu::InitiatingMessage(f1ap::InitiatingMessage::InitialUlRrcMessageTransfer(r)) => {
                self.initial_ul_rrc_message_transfer(Box::new(r), rrc_context, core_context)
                    .await?;
            }
            F1apPdu::InitiatingMessage(f1ap::InitiatingMessage::UlRrcMessageTransfer(r)) => {
                self.log_message(">> F1ap UlRrcMessageTransfer");
                RrcProcedure {
                    ue: rrc_context,
                    logger: &self.logger.clone(),
                    api: self,
                }
                .dispatch_pdcp(&r.rrc_container.0, core_context)
                .await?;
            }
            F1apPdu::InitiatingMessage(f1ap::InitiatingMessage::UeContextReleaseRequest(r)) => {
                self.log_message(">> F1ap UeContextReleaseRequest");
                info!(
                    self.logger,
                    "DU initiated context release, cause {:?}", r.cause
                );
                self.release_cause = r.cause.clone();
                bail!("Context release");
            }
            pdu => {
                debug!(self.logger, "Unsupported F1apPdu");
                bail!("Unsupported F1apPdu {pdu:?}");
            }
        }
        Ok(())
    }

    pub async fn dispatch_rrc(
        &mut self,
        pdu: Box<UlDcchMessage>,
        rrc_context: &mut UeRrcContext,
        core_context: &mut UeContext5GC,
    ) -> Result<()> {
        RrcProcedure {
            ue: rrc_context,
            logger: &self.logger.clone(),
            api: self,
        }
        .dispatch_ul_dcch(pdu, core_context)
        .await
    }

    pub async fn dispatch_nas(
        &mut self,
        pdu: DecodedNas,
        rrc_context: &mut UeRrcContext,
        core_context: &mut UeContext5GC,
    ) -> Result<()> {
        RrcProcedure {
            ue: rrc_context,
            logger: &self.logger.clone(),
            api: self,
        }
        .dispatch_nas(pdu, core_context)
        .await
    }

    pub fn log_message(&self, s: &str) {
        debug!(self.logger, "{}", s)
    }
}

use delegate::delegate;

impl<'a, B: RanUeBase> RrcBase for &mut F1apUeProcedure<'a, B> {
    delegate! {
    to self.api {
        fn config(&self) -> &Config;
        async fn reserve_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession>;
        async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str) -> Option<SubscriberAuthParams>;
        async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;
        async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
        async fn delete_userplane_session(
            &self,
            session: &UserplaneSession,
            logger: &Logger,
        );
        fn unexpected_nas_pdu(&mut self, pdu: DecodedNas, expected: &str) -> Result<()>;
        fn unexpected_rrc_pdu(&mut self, pdu: Box<UlDcchMessage>) -> Result<()>;
        fn served_cells(&self) -> &ServedCellsStore;
    }}

    async fn register_new_tmsi(&self, tmsi: Tmsi) {
        self.api
            .register_new_tmsi(tmsi, self.ue.local_ran_ue_id, &self.logger)
            .await
    }

    fn set_rat_capabilities(&mut self, rat_capabilities: Vec<u8>) {
        self.ue.rat_capabilities = Some(rat_capabilities);
    }

    fn rat_capabilities(&self) -> &Option<Vec<u8>> {
        &self.ue.rat_capabilities
    }

    async fn receive_rrc(&mut self) -> Result<Vec<u8>> {
        let ul_rrc_message_transfer = self
            .api
            .receive_xxap_pdu(
                |m: Box<F1apPdu>| match *m {
                    F1apPdu::InitiatingMessage(f1ap::InitiatingMessage::UlRrcMessageTransfer(
                        x,
                    )) => Ok(x),
                    _ => Err(m),
                },
                "UlRrcMessageTransfer",
            )
            .await?;
        self.log_message(">> F1ap UlRrcMessageTransfer");
        Ok(ul_rrc_message_transfer.rrc_container.0)
    }

    async fn rrc_indication(&mut self, srb: f1ap::SrbId, rrc: Vec<u8>) -> Result<()> {
        let dl_message = crate::f1ap::build::dl_rrc_message_transfer(
            self.ue.local_ran_ue_id,
            self.ue.gnb_du_ue_f1ap_id(),
            RrcContainer(rrc),
            srb,
        );
        self.log_message("<< F1ap DlRrcMessageTransfer");
        self.api
            .xxap_indication::<DlRrcMessageTransferProcedure>(dl_message, self.logger)
            .await;
        Ok(())
    }

    fn nr_cgi(&self) -> &Option<NrCgi> {
        &self.ue.nr_cgi
    }

    // TODO: rename to ue_context_setup (the 'ran' is an abstraction for the NasBase not appropriate for the RrcBase)
    async fn ran_session_setup(&mut self, session: &mut PduSession) -> Result<Vec<u8>> {
        self.ue_context_setup(session).await
    }

    async fn ran_session_release(
        &mut self,
        _released_session: &PduSession,
    ) -> Result<Option<Vec<u8>>> {
        // TODO - this is suspect.  Even though it is the last session given our single session limitation,
        // we shouldn't release the context.
        // Because the context includes SRB 1, which should live on.  (Does SRB2 also live on?)
        // Only if the UE goes idle should we actually release the context.
        self.ue_context_release().await;
        Ok(None)
    }
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::F1apUeProcedure;
}
