mod initial_ul_rrc_message_transfer;
mod ue_context_modification;
mod ue_context_release;
mod ue_context_setup;

use super::prelude::*;
use crate::{
    Config,
    data::{SubscriberAuthParams, UeContextRan, UserplaneSession},
    procedures::{
        UeMessage,
        ue_associated::{RrcBase, RrcProcedure, ran_ue_base::ReleaseCause},
    },
    qcore::ServedCellsMap,
};
use f1ap::{DlRrcMessageTransferProcedure, F1apPdu, RrcContainer};
use nas::DecodedNas;
use rrc::UlDcchMessage;
use slog::debug;
use xxap::NrCgi;

pub struct F1apUeProcedure<'a, B: RanUeBase> {
    pub ue: &'a mut UeContextRan,
    pub logger: Logger,
    pub api: B,
}

impl<'a, B: RanUeBase> F1apUeProcedure<'a, B> {
    pub async fn dispatch(
        &mut self,
        pdu: Box<F1apPdu>,
        rrc_context: &'a mut UeContextRrc,
        core_context: &'a mut UeContext5GC,
    ) -> Result<()> {
        match *pdu {
            F1apPdu::InitiatingMessage(f1ap::InitiatingMessage::InitialUlRrcMessageTransfer(r)) => {
                self.initial_ul_rrc_message_transfer(Box::new(r), rrc_context, core_context)
                    .await?;
            }
            F1apPdu::InitiatingMessage(f1ap::InitiatingMessage::UlRrcMessageTransfer(r)) => {
                self.log_message(">> F1ap UlRrcMessageTransfer");
                self.rrc_procedure(rrc_context)
                    .dispatch_pdcp(&r.rrc_container.0, core_context)
                    .await?;
            }
            F1apPdu::InitiatingMessage(f1ap::InitiatingMessage::UeContextReleaseRequest(r)) => {
                self.log_message(">> F1ap UeContextReleaseRequest");
                info!(
                    self.logger,
                    "DU initiated context release, cause {:?}", r.cause
                );
                self.api.disconnect_ue(ReleaseCause::F1ap(r.cause));
            }
            pdu => {
                debug!(self.logger, "Unsupported F1apPdu");
                bail!("Unsupported F1apPdu {pdu:?}");
            }
        }
        Ok(())
    }

    fn rrc_procedure(&mut self, rrc_context: &'a mut UeContextRrc) -> RrcProcedure<'a, &mut Self> {
        RrcProcedure {
            ue: rrc_context,
            logger: self.logger.clone(),
            api: self,
        }
    }

    pub async fn dispatch_rrc(
        &mut self,
        pdu: Box<UlDcchMessage>,
        rrc_context: &'a mut UeContextRrc,
        core_context: &'a mut UeContext5GC,
    ) -> Result<()> {
        self.rrc_procedure(rrc_context)
            .dispatch_ul_dcch(pdu, core_context)
            .await
    }

    pub async fn dispatch_nas(
        &mut self,
        pdu: DecodedNas,
        rrc_context: &'a mut UeContextRrc,
        core_context: &'a mut UeContext5GC,
    ) -> Result<()> {
        self.rrc_procedure(rrc_context)
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
        async fn allocate_userplane_session(&self, [&self.logger]) -> Result<UserplaneSession>;
        async fn delete_userplane_session(
            &self,
            session: &UserplaneSession,
            [&self.logger],
        );
        async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str) -> Option<SubscriberAuthParams>;
        async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;
        async fn register_new_tmsi(&self, [self.ue.local_ran_ue_id], [&self.logger]) -> [u8;4];
        async fn delete_tmsi(&self, tmsi: [u8; 4]);
        async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
        fn unexpected_pdu<T:Into<UeMessage>>(&mut self, pdu:T, expected: &str) -> Result<()>;
        fn served_cells(&self) -> &ServedCellsMap;
    }}

    fn disconnect_ue(&mut self) {
        // Currently this can only be called in the case of a UE deregistration
        // so there is no need for the cause to be a parameter.
        self.api
            .disconnect_ue(ReleaseCause::F1ap(f1ap::Cause::RadioNetwork(
                f1ap::CauseRadioNetwork::NormalRelease,
            )));
    }

    fn set_ue_rat_capabilities(&mut self, rat_capabilities: Vec<u8>) {
        self.ue.rat_capabilities = Some(rat_capabilities);
    }

    fn ue_rat_capabilities(&self) -> &Option<Vec<u8>> {
        &self.ue.rat_capabilities
    }

    fn ue_nr_cgi(&self) -> &Option<NrCgi> {
        &self.ue.nr_cgi
    }

    fn ue_tac(&self) -> &[u8; 3] {
        &self.ue.tac
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

    async fn send_rrc(&mut self, srb: f1ap::SrbId, rrc: Vec<u8>) -> Result<()> {
        let dl_message = crate::f1ap::build::dl_rrc_message_transfer(
            self.ue.local_ran_ue_id,
            self.ue.gnb_du_ue_f1ap_id(),
            RrcContainer(rrc),
            srb,
        );
        self.log_message("<< F1ap DlRrcMessageTransfer");
        self.api
            .xxap_indication::<DlRrcMessageTransferProcedure>(dl_message, &self.logger)
            .await;
        Ok(())
    }

    async fn ran_ue_context_setup(&mut self, session: &mut PduSession) -> Result<Vec<u8>> {
        self.ue_context_setup(session).await
    }

    async fn ran_ue_context_modification(
        &mut self,
        released_session: &PduSession,
    ) -> Result<Option<Vec<u8>>> {
        self.ue_context_modification(released_session).await
    }
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::F1apUeProcedure;
}
