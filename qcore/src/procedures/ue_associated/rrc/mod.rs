mod reconfiguration;
mod rrc_base;
mod security_mode;
mod setup;
mod ue_capability_enquiry;
mod ul_information_transfer;

pub use rrc_base::RrcBase;

use crate::{
    Config,
    data::{PduSession, SubscriberAuthParams, UeContext5GC, UeContextRrc, UserplaneSession},
    procedures::ue_associated::{NasBase, NasProcedure},
};
use anyhow::{Result, bail};
use asn1_per::SerDes;
use f1ap::SrbId;
use nas::DecodedNas;
use rrc::{
    C1_6, CriticalExtensions37, DedicatedNasMessage, UlDcchMessage, UlDcchMessageType,
    UlInformationTransfer, UlInformationTransferIEs,
};
use slog::{Logger, debug};

pub struct RrcProcedure<'a, B: RrcBase> {
    pub ue: &'a mut UeContextRrc,
    pub logger: Logger,
    pub api: B,
}

impl<'a, B: RrcBase> RrcProcedure<'a, B> {
    pub async fn dispatch_ul_dcch(
        &mut self,
        rrc: Box<UlDcchMessage>,
        core_context: &'a mut UeContext5GC,
    ) -> Result<()> {
        match rrc.message {
            UlDcchMessageType::C1(C1_6::UlInformationTransfer(ul_information_transfer)) => {
                self.ul_information_transfer(ul_information_transfer, core_context)
                    .await?
            }
            _ => {
                bail!("Unsupported UlDcchMessage {rrc:?}");
            }
        }
        Ok(())
    }

    pub async fn dispatch_pdcp(
        &mut self,
        pdcp_bytes: &[u8],
        core_context: &'a mut UeContext5GC,
    ) -> Result<()> {
        let rrc = self.extract_ul_dcch_message(pdcp_bytes)?;
        self.dispatch_ul_dcch(rrc, core_context).await
    }

    fn nas_procedure(&mut self, core_context: &'a mut UeContext5GC) -> NasProcedure<'a, &mut Self> {
        NasProcedure {
            ue: core_context,
            logger: self.logger.clone(),
            api: self,
        }
    }

    pub async fn dispatch_nas(
        &mut self,
        pdu: DecodedNas,
        core_context: &'a mut UeContext5GC,
    ) -> Result<()> {
        self.nas_procedure(core_context).dispatch(pdu).await
    }

    pub fn log_message(&self, s: &str) {
        debug!(self.logger, "{}", s)
    }

    async fn rrc_request<T: Send + SerDes, F>(
        &mut self,
        srb_id: SrbId,
        rrc: &T,
        filter: fn(Box<UlDcchMessage>) -> Result<F, Box<UlDcchMessage>>,
        expected: &str,
    ) -> Result<F> {
        self.send_rrc(srb_id, rrc).await?;
        self.receive_rrc(filter, expected).await
    }

    async fn receive_rrc<T>(
        &mut self,
        filter: fn(Box<UlDcchMessage>) -> Result<T, Box<UlDcchMessage>>,
        expected: &str,
    ) -> Result<T> {
        loop {
            let pdcp_bytes = self.api.receive_rrc().await?;
            let ul_dcch_message = self.extract_ul_dcch_message(&pdcp_bytes)?;
            match filter(ul_dcch_message) {
                Ok(extracted) => return Ok(extracted),
                Err(ul_dcch_message) => {
                    debug!(
                        self.logger,
                        "Queue message (wanted {expected} got {:?})", ul_dcch_message
                    );
                    self.api.unexpected_pdu(ul_dcch_message, expected)?;
                }
            }
        }
    }

    // Does this need a separate function?
    fn extract_ul_dcch_message(&self, pdcp_bytes: &[u8]) -> Result<Box<UlDcchMessage>> {
        let rrc_message_bytes = pdcp::view_inner(pdcp_bytes)?;
        Ok(Box::new(UlDcchMessage::from_bytes(rrc_message_bytes)?))
    }

    /// Sends an RRC message.
    async fn send_rrc<T: Send + SerDes>(&mut self, srb: SrbId, rrc: &T) -> Result<()> {
        let rrc_bytes = rrc.as_bytes()?;

        // This needs to be PDCP encapsulated if not going over SRB 0.
        let srb_id = srb.0 as u8;
        let rrc_bytes = if srb_id == 0 {
            rrc_bytes
        } else {
            self.ue.pdcp_tx.encode(srb_id, rrc_bytes).into()
        };

        self.api.send_rrc(srb, rrc_bytes).await
    }
}

use delegate::delegate;
impl<'a, B: RrcBase> NasBase for &mut RrcProcedure<'a, B> {
    delegate! {
    to self.api {
        fn config(&self) -> &Config;
        async fn allocate_userplane_session(&self, ipv4: bool, ue_dhcp_identifier: Vec<u8>) -> Result<UserplaneSession>;
        async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str) -> Option<SubscriberAuthParams>;
        async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;
        async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
        async fn delete_userplane_session(
            &self,
            session: &UserplaneSession
        );
        #[call(unexpected_pdu)]
        fn unexpected_nas_pdu(&mut self, pdu: DecodedNas, expected: &str) -> Result<()>;
        async fn register_new_tmsi(&self) -> [u8; 4];
        async fn delete_tmsi(&self, tmsi: [u8; 4]);
        fn ue_tac(&self) -> &[u8; 3];
        fn disconnect_ue(&mut self);
    }}

    async fn ran_session_setup(
        &mut self,
        pdu_session: &mut PduSession,
        nas: Vec<u8>,
    ) -> Result<()> {
        let cell_group_config = self.api.ran_ue_context_setup(pdu_session).await?;
        self.reconfiguration_add_session(pdu_session, nas, cell_group_config)
            .await
    }

    // TODO naming consistency pdu_session, session_list.  Just use session and sessions for param name?

    async fn ran_context_create(
        &mut self,
        kgnb: &[u8; 32],
        nas: Vec<u8>,
        session_list: &mut Vec<PduSession>,
        _ue_security_capabilities: &[u8; 2],
    ) -> Result<bool> {
        self.security_mode(kgnb).await?;
        if self.api.ue_rat_capabilities().is_none() {
            self.ue_capability_enquiry().await?;
        };

        // If there are PDU sessions to reactivate, create the UE context, otherwise just send the PDU.
        if !session_list.is_empty() {
            // TODO: support >1 session
            let session = &mut session_list[0];
            self.ran_session_setup(session, nas).await?;
        } else {
            self.send_nas(nas).await?;
        }

        // TODO: implement + test paging in F1 mode.  We will need to return true here
        // to trigger a configuration update to the UE following paging.
        Ok(false)
    }

    async fn ran_session_release(
        &mut self,
        released_session: &PduSession,
        nas: Vec<u8>,
    ) -> Result<()> {
        // Send a UE context modification to delete the DRB.
        let cell_group_config = self
            .api
            .ran_ue_context_modification(released_session)
            .await?;
        self.reconfiguration_delete_session(nas, released_session, cell_group_config)
            .await
    }

    async fn send_nas(&mut self, nas_bytes: Vec<u8>) -> Result<()> {
        let rrc = crate::rrc::build::dl_information_transfer(
            1, // TODO transaction ID
            DedicatedNasMessage(nas_bytes),
        );

        self.send_rrc(SrbId(1), &rrc).await
    }

    async fn receive_nas(&mut self) -> Result<Vec<u8>> {
        let ul_information_transfer = self
            .receive_rrc(
                |m| match m.message {
                    UlDcchMessageType::C1(C1_6::UlInformationTransfer(x)) => Ok(x),
                    _ => Err(m),
                },
                "UlInformationTransfer",
            )
            .await?;
        self.log_message(">> Rrc UlInformationTransfer");

        let UlInformationTransfer {
            critical_extensions:
                CriticalExtensions37::UlInformationTransfer(UlInformationTransferIEs {
                    dedicated_nas_message: Some(DedicatedNasMessage(nas_pdu)),
                    ..
                }),
        } = ul_information_transfer
        else {
            bail!("Expected DedicatedNasMessage in UlInformationTransfer")
        };
        Ok(nas_pdu)
    }
}

#[macro_export]
macro_rules! rrc_filter {
    ($m:ident) => {{
        |m| match *m {
            UlDcchMessage {
                message: UlDcchMessageType::C1(C1_6::$m(message)),
            } => Ok(message),
            _ => Err(m),
        }
    }};
}

#[macro_export]
macro_rules! rrc_request_filter {
    ($s:ident, $f:ident) => {{
        |m| match *m {
            UlDcchMessage {
                message: UlDcchMessageType::C1(C1_6::$s(message)),
            } => Ok(Ok(message)),

            UlDcchMessage {
                message: UlDcchMessageType::C1(C1_6::$f(message)),
            } => Ok(Err(message)),

            _ => Err(m),
        }
    }};
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::{RrcBase, RrcProcedure};
    pub use f1ap::SrbId;
    pub use {rrc_filter, rrc_request_filter};
}
