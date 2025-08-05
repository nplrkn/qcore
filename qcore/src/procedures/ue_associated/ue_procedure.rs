use super::prelude::*;
use crate::{
    UeContext,
    data::{DecodedNas, PduSession, UeContext5GC},
    procedures::{
        UeMessage,
        ue_associated::{
            F1apRanSessionReleaseProcedure, F1apUeContextReleaseProcedure,
            InitialContextSetupProcedure, InitialUeMessageProcedure,
            InitialUlRrcMessageTransferProcedure, NasBase, NgapRanSessionReleaseProcedure,
            NgapUeContextReleaseProcedure, PduSessionResourceSetupProcedure, RrcBase,
            RrcReconfigurationProcedure, RrcSecurityModeProcedure, RrcUeCapabilityEnquiryProcedure,
            UeContextSetupProcedure, UlInformationTransferProcedure, UplinkNasProcedure,
            UplinkNasTransportProcedure,
        },
    },
    protocols::nas::{ABORT_PROCEDURE, FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED, Tmsi, parse},
};
use anyhow::ensure;
use asn1_per::SerDes;
use async_std::channel::{Receiver, Sender};
use f1ap::{DlRrcMessageTransferProcedure, F1apPdu, RrcContainer, SrbId, UlRrcMessageTransfer};
use ngap::{AmfUeNgapId, NgapPdu};
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, NasFGsMobileIdentity, NasPduSessionStatus,
    NasUplinkDataStatus, decode_nas_5gs_message, messages::Nas5gsSecurityHeader,
};
use rrc::{
    C1_6, CriticalExtensions37, DedicatedNasMessage, UlDcchMessage, UlDcchMessageType,
    UlInformationTransfer, UlInformationTransferIEs,
};
use std::collections::VecDeque;

pub struct UeProcedure<'a, A: HandlerApi> {
    base: Procedure<'a, A>,
    pub ue: &'a mut UeContext,
    receiver: &'a Receiver<UeMessage>,
    give_context: &'a mut Option<Sender<UeContext5GC>>,
    pub f1ap_release_cause: f1ap::Cause,
    pub ngap_release_cause: ngap::Cause,
    queued_messages: &'a mut VecDeque<UeMessage>,
    disconnected: &'a mut bool,
}

impl<'a, A: HandlerApi> std::ops::Deref for UeProcedure<'a, A> {
    type Target = Procedure<'a, A>;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl<'a, A: HandlerApi> UeProcedure<'a, A> {
    pub fn new(
        api: &'a A,
        ue: &'a mut UeContext,
        logger: &'a Logger,
        receiver: &'a Receiver<UeMessage>,
        give_context: &'a mut Option<Sender<UeContext5GC>>,
        queued_messages: &'a mut VecDeque<UeMessage>,
        disconnected: &'a mut bool,
    ) -> Self {
        UeProcedure {
            base: Procedure::new(api, logger),
            ue,
            receiver,
            give_context,
            f1ap_release_cause: f1ap::Cause::RadioNetwork(f1ap::CauseRadioNetwork::NormalRelease),
            ngap_release_cause: ngap::Cause::Nas(ngap::CauseNas::NormalRelease),
            queued_messages,
            disconnected,
        }
    }

    // Enables a secure RAN channel for this UE, and reactivates any PDU sessions.
    pub async fn ran_context_create(self, nas: Box<Nas5gsMessage>) -> Result<Self> {
        debug!(
            self.logger,
            "UL NAS COUNT for kGNB derivation {}",
            self.ue.core.nas.ul_nas_count()
        );
        let kgnb = security::derive_kgnb(&self.ue.core.kamf, self.ue.core.nas.ul_nas_count());

        if self.ngap_mode() {
            let nas = self.ue.core.nas.encode(nas)?;
            let s = InitialContextSetupProcedure::new(self)
                .run(&kgnb, nas)
                .await?;
            Ok(s)
        } else {
            // TODO: this should be a procedure of its own.  This function should not contain the implementation of
            // 'ran ue registration'.  It should just swtich to ngap::RanUeRegistration or f1ap::.
            let s = RrcSecurityModeProcedure::new(self).run(&kgnb).await?;

            let mut s = if s.ue.rat_capabilities.is_none() {
                RrcUeCapabilityEnquiryProcedure::new(s).run().await?
            } else {
                s
            };

            // If there are PDU sessions to reactivate, create the UE context, otherwise just send the PDU.
            let s = if !s.ue.core.pdu_sessions.is_empty() {
                s.ran_session_setup(nas).await?
            } else {
                s.nas_indication(nas).await?;
                s
            };
            Ok(s)
        }
    }

    pub async fn commit_userplane_sessions(&mut self) -> Result<()> {
        for session in self.ue.core.pdu_sessions.iter_mut() {
            self.base
                .commit_userplane_session(&session.userplane_info, self.base.logger)
                .await?;
        }
        Ok(())
    }

    pub async fn ran_session_setup(self, nas: Box<Nas5gsMessage>) -> Result<Self> {
        let nas = self.ue.core.nas.encode(nas)?;
        Ok(if self.ngap_mode() {
            let mut inner = PduSessionResourceSetupProcedure::new(self).run(nas).await?;
            inner.commit_userplane_sessions().await?;
            inner
        } else {
            let (mut inner, cell_group_config) = UeContextSetupProcedure::new(self).run().await?;
            inner.commit_userplane_sessions().await?;
            RrcReconfigurationProcedure::new(inner)
                .add_session(nas, cell_group_config.0)
                .await?
        })
    }

    pub async fn ran_session_release(
        self,
        released_session: &PduSession,
        nas: Box<Nas5gsMessage>,
    ) -> Result<Self> {
        let nas = self.ue.core.nas.encode(nas)?;
        if self.ngap_mode() {
            NgapRanSessionReleaseProcedure::new(self)
                .run(released_session, nas)
                .await
        } else {
            F1apRanSessionReleaseProcedure::new(self)
                .run(released_session, nas)
                .await
        }
    }

    pub async fn ran_context_release(self) -> Result<()> {
        if !*self.disconnected {
            if self.ngap_mode() {
                NgapUeContextReleaseProcedure::new(self).run().await
            } else {
                F1apUeContextReleaseProcedure::new(self).run().await
            }
        } else {
            debug!(self.logger, "UE was disconnected - skip RAN release");
            Ok(())
        }
    }

    // TODO move these into a different trait and/or file "Dispatcher"?
    // Return Err if the UE handler should exit.
    pub async fn dispatch(self) -> Result<()> {
        // Process any queued messages before going to the inbox.
        let next_message = if let Some(message) = self.queued_messages.pop_front() {
            message
        } else {
            self.receiver.recv().await?
        };

        match next_message {
            UeMessage::Ngap(pdu) => self.ngap_dispatch(pdu).await,
            UeMessage::F1ap(pdu) => self.f1ap_dispatch(pdu).await,
            UeMessage::Rrc(pdu) => self.rrc_dispatch(pdu).await,
            UeMessage::Nas(pdu) => self.nas_dispatch(pdu).await,
            UeMessage::TakeContext(sender) => {
                info!(
                    &self.logger,
                    "UE changed channel - transfer context and clean up"
                );
                *self.give_context = Some(sender);
                Err(anyhow!("Take context"))
            }
            UeMessage::Disconnect => {
                info!(
                    &self.logger,
                    "UE disconnected - exit message handler and store context"
                );
                *self.disconnected = true;
                Err(anyhow!("Disconnected"))
            }
            UeMessage::Ping(sender) => {
                debug!(self.logger, "Respond to ping");
                sender.send(()).await?;
                Ok(())
            }
        }
    }

    async fn nas_dispatch(self, pdu: DecodedNas) -> Result<()> {
        UplinkNasProcedure::new(self).run_decoded(pdu).await
    }

    // Return Err if the UE handler should exit.
    async fn ngap_dispatch(mut self, pdu: Box<NgapPdu>) -> Result<()> {
        match *pdu {
            NgapPdu::InitiatingMessage(ngap::InitiatingMessage::InitialUeMessage(r)) => {
                InitialUeMessageProcedure::new(self)
                    .run(Box::new(r))
                    .await?
            }
            NgapPdu::InitiatingMessage(ngap::InitiatingMessage::UplinkNasTransport(r)) => {
                UplinkNasTransportProcedure::new(self)
                    .run(Box::new(r))
                    .await?
            }
            NgapPdu::InitiatingMessage(
                ngap::InitiatingMessage::UeRadioCapabilityInfoIndication(_r),
            ) => {
                self.log_message(">> Ngap UeRadioCapabilityInfoIndication");
                debug!(self.logger, "Ignoring UeRadioCapabilityInfoIndication");
            }
            NgapPdu::InitiatingMessage(ngap::InitiatingMessage::UeContextReleaseRequest(r)) => {
                self.log_message(">> Ngap UeContextReleaseRequest");
                info!(
                    self.logger,
                    "GNB initiated context release, cause {:?}", r.cause
                );
                self.ngap_release_cause = r.cause.clone();
                bail!("Context release");
            }

            pdu => {
                debug!(self.logger, "Unsupported NgapPdu");
                bail!("Unsupported NgapPdu {pdu:?}");
            }
        }
        Ok(())
    }

    async fn rrc_dispatch(self, rrc: Box<UlDcchMessage>) -> Result<()> {
        match rrc.message {
            UlDcchMessageType::C1(C1_6::UlInformationTransfer(ul_information_transfer)) => {
                UlInformationTransferProcedure::new(self)
                    .run(ul_information_transfer)
                    .await?
            }
            _ => {
                bail!("Unsupported UlDcchMessage {rrc:?}");
            }
        }
        Ok(())
    }

    async fn f1ap_dispatch(mut self, pdu: Box<F1apPdu>) -> Result<()> {
        match *pdu {
            F1apPdu::InitiatingMessage(f1ap::InitiatingMessage::InitialUlRrcMessageTransfer(r)) => {
                InitialUlRrcMessageTransferProcedure::new(self)
                    .run(Box::new(r))
                    .await?;
            }
            F1apPdu::InitiatingMessage(f1ap::InitiatingMessage::UlRrcMessageTransfer(r)) => {
                self.log_message(">> F1ap UlRrcMessageTransfer");
                let rrc = self.extract_ul_dcch_message(&r)?;
                self.rrc_dispatch(rrc).await?;
            }
            F1apPdu::InitiatingMessage(f1ap::InitiatingMessage::UeContextReleaseRequest(r)) => {
                self.log_message(">> F1ap UeContextReleaseRequest");
                info!(
                    self.logger,
                    "DU initiated context release, cause {:?}", r.cause
                );
                self.f1ap_release_cause = r.cause.clone();
                bail!("Context release");
            }
            pdu => {
                debug!(self.logger, "Unsupported F1apPdu");
                bail!("Unsupported F1apPdu {pdu:?}");
            }
        }
        Ok(())
    }

    /// Receive an NGAP or F1AP message mid-procedure.  
    ///
    /// The caller provides a filter that skips over any unwanted messages.  The caller
    /// may also call enqueue_message() itself if more complex filtering is needed.
    ///
    /// Attempting to queue certain messages will immediately fail and abort the procedure - for example
    /// a Ue Context release request from the DU.  Otherwise, a queue message will be processed later in dispatch().
    ///
    /// The TakeContext message immediately causes any procedure to abort.
    async fn receive_xxap_pdu<T, BoxP>(
        &mut self,
        filter: fn(BoxP) -> Result<T, BoxP>,
        expected: &str,
    ) -> Result<T>
    where
        BoxP: TryFrom<UeMessage, Error = UeMessage> + Into<UeMessage>,
    {
        loop {
            let msg = self.receiver.recv().await?;
            let msg = match BoxP::try_from(msg) {
                Ok(pdu) => match filter(pdu) {
                    Ok(extracted) => return Ok(extracted),
                    Err(pdu) => pdu.into(),
                },
                Err(msg) => msg,
            };
            debug!(self.logger, "Queue message (wanted {expected}) got {}", msg);
            self.enqueue_message(msg)?; // e.g. UeMessage::Ping
        }
    }

    // Used to enqueue a message if the receiver is not ready to process it immediately.
    fn enqueue_message(&mut self, message: UeMessage) -> Result<()> {
        // Check for messages that should abort the procedure immediately.
        match message {
            UeMessage::TakeContext(sender) => {
                *self.give_context = Some(sender);
                bail!("Take context")
            }
            UeMessage::F1ap(ref m) => {
                if let F1apPdu::InitiatingMessage(
                    f1ap::InitiatingMessage::UeContextReleaseRequest(_),
                ) = *m.as_ref()
                {
                    bail!("Context release request from DU - abort current procedure");
                }
            }
            UeMessage::Ngap(ref m) => {
                if let NgapPdu::InitiatingMessage(
                    ngap::InitiatingMessage::UeContextReleaseRequest(_),
                ) = *m.as_ref()
                {
                    bail!("Context release request from gNB - abort current procedure");
                }
            }
            _ => (),
        }

        self.queued_messages.push_back(message);
        Ok(())
    }

    async fn receive_nas_inner(&mut self) -> Result<DecodedNas> {
        let nas = if self.ngap_mode() {
            let uplink_nas_transport = self
                .receive_xxap_pdu(
                    |m: Box<NgapPdu>| match *m {
                        NgapPdu::InitiatingMessage(
                            ngap::InitiatingMessage::UplinkNasTransport(x),
                        ) => Ok(x),
                        _ => Err(m),
                    },
                    "Uplink Nas Transport",
                )
                .await?;
            self.log_message(">> Ngap UplinkNasTransport");
            uplink_nas_transport.nas_pdu.0
        } else {
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
            nas_pdu
        };

        self.nas_decode(&nas)
    }

    fn unexpected_nas_pdu(&mut self, pdu: DecodedNas, expected: &str) -> Result<()> {
        debug!(self.logger, "Queue NAS PDU (wanted {expected})");
        self.enqueue_message(UeMessage::Nas(pdu))?;
        Ok(())
    }

    pub fn nas_decode(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Box<Nas5gsMessage>, Option<Nas5gsSecurityHeader>)> {
        self.ue.core.nas.decode(bytes)
    }

    fn extract_ul_dcch_message(&self, r: &UlRrcMessageTransfer) -> Result<Box<UlDcchMessage>> {
        let rrc_message_bytes = pdcp::view_inner(&r.rrc_container.0)?;
        Ok(Box::new(UlDcchMessage::from_bytes(rrc_message_bytes)?))
    }

    pub async fn retrieve_ue(
        &mut self,
        amf_region: Option<u8>,
        amf_set_and_pointer: &[u8],
        tmsi: &[u8],
    ) -> Result<bool, u8> {
        let guami_matches = amf_set_and_pointer == &self.config().amf_ids[1..3]
            && amf_region
                .map(|x| x == self.config().amf_ids[0])
                .unwrap_or(true);
        if !guami_matches {
            warn!(
                self.logger,
                "Wrong AMF IDs in GUTI/STMSI - theirs {:?}, {:?} ours {}",
                amf_region,
                amf_set_and_pointer,
                self.config().amf_ids
            );
        }

        // Has the UE already obtained a TMSI on its current radio channel?
        if let Some(existing_tmsi) = &self.ue.tmsi {
            if existing_tmsi.0 == tmsi && guami_matches {
                return Ok(false);
            } else {
                warn!(self.logger, "UE not using GUTI it was given");
                return Err(FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED);
            }
        }

        // If we know about this GUTI, retrieve the core context and attach it to this UE.
        if guami_matches {
            match self.take_core_context(tmsi).await {
                Some(c) => {
                    self.ue.core = c;
                    self.ue.tmsi = Some(Tmsi(tmsi.try_into().map_err(|_| ABORT_PROCEDURE)?));
                    return Ok(false);
                }
                None => {
                    debug!(self.logger, "Unknown TMSI");
                }
            }
        }

        // Identity procedure needed
        debug!(self.logger, "GUTI/TMSI with unknown AMF IDs or TMSI");

        Ok(true)
    }
}

impl<'a, A: HandlerApi> super::RrcBase for UeProcedure<'a, A> {
    /// Sends an RRC message and waits for a response.
    async fn rrc_request<T: Send + SerDes, F>(
        &mut self,
        srb_id: SrbId,
        rrc: &T,
        filter: fn(Box<UlDcchMessage>) -> Result<F, Box<UlDcchMessage>>,
        expected: &str,
    ) -> Result<F> {
        // Send the request using the common code in rrc_indication().
        self.rrc_indication(srb_id, rrc).await?;
        self.receive_rrc(filter, expected).await
    }

    async fn receive_rrc<T>(
        &mut self,
        filter: fn(Box<UlDcchMessage>) -> Result<T, Box<UlDcchMessage>>,
        expected: &str,
    ) -> Result<T> {
        loop {
            let ul_rrc_message_transfer = self
                .receive_xxap_pdu(
                    |m: Box<F1apPdu>| match *m {
                        F1apPdu::InitiatingMessage(
                            f1ap::InitiatingMessage::UlRrcMessageTransfer(x),
                        ) => Ok(x),
                        _ => Err(m),
                    },
                    "UlRrcMessageTransfer",
                )
                .await?;
            self.log_message(">> F1ap UlRrcMessageTransfer");
            let ul_dcch_message = self.extract_ul_dcch_message(&ul_rrc_message_transfer)?;
            match filter(ul_dcch_message) {
                Ok(extracted) => return Ok(extracted),
                Err(ul_dcch_message) => {
                    debug!(
                        self.logger,
                        "Queue message (wanted {expected} got {:?})", ul_dcch_message
                    );
                    self.enqueue_message(UeMessage::Rrc(ul_dcch_message))?;
                }
            }
        }
    }

    /// Sends an RRC message.
    async fn rrc_indication<T: Send + SerDes>(&mut self, srb: SrbId, rrc: &T) -> Result<()> {
        let rrc_bytes = rrc.as_bytes()?;

        // This needs to be PDCP encapsulated if not going over SRB 0.
        let srb_id = srb.0 as u8;
        let rrc_bytes = if srb_id == 0 {
            rrc_bytes
        } else {
            self.ue.pdcp_tx.encode(srb_id, rrc_bytes).into()
        };

        let dl_message = crate::f1ap::build::dl_rrc_message_transfer(
            self.ue.local_ran_ue_id,
            self.ue.gnb_du_ue_f1ap_id(),
            RrcContainer(rrc_bytes),
            srb,
        );
        self.log_message("<< F1ap DlRrcMessageTransfer");
        self.api
            .xxap_indication::<DlRrcMessageTransferProcedure>(dl_message, self.logger)
            .await;
        Ok(())
    }
}

impl<'a, A: HandlerApi> NasBase for UeProcedure<'a, A> {
    async fn receive_nas<T>(
        &mut self,
        filter: fn(DecodedNas) -> Result<T, DecodedNas>,
        expected: &str,
    ) -> Result<T> {
        loop {
            let nas = self.receive_nas_inner().await?;
            match filter(nas) {
                Ok(extracted) => return Ok(extracted),
                Err(nas) => self.unexpected_nas_pdu(nas, expected)?,
            }
        }
    }

    async fn receive_nas_sm<T>(
        &mut self,
        filter: fn(Nas5gsmMessage) -> Option<T>,
        expected: &str,
    ) -> Result<T> {
        loop {
            let nas = self.receive_nas_inner().await?;
            if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::UlNasTransport(ref ul_nas_transport)) =
                *nas.0
            {
                let inner = Box::new(decode_nas_5gs_message(
                    &ul_nas_transport.payload_container.value,
                )?);
                if let Nas5gsMessage::Gsm(_, nas_sm) = *inner {
                    if let Some(extracted) = filter(nas_sm) {
                        return Ok(extracted);
                    }
                }
            }
            // This is not the message we are looking for.  Park the top level NAS PDU.  This is rather inefficient
            // since it means we will decode the inner message again later.
            self.unexpected_nas_pdu(nas, expected)?;
        }
    }

    async fn nas_request<T>(
        &mut self,
        nas: Box<Nas5gsMessage>,
        filter: fn(DecodedNas) -> Result<T, DecodedNas>,
        expected: &str,
    ) -> Result<T> {
        self.nas_indication(nas).await?;
        self.receive_nas(filter, expected).await
    }

    async fn nas_indication(&mut self, nas: Box<Nas5gsMessage>) -> Result<()> {
        let nas_bytes = self.ue.core.nas.encode(nas)?;
        if self.ngap_mode() {
            let ngap = crate::ngap::build::downlink_nas_transport(
                AmfUeNgapId(self.ue.local_ran_ue_id as u64),
                self.ue.ran_ue_ngap_id(),
                nas_bytes,
            );

            self.api
                .xxap_indication::<ngap::DownlinkNasTransportProcedure>(ngap, self.logger)
                .await;
            Ok(())
        } else {
            let rrc = crate::rrc::build::dl_information_transfer(
                1, // TODO transaction ID
                DedicatedNasMessage(nas_bytes),
            );

            self.rrc_indication(SrbId(1), &rrc).await
        }
    }

    async fn allocate_tmsi(&mut self) -> NasFGsMobileIdentity {
        let tmsi = Tmsi(rand::random()); // TODO: 0xffffffff is not a valid TMSI (TS23.003, 2.4))
        debug!(self.logger, "Assigned {}", tmsi);
        self.api
            .register_new_tmsi(tmsi.clone(), self.ue.local_ran_ue_id, self.logger)
            .await;
        let guti = crate::protocols::nas::build::nas_mobile_identity_guti(
            &self.config().plmn,
            &self.config().amf_ids,
            &tmsi.0,
        );
        self.ue.tmsi = Some(tmsi);
        guti
    }

    // Removes any sessions that the UE doesn't know about from our UE context.
    // Returns (current sessions, reactivation result).
    async fn reconcile_sessions(
        &mut self,
        uplink_data_status: &Option<NasUplinkDataStatus>,
        pdu_session_status: &Option<NasPduSessionStatus>,
    ) -> Result<(u16, u16)> {
        let uplink_data_status = parse::uplink_data_status(uplink_data_status);
        let pdu_session_status = parse::pdu_session_status(pdu_session_status);

        debug!(
            self.logger,
            "Reconcile sessions: uplink_data_status={:016b}, pdu_session_status={:016b}",
            uplink_data_status,
            pdu_session_status
        );
        // Warn if the uplink data status does not match the PDU session status.
        if uplink_data_status != pdu_session_status {
            warn!(
                self.logger,
                "Uplink data status ({:016b}) does not match PDU session status ({:016b}) - QCore always reactivates all known sessions",
                uplink_data_status,
                pdu_session_status,
            )
        }

        let mut sessions_to_reactivate: u16 = pdu_session_status;

        // Rebuild the UE session list to contain only sessions that the UE knows about.
        let sessions = std::mem::take(&mut self.ue.core.pdu_sessions);
        for session in sessions.into_iter() {
            ensure!(session.id < 16, "Session ID >= 16 not supported");
            let session_id_bit = 1 << session.id;
            if sessions_to_reactivate & session_id_bit == 0 {
                debug!(
                    self.logger,
                    "UE not aware of session {} so delete it", session.id
                );
                self.delete_userplane_session(&session.userplane_info, self.logger)
                    .await;
            } else {
                debug!(self.logger, "UE confirms existing session {}", session.id);
                self.ue.core.pdu_sessions.push(session);

                // Clear the bit in the sessions_to_reactivate bitmask.  Any bits still left set after this process will indicate
                // reactivation failures - cases where the UE thought there was a session but we don't know about it.
                sessions_to_reactivate &= !session_id_bit;
            }
        }

        if sessions_to_reactivate != 0 {
            warn!(
                self.logger,
                "UE asked to reactivate one or more sessions that we don't know about: {:b}",
                sessions_to_reactivate
            );
        }

        let active_sessions = pdu_session_status & !sessions_to_reactivate;

        Ok((active_sessions, sessions_to_reactivate))
    }
}
