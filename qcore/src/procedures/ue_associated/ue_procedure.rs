use super::prelude::*;
use crate::{
    NasContext, UeContext,
    data::{DecodedNas, PduSession},
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
};
use asn1_per::SerDes;
use async_std::channel::{Receiver, Sender};
use f1ap::{
    CellGroupConfig, DlRrcMessageTransferProcedure, F1apPdu, RrcContainer, SrbId,
    UlRrcMessageTransfer,
};
use ngap::{AmfUeNgapId, NgapPdu};
use oxirush_nas::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, decode_nas_5gs_message,
    messages::Nas5gsSecurityHeader,
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
    give_context: &'a mut Option<Sender<NasContext>>,
    pub f1ap_release_cause: f1ap::Cause,
    pub ngap_release_cause: ngap::Cause,
    queued_messages: &'a mut VecDeque<UeMessage>,
}

impl<'a, A: HandlerApi> std::ops::Deref for UeProcedure<'a, A> {
    type Target = Procedure<'a, A>;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

pub enum RanSessionSetupState {
    Ngap,
    F1ap(CellGroupConfig, Vec<u8>),
}

impl<'a, A: HandlerApi> UeProcedure<'a, A> {
    pub fn new(
        api: &'a A,
        ue: &'a mut UeContext,
        logger: &'a Logger,
        receiver: &'a Receiver<UeMessage>,
        give_context: &'a mut Option<Sender<NasContext>>,
        queued_messages: &'a mut VecDeque<UeMessage>,
    ) -> Self {
        UeProcedure {
            base: Procedure::new(api, logger),
            ue,
            receiver,
            give_context,
            f1ap_release_cause: f1ap::Cause::RadioNetwork(f1ap::CauseRadioNetwork::NormalRelease),
            ngap_release_cause: ngap::Cause::Nas(ngap::CauseNas::NormalRelease),
            queued_messages,
        }
    }

    pub async fn ran_ue_registration(self, kgnb: &[u8; 32]) -> Result<Self> {
        if self.ngap_mode() {
            InitialContextSetupProcedure::new(self).run(kgnb).await
        } else {
            // TODO: this should be a procedure of its own.  This function should not contain the implementation of
            // 'ran ue registration'.  It should just swtich to ngap::RanUeRegistration or f1ap::.
            let s = RrcSecurityModeProcedure::new(self).run(kgnb).await?;

            let s = if s.ue.rat_capabilities.is_none() {
                RrcUeCapabilityEnquiryProcedure::new(s).run().await?
            } else {
                s
            };
            Ok(s)
        }
    }

    pub async fn ran_session_setup_phase1(
        self,
        session: &mut PduSession,
        nas_accept: Vec<u8>,
    ) -> Result<(Self, RanSessionSetupState)> {
        if self.ngap_mode() {
            self.log_message("<< Nas PduSessionEstablishmentAccept");
            PduSessionResourceSetupProcedure::new(self)
                .run(session, nas_accept)
                .await
                .map(|inner| (inner, RanSessionSetupState::Ngap))
        } else {
            UeContextSetupProcedure::new(self).run(session).await.map(
                |(inner, cell_group_config)| {
                    (
                        inner,
                        RanSessionSetupState::F1ap(cell_group_config, nas_accept),
                    )
                },
            )
        }
    }

    pub async fn ran_session_setup_phase2(
        self,
        session_index: usize,
        ran_session_setup_state: RanSessionSetupState,
    ) -> Result<()> {
        match ran_session_setup_state {
            RanSessionSetupState::Ngap => Ok(()),
            RanSessionSetupState::F1ap(cell_group_config, nas) => {
                self.log_message("<< Nas PduSessionEstablishmentAccept");
                let _ = RrcReconfigurationProcedure::new(self)
                    .add_session(nas, session_index, cell_group_config.0)
                    .await;
                Ok(())
            }
        }
    }

    pub async fn ran_session_release(
        self,
        released_session: &PduSession,
        nas: Vec<u8>,
    ) -> Result<Self> {
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
        if self.ngap_mode() {
            NgapUeContextReleaseProcedure::new(self).run().await
        } else {
            F1apUeContextReleaseProcedure::new(self).run().await
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
            UeMessage::Ping(sender) => {
                debug!(self.logger, "Respond to ping");
                sender.send(()).await?;
                Ok(())
            }
        }
    }

    async fn nas_dispatch(self, pdu: DecodedNas) -> Result<()> {
        UplinkNasProcedure::new(self).run(pdu).await
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

    async fn rrc_dispatch(self, mut rrc: Box<UlDcchMessage>) -> Result<()> {
        match &mut rrc.message {
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
        self.ue.nas.decode(bytes, self.logger)
    }

    fn extract_ul_dcch_message(&self, r: &UlRrcMessageTransfer) -> Result<Box<UlDcchMessage>> {
        let rrc_message_bytes = pdcp::view_inner(&r.rrc_container.0)?;
        Ok(Box::new(UlDcchMessage::from_bytes(rrc_message_bytes)?))
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
            self.ue.key,
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
        let nas_bytes = self.ue.nas.encode(nas)?;
        if self.ngap_mode() {
            let ngap = crate::ngap::build::downlink_nas_transport(
                AmfUeNgapId(self.ue.key as u64),
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
}
