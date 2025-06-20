use super::prelude::*;
use crate::{
    NasContext, UeContext,
    data::{DecodedNas, PduSession},
    procedures::{
        UeMessage,
        ue_associated::{
            F1apBase, F1apModeSessionReleaseProcedure, InitialContextSetupProcedure,
            InitialUeMessageProcedure, NasBase, PduSessionResourceSetupProcedure,
            RrcReconfigurationProcedure, RrcSecurityModeProcedure, RrcSetupProcedure,
            RrcUeCapabilityEnquiryProcedure, UeContextReleaseProcedure, UeContextSetupProcedure,
            UlInformationTransferProcedure, UplinkNasProcedure, UplinkNasTransportProcedure,
        },
    },
};
use asn1_per::SerDes;
use async_std::channel::{Receiver, Sender};
use f1ap::{
    CellGroupConfig, DlRrcMessageTransferProcedure, F1apPdu, InitiatingMessage, RrcContainer,
    SrbId, UlRrcMessageTransfer,
};
use ngap::{AmfUeNgapId, NgapPdu, UplinkNasTransport};
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
    ping: &'a mut Option<Sender<()>>,
    pub f1ap_release_cause: f1ap::Cause,
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
        ping: &'a mut Option<Sender<()>>,
        queued_messages: &'a mut VecDeque<UeMessage>,
    ) -> Self {
        UeProcedure {
            base: Procedure::new(api, logger),
            ue,
            receiver,
            give_context,
            ping,
            f1ap_release_cause: f1ap::Cause::RadioNetwork(f1ap::CauseRadioNetwork::NormalRelease),
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
                self.log_message("<< NasPduSessionEstablishmentAccept");
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
            bail!("Session deletion not yet implemented in NGAP mode")
        } else {
            F1apModeSessionReleaseProcedure::new(self)
                .run(released_session, nas)
                .await
        }
    }

    pub async fn ran_context_release(self) -> Result<()> {
        if self.ngap_mode() {
            bail!("Ran context release not yet implemented in NGAP mode")
        } else {
            UeContextReleaseProcedure::new(self).run().await
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
                *(self.ping) = Some(sender);
                Ok(())
            }
        }
    }

    async fn nas_dispatch(self, pdu: DecodedNas) -> Result<()> {
        UplinkNasProcedure::new(self).run(pdu).await
    }

    // Return Err if the UE handler should exit.
    async fn ngap_dispatch(self, pdu: Box<NgapPdu>) -> Result<()> {
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
            pdu => {
                bail!("Unsupported NgapPdu {pdu:?}");
            }
        }
        Ok(())
    }

    async fn f1ap_dispatch(mut self, pdu: Box<F1apPdu>) -> Result<()> {
        match *pdu {
            F1apPdu::InitiatingMessage(InitiatingMessage::InitialUlRrcMessageTransfer(r)) => {
                self.log_message(">> F1ap InitialUlRrcMessageTransfer");
                RrcSetupProcedure::new(self).run(Box::new(r)).await?;
            }
            F1apPdu::InitiatingMessage(InitiatingMessage::UlRrcMessageTransfer(r)) => {
                self.log_message(">> F1ap UlRrcMessageTransfer");
                let mut rrc = self.extract_ul_dcch_message(&r)?;
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
            }
            F1apPdu::InitiatingMessage(InitiatingMessage::UeContextReleaseRequest(r)) => {
                self.log_message(">> F1ap UeContextReleaseRequest");
                info!(
                    self.logger,
                    "DU initiated context release, cause {:?}", r.cause
                );
                self.f1ap_release_cause = r.cause.clone();
                bail!("Context release");
            }
            pdu => {
                bail!("Unsupported F1apPdu {pdu:?}");
            }
        }
        Ok(())
    }

    async fn receive_pdu(&mut self) -> Result<UeMessage> {
        loop {
            match self.receiver.recv().await? {
                UeMessage::TakeContext(sender) => {
                    *self.give_context = Some(sender);
                    bail!("Take context")
                }
                UeMessage::Ping(sender) => {
                    *self.ping = Some(sender);
                }
                x => return Ok(x),
            }
        }
    }

    async fn receive_f1ap_pdu<T>(
        &mut self,
        filter: fn(Box<F1apPdu>) -> Result<T, Box<F1apPdu>>,
        expected: &str,
    ) -> Result<T> {
        loop {
            let msg = self.receive_pdu().await?;
            match msg {
                UeMessage::F1ap(pdu) => match filter(pdu) {
                    Ok(extracted) => return Ok(extracted),
                    Err(pdu) => {
                        self.unexpected_f1ap_pdu(pdu, expected)?;
                        continue;
                    }
                },
                _ => {
                    bail!("Unexpected UeMessage received");
                }
            }
        }
    }

    async fn receive_ngap_pdu<T>(
        &mut self,
        filter: fn(Box<NgapPdu>) -> Result<T, Box<NgapPdu>>,
        expected: &str,
    ) -> Result<T> {
        loop {
            let msg = self.receive_pdu().await?;
            match msg {
                UeMessage::Ngap(pdu) => match filter(pdu) {
                    Ok(extracted) => return Ok(extracted),
                    Err(pdu) => {
                        self.unexpected_ngap_pdu(pdu, expected)?;
                        continue;
                    }
                },
                _ => {
                    bail!("Unexpected UeMessage received");
                }
            }
        }
    }

    // Used to enqueue a message if the receiver is not ready to process it immediately.
    fn enqueue_message(&mut self, message: UeMessage) {
        self.queued_messages.push_back(message);
    }

    async fn receive_nas_inner(&mut self) -> Result<DecodedNas> {
        if self.ngap_mode() {
            let uplink_nas_transport = self
                .receive_ngap_pdu(
                    |m| match *m {
                        NgapPdu::InitiatingMessage(
                            ngap::InitiatingMessage::UplinkNasTransport(x),
                        ) => Ok(x),
                        _ => Err(m),
                    },
                    "Uplink Nas Transport",
                )
                .await?;

            let msg = self.nas_decode(&uplink_nas_transport.nas_pdu.0)?;
            return Ok(msg);
        } else {
            self.receive_rrc().await.and_then(|x| match x.message {
                UlDcchMessageType::C1(C1_6::UlInformationTransfer(UlInformationTransfer {
                    critical_extensions:
                        CriticalExtensions37::UlInformationTransfer(UlInformationTransferIEs {
                            dedicated_nas_message: Some(DedicatedNasMessage(response_bytes)),
                            ..
                        }),
                })) => {
                    let msg = self.nas_decode(&response_bytes)?;
                    Ok(msg)
                }
                _ => Err(anyhow!(
                    "Expected RrcUlInformationTransfer with DedicatedNasMessage"
                )),
            })
        }
    }

    // Used in the middle of a procedure when an unexpected message is received and
    // decides whether to enqueue an unexpected NGAP PDU or abort the current procedure.
    //
    // For example, while a NAS procedure might be waiting for a response that will arrive
    // in a Ngap UplinkNasTransport, the GNB might first send a UE capability indication.  In this case,
    // we can process the indication later.
    //
    // However if the indication is telling us to tear down the UE context, we should abandon the Nas procedure.
    fn unexpected_ngap_pdu(&mut self, pdu: Box<NgapPdu>, expected: &str) -> Result<()> {
        debug!(self.logger, "Queue NGAP PDU (wanted {expected})");
        self.enqueue_message(UeMessage::Ngap(pdu));
        Ok(())
    }

    fn unexpected_f1ap_pdu(&mut self, pdu: Box<F1apPdu>, expected: &str) -> Result<()> {
        bail!("Expected {expected}, got {pdu:?}");
    }

    fn unexpected_nas_pdu(&mut self, pdu: DecodedNas, expected: &str) -> Result<()> {
        debug!(self.logger, "Queue NAS PDU (wanted {expected})");
        self.enqueue_message(UeMessage::Nas(pdu));
        Ok(())
    }

    // pub fn nas_decode(&mut self, bytes: &[u8]) -> Result<Box<Nas5gsMessage>> {
    //     self.ue.nas.decode(bytes, self.logger)
    // }

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

    // OAI UE sends a security protected deregistration request where the inner
    // message has security header type 0x0100 - INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_SECU_CTX -
    // but no security header.
    // Wireshark parses this OK, but our Oxirush NAS decoder doesn't.
    // Current hypothesis is that OAI is getting it wrong, and Wireshark is tolerating it because
    // it calculates inner messsage offsets assuming that it cannot have a security header.
    //
    // For now, we have this hack to patch the message to pacify the NAS decoder.
    // fn patch_nas_for_oai_deregistration_security_header(&self, nas_bytes: &mut [u8]) {
    //     const INNER_SECURITY_HEADER_TYPE_OFFSET: usize = 8;
    //     if nas_bytes.len() < (INNER_SECURITY_HEADER_TYPE_OFFSET + 1) {
    //         return;
    //     }

    //     if nas_bytes[0] == 0x7e && nas_bytes[1] == 0x02 {
    //         // Security protected MM message.
    //         // The inner message header starts at byte 7, and its security header type is at byte 8.
    //         if nas_bytes[INNER_SECURITY_HEADER_TYPE_OFFSET] != 0x00 {
    //             warn!(
    //                 self.logger,
    //                 "Patching NAS message to change inner message security header type from {:?} to 0",
    //                 nas_bytes[INNER_SECURITY_HEADER_TYPE_OFFSET]
    //             );
    //             nas_bytes[INNER_SECURITY_HEADER_TYPE_OFFSET] = 0x00;
    //         }
    //     }
    // }
}

impl<'a, A: HandlerApi> super::F1apBase for UeProcedure<'a, A> {
    /// Sends an RRC message and waits for a response.
    async fn rrc_request<T: Send + SerDes>(
        &mut self,
        srb_id: SrbId,
        rrc: &T,
    ) -> Result<Box<UlDcchMessage>> {
        // Send the request using the common code in rrc_indication().
        self.rrc_indication(srb_id, rrc).await?;
        self.receive_rrc().await
    }

    async fn receive_rrc(&mut self) -> Result<Box<UlDcchMessage>> {
        let ul_rrc_message_transfer = self
            .receive_f1ap_pdu(
                |message| match *message {
                    F1apPdu::InitiatingMessage(InitiatingMessage::UlRrcMessageTransfer(x)) => Ok(x),
                    _ => Err(message),
                },
                "UlRrcMessageTransfer",
            )
            .await?;
        self.log_message(">> F1ap UlRrcMessageTransfer");
        return self.extract_ul_dcch_message(&ul_rrc_message_transfer);
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
