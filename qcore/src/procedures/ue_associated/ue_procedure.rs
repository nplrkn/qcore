use super::prelude::*;
use crate::{
    NasContext, UeContext,
    procedures::{
        UeMessage,
        ue_associated::{
            F1apBase, InitialContextSetupProcedure, InitialUeMessageProcedure, NasBase,
            RrcSecurityModeProcedure, RrcSetupProcedure, UeContextReleaseProcedure,
            UlInformationTransferProcedure,
        },
    },
};
use asn1_per::SerDes;
use async_std::channel::{Receiver, Sender};
use f1ap::{
    DlRrcMessageTransferProcedure, F1apPdu, InitiatingMessage, RrcContainer, SrbId,
    UlRrcMessageTransfer,
};
use ngap::{AmfUeNgapId, NgapPdu, UplinkNasTransport};
use oxirush_nas::{Nas5gsMessage, messages::Nas5gsSecurityHeader};
use rrc::{
    C1_6, CriticalExtensions37, DedicatedNasMessage, UlDcchMessage, UlDcchMessageType,
    UlInformationTransfer, UlInformationTransferIEs,
};

pub struct UeProcedure<'a, A: HandlerApi> {
    base: Procedure<'a, A>,
    pub ue: &'a mut UeContext,
    receiver: &'a Receiver<UeMessage>,
    give_context: &'a mut Option<Sender<NasContext>>,
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
        give_context: &'a mut Option<Sender<NasContext>>,
    ) -> Self {
        UeProcedure {
            base: Procedure::new(api, logger),
            ue,
            receiver,
            give_context,
        }
    }

    pub async fn perform_ran_ue_registration_actions(self, kgnb: &[u8; 32]) -> Result<Self> {
        if self.ngap_mode() {
            InitialContextSetupProcedure::new(self).run(kgnb).await
        } else {
            RrcSecurityModeProcedure::new(self).run(&kgnb).await
        }
    }

    pub async fn dispatch(self) -> Result<()> {
        match self.receiver.recv().await? {
            UeMessage::Ngap(pdu) => self.ngap_dispatch(pdu).await,
            UeMessage::F1ap(pdu) => self.f1ap_dispatch(pdu).await,
            UeMessage::TakeContext(sender) => {
                *self.give_context = Some(sender);
                Err(anyhow!("Take context"))
            }
        }
    }

    // Return Err if the UE handler should exit.
    async fn ngap_dispatch(self, pdu: Box<NgapPdu>) -> Result<()> {
        match *pdu {
            NgapPdu::InitiatingMessage(ngap::InitiatingMessage::InitialUeMessage(r)) => {
                self.log_message(">> Ngap InitialUeMessage");
                InitialUeMessageProcedure::new(self)
                    .run(Box::new(r))
                    .await?
            }
            pdu => {
                bail!("Unsupported F1apPdu {pdu:?}");
            }
        }
        Ok(())
    }

    // TODO move into a different trait Dispatcher?
    // Return Err if the UE handler should exit.
    async fn f1ap_dispatch(self, pdu: Box<F1apPdu>) -> Result<()> {
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
                UeContextReleaseProcedure::new(self)
                    .du_initiated(&r)
                    .await?;
                bail!("Context release");
            }
            pdu => {
                bail!("Unsupported F1apPdu {pdu:?}");
            }
        }
        Ok(())
    }

    // Returns the next F1AP PDU, and also handles TakeContext messages.
    // The latter causes the self-destruction of the UE handler by returning
    // an error.
    async fn receive_f1ap_pdu(&mut self) -> Result<Box<F1apPdu>> {
        match self.receiver.recv().await? {
            UeMessage::F1ap(pdu) => Ok(pdu),
            UeMessage::TakeContext(sender) => {
                *self.give_context = Some(sender);
                Err(anyhow!("Take context"))
            }
            _ => {
                bail!("Unexpected UeMessage received");
            }
        }
    }

    async fn receive_ngap_pdu(&mut self) -> Result<Box<NgapPdu>> {
        match self.receiver.recv().await? {
            UeMessage::Ngap(pdu) => Ok(pdu),
            UeMessage::TakeContext(sender) => {
                *self.give_context = Some(sender);
                Err(anyhow!("Take context"))
            }
            _ => {
                bail!("Unexpected UeMessage received");
            }
        }
    }

    pub fn nas_decode(&mut self, bytes: &[u8]) -> Result<Box<Nas5gsMessage>> {
        self.ue.nas.decode(bytes, self.logger)
    }

    pub fn nas_decode_with_security_header(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Box<Nas5gsMessage>, Option<Nas5gsSecurityHeader>)> {
        self.ue.nas.decode_with_security_header(bytes, self.logger)
    }

    fn extract_ul_dcch_message(&self, r: &UlRrcMessageTransfer) -> Result<Box<UlDcchMessage>> {
        let rrc_message_bytes = pdcp::view_inner(&r.rrc_container.0)?;
        Ok(Box::new(UlDcchMessage::from_bytes(rrc_message_bytes)?))
    }
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

        // Wait for a response.
        let pdu = self.receive_f1ap_pdu().await?;
        let F1apPdu::InitiatingMessage(InitiatingMessage::UlRrcMessageTransfer(
            ul_rrc_message_transfer,
        )) = *pdu
        else {
            bail!("Expected UlRrcMessageTransfer, got {pdu:?}");
        };
        self.log_message(">> F1ap UlRrcMessageTransfer");
        self.extract_ul_dcch_message(&ul_rrc_message_transfer)
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
    async fn nas_request(&mut self, nas: Box<Nas5gsMessage>) -> Result<Box<Nas5gsMessage>> {
        // TODO: these two implementation should be in different files
        if self.ngap_mode() {
            self.nas_indication(nas).await?;
            self.receive_ngap_pdu().await.and_then(|x| match *x {
                NgapPdu::InitiatingMessage(ngap::InitiatingMessage::UplinkNasTransport(
                    UplinkNasTransport { nas_pdu, .. },
                )) => {
                    let msg = self.nas_decode(&nas_pdu.0)?;
                    Ok(msg)
                }
                _ => Err(anyhow!(
                    "Expected DownlinkNasTransport for UE {}",
                    self.ue.key
                )),
            })
        } else {
            let nas_bytes = self.ue.nas.encode(nas)?;
            let rrc = crate::rrc::build::dl_information_transfer(
                1, // TODO transaction ID
                DedicatedNasMessage(nas_bytes),
            );

            self.rrc_request(SrbId(1), &rrc)
                .await
                .and_then(|x| match x.message {
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
