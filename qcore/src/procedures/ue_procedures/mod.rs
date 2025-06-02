mod deregistration;
mod pdu_session_establishment;
mod registration;
mod rrc_setup;
mod ue_context_release;
mod ue_message_handler;
mod ul_information_transfer;
mod uplink_nas;

use super::{Procedure, UeMessage};
use crate::{HandlerApi, NasContext, UeContext};
use anyhow::{Result, anyhow, bail};
use asn1_per::SerDes;
use async_std::channel::{Receiver, Sender};
use f1ap::{
    DlRrcMessageTransferProcedure, F1apPdu, InitiatingMessage, RrcContainer, SrbId,
    UlRrcMessageTransfer,
};
use oxirush_nas::{Nas5gsMessage, messages::Nas5gsSecurityHeader};
use rrc::{
    C1_6, CriticalExtensions37, DedicatedNasMessage, UlDcchMessage, UlDcchMessageType,
    UlInformationTransfer, UlInformationTransferIEs,
};
use slog::Logger;

pub use deregistration::DeregistrationProcedure;
pub use pdu_session_establishment::SessionEstablishmentProcedure;
pub use rrc_setup::RrcSetupProcedure;
pub use ue_context_release::UeContextReleaseProcedure;
pub use ue_message_handler::UeMessageHandler;
pub use ul_information_transfer::UlInformationTransferProcedure;
pub use uplink_nas::UplinkNasProcedure;

pub struct UeProcedure<'a, A: HandlerApi> {
    base: Procedure<'a, A>,
    ue: &'a mut UeContext,
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

    // Return Err if the UE handler should exit.
    async fn dispatch(mut self) -> Result<()> {
        match *self.receive_pdu().await? {
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
    async fn receive_pdu(&mut self) -> Result<Box<F1apPdu>> {
        match self.receiver.recv().await? {
            UeMessage::F1ap(pdu) => Ok(pdu),
            UeMessage::TakeContext(sender) => {
                *self.give_context = Some(sender);
                Err(anyhow!("Take context"))
            }
        }
    }

    /// Sends an RRC message and waits for a response.
    async fn rrc_request<T: Send + SerDes>(
        &mut self,
        srb_id: SrbId,
        rrc: &T,
    ) -> Result<Box<UlDcchMessage>> {
        // Send the request using the common code in rrc_indication().
        self.rrc_indication(srb_id, rrc).await?;

        // Wait for a response.
        let pdu = self.receive_pdu().await?;
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
            self.ue.gnb_du_ue_f1ap_id,
            RrcContainer(rrc_bytes),
            srb,
        );
        self.log_message("<< F1ap DlRrcMessageTransfer");
        self.api
            .f1ap_indication::<DlRrcMessageTransferProcedure>(dl_message, self.logger)
            .await;
        Ok(())
    }

    fn extract_ul_dcch_message(&self, r: &UlRrcMessageTransfer) -> Result<Box<UlDcchMessage>> {
        let rrc_message_bytes = pdcp::view_inner(&r.rrc_container.0)?;
        Ok(Box::new(UlDcchMessage::from_bytes(rrc_message_bytes)?))
    }

    fn nas_decode(&mut self, bytes: &[u8]) -> Result<Box<Nas5gsMessage>> {
        self.ue.nas.decode(bytes, self.logger)
    }

    fn nas_decode_with_security_header(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Box<Nas5gsMessage>, Option<Nas5gsSecurityHeader>)> {
        self.ue.nas.decode_with_security_header(bytes, self.logger)
    }

    async fn nas_request(&mut self, nas: Box<Nas5gsMessage>) -> Result<Box<Nas5gsMessage>> {
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

    async fn nas_indication(&mut self, nas: Box<Nas5gsMessage>) -> Result<()> {
        let nas_bytes = self.ue.nas.encode(nas)?;
        let rrc = crate::rrc::build::dl_information_transfer(
            1, // TODO transaction ID
            DedicatedNasMessage(nas_bytes),
        );

        self.rrc_indication(SrbId(1), &rrc).await
    }
}
