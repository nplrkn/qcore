mod deregistration;
mod initial_access;
mod pdu_session_establishment;
mod ue_context_release;
mod ue_message_handler;
mod ul_information_transfer;
mod uplink_nas;

pub use deregistration::DeregistrationProcedure;
pub use initial_access::InitialAccessProcedure;
pub use pdu_session_establishment::SessionEstablishmentProcedure;
pub use ue_context_release::UeContextReleaseProcedure;
pub use ue_message_handler::UeMessageHandler;
pub use ul_information_transfer::UlInformationTransferProcedure;
pub use uplink_nas::UplinkNasProcedure;

use super::Procedure;
use crate::{HandlerApi, UeContext};
use anyhow::{Result, anyhow, bail};
use asn1_per::SerDes;
use async_channel::Receiver;
use f1ap::{
    DlRrcMessageTransferProcedure, F1apPdu, InitiatingMessage, RrcContainer, SrbId,
    UlRrcMessageTransfer,
};
use oxirush_nas::Nas5gsMessage;
use pdcp::{PdcpPdu, PdcpTx};
use rrc::{
    C1_6, CriticalExtensions37, DedicatedNasMessage, UlDcchMessage, UlDcchMessageType,
    UlInformationTransfer, UlInformationTransferIEs,
};
use slog::Logger;

pub struct UeProcedure<'a, A: HandlerApi> {
    base: Procedure<'a, A>,
    ue: &'a mut UeContext,
    receiver: &'a Receiver<F1apPdu>,
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
        receiver: &'a Receiver<F1apPdu>,
    ) -> Self {
        UeProcedure {
            base: Procedure::new(api, logger),
            ue,
            receiver,
        }
    }

    async fn rrc_request<T: Send + SerDes>(
        &mut self,
        srb_id: SrbId,
        rrc: T,
    ) -> Result<UlDcchMessage> {
        let rrc_bytes = rrc.into_bytes()?;
        let rrc_container = maybe_pdcp_encapsulate(rrc_bytes, srb_id.0, &mut self.ue.pdcp_tx);
        let dl_message = crate::f1ap::build::dl_rrc_message_transfer(
            self.ue.key,
            self.ue.gnb_du_ue_f1ap_id,
            rrc_container,
            srb_id,
        );
        self.log_message("<< F1ap DlRrcMessageTransfer");
        self.api
            .f1ap_indication::<DlRrcMessageTransferProcedure>(dl_message, self.logger)
            .await;
        let pdu = self.receiver.recv().await?;
        let F1apPdu::InitiatingMessage(InitiatingMessage::UlRrcMessageTransfer(
            ul_rrc_message_transfer,
        )) = pdu
        else {
            bail!("Expected UlRrcMessageTransfer, got {pdu:?}");
        };
        self.log_message(">> F1ap UlRrcMessageTransfer");
        self.extract_ul_dcch_message(ul_rrc_message_transfer)
    }

    fn extract_ul_dcch_message(
        &self,
        ul_rrc_message_transfer: UlRrcMessageTransfer,
    ) -> Result<UlDcchMessage> {
        let pdcp_pdu = PdcpPdu(ul_rrc_message_transfer.rrc_container.0);
        let rrc_message_bytes = pdcp_pdu.view_inner()?;
        Ok(UlDcchMessage::from_bytes(rrc_message_bytes)?)
    }

    async fn nas_request(&mut self, nas: Nas5gsMessage) -> Result<Nas5gsMessage> {
        let nas_bytes = self.ue.nas.encode(nas)?;
        let rrc = crate::rrc::build::dl_information_transfer(
            1, // TODO transaction ID
            DedicatedNasMessage(nas_bytes),
        );

        self.rrc_request(SrbId(1), rrc)
            .await
            .and_then(|x| match x.message {
                UlDcchMessageType::C1(C1_6::UlInformationTransfer(UlInformationTransfer {
                    critical_extensions:
                        CriticalExtensions37::UlInformationTransfer(UlInformationTransferIEs {
                            dedicated_nas_message: Some(DedicatedNasMessage(response_bytes)),
                            ..
                        }),
                })) => {
                    let msg = self.ue.nas.decode(&response_bytes)?;
                    Ok(msg)
                }
                _ => Err(anyhow!(
                    "Expected RrcUlInformationTransfer with DedicatedNasMessage"
                )),
            })
    }
}

fn maybe_pdcp_encapsulate(rrc_bytes: Vec<u8>, srb_id: u8, pdcp: &mut PdcpTx) -> RrcContainer {
    RrcContainer(if srb_id == 0 {
        rrc_bytes
    } else {
        pdcp.encode(srb_id, rrc_bytes).into()
    })
}
