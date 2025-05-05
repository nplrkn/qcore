use super::{
    InitialAccessProcedure, UeContextReleaseProcedure, UeProcedure, UlInformationTransferProcedure,
};
use crate::{HandlerApi, UeContext};
use anyhow::{Result, bail};
use async_channel::{Receiver, Sender};
use f1ap::{F1apPdu, InitialUlRrcMessageTransfer, InitiatingMessage};
use rrc::{C1_6, UlDcchMessageType};
use slog::{Logger, warn};

pub struct UeMessageHandler<A: HandlerApi> {
    receiver: Receiver<F1apPdu>,
    api: A,
    logger: Logger,
}

impl<A: HandlerApi> UeMessageHandler<A> {
    pub fn spawn(ue_id: u32, api: A, logger: Logger) -> Sender<F1apPdu> {
        let (sender, receiver) = async_channel::unbounded();
        let handler = UeMessageHandler {
            receiver,
            api,
            logger,
        };
        async_std::task::spawn(async move {
            if let Err(e) = handler.run(ue_id).await {
                warn!(handler.logger, "UE message handler exiting: {e}");
            }
        });
        sender
    }

    async fn run(&self, ue_id: u32) -> Result<()> {
        // Create a UE context.
        let message = self.receiver.recv().await?;
        let F1apPdu::InitiatingMessage(InitiatingMessage::InitialUlRrcMessageTransfer(r)) = message
        else {
            bail!("Expected InitialUlRrcMessageTransfer, got {message:?}");
        };
        let mut ue_context = UeContext::new(ue_id, r.gnb_du_ue_f1ap_id, r.nr_cgi.clone());
        let result = self.run_inner(&mut ue_context, r).await;
        self.destroy(&mut ue_context).await;
        result
    }

    async fn run_inner(
        &self,
        ue_context: &mut UeContext,
        r: InitialUlRrcMessageTransfer,
    ) -> Result<()> {
        // Run the initial access procedure.
        InitialAccessProcedure::new(UeProcedure::new(
            &self.api,
            ue_context,
            &self.logger,
            &self.receiver,
        ))
        .run(r)
        .await?;

        // Run successive procedures on the UE.
        while let Ok(pdu) = self.receiver.recv().await {
            let ue_procedure =
                UeProcedure::new(&self.api, ue_context, &self.logger, &self.receiver);

            match pdu {
                F1apPdu::InitiatingMessage(InitiatingMessage::UlRrcMessageTransfer(r)) => {
                    ue_procedure.log_message(">> F1ap UlRrcMessageTransfer");
                    let rrc = ue_procedure.extract_ul_dcch_message(r)?;
                    match rrc.message {
                        UlDcchMessageType::C1(C1_6::UlInformationTransfer(
                            ul_information_transfer,
                        )) => {
                            UlInformationTransferProcedure::new(ue_procedure)
                                .run(ul_information_transfer)
                                .await?
                        }
                        _ => {
                            bail!("Unsupported UlDcchMessage {rrc:?}");
                        }
                    }
                }
                F1apPdu::InitiatingMessage(InitiatingMessage::UeContextReleaseRequest(r)) => {
                    UeContextReleaseProcedure::new(ue_procedure)
                        .du_initiated(r)
                        .await?;
                    bail!("DU initiated context release")
                }
                _ => {
                    bail!("Unsupported F1apPdu {pdu:?}");
                }
            }
        }
        Ok(())
    }

    async fn destroy(&self, ue_context: &mut UeContext) {
        for session in ue_context.pdu_sessions.drain(..) {
            self.api
                .delete_userplane_session(&session.userplane_info, &self.logger)
                .await;
        }

        // Remove the channel to this UE.
        self.api.delete_ue_channel(ue_context.key);
    }
}
