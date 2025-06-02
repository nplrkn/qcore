use super::{RrcSetupProcedure, UeProcedure};
use crate::{HandlerApi, UeContext, data::NasContext, procedures::UeMessage};
use anyhow::{Result, bail};
use async_std::channel::{self, Receiver, Sender};
use f1ap::{F1apPdu, InitialUlRrcMessageTransfer, InitiatingMessage};
use slog::{Logger, debug, warn};

pub struct UeMessageHandler<A: HandlerApi> {
    receiver: Receiver<UeMessage>,
    api: A,
    logger: Logger,
}

impl<A: HandlerApi> UeMessageHandler<A> {
    pub fn spawn(ue_id: u32, api: A, logger: Logger) -> Sender<UeMessage> {
        let (sender, receiver) = channel::unbounded();
        let handler = Box::new(UeMessageHandler {
            receiver,
            api,
            logger,
        });
        async_std::task::spawn(async move {
            if let Err(e) = handler.run(ue_id).await {
                warn!(handler.logger, "UE message handler exiting: {e}");
            }
        });
        sender
    }

    async fn run(&self, ue_id: u32) -> Result<()> {
        let (mut ue_context, r) = self.init(ue_id).await?;
        let mut give_context = None;
        let result = self.run_inner(&mut ue_context, r, &mut give_context).await;
        self.cleanup(&give_context, ue_context).await;
        result
    }

    async fn init(&self, ue_id: u32) -> Result<(Box<UeContext>, Box<InitialUlRrcMessageTransfer>)> {
        let UeMessage::F1ap(message) = self.receiver.recv().await? else {
            bail!("Expected InitialUlRrcMessageTransfer, got TakeContext");
        };
        let r = match *message {
            F1apPdu::InitiatingMessage(InitiatingMessage::InitialUlRrcMessageTransfer(r)) => {
                Box::new(r)
            }
            _ => bail!("Expected InitialUlRrcMessageTransfer, got {message:?}"),
        };
        Ok((
            Box::new(UeContext::new(ue_id, r.gnb_du_ue_f1ap_id, r.nr_cgi.clone())),
            r,
        ))
    }

    async fn run_inner(
        &self,
        ue_context: &mut UeContext,
        r: Box<InitialUlRrcMessageTransfer>,
        give_context: &mut Option<Sender<NasContext>>,
    ) -> Result<()> {
        // Run the initial access procedure.
        RrcSetupProcedure::new(UeProcedure::new(
            &self.api,
            ue_context,
            &self.logger,
            &self.receiver,
            give_context,
        ))
        .run(r)
        .await?;

        // Run subsequent procedures.
        loop {
            UeProcedure::new(
                &self.api,
                ue_context,
                &self.logger,
                &self.receiver,
                give_context,
            )
            .dispatch()
            .await?;
        }
    }

    async fn cleanup(
        &self,
        give_context: &Option<Sender<NasContext>>,
        mut ue_context: Box<UeContext>,
    ) {
        // Remove the channel to this UE.
        self.api.delete_ue_channel(ue_context.key);

        // If the message handler was asked to give away the NAS context, send it.
        if let Some(sender) = give_context {
            if let Err(e) = sender.send(ue_context.nas).await {
                warn!(self.logger, "Failed to send NAS context: {e}");
            }

            // TODO - give the sessions too.
        } else {
            // If the UE has a TMSI, save off its NAS context, so that we can recover the security context
            // based on GUTI later.
            if let Some(tmsi) = ue_context.tmsi.take() {
                debug!(self.logger, "Store NAS context for TMSI {tmsi}");
                self.api
                    .put_nas_context(tmsi, ue_context.key, ue_context.nas, 0, &self.logger)
                    .await;
            }
        }

        // Clean up sessions.
        for session in ue_context.pdu_sessions.drain(..) {
            self.api
                .delete_userplane_session(&session.userplane_info, &self.logger)
                .await;
        }
    }
}
