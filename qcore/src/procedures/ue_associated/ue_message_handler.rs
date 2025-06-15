use super::UeProcedure;
use crate::{HandlerApi, NasContext, UeContext, procedures::UeMessage};
use anyhow::Result;
use async_std::channel::{self, Receiver, Sender};
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
        let mut give_context = None;
        let mut ue = Box::new(UeContext::new(ue_id));
        let result = self.dispatch_all(&mut ue, &mut give_context).await;
        self.cleanup(&give_context, ue).await;
        result
    }

    async fn dispatch_all(
        &self,
        ue_context: &mut UeContext,
        give_context: &mut Option<Sender<NasContext>>,
    ) -> Result<()> {
        loop {
            let mut ping = None;
            UeProcedure::new(
                &self.api,
                ue_context,
                &self.logger,
                &self.receiver,
                give_context,
                &mut ping,
            )
            .dispatch()
            .await?;

            if let Some(sender) = ping {
                let _ = sender.send(()).await;
            }
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
