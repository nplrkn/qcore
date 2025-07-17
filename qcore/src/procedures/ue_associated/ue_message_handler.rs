use super::UeProcedure;
use crate::{HandlerApi, UeContext, data::UeContext5GC, procedures::UeMessage};
use anyhow::Result;
use async_std::channel::{self, Receiver, Sender};
use slog::{Logger, debug, warn};
use std::collections::VecDeque;

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
        self.cleanup(give_context, ue).await;
        result
    }

    async fn dispatch_all(
        &self,
        ue_context: &mut UeContext,
        give_context: &mut Option<Sender<UeContext5GC>>,
    ) -> Result<()> {
        let mut queue = VecDeque::new();
        let mut result = Ok(());
        let mut disconnected = false;
        loop {
            let ue_procedure = UeProcedure::new(
                &self.api,
                ue_context,
                &self.logger,
                &self.receiver,
                give_context,
                &mut queue,
                &mut disconnected,
            );

            // On success, keep dispatching.  On error, release the RAN context as a final
            // procedure before passing up the error.
            if result.is_ok() {
                result = ue_procedure.dispatch().await;
            } else {
                if let Err(e) = ue_procedure.ran_context_release().await {
                    warn!(self.logger, "Failed to release RAN context: {e}");
                }
                return result;
            }
        }
    }

    async fn cleanup(
        &self,
        give_context: Option<Sender<UeContext5GC>>,
        mut ue_context: Box<UeContext>,
    ) {
        debug!(self.logger, "Clean up UE context");

        // Remove the channel to this UE and drop all messages in it.
        self.api.delete_ue_channel(ue_context.local_ran_ue_id).await;
        debug!(self.logger, "Deleted UE channel");
        self.receiver.close();

        while !self.receiver.is_empty() {
            debug!(self.logger, "Receive and discard pending message");
            let _ = self.receiver.recv().await;
        }

        // Deactivate sessions.
        for session in ue_context.core.pdu_sessions.iter() {
            self.api
                .deactivate_userplane_session(&session.userplane_info, &self.logger)
                .await;
        }

        // If the message handler was asked to give away the core context, send it.
        if let Some(sender) = give_context {
            if let Err(e) = sender.send(ue_context.core).await {
                warn!(self.logger, "Failed to send core context: {e}");
            }
        } else {
            // If the UE has a TMSI, save off its core context, so that we can recover it based on GUTI later.
            if let Some(tmsi) = ue_context.tmsi.take() {
                debug!(self.logger, "Store core context for TMSI {tmsi}");
                self.api
                    .put_core_context(
                        tmsi,
                        ue_context.local_ran_ue_id,
                        ue_context.core,
                        0,
                        &self.logger,
                    )
                    .await;
            }
        }
    }
}
