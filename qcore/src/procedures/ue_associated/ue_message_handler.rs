use crate::{
    HandlerApi, UeContext,
    data::{UeContext5GC, UserplaneSession},
    procedures::{
        UeMessage,
        ue_associated::{NgapUeProcedure, RanUeBase},
    },
};
use anyhow::{Result, anyhow};
use async_std::channel::{self, Receiver, Sender};
use slog::{Logger, debug, info, warn};
use std::collections::VecDeque;

pub struct UeMessageHandler<A: HandlerApi> {
    receiver: Receiver<UeMessage>,
    api: A,
    logger: Logger,
    queue: VecDeque<UeMessage>,
}

impl<A: HandlerApi> UeMessageHandler<A> {
    pub fn spawn(ue_id: u32, api: A, logger: Logger) -> Sender<UeMessage> {
        let (sender, receiver) = channel::unbounded();
        let handler = Box::new(UeMessageHandler {
            receiver,
            api,
            logger,
            queue: VecDeque::new(),
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

    // TODO move these into a different trait and/or file "Dispatcher"?
    // Return Err if the UE handler should exit.
    pub async fn dispatch(
        self,
        ue: &mut UeContext,
        give_context: &mut Option<Sender<UeContext5GC>>,
        disconnected: &mut bool,
    ) -> Result<()> {
        // Process any queued messages before going to the inbox.
        let next_message = if let Some(message) = self.queue.pop_front() {
            message
        } else {
            self.receiver.recv().await?
        };

        match next_message {
            UeMessage::Ngap(pdu) => {
                NgapUeProcedure {
                    ue: &mut ue.ran,
                    logger: &self.logger.clone(),
                    api: self,
                    release_cause: ngap::Cause::Nas(ngap::CauseNas::NormalRelease),
                }
                .dispatch(pdu, &mut ue.core)
                .await
            }
            UeMessage::F1ap(pdu) => self.f1ap_dispatch(pdu).await,
            UeMessage::Rrc(pdu) => self.rrc_dispatch(pdu).await,
            UeMessage::Nas(pdu) => {
                if self.api.ngap_mode() {
                    NgapUeProcedure {
                        ue: &mut ue.ran,
                        logger: &self.logger.clone(),
                        api: self,
                        release_cause: ngap::Cause::Nas(ngap::CauseNas::NormalRelease),
                    }
                    .dispatch_nas(pdu, &mut ue.core)
                    .await
                } else {
                    todo!()
                }
            }

            UeMessage::TakeContext(sender) => {
                info!(
                    &self.logger,
                    "UE changed channel - transfer context and clean up"
                );
                *give_context = Some(sender);
                Err(anyhow!("Take context"))
            }
            UeMessage::Disconnect => {
                info!(
                    &self.logger,
                    "UE disconnected - exit message handler and store context"
                );
                *disconnected = true;
                Err(anyhow!("Disconnected"))
            }
            UeMessage::Ping(sender) => {
                debug!(self.logger, "Respond to ping");
                sender.send(()).await?;
                Ok(())
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
        self.api
            .delete_ue_channel(ue_context.ran.local_ran_ue_id)
            .await;
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
            if let Some(tmsi) = ue_context.core.tmsi.take() {
                debug!(self.logger, "Store core context for TMSI {tmsi}");
                self.api
                    .put_core_context(
                        tmsi,
                        ue_context.ran.local_ran_ue_id,
                        ue_context.core,
                        0,
                        &self.logger,
                    )
                    .await;
            }
        }
    }
}

use delegate::delegate;

impl<A: HandlerApi> RanUeBase for UeMessageHandler<A> {
    delegate! {
        to self.api {
            fn config(&self) -> &crate::Config;
            async fn reserve_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession>;
    async fn xxap_request<P: xxap::Procedure>(
        &self,
        r: Box<P::Request>,
        logger: &Logger,
    ) -> Result<P::Success, xxap::RequestError<P::Failure>>;
    async fn xxap_indication<P: xxap::Indication>(&self, r: Box<P::Request>, logger: &Logger);
        async fn commit_userplane_session(
        &self,
        session: &crate::data::UserplaneSession,
        logger: &Logger,
    ) -> Result<()>;

    async fn deactivate_userplane_session(
        &self,
        session: &crate::data::UserplaneSession,
        logger: &Logger,
    );

    async fn delete_userplane_session(
        &self,
        session: &crate::data::UserplaneSession,
        logger: &Logger,
    );

    async fn lookup_subscriber_creds_and_inc_sqn(
        &self,
        imsi: &str,
    ) -> Option<crate::data::SubscriberAuthParams>;

    async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;

    async fn register_new_tmsi(
        &self,
        tmsi: crate::protocols::nas::Tmsi,
        ue_id: u32,
        logger: &Logger,
    );

    async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
        }
    }

    async fn receive_xxap_pdu<T, BoxP>(
        &mut self,
        filter: fn(BoxP) -> Result<T, BoxP>,
        expected: &str,
    ) -> Result<T>
    where
        BoxP: TryFrom<UeMessage, Error = UeMessage> + Into<UeMessage>,
    {
        todo!()
    }

    fn unexpected_nas_pdu(&mut self, pdu: crate::data::DecodedNas, expected: &str) -> Result<()> {
        todo!()
    }
}
