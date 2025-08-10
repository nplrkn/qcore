use crate::{
    HandlerApi, UeContext,
    data::{UeContext5GC, UserplaneSession},
    procedures::{
        UeMessage,
        ue_associated::{F1apUeProcedure, NgapUeProcedure, RanUeBase},
    },
    qcore::ServedCellsStore,
};
use anyhow::{Result, anyhow, bail};
use async_std::channel::{self, Receiver, Sender};
use f1ap::F1apPdu;
use ngap::NgapPdu;
use slog::{Logger, debug, info, warn};
use std::collections::VecDeque;

pub struct UeMessageHandler<A: HandlerApi> {
    receiver: Receiver<UeMessage>,
    api: A,
    logger: Logger,
    queue: VecDeque<UeMessage>,
    give_context: Option<Sender<UeContext5GC>>,
}

impl<A: HandlerApi> UeMessageHandler<A> {
    pub fn spawn(ue_id: u32, api: A, logger: Logger) -> Sender<UeMessage> {
        let (sender, receiver) = channel::unbounded();
        let mut handler = Box::new(UeMessageHandler {
            receiver,
            api,
            logger,
            queue: VecDeque::new(),
            give_context: None,
        });
        async_std::task::spawn(async move {
            if let Err(e) = handler.run(ue_id).await {
                warn!(handler.logger, "UE message handler exiting: {e}");
            }
        });
        sender
    }

    async fn run(&mut self, ue_id: u32) -> Result<()> {
        let mut ue = Box::new(UeContext::new(ue_id));
        let result = self.dispatch_all(&mut ue).await;
        self.cleanup(ue).await;
        result
    }

    async fn dispatch_all(&mut self, ue: &mut UeContext) -> Result<()> {
        let mut result = Ok(());
        let mut disconnected = false;
        loop {
            // On success, keep dispatching.  On error, release the RAN context as a final
            // procedure before passing up the error.
            if result.is_ok() {
                result = self.dispatch(ue, &mut disconnected).await;
            } else {
                if disconnected {
                    debug!(self.logger, "UE was disconnected - skip RAN release");
                } else if self.api.ngap_mode() {
                    NgapUeProcedure {
                        ue: &mut ue.ran,
                        logger: &self.logger.clone(),
                        api: self,
                        release_cause: ngap::Cause::Nas(ngap::CauseNas::NormalRelease),
                    }
                    .ue_context_release()
                    .await
                } else {
                    F1apUeProcedure {
                        ue: &mut ue.ran,
                        logger: &self.logger.clone(),
                        api: self,
                        release_cause: f1ap::Cause::RadioNetwork(
                            f1ap::CauseRadioNetwork::NormalRelease,
                        ),
                    }
                    .ue_context_release()
                    .await
                }

                return result;
            }
        }
    }

    // TODO move these into a different trait and/or file "Dispatcher"?
    // Return Err if the UE handler should exit.
    pub async fn dispatch(&mut self, ue: &mut UeContext, disconnected: &mut bool) -> Result<()> {
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
            UeMessage::F1ap(pdu) => {
                F1apUeProcedure {
                    ue: &mut ue.ran,
                    logger: &self.logger.clone(),
                    api: self,
                    release_cause: f1ap::Cause::RadioNetwork(
                        f1ap::CauseRadioNetwork::NormalRelease,
                    ),
                }
                .dispatch(pdu, &mut ue.rrc, &mut ue.core)
                .await
            }
            UeMessage::Rrc(pdu) => {
                F1apUeProcedure {
                    ue: &mut ue.ran,
                    logger: &self.logger.clone(),
                    api: self,
                    release_cause: f1ap::Cause::RadioNetwork(
                        f1ap::CauseRadioNetwork::NormalRelease,
                    ),
                }
                .dispatch_rrc(pdu, &mut ue.rrc, &mut ue.core)
                .await
            }
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
                    F1apUeProcedure {
                        ue: &mut ue.ran,
                        logger: &self.logger.clone(),
                        api: self,
                        release_cause: f1ap::Cause::RadioNetwork(
                            f1ap::CauseRadioNetwork::NormalRelease,
                        ),
                    }
                    .dispatch_nas(pdu, &mut ue.rrc, &mut ue.core)
                    .await
                }
            }
            UeMessage::TakeContext(sender) => {
                info!(
                    &self.logger,
                    "UE changed channel - transfer context and clean up"
                );
                self.give_context = Some(sender);
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

    async fn cleanup(&mut self, mut ue_context: Box<UeContext>) {
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
        if let Some(sender) = self.give_context.take() {
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

    // Used to enqueue a message if the receiver is not ready to process it immediately.
    fn enqueue_message(&mut self, message: UeMessage) -> Result<()> {
        // Check for messages that should abort the procedure immediately.
        match message {
            UeMessage::TakeContext(sender) => {
                self.give_context = Some(sender);
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

        self.queue.push_back(message);
        Ok(())
    }
}

use delegate::delegate;

impl<A: HandlerApi> RanUeBase for &mut UeMessageHandler<A> {
    delegate! {
        to self.api {
            fn config(&self) -> &crate::Config;
            fn served_cells(&self) -> &ServedCellsStore;
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
        // async fn deactivate_userplane_session(
        //     &self,
        //     session: &crate::data::UserplaneSession,
        //     logger: &Logger,
        // );
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
    }}

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

    fn unexpected_pdu<T: Into<UeMessage>>(&mut self, pdu: T, expected: &str) -> Result<()> {
        debug!(self.logger, "Queue PDU (wanted {expected})");
        self.enqueue_message(pdu.into())
    }
}
