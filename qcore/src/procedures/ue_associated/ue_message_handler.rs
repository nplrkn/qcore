use crate::{
    ProcedureBase, UeContext,
    data::{UeContext5GC, UeContextRan, UserplaneSession},
    procedures::{
        UeMessage,
        ue_associated::{F1apUeProcedure, NgapUeProcedure, RanUeBase, ran_ue_base::ReleaseCause},
    },
    qcore::ServedCellsMap,
};
use anyhow::{Result, anyhow};
use async_std::channel::{self, Receiver, Sender};
use f1ap::F1apPdu;
use ngap::NgapPdu;
use slog::{Logger, debug, info, warn};
use std::collections::VecDeque;

pub struct UeMessageHandler<A: ProcedureBase> {
    receiver: Receiver<UeMessage>,
    api: A,
    logger: Logger,
    queue: VecDeque<UeMessage>,
    dispatch_status: DispatchStatus,
    release_cause: ReleaseCause,
}

impl<A: ProcedureBase> UeMessageHandler<A> {
    pub fn spawn(ue_id: u32, api: A, logger: Logger) -> Sender<UeMessage> {
        let (sender, receiver) = channel::unbounded();
        async_std::task::spawn(async move {
            UeMessageHandler {
                receiver,
                api,
                logger,
                queue: VecDeque::new(),
                dispatch_status: DispatchStatus::Continue,
                release_cause: ReleaseCause::None,
            }
            .run(ue_id)
            .await;
        });
        sender
    }

    async fn run(&mut self, ue_id: u32) {
        let mut ue = Box::new(UeContext::new(ue_id));
        self.dispatch_all(&mut ue).await;
        self.cleanup(ue).await;
    }

    async fn cleanup(&mut self, mut ue: Box<UeContext>) {
        self.maybe_release_ran(&mut ue).await;
        self.deactivate_pdu_sessions(&ue).await;
        self.give_or_park_core_context(&ue.ran, ue.core).await;
        self.remove_channel(ue.ran).await;
    }

    async fn dispatch_all(&mut self, ue: &mut UeContext) {
        while let DispatchStatus::Continue = self.dispatch_status {
            if let Err(e) = self.dispatch(ue).await {
                // {:#} means print the whole error chain
                warn!(self.logger, "Procedure failure: {:#}", e);
            }
        }
    }

    async fn maybe_release_ran(&mut self, ue: &mut UeContext) {
        if let DispatchStatus::Disconnected = self.dispatch_status {
            debug!(self.logger, "UE disconnected - skip RAN release");
        } else if self.api.ngap_mode() {
            let cause = if let ReleaseCause::Ngap(ref cause) = self.release_cause {
                cause.clone()
            } else {
                ngap::Cause::Nas(ngap::CauseNas::NormalRelease)
            };
            self.ngap_ue_procedure(&mut ue.ran)
                .ue_context_release(cause)
                .await
        } else {
            let cause = if let ReleaseCause::F1ap(ref cause) = self.release_cause {
                cause.clone()
            } else {
                f1ap::Cause::RadioNetwork(f1ap::CauseRadioNetwork::NormalRelease)
            };
            self.f1ap_ue_procedure(&mut ue.ran)
                .ue_context_release(cause)
                .await
        }
    }

    async fn deactivate_pdu_sessions(&mut self, ue: &UeContext) {
        for session in ue.core.pdu_sessions.iter() {
            self.api
                .deactivate_userplane_session(&session.userplane_info, &self.logger)
                .await;
        }
    }

    async fn give_or_park_core_context(
        &mut self,
        ue_ran: &UeContextRan,
        mut ue_core: UeContext5GC,
    ) {
        // If the message handler was asked to give away the core context, send it.
        if let DispatchStatus::ReleaseAndGiveContext(ref sender) = self.dispatch_status {
            if let Err(e) = sender.send(ue_core).await {
                warn!(self.logger, "Failed to send core context: {e}");
            }
        } else {
            // If the UE has a TMSI, save off its core context, so that we can recover it based on GUTI later.
            if let Some(tmsi) = ue_core.tmsi.take() {
                debug!(self.logger, "Store core context for TMSI {tmsi}");
                self.api
                    .put_core_context(tmsi.0, ue_ran.local_ran_ue_id, ue_core, 0, &self.logger)
                    .await;
            }
        }
    }

    async fn remove_channel(&mut self, ue_ran: UeContextRan) {
        // Remove the channel to this UE and drop all messages in it.
        // This must happen after we have stored the core context - see the note on the timing
        // window in take_core_context().
        self.api.delete_ue_channel(ue_ran.local_ran_ue_id).await;
        debug!(self.logger, "Deleted UE channel");
        self.receiver.close();
        while !self.receiver.is_empty() {
            debug!(self.logger, "Receive and discard pending message");
            let _ = self.receiver.recv().await;
        }
    }

    fn ngap_ue_procedure<'a>(
        &mut self,
        ue: &'a mut UeContextRan,
    ) -> NgapUeProcedure<'a, &mut Self> {
        NgapUeProcedure {
            ue,
            logger: self.logger.clone(),
            api: self,
        }
    }

    fn f1ap_ue_procedure<'a>(
        &mut self,
        ue: &'a mut UeContextRan,
    ) -> F1apUeProcedure<'a, &mut Self> {
        F1apUeProcedure {
            ue,
            logger: self.logger.clone(),
            api: self,
        }
    }

    // Returns Err if the UE handler should exit.
    pub async fn dispatch(&mut self, ue: &mut UeContext) -> Result<()> {
        // Process any queued messages before going to the inbox.
        let next_message = if let Some(message) = self.queue.pop_front() {
            message
        } else {
            self.receiver.recv().await?
        };

        match next_message {
            UeMessage::Ngap(pdu) => {
                self.ngap_ue_procedure(&mut ue.ran)
                    .dispatch(pdu, &mut ue.core)
                    .await
            }
            UeMessage::F1ap(pdu) => {
                self.f1ap_ue_procedure(&mut ue.ran)
                    .dispatch(pdu, &mut ue.rrc, &mut ue.core)
                    .await
            }
            UeMessage::Rrc(pdu) => {
                self.f1ap_ue_procedure(&mut ue.ran)
                    .dispatch_rrc(pdu, &mut ue.rrc, &mut ue.core)
                    .await
            }
            UeMessage::Nas(pdu) => {
                if self.api.ngap_mode() {
                    self.ngap_ue_procedure(&mut ue.ran)
                        .dispatch_nas(pdu, &mut ue.core)
                        .await
                } else {
                    self.f1ap_ue_procedure(&mut ue.ran)
                        .dispatch_nas(pdu, &mut ue.rrc, &mut ue.core)
                        .await
                }
            }
            UeMessage::TakeContext(sender) => {
                info!(
                    &self.logger,
                    "UE changed channel - transfer context and clean up"
                );
                self.dispatch_status = DispatchStatus::ReleaseAndGiveContext(sender);
                Ok(())
            }
            UeMessage::Disconnect => {
                debug!(
                    &self.logger,
                    "UE disconnected - exit message handler and store context"
                );
                self.dispatch_status = DispatchStatus::Disconnected;
                Ok(())
            }
            UeMessage::Ping(sender) => {
                debug!(self.logger, "Respond to ping");
                sender.send(()).await?;
                Ok(())
            }
        }
    }

    // Used to enqueue a message if the receiver is not ready to process it.
    fn enqueue_message(&mut self, message: UeMessage) -> Result<()> {
        let mut result = Ok(());

        // Check for messages that should abort the procedure immediately.
        match message {
            UeMessage::TakeContext(_) => {
                result = Err(anyhow!("Take context"));
            }
            UeMessage::Disconnect => {
                result = Err(anyhow!("SCTP disconnection"));
            }
            UeMessage::F1ap(ref m) => {
                if let F1apPdu::InitiatingMessage(
                    f1ap::InitiatingMessage::UeContextReleaseRequest(_),
                ) = *m.as_ref()
                {
                    result = Err(anyhow!("Context release request from DU"));
                }
            }
            UeMessage::Ngap(ref m) => {
                if let NgapPdu::InitiatingMessage(
                    ngap::InitiatingMessage::UeContextReleaseRequest(_),
                ) = *m.as_ref()
                {
                    result = Err(anyhow!("Context release request from gNB"));
                }
            }
            _ => (),
        }

        // In the case of an abort message, we clear the queue of all other messages so
        // we immediately process the abort message in the next round of the dispatch loop.
        if result.is_err() {
            self.queue.clear();
        }

        self.queue.push_back(message);
        result
    }
}

use delegate::delegate;

impl<A: ProcedureBase> RanUeBase for &mut UeMessageHandler<A> {
    delegate! {
        to self.api {
            fn config(&self) -> &crate::Config;
            fn served_cells(&self) -> &ServedCellsMap;
            async fn allocate_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession>;
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
            ue_id: u32,
            logger: &Logger,
        ) -> [u8;4];
        async fn delete_tmsi(&self, tmsi: [u8; 4]);
        async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
    }}

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

    fn disconnect_ue(&mut self, cause: ReleaseCause) {
        self.dispatch_status = DispatchStatus::Release;
        self.release_cause = cause;
    }
}

enum DispatchStatus {
    Continue,
    Disconnected,
    Release,
    ReleaseAndGiveContext(Sender<UeContext5GC>),
}
