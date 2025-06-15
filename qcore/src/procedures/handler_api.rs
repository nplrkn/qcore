use crate::{Config, NasContext, SubscriberAuthParams, UserplaneSession, nas::Tmsi};
use anyhow::Result;
use async_std::channel::Sender;
use async_trait::async_trait;
use f1ap::F1apPdu;
use ngap::NgapPdu;
use slog::Logger;
use xxap::{Indication, Procedure, RequestError};

#[derive(Debug)]
pub enum UeMessage {
    F1ap(Box<F1apPdu>),
    Ngap(Box<NgapPdu>),
    TakeContext(Sender<NasContext>),

    // Send this message to a message handler to get a notification when the current procedure has finished processing.
    // Useful for testing purposes, to ensure that QCore has finished processing a response that the test framework
    // has sent in.
    Ping(Sender<()>),
}

/// Trait representing the collection of services needed by QCore procedure handlers.
#[async_trait]
pub trait HandlerApi: Send + Sync + Clone + 'static {
    fn config(&self) -> &Config;
    fn ngap_mode(&self) -> bool;

    // Returns the K, OPC and SQN, and increments the SQN.
    // The returned SQN is the one _before_ the increment.  This means that
    // resync_subscriber_sqn() followed by lookup_subscriber_creds_and_inc_sqn()
    // returns the SQN supplied by the UE for the next challenge.
    async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str)
    -> Option<SubscriberAuthParams>;
    async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;

    async fn register_new_tmsi(&self, tmsi: Tmsi, ue_id: u32, logger: &Logger);
    async fn take_nas_context(&self, tmsi: &Tmsi) -> Option<NasContext>;
    async fn put_nas_context(
        &self,
        tmsi: Tmsi,
        ue_id: u32,
        c: NasContext,
        ttl_secs: u32,
        logger: &Logger,
    );

    fn spawn_ue_message_handler(&self) -> u32;
    async fn dispatch_ue_message(&self, ue_id: u32, message: UeMessage) -> Result<()>;
    fn delete_ue_channel(&self, ue_id: u32);
    fn delete_ue_channels(&self);

    async fn xxap_request<P: Procedure>(
        &self,
        r: Box<P::Request>,
        logger: &Logger,
    ) -> Result<P::Success, RequestError<P::Failure>>;
    async fn xxap_indication<P: Indication>(&self, r: Box<P::Request>, logger: &Logger);

    async fn reserve_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession>;
    async fn commit_userplane_session(
        &self,
        session: &UserplaneSession,
        logger: &Logger,
    ) -> Result<()>;
    async fn delete_userplane_session(&self, session: &UserplaneSession, logger: &Logger);
}
