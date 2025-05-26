use crate::SubscriberAuthParams;
use crate::data::NasContext;
use crate::protocols::nas::Tmsi;
use crate::{Config, UserplaneSession};
use anyhow::Result;
use async_trait::async_trait;
use f1ap::F1apPdu;
use slog::Logger;
use xxap::{GtpTunnel, Indication, Procedure, RequestError};

/// Trait representing the collection of services needed by QCore handlers.
#[async_trait]
pub trait HandlerApi: Send + Sync + Clone + 'static {
    fn config(&self) -> &Config;

    // Returns the K, OPC and SQN, and increments the SQN.
    // The returned SQN is the one _before_ the increment.  This means that
    // resync_subscriber_sqn() followed by lookup_subscriber_creds_and_inc_sqn()
    // returns the SQN supplied by the UE for the next challenge.
    async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str)
    -> Option<SubscriberAuthParams>;
    async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;

    async fn take_nas_context(&self, tmsi: &Tmsi) -> Option<NasContext>;
    async fn put_nas_context(&self, tmsi: Tmsi, c: NasContext, ttl_secs: u32);

    fn spawn_ue_message_handler(&self) -> u32;
    async fn dispatch_ue_message(&self, ue_id: u32, message: F1apPdu) -> Result<()>;
    fn delete_ue_channel(&self, ue_id: u32);
    fn delete_ue_channels(&self);

    async fn f1ap_request<P: Procedure>(
        &self,
        r: P::Request,
        logger: &Logger,
    ) -> Result<P::Success, RequestError<P::Failure>>;
    async fn f1ap_indication<P: Indication>(&self, r: P::Request, logger: &Logger);

    async fn reserve_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession>;
    async fn commit_userplane_session(
        &self,
        session: &UserplaneSession,
        remote_tunnel_info: GtpTunnel,
        logger: &Logger,
    ) -> Result<()>;
    async fn delete_userplane_session(&self, session: &UserplaneSession, logger: &Logger);
}
