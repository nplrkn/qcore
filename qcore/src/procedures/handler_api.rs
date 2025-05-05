use crate::SimCreds;
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

    fn lookup_sim(&self, imsi: &str) -> Option<&'static SimCreds>;

    fn spawn_ue_message_handler(&self) -> u32;
    async fn dispatch_ue_message(&self, ue_id: u32, message: F1apPdu) -> Result<()>;
    fn delete_ue_channel(&self, ue_id: u32);

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
