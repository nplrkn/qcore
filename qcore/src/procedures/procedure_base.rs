use crate::{
    Config, SubscriberAuthParams, UserplaneSession, data::UeContext5GC, procedures::UeMessage,
    qcore::ServedCellsMap,
};
use anyhow::Result;
use async_trait::async_trait;
use slog::Logger;
use xxap::{Indication, Procedure, RequestError};

/// Trait representing the collection of services needed by QCore procedure handlers.
#[async_trait]
pub trait ProcedureBase: Send + Sync + Clone + 'static {
    fn config(&self) -> &Config;
    fn ngap_mode(&self) -> bool;
    fn served_cells(&self) -> &ServedCellsMap;

    // Returns the K, OPC and SQN, and increments the SQN.
    // The returned SQN is the one _before_ the increment.  This means that
    // resync_subscriber_sqn() followed by lookup_subscriber_creds_and_inc_sqn()
    // returns the SQN that the UE will use for the next challenge.
    async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str)
    -> Option<SubscriberAuthParams>;
    async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;

    async fn register_new_tmsi(&self, ue_id: u32, logger: &Logger) -> [u8; 4];
    async fn delete_tmsi(&self, tmsi: [u8; 4]);
    async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
    async fn put_core_context(
        &self,
        tmsi: [u8; 4],
        ue_id: u32,
        c: UeContext5GC,
        _ttl_secs: u32,
        logger: &Logger,
    );

    async fn spawn_ue_message_handler(&self) -> u32;
    async fn dispatch_ue_message(&self, ue_id: u32, message: UeMessage) -> Result<()>;
    async fn delete_ue_channel(&self, ue_id: u32);
    async fn disconnect_ues(&self);

    async fn xxap_request<P: Procedure>(
        &self,
        r: Box<P::Request>,
        logger: &Logger,
    ) -> Result<P::Success, RequestError<P::Failure>>;
    async fn xxap_indication<P: Indication>(&self, r: Box<P::Request>, logger: &Logger);

    async fn allocate_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession>;
    async fn commit_userplane_session(
        &self,
        session: &UserplaneSession,
        logger: &Logger,
    ) -> Result<()>;
    async fn deactivate_userplane_session(&self, session: &UserplaneSession, logger: &Logger);
    async fn delete_userplane_session(&self, session: &UserplaneSession, logger: &Logger);
}
