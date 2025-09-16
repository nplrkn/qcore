use crate::{
    Config,
    data::{SubscriberAuthParams, UeContext5GC, UserplaneSession},
    procedures::UeMessage,
    qcore::ServedCellsMap,
};
use anyhow::Result;
use slog::Logger;
use xxap::{Indication, Procedure, RequestError};

pub trait RanUeBase {
    fn config(&self) -> &Config;
    fn served_cells(&self) -> &ServedCellsMap;

    async fn xxap_request<P: Procedure>(
        &self,
        r: Box<P::Request>,
        logger: &Logger,
    ) -> Result<P::Success, RequestError<P::Failure>>;
    async fn xxap_indication<P: Indication>(&self, r: Box<P::Request>, logger: &Logger);

    /// Receive an NGAP or F1AP message mid-procedure.  
    ///
    /// The caller provides a filter that skips over any unwanted messages.  For more complex filtering, the
    /// caller can receive a message using this function and then put it back in the queue if unwanted using
    /// unexpected_pdu().
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
        BoxP: TryFrom<UeMessage, Error = UeMessage> + Into<UeMessage>;

    fn unexpected_pdu<T: Into<UeMessage>>(&mut self, pdu: T, expected: &str) -> Result<()>;

    async fn allocate_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession>;
    async fn commit_userplane_session(
        &self,
        session: &UserplaneSession,
        logger: &Logger,
    ) -> Result<bool>;
    async fn delete_userplane_session(&self, session: &UserplaneSession, logger: &Logger);

    async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str)
    -> Option<SubscriberAuthParams>;
    async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;

    async fn register_new_tmsi(&self, ue_id: u32, logger: &Logger) -> [u8; 4];
    async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
    async fn delete_tmsi(&self, tmsi: [u8; 4]);

    fn disconnect_ue(&mut self, cause: ReleaseCause);
}

pub enum ReleaseCause {
    None,
    Ngap(ngap::Cause),
    F1ap(f1ap::Cause),
}
