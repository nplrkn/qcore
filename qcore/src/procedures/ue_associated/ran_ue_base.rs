use crate::{
    Config,
    data::{
        DecodedNas, PduSession, SubscriberAuthParams, UeContext5GC, UeRanContext, UserplaneSession,
    },
    procedures::UeMessage,
    protocols::nas::Tmsi,
    qcore::ServedCellsStore,
};
use anyhow::Result;
use slog::{Logger, debug, info};
use xxap::{Indication, Procedure, RequestError};

pub trait RanUeBase {
    fn config(&self) -> &Config;
    fn served_cells(&self) -> &ServedCellsStore;

    async fn reserve_userplane_session(&self, logger: &Logger) -> Result<UserplaneSession>;
    async fn xxap_request<P: Procedure>(
        &self,
        r: Box<P::Request>,
        logger: &Logger,
    ) -> Result<P::Success, RequestError<P::Failure>>;
    async fn xxap_indication<P: Indication>(&self, r: Box<P::Request>, logger: &Logger);
    async fn receive_xxap_pdu<T, BoxP>(
        &mut self,
        filter: fn(BoxP) -> Result<T, BoxP>,
        expected: &str,
    ) -> Result<T>
    where
        BoxP: TryFrom<UeMessage, Error = UeMessage> + Into<UeMessage>;

    async fn commit_userplane_session(
        &self,
        session: &UserplaneSession,
        logger: &Logger,
    ) -> Result<()>;
    async fn deactivate_userplane_session(&self, session: &UserplaneSession, logger: &Logger);
    async fn delete_userplane_session(&self, session: &UserplaneSession, logger: &Logger);
    async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str)
    -> Option<SubscriberAuthParams>;
    async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;

    async fn register_new_tmsi(&self, tmsi: Tmsi, ue_id: u32, logger: &Logger);
    async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;

    // could we do T: Into<UeMessage> to avoid two different functions?
    fn unexpected_nas_pdu(&mut self, pdu: DecodedNas, expected: &str) -> Result<()>;
    fn unexpected_rrc_pdu(&mut self, pdu: Box<rrc::UlDcchMessage>) -> Result<()>;
}
