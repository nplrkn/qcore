use super::prelude::*;
use crate::{
    Config,
    data::{SubscriberAuthParams, UserplaneSession},
    procedures::UeMessage,
    qcore::ServedCellsMap,
};
use xxap::NrCgi;

pub trait RrcBase {
    async fn receive_rrc(&mut self) -> Result<Vec<u8>>;
    async fn send_rrc(&mut self, srb: SrbId, rrc: Vec<u8>) -> Result<()>;

    fn unexpected_pdu<T: Into<UeMessage>>(&mut self, pdu: T, expected: &str) -> Result<()>;

    fn config(&self) -> &Config;
    fn served_cells(&self) -> &ServedCellsMap;

    fn ue_nr_cgi(&self) -> &Option<NrCgi>;
    fn set_ue_rat_capabilities(&mut self, rat_capabilities: Vec<u8>);
    fn ue_rat_capabilities(&self) -> &Option<Vec<u8>>;
    fn ue_tac(&self) -> &[u8; 3];

    async fn allocate_userplane_session(
        &self,
        ipv4: bool,
        ue_dhcp_identifier: Vec<u8>,
    ) -> Result<UserplaneSession>;
    async fn delete_userplane_session(&self, session: &UserplaneSession);

    async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str)
    -> Option<SubscriberAuthParams>;
    async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;

    async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
    async fn register_new_tmsi(&self) -> [u8; 4];
    async fn delete_tmsi(&self, tmsi: [u8; 4]);
    async fn replicate_ue_context(&self, cxt: &UeContext5GC);

    async fn ran_ue_context_setup(&mut self, session: &mut PduSession) -> Result<Vec<u8>>; // Returns cell group config
    async fn ran_ue_context_modification(
        &mut self,
        released_session: &PduSession,
    ) -> Result<Option<Vec<u8>>>;
    fn disconnect_ue(&mut self);
}
