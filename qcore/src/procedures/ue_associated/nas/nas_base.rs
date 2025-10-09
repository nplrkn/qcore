use crate::{
    Config,
    data::{PduSession, SubscriberAuthParams, UeContext5GC, UserplaneSession},
};
use anyhow::Result;
use nas::DecodedNas;

pub trait NasBase {
    fn config(&self) -> &Config;
    fn ue_tac(&self) -> &[u8; 3];

    async fn register_new_tmsi(&self) -> [u8; 4];
    async fn take_core_context(&self, tmsi: &[u8]) -> Option<UeContext5GC>;
    async fn delete_tmsi(&self, tmsi: [u8; 4]);

    async fn replicate_ue_context(&self, cxt: &UeContext5GC);

    async fn allocate_userplane_session(
        &self,
        ipv4: bool,
        ue_dhcp_identifier: Vec<u8>,
    ) -> Result<UserplaneSession>;
    async fn delete_userplane_session(&self, session: &UserplaneSession);

    async fn ran_session_setup(&mut self, pdu_session: &mut PduSession, nas: Vec<u8>)
    -> Result<()>;

    async fn ran_context_create(
        &mut self,
        kgnb: &[u8; 32],
        nas: Vec<u8>,
        ue_session_list: &mut Vec<PduSession>,
        ue_security_capabilities: &[u8; 2],
    ) -> Result<bool>;

    async fn ran_session_release(
        &mut self,
        released_session: &PduSession,
        nas: Vec<u8>,
    ) -> Result<()>;

    async fn lookup_subscriber_creds_and_inc_sqn(&self, imsi: &str)
    -> Option<SubscriberAuthParams>;

    async fn send_nas(&mut self, nas: Vec<u8>) -> Result<()>;
    async fn receive_nas(&mut self) -> Result<Vec<u8>>;
    fn unexpected_nas_pdu(&mut self, pdu: DecodedNas, expected: &str) -> Result<()>;

    async fn resync_subscriber_sqn(&self, imsi: &str, sqn: [u8; 6]) -> Result<()>;

    fn disconnect_ue(&mut self);
}
