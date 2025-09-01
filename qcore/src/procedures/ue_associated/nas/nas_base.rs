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

    async fn allocate_userplane_session(&self) -> Result<UserplaneSession>;
    async fn delete_userplane_session(&self, session: &UserplaneSession);

    // These must take the sessions as a mut &.  Because the NasProcedure has a borrow on them.
    // So if the NasProcedure continues to exist, it must lend them.

    // The underlying layer cannot simultaneously know about them implicitly.
    // This models an exchange over a network API.

    // What the underlying layer _can_ know about its own UE context.
    // Conclusion - sessions get passed as parameter?

    // Solve that problem, implement this trait and them come back to the take() of the Ue5GCContext.

    async fn ran_session_setup(&mut self, pdu_session: &mut PduSession, nas: Vec<u8>)
    -> Result<()>;

    async fn ran_context_create(
        &mut self,
        kgnb: &[u8; 32],
        nas: Vec<u8>,
        ue_session_list: &mut Vec<PduSession>,
        ue_security_capabilities: &[u8; 2],
    ) -> Result<()>;

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
