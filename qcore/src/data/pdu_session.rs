use crate::UserplaneSession;
use xxap::Snssai;

#[derive(Debug)]
pub struct PduSession {
    pub id: u8,
    pub snssai: Snssai,
    pub userplane_info: UserplaneSession,
}
