use crate::UserplaneSession;
use bincode::{Decode, Encode};
use xxap::Snssai;

#[derive(Debug, Decode, Encode)]
pub struct PduSession {
    pub id: u8,
    pub sst: u8,
    pub sd: Option<[u8; 3]>,
    pub dnn: Vec<u8>,
    pub userplane: UserplaneSession,
}

impl PduSession {
    pub fn snssai(&self) -> Snssai {
        Snssai(self.sst, self.sd)
    }
}
