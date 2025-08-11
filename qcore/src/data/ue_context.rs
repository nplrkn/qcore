use super::{UeContext5GC, UeContextRan, UeContextRrc};

#[derive(Debug, Default)]
pub struct UeContext {
    pub core: UeContext5GC,
    pub rrc: UeContextRrc,
    pub ran: UeContextRan,
}

impl UeContext {
    pub fn new(ue_id: u32) -> Self {
        UeContext {
            core: UeContext5GC::default(),
            rrc: UeContextRrc::default(),
            ran: UeContextRan::new(ue_id),
        }
    }
}
