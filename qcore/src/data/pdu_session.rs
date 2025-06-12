use crate::UserplaneSession;
use f1ap::CellGroupConfig;
use xxap::Snssai;

#[derive(Debug)]
pub struct PduSession {
    pub id: u8,
    pub snssai: Snssai,
    pub dnn: Vec<u8>,
    pub userplane_info: UserplaneSession,

    // This field is used as a temporary place to store
    // CellGroupConfig during an F1AP session establishment procedure.
    pub cell_group_config: Option<CellGroupConfig>,
}
