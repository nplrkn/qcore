#[derive(Clone, Default)]
pub struct UePagingInfo {
    pub tmsi: [u8; 4],
    pub tac: [u8; 3],
}
