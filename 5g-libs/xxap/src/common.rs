// The canonical form of Snssai.
#[derive(Copy, Clone, Debug)]
pub struct Snssai(pub u8, pub Option<[u8; 3]>);
