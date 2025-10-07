#[derive(Debug, bincode::Decode, bincode::Encode)]
pub struct Ksi(pub u8);
impl Default for Ksi {
    fn default() -> Self {
        Self(Self::MAX_VALUE)
    }
}
impl Ksi {
    const MAX_VALUE: u8 = 6;
    pub fn inc(&mut self) {
        self.0 = (self.0 + 1) % 7
    }
}
