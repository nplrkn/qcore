#[derive(Clone, Debug)]
pub struct Sqn(pub [u8; 6]);

impl Sqn {
    pub fn add(&mut self, amount: u8) {
        let mut scratch = [0u8; 8];
        scratch[2..8].clone_from_slice(&self.0);
        let mut s = u64::from_be_bytes(scratch);
        s += amount as u64;
        let scratch = s.to_be_bytes();
        self.0.clone_from_slice(&scratch[2..8]);
    }
    pub fn inc(&mut self) {
        self.add(1);
    }
}
