mod rrc;
pub use crate::rrc::*;
use asn1_per::*;

#[cfg(test)]
mod test;

#[derive(Clone, Debug)]
pub enum SetupRelease<T: PerCodec> {
    Release,
    Setup(T),
}

impl<T: PerCodec> PerCodec for SetupRelease<T> {
    type Allocator = uper::Allocator;
    fn decode(_data: &mut PerCodecData) -> Result<Self, PerCodecError> {
        todo!()
    }
    fn encode(&self, _data: &mut PerCodecData) -> Result<(), PerCodecError> {
        todo!()
    }
}
