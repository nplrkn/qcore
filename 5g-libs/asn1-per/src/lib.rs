pub use asn1_codecs::{PerCodecData, PerCodecError};
use asn1_codecs::PerCodecErrorCause;
pub use bitvec::prelude::*;
pub type BitString = BitVec<u8, Msb0>;
pub use nonempty::*;
pub use num_enum::TryFromPrimitive;

pub fn per_codec_error_new<T: AsRef<str> + std::fmt::Display>(message: T) -> PerCodecError {
    PerCodecError::new(PerCodecErrorCause::Generic, message)
}

pub trait PerCodec: Sized {
    type Allocator: CodecDataAllocator;
    fn decode(data: &mut PerCodecData) -> Result<Self, crate::PerCodecError>;
    fn encode(&self, _data: &mut PerCodecData) -> Result<(), crate::PerCodecError>;
}

pub trait SerDes: Sized {
    fn into_bytes(self) -> Result<Vec<u8>, PerCodecError>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, PerCodecError>;
}

impl<T: PerCodec> SerDes for T {
    fn into_bytes(self) -> Result<Vec<u8>, PerCodecError> {
        let mut d = T::Allocator::new_codec_data();
        self.encode(&mut d)?;
        Ok(d.into_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PerCodecError> {
        let mut d = T::Allocator::from_slice(bytes);
        Self::decode(&mut d)
    }
}

pub trait CodecDataAllocator {
    fn new_codec_data() -> PerCodecData;
    fn from_slice(bytes: &[u8]) -> PerCodecData;
}

pub mod aper {
    pub use super::{CodecDataAllocator, PerCodecData};
    pub use asn1_codecs::aper::{decode, encode};
    pub struct Allocator;
    impl CodecDataAllocator for Allocator {
        fn new_codec_data() -> PerCodecData {
            PerCodecData::new_aper()
        }
        fn from_slice(bytes: &[u8]) -> PerCodecData {
            crate::PerCodecData::from_slice_aper(bytes)
        }
    }
}

pub mod uper {
    pub use super::{CodecDataAllocator, PerCodecData};
    pub use asn1_codecs::uper::{decode, encode};

    pub struct Allocator;
    impl CodecDataAllocator for Allocator {
        fn new_codec_data() -> PerCodecData {
            PerCodecData::new_uper()
        }
        fn from_slice(bytes: &[u8]) -> PerCodecData {
            crate::PerCodecData::from_slice_uper(bytes)
        }
    }
}
