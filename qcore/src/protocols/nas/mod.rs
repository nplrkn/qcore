use std::fmt::Display;

use derive_deref::Deref;
use xxap::PlmnIdentity;

pub mod build;
pub mod parse;

// TS24.501, Table 9.11.3.2.1
pub const FGMM_CAUSE_ILLEGAL_UE: u8 = 0b00000011;
#[allow(dead_code)]
pub const FGMM_CAUSE_IMPLICITLY_DEREGISTERED: u8 = 0b00001010;
pub const FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED: u8 = 0b00001001;
#[allow(dead_code)]
pub const FGMM_CAUSE_PLMN_NOT_ALLOWED: u8 = 0b00001011;
pub const FGMM_CAUSE_SYNCH_FAILURE: u8 = 0b0010101;
pub const FGMM_CAUSE_NGKSI_ALREADY_IN_USE: u8 = 0b01000111;
pub const FGMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE: u8 = 0b01011111;
pub const FGMM_CAUSE_IE_NONEXISTENT_OR_NOT_IMPLEMENTED: u8 = 0b01100011;
pub const FGMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE: u8 = 0b01011011;

#[derive(Deref, Debug)]
pub struct Imsi(pub String);

#[derive(Deref, Debug, Eq, Hash, PartialEq, Clone)]
pub struct Tmsi(pub [u8; 4]);
impl Display for Tmsi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tmsi-{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

#[derive(Deref, Debug, Eq, PartialEq, Clone)]
pub struct AmfIds(pub [u8; 3]);
impl Display for AmfIds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}{:02x}{:02x}", self.0[0], self.0[1], self.0[2])
    }
}

#[derive(Debug)]
pub enum MobileIdentity {
    Supi(PlmnIdentity, Imsi),
    Guti(PlmnIdentity, AmfIds, Tmsi),
}

#[macro_export]
macro_rules! ensure_nas {
    ($t:ident, $boxed_nas:expr) => {
        match *$boxed_nas {
            oxirush_nas::Nas5gsMessage::Gmm(_header, oxirush_nas::Nas5gmmMessage::$t(message)) => {
                message
            }
            m => bail!("Expected Nas {} but got {:?}", stringify!($t), m),
        }
    };
}

#[macro_export]
macro_rules! expect_nas {
    ($t:ident, $boxed_nas:expr) => {{
        let b = $boxed_nas;
        match *b {
            oxirush_nas::Nas5gsMessage::Gmm(_header, oxirush_nas::Nas5gmmMessage::$t(message)) => {
                Ok(message)
            }
            _ => Err(b),
        }
    }};
}
