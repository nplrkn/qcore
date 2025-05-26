use derive_deref::Deref;
use f1ap::PlmnIdentity;

pub mod build;
pub mod parse;

// TS24.501, Table 9.11.3.2.1
pub const FGMM_CAUSE_ILLEGAL_UE: u8 = 0b00000011;
pub const FGMM_CAUSE_IMPLICITLY_DEREGISTERED: u8 = 0b00001010;
pub const FGMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED: u8 = 0b00001001;
#[allow(dead_code)]
pub const FGMM_CAUSE_PLMN_NOT_ALLOWED: u8 = 0b00001011;
pub const FGMM_CAUSE_SYNCH_FAILURE: u8 = 0b0010101;

#[derive(Deref, Debug)]
pub struct Imsi(pub String);

#[derive(Deref, Debug, Eq, Hash, PartialEq)]
pub struct Tmsi(pub [u8; 4]);

#[derive(Deref, Debug)]
pub struct AmfIds(pub [u8; 3]);

pub enum MobileIdentity {
    Supi(PlmnIdentity, Imsi),
    Guti(PlmnIdentity, AmfIds, Tmsi),
}

#[macro_export]
macro_rules! expect_nas {
    ($t:ident, $m:expr) => {
        match $m {
            Nas5gsMessage::Gmm(_header, Nas5gmmMessage::$t(message)) => Ok(message),
            m => Err(anyhow!("Expected Nas {} but got {:?}", stringify!($t), m)),
        }
    };
}
