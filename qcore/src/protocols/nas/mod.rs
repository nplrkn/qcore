pub mod build;
pub mod parse;

// TS24.501, Table 9.11.3.2.1
pub const FGMM_CAUSE_SYNCH_FAILURE: u8 = 0b0010101;

#[macro_export]
macro_rules! expect_nas {
    ($t:ident, $m:expr) => {
        match $m {
            Nas5gsMessage::Gmm(_header, Nas5gmmMessage::$t(message)) => Ok(message),
            m => Err(anyhow!("Expected Nas {} but got {:?}", stringify!($t), m)),
        }
    };
}
