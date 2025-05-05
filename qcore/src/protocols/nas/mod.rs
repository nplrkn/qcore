pub mod build;
pub mod parse;

#[macro_export]
macro_rules! expect_nas {
    ($t:ident, $m:expr) => {
        match $m {
            Nas5gsMessage::Gmm(_header, Nas5gmmMessage::$t(message)) => Ok(message),
            m => Err(anyhow!("Expected Nas {} but got {:?}", stringify!($t), m)),
        }
    };
}
