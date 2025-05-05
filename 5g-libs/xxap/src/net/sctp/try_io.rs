//! try_io - macro to reduce boilerplate involved in calling unsafe I/O functions

// To use this macro you need to import as follows;
// use super::try_io::try_io;
// use anyhow::{anyhow, Result};
// use io::Error;

macro_rules! try_io {
    ( $x:expr, $operation_name:expr  ) => {{
        let rc = unsafe { $x };
        if rc < 0 {
            Err(anyhow!(format!(
                "{} during SCTP {}",
                Error::last_os_error(),
                $operation_name
            )))
        } else {
            Ok(rc)
        }
    }};
}

pub(crate) use try_io;
