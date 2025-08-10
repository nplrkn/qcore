mod f1ap;
mod ngap;

use super::HandlerApi;
use slog::{Logger, debug};

pub struct Procedure<'a, A: HandlerApi> {
    pub api: &'a A,
    pub logger: &'a Logger,
}

impl<'a, A: HandlerApi> Procedure<'a, A> {
    pub fn new(api: &'a A, logger: &'a Logger) -> Self {
        Procedure { api, logger }
    }
    pub fn log_message(&self, s: &str) {
        debug!(self.logger, "{}", s)
    }
}

mod prelude {
    pub use super::super::prelude::*;
    pub use super::Procedure;
}
