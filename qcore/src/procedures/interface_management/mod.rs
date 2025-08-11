mod f1ap;
mod ngap;

use super::ProcedureBase;
use slog::{Logger, debug};

pub struct Procedure<'a, A: ProcedureBase> {
    pub api: &'a A,
    pub logger: &'a Logger,
}

impl<'a, A: ProcedureBase> Procedure<'a, A> {
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
