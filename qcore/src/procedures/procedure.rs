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
    // pub fn log_message_error(&self, s: &str) {
    //     warn!(self.logger, "{}", s)
    // }
}

impl<A: HandlerApi> std::ops::Deref for Procedure<'_, A> {
    type Target = A;

    fn deref(&self) -> &Self::Target {
        self.api
    }
}
