//! shutdown_handle - constructed for each long-running async task to simplify the job of gracefully shutting it down

use async_std::task::JoinHandle;
use stop_token::StopSource;

pub struct ShutdownHandle {
    handle: JoinHandle<()>,
    stop_source: StopSource,
}

impl ShutdownHandle {
    pub fn new(handle: JoinHandle<()>, stop_source: StopSource) -> Self {
        Self {
            handle,
            stop_source,
        }
    }
    pub async fn graceful_shutdown(self) {
        drop(self.stop_source);
        self.handle.await
    }
}
