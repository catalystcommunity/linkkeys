use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Ops service handler for health and readiness checks.
///
/// Once csilgen produces valid traits, this will implement the generated Ops trait.
pub struct OpsHandler {
    pub migrations_complete: Arc<AtomicBool>,
}

impl OpsHandler {
    pub fn healthcheck(&self) -> bool {
        true
    }

    pub fn readiness(&self) -> bool {
        self.migrations_complete.load(Ordering::SeqCst)
    }
}
