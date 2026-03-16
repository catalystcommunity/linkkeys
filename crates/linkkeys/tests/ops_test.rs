use linkkeys::services::ops::OpsHandler;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[test]
fn test_healthcheck_always_true() {
    let handler = OpsHandler {
        migrations_complete: Arc::new(AtomicBool::new(false)),
    };
    assert!(handler.healthcheck());
}

#[test]
fn test_readiness_before_migrations() {
    let handler = OpsHandler {
        migrations_complete: Arc::new(AtomicBool::new(false)),
    };
    assert!(!handler.readiness());
}

#[test]
fn test_readiness_after_migrations() {
    let handler = OpsHandler {
        migrations_complete: Arc::new(AtomicBool::new(true)),
    };
    assert!(handler.readiness());
}
