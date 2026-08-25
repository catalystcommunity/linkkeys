mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::{future::Future, pin::Pin};

use linkkeys::services::notification::{
    DeliveryFailure, EmailDeliveryChannel, InMemoryEmailTransport, OutboxWorker,
};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
}

fn enqueue(
    pool: &linkkeys::db::DbPool,
    user_id: &str,
    key: &[u8; 32],
    purpose: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) {
    let link = format!(
        "https://id.example.test/app/action?token={purpose}-secret-{}",
        uuid::Uuid::now_v7()
    );
    let encrypted = liblinkkeys::crypto::encrypt_with_key(key, link.as_bytes()).unwrap();
    pool.create_account_challenge_and_outbox(
        user_id,
        purpose,
        "email",
        "person@example.test",
        &linkkeys::services::verification::token_digest(&link),
        encrypted,
        expires_at,
        None,
    )
    .expect("enqueue notification");
}

#[test]
fn worker_delivers_and_redacts_the_secret_payload() {
    let pool = common::create_test_pool();
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let key = [7_u8; 32];
    enqueue(
        &pool,
        &user.id,
        &key,
        "verify_contact",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let transport = Arc::new(InMemoryEmailTransport::default());
    let channel = Arc::new(EmailDeliveryChannel::new(
        "LinkKeys <noreply@example.test>".to_string(),
        transport.clone(),
    ));
    let worker = OutboxWorker::new(pool.clone(), channel, key, 3, 60);

    assert!(runtime().block_on(worker.run_once()).unwrap());
    let item = pool
        .find_latest_notification_outbox(&user.id, "verify_contact")
        .unwrap()
        .unwrap();
    assert_eq!(item.state, "delivered");
    assert_eq!(item.attempt_count, 1);
    assert!(item.encrypted_payload.is_none());
    assert!(item.lease_owner.is_none());
    let messages = transport.messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].to, "person@example.test");
    assert!(messages[0].body.contains("verify_contact-secret"));
    assert!(!runtime().block_on(worker.run_once()).unwrap());
}

#[test]
fn worker_retries_temporary_failures_and_redacts_terminal_failures() {
    let pool = common::create_test_pool();
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let key = [8_u8; 32];
    let transport = Arc::new(InMemoryEmailTransport::default());
    let channel = Arc::new(EmailDeliveryChannel::new(
        "noreply@example.test".to_string(),
        transport.clone(),
    ));
    let worker = OutboxWorker::new(pool.clone(), channel, key, 3, 60);

    enqueue(
        &pool,
        &user.id,
        &key,
        "verify_contact",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    transport.fail_next(DeliveryFailure {
        category: "smtp_timeout",
        permanent: false,
    });
    runtime().block_on(worker.run_once()).unwrap();
    let retry = pool
        .find_latest_notification_outbox(&user.id, "verify_contact")
        .unwrap()
        .unwrap();
    assert_eq!(retry.state, "pending");
    assert_eq!(retry.last_error.as_deref(), Some("smtp_timeout"));
    assert!(retry.encrypted_payload.is_some());
    assert!(retry.next_attempt_at > chrono::Utc::now().to_rfc3339());

    enqueue(
        &pool,
        &user.id,
        &key,
        "verify_contact",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    transport.fail_next(DeliveryFailure {
        category: "smtp_permanent",
        permanent: true,
    });
    runtime().block_on(worker.run_once()).unwrap();
    let failed = pool
        .find_latest_notification_outbox(&user.id, "verify_contact")
        .unwrap()
        .unwrap();
    assert_eq!(failed.state, "failed");
    assert_eq!(failed.last_error.as_deref(), Some("smtp_permanent"));
    assert!(failed.encrypted_payload.is_none());
}

struct NeverDelivery;

impl linkkeys::services::notification::DeliveryChannel for NeverDelivery {
    fn channel(&self) -> &'static str {
        "email"
    }

    fn supports(&self, _purpose: &str) -> bool {
        true
    }

    fn deliver<'a>(
        &'a self,
        _item: &'a linkkeys::db::models::NotificationOutboxItem,
        _secret_payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), DeliveryFailure>> + Send + 'a>> {
        Box::pin(std::future::pending())
    }
}

#[test]
fn worker_times_out_before_its_lease_and_stops_at_max_attempts() {
    let pool = common::create_test_pool();
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let key = [12_u8; 32];
    enqueue(
        &pool,
        &user.id,
        &key,
        "verify_contact",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let worker = OutboxWorker::new(pool.clone(), Arc::new(NeverDelivery), key, 1, 2);

    assert!(runtime().block_on(worker.run_once()).unwrap());
    let failed = pool
        .find_latest_notification_outbox(&user.id, "verify_contact")
        .unwrap()
        .unwrap();
    assert_eq!(failed.state, "failed");
    assert_eq!(failed.last_error.as_deref(), Some("delivery_timeout"));
    assert!(failed.encrypted_payload.is_none());
}

#[test]
fn leases_prevent_two_workers_from_claiming_the_same_item() {
    let pool = common::create_test_pool();
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let key = [9_u8; 32];
    enqueue(
        &pool,
        &user.id,
        &key,
        "verify_contact",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );
    let first = pool
        .claim_notification_outbox("email", "worker-one", 60)
        .unwrap()
        .unwrap();
    assert!(pool
        .claim_notification_outbox("email", "worker-two", 60)
        .unwrap()
        .is_none());
    assert_eq!(
        pool.finish_notification_outbox(
            &first.id,
            "worker-two",
            "pending",
            chrono::Utc::now(),
            Some("retry"),
            false,
        )
        .unwrap(),
        0
    );
    assert_eq!(
        pool.finish_notification_outbox(
            &first.id,
            "worker-one",
            "pending",
            chrono::Utc::now(),
            Some("retry"),
            false,
        )
        .unwrap(),
        1
    );
    let second = pool
        .claim_notification_outbox("email", "worker-two", 60)
        .unwrap()
        .unwrap();
    assert_eq!(second.id, first.id);
    assert_eq!(second.attempt_count, 2);
}

#[test]
fn expiry_redacts_pending_payloads() {
    let pool = common::create_test_pool();
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    let key = [10_u8; 32];
    enqueue(
        &pool,
        &user.id,
        &key,
        "verify_contact",
        chrono::Utc::now() - chrono::Duration::seconds(1),
    );
    assert_eq!(pool.expire_notification_outbox().unwrap(), 1);
    let item = pool
        .find_latest_notification_outbox(&user.id, "verify_contact")
        .unwrap()
        .unwrap();
    assert_eq!(item.state, "expired");
    assert_eq!(item.last_error.as_deref(), Some("expired"));
    assert!(item.encrypted_payload.is_none());
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_workers_claim_one_item_once_across_connections() {
    use diesel::connection::SimpleConnection;
    use diesel::r2d2::{self, ConnectionManager};
    use std::sync::Barrier;

    let path = std::env::temp_dir().join(format!(
        "linkkeys-outbox-concurrency-{}.db",
        uuid::Uuid::now_v7()
    ));
    let manager = ConnectionManager::<diesel::SqliteConnection>::new(path.to_string_lossy());
    let raw_pool = r2d2::Pool::builder()
        .max_size(2)
        .build(manager)
        .expect("SQLite pool");
    {
        let mut first = raw_pool.get().unwrap();
        let mut second = raw_pool.get().unwrap();
        first
            .batch_execute("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .unwrap();
        second.batch_execute("PRAGMA busy_timeout=5000;").unwrap();
        linkkeys::db::migrate_sqlite(&mut first).unwrap();
    }
    let pool = linkkeys::db::DbPool::Sqlite(raw_pool.clone());
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    enqueue(
        &pool,
        &user.id,
        &[11_u8; 32],
        "verify_contact",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );

    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = ["worker-one", "worker-two"]
        .into_iter()
        .map(|worker| {
            let barrier = barrier.clone();
            let pool = pool.clone();
            std::thread::spawn(move || {
                barrier.wait();
                pool.claim_notification_outbox("email", worker, 60)
                    .expect("claim succeeds")
            })
        })
        .collect();
    barrier.wait();
    let claimed = handles
        .into_iter()
        .filter_map(|handle| handle.join().unwrap())
        .count();
    assert_eq!(claimed, 1);

    drop(pool);
    drop(raw_pool);
    std::fs::remove_file(path).expect("remove SQLite test file");
}

#[cfg(feature = "postgres")]
#[test]
fn postgres_workers_claim_one_item_once_across_connections() {
    use diesel::prelude::*;
    use diesel::r2d2::{self, ConnectionManager};
    use std::sync::Barrier;

    if std::env::var("TEST_DATABASE_BACKEND").as_deref() != Ok("postgres") {
        return;
    }
    let base_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://devuser:devpass@localhost/linkkeys_test".to_string());
    let schema = format!("outbox_{}", uuid::Uuid::now_v7().simple());
    let mut administrator = diesel::PgConnection::establish(&base_url).expect("PostgreSQL test DB");
    diesel::sql_query(format!("CREATE SCHEMA {schema}"))
        .execute(&mut administrator)
        .expect("create isolated schema");
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let isolated_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let manager = ConnectionManager::<diesel::PgConnection>::new(&isolated_url);
    let raw_pool = r2d2::Pool::builder()
        .max_size(2)
        .build(manager)
        .expect("PostgreSQL pool");
    linkkeys::db::migrate_pg(&mut raw_pool.get().unwrap()).expect("migrate isolated schema");
    let pool = linkkeys::db::DbPool::Postgres(raw_pool.clone());
    let user = common::data_factory::create_user(&pool, &HashMap::new());
    enqueue(
        &pool,
        &user.id,
        &[13_u8; 32],
        "verify_contact",
        chrono::Utc::now() + chrono::Duration::hours(1),
    );

    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = ["worker-one", "worker-two"]
        .into_iter()
        .map(|worker| {
            let barrier = barrier.clone();
            let pool = pool.clone();
            std::thread::spawn(move || {
                barrier.wait();
                pool.claim_notification_outbox("email", worker, 60)
                    .expect("claim succeeds")
            })
        })
        .collect();
    barrier.wait();
    let claimed = handles
        .into_iter()
        .filter_map(|handle| handle.join().unwrap())
        .count();
    assert_eq!(claimed, 1);

    drop(pool);
    drop(raw_pool);
    diesel::sql_query(format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut administrator)
        .expect("remove isolated schema");
}
