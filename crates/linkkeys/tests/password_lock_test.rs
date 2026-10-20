//! Admin password lock: a locked account cannot change its own password or use
//! password recovery. An admin can still reset it, and the lock shows on the
//! account record.

mod common;

use common::data_factory::{create_auth_credential, create_relation, create_user, DataMap};
use liblinkkeys::generated::types::{
    ChangePasswordRequest, GetUserRequest, ResetPasswordRequest, SetUserPasswordLockRequest,
};
use linkkeys::db::DbPool;
use linkkeys::services::auth::Authenticator;
use linkkeys::services::{account, admin, auth, recovery};

const TEST_DOMAIN: &str = "passwordlock.test";
const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a different long password";

/// Password hashing has a bounded worker pool per process. These tests hash
/// several times each, so they run one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn setup() -> DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    std::env::set_var("ENABLE_PASSWORD_AUTH", "true");
    common::create_test_pool()
}

fn user_with_password(pool: &DbPool) -> linkkeys::db::models::User {
    let user = create_user(pool, &DataMap::new());
    let hash = linkkeys::services::password::hash_for_storage(PASSWORD).unwrap();
    create_auth_credential(pool, &user.id, "password", &hash);
    user
}

/// Give the user a verified email contact that can authorize recovery.
fn verified_contact(pool: &DbPool, user_id: &str, destination: &str) {
    let challenge = pool
        .create_account_challenge_and_outbox(
            user_id,
            "verify_contact",
            "email",
            destination,
            &linkkeys::services::verification::token_digest(&format!("verify-{destination}")),
            vec![1],
            chrono::Utc::now() + chrono::Duration::hours(1),
            None,
        )
        .expect("contact challenge");
    pool.confirm_contact_challenge(&challenge.id, &[])
        .expect("confirm contact");
}

fn lock(pool: &DbPool, user_id: &str, locked: bool) -> liblinkkeys::generated::types::AdminUser {
    admin::set_user_password_lock(
        pool,
        SetUserPasswordLockRequest {
            user_id: user_id.to_string(),
            locked,
        },
    )
    .expect("set lock")
    .user
}

fn password_works(pool: &DbPool, username: &str, password: &str) -> bool {
    auth::PasswordAuthenticator::new(pool.clone())
        .authenticate_with_evidence(username, password)
        .is_ok()
}

#[test]
fn lock_shows_on_the_account_record_only_while_set() {
    let _serial = serial();
    let pool = setup();
    let user = user_with_password(&pool);
    let get = || {
        admin::get_user(
            &pool,
            GetUserRequest {
                user_id: user.id.clone(),
            },
        )
        .unwrap()
        .user
    };
    assert_eq!(
        get().password_locked,
        None,
        "absent, not false, when unlocked"
    );
    assert_eq!(lock(&pool, &user.id, true).password_locked, Some(true));
    assert_eq!(get().password_locked, Some(true));
    assert_eq!(lock(&pool, &user.id, false).password_locked, None);
}

#[test]
fn locked_account_cannot_change_its_password() {
    let _serial = serial();
    let pool = setup();
    let user = user_with_password(&pool);
    lock(&pool, &user.id, true);
    let change = || {
        account::change_password(
            &pool,
            &user.id,
            ChangePasswordRequest {
                current_password: PASSWORD.to_string(),
                new_password: NEW_PASSWORD.to_string(),
            },
        )
    };
    assert_eq!(change().unwrap_err().code, 403);
    assert!(password_works(&pool, &user.username, PASSWORD));

    lock(&pool, &user.id, false);
    change().expect("an unlocked account can change its password");
    assert!(password_works(&pool, &user.username, NEW_PASSWORD));
}

#[test]
fn admin_reset_still_works_on_a_locked_account() {
    let _serial = serial();
    let pool = setup();
    let user = user_with_password(&pool);
    lock(&pool, &user.id, true);
    admin::reset_password(
        &pool,
        ResetPasswordRequest {
            user_id: user.id.clone(),
            new_password: NEW_PASSWORD.to_string(),
        },
    )
    .expect("admin reset");
    assert!(password_works(&pool, &user.username, NEW_PASSWORD));
}

#[test]
fn locked_account_cannot_complete_a_recovery_link() {
    let _serial = serial();
    let pool = setup();
    let user = user_with_password(&pool);
    verified_contact(&pool, &user.id, "person@passwordlock.test");
    let token = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    pool.create_account_challenge_and_outbox(
        &user.id,
        "reset_password",
        "email",
        "person@passwordlock.test",
        &linkkeys::services::verification::token_digest(token),
        vec![1, 2, 3],
        chrono::Utc::now() + chrono::Duration::hours(1),
        None,
    )
    .expect("recovery challenge");

    lock(&pool, &user.id, true);
    assert_eq!(recovery::validate(&pool, token).unwrap_err().code, 403);
    assert_eq!(
        recovery::complete(&pool, token, NEW_PASSWORD)
            .unwrap_err()
            .code,
        403
    );
    assert!(password_works(&pool, &user.username, PASSWORD));

    lock(&pool, &user.id, false);
    recovery::validate(&pool, token).expect("an unlocked account can use the link");
    recovery::complete(&pool, token, NEW_PASSWORD).expect("recovery completes");
    assert!(password_works(&pool, &user.username, NEW_PASSWORD));
}

#[test]
fn locked_account_gets_no_recovery_email() {
    let _serial = serial();
    let pool = setup();
    std::env::set_var("SMTP_HOST", "smtp.example.test");
    std::env::set_var("SMTP_FROM", "noreply@example.test");
    std::env::set_var("PUBLIC_ORIGIN", "https://localhost:8443");
    std::env::set_var("OUTBOX_ENCRYPTION_KEY", "00".repeat(32));
    common::data_factory::create_domain_key(&pool);
    let user = user_with_password(&pool);
    verified_contact(&pool, &user.id, "locked@contact.example");
    let _email_worker = linkkeys::services::notification::start_worker(
        pool.clone(),
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )
    .expect("start email worker")
    .expect("email worker is configured");

    lock(&pool, &user.id, true);
    recovery::request(&pool, "locked@contact.example", "password-lock-source-1")
        .expect("generic response");
    assert!(
        pool.find_latest_notification_outbox(&user.id, "reset_password")
            .unwrap()
            .is_none(),
        "a locked account gets no recovery email"
    );

    lock(&pool, &user.id, false);
    recovery::request(&pool, "locked@contact.example", "password-lock-source-2")
        .expect("generic response");
    assert!(
        pool.find_latest_notification_outbox(&user.id, "reset_password")
            .unwrap()
            .is_some(),
        "an unlocked account gets the recovery email"
    );
}

#[test]
fn set_password_lock_requires_admin() {
    let _serial = serial();
    let pool = setup();
    let target = user_with_password(&pool);
    let make_caller = |relation: &str| {
        let caller = create_user(&pool, &DataMap::new());
        create_relation(&pool, "user", &caller.id, relation, "domain", TEST_DOMAIN);
        let (api_key, hash) = auth::generate_api_key(&caller.id);
        create_auth_credential(&pool, &caller.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
        api_key
    };
    let payload = liblinkkeys::generated::encode_set_user_password_lock_request(
        &SetUserPasswordLockRequest {
            user_id: target.id.clone(),
            locked: true,
        },
    );
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-user-password-lock",
        payload.clone(),
        Some(&make_caller("manage_users")),
        &pool,
        None,
    );
    assert_ne!(status, 0, "manage_users is not enough");
    assert!(!pool.find_user_by_id(&target.id).unwrap().password_locked);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-user-password-lock",
        payload,
        Some(&make_caller("admin")),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_set_user_password_lock_response(&body).unwrap();
    assert_eq!(resp.user.password_locked, Some(true));
    assert!(pool.find_user_by_id(&target.id).unwrap().password_locked);
}
