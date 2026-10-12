//! The domain sign-in length (`Admin/get-sign-in-policy`,
//! `Admin/set-sign-in-policy`): admin-only, defaults to 12 hours, rejects
//! out-of-range values, and sets the expiry of sign-ins made after a change.

mod common;

use common::data_factory::{create_auth_credential, create_relation, create_user, DataMap};
use liblinkkeys::generated::types::{EmptyRequest, SetSignInPolicyRequest, SignInPolicy};
use linkkeys::services::auth::{self, AuthenticationEvidence};
use linkkeys::services::browser_session;

const TEST_DOMAIN: &str = "test.com";

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    common::create_test_pool()
}

fn make_caller(pool: &linkkeys::db::DbPool, is_admin: bool) -> String {
    let user = create_user(pool, &DataMap::new());
    if is_admin {
        create_relation(pool, "user", &user.id, "admin", "domain", TEST_DOMAIN);
    }
    let (api_key, hash) = auth::generate_api_key(&user.id);
    create_auth_credential(pool, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    api_key
}

fn call(
    pool: &linkkeys::db::DbPool,
    key: &str,
    op: &str,
    payload: Vec<u8>,
) -> (i32, Option<SignInPolicy>) {
    let (status, body) =
        linkkeys::tcp::dispatch_for_test_authed("Admin", op, payload, Some(key), pool, None);
    let policy = (status == 0).then(|| {
        liblinkkeys::generated::decode_sign_in_policy(&body).expect("decode SignInPolicy")
    });
    (status, policy)
}

fn get_payload() -> Vec<u8> {
    liblinkkeys::generated::encode_empty_request(&EmptyRequest {})
}

fn set_payload(hours: i64) -> Vec<u8> {
    liblinkkeys::generated::encode_set_sign_in_policy_request(&SetSignInPolicyRequest {
        sign_in_hours: hours,
    })
}

fn new_session_hours(pool: &linkkeys::db::DbPool) -> i64 {
    let user = create_user(pool, &DataMap::new());
    let evidence = AuthenticationEvidence {
        method_types: ["password".to_string()].into_iter().collect(),
        authenticated_at: chrono::Utc::now(),
    };
    let (_, session) = browser_session::create(pool, &user.id, &evidence).expect("session");
    let issued = chrono::DateTime::parse_from_rfc3339(&session.issued_at).unwrap();
    let expires = chrono::DateTime::parse_from_rfc3339(&session.expires_at).unwrap();
    // Round to whole hours: storage can drop sub-second precision.
    ((expires - issued).num_seconds() + 1_800) / 3_600
}

#[test]
fn sign_in_policy_requires_admin() {
    let pool = setup();
    let nonadmin = make_caller(&pool, false);
    assert_ne!(
        call(&pool, &nonadmin, "get-sign-in-policy", get_payload()).0,
        0
    );
    assert_ne!(
        call(&pool, &nonadmin, "set-sign-in-policy", set_payload(24)).0,
        0
    );
    assert_eq!(
        browser_session::sign_in_hours(&pool).unwrap(),
        browser_session::DEFAULT_SIGN_IN_HOURS,
        "a refused change must not be stored"
    );
}

#[test]
fn sign_in_policy_defaults_to_twelve_hours() {
    let pool = setup();
    let admin = make_caller(&pool, true);
    let (status, policy) = call(&pool, &admin, "get-sign-in-policy", get_payload());
    assert_eq!(status, 0);
    let policy = policy.unwrap();
    assert_eq!(policy.sign_in_hours, 12);
    assert_eq!(policy.default_sign_in_hours, 12);
    assert_eq!(policy.min_sign_in_hours, 1);
    assert_eq!(policy.max_sign_in_hours, 720);
    assert_eq!(new_session_hours(&pool), 12);
}

#[test]
fn a_changed_sign_in_length_applies_to_new_sign_ins() {
    let pool = setup();
    let admin = make_caller(&pool, true);
    let (status, policy) = call(&pool, &admin, "set-sign-in-policy", set_payload(48));
    assert_eq!(status, 0);
    assert_eq!(policy.unwrap().sign_in_hours, 48);
    let (_, policy) = call(&pool, &admin, "get-sign-in-policy", get_payload());
    assert_eq!(policy.unwrap().sign_in_hours, 48);
    assert_eq!(new_session_hours(&pool), 48);
}

#[test]
fn sign_in_policy_rejects_out_of_range_hours() {
    let pool = setup();
    let admin = make_caller(&pool, true);
    for hours in [0, -1, 721, i64::from(i32::MAX) + 1] {
        assert_ne!(
            call(&pool, &admin, "set-sign-in-policy", set_payload(hours)).0,
            0,
            "{hours} hours must be refused"
        );
    }
    assert_eq!(browser_session::sign_in_hours(&pool).unwrap(), 12);
}
