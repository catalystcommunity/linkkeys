//! Admin policy previews (`preview-release-policy`, `preview-issuer-policy`):
//! read-only, `manage_claims` only, and they never change stored policy.

mod common;

use common::data_factory::{create_auth_credential, create_relation, create_user, DataMap};
use liblinkkeys::generated::types::{PreviewIssuerPolicyRequest, PreviewReleasePolicyRequest};
use linkkeys::services::auth;

const TEST_DOMAIN: &str = "test.com";

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    common::create_test_pool()
}

fn make_caller(pool: &linkkeys::db::DbPool, relation: Option<&str>) -> String {
    let user = create_user(pool, &DataMap::new());
    if let Some(relation) = relation {
        create_relation(pool, "user", &user.id, relation, "domain", TEST_DOMAIN);
    }
    let (api_key, hash) = auth::generate_api_key(&user.id);
    create_auth_credential(pool, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    api_key
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

fn release_request(temp: Option<(&str, &str, &str)>) -> Vec<u8> {
    liblinkkeys::generated::encode_preview_release_policy_request(&PreviewReleasePolicyRequest {
        audience: "app.example".to_string(),
        required_claims: strings(&["email"]),
        optional_claims: strings(&["over_21", "ssn"]),
        available_claims: strings(&["email", "ssn"]),
        user_choices: strings(&["email", "ssn"]),
        temp_audience: temp.map(|t| t.0.to_string()),
        temp_claim_type: temp.map(|t| t.1.to_string()),
        temp_disposition: temp.map(|t| t.2.to_string()),
    })
}

#[test]
fn release_preview_applies_stored_and_temporary_rules_without_storing() {
    let pool = setup();
    pool.upsert_release_policy("app.example", "ssn", "forced_deny")
        .unwrap();
    let nobody = make_caller(&pool, None);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "preview-release-policy",
        release_request(None),
        Some(&nobody),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without manage_claims is refused");

    let operator = make_caller(&pool, Some("manage_claims"));
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "preview-release-policy",
        release_request(Some(("*", "email", "forced_allow"))),
        Some(&operator),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let preview = liblinkkeys::generated::decode_preview_release_policy_response(&body).unwrap();
    assert_eq!(preview.forced_deny, strings(&["ssn"]));
    assert_eq!(preview.forced_allow, strings(&["email"]));
    assert!(preview.authorized_claims.contains(&"email".to_string()));
    assert!(
        !preview.authorized_claims.contains(&"ssn".to_string()),
        "a forced deny wins over the user's choice"
    );
    let row = |ct: &str| preview.rows.iter().find(|r| r.claim_type == ct).unwrap();
    assert_eq!(row("ssn").policy, "forced_deny");
    assert!(row("ssn").locked);
    assert!(!row("over_21").available);
    assert_eq!(row("email").policy, "forced_allow");

    let stored = pool
        .list_release_policies_for_audience("app.example")
        .unwrap();
    assert!(
        !stored.iter().any(|r| r.claim_type == "email"),
        "the temporary rule is never stored"
    );

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "preview-release-policy",
        release_request(Some(("*", "email", "sometimes"))),
        Some(&operator),
        &pool,
        None,
    );
    assert_ne!(status, 0, "an unknown temporary disposition is refused");
}

#[test]
fn issuer_preview_reports_the_domain_decision_and_issue_rights() {
    let pool = setup();
    let operator = make_caller(&pool, Some("manage_claims"));
    let request = |subject_domain: &str| {
        liblinkkeys::generated::encode_preview_issuer_policy_request(&PreviewIssuerPolicyRequest {
            subject_domain: subject_domain.to_string(),
            denied_domains: Some(strings(&["blocked.example"])),
            denied_tlds: Some(strings(&["invalid"])),
            issuer_user_id: Some("no-such-user".to_string()),
            claim_type: Some("over_21".to_string()),
        })
    };
    for (domain, allowed) in [
        ("fine.example", true),
        ("blocked.example", false),
        ("x.invalid", false),
    ] {
        let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
            "Admin",
            "preview-issuer-policy",
            request(domain),
            Some(&operator),
            &pool,
            None,
        );
        assert_eq!(status, 0);
        let preview = liblinkkeys::generated::decode_preview_issuer_policy_response(&body).unwrap();
        assert_eq!(preview.allowed, allowed, "{domain}");
        assert_eq!(preview.user_can_issue, Some(false));
        assert!(preview.attested_claim_ttl_seconds > 0);
    }
}
