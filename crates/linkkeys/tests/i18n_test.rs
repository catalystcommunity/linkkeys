//! End-to-end test of the unauthenticated `I18n` CSIL service through the
//! `dispatch_for_test` seam (the same entry point the TCP server and the
//! browser `POST /csil/v1/rpc` route share). Covers: locale negotiation,
//! per-key fallback to en-US, and the merge of this domain's per-locale claim
//! labels (Part C) into the served catalog.

mod common;

use common::create_test_pool;
use liblinkkeys::generated::types::{
    ListLocalesResponse, TranslationsRequest, TranslationsResponse,
};

fn get_translations(
    pool: &linkkeys::db::DbPool,
    locale: Option<&str>,
    accept_language: Option<&str>,
) -> (i32, Option<TranslationsResponse>) {
    let payload = liblinkkeys::generated::encode_translations_request(&TranslationsRequest {
        locale: locale.map(str::to_string),
        accept_language: accept_language.map(str::to_string),
    });
    let (status, body) =
        linkkeys::tcp::dispatch_for_test("I18n", "get-translations", payload, pool, None);
    let resp = if status == 0 {
        Some(liblinkkeys::generated::decode_translations_response(&body).expect("decode"))
    } else {
        None
    };
    (status, resp)
}

fn list_locales(pool: &linkkeys::db::DbPool) -> ListLocalesResponse {
    let payload = liblinkkeys::generated::encode_empty_request(
        &liblinkkeys::generated::types::EmptyRequest {},
    );
    let (status, body) =
        linkkeys::tcp::dispatch_for_test("I18n", "list-locales", payload, pool, None);
    assert_eq!(status, 0, "list-locales should succeed unauthenticated");
    liblinkkeys::generated::decode_list_locales_response(&body).expect("decode")
}

#[test]
fn list_locales_returns_shipped_catalogs() {
    let pool = create_test_pool();
    let resp = list_locales(&pool);
    assert!(resp.available_locales.contains(&"en-US".to_string()));
    assert!(resp.available_locales.contains(&"en-XA".to_string()));
}

#[test]
fn get_translations_defaults_to_en_us() {
    let pool = create_test_pool();
    let (status, resp) = get_translations(&pool, None, None);
    assert_eq!(status, 0);
    let resp = resp.unwrap();
    assert_eq!(resp.locale, "en-US");
    assert_eq!(
        resp.messages.get("consent.cancel").map(String::as_str),
        Some("Cancel")
    );
}

#[test]
fn get_translations_negotiates_via_accept_language() {
    let pool = create_test_pool();
    let (status, resp) = get_translations(&pool, None, Some("fr-FR;q=0.9, en-XA;q=0.8"));
    assert_eq!(status, 0);
    let resp = resp.unwrap();
    assert_eq!(resp.locale, "en-XA");
    // en-XA mangles this key...
    assert_eq!(
        resp.messages.get("consent.cancel").map(String::as_str),
        Some("[Ĉåñĉéĺ]")
    );
    // ...but doesn't define this one, so it still falls back to en-US, never
    // missing entirely.
    assert_eq!(
        resp.messages.get("account.title").map(String::as_str),
        Some("Account Dashboard")
    );
}

#[test]
fn get_translations_explicit_locale_overrides_accept_language() {
    let pool = create_test_pool();
    let (_, resp) = get_translations(&pool, Some("en-XA"), Some("fr-FR"));
    assert_eq!(resp.unwrap().locale, "en-XA");
}

#[test]
fn get_translations_merges_builtin_claim_labels_for_registered_types() {
    std::env::set_var("DOMAIN_NAME", "i18n-test.example");
    let pool = create_test_pool();
    pool.seed_default_policies().expect("seed policies");

    let (_, resp) = get_translations(&pool, Some("en-US"), None);
    let messages = resp.unwrap().messages;
    assert_eq!(
        messages.get("claim.display_name.label").map(String::as_str),
        Some("Display name")
    );
    assert_eq!(
        messages.get("claim.email.label").map(String::as_str),
        Some("Email address")
    );
}

#[test]
fn get_translations_merges_operator_per_locale_label_override() {
    std::env::set_var("DOMAIN_NAME", "i18n-test.example");
    let pool = create_test_pool();
    pool.seed_default_policies().expect("seed policies");

    // Operator supplies a custom en-XA label for display_name, overriding both
    // the DB base label and the built-in liblinkkeys catalog.
    pool.upsert_claim_label_i18n(linkkeys::db::models::ClaimLabelI18n {
        claim_type: "display_name".to_string(),
        locale: "en-XA".to_string(),
        label: "Operator Custom Label".to_string(),
        description: Some("Operator custom description".to_string()),
    })
    .expect("upsert claim label");

    let (_, resp) = get_translations(&pool, Some("en-XA"), None);
    let messages = resp.unwrap().messages;
    assert_eq!(
        messages.get("claim.display_name.label").map(String::as_str),
        Some("Operator Custom Label")
    );
    assert_eq!(
        messages
            .get("claim.display_name.description")
            .map(String::as_str),
        Some("Operator custom description")
    );

    // A type with no operator override still resolves through the built-in
    // catalog for the requested locale, not silently dropped.
    assert!(messages.contains_key("claim.email.label"));
}

#[test]
fn resolved_label_falls_back_from_db_to_builtin_to_base_policy() {
    std::env::set_var("DOMAIN_NAME", "i18n-test.example");
    let pool = create_test_pool();
    pool.seed_default_policies().expect("seed policies");

    // No per-locale override yet: falls back to the built-in liblinkkeys
    // catalog entry for display_name.
    let (label, _desc) = pool.resolved_label("display_name", "en-US").unwrap();
    assert_eq!(label, "Display name");

    // A claim type registered by the operator with no built-in catalog entry
    // falls all the way back to the base ClaimTypePolicy.label.
    let custom = linkkeys::db::models::ClaimTypePolicy {
        claim_type: "shoe_size".to_string(),
        label: "Shoe size".to_string(),
        description: "How big your feet are.".to_string(),
        value_type: "text".to_string(),
        max_bytes: 100,
        set_rule: "user_self".to_string(),
        signing_rule: "self_signed".to_string(),
        requires_approval: false,
        user_settable: true,
        default_auto_sign: true,
        suggested: false,
    };
    pool.upsert_claim_policy(custom).unwrap();
    let (label, desc) = pool.resolved_label("shoe_size", "en-US").unwrap();
    assert_eq!(label, "Shoe size");
    assert_eq!(desc, "How big your feet are.");
}
