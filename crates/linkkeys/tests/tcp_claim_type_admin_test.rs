//! Tests for the claim-type registry admin surface on the `Admin` TCP
//! service (policy-admin web UI parity): `list-claim-types`,
//! `set-claim-type`, `remove-claim-type`, `set-claim-type-label`,
//! `remove-claim-type-label`.
//!
//! These are a second CSIL-RPC entry point onto the exact same DB calls
//! `web/policy_admin_ui.rs`'s handlers make
//! (`upsert_policy`/`delete_policy`/`upsert_claim_label`/
//! `delete_claim_label`), so an external controller holding an
//! admin-relation API key can manage the registry without the web UI.
//!
//! Every op requires the `admin` relation (explicit `required_relation_for_op`
//! arm, not the `_ =>` fallthrough, mirroring `tcp_local_rp_admin_test.rs`) —
//! each test below confirms a non-admin caller is forbidden before confirming
//! an admin succeeds.

mod common;

use common::data_factory::{
    create_auth_credential, create_claim_policy, create_relation, create_user, DataMap,
};
use liblinkkeys::generated::types::{
    EmptyRequest, RemoveClaimTypeLabelRequest, RemoveClaimTypeRequest, SetClaimTypeLabelRequest,
    SetClaimTypeRequest,
};
use linkkeys::services::auth;
use serde_json::Value;

const TEST_DOMAIN: &str = "test.com";

fn setup() -> linkkeys::db::DbPool {
    std::env::set_var("DOMAIN_NAME", TEST_DOMAIN);
    common::create_test_pool()
}

/// Create a service-account user with an API key, granting `admin` on the
/// domain only when `is_admin` is true. Returns the API key.
fn make_caller(pool: &linkkeys::db::DbPool, is_admin: bool) -> String {
    let user = create_user(pool, &DataMap::new());
    if is_admin {
        create_relation(pool, "user", &user.id, "admin", "domain", TEST_DOMAIN);
    }
    let (api_key, hash) = auth::generate_api_key(&user.id);
    create_auth_credential(pool, &user.id, auth::CREDENTIAL_TYPE_API_KEY, &hash);
    api_key
}

fn set_claim_type_payload(claim_type: &str, label: &str) -> Vec<u8> {
    liblinkkeys::generated::encode_set_claim_type_request(&SetClaimTypeRequest {
        claim_type: claim_type.to_string(),
        label: label.to_string(),
        description: Some("a test claim type".to_string()),
        value_type: "text".to_string(),
        max_bytes: 4096,
        set_rule: "user_self".to_string(),
        signing_rule: "self_signed".to_string(),
        user_settable: true,
        default_auto_sign: false,
        requires_approval: false,
        suggested: true,
    })
}

// ---------------------------------------------------------------------
// list-claim-types
// ---------------------------------------------------------------------

#[test]
fn list_claim_types_requires_admin() {
    let pool = setup();
    create_claim_policy(
        &pool,
        &DataMap::from([("claim_type".into(), Value::String("pronouns".into()))]),
    );
    let payload = liblinkkeys::generated::encode_empty_request(&EmptyRequest {});

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-claim-types",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-claim-types",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_list_claim_types_response(&body)
        .expect("decode ListClaimTypesResponse");
    assert_eq!(resp.claim_types.len(), 1);
    assert_eq!(resp.claim_types[0].claim_type, "pronouns");
}

#[test]
fn list_claim_types_returns_full_registry_fields() {
    let pool = setup();
    create_claim_policy(
        &pool,
        &DataMap::from([
            ("claim_type".into(), Value::String("age_over_21".into())),
            ("label".into(), Value::String("Age over 21".into())),
            ("description".into(), Value::String("attested age".into())),
            ("value_type".into(), Value::String("bool".into())),
            ("max_bytes".into(), Value::from(128)),
            (
                "set_rule".into(),
                Value::String("trusted_issuer_only".into()),
            ),
            ("signing_rule".into(), Value::String("attested".into())),
            ("requires_approval".into(), Value::Bool(true)),
            ("user_settable".into(), Value::Bool(false)),
            ("default_auto_sign".into(), Value::Bool(false)),
            ("suggested".into(), Value::Bool(true)),
        ]),
    );
    let admin_key = make_caller(&pool, true);
    let payload = liblinkkeys::generated::encode_empty_request(&EmptyRequest {});
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-claim-types",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_list_claim_types_response(&body)
        .expect("decode ListClaimTypesResponse");
    let entry = resp
        .claim_types
        .iter()
        .find(|c| c.claim_type == "age_over_21")
        .expect("age_over_21 present");
    assert_eq!(entry.label, "Age over 21");
    assert_eq!(entry.description, "attested age");
    assert_eq!(entry.value_type, "bool");
    assert_eq!(entry.max_bytes, 128);
    assert_eq!(entry.set_rule, "trusted_issuer_only");
    assert_eq!(entry.signing_rule, "attested");
    assert!(entry.requires_approval);
    assert!(!entry.user_settable);
    assert!(!entry.default_auto_sign);
    assert!(entry.suggested);
}

// ---------------------------------------------------------------------
// set-claim-type
// ---------------------------------------------------------------------

#[test]
fn set_claim_type_requires_admin() {
    let pool = setup();
    let payload = set_claim_type_payload("handle", "Handle");

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_set_claim_type_response(&body)
        .expect("decode SetClaimTypeResponse");
    assert_eq!(resp.claim_type.claim_type, "handle");
    assert_eq!(resp.claim_type.label, "Handle");
}

#[test]
fn set_then_list_claim_type_round_trips() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);

    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type",
        set_claim_type_payload("display_name", "Display name"),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-claim-types",
        liblinkkeys::generated::encode_empty_request(&EmptyRequest {}),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_list_claim_types_response(&body)
        .expect("decode ListClaimTypesResponse");
    let entry = resp
        .claim_types
        .iter()
        .find(|c| c.claim_type == "display_name")
        .expect("display_name present after set");
    assert_eq!(entry.label, "Display name");
    assert_eq!(entry.description, "a test claim type");
    assert_eq!(entry.value_type, "text");
    assert_eq!(entry.max_bytes, 4096);
    assert_eq!(entry.set_rule, "user_self");
    assert_eq!(entry.signing_rule, "self_signed");
    assert!(entry.user_settable);
    assert!(entry.suggested);
}

/// `set-claim-type` is an upsert keyed on `claim_type`: setting the same id
/// twice with a different label must update the one row, not create a
/// second.
#[test]
fn set_claim_type_upserts_existing() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);

    for (status_i, label) in ["First label", "Second label"].into_iter().enumerate() {
        let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
            "Admin",
            "set-claim-type",
            set_claim_type_payload("nickname", label),
            Some(&admin_key),
            &pool,
            None,
        );
        assert_eq!(status, 0, "set #{} must succeed", status_i);
    }

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-claim-types",
        liblinkkeys::generated::encode_empty_request(&EmptyRequest {}),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_list_claim_types_response(&body)
        .expect("decode ListClaimTypesResponse");
    let matches: Vec<_> = resp
        .claim_types
        .iter()
        .filter(|c| c.claim_type == "nickname")
        .collect();
    assert_eq!(matches.len(), 1, "upsert must not create a duplicate row");
    assert_eq!(matches[0].label, "Second label");
}

#[test]
fn set_claim_type_rejects_invalid_value_type() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);
    let mut req = SetClaimTypeRequest {
        claim_type: "bad".to_string(),
        label: "Bad".to_string(),
        description: None,
        value_type: "not-a-real-type".to_string(),
        max_bytes: 100,
        set_rule: "user_self".to_string(),
        signing_rule: "self_signed".to_string(),
        user_settable: true,
        default_auto_sign: false,
        requires_approval: false,
        suggested: false,
    };
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type",
        liblinkkeys::generated::encode_set_claim_type_request(&req),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "an invalid value_type must be rejected");

    req.value_type = "text".to_string();
    req.set_rule = "not-a-real-rule".to_string();
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type",
        liblinkkeys::generated::encode_set_claim_type_request(&req),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "an invalid set_rule must be rejected");

    req.set_rule = "user_self".to_string();
    req.signing_rule = "not-a-real-signing-rule".to_string();
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type",
        liblinkkeys::generated::encode_set_claim_type_request(&req),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "an invalid signing_rule must be rejected");

    req.signing_rule = "self_signed".to_string();
    req.max_bytes = 0;
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type",
        liblinkkeys::generated::encode_set_claim_type_request(&req),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a non-positive max_bytes must be rejected");

    // None of the rejected writes may have created the row.
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "list-claim-types",
        liblinkkeys::generated::encode_empty_request(&EmptyRequest {}),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    let resp = liblinkkeys::generated::decode_list_claim_types_response(&body)
        .expect("decode ListClaimTypesResponse");
    assert!(
        resp.claim_types.iter().all(|c| c.claim_type != "bad"),
        "rejected set-claim-type calls must not persist anything"
    );
}

// ---------------------------------------------------------------------
// remove-claim-type
// ---------------------------------------------------------------------

#[test]
fn remove_claim_type_requires_admin_and_deletes() {
    let pool = setup();
    create_claim_policy(
        &pool,
        &DataMap::from([("claim_type".into(), Value::String("temp_claim".into()))]),
    );
    let payload =
        liblinkkeys::generated::encode_remove_claim_type_request(&RemoveClaimTypeRequest {
            claim_type: "temp_claim".to_string(),
        });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "remove-claim-type",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert!(
        pool.find_claim_policy("temp_claim").unwrap().is_some(),
        "forbidden call must not have deleted anything"
    );

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "remove-claim-type",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_remove_claim_type_response(&body)
        .expect("decode RemoveClaimTypeResponse");
    assert!(resp.success);
    assert!(
        pool.find_claim_policy("temp_claim").unwrap().is_none(),
        "the claim type must be gone"
    );
}

// ---------------------------------------------------------------------
// set-claim-type-label
// ---------------------------------------------------------------------

#[test]
fn set_claim_type_label_requires_admin_and_is_visible_via_db() {
    let pool = setup();
    create_claim_policy(
        &pool,
        &DataMap::from([("claim_type".into(), Value::String("pronouns".into()))]),
    );
    let payload =
        liblinkkeys::generated::encode_set_claim_type_label_request(&SetClaimTypeLabelRequest {
            claim_type: "pronouns".to_string(),
            locale: "es-ES".to_string(),
            label: "Pronombres".to_string(),
            description: Some("pronombres preferidos".to_string()),
        });

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type-label",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert!(
        pool.find_claim_label_i18n("pronouns", "es-ES")
            .unwrap()
            .is_none(),
        "forbidden call must not have written anything"
    );

    let admin_key = make_caller(&pool, true);
    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type-label",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_set_claim_type_label_response(&body)
        .expect("decode SetClaimTypeLabelResponse");
    assert_eq!(resp.label.claim_type, "pronouns");
    assert_eq!(resp.label.locale, "es-ES");
    assert_eq!(resp.label.label, "Pronombres");
    assert_eq!(
        resp.label.description.as_deref(),
        Some("pronombres preferidos")
    );

    // The translation set over CSIL-RPC must show up through the exact same
    // read path `render_policy_admin`'s translations table uses.
    let stored = pool
        .list_claim_labels_i18n("pronouns")
        .expect("list claim labels");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].locale, "es-ES");
    assert_eq!(stored[0].label, "Pronombres");
    assert_eq!(
        stored[0].description.as_deref(),
        Some("pronombres preferidos")
    );
}

#[test]
fn set_claim_type_label_unknown_claim_type_errors() {
    let pool = setup();
    let admin_key = make_caller(&pool, true);
    let payload =
        liblinkkeys::generated::encode_set_claim_type_label_request(&SetClaimTypeLabelRequest {
            claim_type: "does-not-exist".to_string(),
            locale: "es-ES".to_string(),
            label: "No existe".to_string(),
            description: None,
        });
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type-label",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_ne!(
        status, 0,
        "a translation for an unregistered claim type must be rejected"
    );
}

// ---------------------------------------------------------------------
// remove-claim-type-label
// ---------------------------------------------------------------------

#[test]
fn remove_claim_type_label_requires_admin_and_deletes() {
    let pool = setup();
    create_claim_policy(
        &pool,
        &DataMap::from([("claim_type".into(), Value::String("handle".into()))]),
    );
    let admin_key = make_caller(&pool, true);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "set-claim-type-label",
        liblinkkeys::generated::encode_set_claim_type_label_request(&SetClaimTypeLabelRequest {
            claim_type: "handle".to_string(),
            locale: "pt-BR".to_string(),
            label: "Identificador".to_string(),
            description: None,
        }),
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0);
    assert!(
        pool.find_claim_label_i18n("handle", "pt-BR")
            .unwrap()
            .is_some(),
        "translation exists before remove"
    );

    let payload = liblinkkeys::generated::encode_remove_claim_type_label_request(
        &RemoveClaimTypeLabelRequest {
            claim_type: "handle".to_string(),
            locale: "pt-BR".to_string(),
        },
    );

    let nonadmin_key = make_caller(&pool, false);
    let (status, _) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "remove-claim-type-label",
        payload.clone(),
        Some(&nonadmin_key),
        &pool,
        None,
    );
    assert_ne!(status, 0, "a caller without admin must be forbidden");
    assert!(
        pool.find_claim_label_i18n("handle", "pt-BR")
            .unwrap()
            .is_some(),
        "forbidden call must not have deleted anything"
    );

    let (status, body) = linkkeys::tcp::dispatch_for_test_authed(
        "Admin",
        "remove-claim-type-label",
        payload,
        Some(&admin_key),
        &pool,
        None,
    );
    assert_eq!(status, 0, "an admin caller must succeed");
    let resp = liblinkkeys::generated::decode_remove_claim_type_label_response(&body)
        .expect("decode RemoveClaimTypeLabelResponse");
    assert!(resp.success);
    assert!(
        pool.find_claim_label_i18n("handle", "pt-BR")
            .unwrap()
            .is_none(),
        "the translation must be gone"
    );
}
