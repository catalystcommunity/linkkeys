//! `AdminUser`'s generated CBOR codec must stay forward- and
//! backward-compatible across the `? purged_at` / `? purge_reason` fields
//! added for purged-user visibility (list-users / get-user-claims work):
//!
//! - A server that has not been upgraded yet omits `purged_at` and
//!   `purge_reason` entirely. A client built against the newer CSIL must
//!   still decode that payload (optional fields become `None`).
//! - A server newer than this client may add a field this client's CSIL
//!   subset does not know about yet. Decoding must ignore it rather than
//!   fail, so a client copy that lags upstream by a field or two keeps
//!   working.
//!
//! CSIL decode looks fields up by name (`cbor_map_get`) instead of
//! positionally, so both cases are exercised directly against hand-built
//! CBOR maps rather than through `encode_admin_user`, which never omits an
//! optional field's key when the value is `Some` and never emits a key the
//! type doesn't declare.

use ciborium::Value;
use liblinkkeys::generated::{self, types::AdminUser};

fn encode_map(entries: Vec<(&str, Value)>) -> Vec<u8> {
    let map = Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Text(k.to_string()), v))
            .collect(),
    );
    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).expect("encode CBOR map");
    buf
}

fn required_fields(id: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("id", Value::Text(id.to_string())),
        ("username", Value::Text("alice".to_string())),
        ("display_name", Value::Text("Alice".to_string())),
        ("is_active", Value::Bool(true)),
        (
            "created_at",
            Value::Text("2026-01-01T00:00:00Z".to_string()),
        ),
        (
            "updated_at",
            Value::Text("2026-01-01T00:00:00Z".to_string()),
        ),
    ]
}

#[test]
fn decode_admin_user_tolerates_missing_optional_purge_fields() {
    // Simulates a server on a linkkeys build before purged_at/purge_reason
    // existed: the map has none of the two optional keys at all.
    let bytes = encode_map(required_fields("user-1"));

    let user: AdminUser = generated::decode_admin_user(&bytes)
        .expect("decode must tolerate a payload with no purge fields");

    assert_eq!(user.id, "user-1");
    assert_eq!(user.username, "alice");
    assert!(user.purged_at.is_none());
    assert!(user.purge_reason.is_none());
}

#[test]
fn decode_admin_user_ignores_an_unknown_extra_key() {
    // Simulates a server newer than this client's CSIL subset: an extra key
    // ("future_field") this client's AdminUser type does not declare.
    let mut fields = required_fields("user-2");
    fields.push(("purged_at", Value::Text("2026-02-01T00:00:00Z".to_string())));
    fields.push(("purge_reason", Value::Text("policy violation".to_string())));
    fields.push(("future_field", Value::Text("unexpected".to_string())));
    let bytes = encode_map(fields);

    let user: AdminUser = generated::decode_admin_user(&bytes)
        .expect("decode must ignore an unrecognized extra key rather than fail");

    assert_eq!(user.id, "user-2");
    assert_eq!(user.purged_at.as_deref(), Some("2026-02-01T00:00:00Z"));
    assert_eq!(user.purge_reason.as_deref(), Some("policy violation"));
}

#[test]
fn decode_admin_user_round_trips_through_encode() {
    // Sanity check that the codec's own encoder/decoder pair still agrees
    // with itself for both the with- and without-purge-fields shapes.
    let with_purge = AdminUser {
        id: "user-3".to_string(),
        username: "bob".to_string(),
        display_name: "Bob".to_string(),
        is_active: false,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-02T00:00:00Z".to_string(),
        purged_at: Some("2026-01-02T00:00:00Z".to_string()),
        purge_reason: Some("requested".to_string()),
    };
    let encoded = generated::encode_admin_user(&with_purge);
    let decoded = generated::decode_admin_user(&encoded).expect("round-trip decode");
    assert_eq!(decoded.purged_at, with_purge.purged_at);
    assert_eq!(decoded.purge_reason, with_purge.purge_reason);

    let without_purge = AdminUser {
        purged_at: None,
        purge_reason: None,
        ..with_purge
    };
    let encoded = generated::encode_admin_user(&without_purge);
    let decoded = generated::decode_admin_user(&encoded).expect("round-trip decode");
    assert!(decoded.purged_at.is_none());
    assert!(decoded.purge_reason.is_none());
}
