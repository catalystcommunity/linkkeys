//! Regression test for the optional-bytes deserialization bug that broke RP
//! key fetching (IDP `/auth/authorize`) and assertion verification.
//!
//! `DomainPublicKey.key_signature` is an optional `bytes` field (present only on
//! encryption keys). The generated struct annotates it
//! `#[serde(with = "serde_bytes")]`, which disables serde's automatic
//! "missing Option -> None" — so without an accompanying `#[serde(default)]`,
//! ANY keys response containing a signing key (i.e. every real response) fails
//! to deserialize on the consuming side with `missing field key_signature`.
//!
//! This test deserializes a response in the exact shape a server serves — a
//! signing key with no `key_signature`, plus an encryption key that has one —
//! via `serde_json` (the path `fetch_domain_keys` uses). It fails if the
//! `default` is ever lost (e.g. a clean `csilgen generate` before the generator
//! is fixed per docs/csilgen-requests/2026-06-02-optional-bytes-needs-serde-default.md).

use liblinkkeys::generated::types::GetDomainKeysResponse;

#[test]
fn domain_keys_response_with_signing_key_deserializes() {
    let json = r#"{
        "domain": "example.com",
        "keys": [
            {
                "key_id": "sign-1",
                "public_key": [1, 2, 3],
                "fingerprint": "aa",
                "algorithm": "ed25519",
                "key_usage": "sign",
                "created_at": "2026-01-01 00:00:00",
                "expires_at": "2030-01-01T00:00:00+00:00"
            },
            {
                "key_id": "enc-1",
                "public_key": [4, 5, 6],
                "fingerprint": "bb",
                "algorithm": "x25519",
                "key_usage": "encrypt",
                "created_at": "2026-01-01 00:00:00",
                "expires_at": "2030-01-01T00:00:00+00:00",
                "signed_by_key_id": "sign-1",
                "key_signature": [7, 8, 9]
            }
        ]
    }"#;

    let resp: GetDomainKeysResponse =
        serde_json::from_str(json).expect("a response containing a signing key must deserialize");
    assert_eq!(resp.keys.len(), 2);

    let sign = resp.keys.iter().find(|k| k.key_usage == "sign").unwrap();
    assert!(
        sign.key_signature.is_none(),
        "an absent key_signature must deserialize to None, not error"
    );
    assert!(sign.signed_by_key_id.is_none());

    let enc = resp.keys.iter().find(|k| k.key_usage == "encrypt").unwrap();
    assert_eq!(enc.key_signature.as_deref(), Some(&[7u8, 8, 9][..]));
    assert_eq!(enc.signed_by_key_id.as_deref(), Some("sign-1"));
}
