//! Conformance-vector tests for the Rust local-RP SDK.
//!
//! Consumes every applicable file under `sdks/local-rp/conformance/` (see
//! that directory's README for the schema) — the same fixed, checked-in
//! vectors `crates/liblinkkeys/tests/conformance.rs` uses as "consumer zero".
//! This crate's job is different from that test: it proves the *SDK's own
//! public surface* (byte helpers, `check_expirations`, the URL-param +
//! envelope + sealed-box plumbing it wraps) agrees with the vectors, using
//! `linkkeys_local_rp`'s public API wherever it has one, and falling back to
//! the underlying `liblinkkeys` calls this SDK is "largely a wrapper over"
//! (design doc, Language Crypto Matrix) where the SDK doesn't expose its own
//! wrapper for a pure protocol primitive (e.g. raw envelope-signature
//! verification, DNS TXT record parsing).
//!
//! Covers: `keys.json`, `envelopes.json`, `callback_box.json`,
//! `url_params.json`, `dns.json`, `tickets.json`, `expirations.json` — every
//! file in the conformance directory, positive and negative cases.

use chrono::{DateTime, Utc};
use liblinkkeys::crypto::{self, AeadSuite, SigningAlgorithm};
use liblinkkeys::dns::{self as lk_dns, DnsParseError};
use liblinkkeys::encoding;
use liblinkkeys::generated::{self, types::LocalRpEncryptedCallback};
use linkkeys_local_rp::{fingerprint_from_string, fingerprint_to_string};
use serde_json::Value;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../conformance")
}

fn load(name: &str) -> Value {
    let path = conformance_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {} (run the generator?)", path.display(), e));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex string: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .unwrap_or_else(|e| panic!("bad hex byte at {i} in {s:?}: {e}"))
        })
        .collect()
}

fn case_label(case: &Value) -> String {
    case.get("name")
        .or_else(|| case.get("structure"))
        .and_then(|v| v.as_str())
        .unwrap_or("<unnamed case>")
        .to_string()
}

// ---------------------------------------------------------------------
// keys.json
// ---------------------------------------------------------------------

#[test]
fn keys_fingerprints_round_trip_through_sdk_fingerprint_helpers() {
    let d = load("keys.json");

    for (path, priv_field) in [
        (&d["local_rp"]["signing"], "seed_hex"),
        (&d["domain_signing_key"], "seed_hex"),
    ] {
        let seed: [u8; 32] = hex_decode(path[priv_field].as_str().unwrap())
            .try_into()
            .unwrap();
        let public = hex_decode(path["public_key_hex"].as_str().unwrap());
        let expected_fp = path["fingerprint_hex"].as_str().unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(sk.verifying_key().as_bytes().to_vec(), public);

        let computed = crypto::fingerprint(&public);
        assert_eq!(computed, expected_fp);

        // Round-trip through the SDK's own fingerprint string helpers.
        let s = fingerprint_to_string(&computed);
        assert_eq!(fingerprint_from_string(&s).unwrap(), expected_fp);
    }

    // fingerprint_from_string must reject non-fingerprint strings even when
    // they happen to be valid hex of the wrong length.
    assert!(fingerprint_from_string("deadbeef").is_err());
}

// ---------------------------------------------------------------------
// envelopes.json
// ---------------------------------------------------------------------

fn check_envelope_case(case: &Value) {
    let context = case["context"].as_str().unwrap();
    let payload = hex_decode(case["payload_cbor_hex"].as_str().unwrap());
    let expected_sig_input = hex_decode(case["signature_input_cbor_hex"].as_str().unwrap());
    let signature = hex_decode(case["signature_hex"].as_str().unwrap());
    let verify_key = hex_decode(case["verify_key_hex"].as_str().unwrap());
    let expected_valid = case["expected_valid"].as_bool().unwrap();

    let computed_sig_input = liblinkkeys::local_rp::envelope_signature_input(context, &payload);
    assert_eq!(
        computed_sig_input,
        expected_sig_input,
        "signature_input_cbor_hex mismatch for {}",
        case_label(case)
    );

    let result = crypto::verify_with_algorithm(
        SigningAlgorithm::Ed25519,
        &computed_sig_input,
        &signature,
        &verify_key,
    );
    assert_eq!(
        result.is_ok(),
        expected_valid,
        "verify result mismatch for {}",
        case_label(case)
    );
}

#[test]
fn envelopes_positive_cases_verify() {
    let d = load("envelopes.json");
    let cases = d["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        assert!(case["expected_valid"].as_bool().unwrap());
        check_envelope_case(case);
    }
}

#[test]
fn envelopes_negative_cases_fail() {
    let d = load("envelopes.json");
    let cases = d["negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    for case in cases {
        assert!(!case["expected_valid"].as_bool().unwrap());
        check_envelope_case(case);
    }
}

// ---------------------------------------------------------------------
// callback_box.json
// ---------------------------------------------------------------------

fn parse_allowed_suites(case: &Value) -> Vec<AeadSuite> {
    case["allowed_suites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| AeadSuite::parse_str(v.as_str().unwrap()).expect("registered suite id"))
        .collect()
}

#[test]
fn callback_box_positive_cases_open_via_sdk_dependency() {
    let d = load("callback_box.json");
    let cases = d["positive_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);

    for case in cases {
        let header_bytes = hex_decode(case["header_cbor_hex"].as_str().unwrap());
        let ciphertext = hex_decode(case["ciphertext_hex"].as_str().unwrap());
        let decrypt_key: [u8; 32] = hex_decode(case["decrypt_private_key_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let allowed = parse_allowed_suites(case);

        let encrypted = LocalRpEncryptedCallback {
            header: header_bytes.clone(),
            ciphertext,
        };
        // The SDK's own `complete_local_login` calls exactly this
        // (`liblinkkeys::local_rp::open_local_rp_callback`) as its decryption
        // step; exercising it directly here keeps this test independent of
        // the network/TCP parts of `complete_local_login`.
        let (header, signed_payload) =
            liblinkkeys::local_rp::open_local_rp_callback(&encrypted, &decrypt_key, &allowed)
                .unwrap_or_else(|e| {
                    panic!("positive case {:?} failed to open: {e:?}", case["suite"])
                });

        assert_eq!(header.suite, case["suite"].as_str().unwrap());
        assert_eq!(header.fingerprint, case["fingerprint"].as_str().unwrap());
        assert_eq!(
            header.nonce,
            hex_decode(case["nonce_hex"].as_str().unwrap())
        );
        assert_eq!(
            header.state,
            hex_decode(case["state_hex"].as_str().unwrap())
        );
        assert_eq!(header.issued_at, case["issued_at"].as_str().unwrap());
        assert_eq!(header.expires_at, case["expires_at"].as_str().unwrap());

        let plaintext = generated::encode_signed_local_rp_callback_payload(&signed_payload);
        assert_eq!(
            plaintext,
            hex_decode(case["plaintext_cbor_hex"].as_str().unwrap())
        );
    }
}

#[test]
fn callback_box_negative_cases_fail() {
    let d = load("callback_box.json");
    let cases = d["negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);

    for case in cases {
        let header_bytes = hex_decode(case["header_cbor_hex"].as_str().unwrap());
        let ciphertext = hex_decode(case["ciphertext_hex"].as_str().unwrap());
        let decrypt_key: [u8; 32] = hex_decode(case["decrypt_private_key_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let allowed = parse_allowed_suites(case);

        let encrypted = LocalRpEncryptedCallback {
            header: header_bytes,
            ciphertext,
        };
        let result =
            liblinkkeys::local_rp::open_local_rp_callback(&encrypted, &decrypt_key, &allowed);
        assert!(
            result.is_err(),
            "negative case {} unexpectedly opened",
            case_label(case)
        );
    }
}

// ---------------------------------------------------------------------
// url_params.json
// ---------------------------------------------------------------------

#[test]
fn url_params_cases_round_trip_both_directions() {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let d = load("url_params.json");
    for case in d["cases"].as_array().unwrap() {
        let cbor = hex_decode(case["cbor_hex"].as_str().unwrap());
        let b64 = case["base64url_unpadded"].as_str().unwrap();

        assert_eq!(Base64UrlUnpadded::encode_string(&cbor), b64);
        assert_eq!(Base64UrlUnpadded::decode_vec(b64).unwrap(), cbor);

        match case["name"].as_str().unwrap() {
            "signed_local_rp_login_request" => {
                let typed = generated::decode_signed_local_rp_login_request(&cbor).unwrap();
                assert_eq!(
                    encoding::signed_local_rp_login_request_to_url_param(&typed).unwrap(),
                    b64
                );
                let round_tripped =
                    encoding::signed_local_rp_login_request_from_url_param(b64).unwrap();
                assert_eq!(round_tripped.request, typed.request);
                assert_eq!(round_tripped.signature, typed.signature);
            }
            "local_rp_encrypted_callback" => {
                let typed = generated::decode_local_rp_encrypted_callback(&cbor).unwrap();
                assert_eq!(
                    encoding::local_rp_encrypted_callback_to_url_param(&typed).unwrap(),
                    b64
                );
                let round_tripped =
                    encoding::local_rp_encrypted_callback_from_url_param(b64).unwrap();
                assert_eq!(round_tripped.header, typed.header);
                assert_eq!(round_tripped.ciphertext, typed.ciphertext);
            }
            other => panic!("unrecognized url_params.json case name: {other}"),
        }
    }
}

#[test]
fn url_params_negative_cases_rejected() {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let d = load("url_params.json");
    let cases = d["negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let input = case["input"].as_str().unwrap();
        assert!(Base64UrlUnpadded::decode_vec(input).is_err());
        // Also exercise the SDK's own decode path used inside
        // `complete_local_login` for the callback param.
        assert!(encoding::local_rp_encrypted_callback_from_url_param(input).is_err());
    }
}

// ---------------------------------------------------------------------
// dns.json
// ---------------------------------------------------------------------

fn dns_error_code(e: &DnsParseError) -> &'static str {
    match e {
        DnsParseError::NoLinkKeysRecord => "no_linkkeys_record",
        DnsParseError::MissingVersion => "missing_version",
        DnsParseError::UnsupportedVersion(_) => "unsupported_version",
        DnsParseError::MissingApisEndpoint => "missing_apis_endpoint",
        DnsParseError::InvalidFormat(_) => "invalid_format",
    }
}

#[test]
fn dns_linkkeys_txt_cases() {
    let d = load("dns.json");

    for case in d["linkkeys_txt"]["valid_cases"].as_array().unwrap() {
        let txt = case["txt"].as_str().unwrap();
        let record = lk_dns::parse_linkkeys_txt(txt).unwrap();
        let expected: Vec<String> = case["expected_fingerprints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(record.fingerprints, expected, "txt={txt:?}");
    }

    for case in d["linkkeys_txt"]["invalid_cases"].as_array().unwrap() {
        let txt = case["txt"].as_str().unwrap();
        let err = lk_dns::parse_linkkeys_txt(txt).unwrap_err();
        assert_eq!(
            dns_error_code(&err),
            case["expected_error"].as_str().unwrap()
        );
    }

    assert_eq!(
        d["linkkeys_txt"]["no_record_case"]["documentation_only"],
        Value::Bool(true)
    );
}

#[test]
fn dns_linkkeys_apis_txt_cases() {
    let d = load("dns.json");

    for case in d["linkkeys_apis_txt"]["valid_cases"].as_array().unwrap() {
        let txt = case["txt"].as_str().unwrap();
        let apis = lk_dns::parse_linkkeys_apis_txt(txt).unwrap();
        assert_eq!(
            apis.tcp,
            case["expected_tcp"].as_str().map(|s| s.to_string()),
            "txt={txt:?}"
        );
        assert_eq!(
            apis.https_base,
            case["expected_https_base"].as_str().map(|s| s.to_string()),
            "txt={txt:?}"
        );
    }

    for case in d["linkkeys_apis_txt"]["invalid_cases"].as_array().unwrap() {
        let txt = case["txt"].as_str().unwrap();
        let err = lk_dns::parse_linkkeys_apis_txt(txt).unwrap_err();
        assert_eq!(
            dns_error_code(&err),
            case["expected_error"].as_str().unwrap()
        );
    }

    assert_eq!(
        d["default_tcp_port"].as_u64().unwrap() as u16,
        lk_dns::DEFAULT_TCP_PORT
    );
}

// ---------------------------------------------------------------------
// tickets.json
// ---------------------------------------------------------------------

#[test]
fn tickets_hash_pairs_match_fingerprint_routine() {
    let d = load("tickets.json");
    let cases = d["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let ticket = hex_decode(case["ticket_hex"].as_str().unwrap());
        assert_eq!(ticket.len(), 32);
        assert_eq!(
            crypto::fingerprint(&ticket),
            case["sha256_hex"].as_str().unwrap()
        );
    }
}

// ---------------------------------------------------------------------
// expirations.json
// ---------------------------------------------------------------------

fn parse_rfc3339(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

#[test]
fn expirations_check_expirations_thresholds_via_sdk_wrapper() {
    let d = load("expirations.json");
    let expires_at = d["check_expirations"]["expires_at"].as_str().unwrap();
    let cases = d["check_expirations"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 11);

    // Build an identity whose descriptor expires at exactly `expires_at`, so
    // this exercises `linkkeys_local_rp::check_expirations` end to end
    // (identity -> descriptor -> liblinkkeys threshold logic) rather than
    // calling the underlying liblinkkeys function directly.
    let created_at = parse_rfc3339(expires_at) - chrono::Duration::days(3650);
    let identity = linkkeys_local_rp::generate_local_rp_identity(
        linkkeys_local_rp::GenerateLocalRpIdentityConfig {
            app_name: "Conformance Test App".to_string(),
            local_domain_hint: None,
            supported_suites: None,
            lifetime: Some(parse_rfc3339(expires_at) - created_at),
            now: created_at,
        },
    )
    .unwrap();

    for case in cases {
        let now = parse_rfc3339(case["now"].as_str().unwrap());
        let status = linkkeys_local_rp::check_expirations(&identity, now).unwrap();
        assert_eq!(
            status.level.as_str(),
            case["expected_level"].as_str().unwrap(),
            "now={now}"
        );
    }
}

#[test]
fn expirations_check_timestamps_skew_boundaries_are_exact() {
    let d = load("expirations.json");
    let issued_at = d["check_timestamps"]["issued_at"].as_str().unwrap();
    let expires_at = d["check_timestamps"]["expires_at"].as_str().unwrap();
    let skew = d["check_timestamps"]["skew_seconds"].as_i64().unwrap();
    let cases = d["check_timestamps"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);

    for case in cases {
        let now = parse_rfc3339(case["now"].as_str().unwrap());
        let expected_valid = case["expected_valid"].as_bool().unwrap();
        let result = liblinkkeys::local_rp::check_timestamps(issued_at, expires_at, now, skew);
        assert_eq!(result.is_ok(), expected_valid, "now={now}");
    }
}
