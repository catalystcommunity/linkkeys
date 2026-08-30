//! Consumer zero for `sdks/regular-rp/conformance/`: reads the checked-in
//! JSON vectors for application keys (signing-things-request.md, "Required
//! tests and acceptance checks" -> "Cryptographic tests") and verifies every
//! positive AND negative case against the real `liblinkkeys` implementation.
//!
//! This is an integration test (lives in `tests/`, outside the library
//! itself), so reading files here does not violate `liblinkkeys`'s no-I/O
//! rule -- that rule is about the library crate's own source, not its test
//! suite. See `crates/liblinkkeys/examples/generate_application_key_vectors.rs`
//! for how the vectors are produced, and
//! `crates/liblinkkeys/tests/conformance.rs` for the sibling test this one
//! mirrors in structure.
//!
//! Every other language SDK implements the same constructions against these
//! same files; this test is what proves the vectors are actually consistent
//! with the Rust implementation they were generated from.

use liblinkkeys::application_keys::{self as ak, ApplicationKeyRef, InstanceRef};
use liblinkkeys::generated::{self, types::DomainPublicKey};
use serde_json::Value;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/liblinkkeys; the vectors live at the repo
    // root under sdks/regular-rp/conformance/.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/regular-rp/conformance")
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

fn s(v: &Value, field: &str) -> String {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing/non-string field {field:?} in {v}"))
        .to_string()
}

fn opt_s(v: &Value, field: &str) -> Option<String> {
    v.get(field).and_then(|f| f.as_str()).map(|s| s.to_string())
}

fn case_label(case: &Value) -> String {
    case.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("<unnamed case>")
        .to_string()
}

fn instance_from(v: &Value) -> (String, String, String, String) {
    (
        s(v, "subject_user_id"),
        s(v, "subject_domain"),
        s(v, "application_id"),
        s(v, "instance_id"),
    )
}

fn instance_ref<'a>(parts: &'a (String, String, String, String)) -> InstanceRef<'a> {
    InstanceRef {
        subject_user_id: &parts.0,
        subject_domain: &parts.1,
        application_id: &parts.2,
        instance_id: &parts.3,
    }
}

fn key_ref_from(v: &Value) -> ApplicationKeyRef {
    ApplicationKeyRef {
        key_id: s(v, "key_id"),
        key_usage: s(v, "key_usage"),
        algorithm: s(v, "algorithm"),
        public_key: hex_decode(&s(v, "public_key_hex")),
        fingerprint: s(v, "fingerprint"),
        created_at: s(v, "created_at"),
        expires_at: s(v, "expires_at"),
        revoked_at: opt_s(v, "revoked_at"),
    }
}

fn key_refs_from(v: &Value) -> Vec<ApplicationKeyRef> {
    v.as_array()
        .unwrap_or_else(|| panic!("expected array, got {v}"))
        .iter()
        .map(key_ref_from)
        .collect()
}

fn domain_key_from(v: &Value) -> DomainPublicKey {
    DomainPublicKey {
        key_id: s(v, "key_id"),
        public_key: hex_decode(&s(v, "public_key_hex")),
        fingerprint: s(v, "fingerprint"),
        algorithm: s(v, "algorithm"),
        key_usage: s(v, "key_usage"),
        created_at: s(v, "created_at"),
        expires_at: s(v, "expires_at"),
        revoked_at: opt_s(v, "revoked_at"),
        signed_by_key_id: None,
        key_signature: None,
    }
}

fn domain_keys_from(v: &Value) -> Vec<DomainPublicKey> {
    v.as_array()
        .unwrap_or_else(|| panic!("expected array, got {v}"))
        .iter()
        .map(domain_key_from)
        .collect()
}

fn now_from(v: &Value) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(v["now"].as_str().unwrap())
        .unwrap()
        .with_timezone(&chrono::Utc)
}

fn skew_from(v: &Value) -> i64 {
    v["skew_seconds"].as_i64().unwrap()
}

// ---------------------------------------------------------------------
// application_key_attestation.json
// ---------------------------------------------------------------------

fn attestation_signed_from(v: &Value) -> generated::types::SignedApplicationKeyAttestation {
    let signatures = v["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|sig| generated::types::ClaimSignature {
            domain: s(sig, "domain"),
            signed_by_key_id: s(sig, "signed_by_key_id"),
            signature: hex_decode(&s(sig, "signature_hex")),
        })
        .collect();
    generated::types::SignedApplicationKeyAttestation {
        attestation: hex_decode(&s(v, "attestation_cbor_hex")),
        signatures,
    }
}

fn check_attestation_case(case: &Value) {
    let signed = attestation_signed_from(&case["signed"]);
    let domain_keys = domain_keys_from(&case["domain_keys"]);
    let expected_domain = s(case, "expected_domain");
    let expected_valid = case["expected_valid"].as_bool().unwrap();

    let result = ak::verify_attestation_signature(&signed, &domain_keys, &expected_domain);
    assert_eq!(
        result.is_ok(),
        expected_valid,
        "attestation verify mismatch for {}: {:?}",
        case_label(case),
        result
    );
}

#[test]
fn attestation_signature_input_matches_the_real_function() {
    let d = load("application_key_attestation.json");
    let attestation_bytes = hex_decode(d["attestation_cbor_hex"].as_str().unwrap());
    let expected_input = hex_decode(d["signature_input_cbor_hex"].as_str().unwrap());
    assert_eq!(
        ak::attestation_signature_input(&attestation_bytes),
        expected_input
    );
    assert_eq!(d["tag"].as_str().unwrap(), ak::ATTESTATION_TAG);
    assert_eq!(
        d["attestation_lifetime_seconds"].as_i64().unwrap(),
        ak::DEFAULT_ATTESTATION_LIFETIME_SECONDS
    );
}

#[test]
fn attestation_positive_cases_verify() {
    let d = load("application_key_attestation.json");
    let cases = d["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        assert!(
            case["expected_valid"].as_bool().unwrap(),
            "cases[] must all be positive: {}",
            case_label(case)
        );
        check_attestation_case(case);
    }
}

#[test]
fn attestation_negative_cases_fail() {
    let d = load("application_key_attestation.json");
    let cases = d["negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        assert!(
            !case["expected_valid"].as_bool().unwrap(),
            "negative_cases[] must all be negative: {}",
            case_label(case)
        );
        check_attestation_case(case);
    }
}

// ---------------------------------------------------------------------
// application_key_addition.json
// ---------------------------------------------------------------------

fn addition_signed_from(v: &Value) -> generated::types::SignedApplicationKeyAddition {
    let signatures = v["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|sig| generated::types::ApplicationKeySignature {
            signed_by_key_id: s(sig, "signed_by_key_id"),
            signature: hex_decode(&s(sig, "signature_hex")),
        })
        .collect();
    generated::types::SignedApplicationKeyAddition {
        addition: hex_decode(&s(v, "addition_cbor_hex")),
        signatures,
        possession_proof: v["possession_proof_hex"].as_str().map(hex_decode),
    }
}

fn check_addition_case(
    case: &Value,
    instance: &(String, String, String, String),
    now: chrono::DateTime<chrono::Utc>,
    skew: i64,
) {
    let existing_keys = key_refs_from(&case["existing_keys"]);
    let signed = addition_signed_from(&case["signed"]);
    let expected_valid = case["expected_valid"].as_bool().unwrap();

    let result = ak::verify_addition(&signed, &existing_keys, &instance_ref(instance), now, skew);
    assert_eq!(
        result.is_ok(),
        expected_valid,
        "addition verify mismatch for {}: {:?}",
        case_label(case),
        result
    );
}

#[test]
fn addition_signature_inputs_match_the_real_functions() {
    let d = load("application_key_addition.json");
    let addition_bytes = hex_decode(d["addition_cbor_hex"].as_str().unwrap());
    assert_eq!(
        ak::addition_signature_input(&addition_bytes),
        hex_decode(d["addition_signature_input_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        ak::possession_signature_input(&addition_bytes),
        hex_decode(d["possession_signature_input_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(d["quorum_tag"].as_str().unwrap(), ak::ADDITION_TAG);
    assert_eq!(d["possession_tag"].as_str().unwrap(), ak::POSSESSION_TAG);
    assert_eq!(
        d["quorum_size"].as_u64().unwrap() as usize,
        ak::ADDITION_QUORUM
    );
}

#[test]
fn addition_positive_cases_verify() {
    let d = load("application_key_addition.json");
    let instance = instance_from(&d["instance"]);
    let now = now_from(&d);
    let skew = skew_from(&d);
    let cases = d["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        assert!(
            case["expected_valid"].as_bool().unwrap(),
            "cases[] must all be positive: {}",
            case_label(case)
        );
        check_addition_case(case, &instance, now, skew);
    }
}

#[test]
fn addition_negative_cases_fail() {
    let d = load("application_key_addition.json");
    let instance = instance_from(&d["instance"]);
    let now = now_from(&d);
    let skew = skew_from(&d);
    let cases = d["negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        assert!(
            !case["expected_valid"].as_bool().unwrap(),
            "negative_cases[] must all be negative: {}",
            case_label(case)
        );
        check_addition_case(case, &instance, now, skew);
    }
}

// ---------------------------------------------------------------------
// application_key_renewal.json
// ---------------------------------------------------------------------

fn renewal_signed_from(v: &Value) -> generated::types::SignedApplicationKeyRenewal {
    let signatures = v["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|sig| generated::types::ApplicationKeySignature {
            signed_by_key_id: s(sig, "signed_by_key_id"),
            signature: hex_decode(&s(sig, "signature_hex")),
        })
        .collect();
    generated::types::SignedApplicationKeyRenewal {
        renewal: hex_decode(&s(v, "renewal_cbor_hex")),
        signatures,
        possession_proof: v["possession_proof_hex"].as_str().map(hex_decode),
    }
}

fn check_renewal_case(case: &Value, instance: &(String, String, String, String)) {
    let target = key_ref_from(&case["target"]);
    let sibling_keys = key_refs_from(&case["sibling_keys"]);
    let signed = renewal_signed_from(&case["signed"]);
    let now = now_from(case);
    let skew = skew_from(case);
    let expected_valid = case["expected_valid"].as_bool().unwrap();

    let result = ak::verify_renewal(
        &signed,
        &target,
        &sibling_keys,
        &instance_ref(instance),
        now,
        skew,
    );
    assert_eq!(
        result.is_ok(),
        expected_valid,
        "renewal verify mismatch for {}: {:?}",
        case_label(case),
        result
    );
}

#[test]
fn renewal_tags_match_the_real_module() {
    let d = load("application_key_renewal.json");
    assert_eq!(d["renewal_tag"].as_str().unwrap(), ak::RENEWAL_TAG);
    assert_eq!(d["possession_tag"].as_str().unwrap(), ak::POSSESSION_TAG);
    assert_eq!(
        d["renewal_quorum"].as_u64().unwrap() as usize,
        ak::RENEWAL_QUORUM
    );
}

#[test]
fn renewal_positive_cases_verify_and_signature_inputs_match() {
    let d = load("application_key_renewal.json");
    let instance = instance_from(&d["instance"]);
    let cases = d["cases"].as_array().unwrap();
    assert_eq!(
        cases.len(),
        2,
        "expected the ed25519 and x25519 renewal cases"
    );
    for case in cases {
        assert!(
            case["expected_valid"].as_bool().unwrap(),
            "cases[] must all be positive: {}",
            case_label(case)
        );
        let renewal_bytes = hex_decode(case["renewal_cbor_hex"].as_str().unwrap());
        assert_eq!(
            ak::renewal_signature_input(&renewal_bytes),
            hex_decode(case["renewal_signature_input_cbor_hex"].as_str().unwrap()),
            "renewal_signature_input mismatch for {}",
            case_label(case)
        );
        assert_eq!(
            ak::possession_signature_input(&renewal_bytes),
            hex_decode(
                case["possession_signature_input_cbor_hex"]
                    .as_str()
                    .unwrap()
            ),
            "possession_signature_input mismatch for {}",
            case_label(case)
        );
        check_renewal_case(case, &instance);
    }
}

#[test]
fn renewal_negative_cases_fail() {
    let d = load("application_key_renewal.json");
    let instance = instance_from(&d["instance"]);
    let cases = d["negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 1);
    for case in cases {
        assert!(
            !case["expected_valid"].as_bool().unwrap(),
            "negative_cases[] must all be negative: {}",
            case_label(case)
        );
        check_renewal_case(case, &instance);
    }
}

// ---------------------------------------------------------------------
// application_key_revocation.json
// ---------------------------------------------------------------------

fn revocation_from(v: &Value) -> generated::types::ApplicationKeyRevocation {
    let signatures = v["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|sig| generated::types::ApplicationKeySignature {
            signed_by_key_id: s(sig, "signed_by_key_id"),
            signature: hex_decode(&s(sig, "signature_hex")),
        })
        .collect();
    generated::types::ApplicationKeyRevocation {
        subject_user_id: s(v, "subject_user_id"),
        subject_domain: s(v, "subject_domain"),
        application_id: s(v, "application_id"),
        instance_id: s(v, "instance_id"),
        target_key_id: s(v, "target_key_id"),
        target_fingerprint: s(v, "target_fingerprint"),
        revoked_at: s(v, "revoked_at"),
        signatures,
    }
}

fn check_revocation_case(
    case: &Value,
    keys: &[ApplicationKeyRef],
    instance: &(String, String, String, String),
) {
    let rev = revocation_from(&case["revocation"]);
    let expected_valid = case["expected_valid"].as_bool().unwrap();
    let result = ak::verify_revocation(&rev, keys, &instance_ref(instance));
    assert_eq!(
        result.is_ok(),
        expected_valid,
        "revocation verify mismatch for {}: {:?}",
        case_label(case),
        result
    );
}

#[test]
fn revocation_payload_matches_the_real_function() {
    let d = load("application_key_revocation.json");
    let instance = instance_from(&d["instance"]);
    let target_key_id = d["target_key_id"].as_str().unwrap();
    let target_fingerprint = d["target_fingerprint"].as_str().unwrap();
    let revoked_at = d["revoked_at"].as_str().unwrap();
    let expected = hex_decode(d["revocation_payload_cbor_hex"].as_str().unwrap());
    assert_eq!(
        ak::revocation_payload(
            &instance.0,
            &instance.1,
            &instance.2,
            &instance.3,
            target_key_id,
            target_fingerprint,
            revoked_at,
        ),
        expected
    );
    assert_eq!(d["tag"].as_str().unwrap(), ak::REVOCATION_TAG);
    assert_eq!(
        d["quorum"].as_u64().unwrap() as usize,
        ak::REVOCATION_QUORUM
    );
}

#[test]
fn revocation_positive_cases_verify() {
    let d = load("application_key_revocation.json");
    let instance = instance_from(&d["instance"]);
    let keys = key_refs_from(&d["keys"]);
    let cases = d["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        assert!(
            case["expected_valid"].as_bool().unwrap(),
            "cases[] must all be positive: {}",
            case_label(case)
        );
        check_revocation_case(case, &keys, &instance);
    }
}

#[test]
fn revocation_negative_cases_fail() {
    let d = load("application_key_revocation.json");
    let instance = instance_from(&d["instance"]);
    let keys = key_refs_from(&d["keys"]);
    let cases = d["negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        assert!(
            !case["expected_valid"].as_bool().unwrap(),
            "negative_cases[] must all be negative: {}",
            case_label(case)
        );
        check_revocation_case(case, &keys, &instance);
    }
}

// ---------------------------------------------------------------------
// application_key_sealed_challenge.json
// ---------------------------------------------------------------------

#[test]
fn sealed_challenge_reproduces_byte_identical_output() {
    let d = load("application_key_sealed_challenge.json");
    let nonce = hex_decode(d["nonce_hex"].as_str().unwrap());
    let recipient_public: [u8; 32] = hex_decode(d["recipient"]["public_key_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let ephemeral_private: [u8; 32] = hex_decode(d["ephemeral_private_key_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let aead_nonce: [u8; 12] = hex_decode(d["aead_nonce_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let expected = hex_decode(d["sealed_cbor_hex"].as_str().unwrap());

    let sealed = ak::seal_challenge_with_randomness(
        &nonce,
        &recipient_public,
        &ephemeral_private,
        &aead_nonce,
    )
    .expect("deterministic seal must succeed");
    assert_eq!(sealed, expected);
}

#[test]
fn sealed_challenge_positive_case_opens_with_the_right_key() {
    let d = load("application_key_sealed_challenge.json");
    let sealed = hex_decode(d["sealed_cbor_hex"].as_str().unwrap());
    let nonce = hex_decode(d["nonce_hex"].as_str().unwrap());

    let case = &d["cases"][0];
    assert_eq!(case["name"].as_str().unwrap(), "opens_with_correct_key");
    let recipient_private: [u8; 32] =
        hex_decode(case["recipient_private_key_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
    let opened =
        ak::open_challenge(&sealed, &recipient_private).expect("must open with the right key");
    assert_eq!(opened.as_slice(), nonce.as_slice());
    assert_eq!(
        opened.as_slice(),
        hex_decode(case["expected_plaintext_hex"].as_str().unwrap()).as_slice()
    );
}

#[test]
fn sealed_challenge_negative_cases_fail() {
    let d = load("application_key_sealed_challenge.json");
    let default_sealed = hex_decode(d["sealed_cbor_hex"].as_str().unwrap());
    let cases = d["negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        assert!(
            !case["expected_valid"].as_bool().unwrap(),
            "negative_cases[] must all be negative: {}",
            case_label(case)
        );
        let sealed = match case.get("sealed_cbor_hex").and_then(|v| v.as_str()) {
            Some(h) => hex_decode(h),
            None => default_sealed.clone(),
        };
        let recipient_private: [u8; 32] =
            hex_decode(case["recipient_private_key_hex"].as_str().unwrap())
                .try_into()
                .unwrap();
        assert!(
            ak::open_challenge(&sealed, &recipient_private).is_err(),
            "expected open_challenge to fail for {}",
            case_label(case)
        );
    }
}
