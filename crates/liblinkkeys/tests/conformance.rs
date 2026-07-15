//! Consumer zero for `sdks/local-rp/conformance/`: reads the checked-in JSON
//! vectors (dns-less-local-rp-design.md, Phase 8) and verifies every positive
//! AND negative case against the real `liblinkkeys` implementation.
//!
//! This is an integration test (lives in `tests/`, outside the library
//! itself), so reading files here does not violate `liblinkkeys`'s
//! no-I/O rule — that rule is about the library crate's own source, not its
//! test suite. See `crates/liblinkkeys/examples/generate_conformance_vectors.rs`
//! for how the vectors are produced.
//!
//! Every other language SDK implements the same constructions against these
//! same files; this test is what proves the vectors are actually consistent
//! with the Rust implementation they were generated from.

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use liblinkkeys::claims::{self, ClaimError, DomainKeySet};
use liblinkkeys::crypto::{self, AeadSuite, SigningAlgorithm};
use liblinkkeys::dns::{self, DnsParseError};
use liblinkkeys::encoding;
use liblinkkeys::generated::{
    self,
    types::{DomainPublicKey, LocalRpEncryptedCallback, SignedLocalRpCallbackPayload},
};
use liblinkkeys::local_rp;
use liblinkkeys::revocation::{self, RevocationError};
use serde_json::Value;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/liblinkkeys; the vectors live at the repo
    // root under sdks/local-rp/conformance/.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/local-rp/conformance")
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
fn keys_fingerprints_and_keypairs_are_internally_consistent() {
    let d = load("keys.json");

    let signing_seed: [u8; 32] = hex_decode(d["local_rp"]["signing"]["seed_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let signing_pub = hex_decode(d["local_rp"]["signing"]["public_key_hex"].as_str().unwrap());
    let signing_fp = d["local_rp"]["signing"]["fingerprint_hex"]
        .as_str()
        .unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
    assert_eq!(sk.verifying_key().as_bytes().to_vec(), signing_pub);
    assert_eq!(crypto::fingerprint(&signing_pub), signing_fp);

    let domain_seed: [u8; 32] = hex_decode(d["domain_signing_key"]["seed_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let domain_pub = hex_decode(d["domain_signing_key"]["public_key_hex"].as_str().unwrap());
    let domain_fp = d["domain_signing_key"]["fingerprint_hex"].as_str().unwrap();
    let domain_sk = ed25519_dalek::SigningKey::from_bytes(&domain_seed);
    assert_eq!(domain_sk.verifying_key().as_bytes().to_vec(), domain_pub);
    assert_eq!(crypto::fingerprint(&domain_pub), domain_fp);

    for (obj_path, priv_field) in [
        (&d["local_rp"]["encryption"], "private_key_hex"),
        (&d["domain_encryption_recipient"], "private_key_hex"),
    ] {
        let private = hex_decode(obj_path[priv_field].as_str().unwrap());
        let public = hex_decode(obj_path["public_key_hex"].as_str().unwrap());
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
        let priv_arr: [u8; 32] = private.try_into().unwrap();
        let derived_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(priv_arr));
        assert_eq!(derived_public.as_bytes().to_vec(), public);
    }
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

    let computed_sig_input = local_rp::envelope_signature_input(context, &payload);
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
fn envelopes_context_strings_match_library_constants() {
    let d = load("envelopes.json");
    let ctx = &d["context_strings"];
    assert_eq!(
        ctx["descriptor"].as_str().unwrap(),
        local_rp::CTX_LOCAL_RP_DESCRIPTOR
    );
    assert_eq!(
        ctx["login_request"].as_str().unwrap(),
        local_rp::CTX_LOCAL_RP_LOGIN_REQUEST
    );
    assert_eq!(
        ctx["callback_payload"].as_str().unwrap(),
        local_rp::CTX_LOCAL_RP_CALLBACK
    );
    assert_eq!(
        ctx["ticket_redemption"].as_str().unwrap(),
        local_rp::CTX_LOCAL_RP_TICKET_REDEMPTION
    );
}

#[test]
fn envelopes_positive_cases_verify() {
    let d = load("envelopes.json");
    let cases = d["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4, "expected one case per signed structure");
    for case in cases {
        assert!(
            case["expected_valid"].as_bool().unwrap(),
            "cases[] must all be positive: {}",
            case_label(case)
        );
        check_envelope_case(case);
    }
}

#[test]
fn envelopes_negative_cases_fail() {
    let d = load("envelopes.json");
    let cases = d["negative_cases"].as_array().unwrap();
    // 4 structures x (1 tamper + 1 wrong-key + 3 wrong-context) = 20.
    assert_eq!(cases.len(), 20);
    for case in cases {
        assert!(
            !case["expected_valid"].as_bool().unwrap(),
            "negative_cases[] must all be negative: {}",
            case_label(case)
        );
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
fn callback_box_positive_cases_open_and_match() {
    let d = load("callback_box.json");
    let cases = d["positive_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2, "expected one case per suite");

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
        let (header, signed_payload) =
            local_rp::open_local_rp_callback(&encrypted, &decrypt_key, &allowed).unwrap_or_else(
                |e| panic!("positive case {:?} failed to open: {e:?}", case["suite"]),
            );

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

        // Structural cross-check of the published AAD/KDF-context values:
        // aad == kdf_context || header_cbor_bytes, exactly per Wire Precision.
        let kdf_context = hex_decode(case["kdf_context_hex"].as_str().unwrap());
        let aad = hex_decode(case["aad_hex"].as_str().unwrap());
        let mut expected_aad = kdf_context;
        expected_aad.extend_from_slice(&header_bytes);
        assert_eq!(aad, expected_aad);
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
        let result = local_rp::open_local_rp_callback(&encrypted, &decrypt_key, &allowed);
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
    let d = load("url_params.json");
    let cases = d["negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let input = case["input"].as_str().unwrap();
        assert!(
            Base64UrlUnpadded::decode_vec(input).is_err(),
            "negative case {} unexpectedly decoded",
            case_label(case)
        );
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
        let record = dns::parse_linkkeys_txt(txt).unwrap();
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
        let err = dns::parse_linkkeys_txt(txt).unwrap_err();
        assert_eq!(
            dns_error_code(&err),
            case["expected_error"].as_str().unwrap(),
            "txt={txt:?}"
        );
    }

    // The "no record at all" fixture documents an SDK-level contract (no TXT
    // record present at all), not a parser input — there is nothing to parse.
    assert_eq!(
        d["linkkeys_txt"]["no_record_case"]["documentation_only"],
        Value::Bool(true)
    );
    assert!(d["linkkeys_txt"]["no_record_case"]["txt"].is_null());
}

#[test]
fn dns_linkkeys_apis_txt_cases() {
    let d = load("dns.json");

    for case in d["linkkeys_apis_txt"]["valid_cases"].as_array().unwrap() {
        let txt = case["txt"].as_str().unwrap();
        let apis = dns::parse_linkkeys_apis_txt(txt).unwrap();
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
        let err = dns::parse_linkkeys_apis_txt(txt).unwrap_err();
        assert_eq!(
            dns_error_code(&err),
            case["expected_error"].as_str().unwrap(),
            "txt={txt:?}"
        );
    }

    assert_eq!(
        d["default_tcp_port"].as_u64().unwrap() as u16,
        dns::DEFAULT_TCP_PORT
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
        assert_eq!(ticket.len(), 32, "ticket bytes must be 32 bytes");
        let expected_hash = case["sha256_hex"].as_str().unwrap();
        assert_eq!(crypto::fingerprint(&ticket), expected_hash);
    }
}

// ---------------------------------------------------------------------
// expirations.json
// ---------------------------------------------------------------------

fn parse_rfc3339(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .unwrap_or_else(|e| panic!("bad rfc3339 {s:?}: {e}"))
        .with_timezone(&Utc)
}

#[test]
fn expirations_check_expirations_thresholds_are_exact() {
    let d = load("expirations.json");
    let expires_at = d["check_expirations"]["expires_at"].as_str().unwrap();
    let cases = d["check_expirations"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 11);

    for case in cases {
        let now_str = case["now"].as_str().unwrap();
        let now = parse_rfc3339(now_str);
        let status = local_rp::check_expirations(expires_at, now).unwrap();
        assert_eq!(
            status.level.as_str(),
            case["expected_level"].as_str().unwrap(),
            "now={now_str}"
        );
        assert_eq!(status.now, now);
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
        let now_str = case["now"].as_str().unwrap();
        let now = parse_rfc3339(now_str);
        let expected_valid = case["expected_valid"].as_bool().unwrap();
        let result = local_rp::check_timestamps(issued_at, expires_at, now, skew);
        assert_eq!(result.is_ok(), expected_valid, "now={now_str}");
    }
}

// ---------------------------------------------------------------------
// revocations.json
// ---------------------------------------------------------------------

fn parse_domain_keys(d: &Value) -> Vec<DomainPublicKey> {
    parse_key_array(&d["domain_keys"])
}

/// Parse an array of key objects (`key_id`/`public_key_hex`/... entries, as
/// used by revocations.json's `domain_keys` and claims.json's key lists) into
/// `DomainPublicKey`s.
fn parse_key_array(v: &Value) -> Vec<DomainPublicKey> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|k| DomainPublicKey {
            key_id: k["key_id"].as_str().unwrap().to_string(),
            public_key: hex_decode(k["public_key_hex"].as_str().unwrap()),
            fingerprint: k["fingerprint_hex"].as_str().unwrap().to_string(),
            algorithm: k["algorithm"].as_str().unwrap().to_string(),
            key_usage: k["key_usage"].as_str().unwrap().to_string(),
            created_at: k["created_at"].as_str().unwrap().to_string(),
            expires_at: k["expires_at"].as_str().unwrap().to_string(),
            revoked_at: k["revoked_at"].as_str().map(|s| s.to_string()),
            signed_by_key_id: None,
            key_signature: None,
        })
        .collect()
}

#[test]
fn revocations_domain_keys_are_internally_consistent() {
    let d = load("revocations.json");
    let keys = d["domain_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        let seed: [u8; 32] = hex_decode(k["seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let public = hex_decode(k["public_key_hex"].as_str().unwrap());
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(
            sk.verifying_key().as_bytes().to_vec(),
            public,
            "key {}",
            k["key_id"]
        );
        assert_eq!(
            crypto::fingerprint(&public),
            k["fingerprint_hex"].as_str().unwrap(),
            "key {}",
            k["key_id"]
        );
    }
    assert_eq!(
        d["tag"].as_str().unwrap(),
        revocation::REVOCATION_TAG,
        "tag must match the library constant"
    );
    assert_eq!(
        d["quorum"].as_u64().unwrap() as usize,
        revocation::REVOCATION_QUORUM
    );
}

#[test]
fn revocations_certificate_cases() {
    let d = load("revocations.json");
    let domain_keys = parse_domain_keys(&d);
    let cases = d["certificate_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);

    for case in cases {
        let name = case_label(case);
        let cert_bytes = hex_decode(case["certificate_cbor_hex"].as_str().unwrap());
        let cert = generated::decode_revocation_certificate(&cert_bytes)
            .unwrap_or_else(|e| panic!("{name}: decode certificate CBOR: {e}"));

        // Cross-check the wire certificate against the expanded JSON copy.
        let jc = &case["certificate"];
        assert_eq!(cert.target_key_id, jc["target_key_id"].as_str().unwrap());
        assert_eq!(
            cert.target_fingerprint,
            jc["target_fingerprint"].as_str().unwrap()
        );
        assert_eq!(cert.revoked_at, jc["revoked_at"].as_str().unwrap());
        let jsigs = jc["signatures"].as_array().unwrap();
        assert_eq!(cert.signatures.len(), jsigs.len(), "{name}");
        for (sig, jsig) in cert.signatures.iter().zip(jsigs) {
            assert_eq!(sig.domain, jsig["domain"].as_str().unwrap(), "{name}");
            assert_eq!(
                sig.signed_by_key_id,
                jsig["signed_by_key_id"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                sig.signature,
                hex_decode(jsig["signature_hex"].as_str().unwrap()),
                "{name}"
            );
        }

        let verify_domain = case["verify_domain"].as_str().unwrap();
        let expected_valid = case["expected_valid"].as_bool().unwrap();
        let expected_counted = case["expected_counted_signers"].as_u64().unwrap() as usize;

        match revocation::verify_revocation_certificate(&cert, &domain_keys, verify_domain) {
            Ok(()) => assert!(expected_valid, "{name}: unexpectedly verified"),
            Err(RevocationError::InsufficientSignatures { got, need }) => {
                assert!(!expected_valid, "{name}: unexpectedly failed");
                assert_eq!(got, expected_counted, "{name}: counted-signer mismatch");
                assert_eq!(need, revocation::REVOCATION_QUORUM, "{name}");
            }
        }
    }
}

#[test]
fn revocations_positive_case_payload_bytes_are_exact() {
    // Deep-check the positive case: the published per-signature payload bytes
    // must equal the library's own canonical construction, and each signature
    // must verify over exactly those bytes with the named sibling's key.
    let d = load("revocations.json");
    let domain_keys = parse_domain_keys(&d);
    let case = d["certificate_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "valid_quorum_two_siblings")
        .expect("positive case present");
    let jc = &case["certificate"];

    for jsig in jc["signatures"].as_array().unwrap() {
        let published_payload = hex_decode(jsig["signed_payload_cbor_hex"].as_str().unwrap());
        let recomputed = revocation::revocation_payload(
            jc["target_key_id"].as_str().unwrap(),
            jc["target_fingerprint"].as_str().unwrap(),
            jc["revoked_at"].as_str().unwrap(),
            jsig["domain"].as_str().unwrap(),
        );
        assert_eq!(
            published_payload, recomputed,
            "payload bytes must be canonical"
        );

        let key = domain_keys
            .iter()
            .find(|k| k.key_id == jsig["signed_by_key_id"].as_str().unwrap())
            .expect("signer key present in domain_keys");
        crypto::resolve_and_verify(
            &key.algorithm,
            &recomputed,
            &hex_decode(jsig["signature_hex"].as_str().unwrap()),
            &key.public_key,
        )
        .expect("signature must verify over the canonical payload");
    }
}

#[test]
fn revocations_application_case_flips_key_validity() {
    let d = load("revocations.json");
    let domain_keys = parse_domain_keys(&d);
    let app = &d["application_case"];

    let envelope = SignedLocalRpCallbackPayload {
        payload: hex_decode(app["envelope"]["payload_cbor_hex"].as_str().unwrap()),
        signing_key_id: app["envelope"]["signing_key_id"]
            .as_str()
            .unwrap()
            .to_string(),
        signature: hex_decode(app["envelope"]["signature_hex"].as_str().unwrap()),
    };
    let verify_now = parse_rfc3339(app["verify_now"].as_str().unwrap());
    let skew = app["clock_skew_seconds"].as_i64().unwrap();

    // Before applying the revocation: the fetched key list shows the signer
    // as valid (no revoked_at), so the envelope verifies.
    assert!(app["expected_valid_before_revocation"].as_bool().unwrap());
    local_rp::verify_local_rp_callback_payload(&envelope, &domain_keys, verify_now, skew)
        .expect("envelope must verify against the pristine fetched key list");

    // The referenced certificate verifies against the same key list.
    let valid_case = d["certificate_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "valid_quorum_two_siblings")
        .expect("referenced certificate present");
    let cert = generated::decode_revocation_certificate(&hex_decode(
        valid_case["certificate_cbor_hex"].as_str().unwrap(),
    ))
    .unwrap();
    revocation::verify_revocation_certificate(&cert, &domain_keys, d["domain"].as_str().unwrap())
        .expect("certificate must verify");

    // Apply it: mark the target key revoked as of cert.revoked_at. This is
    // what every SDK's complete_local_login must do with fetched revocations.
    let mut revoked_keys = domain_keys;
    let mut applied = false;
    for k in &mut revoked_keys {
        if k.key_id == cert.target_key_id {
            k.revoked_at = Some(cert.revoked_at.clone());
            applied = true;
        }
    }
    assert!(applied, "certificate target must exist in the key list");

    // After: the very same envelope must now fail — the signing key is dead.
    assert!(!app["expected_valid_after_revocation"].as_bool().unwrap());
    assert!(
        local_rp::verify_local_rp_callback_payload(&envelope, &revoked_keys, verify_now, skew)
            .is_err(),
        "envelope must fail once the revocation certificate is applied"
    );
}

// ---------------------------------------------------------------------
// claims.json
// ---------------------------------------------------------------------

/// Build the single-domain `DomainKeySet` list claims.json cases verify
/// against: the case's own `domain_keys` override when present, else the
/// file-level default.
fn claims_key_sets(file: &Value, case: &Value) -> Vec<DomainKeySet> {
    let keys_value = if case.get("domain_keys").is_some() {
        &case["domain_keys"]
    } else {
        &file["domain_keys"]
    };
    let keys = parse_key_array(keys_value);
    // All fixture keys belong to one domain; group them by it.
    let domain = keys_value.as_array().unwrap()[0]["domain"]
        .as_str()
        .unwrap()
        .to_string();
    vec![DomainKeySet { domain, keys }]
}

fn claim_error_code(e: &ClaimError) -> &'static str {
    match e {
        ClaimError::SignatureInvalid => "signature_invalid",
        ClaimError::KeyNotFound(_) => "key_not_found",
        ClaimError::KeyRevoked(_) => "key_revoked",
        ClaimError::KeyExpired(_) => "key_expired",
        ClaimError::Unsigned => "unsigned",
        ClaimError::DomainKeysUnavailable(_) => "domain_keys_unavailable",
        ClaimError::DomainUnverified(_) => "domain_unverified",
        ClaimError::Revoked => "revoked",
        ClaimError::Expired => "expired",
        _ => "other",
    }
}

#[test]
fn claims_signer_keys_are_internally_consistent() {
    let d = load("claims.json");
    assert_eq!(d["tag"].as_str().unwrap(), claims::CLAIM_PAYLOAD_TAG);
    for k in d["signer_keys"].as_array().unwrap() {
        let seed: [u8; 32] = hex_decode(k["seed_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let public = hex_decode(k["public_key_hex"].as_str().unwrap());
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(sk.verifying_key().as_bytes().to_vec(), public);
        assert_eq!(
            crypto::fingerprint(&public),
            k["fingerprint_hex"].as_str().unwrap()
        );
    }
}

#[test]
fn claims_wire_round_trip_is_byte_exact() {
    let d = load("claims.json");
    for case in d["cases"].as_array().unwrap() {
        let name = case_label(case);
        let cbor = hex_decode(case["claim_cbor_hex"].as_str().unwrap());
        let claim = generated::decode_claim(&cbor).unwrap_or_else(|e| panic!("{name}: {e}"));

        let jc = &case["claim"];
        assert_eq!(claim.claim_id, jc["claim_id"].as_str().unwrap(), "{name}");
        assert_eq!(claim.user_id, jc["user_id"].as_str().unwrap(), "{name}");
        assert_eq!(
            claim.claim_type,
            jc["claim_type"].as_str().unwrap(),
            "{name}"
        );
        // The bstr check: claim_value must come back as the exact raw bytes,
        // including the non-UTF-8 case.
        assert_eq!(
            claim.claim_value,
            hex_decode(jc["claim_value_hex"].as_str().unwrap()),
            "{name}"
        );
        assert_eq!(
            claim.attested_at,
            jc["attested_at"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            claim.created_at,
            jc["created_at"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            claim.expires_at.as_deref(),
            jc["expires_at"].as_str(),
            "{name}"
        );
        assert_eq!(
            claim.revoked_at.as_deref(),
            jc["revoked_at"].as_str(),
            "{name}"
        );
        let jsigs = jc["signatures"].as_array().unwrap();
        assert_eq!(claim.signatures.len(), jsigs.len(), "{name}");
        for (sig, jsig) in claim.signatures.iter().zip(jsigs) {
            assert_eq!(sig.domain, jsig["domain"].as_str().unwrap(), "{name}");
            assert_eq!(
                sig.signed_by_key_id,
                jsig["signed_by_key_id"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                sig.signature,
                hex_decode(jsig["signature_hex"].as_str().unwrap()),
                "{name}"
            );
        }

        // Re-encode: byte-identical.
        assert_eq!(generated::encode_claim(&claim), cbor, "{name}: re-encode");
    }
}

#[test]
fn claims_signature_payload_bytes_are_exact() {
    let d = load("claims.json");
    let subject_domain = d["subject_domain"].as_str().unwrap();
    let default_keys = parse_domain_keys(&d);

    for case in d["cases"].as_array().unwrap() {
        let name = case_label(case);
        let jc = &case["claim"];
        for jsig in jc["signatures"].as_array().unwrap() {
            let published = hex_decode(jsig["signed_payload_cbor_hex"].as_str().unwrap());
            let recomputed = claims::claim_sign_payload(
                jc["claim_id"].as_str().unwrap(),
                jc["claim_type"].as_str().unwrap(),
                &hex_decode(jc["claim_value_hex"].as_str().unwrap()),
                jc["user_id"].as_str().unwrap(),
                subject_domain,
                jsig["domain"].as_str().unwrap(),
                jc["expires_at"].as_str(),
                jc["attested_at"].as_str().unwrap(),
            );
            assert_eq!(
                published, recomputed,
                "{name}: payload bytes must be canonical"
            );

            let key = default_keys
                .iter()
                .find(|k| k.key_id == jsig["signed_by_key_id"].as_str().unwrap())
                .unwrap_or_else(|| panic!("{name}: signer key present"));
            crypto::resolve_and_verify(
                &key.algorithm,
                &recomputed,
                &hex_decode(jsig["signature_hex"].as_str().unwrap()),
                &key.public_key,
            )
            .unwrap_or_else(|e| panic!("{name}: signature must verify: {e}"));
        }
    }
}

#[test]
fn claims_verification_cases() {
    let d = load("claims.json");

    for case in d["cases"].as_array().unwrap() {
        let name = case_label(case);
        assert!(case["expected_valid"].as_bool().unwrap(), "{name}");
        let claim =
            generated::decode_claim(&hex_decode(case["claim_cbor_hex"].as_str().unwrap())).unwrap();
        let key_sets = claims_key_sets(&d, case);
        claims::verify_claim(&claim, case["subject_domain"].as_str().unwrap(), &key_sets)
            .unwrap_or_else(|e| panic!("{name}: expected valid, got {e}"));
    }

    let negatives = d["negative_cases"].as_array().unwrap();
    assert_eq!(negatives.len(), 4);
    for case in negatives {
        let name = case_label(case);
        let claim =
            generated::decode_claim(&hex_decode(case["claim_cbor_hex"].as_str().unwrap())).unwrap();
        let key_sets = claims_key_sets(&d, case);
        let err = claims::verify_claim(&claim, case["subject_domain"].as_str().unwrap(), &key_sets)
            .expect_err(&format!("{name}: expected failure"));
        assert_eq!(
            claim_error_code(&err),
            case["expected_error"].as_str().unwrap(),
            "{name}: error kind"
        );
    }
}

#[test]
fn claims_value_as_cbor_text_fails_decode() {
    let d = load("claims.json");
    let cases = d["decode_negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 1);
    for case in cases {
        let name = case_label(case);
        assert!(!case["expected_decode_ok"].as_bool().unwrap(), "{name}");
        let cbor = hex_decode(case["claim_cbor_hex"].as_str().unwrap());
        assert!(
            generated::decode_claim(&cbor).is_err(),
            "{name}: a tstr-encoded claim_value must fail the strict decoder"
        );
    }
}

#[test]
fn claims_ticket_redemption_response_round_trips() {
    let d = load("claims.json");
    let r = &d["ticket_redemption_response"];
    let cbor = hex_decode(r["response_cbor_hex"].as_str().unwrap());
    let response = generated::decode_local_rp_ticket_redemption_response(&cbor).unwrap();

    assert_eq!(response.user_id, r["user_id"].as_str().unwrap());
    assert_eq!(response.user_domain, r["user_domain"].as_str().unwrap());
    assert_eq!(
        response.ticket_expires_at,
        r["ticket_expires_at"].as_str().unwrap()
    );

    // The embedded claims must be byte-for-byte the positive cases, in order.
    let cases = d["cases"].as_array().unwrap();
    assert_eq!(response.claims.len(), cases.len());
    for (claim, case) in response.claims.iter().zip(cases) {
        let expected =
            generated::decode_claim(&hex_decode(case["claim_cbor_hex"].as_str().unwrap())).unwrap();
        assert_eq!(claim, &expected, "{}", case_label(case));
    }

    // Re-encode: byte-identical.
    assert_eq!(
        generated::encode_local_rp_ticket_redemption_response(&response),
        cbor
    );

    // And the embedded claims must actually verify — SDKs verify what they
    // pull out of this response, not just decode it.
    let subject_domain = d["subject_domain"].as_str().unwrap();
    let key_sets = vec![DomainKeySet {
        domain: subject_domain.to_string(),
        keys: parse_domain_keys(&d),
    }];
    for claim in &response.claims {
        claims::verify_claim(claim, subject_domain, &key_sets)
            .unwrap_or_else(|e| panic!("embedded claim {} must verify: {e}", claim.claim_id));
    }
}
