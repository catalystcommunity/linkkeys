//! Conformance coverage for `sdks/local-rp/conformance/claims.json` — Claim
//! wire encoding and claim-signature verification (see that directory's
//! README, "claims.json" section, for the schema).
//!
//! **The trap this file exists to catch**: `Claim.claim_value` is CBOR
//! **bytes** (bstr, major type 2), never a text string — both on the wire
//! and inside the signed payload. The OCaml SDK wired it as text (tstr) and
//! passed its own self-tests perfectly, because signing wrong bytes and
//! verifying the same wrong bytes is self-consistent; only cross-
//! implementation vectors expose the bug. `claim_non_utf8_binary_value` is
//! the discriminator (its value bytes are not valid UTF-8, so a tstr codec
//! cannot even represent them), and `claim_value_as_cbor_text_rejected` is a
//! wire message a strict bstr codec must refuse to decode.
//!
//! Every case here goes through this SDK's own claim-handling path: the
//! exact `liblinkkeys::generated::{decode,encode}_claim`,
//! `liblinkkeys::claims::verify_claim`, and
//! `liblinkkeys::generated::{decode,encode}_local_rp_ticket_redemption_response`
//! calls `linkkeys_local_rp::complete::complete_local_login` step 8 makes
//! (see `src/complete.rs`), including this crate's own `Error` mapping
//! (`impl From<liblinkkeys::claims::ClaimError> for Error`) for the
//! verification-negative cases.

use liblinkkeys::claims::{self, ClaimError, DomainKeySet};
use liblinkkeys::generated;
use liblinkkeys::generated::types::DomainPublicKey;
use linkkeys_local_rp::{Claim, ClaimSignature, Error};
use serde_json::Value;
use std::path::PathBuf;

fn load_claims() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../conformance/claims.json");
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
        .and_then(|v| v.as_str())
        .unwrap_or("<unnamed case>")
        .to_string()
}

/// Build the `Vec<DomainPublicKey>` wire entries from a `domain_keys[]`
/// array (either the file-level default or a case's own override).
fn parse_domain_keys(keys_value: &Value) -> Vec<DomainPublicKey> {
    keys_value
        .as_array()
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

/// Build the single-domain `DomainKeySet` list a case verifies against: its
/// own `domain_keys` override when present, else the file-level default.
/// All fixture keys belong to one domain (`conformance.example`).
fn claims_key_sets(file: &Value, case: &Value) -> Vec<DomainKeySet> {
    let keys_value = if case.get("domain_keys").is_some() {
        &case["domain_keys"]
    } else {
        &file["domain_keys"]
    };
    let keys = parse_domain_keys(keys_value);
    let domain = keys_value.as_array().unwrap()[0]["domain"]
        .as_str()
        .unwrap()
        .to_string();
    vec![DomainKeySet { domain, keys }]
}

/// Map a claim-verification failure the way `complete_local_login`'s callers
/// see it: through this SDK's own `Error::Claim(ClaimError)` wrapping
/// (`src/error.rs`'s `impl From<ClaimError> for Error`), collapsed to the
/// same symbolic strings the fixture uses.
fn sdk_claim_error_kind(e: Error) -> &'static str {
    match e {
        Error::Claim(ClaimError::SignatureInvalid) => "signature_invalid",
        Error::Claim(ClaimError::KeyNotFound(_)) => "key_not_found",
        Error::Claim(ClaimError::KeyRevoked(_)) => "key_revoked",
        Error::Claim(ClaimError::KeyExpired(_)) => "key_expired",
        Error::Claim(ClaimError::Unsigned) => "unsigned",
        Error::Claim(ClaimError::DomainKeysUnavailable(_)) => "domain_keys_unavailable",
        Error::Claim(ClaimError::DomainUnverified(_)) => "domain_unverified",
        Error::Claim(ClaimError::Revoked) => "revoked",
        Error::Claim(ClaimError::Expired) => "expired",
        other => panic!("expected an Error::Claim variant, got {other:?}"),
    }
}

/// Compare a decoded `Claim`'s fields against the fixture's expanded
/// `claim` object (everything but the wire round-trip itself, which the
/// caller checks separately).
fn assert_claim_matches_fixture(claim: &Claim, jc: &Value, name: &str) {
    assert_eq!(claim.claim_id, jc["claim_id"].as_str().unwrap(), "{name}");
    assert_eq!(claim.user_id, jc["user_id"].as_str().unwrap(), "{name}");
    assert_eq!(
        claim.claim_type,
        jc["claim_type"].as_str().unwrap(),
        "{name}"
    );
    // The bstr check: claim_value must come back as the exact raw bytes,
    // including the non-UTF-8 case — never re-decoded/re-encoded as text.
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
}

// ---------------------------------------------------------------------
// cases[] — positive wire round-trips
// ---------------------------------------------------------------------

#[test]
fn claims_positive_cases_wire_round_trip_byte_exact() {
    let d = load_claims();
    let cases = d["cases"].as_array().unwrap();
    assert_eq!(
        cases.len(),
        3,
        "expected the three documented positive cases"
    );

    for case in cases {
        let name = case_label(case);
        assert!(case["expected_valid"].as_bool().unwrap(), "{name}");

        let cbor = hex_decode(case["claim_cbor_hex"].as_str().unwrap());
        let claim: Claim =
            generated::decode_claim(&cbor).unwrap_or_else(|e| panic!("{name}: decode: {e}"));
        assert_claim_matches_fixture(&claim, &case["claim"], &name);

        // Byte-exact re-encode — the wire round-trip this SDK's decode/
        // encode of Claim (used by `redeem_claim_ticket`'s response and its
        // embedded LocalRpTicketRedemptionResponse.claims) must satisfy.
        assert_eq!(
            generated::encode_claim(&claim),
            cbor,
            "{name}: re-encode is not byte-identical"
        );
    }
}

// ---------------------------------------------------------------------
// cases[] — signed-payload bytes (the tstr/bstr trap, pinned exactly)
// ---------------------------------------------------------------------

#[test]
fn claims_positive_cases_signature_payload_bytes_are_exact_and_verify() {
    let d = load_claims();
    let subject_domain = d["subject_domain"].as_str().unwrap();
    let default_keys = parse_domain_keys(&d["domain_keys"]);

    for case in d["cases"].as_array().unwrap() {
        let name = case_label(case);
        let jc = &case["claim"];
        for jsig in jc["signatures"].as_array().unwrap() {
            let published = hex_decode(jsig["signed_payload_cbor_hex"].as_str().unwrap());
            // claim_sign_payload is the exact function `verify_claim` (and,
            // server-side, claim issuance) calls to build the 8-element
            // tag-first CBOR array — this is what an SDK that wired
            // claim_value as tstr would compute differently.
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
                "{name}: signed payload bytes must be canonical (8-element tag-first array, \
                 '@'-joined subject, claim_value as bstr)"
            );

            let key = default_keys
                .iter()
                .find(|k| k.key_id == jsig["signed_by_key_id"].as_str().unwrap())
                .unwrap_or_else(|| panic!("{name}: signer key present in domain_keys"));
            liblinkkeys::crypto::resolve_and_verify(
                &key.algorithm,
                &recomputed,
                &hex_decode(jsig["signature_hex"].as_str().unwrap()),
                &key.public_key,
            )
            .unwrap_or_else(|e| panic!("{name}: signature must verify: {e}"));
        }
    }
}

// ---------------------------------------------------------------------
// cases[] — through verify_claim (what complete_local_login step 8 calls)
// ---------------------------------------------------------------------

#[test]
fn claims_positive_cases_verify_through_sdk_path() {
    let d = load_claims();
    for case in d["cases"].as_array().unwrap() {
        let name = case_label(case);
        let claim: Claim =
            generated::decode_claim(&hex_decode(case["claim_cbor_hex"].as_str().unwrap())).unwrap();
        let key_sets = claims_key_sets(&d, case);
        claims::verify_claim(&claim, case["subject_domain"].as_str().unwrap(), &key_sets)
            .map_err(Error::from)
            .unwrap_or_else(|e| panic!("{name}: expected valid, got {e}"));
    }
}

// ---------------------------------------------------------------------
// negative_cases[] — verification failures, expected error kinds
// ---------------------------------------------------------------------

#[test]
fn claims_negative_cases_fail_with_expected_error_kind() {
    let d = load_claims();
    let negatives = d["negative_cases"].as_array().unwrap();
    assert_eq!(
        negatives.len(),
        4,
        "expected the four documented verification-negative cases"
    );

    for case in negatives {
        let name = case_label(case);
        let claim: Claim =
            generated::decode_claim(&hex_decode(case["claim_cbor_hex"].as_str().unwrap())).unwrap();
        let key_sets = claims_key_sets(&d, case);

        let raw_err =
            claims::verify_claim(&claim, case["subject_domain"].as_str().unwrap(), &key_sets)
                .expect_err(&format!("{name}: expected verification failure"));

        // Through the SDK's own error mapping (Error::from(ClaimError)),
        // exactly as complete_local_login's `.map_err(Error::from)?` at step
        // 8 produces for app code.
        let sdk_err = Error::from(raw_err);
        assert_eq!(
            sdk_claim_error_kind(sdk_err),
            case["expected_error"].as_str().unwrap(),
            "{name}: error kind mismatch"
        );
    }
}

// ---------------------------------------------------------------------
// decode_negative_cases[] — the tstr/bstr discriminator
// ---------------------------------------------------------------------

#[test]
fn claims_value_as_cbor_text_is_rejected_by_decode() {
    let d = load_claims();
    let cases = d["decode_negative_cases"].as_array().unwrap();
    assert_eq!(
        cases.len(),
        1,
        "expected the one documented decode-negative case"
    );

    for case in cases {
        let name = case_label(case);
        assert!(!case["expected_decode_ok"].as_bool().unwrap(), "{name}");
        let cbor = hex_decode(case["claim_cbor_hex"].as_str().unwrap());
        let result: Result<Claim, _> = generated::decode_claim(&cbor);
        assert!(
            result.is_err(),
            "{name}: a tstr-encoded claim_value must fail this SDK's strict bstr decoder \
             (Claim.claim_value is major type 2, never major type 3)"
        );
    }
}

// ---------------------------------------------------------------------
// ticket_redemption_response — the wire message complete_local_login
// actually consumes Claims from (rpc.rs's redeem_claim_ticket)
// ---------------------------------------------------------------------

#[test]
fn claims_ticket_redemption_response_round_trips_and_embedded_claims_verify() {
    let d = load_claims();
    let r = &d["ticket_redemption_response"];
    let cbor = hex_decode(r["response_cbor_hex"].as_str().unwrap());

    // decode_local_rp_ticket_redemption_response is the exact call
    // `linkkeys_local_rp::rpc::redeem_claim_ticket` makes on the RPC
    // response bytes.
    let response = generated::decode_local_rp_ticket_redemption_response(&cbor)
        .unwrap_or_else(|e| panic!("decode LocalRpTicketRedemptionResponse: {e}"));

    assert_eq!(response.user_id, r["user_id"].as_str().unwrap());
    assert_eq!(response.user_domain, r["user_domain"].as_str().unwrap());
    assert_eq!(
        response.ticket_expires_at,
        r["ticket_expires_at"].as_str().unwrap()
    );

    // The embedded claims must be byte-for-byte the three positive cases,
    // in order.
    let cases = d["cases"].as_array().unwrap();
    assert_eq!(response.claims.len(), cases.len());
    for (claim, case) in response.claims.iter().zip(cases) {
        let expected: Claim =
            generated::decode_claim(&hex_decode(case["claim_cbor_hex"].as_str().unwrap())).unwrap();
        assert_eq!(
            claim.claim_id,
            expected.claim_id,
            "{}: embedded claim mismatch",
            case_label(case)
        );
        assert_eq!(
            claim.claim_value,
            expected.claim_value,
            "{}: embedded claim_value mismatch",
            case_label(case)
        );
        assert_eq!(
            claim.signatures.len(),
            expected.signatures.len(),
            "{}: embedded signature count mismatch",
            case_label(case)
        );
        for (s, es) in claim.signatures.iter().zip(&expected.signatures) {
            assert_eq!(s.signature, es.signature, "{}", case_label(case));
        }
    }

    // Re-encode: byte-identical — decoding without being able to reproduce
    // the exact wire bytes would mean this SDK can't safely relay/cache the
    // response either.
    assert_eq!(
        generated::encode_local_rp_ticket_redemption_response(&response),
        cbor,
        "response re-encode is not byte-identical"
    );

    // Decoding without verifying fails the point (README: "decoding without
    // verifying fails the point") — every embedded claim must actually
    // verify through the same `verify_claim` call complete_local_login step
    // 8 makes.
    let subject_domain = d["subject_domain"].as_str().unwrap();
    let key_sets = vec![DomainKeySet {
        domain: subject_domain.to_string(),
        keys: parse_domain_keys(&d["domain_keys"]),
    }];
    for claim in &response.claims {
        claims::verify_claim(claim, subject_domain, &key_sets)
            .map_err(Error::from)
            .unwrap_or_else(|e| panic!("embedded claim {} must verify: {e}", claim.claim_id));
    }
}

/// `ClaimSignature` is re-exported for app code that wants to inspect
/// `VerifiedLocalLogin.claims` signatures directly; make sure it's actually
/// usable to reconstruct a signature from fixture fields (sanity, not a
/// conformance case of its own).
#[test]
fn claim_signature_type_is_constructible_from_fixture_fields() {
    let d = load_claims();
    let case = &d["cases"][0];
    let jsig = &case["claim"]["signatures"][0];
    let sig = ClaimSignature {
        domain: jsig["domain"].as_str().unwrap().to_string(),
        signed_by_key_id: jsig["signed_by_key_id"].as_str().unwrap().to_string(),
        signature: hex_decode(jsig["signature_hex"].as_str().unwrap()),
    };
    assert_eq!(sig.domain, "conformance.example");
}
