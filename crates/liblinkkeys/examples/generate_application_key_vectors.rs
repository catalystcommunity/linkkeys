//! Generates the cross-language conformance vectors for application keys
//! (signing-things-request.md, "Required tests and acceptance checks" ->
//! "Cryptographic tests") checked into `sdks/regular-rp/conformance/`.
//!
//! Application keys are a REGULAR-RP concern (an application instance enrolls
//! and renews keys through its regular RP or reads them anonymously as a
//! DNS-less RP) rather than a local-RP one, so these vectors live in a
//! sibling directory to `sdks/local-rp/conformance/` rather than inside it.
//! See `crates/liblinkkeys/src/application_keys.rs` for the module under
//! test and `crates/liblinkkeys/examples/generate_conformance_vectors.rs`
//! for the sibling generator this one deliberately mirrors in structure and
//! determinism discipline (this file does not modify or depend on that one).
//!
//! ## Determinism
//!
//! All key material is FIXED test-only seeds (hardcoded below, never used in
//! production). All timestamps are fixed RFC3339 constants. The one wire
//! construction with real randomness in production -- the sealed
//! challenge's ephemeral X25519 key and AEAD nonce -- is generated here via
//! [`liblinkkeys::application_keys::seal_challenge_with_randomness`], which
//! takes those values as explicit parameters instead of sourcing them from
//! the OS RNG (the same pattern `local_rp::seal_local_rp_callback_with_randomness`
//! uses for the local-RP callback box; that pattern is why this generator
//! added the function rather than reimplementing the sealed box by hand).
//! Ed25519 signing needs no such treatment: EdDSA signing is fully
//! deterministic by construction.
//!
//! Running this generator twice must produce byte-identical output.
//!
//! ## Usage
//!
//! ```sh
//! cargo run -p liblinkkeys --example generate_application_key_vectors
//! # or, to write elsewhere:
//! cargo run -p liblinkkeys --example generate_application_key_vectors -- /tmp/out
//! ```
//!
//! With no argument, output goes to `sdks/regular-rp/conformance/` relative
//! to the repo root (resolved via `CARGO_MANIFEST_DIR`, not the process's
//! current directory).

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use liblinkkeys::application_keys::{
    self as ak, ApplicationKeyError, ApplicationKeyRef, ApplicationSigner, InstanceRef,
};
use liblinkkeys::claims::ClaimSigner;
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::generated::{self, types::DomainPublicKey};
use liblinkkeys::local_rp::DEFAULT_CLOCK_SKEW_SECONDS;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

// ---------------------------------------------------------------------
// Fixed test-only key material. NEVER use these seeds for anything real.
// ---------------------------------------------------------------------

const SUBJECT: &str = "018f2222-0000-7000-8000-000000000099";
const DOMAIN: &str = "app-conformance.example";
const APPLICATION_ID: &str = "tinku-conformance";
const INSTANCE_ID: &str = "instance-1";

const DOMAIN_SIGNING_SEED: [u8; 32] = [0x21; 32];
const DOMAIN_SIGNING_KEY_ID: &str = "domain-key-1";

const KEY_A_SEED: [u8; 32] = [0x01; 32];
const KEY_B_SEED: [u8; 32] = [0x02; 32];
const KEY_C_SEED: [u8; 32] = [0x03; 32]; // third sibling, used by revocation vectors
const KEY_AGREE_SEED: [u8; 32] = [0x04; 32]; // an existing, already-enrolled X25519 key
const NEW_SIGN_SEED: [u8; 32] = [0x05; 32]; // the new signing key being added
const IMPOSTOR_SEED: [u8; 32] = [0x07; 32];

const KEY_A_ID: &str = "app-key-a";
const KEY_B_ID: &str = "app-key-b";
const KEY_C_ID: &str = "app-key-c";
const KEY_AGREE_ID: &str = "app-key-agree";
const NEW_SIGN_ID: &str = "app-key-new";
const IMPOSTOR_ID: &str = "impostor-key";

// Sealed-challenge fixtures: the recipient X25519 key the challenge is
// correctly sealed to, and a second, unrelated X25519 key used only for the
// "wrong key" negative case.
const CHALLENGE_RECIPIENT_SEED: [u8; 32] = [0x08; 32];
const CHALLENGE_WRONG_RECIPIENT_SEED: [u8; 32] = [0x09; 32];
const CHALLENGE_EPHEMERAL_SEED: [u8; 32] = [0x0a; 32];
const CHALLENGE_AEAD_NONCE: [u8; 12] = [0x0b; 12];
const CHALLENGE_NONCE: [u8; 32] = [0xa1; 32];

// A domain signing key's own validity is checked against WALL-CLOCK time in
// the Rust implementation (`crypto::signing_key_validity`), not an injected
// `now` -- see `check_signing_key_valid`. This fixture must simply outlive
// any realistic test run.
const DOMAIN_KEY_FAR_EXPIRES: &str = "2126-01-01T00:00:00+00:00";

const SKEW_SECONDS: i64 = DEFAULT_CLOCK_SKEW_SECONDS;

fn base_instant() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-06-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

struct Ed25519Fixture {
    key_id: &'static str,
    seed: [u8; 32],
    public_key: [u8; 32],
    private_key: [u8; 32],
    fingerprint: String,
}

fn ed25519_fixture(key_id: &'static str, seed: [u8; 32]) -> Ed25519Fixture {
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    Ed25519Fixture {
        key_id,
        seed,
        public_key: *pk.as_bytes(),
        private_key: sk.to_bytes(),
        fingerprint: crypto::fingerprint(pk.as_bytes()),
    }
}

impl Ed25519Fixture {
    fn signer(&self) -> ApplicationSigner<'_> {
        ApplicationSigner {
            key_id: self.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &self.private_key,
        }
    }

    fn claim_signer(&self, domain: &'static str) -> ClaimSigner<'_> {
        ClaimSigner {
            domain,
            key_id: self.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &self.private_key,
        }
    }

    /// An `ApplicationKeyRef` for this key: a currently-valid signing key
    /// created at `base_instant()` and expiring one year later.
    fn key_ref(&self) -> ApplicationKeyRef {
        ApplicationKeyRef {
            key_id: self.key_id.to_string(),
            key_usage: ak::KEY_USAGE_SIGN.to_string(),
            algorithm: "ed25519".to_string(),
            public_key: self.public_key.to_vec(),
            fingerprint: self.fingerprint.clone(),
            created_at: rfc3339(base_instant()),
            expires_at: rfc3339(base_instant() + Duration::days(365)),
            revoked_at: None,
        }
    }

    fn key_ref_json(&self) -> Value {
        key_ref_json(&self.key_ref())
    }
}

struct X25519Fixture {
    key_id: &'static str,
    seed: [u8; 32],
    public_key: [u8; 32],
    private_key: [u8; 32],
    fingerprint: String,
}

fn x25519_fixture(key_id: &'static str, seed: [u8; 32]) -> X25519Fixture {
    let sk = X25519StaticSecret::from(seed);
    let pk = X25519PublicKey::from(&sk);
    X25519Fixture {
        key_id,
        seed,
        public_key: *pk.as_bytes(),
        private_key: seed,
        fingerprint: crypto::fingerprint(pk.as_bytes()),
    }
}

impl X25519Fixture {
    fn key_ref(&self) -> ApplicationKeyRef {
        ApplicationKeyRef {
            key_id: self.key_id.to_string(),
            key_usage: ak::KEY_USAGE_AGREE.to_string(),
            algorithm: "x25519".to_string(),
            public_key: self.public_key.to_vec(),
            fingerprint: self.fingerprint.clone(),
            created_at: rfc3339(base_instant()),
            expires_at: rfc3339(base_instant() + Duration::days(365)),
            revoked_at: None,
        }
    }
}

fn key_ref_json(k: &ApplicationKeyRef) -> Value {
    json!({
        "key_id": k.key_id,
        "key_usage": k.key_usage,
        "algorithm": k.algorithm,
        "public_key_hex": hex(&k.public_key),
        "fingerprint": k.fingerprint,
        "created_at": k.created_at,
        "expires_at": k.expires_at,
        "revoked_at": k.revoked_at,
    })
}

fn instance() -> InstanceRef<'static> {
    InstanceRef {
        subject_user_id: SUBJECT,
        subject_domain: DOMAIN,
        application_id: APPLICATION_ID,
        instance_id: INSTANCE_ID,
    }
}

fn instance_json() -> Value {
    json!({
        "subject_user_id": SUBJECT,
        "subject_domain": DOMAIN,
        "application_id": APPLICATION_ID,
        "instance_id": INSTANCE_ID,
    })
}

fn write_json(dir: &Path, name: &str, value: &Value) {
    let mut text = serde_json::to_string_pretty(value).expect("serialize vector JSON");
    text.push('\n');
    let path = dir.join(name);
    std::fs::write(&path, &text).unwrap_or_else(|e| panic!("write {}: {}", path.display(), e));
    println!("wrote {}", path.display());
}

fn main() {
    let out_dir: PathBuf = match std::env::args().nth(1) {
        Some(arg) => PathBuf::from(arg),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdks/regular-rp/conformance"),
    };
    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|e| panic!("create {}: {}", out_dir.display(), e));

    write_json(
        &out_dir,
        "application_key_attestation.json",
        &attestation_vectors(),
    );
    write_json(
        &out_dir,
        "application_key_addition.json",
        &addition_vectors(),
    );
    write_json(&out_dir, "application_key_renewal.json", &renewal_vectors());
    write_json(
        &out_dir,
        "application_key_revocation.json",
        &revocation_vectors(),
    );
    write_json(
        &out_dir,
        "application_key_sealed_challenge.json",
        &sealed_challenge_vectors(),
    );

    println!("done.");
}

// ---------------------------------------------------------------------
// application_key_attestation.json
// ---------------------------------------------------------------------

fn attestation_vectors() -> Value {
    let domain_key = ed25519_fixture(DOMAIN_SIGNING_KEY_ID, DOMAIN_SIGNING_SEED);
    let app_key = ed25519_fixture(KEY_A_ID, KEY_A_SEED);

    let attested_at = base_instant();
    let mut key_ref = app_key.key_ref();
    key_ref.expires_at = rfc3339(base_instant() + Duration::days(365));

    let attestation = ak::build_attestation(
        &instance(),
        &key_ref,
        attested_at,
        ak::DEFAULT_ATTESTATION_LIFETIME_SECONDS,
    );
    let attestation_bytes = generated::encode_application_key_attestation(&attestation);
    let signature_input = ak::attestation_signature_input(&attestation_bytes);
    let signed = ak::sign_attestation(&attestation, &[domain_key.claim_signer(DOMAIN)]).unwrap();
    assert_eq!(signed.attestation, attestation_bytes);

    let domain_public_key = DomainPublicKey {
        key_id: domain_key.key_id.to_string(),
        public_key: domain_key.public_key.to_vec(),
        fingerprint: domain_key.fingerprint.clone(),
        algorithm: "ed25519".to_string(),
        key_usage: "sign".to_string(),
        created_at: rfc3339(base_instant()),
        expires_at: DOMAIN_KEY_FAR_EXPIRES.to_string(),
        revoked_at: None,
        signed_by_key_id: None,
        key_signature: None,
    };
    let domain_keys = vec![domain_public_key.clone()];

    // Generator sanity: the real verifier must accept the positive case.
    let verified = ak::verify_attestation_signature(&signed, &domain_keys, DOMAIN)
        .expect("positive attestation case must verify");
    assert_eq!(verified.key_id, KEY_A_ID);

    let domain_keys_json = vec![json!({
        "key_id": domain_public_key.key_id,
        "public_key_hex": hex(&domain_public_key.public_key),
        "fingerprint": domain_public_key.fingerprint,
        "algorithm": domain_public_key.algorithm,
        "key_usage": domain_public_key.key_usage,
        "created_at": domain_public_key.created_at,
        "expires_at": domain_public_key.expires_at,
        "revoked_at": domain_public_key.revoked_at,
    })];

    let signed_json = |s: &liblinkkeys::generated::types::SignedApplicationKeyAttestation| {
        json!({
            "attestation_cbor_hex": hex(&s.attestation),
            "signatures": s.signatures.iter().map(|sig| json!({
                "domain": sig.domain,
                "signed_by_key_id": sig.signed_by_key_id,
                "signature_hex": hex(&sig.signature),
            })).collect::<Vec<_>>(),
        })
    };

    let mut negative_cases = Vec::new();

    // Negative: same attestation bytes, signed under a DIFFERENT
    // domain-separation tag (reuses ADDITION_TAG, a real tag in this module,
    // just not the one attestations use).
    {
        let wrong_tag_input =
            liblinkkeys::local_rp::envelope_signature_input(ak::ADDITION_TAG, &attestation_bytes);
        let wrong_tag_sig = crypto::sign_with_algorithm(
            SigningAlgorithm::Ed25519,
            &wrong_tag_input,
            &domain_key.private_key,
        )
        .unwrap();
        let mut mistagged = signed.clone();
        mistagged.signatures[0].signature = wrong_tag_sig;
        assert!(
            ak::verify_attestation_signature(&mistagged, &domain_keys, DOMAIN).is_err(),
            "mistagged signature must not verify"
        );
        negative_cases.push(json!({
            "name": "wrong_domain_separation_tag",
            "description": "The exact same attestation bytes, but the signature was produced under ADDITION_TAG instead of ATTESTATION_TAG. Must be rejected: a signature for one signed structure must never verify as another.",
            "signed": signed_json(&mistagged),
            "domain_keys": domain_keys_json,
            "expected_domain": DOMAIN,
            "expected_valid": false,
        }));
    }

    // Negative: tampered attestation byte (last byte of the CBOR flipped),
    // original signature reused.
    {
        let mut tampered_bytes = attestation_bytes.clone();
        *tampered_bytes.last_mut().unwrap() ^= 0xff;
        let mut tampered = signed.clone();
        tampered.attestation = tampered_bytes;
        assert!(
            ak::verify_attestation_signature(&tampered, &domain_keys, DOMAIN).is_err(),
            "tampered attestation bytes must not verify"
        );
        negative_cases.push(json!({
            "name": "tampered_attestation_byte",
            "description": "Last byte of the attestation CBOR flipped after signing; original signature reused. Depending on where the flipped byte lands this may also fail to decode as valid CBOR/UTF-8 -- either outcome is an acceptable 'not valid' result.",
            "signed": signed_json(&tampered),
            "domain_keys": domain_keys_json,
            "expected_domain": DOMAIN,
            "expected_valid": false,
        }));
    }

    // Negative: an attestation for a DIFFERENT subject_domain than the one
    // the caller expects, even though the signature itself is genuine.
    {
        let mut other_domain_attestation = attestation.clone();
        other_domain_attestation.subject_domain = "evil.example".to_string();
        let other_signed = ak::sign_attestation(
            &other_domain_attestation,
            &[domain_key.claim_signer(DOMAIN)],
        )
        .unwrap();
        assert_eq!(
            ak::verify_attestation_signature(&other_signed, &domain_keys, DOMAIN),
            Err(ApplicationKeyError::IdentityMismatch {
                field: "subject_domain"
            })
        );
        negative_cases.push(json!({
            "name": "attestation_for_different_subject_domain",
            "description": "A genuinely-signed attestation whose subject_domain field is 'evil.example', verified with expected_domain = the real domain. The signature verifies fine; the identity binding must still refuse it.",
            "signed": signed_json(&other_signed),
            "domain_keys": domain_keys_json,
            "expected_domain": DOMAIN,
            "expected_valid": false,
        }));
    }

    json!({
        "note": "ApplicationKeyAttestation: the home domain's short-lived attestation over one application public key. `attestation` is the exact deterministic CBOR encoding; each ClaimSignature in `signatures` covers CBOR([ATTESTATION_TAG, attestation_bytes]) -- see envelope_signature_input in local_rp.rs, reused here. ALL KEYS IN THIS FILE ARE FIXED, PUBLICLY-KNOWN TEST-ONLY MATERIAL. Never reuse any key here for anything real.",
        "tag": ak::ATTESTATION_TAG,
        "attestation_lifetime_seconds": ak::DEFAULT_ATTESTATION_LIFETIME_SECONDS,
        "instance": instance_json(),
        "domain_signing_key": {
            "key_id": domain_key.key_id,
            "seed_hex": hex(&domain_key.seed),
            "private_key_hex": hex(&domain_key.private_key),
            "public_key_hex": hex(&domain_key.public_key),
            "fingerprint": domain_key.fingerprint,
        },
        "application_key": {
            "key_id": app_key.key_id,
            "seed_hex": hex(&app_key.seed),
            "private_key_hex": hex(&app_key.private_key),
            "public_key_hex": hex(&app_key.public_key),
            "fingerprint": app_key.fingerprint,
            "created_at": key_ref.created_at,
            "expires_at": key_ref.expires_at,
        },
        "attestation": {
            "attested_at": attestation.attested_at,
            "attestation_expires_at": attestation.attestation_expires_at,
        },
        "attestation_cbor_hex": hex(&attestation_bytes),
        "signature_input_cbor_hex": hex(&signature_input),
        "signed": signed_json(&signed),
        "domain_keys": domain_keys_json,
        "expected_domain": DOMAIN,
        "cases": [{
            "name": "domain_signed_attestation",
            "description": "One home-domain signature over one application signing key's attestation.",
            "signed": signed_json(&signed),
            "domain_keys": domain_keys_json,
            "expected_domain": DOMAIN,
            "expected_valid": true,
        }],
        "negative_cases": negative_cases,
    })
}

// ---------------------------------------------------------------------
// application_key_addition.json
// ---------------------------------------------------------------------

fn addition_vectors() -> Value {
    let a = ed25519_fixture(KEY_A_ID, KEY_A_SEED);
    let b = ed25519_fixture(KEY_B_ID, KEY_B_SEED);
    let new_key = ed25519_fixture(NEW_SIGN_ID, NEW_SIGN_SEED);
    let impostor = ed25519_fixture(IMPOSTOR_ID, IMPOSTOR_SEED);

    let existing_keys = vec![a.key_ref(), b.key_ref()];
    let existing_keys_json = vec![a.key_ref_json(), b.key_ref_json()];

    let requested_at = base_instant();
    let expires_at = requested_at + Duration::minutes(5);
    let now = requested_at + Duration::minutes(1);

    let addition = liblinkkeys::generated::types::ApplicationKeyAddition {
        subject_user_id: SUBJECT.to_string(),
        subject_domain: DOMAIN.to_string(),
        application_id: APPLICATION_ID.to_string(),
        instance_id: INSTANCE_ID.to_string(),
        key_id: new_key.key_id.to_string(),
        key_usage: ak::KEY_USAGE_SIGN.to_string(),
        algorithm: "ed25519".to_string(),
        public_key: new_key.public_key.to_vec(),
        fingerprint: new_key.fingerprint.clone(),
        requested_key_lifetime_seconds: 31_536_000,
        challenge_id: "addition-challenge-1".to_string(),
        challenge: vec![0x77; 32],
        requested_at: rfc3339(requested_at),
        expires_at: rfc3339(expires_at),
    };
    let addition_bytes = generated::encode_application_key_addition(&addition);
    let addition_signature_input = ak::addition_signature_input(&addition_bytes);
    let possession_signature_input = ak::possession_signature_input(&addition_bytes);

    let signed = ak::sign_addition(
        &addition,
        &[a.signer(), b.signer()],
        Some(&new_key.signer()),
    )
    .unwrap();
    assert_eq!(signed.addition, addition_bytes);
    ak::verify_addition(&signed, &existing_keys, &instance(), now, SKEW_SECONDS)
        .expect("positive addition case must verify");

    type SignedAddition = liblinkkeys::generated::types::SignedApplicationKeyAddition;
    let signed_json = |s: &SignedAddition| {
        json!({
            "addition_cbor_hex": hex(&s.addition),
            "signatures": s.signatures.iter().map(|sig| json!({
                "signed_by_key_id": sig.signed_by_key_id,
                "signature_hex": hex(&sig.signature),
            })).collect::<Vec<_>>(),
            "possession_proof_hex": s.possession_proof.as_ref().map(|p| hex(p)),
        })
    };

    let mut negative_cases = Vec::new();

    // One signature: below quorum of two.
    {
        let one = ak::sign_addition(&addition, &[a.signer()], Some(&new_key.signer())).unwrap();
        assert_eq!(
            ak::verify_addition(&one, &existing_keys, &instance(), now, SKEW_SECONDS),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
        negative_cases.push(json!({
            "name": "one_signature_insufficient",
            "description": "Only app-key-a signed. One valid signer is below the quorum of two.",
            "existing_keys": existing_keys_json,
            "signed": signed_json(&one),
            "expected_valid": false,
        }));
    }

    // Duplicate signer: the same key signing twice still counts once.
    {
        let dup = ak::sign_addition(
            &addition,
            &[a.signer(), a.signer()],
            Some(&new_key.signer()),
        )
        .unwrap();
        assert_eq!(
            ak::verify_addition(&dup, &existing_keys, &instance(), now, SKEW_SECONDS),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
        negative_cases.push(json!({
            "name": "duplicate_signer",
            "description": "app-key-a signed twice (two ApplicationKeySignature entries, same signed_by_key_id). A key never counts twice, so this is still one distinct signer.",
            "existing_keys": existing_keys_json,
            "signed": signed_json(&dup),
            "expected_valid": false,
        }));
    }

    // The new key signs its own authorization; must never count even if a
    // compromised or confused server also lists it among "existing" keys.
    {
        let existing_with_new = vec![a.key_ref(), new_key.key_ref()];
        let existing_with_new_json = vec![a.key_ref_json(), new_key.key_ref_json()];
        let self_signed = ak::sign_addition(
            &addition,
            &[a.signer(), new_key.signer()],
            Some(&new_key.signer()),
        )
        .unwrap();
        assert_eq!(
            ak::verify_addition(
                &self_signed,
                &existing_with_new,
                &instance(),
                now,
                SKEW_SECONDS
            ),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
        negative_cases.push(json!({
            "name": "new_key_signs_own_authorization",
            "description": "The new key (app-key-new) is presented as though it were already an existing key AND signs the quorum message for its own addition. It must never count toward its own authorization, so only app-key-a counts.",
            "existing_keys": existing_with_new_json,
            "signed": signed_json(&self_signed),
            "expected_valid": false,
        }));
    }

    // Possession proof by the wrong key.
    {
        let wrong_proof = ak::sign_addition(
            &addition,
            &[a.signer(), b.signer()],
            Some(&impostor.signer()),
        )
        .unwrap();
        assert_eq!(
            ak::verify_addition(&wrong_proof, &existing_keys, &instance(), now, SKEW_SECONDS),
            Err(ApplicationKeyError::BadPossessionProof)
        );
        negative_cases.push(json!({
            "name": "possession_proof_wrong_key",
            "description": "A valid two-signature quorum, but the possession proof was signed by a key (impostor-key) other than the new key itself. Proves nothing about who holds the new key's private key.",
            "existing_keys": existing_keys_json,
            "signed": signed_json(&wrong_proof),
            "expected_valid": false,
        }));
    }

    // A quorum signature replayed as a possession proof.
    {
        let mut replayed = signed.clone();
        let quorum_style = crypto::sign_with_algorithm(
            SigningAlgorithm::Ed25519,
            &addition_signature_input,
            &new_key.private_key,
        )
        .unwrap();
        replayed.possession_proof = Some(quorum_style);
        assert_eq!(
            ak::verify_addition(&replayed, &existing_keys, &instance(), now, SKEW_SECONDS),
            Err(ApplicationKeyError::BadPossessionProof)
        );
        negative_cases.push(json!({
            "name": "quorum_signature_as_possession_proof",
            "description": "The new key's OWN quorum-tagged signature (over addition_signature_input, i.e. as if it were an authorizing signer) is offered as the possession proof (which must cover possession_signature_input instead). The two message bytes share the same payload under DIFFERENT tags, so this must fail.",
            "existing_keys": existing_keys_json,
            "signed": signed_json(&replayed),
            "expected_valid": false,
        }));
    }

    json!({
        "note": "ApplicationKeyAddition: a two-signing-key quorum authorizes adding a new application key, which separately proves possession of its own private key. ALL KEYS IN THIS FILE ARE FIXED, PUBLICLY-KNOWN TEST-ONLY MATERIAL. Never reuse any key here for anything real.",
        "quorum_tag": ak::ADDITION_TAG,
        "possession_tag": ak::POSSESSION_TAG,
        "quorum_size": ak::ADDITION_QUORUM,
        "instance": instance_json(),
        "existing_keys": existing_keys_json,
        "new_key": {
            "key_id": new_key.key_id,
            "key_usage": "sign",
            "algorithm": "ed25519",
            "seed_hex": hex(&new_key.seed),
            "private_key_hex": hex(&new_key.private_key),
            "public_key_hex": hex(&new_key.public_key),
            "fingerprint": new_key.fingerprint,
        },
        "impostor_key": {
            "key_id": impostor.key_id,
            "seed_hex": hex(&impostor.seed),
            "private_key_hex": hex(&impostor.private_key),
            "public_key_hex": hex(&impostor.public_key),
            "fingerprint": impostor.fingerprint,
        },
        "addition_cbor_hex": hex(&addition_bytes),
        "addition_signature_input_cbor_hex": hex(&addition_signature_input),
        "possession_signature_input_cbor_hex": hex(&possession_signature_input),
        "now": rfc3339(now),
        "skew_seconds": SKEW_SECONDS,
        "cases": [{
            "name": "two_key_quorum_with_possession_proof",
            "description": "app-key-a and app-key-b (two distinct, currently-valid existing signing keys) authorize adding app-key-new; app-key-new separately proves possession.",
            "existing_keys": existing_keys_json,
            "signed": signed_json(&signed),
            "expected_valid": true,
        }],
        "negative_cases": negative_cases,
    })
}

// ---------------------------------------------------------------------
// application_key_renewal.json
// ---------------------------------------------------------------------

fn renewal_vectors() -> Value {
    let a = ed25519_fixture(KEY_A_ID, KEY_A_SEED);
    let agree = x25519_fixture(KEY_AGREE_ID, KEY_AGREE_SEED);

    let requested_at = base_instant();
    let expires_at = requested_at + Duration::minutes(5);
    let now = requested_at + Duration::minutes(1);

    type Renewal = liblinkkeys::generated::types::ApplicationKeyRenewal;
    type SignedRenewal = liblinkkeys::generated::types::SignedApplicationKeyRenewal;

    let renewal_for = |key_id: &str, challenge_id: &str| -> Renewal {
        Renewal {
            subject_user_id: SUBJECT.to_string(),
            subject_domain: DOMAIN.to_string(),
            application_id: APPLICATION_ID.to_string(),
            instance_id: INSTANCE_ID.to_string(),
            key_id: key_id.to_string(),
            challenge_id: challenge_id.to_string(),
            challenge: vec![0x88; 32],
            requested_at: rfc3339(requested_at),
            expires_at: rfc3339(expires_at),
        }
    };

    let signed_json = |s: &SignedRenewal| {
        json!({
            "renewal_cbor_hex": hex(&s.renewal),
            "signatures": s.signatures.iter().map(|sig| json!({
                "signed_by_key_id": sig.signed_by_key_id,
                "signature_hex": hex(&sig.signature),
            })).collect::<Vec<_>>(),
            "possession_proof_hex": s.possession_proof.as_ref().map(|p| hex(p)),
        })
    };

    let mut cases = Vec::new();

    // Ed25519 self-renewal: the target key proves possession by signing for
    // itself; no sibling quorum is needed or used.
    let ed_renewal = renewal_for(a.key_id, "renewal-challenge-ed25519");
    let ed_bytes = generated::encode_application_key_renewal(&ed_renewal);
    let ed_signature_input = ak::renewal_signature_input(&ed_bytes);
    let ed_possession_input = ak::possession_signature_input(&ed_bytes);
    let ed_signed = ak::sign_renewal(&ed_renewal, &[], Some(&a.signer())).unwrap();
    ak::verify_renewal(
        &ed_signed,
        &a.key_ref(),
        &[],
        &instance(),
        now,
        SKEW_SECONDS,
    )
    .expect("ed25519 self-renewal must verify");
    cases.push(json!({
        "name": "ed25519_self_renewal",
        "description": "app-key-a (Ed25519, can sign) renews its own attestation by signing possession_signature_input(renewal_bytes) directly. No sibling quorum is used.",
        "target": key_ref_json(&a.key_ref()),
        "sibling_keys": Vec::<Value>::new(),
        "renewal_cbor_hex": hex(&ed_bytes),
        "renewal_signature_input_cbor_hex": hex(&ed_signature_input),
        "possession_signature_input_cbor_hex": hex(&ed_possession_input),
        "signed": signed_json(&ed_signed),
        "now": rfc3339(now),
        "skew_seconds": SKEW_SECONDS,
        "expected_valid": true,
    }));

    // X25519 sibling-signed renewal: the target cannot sign for itself, so a
    // sibling signing key vouches for it (RENEWAL_QUORUM = 1).
    let x_renewal = renewal_for(agree.key_id, "renewal-challenge-x25519");
    let x_bytes = generated::encode_application_key_renewal(&x_renewal);
    let x_signature_input = ak::renewal_signature_input(&x_bytes);
    let x_possession_input = ak::possession_signature_input(&x_bytes);
    let x_signed = ak::sign_renewal(&x_renewal, &[a.signer()], None).unwrap();
    let sibling_keys = vec![a.key_ref()];
    ak::verify_renewal(
        &x_signed,
        &agree.key_ref(),
        &sibling_keys,
        &instance(),
        now,
        SKEW_SECONDS,
    )
    .expect("x25519 sibling-signed renewal must verify");
    cases.push(json!({
        "name": "x25519_sibling_renewal",
        "description": "app-key-agree (X25519, cannot sign) is renewed on a sibling signature from app-key-a, meeting RENEWAL_QUORUM = 1. No possession_proof is present.",
        "target": key_ref_json(&agree.key_ref()),
        "sibling_keys": [a.key_ref_json()],
        "renewal_cbor_hex": hex(&x_bytes),
        "renewal_signature_input_cbor_hex": hex(&x_signature_input),
        "possession_signature_input_cbor_hex": hex(&x_possession_input),
        "signed": signed_json(&x_signed),
        "now": rfc3339(now),
        "skew_seconds": SKEW_SECONDS,
        "expected_valid": true,
    }));

    // Negative: no possession proof and no sibling signature at all.
    let unsigned_renewal = renewal_for(a.key_id, "renewal-challenge-none");
    let unsigned_bytes = generated::encode_application_key_renewal(&unsigned_renewal);
    let unsigned_signed = ak::sign_renewal(&unsigned_renewal, &[], None).unwrap();
    assert_eq!(
        ak::verify_renewal(
            &unsigned_signed,
            &a.key_ref(),
            &[],
            &instance(),
            now,
            SKEW_SECONDS
        ),
        Err(ApplicationKeyError::MissingPossessionProof)
    );
    let negative_cases = vec![json!({
        "name": "no_possession_proof",
        "description": "app-key-a's renewal request carries neither a possession_proof nor any sibling signature. An Ed25519 target's renewal MUST carry current proof of possession.",
        "target": key_ref_json(&a.key_ref()),
        "sibling_keys": Vec::<Value>::new(),
        "renewal_cbor_hex": hex(&unsigned_bytes),
        "signed": signed_json(&unsigned_signed),
        "now": rfc3339(now),
        "skew_seconds": SKEW_SECONDS,
        "expected_valid": false,
    })];

    json!({
        "note": "ApplicationKeyRenewal: renews the attestation of an EXISTING key without creating a new one. An Ed25519 target proves current possession by signing for itself; an X25519 target cannot sign, so a sibling signing key vouches for it instead (RENEWAL_QUORUM = 1). ALL KEYS IN THIS FILE ARE FIXED, PUBLICLY-KNOWN TEST-ONLY MATERIAL. Never reuse any key here for anything real.",
        "renewal_tag": ak::RENEWAL_TAG,
        "possession_tag": ak::POSSESSION_TAG,
        "renewal_quorum": ak::RENEWAL_QUORUM,
        "instance": instance_json(),
        "keys": {
            "app_key_a": {
                "key_id": a.key_id,
                "seed_hex": hex(&a.seed),
                "private_key_hex": hex(&a.private_key),
                "public_key_hex": hex(&a.public_key),
                "fingerprint": a.fingerprint,
            },
            "app_key_agree": {
                "key_id": agree.key_id,
                "algorithm": "x25519",
                "seed_hex": hex(&agree.seed),
                "private_key_hex": hex(&agree.private_key),
                "public_key_hex": hex(&agree.public_key),
                "fingerprint": agree.fingerprint,
            },
        },
        "cases": cases,
        "negative_cases": negative_cases,
    })
}

// ---------------------------------------------------------------------
// application_key_revocation.json
// ---------------------------------------------------------------------

fn revocation_vectors() -> Value {
    let a = ed25519_fixture(KEY_A_ID, KEY_A_SEED);
    let b = ed25519_fixture(KEY_B_ID, KEY_B_SEED);
    let c = ed25519_fixture(KEY_C_ID, KEY_C_SEED);
    let target = c; // the key being revoked

    let keys = vec![a.key_ref(), b.key_ref(), target.key_ref()];
    let keys_json = vec![a.key_ref_json(), b.key_ref_json(), target.key_ref_json()];

    let revoked_at = rfc3339(base_instant() + Duration::days(1));

    let payload = ak::revocation_payload(
        SUBJECT,
        DOMAIN,
        APPLICATION_ID,
        INSTANCE_ID,
        target.key_id,
        &target.fingerprint,
        &revoked_at,
    );

    let revocation_json = |rev: &liblinkkeys::generated::types::ApplicationKeyRevocation| {
        json!({
            "subject_user_id": rev.subject_user_id,
            "subject_domain": rev.subject_domain,
            "application_id": rev.application_id,
            "instance_id": rev.instance_id,
            "target_key_id": rev.target_key_id,
            "target_fingerprint": rev.target_fingerprint,
            "revoked_at": rev.revoked_at,
            "signatures": rev.signatures.iter().map(|sig| json!({
                "signed_by_key_id": sig.signed_by_key_id,
                "signature_hex": hex(&sig.signature),
            })).collect::<Vec<_>>(),
            "revocation_cbor_hex": hex(&generated::encode_application_key_revocation(rev)),
        })
    };

    // Positive: two distinct siblings revoke the target.
    let valid = ak::sign_revocation(
        &instance(),
        target.key_id,
        &target.fingerprint,
        &revoked_at,
        &[a.signer(), b.signer()],
    )
    .unwrap();
    ak::verify_revocation(&valid, &keys, &instance()).expect("two-sibling revocation must verify");

    let mut negative_cases = Vec::new();

    // One signature: below REVOCATION_QUORUM.
    {
        let one = ak::sign_revocation(
            &instance(),
            target.key_id,
            &target.fingerprint,
            &revoked_at,
            &[a.signer()],
        )
        .unwrap();
        assert_eq!(
            ak::verify_revocation(&one, &keys, &instance()),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
        negative_cases.push(json!({
            "name": "one_signature_insufficient",
            "description": "Only app-key-a signed. One valid signer is below REVOCATION_QUORUM = 2.",
            "revocation": revocation_json(&one),
            "expected_valid": false,
        }));
    }

    // The target signs its own revocation; must never count.
    {
        let self_rev = ak::sign_revocation(
            &instance(),
            target.key_id,
            &target.fingerprint,
            &revoked_at,
            &[a.signer(), target.signer()],
        )
        .unwrap();
        assert_eq!(
            ak::verify_revocation(&self_rev, &keys, &instance()),
            Err(ApplicationKeyError::InsufficientSignatures { got: 1, need: 2 })
        );
        negative_cases.push(json!({
            "name": "target_signs_own_revocation",
            "description": "app-key-a plus the TARGET key (app-key-c) itself. The target's signature is cryptographically valid but a key can never authorize its own revocation, so only app-key-a counts.",
            "revocation": revocation_json(&self_rev),
            "expected_valid": false,
        }));
    }

    // Tampered revoked_at: both signatures now cover stale payload bytes.
    {
        let mut tampered = valid.clone();
        tampered.revoked_at = rfc3339(base_instant() + Duration::days(2));
        assert!(
            ak::verify_revocation(&tampered, &keys, &instance()).is_err(),
            "a revocation whose revoked_at changed after signing must not verify"
        );
        negative_cases.push(json!({
            "name": "tampered_revoked_at",
            "description": "A valid two-signer revocation whose revoked_at field was changed AFTER signing. The recomputed payload no longer matches either signature, so zero signers count.",
            "revocation": revocation_json(&tampered),
            "expected_valid": false,
        }));
    }

    json!({
        "note": "ApplicationKeyRevocation: two DISTINCT, currently-valid sibling signing keys revoke a target key, which never signs or counts toward its own revocation. Unlike the attestation/addition/renewal envelopes, the signed payload is built from the revocation's FIELDS (revocation_payload), not stored raw bytes -- CBOR([tag, subject_user_id, subject_domain, application_id, instance_id, target_key_id, target_fingerprint, revoked_at]), a SEVEN-element array with the tag first (not counting the array wrapper). ALL KEYS IN THIS FILE ARE FIXED, PUBLICLY-KNOWN TEST-ONLY MATERIAL. Never reuse any key here for anything real.",
        "tag": ak::REVOCATION_TAG,
        "quorum": ak::REVOCATION_QUORUM,
        "instance": instance_json(),
        "keys": keys_json,
        "target_key_id": target.key_id,
        "target_fingerprint": target.fingerprint,
        "revoked_at": revoked_at,
        "revocation_payload_cbor_hex": hex(&payload),
        "signer_keys": {
            "app_key_a": { "key_id": a.key_id, "seed_hex": hex(&a.seed), "private_key_hex": hex(&a.private_key), "public_key_hex": hex(&a.public_key), "fingerprint": a.fingerprint },
            "app_key_b": { "key_id": b.key_id, "seed_hex": hex(&b.seed), "private_key_hex": hex(&b.private_key), "public_key_hex": hex(&b.public_key), "fingerprint": b.fingerprint },
            "app_key_c_target": { "key_id": target.key_id, "seed_hex": hex(&target.seed), "private_key_hex": hex(&target.private_key), "public_key_hex": hex(&target.public_key), "fingerprint": target.fingerprint },
        },
        "cases": [{
            "name": "two_sibling_revocation",
            "description": "app-key-a and app-key-b (two distinct, currently-valid sibling signing keys) revoke app-key-c. Meets REVOCATION_QUORUM = 2.",
            "revocation": revocation_json(&valid),
            "expected_valid": true,
        }],
        "negative_cases": negative_cases,
    })
}

// ---------------------------------------------------------------------
// application_key_sealed_challenge.json
// ---------------------------------------------------------------------

fn sealed_challenge_vectors() -> Value {
    let recipient = x25519_fixture("challenge-recipient", CHALLENGE_RECIPIENT_SEED);
    let wrong_recipient =
        x25519_fixture("challenge-wrong-recipient", CHALLENGE_WRONG_RECIPIENT_SEED);

    let sealed = ak::seal_challenge_with_randomness(
        &CHALLENGE_NONCE,
        &recipient.public_key,
        &CHALLENGE_EPHEMERAL_SEED,
        &CHALLENGE_AEAD_NONCE,
    )
    .unwrap();

    // Generator sanity: the real implementation must open it with the right
    // key and refuse it with the wrong one.
    let opened = ak::open_challenge(&sealed, &recipient.private_key).unwrap();
    assert_eq!(opened.as_slice(), &CHALLENGE_NONCE[..]);
    assert!(ak::open_challenge(&sealed, &wrong_recipient.private_key).is_err());

    let mut corrupted_sealed = sealed.clone();
    *corrupted_sealed.last_mut().unwrap() ^= 0xff;
    assert!(
        ak::open_challenge(&corrupted_sealed, &recipient.private_key).is_err(),
        "a corrupted sealed challenge must not open"
    );

    json!({
        "note": "seal_challenge: the home domain's proof-of-possession exchange for an X25519 (key-agreement) key, which cannot sign for itself. `sealed_cbor_hex` is CBOR([suite: tstr, ephemeral_public_key: bstr, aead_nonce: bstr, ciphertext: bstr]) -- a FOUR-element array. Production code draws the ephemeral X25519 key and AEAD nonce from the OS RNG (seal_challenge); this vector was produced with the deterministic seam seal_challenge_with_randomness so the ciphertext is byte-stable across regeneration. ALL KEYS IN THIS FILE ARE FIXED, PUBLICLY-KNOWN TEST-ONLY MATERIAL. Never reuse any key here for anything real.",
        "suite": ak::CHALLENGE_SEAL_SUITE.as_str(),
        "nonce_hex": hex(&CHALLENGE_NONCE),
        "ephemeral_private_key_hex": hex(&CHALLENGE_EPHEMERAL_SEED),
        "aead_nonce_hex": hex(&CHALLENGE_AEAD_NONCE),
        "recipient": {
            "key_id": recipient.key_id,
            "seed_hex": hex(&recipient.seed),
            "private_key_hex": hex(&recipient.private_key),
            "public_key_hex": hex(&recipient.public_key),
        },
        "wrong_recipient": {
            "key_id": wrong_recipient.key_id,
            "seed_hex": hex(&wrong_recipient.seed),
            "private_key_hex": hex(&wrong_recipient.private_key),
            "public_key_hex": hex(&wrong_recipient.public_key),
        },
        "sealed_cbor_hex": hex(&sealed),
        "cases": [
            {
                "name": "opens_with_correct_key",
                "recipient_private_key_hex": hex(&recipient.private_key),
                "expected_valid": true,
                "expected_plaintext_hex": hex(&CHALLENGE_NONCE),
            },
        ],
        "negative_cases": [
            {
                "name": "refused_by_wrong_key",
                "description": "The same sealed challenge opened with a DIFFERENT, real X25519 private key than the one it was sealed to.",
                "recipient_private_key_hex": hex(&wrong_recipient.private_key),
                "expected_valid": false,
            },
            {
                "name": "refused_when_corrupted",
                "description": "The sealed challenge bytes with the last byte flipped (part of the AEAD ciphertext/tag), opened with the CORRECT key.",
                "sealed_cbor_hex": hex(&corrupted_sealed),
                "recipient_private_key_hex": hex(&recipient.private_key),
                "expected_valid": false,
            },
        ],
    })
}
