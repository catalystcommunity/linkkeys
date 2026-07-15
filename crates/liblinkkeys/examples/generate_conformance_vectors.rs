//! Generates the DNS-less local-RP conformance vectors checked into
//! `sdks/local-rp/conformance/` (dns-less-local-rp-design.md, Phase 8).
//!
//! Every SDK in every language implements the wire constructions documented
//! in the design doc's "Wire Precision (Normative)" section against these
//! vectors. `liblinkkeys` itself is "consumer zero": see
//! `crates/liblinkkeys/tests/conformance.rs`, which reads these same files
//! back and verifies every case against the real implementation.
//!
//! ## Determinism
//!
//! All key material is FIXED test-only seeds (hardcoded below, never used in
//! production). All timestamps are fixed constants. The one wire
//! construction with real randomness in production — the callback sealed
//! box's ephemeral X25519 key and AEAD nonce — is generated here via
//! [`liblinkkeys::local_rp::seal_local_rp_callback_with_randomness`], which
//! takes those values as explicit parameters instead of sourcing them from
//! the OS RNG. Ed25519 signing needs no such treatment: EdDSA signing is
//! fully deterministic by construction.
//!
//! Running this generator twice must produce byte-identical output. That is
//! the whole point: the checked-in JSON is not just an example, it is *the*
//! output for these fixed inputs.
//!
//! ## Usage
//!
//! ```sh
//! cargo run -p liblinkkeys --example generate_conformance_vectors
//! # or, to write elsewhere:
//! cargo run -p liblinkkeys --example generate_conformance_vectors -- /tmp/out
//! ```
//!
//! With no argument, output goes to `sdks/local-rp/conformance/` relative to
//! the repo root (resolved via `CARGO_MANIFEST_DIR`, not the process's
//! current directory).

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use liblinkkeys::claims::{self, ClaimSigner, ClaimSpec, DomainKeySet};
use liblinkkeys::crypto::{self, AeadSuite, SigningAlgorithm};
use liblinkkeys::dns::{self, DnsParseError};
use liblinkkeys::encoding;
use liblinkkeys::generated;
use liblinkkeys::generated::types::{
    Claim, ClaimSignature, DomainPublicKey, LocalRpCallbackHeader, LocalRpEncryptedCallback,
    LocalRpTicketRedemptionResponse, RevocationCertificate,
};
use liblinkkeys::local_rp::{self, CTX_LOCAL_RP_CALLBACK, CTX_LOCAL_RP_DESCRIPTOR};
use liblinkkeys::local_rp::{CTX_LOCAL_RP_LOGIN_REQUEST, CTX_LOCAL_RP_TICKET_REDEMPTION};
use liblinkkeys::revocation;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

// ---------------------------------------------------------------------
// Fixed test-only key material. NEVER use these seeds for anything real.
// ---------------------------------------------------------------------

const LOCAL_RP_SIGNING_SEED: [u8; 32] = [0x01; 32];
const LOCAL_RP_ENCRYPTION_SEED: [u8; 32] = [0x02; 32];
const DOMAIN_SIGNING_SEED: [u8; 32] = [0x03; 32];
const DOMAIN_ENCRYPTION_RECIPIENT_SEED: [u8; 32] = [0x04; 32];

const EPHEMERAL_SEED_AES: [u8; 32] = [0x05; 32];
const EPHEMERAL_SEED_CHACHA: [u8; 32] = [0x06; 32];
const AEAD_NONCE_AES: [u8; 12] = [0x07; 12];
const AEAD_NONCE_CHACHA: [u8; 12] = [0x08; 12];

const DOMAIN_SIGNING_KEY_ID: &str = "test-domain-key-1";

// Sibling signing keys for revocations.json: a domain with three active
// signing keys (sibling 3 is the revocation target), plus one expired and one
// already-revoked sibling whose signatures must never count toward quorum.
const SIBLING_1_SEED: [u8; 32] = [0x09; 32];
const SIBLING_2_SEED: [u8; 32] = [0x0a; 32];
const SIBLING_3_SEED: [u8; 32] = [0x0b; 32]; // the revocation target
const SIBLING_EXPIRED_SEED: [u8; 32] = [0x0c; 32];
const SIBLING_REVOKED_SEED: [u8; 32] = [0x0d; 32];

const SIBLING_1_KEY_ID: &str = "sibling-key-1";
const SIBLING_2_KEY_ID: &str = "sibling-key-2";
const SIBLING_3_KEY_ID: &str = "sibling-key-3";
const SIBLING_EXPIRED_KEY_ID: &str = "sibling-key-expired";
const SIBLING_REVOKED_KEY_ID: &str = "sibling-key-revoked";

// Claim-signer keys for claims.json: two valid signing keys of the fixture
// domain, plus a third key used only to supply a WRONG public key under
// claim-key-1's key id in the wrong-signer-key negative case.
const CLAIM_KEY_1_SEED: [u8; 32] = [0x0e; 32];
const CLAIM_KEY_2_SEED: [u8; 32] = [0x0f; 32];
const CLAIM_WRONG_KEY_SEED: [u8; 32] = [0x10; 32];

const CLAIM_KEY_1_ID: &str = "claim-key-1";
const CLAIM_KEY_2_ID: &str = "claim-key-2";

// Fixed fixture strings shared across every vector file, so a reader can
// cross-reference (e.g. the same nonce/state appear in the login request,
// the callback header, and the callback payload, exactly as a real flow
// would bind them together).
const NONCE: [u8; 16] = [0xaa; 16];
const STATE: [u8; 16] = [0xbb; 16];
const CLAIM_TICKET: [u8; 32] = [0xcc; 32];
const CALLBACK_URL: &str = "http://127.0.0.1:8080/callback";
const USER_ID: &str = "conformance-user-1";
const USER_DOMAIN: &str = "conformance.example";
const APP_NAME: &str = "Conformance Test App";

// Fixed instants (RFC3339, UTC). Everything else is derived by offset so the
// whole vector set has one time anchor.
fn base_instant() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00")
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
    public_key: [u8; 32],
    private_key: [u8; 32],
    fingerprint: String,
}

fn ed25519_fixture(seed: [u8; 32]) -> Ed25519Fixture {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    Ed25519Fixture {
        public_key: *pk.as_bytes(),
        private_key: sk.to_bytes(),
        fingerprint: crypto::fingerprint(pk.as_bytes()),
    }
}

struct X25519Fixture {
    public_key: [u8; 32],
    private_key: [u8; 32],
}

fn x25519_fixture(seed: [u8; 32]) -> X25519Fixture {
    let sk = X25519StaticSecret::from(seed);
    let pk = X25519PublicKey::from(&sk);
    X25519Fixture {
        public_key: *pk.as_bytes(),
        private_key: seed,
    }
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
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdks/local-rp/conformance"),
    };
    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|e| panic!("create {}: {}", out_dir.display(), e));

    let local_rp_signing = ed25519_fixture(LOCAL_RP_SIGNING_SEED);
    let local_rp_encryption = x25519_fixture(LOCAL_RP_ENCRYPTION_SEED);
    let domain_signing = ed25519_fixture(DOMAIN_SIGNING_SEED);
    let domain_encryption_recipient = x25519_fixture(DOMAIN_ENCRYPTION_RECIPIENT_SEED);

    write_json(
        &out_dir,
        "keys.json",
        &keys_json(
            &local_rp_signing,
            &local_rp_encryption,
            &domain_signing,
            &domain_encryption_recipient,
        ),
    );

    let envelopes = envelopes_json(&local_rp_signing, &local_rp_encryption, &domain_signing);
    write_json(&out_dir, "envelopes.json", &envelopes.json);

    let callback_box = callback_box_json(
        &local_rp_signing,
        &local_rp_encryption,
        &domain_encryption_recipient,
        &envelopes,
    );
    write_json(&out_dir, "callback_box.json", &callback_box.json);

    write_json(
        &out_dir,
        "url_params.json",
        &url_params_json(&envelopes, &callback_box),
    );

    write_json(
        &out_dir,
        "dns.json",
        &dns_json(&local_rp_signing, &domain_signing),
    );

    write_json(&out_dir, "tickets.json", &tickets_json());

    write_json(&out_dir, "expirations.json", &expirations_json());

    write_json(&out_dir, "revocations.json", &revocations_json());

    write_json(&out_dir, "claims.json", &claims_json());

    println!("done.");
}

// ---------------------------------------------------------------------
// keys.json
// ---------------------------------------------------------------------

fn keys_json(
    local_rp_signing: &Ed25519Fixture,
    local_rp_encryption: &X25519Fixture,
    domain_signing: &Ed25519Fixture,
    domain_encryption_recipient: &X25519Fixture,
) -> Value {
    json!({
        "note": "ALL KEYS IN THIS FILE ARE FIXED, PUBLICLY-KNOWN TEST-ONLY MATERIAL (hardcoded 32-byte seeds, e.g. 0x01 repeated). Never use any key in this file for anything real.",
        "local_rp": {
            "signing": {
                "algorithm": "ed25519",
                "seed_hex": hex(&LOCAL_RP_SIGNING_SEED),
                "private_key_hex": hex(&local_rp_signing.private_key),
                "public_key_hex": hex(&local_rp_signing.public_key),
                "fingerprint_hex": local_rp_signing.fingerprint,
            },
            "encryption": {
                "algorithm": "x25519",
                "private_key_hex": hex(&local_rp_encryption.private_key),
                "public_key_hex": hex(&local_rp_encryption.public_key),
            },
        },
        "domain_signing_key": {
            "key_id": DOMAIN_SIGNING_KEY_ID,
            "algorithm": "ed25519",
            "seed_hex": hex(&DOMAIN_SIGNING_SEED),
            "private_key_hex": hex(&domain_signing.private_key),
            "public_key_hex": hex(&domain_signing.public_key),
            "fingerprint_hex": domain_signing.fingerprint,
        },
        "domain_encryption_recipient": {
            "algorithm": "x25519",
            "private_key_hex": hex(&domain_encryption_recipient.private_key),
            "public_key_hex": hex(&domain_encryption_recipient.public_key),
            "note": "Not the callback box's real recipient (that is local_rp.encryption). Provided as a second, distinct X25519 keypair so callback_box.json can vector a 'valid ciphertext, wrong recipient key' negative case.",
        },
    })
}

// ---------------------------------------------------------------------
// envelopes.json
// ---------------------------------------------------------------------

struct EnvelopesOutput {
    json: Value,
    /// The signed callback-payload envelope, exposed so callback_box.json can
    /// seal exactly this envelope as its plaintext.
    signed_callback_payload: liblinkkeys::generated::types::SignedLocalRpCallbackPayload,
    /// The signed login request, exposed so url_params.json can encode it.
    signed_login_request: liblinkkeys::generated::types::SignedLocalRpLoginRequest,
}

fn envelopes_json(
    local_rp_signing: &Ed25519Fixture,
    local_rp_encryption: &X25519Fixture,
    domain_signing: &Ed25519Fixture,
) -> EnvelopesOutput {
    let base = base_instant();
    let descriptor_created = base;
    let descriptor_expires = base + Duration::days(3650);
    let login_issued = base + Duration::minutes(5);
    let login_expires = login_issued + Duration::minutes(5);
    let callback_issued = login_issued + Duration::minutes(1);
    let callback_expires = callback_issued + Duration::minutes(5);
    let ticket_issued = callback_issued + Duration::minutes(1);

    // --- descriptor ---
    let descriptor = local_rp::build_local_rp_descriptor(
        APP_NAME,
        None,
        &local_rp_signing.public_key,
        &local_rp_encryption.public_key,
        vec![
            crypto::AEAD_SUITE_AES_256_GCM.to_string(),
            crypto::AEAD_SUITE_CHACHA20_POLY1305.to_string(),
        ],
        &rfc3339(descriptor_created),
        &rfc3339(descriptor_expires),
    );
    let descriptor_bytes = generated::encode_local_rp_descriptor(&descriptor);
    let signed_descriptor =
        local_rp::sign_local_rp_descriptor(&descriptor, &local_rp_signing.private_key).unwrap();

    // --- login request ---
    let login_request = local_rp::build_local_rp_login_request(
        signed_descriptor.clone(),
        CALLBACK_URL,
        NONCE.to_vec(),
        STATE.to_vec(),
        vec![
            "display_name".to_string(),
            "email".to_string(),
            "handle".to_string(),
        ],
        vec!["handle".to_string()],
        &rfc3339(login_issued),
        &rfc3339(login_expires),
    );
    let login_request_bytes = generated::encode_local_rp_login_request(&login_request);
    let signed_login_request =
        local_rp::sign_local_rp_login_request(&login_request, &local_rp_signing.private_key)
            .unwrap();

    // --- callback payload (domain-signed) ---
    let callback_payload = local_rp::build_local_rp_callback_payload(
        USER_ID,
        USER_DOMAIN,
        CLAIM_TICKET.to_vec(),
        &local_rp_signing.fingerprint,
        CALLBACK_URL,
        NONCE.to_vec(),
        STATE.to_vec(),
        &rfc3339(callback_issued),
        &rfc3339(callback_expires),
    );
    let callback_payload_bytes = generated::encode_local_rp_callback_payload(&callback_payload);
    let signed_callback_payload = local_rp::sign_local_rp_callback_payload(
        &callback_payload,
        DOMAIN_SIGNING_KEY_ID,
        SigningAlgorithm::Ed25519,
        &domain_signing.private_key,
    )
    .unwrap();

    // --- ticket redemption request (local-RP-signed) ---
    let ticket_request = local_rp::build_local_rp_ticket_redemption_request(
        CLAIM_TICKET.to_vec(),
        &local_rp_signing.fingerprint,
        &rfc3339(ticket_issued),
    );
    let ticket_request_bytes =
        generated::encode_local_rp_ticket_redemption_request(&ticket_request);
    let signed_ticket_request = local_rp::sign_local_rp_ticket_redemption_request(
        &ticket_request,
        &local_rp_signing.private_key,
    )
    .unwrap();

    struct Base {
        structure: &'static str,
        envelope_field: &'static str,
        context: &'static str,
        payload_bytes: Vec<u8>,
        signature: Vec<u8>,
        verify_key: [u8; 32],
        signing_key_id: Option<&'static str>,
    }

    let bases = vec![
        Base {
            structure: "descriptor",
            envelope_field: "descriptor",
            context: CTX_LOCAL_RP_DESCRIPTOR,
            payload_bytes: descriptor_bytes.clone(),
            signature: signed_descriptor.signature.clone(),
            verify_key: local_rp_signing.public_key,
            signing_key_id: None,
        },
        Base {
            structure: "login_request",
            envelope_field: "request",
            context: CTX_LOCAL_RP_LOGIN_REQUEST,
            payload_bytes: login_request_bytes.clone(),
            signature: signed_login_request.signature.clone(),
            verify_key: local_rp_signing.public_key,
            signing_key_id: None,
        },
        Base {
            structure: "callback_payload",
            envelope_field: "payload",
            context: CTX_LOCAL_RP_CALLBACK,
            payload_bytes: callback_payload_bytes.clone(),
            signature: signed_callback_payload.signature.clone(),
            verify_key: domain_signing.public_key,
            signing_key_id: Some(DOMAIN_SIGNING_KEY_ID),
        },
        Base {
            structure: "ticket_redemption",
            envelope_field: "request",
            context: CTX_LOCAL_RP_TICKET_REDEMPTION,
            payload_bytes: ticket_request_bytes.clone(),
            signature: signed_ticket_request.signature.clone(),
            verify_key: local_rp_signing.public_key,
            signing_key_id: None,
        },
    ];

    let all_contexts = [
        CTX_LOCAL_RP_DESCRIPTOR,
        CTX_LOCAL_RP_LOGIN_REQUEST,
        CTX_LOCAL_RP_CALLBACK,
        CTX_LOCAL_RP_TICKET_REDEMPTION,
    ];

    let mut cases = Vec::new();
    let mut negative_cases = Vec::new();

    for b in &bases {
        let sig_input = local_rp::envelope_signature_input(b.context, &b.payload_bytes);
        let mut case = json!({
            "structure": b.structure,
            "envelope_field": b.envelope_field,
            "context": b.context,
            "payload_cbor_hex": hex(&b.payload_bytes),
            "signature_input_cbor_hex": hex(&sig_input),
            "signature_hex": hex(&b.signature),
            "verify_key_hex": hex(&b.verify_key),
            "expected_valid": true,
        });
        if let Some(kid) = b.signing_key_id {
            case["signing_key_id"] = json!(kid);
        }
        cases.push(case);

        // Negative: tampered payload (flip last byte), original signature reused.
        let mut tampered_payload = b.payload_bytes.clone();
        *tampered_payload.last_mut().unwrap() ^= 0xff;
        let tampered_sig_input = local_rp::envelope_signature_input(b.context, &tampered_payload);
        negative_cases.push(json!({
            "name": format!("{}_tampered_payload", b.structure),
            "structure": b.structure,
            "description": "Last byte of the payload flipped; original signature reused.",
            "context": b.context,
            "payload_cbor_hex": hex(&tampered_payload),
            "signature_input_cbor_hex": hex(&tampered_sig_input),
            "signature_hex": hex(&b.signature),
            "verify_key_hex": hex(&b.verify_key),
            "expected_valid": false,
        }));

        // Negative: wrong verification key (a real, differently-keyed signer).
        let wrong_key = if b.structure == "callback_payload" {
            local_rp_signing.public_key
        } else {
            domain_signing.public_key
        };
        negative_cases.push(json!({
            "name": format!("{}_wrong_key", b.structure),
            "structure": b.structure,
            "description": "Verified against a real but different Ed25519 public key than the one that signed it.",
            "context": b.context,
            "payload_cbor_hex": hex(&b.payload_bytes),
            "signature_input_cbor_hex": hex(&sig_input),
            "signature_hex": hex(&b.signature),
            "verify_key_hex": hex(&wrong_key),
            "expected_valid": false,
        }));

        // Negative: signature presented under every OTHER structure's context.
        for &wrong_ctx in all_contexts.iter().filter(|c| **c != b.context) {
            let wrong_sig_input = local_rp::envelope_signature_input(wrong_ctx, &b.payload_bytes);
            negative_cases.push(json!({
                "name": format!("{}_signature_under_context_{}", b.structure, wrong_ctx),
                "structure": b.structure,
                "description": format!(
                    "The {} envelope's own (payload, signature) pair verified against a DIFFERENT context string ('{}') than the one it was actually signed under ('{}'). Must fail: a signature over one structure must never verify as another.",
                    b.structure, wrong_ctx, b.context
                ),
                "context": wrong_ctx,
                "payload_cbor_hex": hex(&b.payload_bytes),
                "signature_input_cbor_hex": hex(&wrong_sig_input),
                "signature_hex": hex(&b.signature),
                "verify_key_hex": hex(&b.verify_key),
                "expected_valid": false,
            }));
        }
    }

    let json = json!({
        "note": "Every signature-input is CBOR([context: tstr, payload: bstr]) — a two-element CBOR array, context first — per Wire Precision \"Signature input bytes\". `payload_cbor_hex` is the exact bytes shipped in the envelope's payload-carrying field (see `envelope_field`); `signature_input_cbor_hex` is CBOR([context, payload_cbor_hex]); `signature_hex` is the Ed25519 signature over `signature_input_cbor_hex`. All four structures use Ed25519 only.",
        "context_strings": {
            "descriptor": CTX_LOCAL_RP_DESCRIPTOR,
            "login_request": CTX_LOCAL_RP_LOGIN_REQUEST,
            "callback_payload": CTX_LOCAL_RP_CALLBACK,
            "ticket_redemption": CTX_LOCAL_RP_TICKET_REDEMPTION,
        },
        "timestamps": {
            "descriptor_created_at": rfc3339(descriptor_created),
            "descriptor_expires_at": rfc3339(descriptor_expires),
            "login_request_issued_at": rfc3339(login_issued),
            "login_request_expires_at": rfc3339(login_expires),
            "callback_payload_issued_at": rfc3339(callback_issued),
            "callback_payload_expires_at": rfc3339(callback_expires),
            "ticket_redemption_issued_at": rfc3339(ticket_issued),
        },
        "cases": cases,
        "negative_cases": negative_cases,
    });

    EnvelopesOutput {
        json,
        signed_callback_payload,
        signed_login_request,
    }
}

// ---------------------------------------------------------------------
// callback_box.json
// ---------------------------------------------------------------------

struct CallbackBoxOutput {
    json: Value,
    aes_encrypted: LocalRpEncryptedCallback,
}

fn callback_box_json(
    local_rp_signing: &Ed25519Fixture,
    local_rp_encryption: &X25519Fixture,
    domain_encryption_recipient: &X25519Fixture,
    envelopes: &EnvelopesOutput,
) -> CallbackBoxOutput {
    let base = base_instant();
    let callback_issued = base + Duration::minutes(6);
    let callback_expires = callback_issued + Duration::minutes(5);

    let plaintext_cbor =
        generated::encode_signed_local_rp_callback_payload(&envelopes.signed_callback_payload);

    let suites: [(AeadSuite, [u8; 32], [u8; 12]); 2] = [
        (AeadSuite::Aes256Gcm, EPHEMERAL_SEED_AES, AEAD_NONCE_AES),
        (
            AeadSuite::ChaCha20Poly1305,
            EPHEMERAL_SEED_CHACHA,
            AEAD_NONCE_CHACHA,
        ),
    ];

    // Wire Precision, "Callback sealed box": kdf/AAD context is
    // `tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)`,
    // tag `linkkeys-local-rp-callback-box`. Recomputed here (not exported
    // from `local_rp`, which keeps it private) purely so the vectors can
    // publish the intermediate KDF-context/AAD bytes for SDKs to unit-test
    // their own HKDF derivation independent of full decrypt.
    const CALLBACK_BOX_TAG: &[u8] = b"linkkeys-local-rp-callback-box";
    fn kdf_context(
        suite: AeadSuite,
        ephemeral_public: &[u8; 32],
        recipient_public: &[u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CALLBACK_BOX_TAG);
        out.extend_from_slice(suite.as_str().as_bytes());
        out.extend_from_slice(ephemeral_public);
        out.extend_from_slice(recipient_public);
        out
    }

    let mut positive_cases = Vec::new();
    let mut aes_encrypted_holder: Option<LocalRpEncryptedCallback> = None;
    let mut aes_header_bytes: Option<Vec<u8>> = None;

    for (suite, ephemeral_seed, aead_nonce) in suites {
        let ephemeral_public = X25519PublicKey::from(&X25519StaticSecret::from(ephemeral_seed));

        let encrypted = local_rp::seal_local_rp_callback_with_randomness(
            &envelopes.signed_callback_payload,
            suite,
            &local_rp_encryption.public_key,
            &local_rp_signing.fingerprint,
            NONCE.to_vec(),
            STATE.to_vec(),
            &rfc3339(callback_issued),
            &rfc3339(callback_expires),
            &ephemeral_seed,
            &aead_nonce,
        )
        .unwrap();

        let header: LocalRpCallbackHeader =
            generated::decode_local_rp_callback_header(&encrypted.header).unwrap();
        let ctx = kdf_context(
            suite,
            ephemeral_public.as_bytes(),
            &local_rp_encryption.public_key,
        );
        let mut aad = ctx.clone();
        aad.extend_from_slice(&encrypted.header);

        positive_cases.push(json!({
            "suite": suite.as_str(),
            "ephemeral_private_key_hex": hex(&ephemeral_seed),
            "ephemeral_public_key_hex": hex(ephemeral_public.as_bytes()),
            "aead_nonce_hex": hex(&aead_nonce),
            "recipient_public_key_hex": hex(&local_rp_encryption.public_key),
            "decrypt_private_key_hex": hex(&local_rp_encryption.private_key),
            "fingerprint": header.fingerprint,
            "nonce_hex": hex(&NONCE),
            "state_hex": hex(&STATE),
            "issued_at": rfc3339(callback_issued),
            "expires_at": rfc3339(callback_expires),
            "header_cbor_hex": hex(&encrypted.header),
            "kdf_context_hex": hex(&ctx),
            "aad_hex": hex(&aad),
            "plaintext_cbor_hex": hex(&plaintext_cbor),
            "ciphertext_hex": hex(&encrypted.ciphertext),
            "allowed_suites": ["aes-256-gcm", "chacha20-poly1305"],
            "expected_valid": true,
        }));

        if suite == AeadSuite::Aes256Gcm {
            aes_encrypted_holder = Some(encrypted.clone());
            aes_header_bytes = Some(encrypted.header.clone());
        }
    }

    let aes_encrypted = aes_encrypted_holder.expect("aes-256-gcm case recorded");
    let aes_header_bytes = aes_header_bytes.expect("aes-256-gcm header recorded");
    let aes_header: LocalRpCallbackHeader =
        generated::decode_local_rp_callback_header(&aes_header_bytes).unwrap();

    // --- negative cases, all built from the aes-256-gcm positive case ---
    let mut negative_cases = Vec::new();

    let reencode_with = |mutate: &dyn Fn(&mut LocalRpCallbackHeader)| -> Vec<u8> {
        let mut h = aes_header.clone();
        mutate(&mut h);
        generated::encode_local_rp_callback_header(&h)
    };

    type HeaderMutator = Box<dyn Fn(&mut LocalRpCallbackHeader)>;
    let header_field_flips: Vec<(&str, HeaderMutator)> = vec![
        (
            "fingerprint",
            Box::new(|h: &mut LocalRpCallbackHeader| {
                h.fingerprint = "swapped-fingerprint".to_string()
            }),
        ),
        (
            "nonce",
            Box::new(|h: &mut LocalRpCallbackHeader| h.nonce = vec![0xee; 16]),
        ),
        (
            "state",
            Box::new(|h: &mut LocalRpCallbackHeader| h.state = vec![0xef; 16]),
        ),
        (
            "suite",
            Box::new(|h: &mut LocalRpCallbackHeader| {
                h.suite = crypto::AEAD_SUITE_CHACHA20_POLY1305.to_string()
            }),
        ),
        (
            "issued_at",
            Box::new(|h: &mut LocalRpCallbackHeader| {
                h.issued_at = "2020-01-01T00:00:00+00:00".to_string()
            }),
        ),
        (
            "expires_at",
            Box::new(|h: &mut LocalRpCallbackHeader| {
                h.expires_at = "2020-01-01T00:05:00+00:00".to_string()
            }),
        ),
        (
            "ephemeral_public_key",
            Box::new(|h: &mut LocalRpCallbackHeader| {
                let mut k = h.ephemeral_public_key.clone();
                k[0] ^= 0xff;
                h.ephemeral_public_key = k;
            }),
        ),
        (
            "aead_nonce",
            Box::new(|h: &mut LocalRpCallbackHeader| {
                let mut n = h.aead_nonce.clone();
                n[0] ^= 0xff;
                h.aead_nonce = n;
            }),
        ),
    ];

    for (field, mutate) in &header_field_flips {
        let tampered_header = reencode_with(mutate.as_ref());
        negative_cases.push(json!({
            "name": format!("header_{}_flip_fails_aad", field),
            "description": format!("Cleartext header field `{}` changed after sealing; ciphertext left untouched. The header is bound as AEAD associated data, so any change must fail authentication.", field),
            "header_cbor_hex": hex(&tampered_header),
            "ciphertext_hex": hex(&aes_encrypted.ciphertext),
            "decrypt_private_key_hex": hex(&local_rp_encryption.private_key),
            "allowed_suites": ["aes-256-gcm", "chacha20-poly1305"],
            "expected_valid": false,
        }));
    }

    // Unadvertised suite: chacha20-poly1305 case is validly encrypted, but the
    // caller (the local RP) only advertised/allows aes-256-gcm.
    let chacha_case = positive_cases
        .iter()
        .find(|c| c["suite"] == "chacha20-poly1305")
        .unwrap()
        .clone();
    negative_cases.push(json!({
        "name": "unadvertised_suite_rejected",
        "description": "Validly encrypted with chacha20-poly1305, but the decrypting side's own allowed/advertised suite list is aes-256-gcm only. Must be rejected even though chacha20-poly1305 is a real registry suite.",
        "header_cbor_hex": chacha_case["header_cbor_hex"],
        "ciphertext_hex": chacha_case["ciphertext_hex"],
        "decrypt_private_key_hex": hex(&local_rp_encryption.private_key),
        "allowed_suites": ["aes-256-gcm"],
        "expected_valid": false,
    }));

    // Unknown suite id: not in the registry at all.
    let unknown_suite_header =
        reencode_with(&|h: &mut LocalRpCallbackHeader| h.suite = "made-up-suite".to_string());
    negative_cases.push(json!({
        "name": "unknown_suite_id_rejected",
        "description": "Header advertises a suite id outside the registry entirely (not aes-256-gcm or chacha20-poly1305).",
        "header_cbor_hex": hex(&unknown_suite_header),
        "ciphertext_hex": hex(&aes_encrypted.ciphertext),
        "decrypt_private_key_hex": hex(&local_rp_encryption.private_key),
        "allowed_suites": ["aes-256-gcm", "chacha20-poly1305"],
        "expected_valid": false,
    }));

    // Low-order ephemeral key: an all-zero X25519 public key forces an
    // all-zero ECDH shared secret regardless of the recipient's private key.
    let low_order_header =
        reencode_with(&|h: &mut LocalRpCallbackHeader| h.ephemeral_public_key = vec![0u8; 32]);
    negative_cases.push(json!({
        "name": "low_order_ephemeral_key_rejected",
        "description": "Header's ephemeral_public_key replaced with an all-zero (low-order) X25519 point, which forces an all-zero ECDH shared secret. Must be rejected outright, not merely fail to decrypt.",
        "header_cbor_hex": hex(&low_order_header),
        "ciphertext_hex": hex(&aes_encrypted.ciphertext),
        "decrypt_private_key_hex": hex(&local_rp_encryption.private_key),
        "allowed_suites": ["aes-256-gcm", "chacha20-poly1305"],
        "expected_valid": false,
    }));

    // Wrong recipient key: correctly-formed ciphertext, but the private key
    // attempting to open it is not the one it was sealed to.
    negative_cases.push(json!({
        "name": "wrong_recipient_key_rejected",
        "description": "A validly-sealed aes-256-gcm callback opened with a DIFFERENT (but real) X25519 private key than the one it was encrypted to.",
        "header_cbor_hex": hex(&aes_header_bytes),
        "ciphertext_hex": hex(&aes_encrypted.ciphertext),
        "decrypt_private_key_hex": hex(&domain_encryption_recipient.private_key),
        "allowed_suites": ["aes-256-gcm", "chacha20-poly1305"],
        "expected_valid": false,
    }));

    // Truncated ciphertext.
    let mut truncated = aes_encrypted.ciphertext.clone();
    truncated.truncate(truncated.len().saturating_sub(4));
    negative_cases.push(json!({
        "name": "truncated_ciphertext_rejected",
        "description": "Last 4 bytes of the ciphertext (part of the AEAD authentication tag) dropped.",
        "header_cbor_hex": hex(&aes_header_bytes),
        "ciphertext_hex": hex(&truncated),
        "decrypt_private_key_hex": hex(&local_rp_encryption.private_key),
        "allowed_suites": ["aes-256-gcm", "chacha20-poly1305"],
        "expected_valid": false,
    }));

    let json = json!({
        "note": "Both suites seal the SAME plaintext (envelopes.json's callback_payload case, re-wrapped as a SignedLocalRpCallbackPayload envelope) to local_rp.encryption from keys.json. Ephemeral X25519 keys and AEAD nonces are FIXED test constants here (see generator source) so ciphertexts are byte-stable across regeneration; production code always uses fresh randomness (see seal_local_rp_callback vs. seal_local_rp_callback_with_randomness in crates/liblinkkeys/src/local_rp.rs).",
        "kdf": {
            "tag": "linkkeys-local-rp-callback-box",
            "info_and_aad_prefix_layout": "tag || suite_id_utf8 || ephemeral_public_key(32) || recipient_public_key(32)",
            "kdf_algorithm": "HKDF-SHA256, no salt, expand to 32 bytes",
            "aad_layout": "kdf_context || header_cbor_bytes",
        },
        "positive_cases": positive_cases,
        "negative_cases": negative_cases,
    });

    CallbackBoxOutput {
        json,
        aes_encrypted,
    }
}

// ---------------------------------------------------------------------
// url_params.json
// ---------------------------------------------------------------------

fn url_params_json(envelopes: &EnvelopesOutput, callback_box: &CallbackBoxOutput) -> Value {
    let signed_request_cbor =
        generated::encode_signed_local_rp_login_request(&envelopes.signed_login_request);
    let signed_request_b64 =
        encoding::signed_local_rp_login_request_to_url_param(&envelopes.signed_login_request)
            .unwrap();
    assert_eq!(
        Base64UrlUnpadded::encode_string(&signed_request_cbor),
        signed_request_b64
    );

    let encrypted_callback_cbor =
        generated::encode_local_rp_encrypted_callback(&callback_box.aes_encrypted);
    let encrypted_callback_b64 =
        encoding::local_rp_encrypted_callback_to_url_param(&callback_box.aes_encrypted).unwrap();
    assert_eq!(
        Base64UrlUnpadded::encode_string(&encrypted_callback_cbor),
        encrypted_callback_b64
    );

    // Negative: append standard base64 padding to an otherwise-valid unpadded
    // string. The unpadded decoder must reject the '=' character.
    let padded = format!("{}=", signed_request_b64);
    assert!(
        Base64UrlUnpadded::decode_vec(&padded).is_err(),
        "padded input unexpectedly decoded"
    );

    // Negative: swap a url-safe alphabet character for its standard-alphabet
    // counterpart ('-' -> '+', or '_' -> '/'). The url-safe decoder must
    // reject standard-alphabet characters.
    let standard_alphabet = if let Some(pos) = signed_request_b64.find('-') {
        let mut s = signed_request_b64.clone();
        s.replace_range(pos..pos + 1, "+");
        s
    } else if let Some(pos) = signed_request_b64.find('_') {
        let mut s = signed_request_b64.clone();
        s.replace_range(pos..pos + 1, "/");
        s
    } else {
        panic!("signed_request_b64 contains neither '-' nor '_' to substitute");
    };
    assert!(
        Base64UrlUnpadded::decode_vec(&standard_alphabet).is_err(),
        "standard-alphabet input unexpectedly decoded"
    );

    json!({
        "note": "base64url, UNPADDED (RFC 4648 Table 2 alphabet: '-' and '_' in place of '+' and '/'; no trailing '=' padding characters).",
        "cases": [
            {
                "name": "signed_local_rp_login_request",
                "description": "GET /auth/local-rp?signed_request=<this> — CBOR encoding of the outer SignedLocalRpLoginRequest envelope (envelopes.json's login_request case).",
                "cbor_hex": hex(&signed_request_cbor),
                "base64url_unpadded": signed_request_b64,
            },
            {
                "name": "local_rp_encrypted_callback",
                "description": "Callback redirect's `encrypted_token=<this>` query parameter — CBOR encoding of LocalRpEncryptedCallback (callback_box.json's aes-256-gcm positive case).",
                "cbor_hex": hex(&encrypted_callback_cbor),
                "base64url_unpadded": encrypted_callback_b64,
            },
        ],
        "negative_cases": [
            {
                "name": "padded_base64_rejected",
                "description": "A single '=' padding character appended to an otherwise-valid unpadded string. An unpadded base64url decoder must reject it.",
                "input": padded,
                "expected_valid": false,
            },
            {
                "name": "standard_alphabet_rejected",
                "description": "One url-safe alphabet character ('-' or '_') replaced with its standard-base64 counterpart ('+' or '/'). A url-safe decoder must reject it.",
                "input": standard_alphabet,
                "expected_valid": false,
            },
        ],
    })
}

// ---------------------------------------------------------------------
// dns.json
// ---------------------------------------------------------------------

fn linkkeys_error_code(e: &DnsParseError) -> &'static str {
    match e {
        DnsParseError::NoLinkKeysRecord => "no_linkkeys_record",
        DnsParseError::MissingVersion => "missing_version",
        DnsParseError::UnsupportedVersion(_) => "unsupported_version",
        DnsParseError::MissingApisEndpoint => "missing_apis_endpoint",
        DnsParseError::InvalidFormat(_) => "invalid_format",
    }
}

fn dns_json(local_rp_signing: &Ed25519Fixture, domain_signing: &Ed25519Fixture) -> Value {
    let fp_a = local_rp_signing.fingerprint.clone();
    let fp_b = domain_signing.fingerprint.clone();
    let fp_c = "c".repeat(64);

    let linkkeys_txt_valid: Vec<Value> = vec![
        format!("v=lk1 fp={}", fp_a),
        format!("v=lk1 fp={} fp={}", fp_a, fp_b),
        format!("v=lk1 fp={} fp={} fp={}", fp_a, fp_b, fp_c),
    ]
    .into_iter()
    .map(|txt| {
        let record = dns::parse_linkkeys_txt(&txt).unwrap();
        json!({ "txt": txt, "expected_fingerprints": record.fingerprints })
    })
    .collect();

    let linkkeys_txt_invalid: Vec<Value> = vec![
        ("missing_version", "fp=abc"),
        ("wrong_version", "v=lk99 fp=abc"),
    ]
    .into_iter()
    .map(|(name, txt)| {
        let err = dns::parse_linkkeys_txt(txt).unwrap_err();
        json!({
            "name": name,
            "txt": txt,
            "expected_error": linkkeys_error_code(&err),
        })
    })
    .collect();

    let no_record_case = json!({
        "name": "no_record",
        "txt": null,
        "documentation_only": true,
        "expected_error": "no_linkkeys_record",
        "description": "Represents the DNS lookup itself returning no _linkkeys TXT record at all (NXDOMAIN / empty answer) — not a string for parse_linkkeys_txt to parse. An SDK's DNS layer must treat this the same as an untrusted/absent trust anchor.",
    });

    let apis_valid_specs: Vec<(&str, &str)> = vec![
        (
            "full_tcp_and_https",
            "v=lk1 tcp=idp.example.com:6000 https=idp.example.com/linkkeys",
        ),
        ("tcp_port_defaulted", "v=lk1 tcp=idp.example.com"),
        ("tcp_only", "v=lk1 tcp=idp.example.com:6000"),
        ("https_only", "v=lk1 https=idp.example.com:8443/x"),
    ];
    let apis_valid: Vec<Value> = apis_valid_specs
        .into_iter()
        .map(|(name, txt)| {
            let apis = dns::parse_linkkeys_apis_txt(txt).unwrap();
            json!({
                "name": name,
                "txt": txt,
                "expected_tcp": apis.tcp,
                "expected_https_base": apis.https_base,
            })
        })
        .collect();

    let apis_invalid: Vec<Value> = vec![("missing_endpoint", "v=lk1")]
        .into_iter()
        .map(|(name, txt)| {
            let err = dns::parse_linkkeys_apis_txt(txt).unwrap_err();
            json!({
                "name": name,
                "txt": txt,
                "expected_error": linkkeys_error_code(&err),
            })
        })
        .collect();

    json!({
        "note": "Mirrors crates/liblinkkeys/src/dns.rs's own test cases. `_linkkeys.{domain}` is the trust-anchor record (fp= pins); `_linkkeys_apis.{domain}` is the service-endpoint record (tcp=/https=). Both require a `v=lk1` tag; fields are whitespace-separated and order-independent.",
        "default_tcp_port": dns::DEFAULT_TCP_PORT,
        "linkkeys_txt": {
            "valid_cases": linkkeys_txt_valid,
            "invalid_cases": linkkeys_txt_invalid,
            "no_record_case": no_record_case,
        },
        "linkkeys_apis_txt": {
            "valid_cases": apis_valid,
            "invalid_cases": apis_invalid,
        },
    })
}

// ---------------------------------------------------------------------
// tickets.json
// ---------------------------------------------------------------------

fn tickets_json() -> Value {
    let ticket_a = CLAIM_TICKET;
    let ticket_b = [0xdd; 32];

    json!({
        "note": "A claim ticket is 32 opaque random bytes; the server stores only its SHA-256 hex (crypto::fingerprint applied to the raw ticket bytes, same hex-hash routine used for key fingerprints), never the raw ticket. `ticket_a` is the SAME bytes used as `claim_ticket` in envelopes.json's ticket_redemption case and callback_box.json's plaintext, so the ticket referenced end-to-end there is this one. See envelopes.json's `ticket_redemption` case for the full SignedLocalRpTicketRedemptionRequest envelope vector (payload/signature/context).",
        "hash_algorithm": "sha256",
        "cases": [
            { "name": "ticket_a", "ticket_hex": hex(&ticket_a), "sha256_hex": crypto::fingerprint(&ticket_a) },
            { "name": "ticket_b", "ticket_hex": hex(&ticket_b), "sha256_hex": crypto::fingerprint(&ticket_b) },
        ],
        "redemption_request_ref": "envelopes.json#/cases (structure == \"ticket_redemption\")",
    })
}

// ---------------------------------------------------------------------
// expirations.json
// ---------------------------------------------------------------------

fn expirations_json() -> Value {
    let identity_expires = base_instant() + Duration::days(3650);

    let expiration_cases = [
        (Duration::days(181), "ok"),
        (Duration::days(180), "notice"),
        (Duration::days(179), "notice"),
        (Duration::days(91), "notice"),
        (Duration::days(90), "warning"),
        (Duration::days(89), "warning"),
        (Duration::days(31), "warning"),
        (Duration::days(30), "critical"),
        (Duration::seconds(1), "critical"),
        (Duration::seconds(0), "expired"),
        (Duration::days(-1), "expired"),
    ]
    .into_iter()
    .map(|(remaining, expected_level)| {
        let now = identity_expires - remaining;
        let status = local_rp::check_expirations(&rfc3339(identity_expires), now).unwrap();
        assert_eq!(
            status.level.as_str(),
            expected_level,
            "remaining={remaining:?}"
        );
        json!({
            "now": rfc3339(now),
            "expected_level": expected_level,
        })
    })
    .collect::<Vec<_>>();

    let skew = 300i64;
    let ts_issued = base_instant();
    let ts_expires = ts_issued + Duration::minutes(5);

    let timestamp_cases = [
        (
            ts_expires + Duration::seconds(skew),
            true,
            "at the trailing skew boundary, inclusive",
        ),
        (
            ts_expires + Duration::seconds(skew + 1),
            false,
            "one second past the trailing skew boundary",
        ),
        (
            ts_issued - Duration::seconds(skew),
            true,
            "at the leading skew boundary, inclusive",
        ),
        (
            ts_issued - Duration::seconds(skew + 1),
            false,
            "one second past the leading skew boundary",
        ),
    ]
    .into_iter()
    .map(|(now, expected_valid, description)| {
        let result =
            local_rp::check_timestamps(&rfc3339(ts_issued), &rfc3339(ts_expires), now, skew);
        assert_eq!(result.is_ok(), expected_valid, "{description}");
        json!({
            "now": rfc3339(now),
            "expected_valid": expected_valid,
            "description": description,
        })
    })
    .collect::<Vec<_>>();

    json!({
        "check_expirations": {
            "note": "check_expirations(expires_at, now) -> ExpirationStatus. Thresholds are inclusive: exactly N days remaining already reaches that level. `notice` <= 180d remaining, `warning` <= 90d, `critical` <= 30d, `expired` when now >= expires_at, else `ok`.",
            "expires_at": rfc3339(identity_expires),
            "thresholds_days": { "notice": 180, "warning": 90, "critical": 30 },
            "cases": expiration_cases,
        },
        "check_timestamps": {
            "note": "check_timestamps(issued_at, expires_at, now, skew_seconds) — bounded clock-skew tolerance, boundaries inclusive.",
            "issued_at": rfc3339(ts_issued),
            "expires_at": rfc3339(ts_expires),
            "skew_seconds": skew,
            "cases": timestamp_cases,
        },
    })
}

// ---------------------------------------------------------------------
// revocations.json
// ---------------------------------------------------------------------

/// Far-future sibling-key expiry. Sibling-key validity in the Rust
/// implementation (`check_signing_key_valid` -> `signing_key_validity`) is
/// checked against WALL-CLOCK time, not an injected `now`, so these fixtures
/// must simply outlive any realistic test run.
const SIBLING_FAR_EXPIRES: &str = "2126-01-01T00:00:00+00:00";
/// Expiry in the past, for the expired-sibling negative case.
const SIBLING_PAST_EXPIRES: &str = "2020-01-01T00:00:00+00:00";
/// revoked_at for the already-revoked sibling (revoked before these vectors'
/// time anchor).
const SIBLING_REVOKED_AT: &str = "2025-12-01T00:00:00+00:00";

fn revocations_json() -> Value {
    let domain = USER_DOMAIN;
    let wrong_domain = "evil.example";

    let sib1 = ed25519_fixture(SIBLING_1_SEED);
    let sib2 = ed25519_fixture(SIBLING_2_SEED);
    let sib3 = ed25519_fixture(SIBLING_3_SEED); // target
    let sib_expired = ed25519_fixture(SIBLING_EXPIRED_SEED);
    let sib_revoked = ed25519_fixture(SIBLING_REVOKED_SEED);

    let created_at = rfc3339(base_instant());
    let cert_revoked_at = rfc3339(base_instant() + Duration::minutes(10));
    let target_fingerprint = sib3.fingerprint.clone();

    let mk_domain_key = |key_id: &str,
                         fixture: &Ed25519Fixture,
                         expires_at: &str,
                         revoked_at: Option<&str>|
     -> DomainPublicKey {
        DomainPublicKey {
            key_id: key_id.to_string(),
            public_key: fixture.public_key.to_vec(),
            fingerprint: fixture.fingerprint.clone(),
            algorithm: "ed25519".to_string(),
            key_usage: "sign".to_string(),
            created_at: created_at.clone(),
            expires_at: expires_at.to_string(),
            revoked_at: revoked_at.map(|s| s.to_string()),
            signed_by_key_id: None,
            key_signature: None,
        }
    };

    /// (key_id, fixture, seed, expires_at, revoked_at) for one sibling key.
    type SiblingSpec<'a> = (
        &'a str,
        &'a Ed25519Fixture,
        [u8; 32],
        &'a str,
        Option<&'a str>,
    );
    let domain_key_specs: Vec<SiblingSpec> = vec![
        (
            SIBLING_1_KEY_ID,
            &sib1,
            SIBLING_1_SEED,
            SIBLING_FAR_EXPIRES,
            None,
        ),
        (
            SIBLING_2_KEY_ID,
            &sib2,
            SIBLING_2_SEED,
            SIBLING_FAR_EXPIRES,
            None,
        ),
        (
            SIBLING_3_KEY_ID,
            &sib3,
            SIBLING_3_SEED,
            SIBLING_FAR_EXPIRES,
            None,
        ),
        (
            SIBLING_EXPIRED_KEY_ID,
            &sib_expired,
            SIBLING_EXPIRED_SEED,
            SIBLING_PAST_EXPIRES,
            None,
        ),
        (
            SIBLING_REVOKED_KEY_ID,
            &sib_revoked,
            SIBLING_REVOKED_SEED,
            SIBLING_FAR_EXPIRES,
            Some(SIBLING_REVOKED_AT),
        ),
    ];

    let domain_keys: Vec<DomainPublicKey> = domain_key_specs
        .iter()
        .map(|(key_id, fixture, _seed, expires, revoked)| {
            mk_domain_key(key_id, fixture, expires, *revoked)
        })
        .collect();

    let domain_keys_json: Vec<Value> = domain_key_specs
        .iter()
        .map(|(key_id, fixture, seed, expires, revoked)| {
            json!({
                "key_id": key_id,
                "algorithm": "ed25519",
                "key_usage": "sign",
                "seed_hex": hex(seed),
                "private_key_hex": hex(&fixture.private_key),
                "public_key_hex": hex(&fixture.public_key),
                "fingerprint_hex": fixture.fingerprint,
                "created_at": created_at,
                "expires_at": expires,
                "revoked_at": revoked.map(|s| s.to_string()),
            })
        })
        .collect();

    // Sign the canonical revocation payload for the fixed target with one
    // sibling. `payload_domain` is the domain bound INTO the signed payload;
    // `wire_domain` is what the ClaimSignature's `domain` field claims on the
    // wire. They differ only in the cross-domain-reuse negative case.
    let sign_one = |fixture: &Ed25519Fixture,
                    key_id: &str,
                    payload_domain: &str,
                    wire_domain: &str,
                    tamper_signature: bool|
     -> (ClaimSignature, Vec<u8>) {
        let payload = revocation::revocation_payload(
            SIBLING_3_KEY_ID,
            &target_fingerprint,
            &cert_revoked_at,
            payload_domain,
        );
        let mut signature =
            crypto::sign_with_algorithm(SigningAlgorithm::Ed25519, &payload, &fixture.private_key)
                .unwrap();
        if tamper_signature {
            signature[0] ^= 0xff;
        }
        (
            ClaimSignature {
                domain: wire_domain.to_string(),
                signed_by_key_id: key_id.to_string(),
                signature,
            },
            payload,
        )
    };

    let mk_cert = |signatures: Vec<ClaimSignature>| -> RevocationCertificate {
        RevocationCertificate {
            target_key_id: SIBLING_3_KEY_ID.to_string(),
            target_fingerprint: target_fingerprint.clone(),
            revoked_at: cert_revoked_at.clone(),
            signatures,
        }
    };

    let sig_json = |sig: &ClaimSignature, signed_payload: &[u8], note: Option<&str>| -> Value {
        let mut v = json!({
            "domain": sig.domain,
            "signed_by_key_id": sig.signed_by_key_id,
            "signature_hex": hex(&sig.signature),
            "signed_payload_cbor_hex": hex(signed_payload),
        });
        if let Some(n) = note {
            v["note"] = json!(n);
        }
        v
    };

    let case_json = |name: &str,
                     description: &str,
                     cert: &RevocationCertificate,
                     signatures_json: Vec<Value>,
                     verify_domain: &str,
                     expected_valid: bool,
                     expected_counted_signers: usize|
     -> Value {
        json!({
            "name": name,
            "description": description,
            "verify_domain": verify_domain,
            "certificate": {
                "target_key_id": cert.target_key_id,
                "target_fingerprint": cert.target_fingerprint,
                "revoked_at": cert.revoked_at,
                "signatures": signatures_json,
            },
            "certificate_cbor_hex": hex(&generated::encode_revocation_certificate(cert)),
            "expected_valid": expected_valid,
            "expected_counted_signers": expected_counted_signers,
        })
    };

    let mut cases = Vec::new();

    // Positive: quorum of two distinct, valid siblings.
    let (s1, p1) = sign_one(&sib1, SIBLING_1_KEY_ID, domain, domain, false);
    let (s2, p2) = sign_one(&sib2, SIBLING_2_KEY_ID, domain, domain, false);
    let valid_cert = mk_cert(vec![s1.clone(), s2.clone()]);
    cases.push(case_json(
        "valid_quorum_two_siblings",
        "Certificate for sibling-key-3 signed by sibling-key-1 and sibling-key-2 (two distinct, currently-valid signing keys of the domain). Meets the quorum of 2.",
        &valid_cert,
        vec![sig_json(&s1, &p1, None), sig_json(&s2, &p2, None)],
        domain,
        true,
        2,
    ));

    // Negative: only one sibling signature.
    let single_cert = mk_cert(vec![s1.clone()]);
    cases.push(case_json(
        "single_signature_insufficient",
        "Only sibling-key-1 signed. One valid signer < quorum of 2.",
        &single_cert,
        vec![sig_json(&s1, &p1, None)],
        domain,
        false,
        1,
    ));

    // Negative: the target key signs its own revocation; that signature must
    // not count toward quorum even though it is cryptographically valid.
    let (s_target, p_target) = sign_one(&sib3, SIBLING_3_KEY_ID, domain, domain, false);
    let self_cert = mk_cert(vec![s1.clone(), s_target.clone()]);
    cases.push(case_json(
        "target_self_signature_does_not_count",
        "sibling-key-1 plus the TARGET key (sibling-key-3) itself. The target's signature is cryptographically valid but a key can never authorize its own revocation, so only 1 signer counts.",
        &self_cert,
        vec![
            sig_json(&s1, &p1, None),
            sig_json(
                &s_target,
                &p_target,
                Some("Signed by the target key itself — must be ignored by the verifier."),
            ),
        ],
        domain,
        false,
        1,
    ));

    // Negative: revoked_at changed after signing — both signatures now cover
    // stale payload bytes, so neither verifies.
    let mut tampered_cert = mk_cert(vec![s1.clone(), s2.clone()]);
    tampered_cert.revoked_at = rfc3339(base_instant() + Duration::days(1));
    cases.push(case_json(
        "tampered_revoked_at",
        "A valid two-signer certificate whose revoked_at field was changed AFTER signing. The recomputed payload no longer matches either signature, so zero signers count.",
        &tampered_cert,
        vec![
            sig_json(
                &s1,
                &p1,
                Some("signed_payload_cbor_hex is what WAS signed (original revoked_at) — the verifier recomputes with the tampered revoked_at and gets different bytes."),
            ),
            sig_json(&s2, &p2, None),
        ],
        domain,
        false,
        0,
    ));

    // Negative: one signature byte-flipped; the other still valid -> 1 < 2.
    let (s1_bad, p1_bad) = sign_one(&sib1, SIBLING_1_KEY_ID, domain, domain, true);
    let tampered_sig_cert = mk_cert(vec![s1_bad.clone(), s2.clone()]);
    cases.push(case_json(
        "tampered_signature_byte",
        "sibling-key-1's signature has its first byte flipped; sibling-key-2's is intact. Only 1 valid signer.",
        &tampered_sig_cert,
        vec![
            sig_json(&s1_bad, &p1_bad, Some("First signature byte flipped after signing.")),
            sig_json(&s2, &p2, None),
        ],
        domain,
        false,
        1,
    ));

    // Negative: a fully valid certificate verified under a different domain.
    cases.push(case_json(
        "verified_under_wrong_domain",
        "The valid two-signer certificate, verified with domain 'evil.example' instead of the domain the signatures are bound to. Every signature's `domain` field mismatches, so zero signers count.",
        &valid_cert,
        vec![sig_json(&s1, &p1, None), sig_json(&s2, &p2, None)],
        wrong_domain,
        false,
        0,
    ));

    // Negative: cross-domain signature reuse. sibling-key-1's signature was
    // produced with 'evil.example' bound into the payload, then its wire
    // `domain` field rewritten to the real domain. The verifier recomputes
    // the payload with the wire domain and the signature no longer matches —
    // this is exactly the reuse the per-signature domain binding prevents.
    let (s1_rebound, p1_rebound) = sign_one(&sib1, SIBLING_1_KEY_ID, wrong_domain, domain, false);
    let cross_domain_cert = mk_cert(vec![s1_rebound.clone(), s2.clone()]);
    cases.push(case_json(
        "cross_domain_signature_reuse",
        "sibling-key-1's signature covers a payload bound to 'evil.example', but its wire `domain` field claims the real domain. The verifier recomputes the payload from the wire domain, so the signature fails; only sibling-key-2 counts.",
        &cross_domain_cert,
        vec![
            sig_json(
                &s1_rebound,
                &p1_rebound,
                Some("signed_payload_cbor_hex has 'evil.example' bound in — note it differs from the other signatures' payloads."),
            ),
            sig_json(&s2, &p2, None),
        ],
        domain,
        false,
        1,
    ));

    // Negative: an EXPIRED sibling's (otherwise valid) signature never counts.
    let (s_expired, p_expired) =
        sign_one(&sib_expired, SIBLING_EXPIRED_KEY_ID, domain, domain, false);
    let expired_cert = mk_cert(vec![s1.clone(), s_expired.clone()]);
    cases.push(case_json(
        "expired_sibling_does_not_count",
        "sibling-key-1 plus sibling-key-expired (expires_at in the past). The expired key's signature is cryptographically valid but the key itself is no longer valid, so only 1 signer counts.",
        &expired_cert,
        vec![
            sig_json(&s1, &p1, None),
            sig_json(&s_expired, &p_expired, Some("Signer key is expired — must not count.")),
        ],
        domain,
        false,
        1,
    ));

    // Negative: an already-REVOKED sibling's signature never counts.
    let (s_revoked, p_revoked) =
        sign_one(&sib_revoked, SIBLING_REVOKED_KEY_ID, domain, domain, false);
    let revoked_cert = mk_cert(vec![s1.clone(), s_revoked.clone()]);
    cases.push(case_json(
        "revoked_sibling_does_not_count",
        "sibling-key-1 plus sibling-key-revoked (revoked_at set in the key list). A revoked key cannot help revoke another key, so only 1 signer counts.",
        &revoked_cert,
        vec![
            sig_json(&s1, &p1, None),
            sig_json(&s_revoked, &p_revoked, Some("Signer key is itself revoked — must not count.")),
        ],
        domain,
        false,
        1,
    ));

    // --- Application case: the flow every SDK exercises in
    // complete_local_login. A callback-payload envelope signed by
    // sibling-key-3 verifies fine against the fetched key list (key 3 has no
    // revoked_at) — until the valid revocation certificate is applied, after
    // which key 3 must be treated as revoked and the same envelope must fail.
    let app_issued = base_instant() + Duration::minutes(6);
    let app_expires = app_issued + Duration::minutes(5);
    let app_verify_now = app_issued + Duration::minutes(1);
    let app_payload = local_rp::build_local_rp_callback_payload(
        USER_ID,
        USER_DOMAIN,
        CLAIM_TICKET.to_vec(),
        "unused-audience-fingerprint",
        CALLBACK_URL,
        NONCE.to_vec(),
        STATE.to_vec(),
        &rfc3339(app_issued),
        &rfc3339(app_expires),
    );
    let app_signed = local_rp::sign_local_rp_callback_payload(
        &app_payload,
        SIBLING_3_KEY_ID,
        SigningAlgorithm::Ed25519,
        &sib3.private_key,
    )
    .unwrap();

    // Sanity-check the whole application story against the real
    // implementation before writing it out.
    {
        use liblinkkeys::local_rp::DEFAULT_CLOCK_SKEW_SECONDS;
        local_rp::verify_local_rp_callback_payload(
            &app_signed,
            &domain_keys,
            app_verify_now,
            DEFAULT_CLOCK_SKEW_SECONDS,
        )
        .expect("application envelope must verify BEFORE the revocation is applied");
        revocation::verify_revocation_certificate(&valid_cert, &domain_keys, domain)
            .expect("the valid certificate must verify against the domain keys");
        let mut revoked_keys = domain_keys.clone();
        for k in &mut revoked_keys {
            if k.key_id == valid_cert.target_key_id {
                k.revoked_at = Some(valid_cert.revoked_at.clone());
            }
        }
        assert!(
            local_rp::verify_local_rp_callback_payload(
                &app_signed,
                &revoked_keys,
                app_verify_now,
                DEFAULT_CLOCK_SKEW_SECONDS,
            )
            .is_err(),
            "application envelope must FAIL after the revocation is applied"
        );
    }

    let application_case = json!({
        "note": "The case complete_local_login actually exercises: fetch domain keys (where sibling-key-3 carries NO revoked_at), fetch revocations, verify the certificate, and treat its target as revoked from cert.revoked_at onward. After applying, any signature by sibling-key-3 must fail verification even though the fetched key entry itself looked valid.",
        "certificate_ref": "certificate_cases[] entry with name == \"valid_quorum_two_siblings\"",
        "envelope": {
            "structure": "callback_payload",
            "context": CTX_LOCAL_RP_CALLBACK,
            "signing_key_id": SIBLING_3_KEY_ID,
            "payload_cbor_hex": hex(&app_signed.payload),
            "signature_hex": hex(&app_signed.signature),
        },
        "verify_now": rfc3339(app_verify_now),
        "clock_skew_seconds": local_rp::DEFAULT_CLOCK_SKEW_SECONDS,
        "expected_valid_before_revocation": true,
        "expected_valid_after_revocation": false,
    });

    json!({
        "note": "Sibling-signed key revocation certificates. Signed payload per signature: CBOR([tag, target_key_id, target_fingerprint, revoked_at, signing_domain]) — a FIVE-element CBOR array with the domain-separation tag first (the older house tuple pattern; NOT the local-RP envelopes' two-element CBOR([context, payload]) framing). Verification counts DISTINCT signers whose signature verifies, whose wire `domain` equals the domain being verified, whose key exists in the fetched key list as a currently-valid signing key, and who are NOT the target key; the certificate is valid iff that count >= quorum. Sibling-key validity (expiry/revocation) is evaluated against wall-clock time in the Rust implementation, which is why these fixtures use a far-future expires_at.",
        "tag": revocation::REVOCATION_TAG,
        "quorum": revocation::REVOCATION_QUORUM,
        "domain": domain,
        "domain_keys": domain_keys_json,
        "certificate_cases": cases,
        "application_case": application_case,
    })
}

// ---------------------------------------------------------------------
// claims.json
// ---------------------------------------------------------------------

/// Non-UTF-8 claim value: 0x00 plus several byte sequences that are invalid
/// UTF-8 (lone continuation byte, overlong-encoding lead byte, 0xfe/0xff which
/// never appear in UTF-8). An SDK that decodes/encodes `claim_value` as a CBOR
/// text string (tstr) instead of a byte string (bstr) cannot round-trip this.
const NON_UTF8_CLAIM_VALUE: [u8; 6] = [0x00, 0xff, 0xfe, 0x80, 0xc0, 0x9f];

fn claims_json() -> Value {
    let subject_domain = USER_DOMAIN;
    let key1 = ed25519_fixture(CLAIM_KEY_1_SEED);
    let key2 = ed25519_fixture(CLAIM_KEY_2_SEED);
    let wrong_key = ed25519_fixture(CLAIM_WRONG_KEY_SEED);

    let attested_at = rfc3339(base_instant());
    let created_at = rfc3339(base_instant());

    // sign_claim stamps created_at from the wall clock (it is deliberately NOT
    // part of the signed payload); pin it to the fixture instant afterward so
    // the encoded bytes are deterministic.
    let mk_claim = |claim_id: &str,
                    claim_type: &str,
                    claim_value: &[u8],
                    expires_at: Option<&str>,
                    signers: &[ClaimSigner<'_>]|
     -> Claim {
        let mut claim = claims::sign_claim(
            &ClaimSpec {
                claim_id,
                claim_type,
                claim_value,
                user_id: USER_ID,
                subject_domain,
                expires_at,
                attested_at: &attested_at,
            },
            signers,
        )
        .unwrap();
        claim.created_at = created_at.clone();
        claim
    };

    let claim_text = mk_claim(
        "conformance-claim-1",
        "display_name",
        b"Alice Example",
        Some(SIBLING_FAR_EXPIRES),
        &[ClaimSigner {
            domain: subject_domain,
            key_id: CLAIM_KEY_1_ID,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &key1.private_key,
        }],
    );

    let claim_binary = mk_claim(
        "conformance-claim-2",
        "avatar_hash",
        &NON_UTF8_CLAIM_VALUE,
        None,
        &[ClaimSigner {
            domain: subject_domain,
            key_id: CLAIM_KEY_1_ID,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &key1.private_key,
        }],
    );

    let claim_multi_sig = mk_claim(
        "conformance-claim-3",
        "handle",
        b"alice",
        None,
        &[
            ClaimSigner {
                domain: subject_domain,
                key_id: CLAIM_KEY_1_ID,
                algorithm: SigningAlgorithm::Ed25519,
                private_key_bytes: &key1.private_key,
            },
            ClaimSigner {
                domain: subject_domain,
                key_id: CLAIM_KEY_2_ID,
                algorithm: SigningAlgorithm::Ed25519,
                private_key_bytes: &key2.private_key,
            },
        ],
    );

    // The default verification key set: claim-key-1 and claim-key-2, both
    // currently-valid signing keys of the fixture domain.
    let mk_verify_key = |key_id: &str, fixture: &Ed25519Fixture| -> Value {
        json!({
            "domain": subject_domain,
            "key_id": key_id,
            "algorithm": "ed25519",
            "key_usage": "sign",
            "public_key_hex": hex(&fixture.public_key),
            "fingerprint_hex": fixture.fingerprint,
            "created_at": created_at,
            "expires_at": SIBLING_FAR_EXPIRES,
            "revoked_at": null,
        })
    };
    let default_domain_keys = vec![
        mk_verify_key(CLAIM_KEY_1_ID, &key1),
        mk_verify_key(CLAIM_KEY_2_ID, &key2),
    ];

    // DomainPublicKey view of the same defaults, for the generator's own
    // sanity checks below.
    let mk_dpk = |key_id: &str, fixture: &Ed25519Fixture| -> DomainPublicKey {
        DomainPublicKey {
            key_id: key_id.to_string(),
            public_key: fixture.public_key.to_vec(),
            fingerprint: fixture.fingerprint.clone(),
            algorithm: "ed25519".to_string(),
            key_usage: "sign".to_string(),
            created_at: created_at.clone(),
            expires_at: SIBLING_FAR_EXPIRES.to_string(),
            revoked_at: None,
            signed_by_key_id: None,
            key_signature: None,
        }
    };
    let default_key_set = vec![DomainKeySet {
        domain: subject_domain.to_string(),
        keys: vec![mk_dpk(CLAIM_KEY_1_ID, &key1), mk_dpk(CLAIM_KEY_2_ID, &key2)],
    }];

    let claim_json = |claim: &Claim| -> Value {
        let signatures: Vec<Value> = claim
            .signatures
            .iter()
            .map(|sig| {
                let payload = claims::claim_sign_payload(
                    &claim.claim_id,
                    &claim.claim_type,
                    &claim.claim_value,
                    &claim.user_id,
                    subject_domain,
                    &sig.domain,
                    claim.expires_at.as_deref(),
                    &claim.attested_at,
                );
                json!({
                    "domain": sig.domain,
                    "signed_by_key_id": sig.signed_by_key_id,
                    "signature_hex": hex(&sig.signature),
                    "signed_payload_cbor_hex": hex(&payload),
                })
            })
            .collect();
        json!({
            "claim_id": claim.claim_id,
            "user_id": claim.user_id,
            "claim_type": claim.claim_type,
            "claim_value_hex": hex(&claim.claim_value),
            "attested_at": claim.attested_at,
            "created_at": claim.created_at,
            "expires_at": claim.expires_at,
            "revoked_at": claim.revoked_at,
            "signatures": signatures,
        })
    };

    let mut positive_cases = Vec::new();
    for (name, description, claim) in [
        (
            "claim_utf8_text_value",
            "A display_name claim whose value happens to be UTF-8 text — but it is STILL a CBOR byte string (bstr) on the wire, never a text string. One signature; expires_at present (far future).",
            &claim_text,
        ),
        (
            "claim_non_utf8_binary_value",
            "A claim whose value is NON-UTF-8 binary bytes. This is the case that distinguishes a correct bstr codec from a tstr one: a text-string codec cannot represent these bytes at all. expires_at absent (null in the signed payload).",
            &claim_binary,
        ),
        (
            "claim_multiple_signatures",
            "A claim carrying TWO ClaimSignatures from two different keys of the same domain. Verification needs only one currently-valid signature per signing domain.",
            &claim_multi_sig,
        ),
    ] {
        // Generator sanity: the real verifier must accept it.
        claims::verify_claim(claim, subject_domain, &default_key_set)
            .unwrap_or_else(|e| panic!("{name} failed self-verification: {e}"));
        positive_cases.push(json!({
            "name": name,
            "description": description,
            "subject_domain": subject_domain,
            "claim": claim_json(claim),
            "claim_cbor_hex": hex(&generated::encode_claim(claim)),
            "expected_valid": true,
        }));
    }

    // --- verification negative cases ---
    let mut negative_cases = Vec::new();

    // Tampered claim_value byte: last byte flipped after signing.
    let mut tampered = claim_text.clone();
    *tampered.claim_value.last_mut().unwrap() ^= 0xff;
    assert!(claims::verify_claim(&tampered, subject_domain, &default_key_set).is_err());
    negative_cases.push(json!({
        "name": "tampered_claim_value_byte",
        "description": "claim_utf8_text_value with the last byte of claim_value flipped after signing; signature unchanged. claim_value is bound into the signed payload, so verification must fail.",
        "subject_domain": subject_domain,
        "claim_cbor_hex": hex(&generated::encode_claim(&tampered)),
        "expected_error": "signature_invalid",
    }));

    // Wrong signer key: the key id resolves, but to a DIFFERENT public key.
    let wrong_key_set_json = vec![
        mk_verify_key(CLAIM_KEY_1_ID, &wrong_key),
        mk_verify_key(CLAIM_KEY_2_ID, &key2),
    ];
    {
        let wrong_set = vec![DomainKeySet {
            domain: subject_domain.to_string(),
            keys: vec![
                mk_dpk(CLAIM_KEY_1_ID, &wrong_key),
                mk_dpk(CLAIM_KEY_2_ID, &key2),
            ],
        }];
        assert!(claims::verify_claim(&claim_text, subject_domain, &wrong_set).is_err());
    }
    negative_cases.push(json!({
        "name": "wrong_signer_key",
        "description": "claim_utf8_text_value verified against a key list where claim-key-1's key id resolves to a REAL but different Ed25519 public key. The signature cannot verify.",
        "subject_domain": subject_domain,
        "claim_cbor_hex": hex(&generated::encode_claim(&claim_text)),
        "domain_keys": wrong_key_set_json,
        "expected_error": "signature_invalid",
    }));

    // Signer key id entirely absent from the supplied key list.
    {
        let missing_set = vec![DomainKeySet {
            domain: subject_domain.to_string(),
            keys: vec![mk_dpk(CLAIM_KEY_2_ID, &key2)],
        }];
        assert!(claims::verify_claim(&claim_text, subject_domain, &missing_set).is_err());
    }
    negative_cases.push(json!({
        "name": "signer_key_not_found",
        "description": "claim_utf8_text_value verified against a key list that does not contain claim-key-1 at all (only claim-key-2 is supplied).",
        "subject_domain": subject_domain,
        "claim_cbor_hex": hex(&generated::encode_claim(&claim_text)),
        "domain_keys": vec![mk_verify_key(CLAIM_KEY_2_ID, &key2)],
        "expected_error": "key_not_found",
    }));

    // Subject-domain replay: same claim + same signature presented as being
    // about the same user_id at a DIFFERENT domain. The subject is bound into
    // the signed payload as `user_id@subject_domain`, so this must fail.
    assert!(claims::verify_claim(&claim_text, "evil.example", &default_key_set).is_err());
    negative_cases.push(json!({
        "name": "subject_domain_replay",
        "description": "claim_utf8_text_value, unmodified, verified with subject_domain 'evil.example' instead of the domain it was issued for. The signed payload binds the subject as user_id@subject_domain, so the recomputed payload differs and the signature fails.",
        "subject_domain": "evil.example",
        "claim_cbor_hex": hex(&generated::encode_claim(&claim_text)),
        "expected_error": "signature_invalid",
    }));

    // --- decode negative case: claim_value as tstr must fail to decode ---
    // Take the canonical claim bytes, re-encode ONLY the claim_value entry as
    // a CBOR text string (its value is valid UTF-8, so the text form exists),
    // and re-serialize. A strict bstr codec must reject this.
    let text_encoded_claim = {
        let canonical = generated::encode_claim(&claim_text);
        let mut value: ciborium::value::Value =
            ciborium::de::from_reader(canonical.as_slice()).unwrap();
        let ciborium::value::Value::Map(entries) = &mut value else {
            panic!("claim CBOR must be a map");
        };
        let mut swapped = false;
        for (k, v) in entries.iter_mut() {
            if k.as_text() == Some("claim_value") {
                let bytes = v.as_bytes().expect("claim_value is bstr").clone();
                *v = ciborium::value::Value::Text(String::from_utf8(bytes).unwrap());
                swapped = true;
            }
        }
        assert!(swapped, "claim_value entry present");
        let mut out = Vec::new();
        ciborium::ser::into_writer(&value, &mut out).unwrap();
        out
    };
    assert!(
        generated::decode_claim(&text_encoded_claim).is_err(),
        "tstr-encoded claim_value must fail the strict decoder"
    );
    let decode_negative_cases = vec![json!({
        "name": "claim_value_as_cbor_text_rejected",
        "description": "Byte-identical to claim_utf8_text_value's CBOR except the claim_value entry is encoded as a CBOR TEXT string (major type 3) instead of a byte string (major type 2). CSIL declares claim_value as bytes; a strict codec must fail to decode this. An SDK that accepts it has claim_value wired as tstr and will also produce wrong signature payloads.",
        "claim_cbor_hex": hex(&text_encoded_claim),
        "expected_decode_ok": false,
    })];

    // --- LocalRpTicketRedemptionResponse: where SDKs actually receive Claims ---
    let response = LocalRpTicketRedemptionResponse {
        user_id: USER_ID.to_string(),
        user_domain: USER_DOMAIN.to_string(),
        claims: vec![
            claim_text.clone(),
            claim_binary.clone(),
            claim_multi_sig.clone(),
        ],
        ticket_expires_at: rfc3339(base_instant() + Duration::hours(1)),
    };
    let response_bytes = generated::encode_local_rp_ticket_redemption_response(&response);
    {
        let decoded = generated::decode_local_rp_ticket_redemption_response(&response_bytes)
            .expect("response round-trips");
        assert_eq!(decoded, response);
    }
    let ticket_redemption_response = json!({
        "note": "The wire message complete_local_login actually consumes Claims from: the redeem-claim-ticket response. Contains all three positive-case claims, in order. Decoding must reproduce each claim byte-exactly (claim_value as raw bytes), and re-encoding must reproduce response_cbor_hex.",
        "user_id": USER_ID,
        "user_domain": USER_DOMAIN,
        "ticket_expires_at": rfc3339(base_instant() + Duration::hours(1)),
        "claims_ref": "cases[] in order: claim_utf8_text_value, claim_non_utf8_binary_value, claim_multiple_signatures",
        "response_cbor_hex": hex(&response_bytes),
    });

    json!({
        "note": "Claim wire encoding and claim-signature verification. THE TRAP THIS FILE EXISTS TO CATCH: Claim.claim_value is CBOR bytes (bstr, major type 2), NEVER a text string — both on the wire and inside the signed payload. An SDK that wires it as text will pass its own self-tests (sign-wrong/verify-wrong is self-consistent) and only these cross-implementation vectors expose it; claim_non_utf8_binary_value cannot even be represented by a tstr codec. Signed payload per signature: CBOR([tag, claim_id, claim_type, claim_value(bstr), subject, signing_domain, expires_at_or_null, attested_at]) — an EIGHT-element CBOR array, tag first, where subject is the single string 'user_id@subject_domain' and expires_at is CBOR null when absent. created_at is deliberately NOT signed. Verification: every DISTINCT domain in the claim's signatures must contribute at least one signature that verifies against a currently-valid signing key of that domain (key validity is wall-clock-evaluated, like revocations.json).",
        "tag": claims::CLAIM_PAYLOAD_TAG,
        "payload_layout": "CBOR([tag, claim_id, claim_type, claim_value(bstr), 'user_id@subject_domain', signing_domain, expires_at_or_null, attested_at])",
        "subject_domain": subject_domain,
        "signer_keys": [
            {
                "key_id": CLAIM_KEY_1_ID,
                "seed_hex": hex(&CLAIM_KEY_1_SEED),
                "private_key_hex": hex(&key1.private_key),
                "public_key_hex": hex(&key1.public_key),
                "fingerprint_hex": key1.fingerprint,
            },
            {
                "key_id": CLAIM_KEY_2_ID,
                "seed_hex": hex(&CLAIM_KEY_2_SEED),
                "private_key_hex": hex(&key2.private_key),
                "public_key_hex": hex(&key2.public_key),
                "fingerprint_hex": key2.fingerprint,
            },
            {
                "key_id": "wrong-key (used only inside the wrong_signer_key case's domain_keys)",
                "seed_hex": hex(&CLAIM_WRONG_KEY_SEED),
                "private_key_hex": hex(&wrong_key.private_key),
                "public_key_hex": hex(&wrong_key.public_key),
                "fingerprint_hex": wrong_key.fingerprint,
            },
        ],
        "domain_keys": default_domain_keys,
        "cases": positive_cases,
        "negative_cases": negative_cases,
        "decode_negative_cases": decode_negative_cases,
        "ticket_redemption_response": ticket_redemption_response,
    })
}
