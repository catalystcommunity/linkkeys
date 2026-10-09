//! Generates the cross-language conformance vectors for act-as grants
//! (docs/spec/reserved/act-as-grants.md) checked into
//! `sdks/regular-rp/conformance/`.
//!
//! ## Determinism
//!
//! All key material is FIXED test-only seeds. All timestamps are fixed
//! RFC3339 constants. Ed25519 signing is deterministic by construction, so
//! running this generator twice produces byte-identical output.
//!
//! A DOMAIN signing key's validity is checked against wall-clock time by the
//! Rust implementation, so domain keys here carry a far-future expiry.
//!
//! ## Usage
//!
//! ```sh
//! cargo run -p liblinkkeys --example generate_act_as_vectors
//! cargo run -p liblinkkeys --example generate_act_as_vectors -- /tmp/out
//! ```

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use liblinkkeys::act_as::{self, GranteeSigner, NewGrant};
use liblinkkeys::application_keys::{ApplicationKeyRef, ApplicationSigner};
use liblinkkeys::claims::ClaimSigner;
use liblinkkeys::crypto::{self, SigningAlgorithm};
use liblinkkeys::generated::{
    self,
    types::{
        ActAsGrantRequest, ActAsGrantRevocation, ActAsRefreshRequest, ActAsScopeEntry,
        ActAsScopeSet, ApplicationRef, DomainPublicKey, GranteeRef, LocalRpDescriptor,
    },
};
use liblinkkeys::local_rp::envelope_signature_input;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

// Fixed test-only key material. NEVER use these seeds for anything real.
const HOME_DOMAIN: &str = "home.conformance.example";
const HOME_KEY_SEED: [u8; 32] = [0x31; 32];
const HOME_KEY_ID: &str = "home-key-1";
const STRANGER_DOMAIN_SEED: [u8; 32] = [0x32; 32];

const GRANTEE_KEY_SEED: [u8; 32] = [0x41; 32];
const GRANTEE_KEY_ID: &str = "grantee-key-1";
const GRANTEE_INSTANCE: &str = "grantee-instance-1";
const THIEF_KEY_SEED: [u8; 32] = [0x42; 32];

const AUDIENCE_KEY_SEED: [u8; 32] = [0x51; 32];
const AUDIENCE_KEY_ID: &str = "audience-key-1";
const AUDIENCE_INSTANCE: &str = "audience-instance-1";
const STRANGER_AUDIENCE_SEED: [u8; 32] = [0x52; 32];
const AUDIENCE_KEY2_SEED: [u8; 32] = [0x53; 32];
const AUDIENCE_KEY2_ID: &str = "audience-key-2";
const AUDIENCE_DOMAIN_KEY_SEED: [u8; 32] = [0x54; 32];
const AUDIENCE_DOMAIN_KEY_ID: &str = "audience-domain-key-1";

const LOCAL_RP_SEED: [u8; 32] = [0x61; 32];
const OTHER_LOCAL_RP_SEED: [u8; 32] = [0x62; 32];

const DOMAIN_KEY_FAR_EXPIRES: &str = "2126-01-01T00:00:00Z";
const SKEW_SECONDS: i64 = 60;
const MAX_PRESENTATION_AGE_SECONDS: i64 = 300;
const REQUEST_DIGEST: &[u8] = b"conformance-request-digest";

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

fn base() -> DateTime<Utc> {
    t("2026-10-06T12:00:00Z")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Fixture {
    key_id: &'static str,
    public: [u8; 32],
    private: [u8; 32],
}

fn fixture(key_id: &'static str, seed: [u8; 32]) -> Fixture {
    let sk = SigningKey::from_bytes(&seed);
    Fixture {
        key_id,
        public: *sk.verifying_key().as_bytes(),
        private: sk.to_bytes(),
    }
}

impl Fixture {
    fn app_signer(&self) -> ApplicationSigner<'_> {
        ApplicationSigner {
            key_id: self.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &self.private,
        }
    }

    fn domain_signer<'a>(&'a self, domain: &'a str) -> ClaimSigner<'a> {
        ClaimSigner {
            domain,
            key_id: self.key_id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &self.private,
        }
    }

    fn key_ref(&self) -> ApplicationKeyRef {
        ApplicationKeyRef {
            key_id: self.key_id.into(),
            key_usage: "sign".into(),
            algorithm: "ed25519".into(),
            public_key: self.public.to_vec(),
            fingerprint: crypto::fingerprint(&self.public),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            revoked_at: None,
        }
    }

    fn domain_key(&self) -> DomainPublicKey {
        DomainPublicKey {
            key_id: self.key_id.into(),
            public_key: self.public.to_vec(),
            fingerprint: crypto::fingerprint(&self.public),
            algorithm: "ed25519".into(),
            key_usage: "sign".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: DOMAIN_KEY_FAR_EXPIRES.into(),
            revoked_at: None,
            signed_by_key_id: None,
            key_signature: None,
        }
    }

    fn json(&self) -> Value {
        json!({
            "key_id": self.key_id,
            "private_key_hex": hex(&self.private),
            "public_key_hex": hex(&self.public),
            "fingerprint": crypto::fingerprint(&self.public),
        })
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

fn domain_key_json(k: &DomainPublicKey) -> Value {
    json!({
        "key_id": k.key_id,
        "key_usage": k.key_usage,
        "algorithm": k.algorithm,
        "public_key_hex": hex(&k.public_key),
        "fingerprint": k.fingerprint,
        "created_at": k.created_at,
        "expires_at": k.expires_at,
    })
}

fn app_ref(user: &str, domain: &str, app: &str) -> ApplicationRef {
    ApplicationRef {
        subject_user_id: user.into(),
        subject_domain: domain.into(),
        application_id: app.into(),
    }
}

fn audience() -> ApplicationRef {
    app_ref(
        "018f3333-0000-7000-8000-0000000000d1",
        "audience.conformance.example",
        "audience-app",
    )
}

fn grantee() -> GranteeRef {
    GranteeRef {
        application: Some(app_ref(
            "018f3333-0000-7000-8000-0000000000c1",
            "grantee.conformance.example",
            "grantee-app",
        )),
        local_rp_descriptor_fingerprint: None,
    }
}

fn app_ref_json(a: &ApplicationRef) -> Value {
    json!({
        "subject_user_id": a.subject_user_id,
        "subject_domain": a.subject_domain,
        "application_id": a.application_id,
    })
}

struct World {
    home: Fixture,
    stranger_domain: Fixture,
    grantee: Fixture,
    thief: Fixture,
    audience: Fixture,
    audience2: Fixture,
    stranger_audience: Fixture,
    audience_domain: Fixture,
}

impl World {
    fn new() -> Self {
        Self {
            home: fixture(HOME_KEY_ID, HOME_KEY_SEED),
            stranger_domain: fixture(HOME_KEY_ID, STRANGER_DOMAIN_SEED),
            grantee: fixture(GRANTEE_KEY_ID, GRANTEE_KEY_SEED),
            thief: fixture(GRANTEE_KEY_ID, THIEF_KEY_SEED),
            audience: fixture(AUDIENCE_KEY_ID, AUDIENCE_KEY_SEED),
            audience2: fixture(AUDIENCE_KEY2_ID, AUDIENCE_KEY2_SEED),
            stranger_audience: fixture(AUDIENCE_KEY_ID, STRANGER_AUDIENCE_SEED),
            audience_domain: fixture(AUDIENCE_DOMAIN_KEY_ID, AUDIENCE_DOMAIN_KEY_SEED),
        }
    }

    /// The audience instance's current signing keys. Scope sets carry one
    /// signature from each.
    fn audience_signers(&self) -> Vec<ApplicationSigner<'_>> {
        vec![self.audience.app_signer(), self.audience2.app_signer()]
    }

    fn audience_key_refs(&self) -> Vec<ApplicationKeyRef> {
        vec![self.audience.key_ref(), self.audience2.key_ref()]
    }

    fn grantee_signer(&self) -> GranteeSigner<'_> {
        GranteeSigner::Application {
            instance_id: GRANTEE_INSTANCE,
            signer: self.grantee.app_signer(),
        }
    }

    fn scope_set_value(&self, grantee: GranteeRef, scopes: &[&str]) -> ActAsScopeSet {
        ActAsScopeSet {
            audience: audience(),
            grantee,
            entries: scopes
                .iter()
                .map(|s| ActAsScopeEntry {
                    scope: (*s).into(),
                    description: Some(format!("Allows {s}")),
                })
                .collect(),
            language: Some("en-US".into()),
            audience_handle_claim: None,
            issued_at: "2026-10-06T11:55:00Z".into(),
            expires_at: "2026-10-06T12:10:00Z".into(),
        }
    }

    fn grant(
        &self,
        grantee: &GranteeRef,
        offered: &[&str],
        approved: &[&str],
    ) -> generated::types::SignedActAsGrant {
        let set = self.scope_set_value(grantee.clone(), offered);
        let scope_set =
            act_as::sign_scope_set(&set, AUDIENCE_INSTANCE, &self.audience_signers()).unwrap();
        let approved: Vec<String> = approved.iter().map(|s| (*s).to_string()).collect();
        let grant = act_as::build_grant(&NewGrant {
            grant_id: "grant-1",
            user_id: "018f3333-0000-7000-8000-0000000000a1",
            subject_domain: HOME_DOMAIN,
            grantee,
            audience: &audience(),
            scope_set: &scope_set,
            approved_scope: &approved,
            lifetime_seconds: 3600,
            renewal_window_seconds: 0,
            now: base(),
        })
        .unwrap();
        act_as::sign_grant(&grant, &[self.home.domain_signer(HOME_DOMAIN)]).unwrap()
    }
}

fn write_json(dir: &Path, name: &str, value: &Value) {
    let path = dir.join(name);
    let mut text = serde_json::to_string_pretty(value).unwrap();
    text.push('\n');
    std::fs::write(&path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("wrote {}", path.display());
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/regular-rp/conformance")
        });
    std::fs::create_dir_all(&dir).unwrap();
    let w = World::new();
    write_json(&dir, "act_as_signatures.json", &signature_vectors(&w));
    write_json(&dir, "act_as_credential.json", &credential_vectors(&w));
    write_json(&dir, "act_as_terms.json", &terms_vectors());
    write_json(
        &dir,
        "act_as_grantee_signing.json",
        &grantee_signing_vectors(&w),
    );
}

// ---------------------------------------------------------------------------
// Signatures: scope set, grant request, refresh request, grant, revocation
// ---------------------------------------------------------------------------

fn signature_vectors(w: &World) -> Value {
    // Scope set.
    let set = w.scope_set_value(grantee(), &["read", "write"]);
    let scope_set = act_as::sign_scope_set(&set, AUDIENCE_INSTANCE, &w.audience_signers()).unwrap();
    let scope_set_cbor = generated::encode_signed_act_as_scope_set(&scope_set);
    let mut tampered = scope_set.clone();
    let last = tampered.scope_set.len() - 1;
    tampered.scope_set[last] ^= 0x01;
    let wrong_tag_set = generated::types::SignedActAsScopeSet {
        signatures: vec![generated::types::ApplicationKeySignature {
            signed_by_key_id: AUDIENCE_KEY_ID.into(),
            signature: crypto::sign_with_algorithm(
                SigningAlgorithm::Ed25519,
                &envelope_signature_input(act_as::GRANT_TAG, &scope_set.scope_set),
                &w.audience.private,
            )
            .unwrap(),
        }],
        ..scope_set.clone()
    };
    // Key-state variants for the revoked-key policy cases. The set was
    // issued at 11:55.
    let mut key1_expired = w.audience.key_ref();
    key1_expired.expires_at = "2026-01-02T00:00:00Z".into();
    let mut key1_revoked_after = w.audience.key_ref();
    key1_revoked_after.revoked_at = Some("2026-10-06T12:30:00Z".into());
    // The home domain recorded key 1 as created after the set's issued_at:
    // 4 minutes later (inside the 5-minute skew) and 5 minutes 1 second later.
    let mut key1_created_inside_skew = w.audience.key_ref();
    key1_created_inside_skew.created_at = "2026-10-06T11:59:00Z".into();
    let mut key1_created_beyond_skew = w.audience.key_ref();
    key1_created_beyond_skew.created_at = "2026-10-06T12:00:01Z".into();
    let mut key1_revoked_before = w.audience.key_ref();
    key1_revoked_before.revoked_at = Some("2026-10-06T11:00:00Z".into());
    let only_key1 =
        act_as::sign_scope_set(&set, AUDIENCE_INSTANCE, &[w.audience.app_signer()]).unwrap();
    let only_key1_cbor = hex(&generated::encode_signed_act_as_scope_set(&only_key1));
    let keys_json = |keys: &[ApplicationKeyRef]| keys.iter().map(key_ref_json).collect::<Vec<_>>();

    // Handle claims about the audience's enrolling account.
    let party = audience();
    let claim = |user: &str, claim_type: &str, signer: &Fixture, domain: &str| {
        liblinkkeys::claims::sign_claim(
            &liblinkkeys::claims::ClaimSpec {
                claim_id: "handle-claim-1",
                claim_type,
                claim_value: b"audience-team",
                user_id: user,
                subject_domain: &party.subject_domain,
                expires_at: None,
                attested_at: "2026-10-06T10:00:00Z",
            },
            &[signer.domain_signer(domain)],
        )
        .unwrap()
    };
    let claim_hex = |c: &generated::types::Claim| hex(&generated::encode_claim(c));
    let good_claim = claim(
        &party.subject_user_id,
        "handle",
        &w.audience_domain,
        &party.subject_domain,
    );
    let other_user_claim = claim(
        "someone-else",
        "handle",
        &w.audience_domain,
        &party.subject_domain,
    );
    let other_type_claim = claim(
        &party.subject_user_id,
        "email",
        &w.audience_domain,
        &party.subject_domain,
    );
    let third_domain_claim = claim(
        &party.subject_user_id,
        "handle",
        &w.audience_domain,
        "third.conformance.example",
    );
    let forged_claim = claim(
        &party.subject_user_id,
        "handle",
        &w.stranger_domain,
        &party.subject_domain,
    );

    // Grant request.
    let request = ActAsGrantRequest {
        grantee: grantee(),
        scope_set: scope_set.clone(),
        requested_lifetime_seconds: Some(1800),
        requested_renewal_window_seconds: Some(7200),
        grantee_handle_claim: None,
        callback_url: "https://grantee.conformance.example/act-as/callback".into(),
        nonce: "grant-request-nonce".into(),
        requested_at: "2026-10-06T11:59:00Z".into(),
        expires_at: "2026-10-06T12:09:00Z".into(),
    };
    let signed_request = act_as::sign_grant_request(&request, &w.grantee_signer()).unwrap();
    let thief_request = act_as::sign_grant_request(
        &request,
        &GranteeSigner::Application {
            instance_id: GRANTEE_INSTANCE,
            signer: w.thief.app_signer(),
        },
    )
    .unwrap();

    // Refresh request.
    let refresh = ActAsRefreshRequest {
        grant_id: "grant-1".into(),
        grantee: grantee(),
        requested_at: "2026-10-06T12:40:00Z".into(),
        expires_at: "2026-10-06T12:45:00Z".into(),
        nonce: "refresh-nonce".into(),
    };
    let signed_refresh = act_as::sign_refresh_request(&refresh, &w.grantee_signer()).unwrap();
    let other_grantee_refresh = act_as::sign_refresh_request(
        &ActAsRefreshRequest {
            grantee: GranteeRef {
                application: Some(app_ref("x", "x.example", "x-app")),
                local_rp_descriptor_fingerprint: None,
            },
            ..refresh.clone()
        },
        &w.grantee_signer(),
    )
    .unwrap();

    // Grant and revocation.
    let grant = w.grant(&grantee(), &["read", "write"], &["read"]);
    let revocation = act_as::sign_grant_revocation(
        &ActAsGrantRevocation {
            grant_id: "grant-1".into(),
            user_id: "018f3333-0000-7000-8000-0000000000a1".into(),
            subject_domain: HOME_DOMAIN.into(),
            revoked_at: "2026-10-06T12:30:00Z".into(),
        },
        &[w.home.domain_signer(HOME_DOMAIN)],
    )
    .unwrap();
    let forged_revocation = act_as::sign_grant_revocation(
        &ActAsGrantRevocation {
            grant_id: "grant-1".into(),
            user_id: "018f3333-0000-7000-8000-0000000000a1".into(),
            subject_domain: HOME_DOMAIN.into(),
            revoked_at: "2026-10-06T12:30:00Z".into(),
        },
        &[w.stranger_domain.domain_signer(HOME_DOMAIN)],
    )
    .unwrap();

    json!({
        "description": "Act-as signature constructions. Every signed structure is signed over CBOR([tag, payload_bytes]).",
        "tags": {
            "scope_set": act_as::SCOPE_SET_TAG,
            "grant": act_as::GRANT_TAG,
            "grant_request": act_as::GRANT_REQUEST_TAG,
            "refresh_request": act_as::REFRESH_REQUEST_TAG,
            "presentation": act_as::PRESENTATION_TAG,
            "grant_revocation": act_as::GRANT_REVOCATION_TAG,
        },
        "now": "2026-10-06T12:00:00Z",
        "skew_seconds": SKEW_SECONDS,
        "home_domain": HOME_DOMAIN,
        "home_domain_keys": [domain_key_json(&w.home.domain_key())],
        "audience": app_ref_json(&audience()),
        "audience_keys": w.audience_key_refs().iter().map(key_ref_json).collect::<Vec<_>>(),
        "grantee_instance_keys": [key_ref_json(&w.grantee.key_ref())],
        "keys": {
            "home": w.home.json(),
            "grantee": w.grantee.json(),
            "audience": w.audience.json(),
        },
        "scope_set": {
            "signed_cbor_hex": hex(&scope_set_cbor),
            "scope_set_cbor_hex": hex(&scope_set.scope_set),
            "signature_input_cbor_hex": hex(&envelope_signature_input(act_as::SCOPE_SET_TAG, &scope_set.scope_set)),
            "cases": [{"name": "audience_signed", "signed_cbor_hex": hex(&scope_set_cbor), "expected_valid": true}],
            "negative_cases": [
                {"name": "tampered_scope_set_byte", "signed_cbor_hex": hex(&generated::encode_signed_act_as_scope_set(&tampered)), "expected_valid": false},
                {"name": "signed_under_grant_tag", "signed_cbor_hex": hex(&generated::encode_signed_act_as_scope_set(&wrong_tag_set)), "expected_valid": false},
                {"name": "signed_by_a_key_that_is_not_the_audiences", "signed_cbor_hex": hex(&generated::encode_signed_act_as_scope_set(&act_as::sign_scope_set(&set, AUDIENCE_INSTANCE, &[w.stranger_audience.app_signer()]).unwrap())), "expected_valid": false},
                {"name": "verified_against_another_audience", "signed_cbor_hex": hex(&scope_set_cbor), "expected_audience": app_ref_json(&app_ref("x", "x.example", "x-app")), "expected_valid": false},
                {"name": "only_signer_revoked_before_it_signed", "signed_cbor_hex": only_key1_cbor, "audience_keys": keys_json(std::slice::from_ref(&key1_revoked_before)), "expected_valid": false},
                {"name": "only_signer_created_beyond_the_clock_skew", "signed_cbor_hex": only_key1_cbor, "audience_keys": keys_json(std::slice::from_ref(&key1_created_beyond_skew)), "expected_valid": false},
                {"name": "only_signer_revoked_after_signing_with_refuse_policy", "signed_cbor_hex": only_key1_cbor, "audience_keys": keys_json(std::slice::from_ref(&key1_revoked_after)), "revoked_key_policy": "refuse_revoked", "expected_valid": false},
            ],
            "policy_cases": [
                {"name": "one_key_expired_other_still_valid", "signed_cbor_hex": hex(&scope_set_cbor), "audience_keys": keys_json(&[key1_expired.clone(), w.audience2.key_ref()]), "revoked_key_policy": "accept_before_revocation", "expected_valid": true},
                {"name": "only_signer_created_within_the_clock_skew", "signed_cbor_hex": only_key1_cbor, "audience_keys": keys_json(std::slice::from_ref(&key1_created_inside_skew)), "revoked_key_policy": "accept_before_revocation", "expected_valid": true},
                {"name": "only_signer_revoked_after_signing_default_policy", "signed_cbor_hex": only_key1_cbor, "audience_keys": keys_json(std::slice::from_ref(&key1_revoked_after)), "revoked_key_policy": "accept_before_revocation", "expected_valid": true},
            ],
        },
        "handle_claims": {
            "description": "A handle claim must be about the party's account, of type handle, and signed by the party's own domain. verify_handle_claim returns the handle.",
            "party": app_ref_json(&party),
            "party_domain_keys": [domain_key_json(&w.audience_domain.domain_key())],
            "cases": [{"name": "signed_by_the_party_domain", "claim_cbor_hex": claim_hex(&good_claim), "expected_handle": "audience-team", "expected_valid": true}],
            "negative_cases": [
                {"name": "about_another_account", "claim_cbor_hex": claim_hex(&other_user_claim), "expected_valid": false},
                {"name": "not_a_handle_claim", "claim_cbor_hex": claim_hex(&other_type_claim), "expected_valid": false},
                {"name": "signed_only_by_a_third_domain", "claim_cbor_hex": claim_hex(&third_domain_claim), "expected_valid": false},
                {"name": "signed_by_a_key_that_is_not_the_domains", "claim_cbor_hex": claim_hex(&forged_claim), "expected_valid": false},
            ],
        },
        "grant_request": {
            "signed_cbor_hex": hex(&generated::encode_signed_act_as_grant_request(&signed_request)),
            "request_cbor_hex": hex(&signed_request.request),
            "signature_input_cbor_hex": hex(&envelope_signature_input(act_as::GRANT_REQUEST_TAG, &signed_request.request)),
            "cases": [{"name": "grantee_signed", "signed_cbor_hex": hex(&generated::encode_signed_act_as_grant_request(&signed_request)), "expected_valid": true}],
            "negative_cases": [
                {"name": "signed_by_a_key_that_is_not_the_grantees", "signed_cbor_hex": hex(&generated::encode_signed_act_as_grant_request(&thief_request)), "expected_valid": false},
                {"name": "verified_after_the_request_window", "signed_cbor_hex": hex(&generated::encode_signed_act_as_grant_request(&signed_request)), "now": "2026-10-06T13:00:00Z", "expected_valid": false},
            ],
        },
        "refresh_request": {
            "signed_cbor_hex": hex(&generated::encode_signed_act_as_refresh_request(&signed_refresh)),
            "grant_grantee": grantee_json(&grantee()),
            "now": "2026-10-06T12:41:00Z",
            "cases": [{"name": "grantee_signed", "signed_cbor_hex": hex(&generated::encode_signed_act_as_refresh_request(&signed_refresh)), "expected_valid": true}],
            "negative_cases": [
                {"name": "names_another_grantee", "signed_cbor_hex": hex(&generated::encode_signed_act_as_refresh_request(&other_grantee_refresh)), "expected_valid": false},
            ],
        },
        "grant": {
            "signed_cbor_hex": hex(&generated::encode_signed_act_as_grant(&grant)),
            "grant_cbor_hex": hex(&grant.grant),
            "signature_input_cbor_hex": hex(&envelope_signature_input(act_as::GRANT_TAG, &grant.grant)),
            "grant_hash_hex": hex(&act_as::grant_hash(&grant.grant)),
        },
        "revocation": {
            "cases": [{"name": "home_domain_signed", "signed_cbor_hex": hex(&generated::encode_signed_act_as_grant_revocation(&revocation)), "expected_grant_id": "grant-1", "expected_valid": true}],
            "negative_cases": [
                {"name": "signed_by_a_key_that_is_not_the_home_domains", "signed_cbor_hex": hex(&generated::encode_signed_act_as_grant_revocation(&forged_revocation)), "expected_valid": false},
            ],
        },
    })
}

fn grantee_json(g: &GranteeRef) -> Value {
    json!({
        "application": g.application.as_ref().map(app_ref_json),
        "local_rp_descriptor_fingerprint": g.local_rp_descriptor_fingerprint,
    })
}

// ---------------------------------------------------------------------------
// Credential verification at the audience
// ---------------------------------------------------------------------------

fn credential_vectors(w: &World) -> Value {
    let presented_at = base() + Duration::minutes(5);
    let verify_now = "2026-10-06T12:05:30Z";
    let grant = w.grant(&grantee(), &["read", "write"], &["read"]);
    let credential = act_as::present(
        &grant,
        &audience(),
        REQUEST_DIGEST,
        presented_at,
        b"presentation-nonce",
        &w.grantee_signer(),
    )
    .unwrap();
    let enc = |c: &generated::types::ActAsCredential| hex(&generated::encode_act_as_credential(c));

    let thief_credential = act_as::present(
        &grant,
        &audience(),
        REQUEST_DIGEST,
        presented_at,
        b"presentation-nonce",
        &GranteeSigner::Application {
            instance_id: GRANTEE_INSTANCE,
            signer: w.thief.app_signer(),
        },
    )
    .unwrap();
    let other_grant = w.grant(&grantee(), &["read", "write"], &["write"]);
    let mut swapped_grant = credential.clone();
    swapped_grant.grant = other_grant;

    let outside_scope = {
        let set = w.scope_set_value(grantee(), &["read"]);
        let scope_set =
            act_as::sign_scope_set(&set, AUDIENCE_INSTANCE, &w.audience_signers()).unwrap();
        let g = generated::types::ActAsGrant {
            grant_id: "grant-2".into(),
            user_id: "018f3333-0000-7000-8000-0000000000a1".into(),
            subject_domain: HOME_DOMAIN.into(),
            grantee: grantee(),
            audience: audience(),
            scope_set,
            approved_scope: vec!["read".into(), "admin".into()],
            issued_at: "2026-10-06T12:00:00Z".into(),
            expires_at: "2026-10-06T13:00:00Z".into(),
            series_issued_at: "2026-10-06T12:00:00Z".into(),
            renewable_until: "2026-10-06T13:00:00Z".into(),
            device_fingerprint: None,
        };
        let signed = act_as::sign_grant(&g, &[w.home.domain_signer(HOME_DOMAIN)]).unwrap();
        act_as::present(
            &signed,
            &audience(),
            REQUEST_DIGEST,
            presented_at,
            b"n",
            &w.grantee_signer(),
        )
        .unwrap()
    };

    let foreign_scope_set = {
        let other = GranteeRef {
            application: Some(app_ref("e", "e.example", "e-app")),
            local_rp_descriptor_fingerprint: None,
        };
        let set = w.scope_set_value(other, &["read"]);
        let scope_set =
            act_as::sign_scope_set(&set, AUDIENCE_INSTANCE, &w.audience_signers()).unwrap();
        let g = act_as::build_grant(&NewGrant {
            grant_id: "grant-3",
            user_id: "018f3333-0000-7000-8000-0000000000a1",
            subject_domain: HOME_DOMAIN,
            grantee: &grantee(),
            audience: &audience(),
            scope_set: &scope_set,
            approved_scope: &["read".to_string()],
            lifetime_seconds: 3600,
            renewal_window_seconds: 0,
            now: base(),
        })
        .unwrap();
        let signed = act_as::sign_grant(&g, &[w.home.domain_signer(HOME_DOMAIN)]).unwrap();
        act_as::present(
            &signed,
            &audience(),
            REQUEST_DIGEST,
            presented_at,
            b"n",
            &w.grantee_signer(),
        )
        .unwrap()
    };

    // Local-RP grantee.
    let local = local_rp_fixture(LOCAL_RP_SEED);
    let local_grantee = GranteeRef {
        application: None,
        local_rp_descriptor_fingerprint: Some(local.fingerprint.clone()),
    };
    let local_grant = w.grant(&local_grantee, &["read"], &["read"]);
    let local_credential = act_as::present(
        &local_grant,
        &audience(),
        REQUEST_DIGEST,
        presented_at,
        b"local-nonce",
        &GranteeSigner::LocalRp {
            descriptor: &local.signed,
            fingerprint: &local.fingerprint,
            signing_private_key: &local.private,
        },
    )
    .unwrap();
    let other_local = local_rp_fixture(OTHER_LOCAL_RP_SEED);
    let impostor_local = act_as::present(
        &local_grant,
        &audience(),
        REQUEST_DIGEST,
        presented_at,
        b"local-nonce",
        &GranteeSigner::LocalRp {
            descriptor: &other_local.signed,
            fingerprint: &other_local.fingerprint,
            signing_private_key: &other_local.private,
        },
    )
    .unwrap();

    json!({
        "description": "The audience's verification checklist (docs/spec/reserved/act-as-grants.md, 'Verification at the audience'). Each case lists only the context fields that differ from 'context'.",
        "context": {
            "own_application": app_ref_json(&audience()),
            "own_scope_set_keys": w.audience_key_refs().iter().map(key_ref_json).collect::<Vec<_>>(),
            "revoked_key_policy": "accept_before_revocation",
            "issuer_domain_keys": [domain_key_json(&w.home.domain_key())],
            "grantee_instance_keys": [key_ref_json(&w.grantee.key_ref())],
            "expected_request_digest_hex": hex(REQUEST_DIGEST),
            "revoked_grant_ids": [],
            "max_presentation_age_seconds": MAX_PRESENTATION_AGE_SECONDS,
            "now": verify_now,
            "skew_seconds": SKEW_SECONDS,
        },
        "cases": [
            {"name": "application_grantee", "credential_cbor_hex": enc(&credential), "expected_valid": true,
             "expected": {"grant_id": "grant-1", "user_id": "018f3333-0000-7000-8000-0000000000a1@home.conformance.example", "approved_scope": ["read"], "signer_instance_id": GRANTEE_INSTANCE, "nonce_hex": hex(b"presentation-nonce")}},
            {"name": "local_rp_grantee", "credential_cbor_hex": enc(&local_credential), "expected_valid": true,
             "expected": {"grant_id": "grant-1", "user_id": "018f3333-0000-7000-8000-0000000000a1@home.conformance.example", "approved_scope": ["read"], "signer_instance_id": null, "nonce_hex": hex(b"local-nonce")}},
        ],
        "negative_cases": [
            {"name": "another_audience", "credential_cbor_hex": enc(&credential), "own_application": app_ref_json(&app_ref("x", "x.example", "x-app")), "expected_valid": false},
            {"name": "grant_signed_by_another_domain_key", "credential_cbor_hex": enc(&credential), "issuer_domain_keys": [domain_key_json(&w.stranger_domain.domain_key())], "expected_valid": false},
            {"name": "presented_with_a_key_that_is_not_the_grantees", "credential_cbor_hex": enc(&thief_credential), "expected_valid": false},
            {"name": "presentation_for_another_request", "credential_cbor_hex": enc(&credential), "expected_request_digest_hex": hex(b"another-request"), "expected_valid": false},
            {"name": "presentation_for_another_grant", "credential_cbor_hex": enc(&swapped_grant), "expected_valid": false},
            {"name": "stale_presentation", "credential_cbor_hex": enc(&credential), "now": "2026-10-06T12:20:00Z", "expected_valid": false},
            {"name": "expired_grant", "credential_cbor_hex": enc(&credential), "now": "2026-10-06T13:01:30Z", "max_presentation_age_seconds": 7200, "expected_valid": false},
            {"name": "revoked_grant", "credential_cbor_hex": enc(&credential), "revoked_grant_ids": ["grant-1"], "expected_valid": false},
            {"name": "approved_scope_outside_scope_set", "credential_cbor_hex": enc(&outside_scope), "expected_valid": false},
            {"name": "scope_set_issued_to_another_grantee", "credential_cbor_hex": enc(&foreign_scope_set), "expected_valid": false},
            {"name": "scope_set_not_signed_by_the_audience", "credential_cbor_hex": enc(&credential), "own_scope_set_keys": [key_ref_json(&w.stranger_audience.key_ref())], "expected_valid": false},
            {"name": "local_rp_impostor_descriptor", "credential_cbor_hex": enc(&impostor_local), "expected_valid": false},
        ],
    })
}

struct LocalRpFixture {
    signed: generated::types::SignedLocalRpDescriptor,
    fingerprint: String,
    private: [u8; 32],
}

fn local_rp_fixture(seed: [u8; 32]) -> LocalRpFixture {
    let sk = SigningKey::from_bytes(&seed);
    let public = sk.verifying_key().to_bytes();
    let fingerprint = crypto::fingerprint(&public);
    let descriptor = LocalRpDescriptor {
        app_name: "conformance-local-rp".into(),
        local_domain_hint: None,
        signing_public_key: public.to_vec(),
        encryption_public_key: vec![0x77; 32],
        fingerprint: fingerprint.clone(),
        supported_suites: vec!["chacha20-poly1305".into()],
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
    };
    let signed =
        liblinkkeys::local_rp::sign_local_rp_descriptor(&descriptor, &sk.to_bytes()).unwrap();
    LocalRpFixture {
        signed,
        fingerprint,
        private: sk.to_bytes(),
    }
}

// ---------------------------------------------------------------------------
// Terms and refresh arithmetic
// ---------------------------------------------------------------------------

fn terms_vectors() -> Value {
    let bounds = act_as::DomainTermBounds::default();
    let offered_cases: Vec<Value> = [
        (None, None),
        (Some(600), None),
        (Some(10_000_000), None),
        (Some(1800), Some(7200)),
        (None, Some(100_000_000)),
    ]
    .iter()
    .map(|(l, r)| {
        let o = act_as::offered_terms(*l, *r, &bounds);
        json!({
            "requested_lifetime_seconds": l,
            "requested_renewal_window_seconds": r,
            "expected": {
                "default_lifetime_seconds": o.default_lifetime_seconds,
                "max_lifetime_seconds": o.max_lifetime_seconds,
                "default_renewal_window_seconds": o.default_renewal_window_seconds,
                "max_renewal_window_seconds": o.max_renewal_window_seconds,
            }
        })
    })
    .collect();

    let offered = act_as::offered_terms(Some(3600), Some(7200), &bounds);
    let issued_cases: Vec<Value> = [
        (600, 0),
        (3600, 7200),
        (3601, 0),
        (3600, 7201),
        (0, 0),
        (60, -1),
    ]
    .iter()
    .map(|(l, r)| {
        let result = act_as::issued_terms(&offered, *l, *r);
        json!({
            "chosen_lifetime_seconds": l,
            "chosen_renewal_window_seconds": r,
            "expected_valid": result.is_ok(),
        })
    })
    .collect();

    // Grant issued 12:00, lifetime 3600, renewal window 1800:
    // expires 13:00, renewable_until 13:30.
    let grant = generated::types::ActAsGrant {
        grant_id: "g".into(),
        user_id: "u".into(),
        subject_domain: HOME_DOMAIN.into(),
        grantee: grantee(),
        audience: audience(),
        scope_set: generated::types::SignedActAsScopeSet {
            scope_set: vec![],
            signer_instance_id: String::new(),
            signatures: vec![],
        },
        approved_scope: vec!["read".into()],
        issued_at: "2026-10-06T12:00:00Z".into(),
        expires_at: "2026-10-06T13:00:00Z".into(),
        series_issued_at: "2026-10-06T12:00:00Z".into(),
        renewable_until: "2026-10-06T13:30:00Z".into(),
        device_fingerprint: None,
    };
    let no_window = generated::types::ActAsGrant {
        renewable_until: "2026-10-06T13:00:00Z".into(),
        ..grant.clone()
    };
    let refresh_case = |name: &str, g: &generated::types::ActAsGrant, now: &str| -> Value {
        let result = act_as::refresh_decision(g, 3600, t(now));
        let expected = match result {
            Ok(act_as::RefreshDecision::Stored) => json!({"decision": "stored"}),
            Ok(act_as::RefreshDecision::Renew {
                issued_at,
                expires_at,
            }) => json!({"decision": "renew", "issued_at": issued_at, "expires_at": expires_at}),
            Err(_) => json!({"decision": "expired"}),
        };
        json!({
            "name": name,
            "grant": {
                "issued_at": g.issued_at,
                "expires_at": g.expires_at,
                "renewable_until": g.renewable_until,
            },
            "lifetime_seconds": 3600,
            "now": now,
            "expected": expected,
        })
    };

    json!({
        "description": "Act-as terms arithmetic. Offered terms come from the grantee's request and the domain bounds. A user's choice above the offer is invalid. Refresh returns stored bytes, renews, or fails for an expired grant.",
        "domain_bounds": {
            "default_lifetime_seconds": bounds.default_lifetime_seconds,
            "max_lifetime_seconds": bounds.max_lifetime_seconds,
            "max_renewal_window_seconds": bounds.max_renewal_window_seconds,
        },
        "offered_terms": offered_cases,
        "issued_terms": {
            "offer": {"requested_lifetime_seconds": 3600, "requested_renewal_window_seconds": 7200},
            "cases": issued_cases,
        },
        "refresh": [
            refresh_case("more_than_half_life_left", &grant, "2026-10-06T12:20:00Z"),
            refresh_case("after_half_life_renews_capped_at_series_end", &grant, "2026-10-06T12:40:00Z"),
            refresh_case("no_window_never_renews", &no_window, "2026-10-06T12:50:00Z"),
            refresh_case("expired_grant", &grant, "2026-10-06T13:00:00Z"),
        ],
    })
}

// ---------------------------------------------------------------------------
// Grantee signing: exact bytes an SDK must reproduce
// ---------------------------------------------------------------------------

fn grantee_signing_vectors(w: &World) -> Value {
    let local = local_rp_fixture(LOCAL_RP_SEED);
    let local_grantee = GranteeRef {
        application: None,
        local_rp_descriptor_fingerprint: Some(local.fingerprint.clone()),
    };
    let local_signer = GranteeSigner::LocalRp {
        descriptor: &local.signed,
        fingerprint: &local.fingerprint,
        signing_private_key: &local.private,
    };
    let app_signer = w.grantee_signer();

    let case = |name: &str, grantee: &GranteeRef, signer: &GranteeSigner<'_>| -> Value {
        let scope_set = act_as::sign_scope_set(
            &w.scope_set_value(grantee.clone(), &["read", "write"]),
            AUDIENCE_INSTANCE,
            &w.audience_signers(),
        )
        .unwrap();
        let request = ActAsGrantRequest {
            grantee: grantee.clone(),
            scope_set: scope_set.clone(),
            requested_lifetime_seconds: Some(1800),
            requested_renewal_window_seconds: None,
            grantee_handle_claim: None,
            callback_url: "http://app.lan:8080/act-as/callback".into(),
            nonce: "grantee-signing-nonce".into(),
            requested_at: "2026-10-06T11:59:00Z".into(),
            expires_at: "2026-10-06T12:04:00Z".into(),
        };
        let signed_request = act_as::sign_grant_request(&request, signer).unwrap();
        let refresh = ActAsRefreshRequest {
            grant_id: "grant-1".into(),
            grantee: grantee.clone(),
            requested_at: "2026-10-06T12:40:00Z".into(),
            expires_at: "2026-10-06T12:45:00Z".into(),
            nonce: "refresh-nonce".into(),
        };
        let signed_refresh = act_as::sign_refresh_request(&refresh, signer).unwrap();
        let grant = w.grant(grantee, &["read", "write"], &["read"]);
        let credential = act_as::present(
            &grant,
            &audience(),
            REQUEST_DIGEST,
            base() + Duration::minutes(5),
            b"presentation-nonce",
            signer,
        )
        .unwrap();
        json!({
            "name": name,
            "grantee": grantee_json(grantee),
            "grant_request": {
                "inputs": {
                    "scope_set_signed_cbor_hex": hex(&generated::encode_signed_act_as_scope_set(&scope_set)),
                    "requested_lifetime_seconds": 1800,
                    "requested_renewal_window_seconds": null,
                    "callback_url": request.callback_url,
                    "nonce": request.nonce,
                    "requested_at": request.requested_at,
                    "expires_at": request.expires_at,
                },
                "request_cbor_hex": hex(&signed_request.request),
                "signature_input_cbor_hex": hex(&envelope_signature_input(act_as::GRANT_REQUEST_TAG, &signed_request.request)),
                "signed_cbor_hex": hex(&generated::encode_signed_act_as_grant_request(&signed_request)),
                "url_param": base64url(&generated::encode_signed_act_as_grant_request(&signed_request)),
            },
            "refresh_request": {
                "inputs": {
                    "grant_id": refresh.grant_id,
                    "requested_at": refresh.requested_at,
                    "expires_at": refresh.expires_at,
                    "nonce": refresh.nonce,
                },
                "request_cbor_hex": hex(&signed_refresh.request),
                "signed_cbor_hex": hex(&generated::encode_signed_act_as_refresh_request(&signed_refresh)),
            },
            "presentation": {
                "inputs": {
                    "grant_signed_cbor_hex": hex(&generated::encode_signed_act_as_grant(&grant)),
                    "audience": app_ref_json(&audience()),
                    "request_digest_hex": hex(REQUEST_DIGEST),
                    "presented_at": "2026-10-06T12:05:00Z",
                    "nonce_hex": hex(b"presentation-nonce"),
                },
                "grant_hash_hex": hex(&act_as::grant_hash(&grant.grant)),
                "presentation_cbor_hex": hex(&credential.presentation.presentation),
                "credential_cbor_hex": hex(&generated::encode_act_as_credential(&credential)),
            },
        })
    };

    json!({
        "description": "Exact bytes a grantee SDK must produce. Ed25519 signing is deterministic, so with the seeds below every signature, and so every signed structure, is byte-identical. Encode each request with the CSIL codec, sign CBOR([tag, request_bytes]), and compare.",
        "tags": {
            "grant_request": act_as::GRANT_REQUEST_TAG,
            "refresh_request": act_as::REFRESH_REQUEST_TAG,
            "presentation": act_as::PRESENTATION_TAG,
        },
        "application_grantee": {
            "instance_id": GRANTEE_INSTANCE,
            "key": w.grantee.json(),
        },
        "local_rp_grantee": {
            "signing_private_key_hex": hex(&local.private),
            "fingerprint": local.fingerprint,
            "signed_descriptor_cbor_hex": hex(&generated::encode_signed_local_rp_descriptor(&local.signed)),
        },
        "cases": [
            case("application_grantee", &grantee(), &app_signer),
            case("local_rp_grantee", &local_grantee, &local_signer),
        ],
    })
}

fn base64url(bytes: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(bytes)
}
