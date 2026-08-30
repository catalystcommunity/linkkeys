//! End-to-end tests for the application-key service boundary: enrollment,
//! challenge issue and consumption, key addition, idempotent renewal,
//! revocation, and the anonymous public read — against a real database in a
//! rolled-back transaction (DataUtils pattern).
//!
//! The pure quorum, possession, and temporal rules are tested in
//! `liblinkkeys::application_keys`. What these tests cover is everything the
//! server adds on top: that the right rule is applied to the right stored
//! state, that a challenge is genuinely single-use, that a write invalidates
//! the cached response, and that the public read answers with material a peer
//! can verify with no further help from us.

mod common;

use chrono::{Duration, Utc};
use liblinkkeys::application_keys as ak;
use liblinkkeys::crypto::{fingerprint, generate_ed25519_keypair, generate_x25519_keypair};
use liblinkkeys::generated::types::{
    AddApplicationKeyRequest, ApplicationKeyAddition, ApplicationKeyRenewal,
    EnrollApplicationInstanceRequest, GetApplicationKeysRequest,
    RenewApplicationKeyAttestationRequest, RevokeApplicationKeyRequest,
};
use linkkeys::db::DbPool;
use linkkeys::services::application_keys as svc;
use std::sync::{Mutex, MutexGuard};

const APP: &str = "tinku";

/// The warm domain signer is a PROCESS-WIDE cache and is not keyed by pool.
/// In production that is correct — one process serves one domain from one
/// pool. In a test binary, several tests each hold their own rolled-back
/// transaction, so a warm entry from one test would sign with keys the next
/// test's database has never seen. Serialize the signing tests and drop the
/// cache between them.
static SIGNING: Mutex<()> = Mutex::new(());

fn signing_guard() -> MutexGuard<'static, ()> {
    let guard = SIGNING.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    linkkeys::services::warm_signer::invalidate();
    guard
}

fn domain() -> String {
    linkkeys::conversions::get_domain_name()
}

struct AppKey {
    key_id: String,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    usage: &'static str,
    algorithm: &'static str,
}

fn signing_key(id: &str) -> AppKey {
    let (vk, sk) = generate_ed25519_keypair();
    AppKey {
        key_id: id.to_string(),
        public_key: vk.as_bytes().to_vec(),
        private_key: sk.to_bytes().to_vec(),
        usage: ak::KEY_USAGE_SIGN,
        algorithm: "ed25519",
    }
}

fn agreement_key(id: &str) -> AppKey {
    let (public_key, private_key) = generate_x25519_keypair();
    AppKey {
        key_id: id.to_string(),
        public_key,
        private_key,
        usage: ak::KEY_USAGE_AGREE,
        algorithm: "x25519",
    }
}

fn signer(k: &AppKey) -> ak::ApplicationSigner<'_> {
    ak::ApplicationSigner {
        key_id: &k.key_id,
        algorithm: liblinkkeys::crypto::SigningAlgorithm::Ed25519,
        private_key_bytes: &k.private_key,
    }
}

/// Ask the domain for a challenge and turn it into the plaintext nonce the
/// signed request must carry. For a signing key that is the value as given;
/// for a key-agreement key it is what comes out of the sealed box, which is
/// the whole proof that the caller holds the X25519 private key.
fn challenge_for(
    pool: &DbPool,
    subject: &str,
    instance_id: &str,
    purpose: &str,
    key: &AppKey,
    now: chrono::DateTime<Utc>,
) -> (String, Vec<u8>) {
    let response = svc::start_challenge(
        pool,
        liblinkkeys::generated::types::StartApplicationKeyChallengeRequest {
            subject_user_id: subject.to_string(),
            application_id: APP.to_string(),
            instance_id: instance_id.to_string(),
            purpose: purpose.to_string(),
            key_usage: key.usage.to_string(),
            algorithm: key.algorithm.to_string(),
            public_key: key.public_key.clone(),
        },
        now,
    )
    .expect("challenge issued");

    let nonce = match (&response.challenge, &response.sealed_challenge) {
        (Some(plain), None) => plain.clone(),
        (None, Some(sealed)) => {
            let secret: [u8; 32] = key.private_key.clone().try_into().expect("x25519 secret");
            ak::open_challenge(sealed, &secret)
                .expect("the holder of the key opens its own challenge")
                .to_vec()
        }
        _ => panic!("exactly one of challenge and sealed_challenge must be set"),
    };
    (response.challenge_id, nonce)
}

#[allow(clippy::too_many_arguments)]
fn addition_for(
    subject: &str,
    instance_id: &str,
    key: &AppKey,
    challenge_id: String,
    challenge: Vec<u8>,
    now: chrono::DateTime<Utc>,
) -> ApplicationKeyAddition {
    ApplicationKeyAddition {
        subject_user_id: subject.to_string(),
        subject_domain: domain(),
        application_id: APP.to_string(),
        instance_id: instance_id.to_string(),
        key_id: key.key_id.clone(),
        key_usage: key.usage.to_string(),
        algorithm: key.algorithm.to_string(),
        public_key: key.public_key.clone(),
        fingerprint: fingerprint(&key.public_key),
        requested_key_lifetime_seconds: 90 * 86_400,
        challenge_id,
        challenge,
        requested_at: (now - Duration::seconds(30)).to_rfc3339(),
        expires_at: (now + Duration::seconds(120)).to_rfc3339(),
    }
}

/// Enrol an instance the way an application actually would: three signing
/// keys, each proving its own possession, in one account-authorized call.
fn enroll(
    pool: &DbPool,
    subject: &str,
    instance_id: &str,
    keys: &[&AppKey],
    now: chrono::DateTime<Utc>,
) -> Result<liblinkkeys::generated::types::EnrollApplicationInstanceResponse, String> {
    let mut signed = Vec::new();
    for key in keys {
        let (challenge_id, challenge) =
            challenge_for(pool, subject, instance_id, ak::PURPOSE_ADD, key, now);
        let addition = addition_for(subject, instance_id, key, challenge_id, challenge, now);
        let self_signer = (key.usage == ak::KEY_USAGE_SIGN).then(|| signer(key));
        signed
            .push(ak::sign_addition(&addition, &[], self_signer.as_ref()).expect("addition signs"));
    }
    svc::enroll_instance(
        pool,
        subject,
        EnrollApplicationInstanceRequest {
            application_id: APP.to_string(),
            instance_id: instance_id.to_string(),
            keys: signed,
        },
        now,
    )
    .map_err(|e| e.message)
}

fn domain_public_keys(pool: &DbPool) -> Vec<liblinkkeys::generated::types::DomainPublicKey> {
    pool.list_active_domain_keys()
        .expect("domain keys")
        .iter()
        .map(Into::into)
        .collect()
}

fn read_and_verify(
    pool: &DbPool,
    subject: &str,
    instance_id: &str,
    now: chrono::DateTime<Utc>,
) -> ak::VerifiedApplicationKeySet {
    let response = svc::get_application_keys(
        pool,
        GetApplicationKeysRequest {
            subject_user_id: subject.to_string(),
            application_id: APP.to_string(),
            instance_id: instance_id.to_string(),
        },
        now,
    )
    .expect("public read");
    let dom = domain();
    let instance = ak::InstanceRef {
        subject_user_id: subject,
        subject_domain: &dom,
        application_id: APP,
        instance_id,
    };
    let set = ak::verify_application_key_set(
        &response.keys,
        &response.revocations,
        &domain_public_keys(pool),
        &instance,
        now,
        300,
    );
    assert!(
        set.rejected.is_empty(),
        "a peer must be able to verify everything this domain published: {:?}",
        set.rejected
    );
    set
}

fn seed(pool: &DbPool) -> String {
    for _ in 0..3 {
        common::data_factory::create_domain_key(pool);
    }
    common::data_factory::create_user(pool, &Default::default()).id
}

// ---------------------------------------------------------------------------

#[test]
fn an_instance_enrolls_rotates_renews_and_revokes() {
    let _guard = signing_guard();
    let pool = common::create_test_pool();
    let subject = seed(&pool);
    let now = Utc::now();
    let instance_id = "instance-a";

    // --- initial enrollment: three signing keys, each proving possession ---
    let (a, b, c) = (signing_key("a"), signing_key("b"), signing_key("c"));
    let enrolled = enroll(&pool, &subject, instance_id, &[&a, &b, &c], now).expect("enrolls");
    assert_eq!(enrolled.attestations.len(), 3);
    assert_eq!(enrolled.subject_domain, domain());

    // A peer can verify all of it with nothing but our published domain keys.
    let set = read_and_verify(&pool, &subject, instance_id, now);
    assert_eq!(set.usable_keys(ak::KEY_USAGE_SIGN).len(), 3);
    // All valid keys of one use are equal: any of them is selectable.
    for id in ["a", "b", "c"] {
        assert!(set.key_for_use(id, ak::KEY_USAGE_SIGN, "ed25519").is_ok());
    }

    // --- rotation: two existing keys authorize a fourth ---
    let d = signing_key("d");
    let (challenge_id, challenge) =
        challenge_for(&pool, &subject, instance_id, ak::PURPOSE_ADD, &d, now);
    let addition = addition_for(&subject, instance_id, &d, challenge_id, challenge, now);
    let signed = ak::sign_addition(&addition, &[signer(&a), signer(&b)], Some(&signer(&d)))
        .expect("addition signs");
    svc::add_key(&pool, AddApplicationKeyRequest { request: signed }, now).expect("adds key");

    let set = read_and_verify(&pool, &subject, instance_id, now);
    assert_eq!(
        set.usable_keys(ak::KEY_USAGE_SIGN).len(),
        4,
        "old and new keys overlap during a rotation"
    );

    // --- renewal is idempotent while most of the lifetime remains ---
    let renewed = renew(&pool, &subject, instance_id, &a, now);
    assert!(
        !renewed.signed,
        "a renewal above the half-life must return the stored bytes and make no signature"
    );

    // Past the half-life, the domain signs again for the SAME key.
    let later = now + Duration::seconds(ak::DEFAULT_ATTESTATION_LIFETIME_SECONDS / 2 + 60);
    let renewed = renew(&pool, &subject, instance_id, &a, later);
    assert!(
        renewed.signed,
        "past the half-life a new attestation is made"
    );
    let reattested = liblinkkeys::generated::decode_application_key_attestation(
        &renewed.attestation.attestation,
    )
    .expect("decodes");
    assert_eq!(reattested.key_id, "a", "renewal never makes a new key");

    // --- revocation: two siblings revoke a third; the target cannot help ---
    let revoked_at = now.to_rfc3339();
    let revocation = ak::sign_revocation(
        &ak::InstanceRef {
            subject_user_id: &subject,
            subject_domain: &domain(),
            application_id: APP,
            instance_id,
        },
        "c",
        &fingerprint(&c.public_key),
        &revoked_at,
        &[signer(&a), signer(&b)],
    )
    .expect("revocation signs");
    svc::revoke_key(&pool, RevokeApplicationKeyRequest { revocation }, now).expect("revokes");

    let after = now + Duration::seconds(1);
    let set = read_and_verify(&pool, &subject, instance_id, after);
    assert!(
        set.key_for_use("c", ak::KEY_USAGE_SIGN, "ed25519").is_err(),
        "a revoked key must fail after its effective time"
    );
    assert!(
        set.key_for_use("a", ak::KEY_USAGE_SIGN, "ed25519").is_ok(),
        "revoking one key must not touch its siblings"
    );

    // The revocation evidence itself is republished, so a peer that has never
    // spoken to us before can still reach the same conclusion.
    let response = svc::get_application_keys(
        &pool,
        GetApplicationKeysRequest {
            subject_user_id: subject.clone(),
            application_id: APP.to_string(),
            instance_id: instance_id.to_string(),
        },
        after,
    )
    .expect("public read");
    assert_eq!(response.revocations.len(), 1);
    assert_eq!(response.revocations[0].target_key_id, "c");

    // A revoked key can never be renewed, however valid its possession proof.
    let err = renew_err(&pool, &subject, instance_id, &c, after);
    assert!(err.contains("revoked"), "unexpected error: {err}");
}

fn renew(
    pool: &DbPool,
    subject: &str,
    instance_id: &str,
    key: &AppKey,
    now: chrono::DateTime<Utc>,
) -> liblinkkeys::generated::types::RenewApplicationKeyAttestationResponse {
    renew_result(pool, subject, instance_id, key, now).expect("renews")
}

fn renew_err(
    pool: &DbPool,
    subject: &str,
    instance_id: &str,
    key: &AppKey,
    now: chrono::DateTime<Utc>,
) -> String {
    renew_result(pool, subject, instance_id, key, now).expect_err("renewal should have failed")
}

fn renew_result(
    pool: &DbPool,
    subject: &str,
    instance_id: &str,
    key: &AppKey,
    now: chrono::DateTime<Utc>,
) -> Result<liblinkkeys::generated::types::RenewApplicationKeyAttestationResponse, String> {
    let (challenge_id, challenge) =
        challenge_for(pool, subject, instance_id, ak::PURPOSE_RENEW, key, now);
    let renewal = ApplicationKeyRenewal {
        subject_user_id: subject.to_string(),
        subject_domain: domain(),
        application_id: APP.to_string(),
        instance_id: instance_id.to_string(),
        key_id: key.key_id.clone(),
        challenge_id,
        challenge,
        requested_at: (now - Duration::seconds(30)).to_rfc3339(),
        expires_at: (now + Duration::seconds(120)).to_rfc3339(),
    };
    let self_signer = (key.usage == ak::KEY_USAGE_SIGN).then(|| signer(key));
    let signed = ak::sign_renewal(&renewal, &[], self_signer.as_ref()).expect("renewal signs");
    svc::renew_attestation(
        pool,
        RenewApplicationKeyAttestationRequest { request: signed },
        now,
    )
    .map_err(|e| e.message)
}

#[test]
fn a_key_agreement_key_enrolls_only_by_opening_its_sealed_challenge() {
    let _guard = signing_guard();
    let pool = common::create_test_pool();
    let subject = seed(&pool);
    let now = Utc::now();
    let instance_id = "instance-agree";

    let (a, b) = (signing_key("a"), signing_key("b"));
    enroll(&pool, &subject, instance_id, &[&a, &b], now).expect("enrolls signing keys");

    let x = agreement_key("x");
    let (challenge_id, challenge) =
        challenge_for(&pool, &subject, instance_id, ak::PURPOSE_ADD, &x, now);
    let addition = addition_for(
        &subject,
        instance_id,
        &x,
        challenge_id.clone(),
        challenge,
        now,
    );
    // No possession proof: an X25519 key cannot sign. Returning the sealed
    // challenge plaintext is the proof.
    let signed =
        ak::sign_addition(&addition, &[signer(&a), signer(&b)], None).expect("addition signs");
    svc::add_key(&pool, AddApplicationKeyRequest { request: signed }, now)
        .expect("adds the key-agreement key");

    let set = read_and_verify(&pool, &subject, instance_id, now);
    assert!(set.key_for_use("x", ak::KEY_USAGE_AGREE, "x25519").is_ok());
    assert_eq!(
        set.usable_keys(ak::KEY_USAGE_SIGN).len(),
        2,
        "a key-agreement key is not a signing key"
    );

    // The attack this closes: enrolling a public key someone else holds. A
    // caller that cannot open the sealed box cannot produce the plaintext, so
    // it has to guess — and a wrong guess is refused.
    let stolen = agreement_key("stolen");
    let (challenge_id, _real) =
        challenge_for(&pool, &subject, instance_id, ak::PURPOSE_ADD, &stolen, now);
    let addition = addition_for(
        &subject,
        instance_id,
        &stolen,
        challenge_id,
        vec![0u8; 32],
        now,
    );
    let signed =
        ak::sign_addition(&addition, &[signer(&a), signer(&b)], None).expect("addition signs");
    let err = svc::add_key(&pool, AddApplicationKeyRequest { request: signed }, now)
        .expect_err("a key the caller does not hold must not enrol");
    assert!(
        err.message.contains("challenge"),
        "unexpected: {}",
        err.message
    );
}

#[test]
fn a_challenge_is_single_use() {
    let _guard = signing_guard();
    let pool = common::create_test_pool();
    let subject = seed(&pool);
    let now = Utc::now();
    let instance_id = "instance-replay";

    let (a, b) = (signing_key("a"), signing_key("b"));
    enroll(&pool, &subject, instance_id, &[&a, &b], now).expect("enrolls");

    let c = signing_key("c");
    let (challenge_id, challenge) =
        challenge_for(&pool, &subject, instance_id, ak::PURPOSE_ADD, &c, now);
    let addition = addition_for(
        &subject,
        instance_id,
        &c,
        challenge_id.clone(),
        challenge.clone(),
        now,
    );
    let signed = ak::sign_addition(&addition, &[signer(&a), signer(&b)], Some(&signer(&c)))
        .expect("addition signs");
    svc::add_key(
        &pool,
        AddApplicationKeyRequest {
            request: signed.clone(),
        },
        now,
    )
    .expect("first use succeeds");

    // Replaying the captured request finds no challenge left to consume, so a
    // recorded addition cannot be replayed onto the wire later.
    let err = svc::add_key(&pool, AddApplicationKeyRequest { request: signed }, now)
        .expect_err("a replayed request must fail");
    assert!(
        err.message.contains("already exists") || err.message.contains("challenge"),
        "unexpected: {}",
        err.message
    );
}

#[test]
fn one_key_cannot_authorize_an_addition_by_itself() {
    let _guard = signing_guard();
    let pool = common::create_test_pool();
    let subject = seed(&pool);
    let now = Utc::now();
    let instance_id = "instance-quorum";

    let (a, b) = (signing_key("a"), signing_key("b"));
    enroll(&pool, &subject, instance_id, &[&a, &b], now).expect("enrolls");

    // A single compromised key must not be able to add a second key and so
    // manufacture its own quorum.
    let evil = signing_key("evil");
    let (challenge_id, challenge) =
        challenge_for(&pool, &subject, instance_id, ak::PURPOSE_ADD, &evil, now);
    let addition = addition_for(&subject, instance_id, &evil, challenge_id, challenge, now);
    let signed =
        ak::sign_addition(&addition, &[signer(&a)], Some(&signer(&evil))).expect("addition signs");
    let err = svc::add_key(&pool, AddApplicationKeyRequest { request: signed }, now)
        .expect_err("one signature is not a quorum");
    assert!(
        err.message.contains("required"),
        "unexpected: {}",
        err.message
    );
}

#[test]
fn enrollment_refuses_a_single_signing_key() {
    let _guard = signing_guard();
    let pool = common::create_test_pool();
    let subject = seed(&pool);
    let now = Utc::now();

    let a = signing_key("a");
    let err = enroll(&pool, &subject, "instance-thin", &[&a], now)
        .expect_err("one key cannot bootstrap an instance");
    assert!(err.contains("at least"), "unexpected: {err}");
}

#[test]
fn an_instance_of_one_subject_is_invisible_to_another() {
    let _guard = signing_guard();
    let pool = common::create_test_pool();
    let one = seed(&pool);
    let two = common::data_factory::create_user(&pool, &Default::default()).id;
    let now = Utc::now();

    let (a, b) = (signing_key("a"), signing_key("b"));
    enroll(&pool, &one, "shared-instance-id", &[&a, &b], now).expect("enrolls");

    // The SAME application id and instance id under a different subject is a
    // different instance. A cache or query that crossed that boundary would
    // hand one account's keys to another.
    let err = svc::get_application_keys(
        &pool,
        GetApplicationKeysRequest {
            subject_user_id: two.clone(),
            application_id: APP.to_string(),
            instance_id: "shared-instance-id".to_string(),
        },
        now,
    )
    .expect_err("a different subject has no such instance");
    assert_eq!(err.code, 404);
}

#[test]
fn the_public_read_refuses_an_unknown_instance() {
    let pool = common::create_test_pool();
    let now = Utc::now();
    let err = svc::get_application_keys(
        &pool,
        GetApplicationKeysRequest {
            subject_user_id: "018f0000-0000-7000-8000-00000000dead".to_string(),
            application_id: APP.to_string(),
            instance_id: "nope".to_string(),
        },
        now,
    )
    .expect_err("unknown instance");
    assert_eq!(err.code, 404);
}

#[test]
fn a_challenge_answers_the_same_for_a_known_and_an_unknown_instance() {
    // Answering differently would turn this anonymous operation into an
    // instance-existence oracle, which is exactly the reconnaissance surface
    // the design refuses to add.
    let pool = common::create_test_pool();
    let now = Utc::now();
    let key = signing_key("probe");

    let known = challenge_for(
        &pool,
        "subject-one",
        "instance-one",
        ak::PURPOSE_ADD,
        &key,
        now,
    );
    let unknown = challenge_for(
        &pool,
        "no-such-subject",
        "no-such-instance",
        ak::PURPOSE_ADD,
        &key,
        now,
    );
    assert_eq!(known.1.len(), unknown.1.len());
    assert_ne!(known.0, unknown.0, "each challenge is its own");
}

#[test]
fn a_configuration_that_could_hide_a_revocation_is_refused() {
    let cfg = svc::AppKeyConfig {
        attestation_lifetime_seconds: 86_400,
        max_key_lifetime_seconds: 365 * 86_400,
        // Far shorter than a key can live: a revocation would fall out of the
        // look-back while the revoked key was still unexpired, and the key
        // would verify clean.
        revocation_window_seconds: 30 * 86_400,
        clock_skew_seconds: 300,
        challenge_ttl_seconds: 300,
        max_keys_per_instance: 16,
        max_revocations: 1024,
        max_response_bytes: 512 * 1024,
        renewal_quota_per_hour: 60.0,
        addition_quota_per_hour: 10.0,
    };
    let error = cfg.validate().expect_err("this must not be startable");
    assert!(error.contains("revoked"), "unexpected: {error}");

    let good = svc::AppKeyConfig {
        revocation_window_seconds: 3 * 365 * 86_400,
        ..cfg
    };
    assert!(good.validate().is_ok());
}

#[test]
fn a_forged_request_cannot_drain_a_victims_quota() {
    // The addition quota is keyed on the subject, application, and instance —
    // values an attacker can simply copy out of a public read. That is only
    // safe because the quota is spent AFTER the quorum signatures verify. If
    // it were spent first, anyone could send garbage until a legitimate
    // instance was locked out of its own key rotation.
    let _guard = signing_guard();
    let pool = common::create_test_pool();
    let subject = seed(&pool);
    let now = Utc::now();
    let instance_id = "instance-quota";

    let (a, b) = (signing_key("a"), signing_key("b"));
    enroll(&pool, &subject, instance_id, &[&a, &b], now).expect("enrolls");

    // Well past the default addition quota of 10 per hour.
    let impostor = signing_key("impostor");
    for i in 0..40 {
        let new = signing_key(&format!("forged-{i}"));
        let (challenge_id, challenge) =
            challenge_for(&pool, &subject, instance_id, ak::PURPOSE_ADD, &new, now);
        let addition = addition_for(&subject, instance_id, &new, challenge_id, challenge, now);
        // Signed by a key this instance has never heard of.
        let signed = ak::sign_addition(
            &addition,
            &[signer(&impostor), signer(&impostor)],
            Some(&signer(&new)),
        )
        .expect("addition signs");
        let err = svc::add_key(&pool, AddApplicationKeyRequest { request: signed }, now)
            .expect_err("a forged quorum must be refused");
        assert_ne!(
            err.code, 429,
            "a forged request must never reach the quota, or it could spend it"
        );
    }

    // The real instance can still rotate its own keys.
    let c = signing_key("c");
    let (challenge_id, challenge) =
        challenge_for(&pool, &subject, instance_id, ak::PURPOSE_ADD, &c, now);
    let addition = addition_for(&subject, instance_id, &c, challenge_id, challenge, now);
    let signed = ak::sign_addition(&addition, &[signer(&a), signer(&b)], Some(&signer(&c)))
        .expect("addition signs");
    svc::add_key(&pool, AddApplicationKeyRequest { request: signed }, now)
        .expect("the legitimate holder is not locked out");
}
