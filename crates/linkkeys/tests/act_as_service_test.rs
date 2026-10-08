//! End-to-end tests for the act-as service boundary: consent inspection,
//! completion, refresh and renewal, revocation, and the public revocation
//! read, against a real database in a rolled-back transaction (DataUtils
//! pattern). Application keys come from a canned key source, so no test
//! touches the network.
//!
//! The pure protocol rules are tested in `liblinkkeys::act_as`. These tests
//! cover what the server adds: stored state, nonce single-use, the account
//! checks, the local-RP admission gate, and that what the server signs is
//! verifiable by a peer with public material only.

mod common;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use common::data_factory::{create_local_rp_with_signing_key, create_user, DataMap};
use liblinkkeys::act_as::{self as aa, AudienceContext, GranteeSigner};
use liblinkkeys::application_keys::{ApplicationKeyRef, ApplicationSigner};
use liblinkkeys::crypto::{fingerprint, generate_keypair, SigningAlgorithm};
use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    ActAsGrantRequest, ActAsRefreshRequest, ActAsScopeEntry, ActAsScopeSet, ApplicationRef,
    BrowserActAsCompleteRequest, DomainPublicKey, GetActAsGrantRevocationsRequest, GranteeRef,
    LocalRpDescriptor, RefreshActAsGrantRequest, RevokeActAsGrantRequest, SignedActAsGrant,
    SignedActAsScopeSet, SignedLocalRpDescriptor,
};
use linkkeys::db::models::User;
use linkkeys::db::DbPool;
use linkkeys::services::act_as::{self as svc, InstanceKeySource};
use serde_json::json;

/// The warm domain signer is a process-wide cache that is not keyed by pool.
/// Each test holds its own rolled-back transaction, so serialize the signing
/// tests and drop the cache between them.
static SIGNING: Mutex<()> = Mutex::new(());

fn signing_guard() -> MutexGuard<'static, ()> {
    let guard = SIGNING.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("DOMAIN_KEY_PASSPHRASE", "test-passphrase");
    linkkeys::services::warm_signer::invalidate();
    guard
}

fn now() -> DateTime<Utc> {
    // Whole seconds, so stored timestamps round-trip byte-identically.
    DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
}

struct Key {
    id: String,
    public: Vec<u8>,
    private: Vec<u8>,
}

fn key(id: &str) -> Key {
    let (public, private) = generate_keypair(SigningAlgorithm::Ed25519);
    Key {
        id: id.to_string(),
        public,
        private,
    }
}

impl Key {
    fn signer(&self) -> ApplicationSigner<'_> {
        ApplicationSigner {
            key_id: &self.id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &self.private,
        }
    }

    fn key_ref(&self) -> ApplicationKeyRef {
        ApplicationKeyRef {
            key_id: self.id.clone(),
            key_usage: "sign".into(),
            algorithm: "ed25519".into(),
            public_key: self.public.clone(),
            fingerprint: fingerprint(&self.public),
            created_at: (Utc::now() - Duration::days(1)).to_rfc3339(),
            expires_at: (Utc::now() + Duration::days(30)).to_rfc3339(),
            revoked_at: None,
        }
    }
}

/// Canned attested keys per (application_id, instance_id), and canned domain
/// signing keys for handle claims.
#[derive(Default)]
struct CannedKeys {
    keys: HashMap<(String, String), Vec<ApplicationKeyRef>>,
    domains: HashMap<String, Vec<DomainPublicKey>>,
}

impl InstanceKeySource for CannedKeys {
    fn instance_keys(
        &self,
        app: &ApplicationRef,
        instance_id: &str,
        _now: DateTime<Utc>,
    ) -> Result<Vec<ApplicationKeyRef>, ServiceError> {
        Ok(self
            .keys
            .get(&(app.application_id.clone(), instance_id.to_string()))
            .cloned()
            .unwrap_or_default())
    }

    fn domain_keys(&self, domain: &str) -> Vec<DomainPublicKey> {
        self.domains.get(domain).cloned().unwrap_or_default()
    }
}

fn grantee_app() -> ApplicationRef {
    ApplicationRef {
        subject_user_id: "018f0000-0000-7000-8000-0000000000c1".into(),
        subject_domain: "grantee.test".into(),
        application_id: "grantee-app".into(),
    }
}

fn audience_app() -> ApplicationRef {
    ApplicationRef {
        subject_user_id: "018f0000-0000-7000-8000-0000000000d1".into(),
        subject_domain: "audience.test".into(),
        application_id: "audience-app".into(),
    }
}

fn app_grantee() -> GranteeRef {
    GranteeRef {
        application: Some(grantee_app()),
        local_rp_descriptor_fingerprint: None,
    }
}

struct World {
    pool: DbPool,
    user: User,
    grantee_key: Key,
    audience_key: Key,
    keys: CannedKeys,
}

fn world() -> World {
    let pool = common::create_test_pool();
    for _ in 0..3 {
        common::data_factory::create_domain_key(&pool);
    }
    let user = create_user(&pool, &DataMap::new());
    let grantee_key = key("grantee-key-1");
    let audience_key = key("audience-key-1");
    let mut keys = CannedKeys::default();
    keys.keys.insert(
        ("grantee-app".into(), "grantee-inst".into()),
        vec![grantee_key.key_ref()],
    );
    keys.keys.insert(
        ("audience-app".into(), "audience-inst".into()),
        vec![audience_key.key_ref()],
    );
    World {
        pool,
        user,
        grantee_key,
        audience_key,
        keys,
    }
}

impl World {
    fn grantee_signer(&self) -> GranteeSigner<'_> {
        GranteeSigner::Application {
            instance_id: "grantee-inst",
            signer: self.grantee_key.signer(),
        }
    }

    fn scope_set(&self, grantee: GranteeRef, expires_in: Duration) -> SignedActAsScopeSet {
        let set = ActAsScopeSet {
            audience: audience_app(),
            grantee,
            entries: ["read", "write", "delete"]
                .iter()
                .map(|s| ActAsScopeEntry {
                    scope: (*s).into(),
                    description: Some(format!("Allows {s}")),
                })
                .collect(),
            language: Some("en-US".into()),
            audience_handle_claim: None,
            issued_at: aa::format_time(now() - Duration::minutes(1)),
            expires_at: aa::format_time(now() + expires_in),
        };
        aa::sign_scope_set(&set, "audience-inst", &[self.audience_key.signer()]).unwrap()
    }

    fn signed_request_with(
        &self,
        grantee: GranteeRef,
        signer: &GranteeSigner<'_>,
        lifetime: Option<i64>,
        window: Option<i64>,
        nonce: &str,
    ) -> String {
        let request = ActAsGrantRequest {
            grantee: grantee.clone(),
            scope_set: self.scope_set(grantee, Duration::minutes(10)),
            requested_lifetime_seconds: lifetime,
            requested_renewal_window_seconds: window,
            grantee_handle_claim: None,
            callback_url: "https://grantee.test/act-as/callback?x=1".into(),
            nonce: nonce.into(),
            requested_at: aa::format_time(now() - Duration::seconds(5)),
            expires_at: aa::format_time(now() + Duration::minutes(10)),
        };
        let signed = aa::sign_grant_request(&request, signer).unwrap();
        Base64UrlUnpadded::encode_string(
            &liblinkkeys::generated::encode_signed_act_as_grant_request(&signed),
        )
    }

    fn signed_request(&self, lifetime: Option<i64>, window: Option<i64>, nonce: &str) -> String {
        self.signed_request_with(
            app_grantee(),
            &self.grantee_signer(),
            lifetime,
            window,
            nonce,
        )
    }

    fn complete(
        &self,
        signed_request: &str,
        approved: &[&str],
        lifetime: i64,
        window: i64,
    ) -> Result<String, ServiceError> {
        let nonces =
            linkkeys::web::nonce_store::NonceStore::new(self.pool.clone(), svc::nonce_ttl());
        svc::complete(
            &self.pool,
            &self.keys,
            &|n| nonces.record(n),
            &self.user,
            &BrowserActAsCompleteRequest {
                signed_request: signed_request.to_string(),
                approved_scope: approved.iter().map(|s| (*s).to_string()).collect(),
                lifetime_seconds: lifetime,
                renewal_window_seconds: window,
            },
            now(),
        )
        .map(|r| r.redirect_url)
    }

    fn domain_keys(&self) -> Vec<DomainPublicKey> {
        self.pool
            .list_active_domain_keys()
            .unwrap()
            .iter()
            .map(Into::into)
            .collect()
    }

    fn refresh(
        &self,
        grant_id: &str,
        signer: &GranteeSigner<'_>,
        at: DateTime<Utc>,
    ) -> Result<(SignedActAsGrant, bool), ServiceError> {
        let request = ActAsRefreshRequest {
            grant_id: grant_id.to_string(),
            grantee: app_grantee(),
            requested_at: aa::format_time(at - Duration::seconds(5)),
            expires_at: aa::format_time(at + Duration::minutes(5)),
            nonce: "refresh-nonce".into(),
        };
        let signed = aa::sign_refresh_request(&request, signer).unwrap();
        svc::refresh(
            &self.pool,
            &self.keys,
            &RefreshActAsGrantRequest { request: signed },
            at,
        )
        .map(|r| (r.grant, r.signed))
    }
}

fn grant_id_from(redirect: &str) -> String {
    let query = redirect.split_once('?').unwrap().1;
    query
        .split('&')
        .find_map(|p| p.strip_prefix("act_as_grant_id="))
        .unwrap()
        .to_string()
}

// ---------------------------------------------------------------------------

#[test]
fn inspect_complete_and_present_end_to_end() {
    let _g = signing_guard();
    let w = world();
    let sr = w.signed_request(Some(1800), Some(3600), "nonce-1");

    let inspected = svc::inspect(&w.pool, &w.keys, &w.user, &sr, now()).unwrap();
    assert_eq!(inspected.entries.len(), 3);
    assert!(inspected.entries.iter().all(|e| !e.removed_by_policy));
    assert_eq!(inspected.default_lifetime_seconds, 1800);
    assert_eq!(inspected.max_lifetime_seconds, 1800);
    assert_eq!(inspected.max_renewal_window_seconds, 3600);
    assert_eq!(inspected.audience, audience_app());
    let g = &inspected.grantee_party;
    assert_eq!(g.domain.as_deref(), Some("grantee.test"));
    assert_eq!(g.application_id.as_deref(), Some("grantee-app"));
    assert_eq!(
        g.subject_user_id.as_deref(),
        Some(grantee_app().subject_user_id.as_str())
    );
    assert_eq!(g.handle, None);
    assert!(!g.user_has_history && !g.domain_key_pinned && !g.operator_trusted && !g.own_domain);
    assert_eq!(
        inspected.audience_party.domain.as_deref(),
        Some("audience.test")
    );

    let redirect = w.complete(&sr, &["read"], 1800, 0).unwrap();
    assert!(redirect.starts_with("https://grantee.test/act-as/callback?x=1&act_as_grant_id="));
    assert!(redirect.ends_with("&nonce=nonce-1"));
    let grant_id = grant_id_from(&redirect);

    // The grantee fetches its grant; a fresh grant is returned as stored.
    let (grant, signed) = w.refresh(&grant_id, &w.grantee_signer(), now()).unwrap();
    assert!(!signed);
    let record = w.pool.find_act_as_grant(&grant_id).unwrap().unwrap();
    assert_eq!(
        liblinkkeys::generated::encode_signed_act_as_grant(&grant),
        record.signed_grant
    );

    // A peer verifies it with public material only.
    let decoded = aa::verify_grant_signature(&grant, &w.domain_keys()).unwrap();
    assert_eq!(decoded.user_id, w.user.id);
    assert_eq!(decoded.approved_scope, vec!["read".to_string()]);

    let credential = aa::present(
        &grant,
        &audience_app(),
        b"request-digest",
        now(),
        b"presentation-nonce",
        &w.grantee_signer(),
    )
    .unwrap();
    let own_keys = [w.audience_key.key_ref()];
    let grantee_keys = [w.grantee_key.key_ref()];
    let domain_keys = w.domain_keys();
    let audience = audience_app();
    let verified = aa::verify_credential(
        &credential,
        &AudienceContext {
            own_application: &audience,
            own_scope_set_keys: &own_keys,
            issuer_domain_keys: &domain_keys,
            grantee_instance_keys: &grantee_keys,
            expected_request_digest: b"request-digest",
            revoked_grant_ids: &[],
            max_presentation_age_seconds: 300,
            now: now(),
            skew_seconds: 60,
            revoked_key_policy: aa::RevokedKeyPolicy::default(),
        },
    )
    .unwrap();
    assert_eq!(verified.grant_id, grant_id);
    assert_eq!(
        verified.user_id,
        format!("{}@{}", w.user.id, linkkeys::conversions::get_domain_name())
    );
}

#[test]
fn a_grant_request_is_single_use() {
    let _g = signing_guard();
    let w = world();
    let sr = w.signed_request(None, None, "nonce-once");
    w.complete(&sr, &["read"], 3600, 0).unwrap();
    let err = w.complete(&sr, &["read"], 3600, 0).unwrap_err();
    assert_eq!(err.code, 400);
    assert!(err.message.contains("already used"), "{}", err.message);
}

#[test]
fn the_user_cannot_exceed_the_offer_or_leave_the_scope_set() {
    let _g = signing_guard();
    let w = world();
    let sr = w.signed_request(Some(600), None, "nonce-terms");
    assert_eq!(w.complete(&sr, &["read"], 601, 0).unwrap_err().code, 400);
    assert_eq!(w.complete(&sr, &["read"], 600, 1).unwrap_err().code, 400);
    assert_eq!(w.complete(&sr, &["admin"], 600, 0).unwrap_err().code, 400);
    assert_eq!(w.complete(&sr, &[], 600, 0).unwrap_err().code, 400);
    // The failed attempts did not burn the nonce.
    assert!(w.complete(&sr, &["read", "write"], 600, 0).is_ok());
}

#[test]
fn an_expired_scope_set_is_refused_at_inspection() {
    let w = world();
    let request = ActAsGrantRequest {
        grantee: app_grantee(),
        scope_set: w.scope_set(app_grantee(), Duration::minutes(-2)),
        requested_lifetime_seconds: None,
        requested_renewal_window_seconds: None,
        grantee_handle_claim: None,
        callback_url: "https://grantee.test/cb".into(),
        nonce: "n".into(),
        requested_at: aa::format_time(now() - Duration::seconds(5)),
        expires_at: aa::format_time(now() + Duration::minutes(5)),
    };
    let signed = aa::sign_grant_request(&request, &w.grantee_signer()).unwrap();
    let sr = Base64UrlUnpadded::encode_string(
        &liblinkkeys::generated::encode_signed_act_as_grant_request(&signed),
    );
    let err = svc::inspect(&w.pool, &w.keys, &w.user, &sr, now()).unwrap_err();
    assert_eq!(err.code, 400);
    assert!(
        err.message.contains("scope set has expired"),
        "{}",
        err.message
    );
}

#[test]
fn a_request_window_longer_than_the_cap_is_refused() {
    let w = world();
    let request = ActAsGrantRequest {
        grantee: app_grantee(),
        scope_set: w.scope_set(app_grantee(), Duration::minutes(10)),
        requested_lifetime_seconds: None,
        requested_renewal_window_seconds: None,
        grantee_handle_claim: None,
        callback_url: "https://grantee.test/cb".into(),
        nonce: "n".into(),
        requested_at: aa::format_time(now() - Duration::seconds(5)),
        expires_at: aa::format_time(now() + Duration::hours(2)),
    };
    let signed = aa::sign_grant_request(&request, &w.grantee_signer()).unwrap();
    let sr = Base64UrlUnpadded::encode_string(
        &liblinkkeys::generated::encode_signed_act_as_grant_request(&signed),
    );
    assert_eq!(
        svc::inspect(&w.pool, &w.keys, &w.user, &sr, now())
            .unwrap_err()
            .code,
        400
    );
}

#[test]
fn a_request_signed_by_a_key_the_grantee_does_not_hold_is_refused() {
    let w = world();
    let thief = key("grantee-key-1");
    let sr = w.signed_request_with(
        app_grantee(),
        &GranteeSigner::Application {
            instance_id: "grantee-inst",
            signer: thief.signer(),
        },
        None,
        None,
        "n",
    );
    assert_eq!(
        svc::inspect(&w.pool, &w.keys, &w.user, &sr, now())
            .unwrap_err()
            .code,
        400
    );
}

#[test]
fn an_administrator_account_cannot_grant() {
    let w = world();
    let admin = User {
        is_admin_account: true,
        ..w.user.clone()
    };
    let sr = w.signed_request(None, None, "n");
    assert_eq!(
        svc::inspect(&w.pool, &w.keys, &admin, &sr, now())
            .unwrap_err()
            .code,
        403
    );
}

#[test]
fn refresh_renews_only_with_a_window_and_after_half_life() {
    let _g = signing_guard();
    let w = world();

    // No renewal window: refresh never signs, and fails after expiry.
    let sr = w.signed_request(Some(600), None, "n-no-window");
    let id = grant_id_from(&w.complete(&sr, &["read"], 600, 0).unwrap());
    let (_, signed) = w
        .refresh(&id, &w.grantee_signer(), now() + Duration::seconds(400))
        .unwrap();
    assert!(!signed);
    assert_eq!(
        w.refresh(&id, &w.grantee_signer(), now() + Duration::seconds(601))
            .unwrap_err()
            .code,
        403
    );

    // With a window: stored before half-life, renewed after it.
    let sr = w.signed_request(Some(600), Some(3600), "n-window");
    let id = grant_id_from(&w.complete(&sr, &["read"], 600, 3600).unwrap());
    let (_, signed) = w
        .refresh(&id, &w.grantee_signer(), now() + Duration::seconds(100))
        .unwrap();
    assert!(!signed);
    let at = now() + Duration::seconds(400);
    let (renewed, signed) = w.refresh(&id, &w.grantee_signer(), at).unwrap();
    assert!(signed);
    let decoded = aa::verify_grant_signature(&renewed, &w.domain_keys()).unwrap();
    assert_eq!(decoded.grant_id, id);
    assert_eq!(decoded.issued_at, aa::format_time(at));
    assert_eq!(
        decoded.expires_at,
        aa::format_time(at + Duration::seconds(600))
    );
    let record = w.pool.find_act_as_grant(&id).unwrap().unwrap();
    assert_eq!(record.expires_at, decoded.expires_at);
    assert_eq!(record.renewable_until, decoded.renewable_until);
}

#[test]
fn refresh_refuses_an_unknown_grant_and_another_applications_key() {
    let _g = signing_guard();
    let w = world();
    let unknown = uuid::Uuid::now_v7().to_string();
    assert_eq!(
        w.refresh(&unknown, &w.grantee_signer(), now())
            .unwrap_err()
            .code,
        404
    );
    let sr = w.signed_request(None, None, "n");
    let id = grant_id_from(&w.complete(&sr, &["read"], 3600, 0).unwrap());
    let thief = key("grantee-key-1");
    let err = w
        .refresh(
            &id,
            &GranteeSigner::Application {
                instance_id: "grantee-inst",
                signer: thief.signer(),
            },
            now(),
        )
        .unwrap_err();
    assert_eq!(err.code, 400);
}

#[test]
fn a_refresh_window_longer_than_the_cap_is_refused() {
    let _g = signing_guard();
    let w = world();
    let sr = w.signed_request(None, None, "n-long-refresh");
    let id = grant_id_from(&w.complete(&sr, &["read"], 3600, 0).unwrap());
    let refresh_with_window = |window: Duration| {
        let request = ActAsRefreshRequest {
            grant_id: id.clone(),
            grantee: app_grantee(),
            requested_at: aa::format_time(now()),
            expires_at: aa::format_time(now() + window),
            nonce: "refresh-nonce".into(),
        };
        let signed = aa::sign_refresh_request(&request, &w.grantee_signer()).unwrap();
        svc::refresh(
            &w.pool,
            &w.keys,
            &RefreshActAsGrantRequest { request: signed },
            now(),
        )
    };
    assert!(refresh_with_window(Duration::seconds(svc::MAX_REQUEST_WINDOW_SECONDS)).is_ok());
    // A request a grantee signed for a year must not be replayable for a year.
    assert_eq!(
        refresh_with_window(Duration::days(365)).unwrap_err().code,
        400
    );
}

#[test]
fn revocation_is_owner_only_published_and_stops_refresh() {
    let _g = signing_guard();
    let w = world();
    let sr = w.signed_request(None, Some(3600), "n");
    let id = grant_id_from(&w.complete(&sr, &["read"], 3600, 3600).unwrap());

    let stranger = create_user(&w.pool, &DataMap::new());
    assert_eq!(
        svc::revoke_for_user(
            &w.pool,
            &stranger,
            &RevokeActAsGrantRequest {
                grant_id: id.clone()
            },
            now()
        )
        .unwrap_err()
        .code,
        404
    );

    let first = svc::revoke_for_user(
        &w.pool,
        &w.user,
        &RevokeActAsGrantRequest {
            grant_id: id.clone(),
        },
        now(),
    )
    .unwrap();
    let again = svc::revoke_for_user(
        &w.pool,
        &w.user,
        &RevokeActAsGrantRequest {
            grant_id: id.clone(),
        },
        now() + Duration::seconds(5),
    )
    .unwrap();
    assert_eq!(first.revoked_at, again.revoked_at);

    let published = svc::get_revocations(
        &w.pool,
        &GetActAsGrantRevocationsRequest {
            grant_ids: vec![id.clone(), uuid::Uuid::now_v7().to_string()],
        },
    )
    .unwrap();
    let revoked = aa::revoked_grant_ids(
        &published.revocations,
        &w.domain_keys(),
        &linkkeys::conversions::get_domain_name(),
    );
    assert_eq!(revoked, vec![id.clone()]);

    assert_eq!(
        w.refresh(&id, &w.grantee_signer(), now()).unwrap_err().code,
        403
    );

    let listed = svc::list_for_user(&w.pool, &w.user).unwrap();
    assert_eq!(listed.grants.len(), 1);
    assert_eq!(
        listed.grants[0].revoked_at.as_deref(),
        Some(first.revoked_at.as_str())
    );
    assert!(svc::list_for_user(&w.pool, &stranger)
        .unwrap()
        .grants
        .is_empty());
}

#[test]
fn the_revocation_read_is_bounded() {
    let w = world();
    assert_eq!(
        svc::get_revocations(
            &w.pool,
            &GetActAsGrantRevocationsRequest { grant_ids: vec![] }
        )
        .unwrap_err()
        .code,
        400
    );
    let too_many: Vec<String> = (0..=aa::MAX_REVOCATION_LOOKUP_IDS)
        .map(|_| uuid::Uuid::now_v7().to_string())
        .collect();
    assert_eq!(
        svc::get_revocations(
            &w.pool,
            &GetActAsGrantRevocationsRequest {
                grant_ids: too_many
            }
        )
        .unwrap_err()
        .code,
        400
    );
}

fn local_rp_descriptor(signing_private: &[u8]) -> (SignedLocalRpDescriptor, String) {
    let sk = ed25519_dalek::SigningKey::from_bytes(signing_private.try_into().unwrap());
    let public = sk.verifying_key().to_bytes().to_vec();
    let fp = fingerprint(&public);
    let descriptor = LocalRpDescriptor {
        app_name: "Desk App".into(),
        local_domain_hint: None,
        signing_public_key: public,
        encryption_public_key: vec![9; 32],
        fingerprint: fp.clone(),
        supported_suites: vec!["chacha20-poly1305".into()],
        created_at: (Utc::now() - Duration::days(1)).to_rfc3339(),
        expires_at: (Utc::now() + Duration::days(30)).to_rfc3339(),
    };
    (
        liblinkkeys::local_rp::sign_local_rp_descriptor(&descriptor, signing_private).unwrap(),
        fp,
    )
}

#[test]
fn a_local_rp_grantee_must_be_approved() {
    let _g = signing_guard();
    let w = world();
    for (status, allowed) in [("pending", false), ("approved", true)] {
        let (rp, private) = create_local_rp_with_signing_key(
            &w.pool,
            &[("status".to_string(), json!(status))]
                .into_iter()
                .collect(),
        );
        let (descriptor, fp) = local_rp_descriptor(&private);
        assert_eq!(fp, rp.fingerprint);
        let grantee = GranteeRef {
            application: None,
            local_rp_descriptor_fingerprint: Some(fp.clone()),
        };
        let signer = GranteeSigner::LocalRp {
            descriptor: &descriptor,
            fingerprint: &fp,
            signing_private_key: &private,
        };
        let sr = w.signed_request_with(grantee, &signer, None, None, status);
        let result = svc::inspect(&w.pool, &w.keys, &w.user, &sr, now());
        if allowed {
            let inspected = result.unwrap();
            assert_eq!(
                inspected.grantee_party.local_rp_name.as_deref(),
                Some("Desk App")
            );
            assert_eq!(
                inspected.grantee_party.local_rp_fingerprint.as_deref(),
                Some(fp.as_str())
            );
            assert_eq!(inspected.grantee_party.domain, None);
            assert!(inspected.grantee_party.operator_trusted);
            assert!(w.complete(&sr, &["read"], 3600, 0).is_ok());
        } else {
            assert_eq!(result.unwrap_err().code, 403);
        }
    }
}

// ---------------------------------------------------------------------------
// Consent-screen parties and key tolerance
// ---------------------------------------------------------------------------

fn handle_claim(
    subject: &ApplicationRef,
    domain_key: &Key,
    value: &str,
) -> liblinkkeys::generated::types::Claim {
    liblinkkeys::claims::sign_claim(
        &liblinkkeys::claims::ClaimSpec {
            claim_id: "handle-1",
            claim_type: "handle",
            claim_value: value.as_bytes(),
            user_id: &subject.subject_user_id,
            subject_domain: &subject.subject_domain,
            expires_at: None,
            attested_at: &aa::format_time(now() - Duration::hours(1)),
        },
        &[liblinkkeys::claims::ClaimSigner {
            domain: &subject.subject_domain,
            key_id: &domain_key.id,
            algorithm: SigningAlgorithm::Ed25519,
            private_key_bytes: &domain_key.private,
        }],
    )
    .unwrap()
}

fn domain_public(k: &Key) -> DomainPublicKey {
    DomainPublicKey {
        key_id: k.id.clone(),
        public_key: k.public.clone(),
        fingerprint: fingerprint(&k.public),
        algorithm: "ed25519".into(),
        key_usage: "sign".into(),
        created_at: String::new(),
        expires_at: "2126-01-01T00:00:00Z".into(),
        revoked_at: None,
        signed_by_key_id: None,
        key_signature: None,
    }
}

#[test]
fn verified_handle_claims_are_shown_and_bad_ones_are_dropped() {
    let mut w = world();
    let grantee_domain_key = key("grantee-domain-key");
    w.keys.domains.insert(
        "grantee.test".into(),
        vec![domain_public(&grantee_domain_key)],
    );
    let good = handle_claim(&grantee_app(), &grantee_domain_key, "grantee-team");
    let forged = handle_claim(&grantee_app(), &key("grantee-domain-key"), "impostor");
    for (claim, expected) in [(good, Some("grantee-team")), (forged, None)] {
        let request = ActAsGrantRequest {
            grantee: app_grantee(),
            scope_set: w.scope_set(app_grantee(), Duration::minutes(10)),
            requested_lifetime_seconds: None,
            requested_renewal_window_seconds: None,
            grantee_handle_claim: Some(claim),
            callback_url: "https://grantee.test/cb".into(),
            nonce: "n".into(),
            requested_at: aa::format_time(now() - Duration::seconds(5)),
            expires_at: aa::format_time(now() + Duration::minutes(5)),
        };
        let signed = aa::sign_grant_request(&request, &w.grantee_signer()).unwrap();
        let sr = Base64UrlUnpadded::encode_string(
            &liblinkkeys::generated::encode_signed_act_as_grant_request(&signed),
        );
        let inspected = svc::inspect(&w.pool, &w.keys, &w.user, &sr, now()).unwrap();
        assert_eq!(inspected.grantee_party.handle.as_deref(), expected);
    }
}

#[test]
fn trust_signals_reflect_pins_operator_trust_and_user_history() {
    let _g = signing_guard();
    let w = world();
    w.pool.create_domain_pin("audience.test", "abc").unwrap();
    w.pool.add_trusted_issuer("handle", "grantee.test").unwrap();
    let sr = w.signed_request(None, None, "first");
    let inspected = svc::inspect(&w.pool, &w.keys, &w.user, &sr, now()).unwrap();
    assert!(inspected.audience_party.domain_key_pinned);
    assert!(!inspected.audience_party.operator_trusted);
    assert!(inspected.grantee_party.operator_trusted);
    assert!(!inspected.grantee_party.user_has_history);
    assert!(!inspected.audience_party.user_has_history);

    w.complete(&sr, &["read"], 3600, 0).unwrap();
    let sr = w.signed_request(None, None, "second");
    let inspected = svc::inspect(&w.pool, &w.keys, &w.user, &sr, now()).unwrap();
    assert!(inspected.grantee_party.user_has_history);
    assert!(inspected.audience_party.user_has_history);
}

#[test]
fn a_scope_set_survives_when_one_of_its_signing_keys_expired() {
    let mut w = world();
    let second = key("audience-key-2");
    let set = ActAsScopeSet {
        audience: audience_app(),
        grantee: app_grantee(),
        entries: vec![ActAsScopeEntry {
            scope: "read".into(),
            description: None,
        }],
        language: None,
        audience_handle_claim: None,
        issued_at: aa::format_time(now() - Duration::minutes(1)),
        expires_at: aa::format_time(now() + Duration::minutes(10)),
    };
    let scope_set = aa::sign_scope_set(
        &set,
        "audience-inst",
        &[w.audience_key.signer(), second.signer()],
    )
    .unwrap();
    // The first key expired before the set was issued; the second is valid.
    let mut expired = w.audience_key.key_ref();
    expired.expires_at = (Utc::now() - Duration::days(1)).to_rfc3339();
    w.keys.keys.insert(
        ("audience-app".into(), "audience-inst".into()),
        vec![expired, second.key_ref()],
    );
    let request = ActAsGrantRequest {
        grantee: app_grantee(),
        scope_set,
        requested_lifetime_seconds: None,
        requested_renewal_window_seconds: None,
        grantee_handle_claim: None,
        callback_url: "https://grantee.test/cb".into(),
        nonce: "n".into(),
        requested_at: aa::format_time(now() - Duration::seconds(5)),
        expires_at: aa::format_time(now() + Duration::minutes(5)),
    };
    let signed = aa::sign_grant_request(&request, &w.grantee_signer()).unwrap();
    let sr = Base64UrlUnpadded::encode_string(
        &liblinkkeys::generated::encode_signed_act_as_grant_request(&signed),
    );
    assert!(svc::inspect(&w.pool, &w.keys, &w.user, &sr, now()).is_ok());
}
