use super::*;
use crate::crypto::{fingerprint, generate_keypair, SigningAlgorithm};
use crate::generated::types::{ActAsScopeEntry, LocalRpDescriptor};
use chrono::TimeZone;

const HOME: &str = "home.example";
const SKEW: i64 = 60;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 6, 12, 0, 0).unwrap()
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

fn app_key_ref(k: &Key) -> ApplicationKeyRef {
    ApplicationKeyRef {
        key_id: k.id.clone(),
        key_usage: "sign".into(),
        algorithm: "ed25519".into(),
        public_key: k.public.clone(),
        fingerprint: fingerprint(&k.public),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        revoked_at: None,
    }
}

fn app_signer(k: &Key) -> ApplicationSigner<'_> {
    ApplicationSigner {
        key_id: &k.id,
        algorithm: SigningAlgorithm::Ed25519,
        private_key_bytes: &k.private,
    }
}

fn domain_public(k: &Key) -> DomainPublicKey {
    DomainPublicKey {
        key_id: k.id.clone(),
        public_key: k.public.clone(),
        fingerprint: fingerprint(&k.public),
        algorithm: "ed25519".into(),
        key_usage: "sign".into(),
        created_at: String::new(),
        // Domain key validity is checked against wall-clock time.
        expires_at: "2126-01-01T00:00:00Z".into(),
        revoked_at: None,
        signed_by_key_id: None,
        key_signature: None,
    }
}

fn domain_signer<'a>(k: &'a Key, domain: &'a str) -> ClaimSigner<'a> {
    ClaimSigner {
        domain,
        key_id: &k.id,
        algorithm: SigningAlgorithm::Ed25519,
        private_key_bytes: &k.private,
    }
}

fn app_ref(user: &str, domain: &str, app: &str) -> ApplicationRef {
    ApplicationRef {
        subject_user_id: user.into(),
        subject_domain: domain.into(),
        application_id: app.into(),
    }
}

fn grantee_c() -> GranteeRef {
    GranteeRef {
        application: Some(app_ref("c-owner", "c.example", "app-c")),
        local_rp_descriptor_fingerprint: None,
    }
}

fn audience_d() -> ApplicationRef {
    app_ref("d-owner", "d.example", "app-d")
}

struct World {
    home_key: Key,
    c_key: Key,
    d_key: Key,
    audience: ApplicationRef,
}

impl World {
    fn new() -> Self {
        Self {
            home_key: key("home-1"),
            c_key: key("c-1"),
            d_key: key("d-1"),
            audience: audience_d(),
        }
    }

    fn c_signer(&self) -> GranteeSigner<'_> {
        GranteeSigner::Application {
            instance_id: "c-inst",
            signer: app_signer(&self.c_key),
        }
    }

    fn scope_set(&self, grantee: GranteeRef, scopes: &[&str]) -> SignedActAsScopeSet {
        let set = ActAsScopeSet {
            audience: audience_d(),
            grantee,
            entries: scopes
                .iter()
                .map(|s| ActAsScopeEntry {
                    scope: (*s).into(),
                    description: Some(format!("Lets the app {s}")),
                })
                .collect(),
            language: Some("en-US".into()),
            audience_handle_claim: None,
            issued_at: "2026-10-06T11:55:00Z".into(),
            expires_at: "2026-10-06T12:10:00Z".into(),
        };
        sign_scope_set(&set, "d-inst", &[app_signer(&self.d_key)]).unwrap()
    }

    fn grant(&self, approved: &[&str], lifetime: i64, window: i64) -> SignedActAsGrant {
        let scope_set = self.scope_set(grantee_c(), &["read", "write", "delete"]);
        let approved: Vec<String> = approved.iter().map(|s| (*s).to_string()).collect();
        let grant = build_grant(&NewGrant {
            grant_id: "grant-1",
            user_id: "user-1",
            subject_domain: HOME,
            grantee: &grantee_c(),
            audience: &audience_d(),
            scope_set: &scope_set,
            approved_scope: &approved,
            lifetime_seconds: lifetime,
            renewal_window_seconds: window,
            now: now(),
        })
        .unwrap();
        sign_grant(&grant, &[domain_signer(&self.home_key, HOME)]).unwrap()
    }

    fn ctx<'a>(
        &'a self,
        d_keys: &'a [ApplicationKeyRef],
        home_keys: &'a [DomainPublicKey],
        c_keys: &'a [ApplicationKeyRef],
        digest: &'a [u8],
        revoked: &'a [String],
    ) -> AudienceContext<'a> {
        AudienceContext {
            own_application: &self.audience,
            own_scope_set_keys: d_keys,
            issuer_domain_keys: home_keys,
            grantee_instance_keys: c_keys,
            expected_request_digest: digest,
            revoked_grant_ids: revoked,
            max_presentation_age_seconds: 300,
            now: now() + Duration::minutes(5),
            skew_seconds: SKEW,
            revoked_key_policy: RevokedKeyPolicy::default(),
        }
    }
}

fn verify_default(w: &World, credential: &ActAsCredential) -> Result<VerifiedActAs, ActAsError> {
    let d_keys = [app_key_ref(&w.d_key)];
    let home_keys = [domain_public(&w.home_key)];
    let c_keys = [app_key_ref(&w.c_key)];
    verify_credential(
        credential,
        &w.ctx(&d_keys, &home_keys, &c_keys, b"digest", &[]),
    )
}

fn presented(w: &World, grant: &SignedActAsGrant) -> ActAsCredential {
    present(
        grant,
        &audience_d(),
        b"digest",
        now() + Duration::minutes(5),
        b"nonce-1",
        &w.c_signer(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

#[test]
fn full_flow_request_grant_present_verify() {
    let w = World::new();
    let scope_set = w.scope_set(grantee_c(), &["read", "write"]);
    let request = ActAsGrantRequest {
        grantee: grantee_c(),
        scope_set: scope_set.clone(),
        requested_lifetime_seconds: Some(1800),
        requested_renewal_window_seconds: Some(3600),
        grantee_handle_claim: None,
        callback_url: "https://c.example/act-as/callback".into(),
        nonce: "n-1".into(),
        requested_at: "2026-10-06T11:59:00Z".into(),
        expires_at: "2026-10-06T12:09:00Z".into(),
    };
    let signed_request = sign_grant_request(&request, &w.c_signer()).unwrap();

    // Home domain side.
    let c_keys = [app_key_ref(&w.c_key)];
    let verified_request = verify_grant_request(&signed_request, &c_keys, now(), SKEW).unwrap();
    let audience = verified_request.scope_set.clone();
    let d_keys = [app_key_ref(&w.d_key)];
    let set = verify_scope_set(
        &audience,
        &audience_d(),
        &d_keys,
        RevokedKeyPolicy::default(),
    )
    .unwrap();
    check_scope_set_current(&set, now(), SKEW).unwrap();
    assert!(same_grantee(&set.grantee, &verified_request.grantee));
    let offered = offered_terms(
        verified_request.requested_lifetime_seconds,
        verified_request.requested_renewal_window_seconds,
        &DomainTermBounds::default(),
    );
    let (lifetime, window) = issued_terms(&offered, 1800, 3600).unwrap();
    let approved = vec!["read".to_string()];
    check_approved_scope(&set, &approved).unwrap();
    let grant = build_grant(&NewGrant {
        grant_id: "grant-1",
        user_id: "user-1",
        subject_domain: HOME,
        grantee: &verified_request.grantee,
        audience: &set.audience,
        scope_set: &audience,
        approved_scope: &approved,
        lifetime_seconds: lifetime,
        renewal_window_seconds: window,
        now: now(),
    })
    .unwrap();
    let signed_grant = sign_grant(&grant, &[domain_signer(&w.home_key, HOME)]).unwrap();

    // Grantee presents; audience verifies.
    let credential = presented(&w, &signed_grant);
    let verified = verify_default(&w, &credential).unwrap();
    assert_eq!(verified.user_id, "user-1@home.example");
    assert_eq!(verified.approved_scope, vec!["read".to_string()]);
    assert_eq!(verified.signer.instance_id.as_deref(), Some("c-inst"));
    assert_eq!(verified.nonce, b"nonce-1");
    assert_eq!(credential_signer_instance(&credential), Some("c-inst"));
    assert_eq!(credential_scope_set_signer(&credential).unwrap(), "d-inst");
}

// ---------------------------------------------------------------------------
// Scope sets
// ---------------------------------------------------------------------------

#[test]
fn scope_set_for_another_audience_is_refused() {
    let w = World::new();
    let signed = w.scope_set(grantee_c(), &["read"]);
    let other = app_ref("x", "x.example", "app-x");
    assert_eq!(
        verify_scope_set(
            &signed,
            &other,
            &[app_key_ref(&w.d_key)],
            RevokedKeyPolicy::default()
        ),
        Err(ActAsError::Mismatch("scope_set.audience"))
    );
}

#[test]
fn scope_set_signed_by_a_key_that_is_not_the_audiences_is_refused() {
    let w = World::new();
    let signed = w.scope_set(grantee_c(), &["read"]);
    let stranger = key("d-1");
    assert_eq!(
        verify_scope_set(
            &signed,
            &audience_d(),
            &[app_key_ref(&stranger)],
            RevokedKeyPolicy::default()
        ),
        Err(ActAsError::NoValidSignature(
            "d-1: signature did not verify".into()
        ))
    );
    assert_eq!(
        verify_scope_set(&signed, &audience_d(), &[], RevokedKeyPolicy::default()),
        Err(ActAsError::NoValidSignature(
            "d-1: not a key of the audience".into()
        ))
    );
}

#[test]
fn scope_set_with_repeated_scope_cannot_be_signed() {
    let w = World::new();
    let set = ActAsScopeSet {
        audience: audience_d(),
        grantee: grantee_c(),
        entries: vec![
            ActAsScopeEntry {
                scope: "read".into(),
                description: None,
            },
            ActAsScopeEntry {
                scope: "read".into(),
                description: None,
            },
        ],
        language: None,
        audience_handle_claim: None,
        issued_at: "2026-10-06T11:55:00Z".into(),
        expires_at: "2026-10-06T12:10:00Z".into(),
    };
    assert!(matches!(
        sign_scope_set(&set, "d-inst", &[app_signer(&w.d_key)]),
        Err(ActAsError::BadScopeSet(_))
    ));
}

#[test]
fn expired_scope_set_fails_at_approval_but_not_at_the_audience() {
    let w = World::new();
    let signed = w.scope_set(grantee_c(), &["read"]);
    let set = verify_scope_set(
        &signed,
        &audience_d(),
        &[app_key_ref(&w.d_key)],
        RevokedKeyPolicy::default(),
    )
    .unwrap();
    assert_eq!(
        check_scope_set_current(&set, now() + Duration::hours(2), SKEW),
        Err(ActAsError::ScopeSetExpired)
    );
    // The grant was made while the set was current; it still verifies at
    // the audience after the set expires, within the grant's own life.
    let grant = w.grant(&["read"], 7200, 0);
    let credential = present(
        &grant,
        &audience_d(),
        b"digest",
        now() + Duration::minutes(90),
        b"n",
        &w.c_signer(),
    )
    .unwrap();
    let d_keys = [app_key_ref(&w.d_key)];
    let home_keys = [domain_public(&w.home_key)];
    let c_keys = [app_key_ref(&w.c_key)];
    let mut ctx = w.ctx(&d_keys, &home_keys, &c_keys, b"digest", &[]);
    ctx.now = now() + Duration::minutes(90);
    assert!(verify_credential(&credential, &ctx).is_ok());
}

#[test]
fn approved_scope_must_be_a_non_empty_subset_without_repeats() {
    let w = World::new();
    let signed = w.scope_set(grantee_c(), &["read", "write"]);
    let set = verify_scope_set(
        &signed,
        &audience_d(),
        &[app_key_ref(&w.d_key)],
        RevokedKeyPolicy::default(),
    )
    .unwrap();
    assert!(check_approved_scope(&set, &["read".into()]).is_ok());
    assert!(check_approved_scope(&set, &["read".into(), "write".into()]).is_ok());
    assert!(matches!(
        check_approved_scope(&set, &[]),
        Err(ActAsError::BadApprovedScope(_))
    ));
    assert!(matches!(
        check_approved_scope(&set, &["admin".into()]),
        Err(ActAsError::BadApprovedScope(_))
    ));
    assert!(matches!(
        check_approved_scope(&set, &["read".into(), "read".into()]),
        Err(ActAsError::BadApprovedScope(_))
    ));
}

#[test]
fn a_grant_whose_approved_scope_leaves_the_scope_set_fails_at_the_audience() {
    let w = World::new();
    let scope_set = w.scope_set(grantee_c(), &["read"]);
    let grant = ActAsGrant {
        grant_id: "g".into(),
        user_id: "u".into(),
        subject_domain: HOME.into(),
        grantee: grantee_c(),
        audience: audience_d(),
        scope_set,
        approved_scope: vec!["read".into(), "admin".into()],
        issued_at: "2026-10-06T12:00:00Z".into(),
        expires_at: "2026-10-06T13:00:00Z".into(),
        series_issued_at: "2026-10-06T12:00:00Z".into(),
        renewable_until: "2026-10-06T13:00:00Z".into(),
        device_fingerprint: None,
    };
    let signed = sign_grant(&grant, &[domain_signer(&w.home_key, HOME)]).unwrap();
    assert!(matches!(
        verify_default(&w, &presented(&w, &signed)),
        Err(ActAsError::BadApprovedScope(_))
    ));
}

#[test]
fn a_scope_set_issued_to_another_grantee_fails_at_the_audience() {
    let w = World::new();
    let other_grantee = GranteeRef {
        application: Some(app_ref("e-owner", "e.example", "app-e")),
        local_rp_descriptor_fingerprint: None,
    };
    let scope_set = w.scope_set(other_grantee, &["read"]);
    let grant = build_grant(&NewGrant {
        grant_id: "g",
        user_id: "u",
        subject_domain: HOME,
        grantee: &grantee_c(),
        audience: &audience_d(),
        scope_set: &scope_set,
        approved_scope: &["read".to_string()],
        lifetime_seconds: 3600,
        renewal_window_seconds: 0,
        now: now(),
    })
    .unwrap();
    let signed = sign_grant(&grant, &[domain_signer(&w.home_key, HOME)]).unwrap();
    assert_eq!(
        verify_default(&w, &presented(&w, &signed)),
        Err(ActAsError::Mismatch("scope_set.grantee"))
    );
}

// ---------------------------------------------------------------------------
// Grant and presentation binding
// ---------------------------------------------------------------------------

#[test]
fn a_grant_for_another_audience_is_refused() {
    let w = World::new();
    let grant = w.grant(&["read"], 3600, 0);
    let d_keys = [app_key_ref(&w.d_key)];
    let home_keys = [domain_public(&w.home_key)];
    let c_keys = [app_key_ref(&w.c_key)];
    let mut ctx = w.ctx(&d_keys, &home_keys, &c_keys, b"digest", &[]);
    let other = app_ref("x", "x.example", "app-x");
    ctx.own_application = &other;
    assert_eq!(
        verify_credential(&presented(&w, &grant), &ctx),
        Err(ActAsError::Mismatch("audience"))
    );
}

#[test]
fn a_grant_signed_by_another_domain_is_refused() {
    let w = World::new();
    let grant = w.grant(&["read"], 3600, 0);
    let d_keys = [app_key_ref(&w.d_key)];
    let stranger = [domain_public(&key("home-1"))];
    let c_keys = [app_key_ref(&w.c_key)];
    let ctx = w.ctx(&d_keys, &stranger, &c_keys, b"digest", &[]);
    assert_eq!(
        verify_credential(&presented(&w, &grant), &ctx),
        Err(ActAsError::UntrustedSigner)
    );
}

#[test]
fn a_tampered_grant_is_refused() {
    let w = World::new();
    let mut grant = w.grant(&["read"], 3600, 0);
    let mut decoded = decode_grant(&grant).unwrap();
    decoded.approved_scope = vec!["read".into(), "write".into()];
    grant.grant = crate::generated::encode_act_as_grant(&decoded);
    assert_eq!(
        verify_default(&w, &presented(&w, &grant)),
        Err(ActAsError::UntrustedSigner)
    );
}

#[test]
fn a_stolen_grant_is_useless_without_a_grantee_key() {
    let w = World::new();
    let grant = w.grant(&["read"], 3600, 0);
    let thief = key("c-1");
    let credential = present(
        &grant,
        &audience_d(),
        b"digest",
        now() + Duration::minutes(5),
        b"n",
        &GranteeSigner::Application {
            instance_id: "c-inst",
            signer: app_signer(&thief),
        },
    )
    .unwrap();
    assert_eq!(
        verify_default(&w, &credential),
        Err(ActAsError::BadSignature)
    );
}

#[test]
fn a_presentation_for_another_request_is_refused() {
    let w = World::new();
    let grant = w.grant(&["read"], 3600, 0);
    let d_keys = [app_key_ref(&w.d_key)];
    let home_keys = [domain_public(&w.home_key)];
    let c_keys = [app_key_ref(&w.c_key)];
    let ctx = w.ctx(&d_keys, &home_keys, &c_keys, b"other-digest", &[]);
    assert_eq!(
        verify_credential(&presented(&w, &grant), &ctx),
        Err(ActAsError::Mismatch("request_digest"))
    );
}

#[test]
fn a_presentation_for_another_grant_is_refused() {
    let w = World::new();
    let grant = w.grant(&["read"], 3600, 0);
    let other = w.grant(&["write"], 3600, 0);
    let mut credential = presented(&w, &grant);
    credential.grant = other;
    assert_eq!(
        verify_default(&w, &credential),
        Err(ActAsError::Mismatch("grant_hash"))
    );
}

#[test]
fn a_stale_presentation_is_refused() {
    let w = World::new();
    let grant = w.grant(&["read"], 3600, 0);
    let credential = present(
        &grant,
        &audience_d(),
        b"digest",
        now() - Duration::minutes(30),
        b"n",
        &w.c_signer(),
    )
    .unwrap();
    assert_eq!(
        verify_default(&w, &credential),
        Err(ActAsError::RequestExpired)
    );
}

#[test]
fn an_expired_grant_is_refused() {
    let w = World::new();
    let grant = w.grant(&["read"], 60, 0);
    assert_eq!(
        verify_default(&w, &presented(&w, &grant)),
        Err(ActAsError::GrantExpired)
    );
}

#[test]
fn a_revoked_grant_is_refused() {
    let w = World::new();
    let grant = w.grant(&["read"], 3600, 0);
    let revocation = sign_grant_revocation(
        &ActAsGrantRevocation {
            grant_id: "grant-1".into(),
            user_id: "user-1".into(),
            subject_domain: HOME.into(),
            revoked_at: "2026-10-06T12:01:00Z".into(),
        },
        &[domain_signer(&w.home_key, HOME)],
    )
    .unwrap();
    let home_keys = [domain_public(&w.home_key)];
    let revoked = revoked_grant_ids(&[revocation], &home_keys, HOME);
    assert_eq!(revoked, vec!["grant-1".to_string()]);
    let d_keys = [app_key_ref(&w.d_key)];
    let c_keys = [app_key_ref(&w.c_key)];
    let ctx = w.ctx(&d_keys, &home_keys, &c_keys, b"digest", &revoked);
    assert_eq!(
        verify_credential(&presented(&w, &grant), &ctx),
        Err(ActAsError::GrantRevoked)
    );
}

#[test]
fn a_revocation_from_another_domain_is_ignored() {
    let w = World::new();
    let stranger = key("home-1");
    let revocation = sign_grant_revocation(
        &ActAsGrantRevocation {
            grant_id: "grant-1".into(),
            user_id: "user-1".into(),
            subject_domain: HOME.into(),
            revoked_at: "2026-10-06T12:01:00Z".into(),
        },
        &[domain_signer(&stranger, HOME)],
    )
    .unwrap();
    assert!(revoked_grant_ids(&[revocation], &[domain_public(&w.home_key)], HOME).is_empty());
}

#[test]
fn a_device_bound_grant_is_refused_until_device_keys_exist() {
    let w = World::new();
    let mut decoded = decode_grant(&w.grant(&["read"], 3600, 0)).unwrap();
    decoded.device_fingerprint = Some("abc".into());
    let signed = sign_grant(&decoded, &[domain_signer(&w.home_key, HOME)]).unwrap();
    assert_eq!(
        verify_default(&w, &presented(&w, &signed)),
        Err(ActAsError::DeviceBindingUnsupported)
    );
}

// ---------------------------------------------------------------------------
// Tag separation
// ---------------------------------------------------------------------------

#[test]
fn a_grant_request_signature_does_not_verify_as_a_refresh_or_presentation() {
    let w = World::new();
    let message = b"same bytes";
    let proof = w
        .c_signer()
        .prove(&envelope_signature_input(GRANT_REQUEST_TAG, message))
        .unwrap();
    let c_keys = [app_key_ref(&w.c_key)];
    for tag in [REFRESH_REQUEST_TAG, PRESENTATION_TAG, SCOPE_SET_TAG] {
        assert_eq!(
            verify_grantee_proof(
                &proof,
                &envelope_signature_input(tag, message),
                &grantee_c(),
                &c_keys,
                now(),
                SKEW
            ),
            Err(ActAsError::BadSignature)
        );
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

fn grant_request(w: &World) -> ActAsGrantRequest {
    ActAsGrantRequest {
        grantee: grantee_c(),
        scope_set: w.scope_set(grantee_c(), &["read"]),
        requested_lifetime_seconds: None,
        requested_renewal_window_seconds: None,
        grantee_handle_claim: None,
        callback_url: "https://c.example/cb".into(),
        nonce: "n".into(),
        requested_at: "2026-10-06T11:59:00Z".into(),
        expires_at: "2026-10-06T12:09:00Z".into(),
    }
}

#[test]
fn a_grant_request_signed_by_another_application_is_refused() {
    let w = World::new();
    let signed = sign_grant_request(&grant_request(&w), &w.c_signer()).unwrap();
    // The caller resolved the instance's attested keys; the signer is absent.
    assert_eq!(
        verify_grant_request(&signed, &[app_key_ref(&key("other"))], now(), SKEW),
        Err(ActAsError::UntrustedSigner)
    );
}

#[test]
fn an_expired_grant_request_is_refused() {
    let w = World::new();
    let signed = sign_grant_request(&grant_request(&w), &w.c_signer()).unwrap();
    assert_eq!(
        verify_grant_request(
            &signed,
            &[app_key_ref(&w.c_key)],
            now() + Duration::hours(1),
            SKEW
        ),
        Err(ActAsError::RequestExpired)
    );
}

#[test]
fn a_proof_whose_form_does_not_match_the_grantee_is_refused() {
    let w = World::new();
    let mut request = grant_request(&w);
    request.grantee = GranteeRef {
        application: None,
        local_rp_descriptor_fingerprint: Some("fp".into()),
    };
    let signed = sign_grant_request(&request, &w.c_signer()).unwrap();
    assert_eq!(
        verify_grant_request(&signed, &[app_key_ref(&w.c_key)], now(), SKEW),
        Err(ActAsError::ProofDoesNotMatchGrantee)
    );
}

#[test]
fn a_grantee_with_both_forms_is_malformed() {
    let both = GranteeRef {
        application: Some(app_ref("a", "b", "c")),
        local_rp_descriptor_fingerprint: Some("fp".into()),
    };
    assert_eq!(check_grantee(&both), Err(ActAsError::MalformedGrantee));
    let neither = GranteeRef {
        application: None,
        local_rp_descriptor_fingerprint: None,
    };
    assert_eq!(check_grantee(&neither), Err(ActAsError::MalformedGrantee));
}

// ---------------------------------------------------------------------------
// Local-RP grantee
// ---------------------------------------------------------------------------

fn local_rp() -> (SignedLocalRpDescriptor, String, Vec<u8>) {
    let (public, private) = generate_keypair(SigningAlgorithm::Ed25519);
    let fp = fingerprint(&public);
    let descriptor = LocalRpDescriptor {
        app_name: "desk-app".into(),
        local_domain_hint: None,
        signing_public_key: public,
        encryption_public_key: vec![7u8; 32],
        fingerprint: fp.clone(),
        supported_suites: vec!["chacha20-poly1305".into()],
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
    };
    let signed = crate::local_rp::sign_local_rp_descriptor(&descriptor, &private).unwrap();
    (signed, fp, private)
}

#[test]
fn a_local_rp_grantee_presents_with_its_descriptor_key() {
    let w = World::new();
    let (descriptor, fp, private) = local_rp();
    let grantee = GranteeRef {
        application: None,
        local_rp_descriptor_fingerprint: Some(fp.clone()),
    };
    let scope_set = w.scope_set(grantee.clone(), &["read"]);
    let grant = build_grant(&NewGrant {
        grant_id: "g",
        user_id: "u",
        subject_domain: HOME,
        grantee: &grantee,
        audience: &audience_d(),
        scope_set: &scope_set,
        approved_scope: &["read".to_string()],
        lifetime_seconds: 3600,
        renewal_window_seconds: 0,
        now: now(),
    })
    .unwrap();
    let signed = sign_grant(&grant, &[domain_signer(&w.home_key, HOME)]).unwrap();
    let signer = GranteeSigner::LocalRp {
        descriptor: &descriptor,
        fingerprint: &fp,
        signing_private_key: &private,
    };
    let credential = present(
        &signed,
        &audience_d(),
        b"digest",
        now() + Duration::minutes(5),
        b"n",
        &signer,
    )
    .unwrap();
    assert_eq!(credential_signer_instance(&credential), None);
    let verified = verify_default(&w, &credential).unwrap();
    assert_eq!(verified.signer.key_id, fp);

    // Another local RP's descriptor key cannot present this grant.
    let (other_descriptor, other_fp, other_private) = local_rp();
    let impostor = GranteeSigner::LocalRp {
        descriptor: &other_descriptor,
        fingerprint: &other_fp,
        signing_private_key: &other_private,
    };
    let credential = present(
        &signed,
        &audience_d(),
        b"digest",
        now() + Duration::minutes(5),
        b"n",
        &impostor,
    )
    .unwrap();
    assert_eq!(
        verify_default(&w, &credential),
        Err(ActAsError::Mismatch("local_rp_descriptor_fingerprint"))
    );
}

// ---------------------------------------------------------------------------
// Terms
// ---------------------------------------------------------------------------

#[test]
fn defaults_are_one_hour_and_no_renewal() {
    let offered = offered_terms(None, None, &DomainTermBounds::default());
    assert_eq!(offered.default_lifetime_seconds, 3600);
    assert_eq!(offered.max_lifetime_seconds, 86_400);
    assert_eq!(offered.default_renewal_window_seconds, 0);
    assert_eq!(offered.max_renewal_window_seconds, 0);
}

#[test]
fn the_grantee_request_is_a_ceiling_and_the_domain_maximum_bounds_it() {
    let bounds = DomainTermBounds::default();
    let offered = offered_terms(Some(600), Some(10_000_000), &bounds);
    assert_eq!(offered.max_lifetime_seconds, 600);
    assert_eq!(offered.default_lifetime_seconds, 600);
    assert_eq!(
        offered.max_renewal_window_seconds,
        DEFAULT_MAX_RENEWAL_WINDOW_SECONDS
    );
    let huge = offered_terms(Some(10_000_000), None, &bounds);
    assert_eq!(huge.max_lifetime_seconds, 86_400);
    assert_eq!(huge.default_lifetime_seconds, 86_400);
}

#[test]
fn the_user_can_lower_terms_but_not_exceed_the_offer() {
    let offered = offered_terms(Some(3600), Some(7200), &DomainTermBounds::default());
    assert_eq!(issued_terms(&offered, 600, 0), Ok((600, 0)));
    assert!(issued_terms(&offered, 3601, 0).is_err());
    assert!(issued_terms(&offered, 3600, 7201).is_err());
    assert!(issued_terms(&offered, 0, 0).is_err());
    assert!(issued_terms(&offered, 60, -1).is_err());
}

#[test]
fn domain_bounds_validate() {
    assert!(DomainTermBounds::default().validate().is_ok());
    let bad = DomainTermBounds {
        default_lifetime_seconds: 10,
        max_lifetime_seconds: 5,
        max_renewal_window_seconds: 0,
    };
    assert!(bad.validate().is_err());
}

#[test]
fn build_grant_sets_the_series_end() {
    let w = World::new();
    let grant = decode_grant(&w.grant(&["read"], 3600, 7200)).unwrap();
    assert_eq!(grant.issued_at, "2026-10-06T12:00:00Z");
    assert_eq!(grant.expires_at, "2026-10-06T13:00:00Z");
    assert_eq!(grant.series_issued_at, "2026-10-06T12:00:00Z");
    assert_eq!(grant.renewable_until, "2026-10-06T15:00:00Z");
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

#[test]
fn refresh_with_no_renewal_window_never_renews() {
    let w = World::new();
    let grant = decode_grant(&w.grant(&["read"], 3600, 0)).unwrap();
    for minutes in [1, 31, 59] {
        assert_eq!(
            refresh_decision(&grant, 3600, now() + Duration::minutes(minutes)),
            Ok(RefreshDecision::Stored)
        );
    }
    assert_eq!(
        refresh_decision(&grant, 3600, now() + Duration::minutes(60)),
        Err(ActAsError::GrantExpired)
    );
}

#[test]
fn refresh_returns_stored_bytes_while_more_than_half_the_life_remains() {
    let w = World::new();
    let grant = decode_grant(&w.grant(&["read"], 3600, 7200)).unwrap();
    assert_eq!(
        refresh_decision(&grant, 3600, now() + Duration::minutes(29)),
        Ok(RefreshDecision::Stored)
    );
}

#[test]
fn refresh_renews_after_half_life_and_caps_at_the_series_end() {
    let w = World::new();
    let grant = decode_grant(&w.grant(&["read"], 3600, 1800)).unwrap();
    // renewable_until = 13:30. At 12:40, now + lifetime = 13:40 -> capped.
    let decision = refresh_decision(&grant, 3600, now() + Duration::minutes(40)).unwrap();
    assert_eq!(
        decision,
        RefreshDecision::Renew {
            issued_at: "2026-10-06T12:40:00Z".into(),
            expires_at: "2026-10-06T13:30:00Z".into(),
        }
    );
    let RefreshDecision::Renew {
        issued_at,
        expires_at,
    } = decision
    else {
        unreachable!()
    };
    let renewed = renewed_grant(&grant, issued_at, expires_at);
    assert_eq!(renewed.grant_id, grant.grant_id);
    assert_eq!(renewed.approved_scope, grant.approved_scope);
    assert_eq!(renewed.renewable_until, grant.renewable_until);
    assert_eq!(renewed.series_issued_at, grant.series_issued_at);
    assert_eq!(renewed.scope_set, grant.scope_set);
    // At the series end, no further renewal extends anything.
    assert_eq!(
        refresh_decision(&renewed, 3600, now() + Duration::minutes(80)),
        Ok(RefreshDecision::Stored)
    );
}

#[test]
fn a_refresh_request_from_another_grantee_is_refused() {
    let w = World::new();
    let request = ActAsRefreshRequest {
        grant_id: "grant-1".into(),
        grantee: GranteeRef {
            application: Some(app_ref("e", "e.example", "app-e")),
            local_rp_descriptor_fingerprint: None,
        },
        requested_at: "2026-10-06T11:59:00Z".into(),
        expires_at: "2026-10-06T12:09:00Z".into(),
        nonce: "n".into(),
    };
    let signed = sign_refresh_request(&request, &w.c_signer()).unwrap();
    assert_eq!(
        verify_refresh_request(&signed, &grantee_c(), &[app_key_ref(&w.c_key)], now(), SKEW),
        Err(ActAsError::Mismatch("grantee"))
    );
    let request = ActAsRefreshRequest {
        grantee: grantee_c(),
        ..request
    };
    let signed = sign_refresh_request(&request, &w.c_signer()).unwrap();
    assert!(
        verify_refresh_request(&signed, &grantee_c(), &[app_key_ref(&w.c_key)], now(), SKEW)
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// Multi-key scope sets and the revoked-key policy
// ---------------------------------------------------------------------------

fn multi_signed(w: &World, second: &Key) -> SignedActAsScopeSet {
    let set = ActAsScopeSet {
        audience: audience_d(),
        grantee: grantee_c(),
        entries: vec![ActAsScopeEntry {
            scope: "read".into(),
            description: None,
        }],
        language: None,
        audience_handle_claim: None,
        issued_at: "2026-10-06T11:55:00Z".into(),
        expires_at: "2026-10-06T12:10:00Z".into(),
    };
    sign_scope_set(&set, "d-inst", &[app_signer(&w.d_key), app_signer(second)]).unwrap()
}

#[test]
fn one_valid_signature_is_enough_when_another_key_expired() {
    let w = World::new();
    let second = key("d-2");
    let signed = multi_signed(&w, &second);
    assert_eq!(signed.signatures.len(), 2);
    let mut expired = app_key_ref(&w.d_key);
    expired.expires_at = "2026-01-02T00:00:00Z".into();
    let keys = [expired, app_key_ref(&second)];
    assert!(verify_scope_set(&signed, &audience_d(), &keys, RevokedKeyPolicy::default()).is_ok());
}

#[test]
fn a_key_revoked_after_signing_is_accepted_by_default_and_refused_on_request() {
    let w = World::new();
    let set = ActAsScopeSet {
        audience: audience_d(),
        grantee: grantee_c(),
        entries: vec![ActAsScopeEntry {
            scope: "read".into(),
            description: None,
        }],
        language: None,
        audience_handle_claim: None,
        issued_at: "2026-10-06T11:55:00Z".into(),
        expires_at: "2026-10-06T12:10:00Z".into(),
    };
    let signed = sign_scope_set(&set, "d-inst", &[app_signer(&w.d_key)]).unwrap();
    let mut revoked = app_key_ref(&w.d_key);
    revoked.revoked_at = Some("2026-10-06T12:30:00Z".into());
    let keys = [revoked.clone()];
    assert!(verify_scope_set(
        &signed,
        &audience_d(),
        &keys,
        RevokedKeyPolicy::AcceptBeforeRevocation
    )
    .is_ok());
    let err = verify_scope_set(
        &signed,
        &audience_d(),
        &keys,
        RevokedKeyPolicy::RefuseRevoked,
    )
    .unwrap_err();
    assert!(
        matches!(&err, ActAsError::NoValidSignature(m) if m.contains("refuses revoked keys")),
        "{err:?}"
    );
    // Revoked before it signed: refused under either policy, with the reason.
    revoked.revoked_at = Some("2026-10-06T11:00:00Z".into());
    let err = verify_scope_set(
        &signed,
        &audience_d(),
        &[revoked],
        RevokedKeyPolicy::default(),
    )
    .unwrap_err();
    assert!(
        matches!(&err, ActAsError::NoValidSignature(m) if m.contains("before it signed")),
        "{err:?}"
    );
}

#[test]
fn signing_needs_distinct_keys() {
    let w = World::new();
    let set = ActAsScopeSet {
        audience: audience_d(),
        grantee: grantee_c(),
        entries: vec![ActAsScopeEntry {
            scope: "read".into(),
            description: None,
        }],
        language: None,
        audience_handle_claim: None,
        issued_at: "2026-10-06T11:55:00Z".into(),
        expires_at: "2026-10-06T12:10:00Z".into(),
    };
    assert!(sign_scope_set(&set, "d-inst", &[]).is_err());
    assert!(sign_scope_set(
        &set,
        "d-inst",
        &[app_signer(&w.d_key), app_signer(&w.d_key)]
    )
    .is_err());
}

// ---------------------------------------------------------------------------
// Handle claims
// ---------------------------------------------------------------------------

fn handle_claim(
    user_id: &str,
    claim_type: &str,
    value: &str,
    signer: &Key,
    domain: &str,
) -> crate::generated::types::Claim {
    crate::claims::sign_claim(
        &crate::claims::ClaimSpec {
            claim_id: "claim-1",
            claim_type,
            claim_value: value.as_bytes(),
            user_id,
            subject_domain: domain,
            expires_at: None,
            attested_at: "2026-10-06T10:00:00Z",
        },
        &[domain_signer(signer, domain)],
    )
    .unwrap()
}

#[test]
fn a_handle_claim_signed_by_the_party_domain_yields_the_handle() {
    let domain_key = key("dk-1");
    let party = audience_d();
    let claim = handle_claim(
        &party.subject_user_id,
        "handle",
        "drive-team",
        &domain_key,
        &party.subject_domain,
    );
    assert_eq!(
        verify_handle_claim(&claim, &party, &[domain_public(&domain_key)]),
        Ok("drive-team".to_string())
    );
}

#[test]
fn a_handle_claim_about_another_account_or_type_or_domain_is_refused() {
    let domain_key = key("dk-1");
    let party = audience_d();
    let keys = [domain_public(&domain_key)];
    let other_user = handle_claim(
        "someone-else",
        "handle",
        "x",
        &domain_key,
        &party.subject_domain,
    );
    assert!(matches!(
        verify_handle_claim(&other_user, &party, &keys),
        Err(ActAsError::BadHandleClaim(_))
    ));
    let other_type = handle_claim(
        &party.subject_user_id,
        "email",
        "x",
        &domain_key,
        &party.subject_domain,
    );
    assert!(matches!(
        verify_handle_claim(&other_type, &party, &keys),
        Err(ActAsError::BadHandleClaim(_))
    ));
    // Signed only by a third domain: the party's own domain never vouched.
    let third = handle_claim(
        &party.subject_user_id,
        "handle",
        "x",
        &domain_key,
        "third.example",
    );
    assert!(matches!(
        verify_handle_claim(&third, &party, &keys),
        Err(ActAsError::BadHandleClaim(_))
    ));
    // Signed by a key that is not the domain's.
    let forged = handle_claim(
        &party.subject_user_id,
        "handle",
        "x",
        &key("dk-1"),
        &party.subject_domain,
    );
    assert!(matches!(
        verify_handle_claim(&forged, &party, &keys),
        Err(ActAsError::BadHandleClaim(_))
    ));
}

#[test]
fn a_key_created_within_the_clock_skew_after_issued_at_counts() {
    let w = World::new();
    let signed = multi_signed(&w, &key("d-2"));
    // The set is issued at 11:55. The home domain recorded the key as created
    // later: inside the skew it counts, beyond the skew it does not.
    let mut inside = app_key_ref(&w.d_key);
    inside.created_at = "2026-10-06T11:59:00Z".into();
    assert!(verify_scope_set(
        &signed,
        &audience_d(),
        &[inside],
        RevokedKeyPolicy::default()
    )
    .is_ok());
    let mut beyond = app_key_ref(&w.d_key);
    beyond.created_at = "2026-10-06T12:00:01Z".into();
    let err = verify_scope_set(
        &signed,
        &audience_d(),
        &[beyond],
        RevokedKeyPolicy::default(),
    )
    .unwrap_err();
    assert!(
        matches!(&err, ActAsError::NoValidSignature(m) if m.contains("validity window")),
        "{err:?}"
    );
}
