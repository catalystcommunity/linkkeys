//! Consumer zero for the act-as vectors in `sdks/regular-rp/conformance/`.
//! Reads the checked-in JSON and verifies every positive AND negative case
//! against the real `liblinkkeys::act_as` implementation, building every input
//! from the JSON alone, the way another language's SDK must.
//!
//! Regenerate the vectors with
//! `cargo run -p liblinkkeys --example generate_act_as_vectors`.

use chrono::{DateTime, Utc};
use liblinkkeys::act_as::{
    self, AudienceContext, DomainTermBounds, RefreshDecision, RevokedKeyPolicy,
};
use liblinkkeys::application_keys::ApplicationKeyRef;
use liblinkkeys::generated::{
    self,
    types::{ApplicationRef, DomainPublicKey, GranteeRef},
};
use serde_json::Value;
use std::path::PathBuf;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdks/regular-rp/conformance")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e} (run the generator?)", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}

fn time(v: &Value) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(v.as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc)
}

fn app_ref(v: &Value) -> ApplicationRef {
    ApplicationRef {
        subject_user_id: s(&v["subject_user_id"]),
        subject_domain: s(&v["subject_domain"]),
        application_id: s(&v["application_id"]),
    }
}

fn grantee(v: &Value) -> GranteeRef {
    GranteeRef {
        application: v["application"]
            .as_object()
            .map(|_| app_ref(&v["application"])),
        local_rp_descriptor_fingerprint: v["local_rp_descriptor_fingerprint"]
            .as_str()
            .map(String::from),
    }
}

fn key_refs(v: &Value) -> Vec<ApplicationKeyRef> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|k| ApplicationKeyRef {
            key_id: s(&k["key_id"]),
            key_usage: s(&k["key_usage"]),
            algorithm: s(&k["algorithm"]),
            public_key: unhex(k["public_key_hex"].as_str().unwrap()),
            fingerprint: s(&k["fingerprint"]),
            created_at: s(&k["created_at"]),
            expires_at: s(&k["expires_at"]),
            revoked_at: k["revoked_at"].as_str().map(String::from),
        })
        .collect()
}

fn domain_keys(v: &Value) -> Vec<DomainPublicKey> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|k| DomainPublicKey {
            key_id: s(&k["key_id"]),
            public_key: unhex(k["public_key_hex"].as_str().unwrap()),
            fingerprint: s(&k["fingerprint"]),
            algorithm: s(&k["algorithm"]),
            key_usage: s(&k["key_usage"]),
            created_at: s(&k["created_at"]),
            expires_at: s(&k["expires_at"]),
            revoked_at: None,
            signed_by_key_id: None,
            key_signature: None,
        })
        .collect()
}

fn policy(v: &Value) -> RevokedKeyPolicy {
    match v.as_str() {
        None | Some("accept_before_revocation") => RevokedKeyPolicy::AcceptBeforeRevocation,
        Some("refuse_revoked") => RevokedKeyPolicy::RefuseRevoked,
        Some(other) => panic!("unknown revoked_key_policy {other}"),
    }
}

fn cases(section: &Value) -> Vec<&Value> {
    let mut out: Vec<&Value> = section["cases"].as_array().unwrap().iter().collect();
    out.extend(section["negative_cases"].as_array().unwrap().iter());
    out
}

fn expect(name: &str, expected_valid: bool, ok: bool) {
    assert_eq!(
        ok, expected_valid,
        "case {name}: expected_valid = {expected_valid}, got valid = {ok}"
    );
}

#[test]
fn signature_vectors() {
    let v = load("act_as_signatures.json");
    let now = time(&v["now"]);
    let skew = v["skew_seconds"].as_i64().unwrap();
    let audience_keys = key_refs(&v["audience_keys"]);
    let grantee_keys = key_refs(&v["grantee_instance_keys"]);
    let home_keys = domain_keys(&v["home_domain_keys"]);
    let home = s(&v["home_domain"]);

    let mut scope_cases = cases(&v["scope_set"]);
    scope_cases.extend(v["scope_set"]["policy_cases"].as_array().unwrap().iter());
    for case in scope_cases {
        let signed = generated::decode_signed_act_as_scope_set(&unhex(
            case["signed_cbor_hex"].as_str().unwrap(),
        ))
        .unwrap();
        let expected_audience = if case["expected_audience"].is_object() {
            app_ref(&case["expected_audience"])
        } else {
            app_ref(&v["audience"])
        };
        let keys = if case["audience_keys"].is_array() {
            key_refs(&case["audience_keys"])
        } else {
            audience_keys.clone()
        };
        let ok = act_as::verify_scope_set(
            &signed,
            &expected_audience,
            &keys,
            policy(&case["revoked_key_policy"]),
        )
        .is_ok();
        expect(
            case["name"].as_str().unwrap(),
            case["expected_valid"].as_bool().unwrap(),
            ok,
        );
    }

    let hc = &v["handle_claims"];
    let party = app_ref(&hc["party"]);
    let party_keys = domain_keys(&hc["party_domain_keys"]);
    for case in cases(hc) {
        let claim =
            generated::decode_claim(&unhex(case["claim_cbor_hex"].as_str().unwrap())).unwrap();
        let result = act_as::verify_handle_claim(&claim, &party, &party_keys);
        if let (Ok(handle), Some(expected)) = (&result, case["expected_handle"].as_str()) {
            assert_eq!(handle, expected);
        }
        expect(
            case["name"].as_str().unwrap(),
            case["expected_valid"].as_bool().unwrap(),
            result.is_ok(),
        );
    }

    for case in cases(&v["grant_request"]) {
        let signed = generated::decode_signed_act_as_grant_request(&unhex(
            case["signed_cbor_hex"].as_str().unwrap(),
        ))
        .unwrap();
        let at = case.get("now").map(time).unwrap_or(now);
        let ok = act_as::verify_grant_request(&signed, &grantee_keys, at, skew).is_ok();
        expect(
            case["name"].as_str().unwrap(),
            case["expected_valid"].as_bool().unwrap(),
            ok,
        );
    }

    let refresh_now = time(&v["refresh_request"]["now"]);
    let grant_grantee = grantee(&v["refresh_request"]["grant_grantee"]);
    for case in cases(&v["refresh_request"]) {
        let signed = generated::decode_signed_act_as_refresh_request(&unhex(
            case["signed_cbor_hex"].as_str().unwrap(),
        ))
        .unwrap();
        let ok = act_as::verify_refresh_request(
            &signed,
            &grant_grantee,
            &grantee_keys,
            refresh_now,
            skew,
        )
        .is_ok();
        expect(
            case["name"].as_str().unwrap(),
            case["expected_valid"].as_bool().unwrap(),
            ok,
        );
    }

    // The grant's signature input and hash match a recomputation.
    let grant = generated::decode_signed_act_as_grant(&unhex(
        v["grant"]["signed_cbor_hex"].as_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(
        grant.grant,
        unhex(v["grant"]["grant_cbor_hex"].as_str().unwrap())
    );
    assert_eq!(
        act_as::grant_hash(&grant.grant),
        unhex(v["grant"]["grant_hash_hex"].as_str().unwrap())
    );
    assert!(act_as::verify_grant_signature(&grant, &home_keys).is_ok());

    for case in cases(&v["revocation"]) {
        let signed = generated::decode_signed_act_as_grant_revocation(&unhex(
            case["signed_cbor_hex"].as_str().unwrap(),
        ))
        .unwrap();
        let result = act_as::verify_grant_revocation(&signed, &home_keys, &home);
        if let (Ok(r), Some(id)) = (&result, case["expected_grant_id"].as_str()) {
            assert_eq!(r.grant_id, id);
        }
        expect(
            case["name"].as_str().unwrap(),
            case["expected_valid"].as_bool().unwrap(),
            result.is_ok(),
        );
    }
}

#[test]
fn credential_vectors() {
    let v = load("act_as_credential.json");
    let base = &v["context"];
    for case in cases(&v) {
        let field = |name: &str| -> Value {
            case.get(name)
                .cloned()
                .unwrap_or_else(|| base[name].clone())
        };
        let credential = generated::decode_act_as_credential(&unhex(
            case["credential_cbor_hex"].as_str().unwrap(),
        ))
        .unwrap();
        let own = app_ref(&field("own_application"));
        let own_keys = key_refs(&field("own_scope_set_keys"));
        let issuer = domain_keys(&field("issuer_domain_keys"));
        let grantee_keys = key_refs(&field("grantee_instance_keys"));
        let digest = unhex(field("expected_request_digest_hex").as_str().unwrap());
        let revoked: Vec<String> = field("revoked_grant_ids")
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect();
        let ctx = AudienceContext {
            own_application: &own,
            own_scope_set_keys: &own_keys,
            issuer_domain_keys: &issuer,
            grantee_instance_keys: &grantee_keys,
            expected_request_digest: &digest,
            revoked_grant_ids: &revoked,
            max_presentation_age_seconds: field("max_presentation_age_seconds").as_i64().unwrap(),
            now: time(&field("now")),
            skew_seconds: field("skew_seconds").as_i64().unwrap(),
            revoked_key_policy: policy(&field("revoked_key_policy")),
        };
        let result = act_as::verify_credential(&credential, &ctx);
        let name = case["name"].as_str().unwrap();
        if let (Ok(verified), Some(expected)) = (&result, case.get("expected")) {
            assert_eq!(verified.grant_id, s(&expected["grant_id"]), "{name}");
            assert_eq!(verified.user_id, s(&expected["user_id"]), "{name}");
            let scope: Vec<String> = expected["approved_scope"]
                .as_array()
                .unwrap()
                .iter()
                .map(s)
                .collect();
            assert_eq!(verified.approved_scope, scope, "{name}");
            assert_eq!(
                verified.signer.instance_id.as_deref(),
                expected["signer_instance_id"].as_str(),
                "{name}"
            );
            assert_eq!(
                verified.nonce,
                unhex(expected["nonce_hex"].as_str().unwrap()),
                "{name}"
            );
        }
        expect(
            name,
            case["expected_valid"].as_bool().unwrap(),
            result.is_ok(),
        );
    }
}

#[test]
fn terms_vectors() {
    let v = load("act_as_terms.json");
    let b = &v["domain_bounds"];
    let bounds = DomainTermBounds {
        default_lifetime_seconds: b["default_lifetime_seconds"].as_i64().unwrap(),
        max_lifetime_seconds: b["max_lifetime_seconds"].as_i64().unwrap(),
        max_renewal_window_seconds: b["max_renewal_window_seconds"].as_i64().unwrap(),
    };
    for case in v["offered_terms"].as_array().unwrap() {
        let o = act_as::offered_terms(
            case["requested_lifetime_seconds"].as_i64(),
            case["requested_renewal_window_seconds"].as_i64(),
            &bounds,
        );
        let e = &case["expected"];
        assert_eq!(
            o.default_lifetime_seconds,
            e["default_lifetime_seconds"].as_i64().unwrap()
        );
        assert_eq!(
            o.max_lifetime_seconds,
            e["max_lifetime_seconds"].as_i64().unwrap()
        );
        assert_eq!(
            o.default_renewal_window_seconds,
            e["default_renewal_window_seconds"].as_i64().unwrap()
        );
        assert_eq!(
            o.max_renewal_window_seconds,
            e["max_renewal_window_seconds"].as_i64().unwrap()
        );
    }

    let offer = &v["issued_terms"]["offer"];
    let offered = act_as::offered_terms(
        offer["requested_lifetime_seconds"].as_i64(),
        offer["requested_renewal_window_seconds"].as_i64(),
        &bounds,
    );
    for case in v["issued_terms"]["cases"].as_array().unwrap() {
        let ok = act_as::issued_terms(
            &offered,
            case["chosen_lifetime_seconds"].as_i64().unwrap(),
            case["chosen_renewal_window_seconds"].as_i64().unwrap(),
        )
        .is_ok();
        assert_eq!(ok, case["expected_valid"].as_bool().unwrap(), "{case}");
    }

    for case in v["refresh"].as_array().unwrap() {
        let g = &case["grant"];
        let grant = generated::types::ActAsGrant {
            grant_id: "g".into(),
            user_id: "u".into(),
            subject_domain: "d".into(),
            grantee: GranteeRef {
                application: None,
                local_rp_descriptor_fingerprint: Some("fp".into()),
            },
            audience: ApplicationRef {
                subject_user_id: "a".into(),
                subject_domain: "b".into(),
                application_id: "c".into(),
            },
            scope_set: generated::types::SignedActAsScopeSet {
                scope_set: vec![],
                signer_instance_id: String::new(),
                signatures: vec![],
            },
            approved_scope: vec!["read".into()],
            issued_at: s(&g["issued_at"]),
            expires_at: s(&g["expires_at"]),
            series_issued_at: s(&g["issued_at"]),
            renewable_until: s(&g["renewable_until"]),
            device_fingerprint: None,
        };
        let result = act_as::refresh_decision(
            &grant,
            case["lifetime_seconds"].as_i64().unwrap(),
            time(&case["now"]),
        );
        let e = &case["expected"];
        match (e["decision"].as_str().unwrap(), result) {
            ("stored", Ok(RefreshDecision::Stored)) => {}
            (
                "renew",
                Ok(RefreshDecision::Renew {
                    issued_at,
                    expires_at,
                }),
            ) => {
                assert_eq!(issued_at, s(&e["issued_at"]));
                assert_eq!(expires_at, s(&e["expires_at"]));
            }
            ("expired", Err(_)) => {}
            (want, got) => panic!("refresh case {}: want {want}, got {got:?}", case["name"]),
        }
    }
}

#[test]
fn grantee_signing_vectors() {
    use liblinkkeys::act_as::GranteeSigner;
    use liblinkkeys::application_keys::ApplicationSigner;
    use liblinkkeys::crypto::SigningAlgorithm;
    use liblinkkeys::generated::types::{ActAsGrantRequest, ActAsRefreshRequest};

    let v = load("act_as_grantee_signing.json");
    let app_key = &v["application_grantee"]["key"];
    let app_private = unhex(app_key["private_key_hex"].as_str().unwrap());
    let app_key_id = s(&app_key["key_id"]);
    let app_instance = s(&v["application_grantee"]["instance_id"]);
    let local = &v["local_rp_grantee"];
    let local_private = unhex(local["signing_private_key_hex"].as_str().unwrap());
    let local_fp = s(&local["fingerprint"]);
    let local_descriptor = generated::decode_signed_local_rp_descriptor(&unhex(
        local["signed_descriptor_cbor_hex"].as_str().unwrap(),
    ))
    .unwrap();

    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let grantee = grantee(&case["grantee"]);
        let signer = if grantee.application.is_some() {
            GranteeSigner::Application {
                instance_id: &app_instance,
                signer: ApplicationSigner {
                    key_id: &app_key_id,
                    algorithm: SigningAlgorithm::Ed25519,
                    private_key_bytes: &app_private,
                },
            }
        } else {
            GranteeSigner::LocalRp {
                descriptor: &local_descriptor,
                fingerprint: &local_fp,
                signing_private_key: &local_private,
            }
        };

        let g = &case["grant_request"];
        let i = &g["inputs"];
        let request = ActAsGrantRequest {
            grantee: grantee.clone(),
            scope_set: generated::decode_signed_act_as_scope_set(&unhex(
                i["scope_set_signed_cbor_hex"].as_str().unwrap(),
            ))
            .unwrap(),
            requested_lifetime_seconds: i["requested_lifetime_seconds"].as_i64(),
            requested_renewal_window_seconds: i["requested_renewal_window_seconds"].as_i64(),
            grantee_handle_claim: None,
            callback_url: s(&i["callback_url"]),
            nonce: s(&i["nonce"]),
            requested_at: s(&i["requested_at"]),
            expires_at: s(&i["expires_at"]),
        };
        let signed = act_as::sign_grant_request(&request, &signer).unwrap();
        assert_eq!(
            signed.request,
            unhex(g["request_cbor_hex"].as_str().unwrap()),
            "{name}: grant request bytes"
        );
        assert_eq!(
            generated::encode_signed_act_as_grant_request(&signed),
            unhex(g["signed_cbor_hex"].as_str().unwrap()),
            "{name}: signed grant request"
        );

        let r = &case["refresh_request"];
        let i = &r["inputs"];
        let refresh = ActAsRefreshRequest {
            grant_id: s(&i["grant_id"]),
            grantee: grantee.clone(),
            requested_at: s(&i["requested_at"]),
            expires_at: s(&i["expires_at"]),
            nonce: s(&i["nonce"]),
        };
        let signed = act_as::sign_refresh_request(&refresh, &signer).unwrap();
        assert_eq!(
            generated::encode_signed_act_as_refresh_request(&signed),
            unhex(r["signed_cbor_hex"].as_str().unwrap()),
            "{name}: signed refresh request"
        );

        let p = &case["presentation"];
        let i = &p["inputs"];
        let grant = generated::decode_signed_act_as_grant(&unhex(
            i["grant_signed_cbor_hex"].as_str().unwrap(),
        ))
        .unwrap();
        let credential = act_as::present(
            &grant,
            &app_ref(&i["audience"]),
            &unhex(i["request_digest_hex"].as_str().unwrap()),
            time(&i["presented_at"]),
            &unhex(i["nonce_hex"].as_str().unwrap()),
            &signer,
        )
        .unwrap();
        assert_eq!(
            act_as::grant_hash(&grant.grant),
            unhex(p["grant_hash_hex"].as_str().unwrap()),
            "{name}: grant hash"
        );
        assert_eq!(
            generated::encode_act_as_credential(&credential),
            unhex(p["credential_cbor_hex"].as_str().unwrap()),
            "{name}: credential"
        );
    }
}
