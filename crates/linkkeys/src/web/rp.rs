use rand::Rng;
use rocket::http::{ContentType, Status};
use rocket::State;
use serde::{Deserialize, Serialize};
use std::env;

use crate::conversions::get_domain_name;
use crate::db::DbPool;

use super::guard::AuthenticatedUser;

// -- Request/Response types for JSON API --

#[derive(Deserialize)]
pub struct SignRequestInput {
    callback_url: String,
    nonce: String,
}

#[derive(Serialize)]
pub struct SignRequestOutput {
    signed_request: String,
}

#[derive(Deserialize)]
pub struct DecryptTokenInput {
    encrypted_token: String,
}

#[derive(Serialize)]
pub struct DecryptTokenOutput {
    signed_assertion: String,
}

#[derive(Deserialize)]
pub struct VerifyAssertionInput {
    signed_assertion: String,
    expected_domain: String,
}

#[derive(Serialize)]
pub struct VerifyAssertionOutput {
    assertion: liblinkkeys::generated::types::IdentityAssertion,
    verified: bool,
}

/// Sign an auth request using this server's domain key.
/// Called by the web app when initiating a login redirect.
#[rocket::post("/v1alpha/sign-request.json", data = "<body>")]
pub fn sign_request_json(
    _user: AuthenticatedUser,
    pool: &State<DbPool>,
    rp_config: &State<crate::rp_config::RpClaimsConfig>,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    let input: SignRequestInput = serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;

    let domain_keys = pool
        .list_active_domain_keys()
        .map_err(|_| Status::InternalServerError)?;
    let dk = super::pick_active_signing_key(&domain_keys).ok_or(Status::InternalServerError)?;

    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|_| Status::InternalServerError)?;

    let algorithm = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm)
        .ok_or(Status::InternalServerError)?;

    let mut request = liblinkkeys::auth_request::build_auth_request(
        &get_domain_name(),
        &input.callback_url,
        &input.nonce,
        &dk.id,
        rp_config.to_claim_request(),
    );

    // Attach claims the RP asserts about itself: self-asserted ones signed now
    // with our domain key, plus any pre-signed third-party claims loaded from a
    // file. The whole request is signed below, so these ride inside the RP's
    // authenticated request.
    let domain = get_domain_name();
    let mut rp_claims: Vec<liblinkkeys::generated::types::DomainClaim> = rp_config
        .self_claims
        .iter()
        .map(|c| {
            liblinkkeys::domain_claims::sign_domain_claim(
                &liblinkkeys::domain_claims::DomainClaimSpec {
                    claim_type: &c.claim_type,
                    claim_value: c.value.as_bytes(),
                    subject_domain: &domain,
                    expires_at: None,
                },
                &[liblinkkeys::claims::ClaimSigner {
                    domain: &domain,
                    key_id: &dk.id,
                    algorithm,
                    private_key_bytes: &sk_bytes,
                }],
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Status::InternalServerError)?;
    rp_claims.extend(crate::rp_config::load_signed_domain_claims());
    if !rp_claims.is_empty() {
        request.relying_party_claims = Some(rp_claims);
    }

    let signed =
        liblinkkeys::auth_request::sign_auth_request(&request, &dk.id, algorithm, &sk_bytes)
            .map_err(|_| Status::InternalServerError)?;

    let encoded = liblinkkeys::encoding::signed_auth_request_to_url_param(&signed)
        .map_err(|_| Status::InternalServerError)?;

    let output = SignRequestOutput {
        signed_request: encoded,
    };
    let out = serde_json::to_vec(&output).map_err(|_| Status::InternalServerError)?;
    Ok((ContentType::JSON, out))
}

/// Decrypt an encrypted token using this server's domain key converted to X25519.
#[rocket::post("/v1alpha/decrypt-token.json", data = "<body>")]
pub fn decrypt_token_json(
    _user: AuthenticatedUser,
    pool: &State<DbPool>,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    let input: DecryptTokenInput = serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;

    let encrypted_token =
        liblinkkeys::encoding::encrypted_token_from_url_param(&input.encrypted_token)
            .map_err(|_| Status::BadRequest)?;

    let domain_keys = pool
        .list_active_domain_keys()
        .map_err(|_| Status::InternalServerError)?;

    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;

    // Try each active ENCRYPTION key (key_usage == "encrypt"); its decrypted
    // private is an X25519 secret used directly — no Ed25519→X25519 conversion.
    for dk in domain_keys.iter().filter(|k| k.key_usage == "encrypt") {
        let sk_bytes = match liblinkkeys::crypto::decrypt_private_key(
            &dk.private_key_encrypted,
            passphrase.as_bytes(),
        ) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let x25519_private: [u8; 32] = match sk_bytes.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => continue,
        };
        if let Ok(plaintext) = liblinkkeys::crypto::sealed_box_decrypt(
            &encrypted_token.ephemeral_public_key,
            &encrypted_token.nonce,
            &encrypted_token.ciphertext,
            &x25519_private,
        ) {
            // The plaintext is CBOR-encoded SignedIdentityAssertion — re-encode as base64url
            let signed_assertion = base64ct::Base64UrlUnpadded::encode_string(&plaintext);
            let output = DecryptTokenOutput { signed_assertion };
            let out = serde_json::to_vec(&output).map_err(|_| Status::InternalServerError)?;
            return Ok((ContentType::JSON, out));
        }
    }

    Err(Status::BadRequest)
}

/// Extract the bare host from an `https://` API base, dropping scheme, any
/// userinfo, port, and path. Returns `None` if there is no parseable host.
/// Used only to detect the single-instance IDP+RP self-call; hostnames are
/// compared case-insensitively by the caller.
fn api_base_host(api_base: &str) -> Option<&str> {
    let rest = api_base.strip_prefix("https://")?;
    let host_with_extras = rest.split(['/', '?', '#']).next()?;
    let after_userinfo = match host_with_extras.rsplit_once('@') {
        Some((_, host)) => host,
        None => host_with_extras,
    };
    // Strip a trailing `:port`, but only when it's all digits — this leaves
    // bracketed IPv6 hosts intact.
    let host = match after_userinfo.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => after_userinfo,
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[derive(Deserialize)]
pub struct FetchUserInfoInput {
    /// URL-param-encoded `SignedIdentityAssertion` the RP received on its
    /// callback (the same value `decrypt-token` returns).
    token: String,
    /// The identity provider's API base (`https://…`), taken from the domain's
    /// `_linkkeys` `api=` record.
    api_base: String,
}

/// Fetch a user's claims from the IDP on the relying party's behalf, proving
/// we are the assertion's audience (crypto-06).
///
/// This is the RP-side counterpart to the IDP's `/v1alpha/userinfo`: the calling
/// app (which holds no domain key) delegates here, and we sign a
/// `SignedUserInfoRequest` with our domain signing key so the IDP can bind the
/// redemption to us via proof-of-possession. Our signing keys are inlined so a
/// first-contact IDP can pin them to our DNS `fp=` without a second fetch.
#[rocket::post("/v1alpha/userinfo-fetch.json", data = "<body>")]
pub async fn fetch_userinfo_json(
    _user: AuthenticatedUser,
    pool: &State<DbPool>,
    net: &State<crate::net::Net>,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    let input: FetchUserInfoInput = serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;

    if !input.api_base.starts_with("https://") {
        return Err(Status::BadRequest);
    }

    let domain_keys = pool
        .list_active_domain_keys()
        .map_err(|_| Status::InternalServerError)?;
    let signing_keys: Vec<_> = domain_keys
        .iter()
        .filter(|k| k.key_usage == "sign")
        .collect();
    if signing_keys.is_empty() {
        return Err(Status::InternalServerError);
    }
    let dk = signing_keys[rand::thread_rng().gen_range(0..signing_keys.len())];

    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|_| Status::InternalServerError)?;
    let algorithm = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm)
        .ok_or(Status::InternalServerError)?;

    let mut nonce_bytes = [0u8; 16];
    rand::thread_rng().fill(&mut nonce_bytes[..]);
    let nonce = base64ct::Base64UrlUnpadded::encode_string(&nonce_bytes);

    let request = liblinkkeys::userinfo::build_user_info_request(
        input.token.into_bytes(),
        &get_domain_name(),
        &nonce,
    );

    let inlined: Vec<liblinkkeys::generated::types::DomainPublicKey> =
        signing_keys.iter().map(|k| (*k).into()).collect();

    let signed = liblinkkeys::userinfo::sign_user_info_request(
        &request,
        &dk.id,
        algorithm,
        &sk_bytes,
        Some(inlined),
    )
    .map_err(|_| Status::InternalServerError)?;

    // Single-instance IDP+RP: when the IDP API we'd call is our own published
    // API host, redeem locally instead of POSTing the request to ourselves over
    // https. There is exactly one IDP per domain, so the host alone identifies
    // it — port and path are irrelevant. We match against API_HOSTNAME (the host
    // we actually publish in our `_linkkeys` api= record), which need not equal
    // our domain name. The local path still runs the full PoP-verify, single-use
    // nonce burn, and claim lookup that the network round-trip would trigger.
    let our_api_host = env::var("API_HOSTNAME").unwrap_or_else(|_| get_domain_name());
    if api_base_host(&input.api_base).is_some_and(|h| h.eq_ignore_ascii_case(&our_api_host)) {
        let user_info = super::build_userinfo_signed(pool, net, &signed).await?;
        let out = serde_json::to_vec(&user_info).map_err(|_| Status::InternalServerError)?;
        return Ok((ContentType::JSON, out));
    }

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&signed, &mut cbor).map_err(|_| Status::InternalServerError)?;

    let url = format!("{}/v1alpha/userinfo", input.api_base);
    let resp = net
        .http
        .post_cbor(&url, cbor)
        .await
        .map_err(|_| Status::BadGateway)?;
    if !resp.success {
        return Err(Status::BadGateway);
    }
    let user_info: liblinkkeys::generated::types::UserInfo =
        ciborium::de::from_reader(&resp.body[..]).map_err(|_| Status::BadGateway)?;

    let out = serde_json::to_vec(&user_info).map_err(|_| Status::InternalServerError)?;
    Ok((ContentType::JSON, out))
}

/// Verify a signed assertion against a domain's published keys.
/// Performs DNS lookup and key fetch for the expected domain.
#[rocket::post("/v1alpha/verify-assertion.json", data = "<body>")]
pub async fn verify_assertion_json(
    _user: AuthenticatedUser,
    pool: &State<DbPool>,
    net: &State<crate::net::Net>,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    let input: VerifyAssertionInput =
        serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;

    // Decode the signed assertion from base64url
    let cbor_bytes = base64ct::Base64UrlUnpadded::decode_vec(&input.signed_assertion)
        .map_err(|_| Status::BadRequest)?;
    let signed: liblinkkeys::generated::types::SignedIdentityAssertion =
        ciborium::de::from_reader(cbor_bytes.as_slice()).map_err(|_| Status::BadRequest)?;

    // Fetch the domain's public keys
    let domain_keys = fetch_domain_keys(pool, net, &input.expected_domain)
        .await
        .map_err(|_| Status::BadGateway)?;

    // Verify the assertion
    let assertion = liblinkkeys::assertions::verify_assertion(&signed, &domain_keys)
        .map_err(|_| Status::Unauthorized)?;

    let output = VerifyAssertionOutput {
        assertion,
        verified: true,
    };
    let out = serde_json::to_vec(&output).map_err(|_| Status::InternalServerError)?;
    Ok((ContentType::JSON, out))
}

use base64ct::Encoding as _;

/// Fetch a relying party's active public keys, preferring the local DB
/// when this server is the relying party (single instance acts as both
/// IDP and RP). Falls back to DNS+HTTP fetch otherwise.
pub async fn fetch_rp_keys(
    pool: &DbPool,
    net: &crate::net::Net,
    rp_domain: &str,
) -> Result<Vec<liblinkkeys::generated::types::DomainPublicKey>, Box<dyn std::error::Error>> {
    if rp_domain == get_domain_name() {
        let keys = pool.list_active_domain_keys()?;
        return Ok(keys.iter().map(Into::into).collect());
    }
    fetch_domain_keys(pool, net, rp_domain).await
}

/// Resolve a domain's `_linkkeys` trust-anchor record into its valid fingerprint
/// set. Only syntactically valid (64-hex) fingerprints can pin anything, and a
/// record with none fails closed.
async fn lookup_linkkeys_fingerprints(
    net: &crate::net::Net,
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let dns_name = liblinkkeys::dns::linkkeys_dns_name(domain);
    let txts = net
        .dns
        .txt_lookup(&dns_name)
        .await
        .map_err(|e| format!("_linkkeys lookup for {} failed: {}", domain, e))?;

    let record = txts
        .iter()
        .find_map(|t| liblinkkeys::dns::parse_linkkeys_txt(t).ok())
        .ok_or_else(|| format!("no valid _linkkeys record for {}", domain))?;

    let fingerprints: Vec<String> = record
        .fingerprints
        .iter()
        .filter(|f| liblinkkeys::dns::is_valid_fingerprint(f))
        .cloned()
        .collect();
    if fingerprints.is_empty() {
        return Err(format!(
            "_linkkeys record for {} publishes no valid fingerprints; cannot pin keys",
            domain
        )
        .into());
    }
    Ok(fingerprints)
}

/// Resolve a domain's `_linkkeys_apis` record into its service endpoints (the
/// `tcp=` protocol service and/or the `https=` browser API base).
async fn lookup_linkkeys_apis(
    net: &crate::net::Net,
    domain: &str,
) -> Result<liblinkkeys::dns::LinkKeysApis, Box<dyn std::error::Error>> {
    let dns_name = liblinkkeys::dns::linkkeys_apis_dns_name(domain);
    let txts = net
        .dns
        .txt_lookup(&dns_name)
        .await
        .map_err(|e| format!("_linkkeys_apis lookup for {} failed: {}", domain, e))?;

    txts.iter()
        .find_map(|t| liblinkkeys::dns::parse_linkkeys_apis_txt(t).ok())
        .ok_or_else(|| format!("no valid _linkkeys_apis record for {}", domain).into())
}

/// Look up only the DNS-published fingerprint set for a domain (no key fetch).
/// Used to pin RP-inlined public keys on the `/userinfo` PoP fast path.
pub async fn fetch_dns_fingerprints(
    net: &crate::net::Net,
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    lookup_linkkeys_fingerprints(net, domain).await
}

/// Resolve the signing keys used to verify a relying party's proof-of-possession
/// signature on a `/userinfo` request.
///
/// Prefers keys the RP inlined in the request, but only after pinning each one's
/// recomputed fingerprint to the RP domain's DNS `fp=` set — this avoids an HTTP
/// key fetch (per the binding spec) while never trusting attacker-supplied keys.
/// When we are the relying party (single-instance IDP+RP) our own DB is
/// authoritative and the inlined hint is ignored. Falls back to the
/// authoritative fetch (DNS + HTTP, already pinned) when no inlined key pins.
pub async fn resolve_rp_signing_keys(
    pool: &DbPool,
    net: &crate::net::Net,
    relying_party: &str,
    inlined: Option<&[liblinkkeys::generated::types::DomainPublicKey]>,
) -> Result<Vec<liblinkkeys::generated::types::DomainPublicKey>, Box<dyn std::error::Error>> {
    if relying_party != get_domain_name() {
        if let Some(keys) = inlined {
            if !keys.is_empty() {
                let fps = fetch_dns_fingerprints(net, relying_party).await?;
                let pinned = liblinkkeys::dns::pin_keys_to_fingerprints(keys.to_vec(), &fps);
                if !pinned.is_empty() {
                    return Ok(pinned);
                }
            }
        }
    }
    fetch_rp_keys(pool, net, relying_party).await
}

/// Fetch a domain's public keys: pin set from `_linkkeys`, key bodies from the
/// `_linkkeys_apis` `https=` endpoint. Each returned key's recomputed
/// fingerprint must be a member of the published `fp=` set (or vouched by a
/// pinned signing key), else it is dropped; an empty result fails closed. The
/// wire `fingerprint` field is never trusted — it is recomputed.
///
/// (HTTPS transport here is the existing browser-adjacent path; server-to-server
/// key retrieval is moving to the `tcp=` endpoint — see DNS apis record.)
pub async fn fetch_domain_keys(
    pool: &DbPool,
    net: &crate::net::Net,
    domain: &str,
) -> Result<Vec<liblinkkeys::generated::types::DomainPublicKey>, Box<dyn std::error::Error>> {
    // A single-instance IDP+RP is authoritative for its own keys: read them
    // from the local DB rather than fetching them over https from ourselves.
    if domain == get_domain_name() {
        let keys = pool.list_active_domain_keys()?;
        return Ok(keys.iter().map(Into::into).collect());
    }

    // Fingerprints (trust anchor) come from `_linkkeys`; the HTTPS endpoint
    // (transport convenience) from `_linkkeys_apis`. Key integrity comes from the
    // pin below, not the transport.
    let fingerprints = lookup_linkkeys_fingerprints(net, domain).await?;
    let api_base = lookup_linkkeys_apis(net, domain)
        .await?
        .https_base
        .ok_or_else(|| {
            format!(
                "_linkkeys_apis for {} advertises no https= endpoint",
                domain
            )
        })?;

    let url = format!("{}/v1alpha/domain-keys.json", api_base);
    let response = net.http.get(&url).await?;
    if !response.success {
        let snippet: String = String::from_utf8_lossy(&response.body)
            .chars()
            .take(200)
            .collect();
        return Err(format!("GET {} returned an error: {}", url, snippet).into());
    }
    let resp: liblinkkeys::generated::types::GetDomainKeysResponse =
        serde_json::from_slice(&response.body).map_err(|e| {
            let snippet: String = String::from_utf8_lossy(&response.body)
                .chars()
                .take(200)
                .collect();
            format!(
                "parsing domain-keys JSON from {} failed: {} (body: {})",
                url, e, snippet
            )
        })?;

    // Establish the trusted key set: signing keys pinned to the DNS fp= set,
    // and encryption keys trusted via a signing-key vouch (verify_key_vouch).
    let trusted = liblinkkeys::dns::trust_keys(resp.keys, &fingerprints);
    if trusted.is_empty() {
        return Err(format!(
            "no key fetched for {} was trusted (no DNS-pinned signer / vouch)",
            domain
        )
        .into());
    }
    Ok(trusted)
}

#[cfg(test)]
mod tests {
    use super::api_base_host;

    #[test]
    fn api_base_host_strips_scheme_port_and_path() {
        assert_eq!(
            api_base_host("https://idp.example.com"),
            Some("idp.example.com")
        );
        assert_eq!(
            api_base_host("https://idp.example.com:8443"),
            Some("idp.example.com")
        );
        assert_eq!(
            api_base_host("https://idp.example.com:8443/v1alpha/userinfo"),
            Some("idp.example.com")
        );
        assert_eq!(
            api_base_host("https://idp.example.com/path?q=1#frag"),
            Some("idp.example.com")
        );
        // userinfo segment is dropped, host preserved
        assert_eq!(
            api_base_host("https://user@idp.example.com:443/x"),
            Some("idp.example.com")
        );
        // bracketed IPv6 host with a port keeps the brackets
        assert_eq!(api_base_host("https://[::1]:8443/x"), Some("[::1]"));
    }

    #[test]
    fn api_base_host_rejects_non_https_or_hostless() {
        assert_eq!(api_base_host("http://idp.example.com"), None);
        assert_eq!(api_base_host("idp.example.com"), None);
        assert_eq!(api_base_host("https:///path"), None);
        assert_eq!(api_base_host("https://"), None);
    }
}
