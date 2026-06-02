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
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    let input: SignRequestInput = serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;

    let domain_keys = pool.list_active_domain_keys().map_err(|_| Status::InternalServerError)?;
    if domain_keys.is_empty() {
        return Err(Status::InternalServerError);
    }
    let dk = &domain_keys[rand::thread_rng().gen_range(0..domain_keys.len())];

    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;
    let sk_bytes = liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
        .map_err(|_| Status::InternalServerError)?;

    let algorithm = liblinkkeys::crypto::SigningAlgorithm::parse_str(&dk.algorithm)
        .ok_or(Status::InternalServerError)?;

    let request = liblinkkeys::auth_request::build_auth_request(
        &get_domain_name(),
        &input.callback_url,
        &input.nonce,
        &dk.id,
    );

    let signed = liblinkkeys::auth_request::sign_auth_request(&request, &dk.id, algorithm, &sk_bytes)
        .map_err(|_| Status::InternalServerError)?;

    let encoded = liblinkkeys::encoding::signed_auth_request_to_url_param(&signed)
        .map_err(|_| Status::InternalServerError)?;

    let output = SignRequestOutput { signed_request: encoded };
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

    let encrypted_token = liblinkkeys::encoding::encrypted_token_from_url_param(&input.encrypted_token)
        .map_err(|_| Status::BadRequest)?;

    let domain_keys = pool.list_active_domain_keys().map_err(|_| Status::InternalServerError)?;

    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;

    // Try each active ENCRYPTION key (key_usage == "encrypt"); its decrypted
    // private is an X25519 secret used directly — no Ed25519→X25519 conversion.
    for dk in domain_keys.iter().filter(|k| k.key_usage == "encrypt") {
        let sk_bytes = match liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes()) {
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
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    let input: FetchUserInfoInput = serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;

    if !input.api_base.starts_with("https://") {
        return Err(Status::BadRequest);
    }

    let domain_keys = pool.list_active_domain_keys().map_err(|_| Status::InternalServerError)?;
    let signing_keys: Vec<_> = domain_keys.iter().filter(|k| k.key_usage == "sign").collect();
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

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&signed, &mut cbor).map_err(|_| Status::InternalServerError)?;

    let accept_invalid = std::env::var("ALLOW_INVALID_CERTS").unwrap_or_default() == "true";
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(accept_invalid)
        .build()
        .map_err(|_| Status::InternalServerError)?;

    let resp = client
        .post(format!("{}/v1alpha/userinfo", input.api_base))
        .header("Content-Type", "application/cbor")
        .body(cbor)
        .send()
        .await
        .map_err(|_| Status::BadGateway)?;

    if !resp.status().is_success() {
        return Err(Status::BadGateway);
    }

    let resp_bytes = resp.bytes().await.map_err(|_| Status::BadGateway)?;
    let user_info: liblinkkeys::generated::types::UserInfo =
        ciborium::de::from_reader(&resp_bytes[..]).map_err(|_| Status::BadGateway)?;

    let out = serde_json::to_vec(&user_info).map_err(|_| Status::InternalServerError)?;
    Ok((ContentType::JSON, out))
}

/// Verify a signed assertion against a domain's published keys.
/// Performs DNS lookup and key fetch for the expected domain.
#[rocket::post("/v1alpha/verify-assertion.json", data = "<body>")]
pub async fn verify_assertion_json(
    _user: AuthenticatedUser,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    let input: VerifyAssertionInput = serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;

    // Decode the signed assertion from base64url
    let cbor_bytes = base64ct::Base64UrlUnpadded::decode_vec(&input.signed_assertion)
        .map_err(|_| Status::BadRequest)?;
    let signed: liblinkkeys::generated::types::SignedIdentityAssertion =
        ciborium::de::from_reader(cbor_bytes.as_slice()).map_err(|_| Status::BadRequest)?;

    // Fetch the domain's public keys
    let domain_keys = fetch_domain_keys(&input.expected_domain).await.map_err(|_| Status::BadGateway)?;

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
    rp_domain: &str,
) -> Result<Vec<liblinkkeys::generated::types::DomainPublicKey>, Box<dyn std::error::Error>> {
    if rp_domain == get_domain_name() {
        let keys = pool.list_active_domain_keys()?;
        return Ok(keys.iter().map(Into::into).collect());
    }
    fetch_domain_keys(rp_domain).await
}

/// Fetch a domain's public keys by looking up its DNS TXT record and then
/// fetching from its API base URL.
///
/// Trust is anchored in DNS: the `_linkkeys` TXT record supplies both the
/// `api=` base (where to fetch key bodies) and the `fp=` set (which keys are
/// authoritative for the domain). Fetched keys are **pinned** — each returned
/// key's recomputed fingerprint must be a member of the published `fp=` set,
/// or it is dropped. Without a published, valid fingerprint set we cannot pin,
/// so we **fail closed** rather than trust the HTTP endpoint. The wire
/// `fingerprint` field on each key is never trusted; it is recomputed.
/// Resolve a domain's `_linkkeys` TXT record into its valid fingerprint set
/// and `api=` base. Trust is anchored here: only syntactically valid (64-hex)
/// fingerprints can pin anything, and a record with none fails closed.
async fn lookup_linkkeys_record(
    domain: &str,
) -> Result<(Vec<String>, String), Box<dyn std::error::Error>> {
    use hickory_resolver::TokioAsyncResolver;

    let dns_name = liblinkkeys::dns::linkkeys_dns_name(domain);
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;

    let response = resolver
        .txt_lookup(&dns_name)
        .await
        .map_err(|e| format!("no _linkkeys TXT record for {}: {}", domain, e))?;

    let mut record = None;
    for r in response.iter() {
        if let Ok(parsed) = liblinkkeys::dns::parse_linkkeys_txt(&r.to_string()) {
            record = Some(parsed);
            break;
        }
    }
    let record = record.ok_or_else(|| format!("no valid _linkkeys record for {}", domain))?;

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

    Ok((fingerprints, record.api_base))
}

/// Look up only the DNS-published fingerprint set for a domain (no key fetch).
/// Used to pin RP-inlined public keys on the `/userinfo` PoP fast path.
pub async fn fetch_dns_fingerprints(
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let (fingerprints, _api_base) = lookup_linkkeys_record(domain).await?;
    Ok(fingerprints)
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
    relying_party: &str,
    inlined: Option<&[liblinkkeys::generated::types::DomainPublicKey]>,
) -> Result<Vec<liblinkkeys::generated::types::DomainPublicKey>, Box<dyn std::error::Error>> {
    if relying_party != get_domain_name() {
        if let Some(keys) = inlined {
            if !keys.is_empty() {
                let fps = fetch_dns_fingerprints(relying_party).await?;
                let pinned = liblinkkeys::dns::pin_keys_to_fingerprints(keys.to_vec(), &fps);
                if !pinned.is_empty() {
                    return Ok(pinned);
                }
            }
        }
    }
    fetch_rp_keys(pool, relying_party).await
}

pub async fn fetch_domain_keys(
    domain: &str,
) -> Result<Vec<liblinkkeys::generated::types::DomainPublicKey>, Box<dyn std::error::Error>> {
    let (fingerprints, api_base) = lookup_linkkeys_record(domain).await?;

    // The api= endpoint is a transport convenience, but key integrity comes
    // from the pin — still require https so the fetch isn't trivially observed.
    if !api_base.starts_with("https://") {
        return Err(format!("_linkkeys api= for {} must use https", domain).into());
    }

    let accept_invalid = std::env::var("ALLOW_INVALID_CERTS").unwrap_or_default() == "true";
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(accept_invalid)
        .build()?;

    let resp: liblinkkeys::generated::types::GetDomainKeysResponse = client
        .get(format!("{}/v1alpha/domain-keys.json", api_base))
        .send()
        .await?
        .json()
        .await?;

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
