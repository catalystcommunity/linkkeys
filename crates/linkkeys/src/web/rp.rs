use rand::Rng;
use rocket::http::{ContentType, Status};
use rocket::State;
use serde::{Deserialize, Serialize};
use std::env;

use linkkeys::conversions::get_domain_name;
use linkkeys::db::DbPool;

use super::guard::BearerUser;

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
    _user: BearerUser,
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

    let algorithm = liblinkkeys::crypto::SigningAlgorithm::from_str(&dk.algorithm)
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
    _user: BearerUser,
    pool: &State<DbPool>,
    body: String,
) -> Result<(ContentType, Vec<u8>), Status> {
    let input: DecryptTokenInput = serde_json::from_str(&body).map_err(|_| Status::BadRequest)?;

    let encrypted_token = liblinkkeys::encoding::encrypted_token_from_url_param(&input.encrypted_token)
        .map_err(|_| Status::BadRequest)?;

    let domain_keys = pool.list_active_domain_keys().map_err(|_| Status::InternalServerError)?;

    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| Status::InternalServerError)?;

    // Try each active key to decrypt (we don't know which key was used to encrypt)
    for dk in &domain_keys {
        let sk_bytes = match liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let x25519_private = match liblinkkeys::crypto::ed25519_private_to_x25519(&sk_bytes) {
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

/// Verify a signed assertion against a domain's published keys.
/// Performs DNS lookup and key fetch for the expected domain.
#[rocket::post("/v1alpha/verify-assertion.json", data = "<body>")]
pub async fn verify_assertion_json(
    _user: BearerUser,
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

/// Fetch a domain's public keys by looking up its DNS TXT record and then
/// fetching from its API base URL.
pub async fn fetch_domain_keys(
    domain: &str,
) -> Result<Vec<liblinkkeys::generated::types::DomainPublicKey>, Box<dyn std::error::Error>> {
    use hickory_resolver::TokioAsyncResolver;

    let dns_name = liblinkkeys::dns::linkkeys_dns_name(domain);
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;

    let api_base = match resolver.txt_lookup(&dns_name).await {
        Ok(response) => {
            let mut api = None;
            for record in response.iter() {
                let txt = record.to_string();
                if let Ok(parsed) = liblinkkeys::dns::parse_linkkeys_txt(&txt) {
                    api = Some(parsed.api_base);
                    break;
                }
            }
            api.unwrap_or_else(|| format!("https://{}", domain))
        }
        Err(_) => format!("https://{}", domain),
    };

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

    Ok(resp.keys)
}
