use rand::Rng;
use rocket::http::Status;
use std::env;

use crate::conversions::get_domain_name;
use crate::db::DbPool;

/// Core of sign-request: build and sign an auth request for the login redirect
/// using this server's domain key. Shared by the web JSON route and the
/// `Rp/sign-request` TCP op.
pub(crate) fn sign_request_core(
    pool: &DbPool,
    rp_config: &crate::rp_config::RpClaimsConfig,
    callback_url: &str,
    nonce: &str,
    requested_claims: Option<liblinkkeys::generated::types::ClaimRequest>,
    flow_context: Option<liblinkkeys::generated::types::AuthFlowContext>,
) -> Result<liblinkkeys::generated::types::RpSignResponse, Status> {
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
        callback_url,
        nonce,
        &dk.id,
        requested_claims.or_else(|| rp_config.to_claim_request()),
        flow_context,
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

    Ok(liblinkkeys::generated::types::RpSignResponse {
        signed_request: encoded,
    })
}

/// Core of decrypt-token: decrypt the RP's encrypted callback token with one of
/// this server's encryption keys. Shared by the web JSON route and the
/// `Rp/decrypt-token` TCP op.
pub(crate) fn decrypt_token_core(
    pool: &DbPool,
    encrypted_token: &str,
) -> Result<liblinkkeys::generated::types::RpDecryptResponse, Status> {
    let encrypted_token = liblinkkeys::encoding::encrypted_token_from_url_param(encrypted_token)
        .map_err(|_| Status::BadRequest)?;

    // Absent `suite` means the mandatory-to-implement baseline (aes-256-gcm);
    // a present-but-unrecognized id is rejected outright rather than falling
    // back silently (Wire Precision: "reject an unadvertised/unsupported
    // suite").
    let suite = liblinkkeys::crypto::resolve_aead_suite(encrypted_token.suite.as_deref())
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
            suite,
        ) {
            // The plaintext is CBOR-encoded SignedIdentityAssertion — re-encode as base64url
            let signed_assertion = base64ct::Base64UrlUnpadded::encode_string(&plaintext);
            return Ok(liblinkkeys::generated::types::RpDecryptResponse { signed_assertion });
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

/// Core of userinfo-fetch: fetch a user's claims from the IDP on the relying
/// party's behalf. Shared by the web JSON route and the `Rp/userinfo-fetch` TCP
/// op. On the single-instance self path it redeems locally with a proof-of-
/// possession request; on the remote path it redeems over the server-to-server
/// CSIL-RPC transport, where mutual TLS with our domain cert proves we are the
/// assertion's audience (so the token alone suffices — no PoP signature).
pub(crate) async fn fetch_userinfo_core(
    pool: &DbPool,
    net: &crate::net::Net,
    token: String,
    api_base: &str,
    domain: &str,
) -> Result<liblinkkeys::generated::types::UserInfo, Status> {
    if !api_base.starts_with("https://") {
        return Err(Status::BadRequest);
    }

    // Single-instance IDP+RP: when the IDP API we'd call is our own published
    // API host, redeem locally instead of going over the network to ourselves.
    // There is exactly one IDP per domain, so the host alone identifies it —
    // port and path are irrelevant. We match against API_HOSTNAME (the host we
    // actually publish in our `_linkkeys` api= record), which need not equal our
    // domain name. The local path builds a self-signed PoP request and runs the
    // full PoP-verify, single-use nonce burn, and claim lookup that the network
    // round-trip would trigger.
    let our_api_host = env::var("API_HOSTNAME").unwrap_or_else(|_| get_domain_name());
    if api_base_host(api_base).is_some_and(|h| h.eq_ignore_ascii_case(&our_api_host)) {
        let signed = build_self_signed_userinfo_request(pool, token)?;
        return super::build_userinfo_signed(pool, net, &signed).await;
    }

    // Remote IDP: redeem over the server-to-server CSIL-RPC transport
    // (`Identity/get-user-info`). Mutual TLS with our domain cert proves we are
    // the assertion's audience — the IDP binds the redemption to the FP-pinned
    // mTLS client domain — so the token alone suffices over TCP; the explicit
    // proof-of-possession signature the HTTPS path carries is unnecessary here.
    let fingerprints = lookup_linkkeys_fingerprints(net, domain)
        .await
        .map_err(|_| Status::BadGateway)?;
    let (addr, hostname) = lookup_tcp_target(net, domain)
        .await
        .map_err(|_| Status::BadGateway)?;
    let client_cert = own_client_cert(pool);
    let payload = liblinkkeys::generated::encode_get_user_info_request(
        &liblinkkeys::generated::types::GetUserInfoRequest {
            token: token.into_bytes(),
        },
    );
    let resp_bytes = net
        .rpc
        .call(
            &addr,
            &hostname,
            fingerprints,
            client_cert,
            "Identity",
            "get-user-info",
            payload,
            None,
        )
        .await
        .map_err(|_| Status::BadGateway)?;
    liblinkkeys::generated::decode_user_info(&resp_bytes).map_err(|_| Status::BadGateway)
}

/// Fetch a user's claims from the IDP on the relying party's behalf, proving
/// we are the assertion's audience (crypto-06).
///
/// This is the RP-side counterpart to the IDP's `/v1alpha/userinfo`: the calling
/// app (which holds no domain key) delegates here.
/// Build a proof-of-possession `SignedUserInfoRequest` signed with one of this
/// domain's signing keys, inlining our signing keys so a first-contact IDP can
/// pin them to our DNS `fp=`. Used only on the single-instance self-redeem path,
/// where the IDP being called is us.
fn build_self_signed_userinfo_request(
    pool: &DbPool,
    token: String,
) -> Result<liblinkkeys::generated::types::SignedUserInfoRequest, Status> {
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
        token.into_bytes(),
        &get_domain_name(),
        &nonce,
    );

    let inlined: Vec<liblinkkeys::generated::types::DomainPublicKey> =
        signing_keys.iter().map(|k| (*k).into()).collect();

    liblinkkeys::userinfo::sign_user_info_request(
        &request,
        &dk.id,
        algorithm,
        &sk_bytes,
        Some(inlined),
    )
    .map_err(|_| Status::InternalServerError)
}

/// Core of verify-assertion: verify a signed assertion against the issuing
/// domain's published keys (fetched via DNS + the server-to-server transport).
/// Shared by the web JSON route and the `Rp/verify-assertion` TCP op.
pub(crate) async fn verify_assertion_core(
    pool: &DbPool,
    net: &crate::net::Net,
    signed_assertion: &str,
    expected_domain: &str,
) -> Result<liblinkkeys::generated::types::RpVerifyResponse, Status> {
    // Decode the signed assertion from base64url
    let cbor_bytes = base64ct::Base64UrlUnpadded::decode_vec(signed_assertion)
        .map_err(|_| Status::BadRequest)?;
    let signed = liblinkkeys::generated::decode_signed_identity_assertion(cbor_bytes.as_slice())
        .map_err(|_| Status::BadRequest)?;

    // Fetch the domain's public keys
    let domain_keys = fetch_domain_keys(pool, net, expected_domain)
        .await
        .map_err(|_| Status::BadGateway)?;

    // Verify the assertion
    let assertion = liblinkkeys::assertions::verify_assertion(&signed, &domain_keys)
        .map_err(|_| Status::Unauthorized)?;

    Ok(liblinkkeys::generated::types::RpVerifyResponse {
        assertion,
        verified: true,
    })
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

/// Resolve a domain's server-to-server TCP target from its `_linkkeys_apis`
/// `tcp=` record: the `host:port` to dial and the SNI/cert hostname to pin. The
/// `tcp=` endpoint is the first-class transport for peer calls; fails closed when
/// the domain advertises no `tcp=` endpoint.
async fn lookup_tcp_target(
    net: &crate::net::Net,
    domain: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let addr = lookup_linkkeys_apis(net, domain)
        .await?
        .tcp
        .ok_or_else(|| format!("_linkkeys_apis for {} advertises no tcp= endpoint", domain))?;
    let hostname = linkkeys_rpc_client::extract_hostname(&addr).to_string();
    Ok((addr, hostname))
}

/// Load this domain's own TLS client certificate (DER cert, DER key) for mutual
/// TLS on outbound server-to-server calls, or `None` when this process holds no
/// usable domain key. When present, the peer can verify us back and bind the
/// call to our domain (e.g. audience binding on `/userinfo`). Mirrors the TCP
/// server's own-cert selection (first active domain key).
fn own_client_cert(pool: &DbPool) -> Option<(Vec<u8>, Vec<u8>)> {
    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE").ok()?;
    let domain_keys = pool.list_active_domain_keys().ok()?;
    let dk = domain_keys.first()?;
    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .ok()?;
    let seed: [u8; 32] = sk_bytes.try_into().ok()?;
    crate::tcp::tls::generate_domain_tls_cert(&get_domain_name(), &seed).ok()
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
/// `_linkkeys_apis` `tcp=` endpoint over the server-to-server CSIL-RPC transport
/// (`DomainKeys/get-domain-keys`). Each returned key's recomputed fingerprint
/// must be a member of the published `fp=` set (or vouched by a pinned signing
/// key), else it is dropped; an empty result fails closed. The wire
/// `fingerprint` field is never trusted — it is recomputed.
pub async fn fetch_domain_keys(
    pool: &DbPool,
    net: &crate::net::Net,
    domain: &str,
) -> Result<Vec<liblinkkeys::generated::types::DomainPublicKey>, Box<dyn std::error::Error>> {
    // A single-instance IDP+RP is authoritative for its own keys: read them
    // from the local DB rather than fetching them over the network from ourselves.
    if domain == get_domain_name() {
        let keys = pool.list_active_domain_keys()?;
        return Ok(keys.iter().map(Into::into).collect());
    }

    // Fingerprints (trust anchor) come from `_linkkeys`; the TCP endpoint
    // (transport) from `_linkkeys_apis`. Key integrity comes from the pin below,
    // not the transport — but the pinned fingerprints also authenticate the TLS
    // server cert, so we only ever speak to the real domain.
    let fingerprints = lookup_linkkeys_fingerprints(net, domain).await?;

    // SEC-01: enforce the TOFU pin before trusting any keys for this domain. A
    // first contact pins the set; a single-key rotation is accepted and re-pinned;
    // a larger unexpected change fails closed (and is queued for admin review).
    if !crate::services::pins::check_and_update_pin(pool, domain, &fingerprints).is_trusted() {
        return Err(format!(
            "refusing keys for {}: its pinned DNS fingerprint set changed unexpectedly; queued for admin review",
            domain
        )
        .into());
    }

    let (addr, hostname) = lookup_tcp_target(net, domain).await?;

    // get-domain-keys is a public read; no client cert needed (server-auth TLS).
    let payload = liblinkkeys::generated::encode_empty_request(
        &liblinkkeys::generated::types::EmptyRequest {},
    );
    let resp_bytes = net
        .rpc
        .call(
            &addr,
            &hostname,
            fingerprints.clone(),
            None,
            "DomainKeys",
            "get-domain-keys",
            payload,
            None,
        )
        .await?;
    let resp =
        liblinkkeys::generated::decode_get_domain_keys_response(&resp_bytes).map_err(|e| {
            format!(
                "decoding get-domain-keys response from {} failed: {}",
                domain, e
            )
        })?;

    // Establish the trusted key set: signing keys pinned to the DNS fp= set,
    // and encryption keys trusted via a signing-key vouch (verify_key_vouch).
    let mut trusted = liblinkkeys::dns::trust_keys(resp.keys, &fingerprints);
    if trusted.is_empty() {
        return Err(format!(
            "no key fetched for {} was trusted (no DNS-pinned signer / vouch)",
            domain
        )
        .into());
    }

    // SEC-08: if the domain signals recent revocations, pull + verify them and
    // drop any key it has provably revoked from the trusted set for this call.
    // Best-effort: a failed fetch never blocks the login (we simply haven't
    // learned of any revocation yet — the other keys stay trusted).
    if resp.recent_revocations_available == Some(true) {
        let revoked = fetch_and_apply_revocations(
            pool,
            net,
            domain,
            &addr,
            &hostname,
            &fingerprints,
            &trusted,
        )
        .await;
        if !revoked.is_empty() {
            trusted.retain(|k| !revoked.contains(&k.key_id));
        }
    }

    Ok(trusted)
}

/// Pull `domain`'s issued revocation certs (public read) and apply the verified
/// ones. Returns the provably-revoked key ids. Any error is logged and yields an
/// empty result — revocation delivery is best-effort and must not fail a login.
#[allow(clippy::too_many_arguments)]
async fn fetch_and_apply_revocations(
    pool: &DbPool,
    net: &crate::net::Net,
    domain: &str,
    addr: &str,
    hostname: &str,
    fingerprints: &[String],
    trusted: &[liblinkkeys::generated::types::DomainPublicKey],
) -> Vec<String> {
    let since = (chrono::Utc::now()
        - chrono::Duration::days(crate::services::revocations::fetch_default_days()))
    .to_rfc3339();
    let payload = liblinkkeys::generated::encode_get_revocations_request(
        &liblinkkeys::generated::types::GetRevocationsRequest { since: Some(since) },
    );
    let resp_bytes = match net
        .rpc
        .call(
            addr,
            hostname,
            fingerprints.to_vec(),
            None,
            "DomainKeys",
            "get-revocations",
            payload,
            None,
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            log::warn!("get-revocations for {domain} failed (continuing): {e}");
            return Vec::new();
        }
    };
    match liblinkkeys::generated::decode_get_revocations_response(&resp_bytes) {
        Ok(resp) => crate::services::revocations::apply(pool, domain, trusted, &resp.revocations),
        Err(e) => {
            log::warn!("decoding get-revocations from {domain} failed (continuing): {e}");
            Vec::new()
        }
    }
}

/// Deposit a signed claim to `domain`'s IDP over the server-to-server CSIL-RPC
/// transport (the `tcp=` endpoint, `Attestation/deposit-claim` op).
/// Server-to-server: an issuer pushes an attestation it signed to the subject's
/// home domain, which verifies + stores it. The claim's own signature is the
/// authority, so no client cert is required — but we still pin the subject
/// domain's TLS server cert to its DNS fingerprints so we only ever deliver to
/// the real domain. Returns Err with a human message on any failure so the
/// caller can fall back (e.g. hand the claim to the user out-of-band).
pub(super) async fn deposit_claim_to_domain(
    net: &crate::net::Net,
    domain: &str,
    claim: &liblinkkeys::generated::types::Claim,
) -> Result<(), String> {
    let fingerprints = lookup_linkkeys_fingerprints(net, domain)
        .await
        .map_err(|e| e.to_string())?;
    let (addr, hostname) = lookup_tcp_target(net, domain)
        .await
        .map_err(|e| e.to_string())?;
    let payload = liblinkkeys::generated::encode_deposit_claim_request(
        &liblinkkeys::generated::types::DepositClaimRequest {
            claim: claim.clone(),
        },
    );
    let resp_bytes = net
        .rpc
        .call(
            &addr,
            &hostname,
            fingerprints,
            None,
            "Attestation",
            "deposit-claim",
            payload,
            None,
        )
        .await
        .map_err(|e| format!("{} rejected the claim: {}", domain, e))?;
    let resp = liblinkkeys::generated::decode_deposit_claim_response(&resp_bytes)
        .map_err(|e| e.to_string())?;
    if !resp.stored {
        return Err(format!("{} rejected the claim", domain));
    }
    Ok(())
}

fn rp_issue_claim_allowed(claim_type: &str) -> bool {
    std::env::var("RP_ISSUE_CLAIMS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .any(|ct| ct == claim_type)
}

/// Issue an attested claim as this RP domain from a user/home-domain signed
/// signing request, then try to deposit it back to the subject's home domain.
/// Used by browser-facing demo apps that do not hold the domain key themselves.
pub(crate) async fn issue_attestation_core(
    pool: &DbPool,
    net: &crate::net::Net,
    signed_request: liblinkkeys::generated::types::SignedSigningRequest,
    claim_type: &str,
    claim_value: &[u8],
) -> Result<liblinkkeys::generated::types::RpIssueAttestationResponse, Status> {
    if !rp_issue_claim_allowed(claim_type) {
        return Err(Status::Forbidden);
    }

    let preview = liblinkkeys::generated::decode_signing_request(&signed_request.request)
        .map_err(|_| Status::BadRequest)?;
    if !preview
        .requested_claim_types
        .iter()
        .any(|requested| requested == claim_type)
    {
        return Err(Status::BadRequest);
    }

    let issuer_domain = get_domain_name();
    if preview.issuer_domain != issuer_domain {
        return Err(Status::Forbidden);
    }

    let keys = fetch_domain_keys(pool, net, &preview.subject_domain)
        .await
        .map_err(|_| Status::BadGateway)?;
    let keysets = vec![liblinkkeys::claims::DomainKeySet {
        domain: preview.subject_domain.clone(),
        keys,
    }];
    let request = liblinkkeys::signing_request::verify_signing_request(
        &signed_request,
        &preview.subject_domain,
        &issuer_domain,
        &keysets,
    )
    .map_err(|_| Status::Unauthorized)?;

    let claim = crate::services::attestation::issue_attested_claim(
        pool,
        &request.subject_user_id,
        &request.subject_domain,
        claim_type,
        claim_value,
    )
    .map_err(|e| match e.code {
        403 => Status::Forbidden,
        400 => Status::BadRequest,
        _ => Status::InternalServerError,
    })?;

    let deposited = match deposit_claim_to_domain(net, &request.subject_domain, &claim).await {
        Ok(()) => true,
        Err(e) => {
            log::warn!(
                "Attested claim deposit failed for subject domain {} and claim type {}: {}",
                request.subject_domain,
                claim_type,
                e
            );
            false
        }
    };
    Ok(liblinkkeys::generated::types::RpIssueAttestationResponse { claim, deposited })
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
