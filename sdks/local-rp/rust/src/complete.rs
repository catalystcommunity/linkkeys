//! `complete_local_login` (design doc: "SDK API Shape", "Flow" steps 12-13).
//!
//! This is the SDK's full verification chain, run in the exact order the
//! pure `liblinkkeys::local_rp` helpers require (see each step's comment for
//! which design-doc/security-checklist bullet it satisfies):
//!
//! 1. decode the callback ciphertext from its URL-param encoding
//! 2. open it (decrypt) — only with a suite this identity's own descriptor
//!    advertises
//! 3. fetch the pending domain's public keys + revocations, DNS-`fp=`-pinned,
//!    over TCP CSIL-RPC
//! 4. verify the domain-signed envelope (key lookup, revocation/expiry,
//!    signature, payload timestamp bounds) — only now is anything inside the
//!    payload trusted
//! 5. cross-check the cleartext header's routing fields against the
//!    now-verified payload
//! 6. audience / issuer / callback-URL / nonce-state checks
//! 7. redeem the claim ticket over TCP CSIL-RPC (signed with the local RP's
//!    own key — the possession proof)
//! 8. verify every returned claim's signatures against ITS signer domain's
//!    keys (fetched the same pinned way), which also checks the claim's own
//!    revocation/expiry (`liblinkkeys::claims::verify_claim`)

use crate::dns::DnsResolver;
use crate::identity::LocalRpKeyMaterial;
use crate::transport::Transport;
use crate::{begin::PendingLogin, Error};
use chrono::{DateTime, Utc};
use liblinkkeys::claims::{self, DomainKeySet};
use liblinkkeys::crypto::AeadSuite;
use liblinkkeys::generated::types::{Claim, DomainPublicKey};
use liblinkkeys::{encoding, local_rp};

/// Bound on the number of distinct claim-signer domains
/// [`complete_local_login`] will fetch keys for per completion — see the
/// comment at its use site for why this exists.
const MAX_CLAIM_SIGNER_DOMAINS: usize = 8;

/// Input to [`complete_local_login`]. Every field is load-bearing (design
/// doc: "`complete_local_login` inputs, spelled out because every one is
/// load-bearing").
pub struct CompleteLocalLoginConfig<'a> {
    /// The same identity `begin_local_login` used.
    pub key_material: &'a LocalRpKeyMaterial,
    /// The pending-login state `begin_local_login` returned, exactly as the
    /// app persisted it. The app must treat this as single-use; this crate
    /// owns no storage and cannot enforce that itself.
    pub pending: &'a PendingLogin,
    /// The raw callback data — the `encrypted_token` query-parameter value
    /// (base64url CBOR `LocalRpEncryptedCallback`).
    pub encrypted_token: &'a str,
    /// The URL the callback actually arrived at (the app's own HTTP
    /// handler's request URL, including the `encrypted_token` query
    /// parameter this SDK strips before comparing against the signed
    /// payload's `callback_url`).
    pub arrived_url: &'a str,
    pub now: DateTime<Utc>,
    /// Clock-skew tolerance for timestamp checks. Defaults to
    /// [`local_rp::DEFAULT_CLOCK_SKEW_SECONDS`] (±300s) when `None`.
    pub clock_skew_seconds: Option<i64>,
    /// The TCP dial seam. Defaults to [`crate::default_transport`].
    pub transport: &'a dyn Transport,
    /// The DNS TXT lookup seam. Defaults to [`crate::default_dns_resolver`].
    pub dns: &'a dyn DnsResolver,
}

impl<'a> CompleteLocalLoginConfig<'a> {
    /// Convenience constructor using the default network seams
    /// ([`crate::default_transport`], [`crate::default_dns_resolver`]).
    /// Override `transport`/`dns` afterward (struct-update syntax) to inject
    /// fakes in tests or a hardened DNS resolver in production.
    pub fn new(
        key_material: &'a LocalRpKeyMaterial,
        pending: &'a PendingLogin,
        encrypted_token: &'a str,
        arrived_url: &'a str,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            key_material,
            pending,
            encrypted_token,
            arrived_url,
            now,
            clock_skew_seconds: None,
            transport: crate::default_transport(),
            dns: crate::default_dns_resolver(),
        }
    }
}

/// What `complete_local_login` returns to app code (design doc: "SDKs ...
/// should either return verified results or call registered callbacks
/// with:" — this crate returns rather than calling back).
#[derive(Debug, Clone)]
pub struct VerifiedLocalLogin {
    pub user_id: String,
    pub user_domain: String,
    /// Verified claim values, current as of ticket redemption (design doc:
    /// "Ticket semantics" — the claim *set* is frozen at consent, but each
    /// redemption returns current *values*).
    pub claims: Vec<Claim>,
    /// The user's home domain's public keys used to verify the callback
    /// envelope (audit/logging context — never the whole trusted set for
    /// every claim signer domain; see `domain_public_keys` docs on
    /// per-signer-domain keys if a claim was attested by another domain).
    pub domain_public_keys: Vec<DomainPublicKey>,
    pub local_rp_fingerprint: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// The ticket's own expiry (design doc: "Valid for a bounded window,
    /// default 1 hour. Multi-use within the window").
    pub ticket_expires_at: DateTime<Utc>,
}

fn parse_rfc3339(field: &'static str, s: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Decode(format!("{field}: {e}")))
}

/// Undo the exact `?`/`&` + `encrypted_token=` suffix construction
/// `crates/linkkeys/src/web/local_rp_ui.rs` (and `web/mod.rs`) uses to
/// deliver the callback, so the recovered value can be compared against the
/// signed payload's `callback_url` (Wire Precision, "URL and parameter
/// conventions": "same name, same mechanics"). If the arrived URL doesn't
/// end with that exact suffix, returns it unchanged — the subsequent
/// `verify_callback_url` equality check will then correctly fail closed
/// rather than this function guessing.
fn strip_encrypted_token_param(arrived_url: &str) -> String {
    for sep in ['?', '&'] {
        let marker = format!("{sep}encrypted_token=");
        if let Some(idx) = arrived_url.rfind(&marker) {
            return arrived_url[..idx].to_string();
        }
    }
    arrived_url.to_string()
}

/// `complete_local_login(config) -> VerifiedLocalLogin` (design doc, "SDK API
/// Shape"). See the module docs for the exact verification order.
pub fn complete_local_login(
    config: CompleteLocalLoginConfig<'_>,
) -> Result<VerifiedLocalLogin, Error> {
    let skew = config
        .clock_skew_seconds
        .unwrap_or(local_rp::DEFAULT_CLOCK_SKEW_SECONDS);

    // 1. Decode the callback's URL-param encoding.
    let encrypted = encoding::local_rp_encrypted_callback_from_url_param(config.encrypted_token)
        .map_err(|e| Error::Decode(e.to_string()))?;

    // 2. Open it, restricted to suites THIS identity's own descriptor
    // advertises (Wire Precision: "The SDK must decrypt only with a suite
    // listed in its own descriptor").
    let own_descriptor = liblinkkeys::generated::decode_local_rp_descriptor(
        &config.key_material.descriptor.descriptor,
    )
    .map_err(|e| Error::Decode(format!("own descriptor: {e}")))?;
    let allowed_suites: Vec<AeadSuite> = own_descriptor
        .supported_suites
        .iter()
        .filter_map(|s| AeadSuite::parse_str(s))
        .collect();
    let (header, signed_payload) = local_rp::open_local_rp_callback(
        &encrypted,
        &config.key_material.encryption_private_key,
        &allowed_suites,
    )?;

    // 3. Fetch the PENDING state's domain's keys + revocations, DNS-pinned,
    // over TCP CSIL-RPC (design doc: "fetches domain public keys and
    // revocations for the domain the login was begun with").
    let user_domain_keys =
        crate::rpc::fetch_domain_keys(config.transport, config.dns, &config.pending.user_domain)?;

    // 4. Verify the domain-signed envelope against those keys (key lookup,
    // revocation/expiry, signature, payload timestamp bounds — all inside
    // `verify_local_rp_callback_payload`). Nothing inside `payload` is
    // trusted before this succeeds.
    let payload = local_rp::verify_local_rp_callback_payload(
        &signed_payload,
        &user_domain_keys,
        config.now,
        skew,
    )?;

    // 5. Cross-check the cleartext header's routing twins against the
    // now-verified payload.
    local_rp::check_callback_header_matches_payload(&header, &payload)?;

    // 6a. Audience: the callback names THIS local RP.
    local_rp::verify_audience(
        &payload.audience_fingerprint,
        &config.key_material.fingerprint,
    )?;

    // 6b. Issuer binding: the payload's user_domain must be the domain the
    // login was BEGUN with, not merely whichever domain's keys happened to
    // verify (SEC checklist: "the response domain equals the domain the
    // login began with").
    local_rp::verify_issuer(&payload.user_domain, &config.pending.user_domain)?;

    // 6c. Callback URL binding against the URL the callback actually arrived
    // at (not merely the URL originally requested).
    let arrived_base_url = strip_encrypted_token_param(config.arrived_url);
    local_rp::verify_callback_url(&payload.callback_url, &arrived_base_url)?;

    // 6d. Nonce/state equality against the pending state. Single-use replay
    // protection at the app boundary is the app's job (design doc) — this
    // only checks the values match.
    //
    // SEC note: this equality check (and the `!=`s in step 6a-6c above) is
    // performed by `liblinkkeys::local_rp::verify_nonce_state`, not this
    // crate — that function lives in `crates/liblinkkeys`, outside this
    // SDK's boundary (`sdks/local-rp/rust/`), so a constant-time comparison
    // there is out of scope for this change; flagging it here rather than
    // silently leaving it unaddressed. The nonce/state are high-entropy
    // (32 random bytes) values an attacker does not otherwise get many
    // guesses at, which bounds the practical exploitability of a timing
    // side-channel here, but it should still be tracked as a follow-up in
    // `crates/liblinkkeys` (that module is hand-written, not CSIL-generated,
    // so it's a direct liblinkkeys change, not a csilgen request).
    local_rp::verify_nonce_state(
        &config.pending.nonce,
        &config.pending.state,
        &payload.nonce,
        &payload.state,
    )?;

    // 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the local
    // RP's own key (the possession proof a stolen ticket can't satisfy).
    let redemption_request = local_rp::build_local_rp_ticket_redemption_request(
        payload.claim_ticket.clone(),
        &config.key_material.fingerprint,
        &config.now.to_rfc3339(),
    );
    let signed_redemption = local_rp::sign_local_rp_ticket_redemption_request(
        &redemption_request,
        &config.key_material.signing_private_key,
    )
    .map_err(Error::from)?;
    let redemption = crate::rpc::redeem_claim_ticket(
        config.transport,
        config.dns,
        &config.pending.user_domain,
        &signed_redemption,
    )?;

    // 7a. Identity binding (SEC fix): the ticket redemption response carries
    // no signature of its own — it is trusted only because it was fetched
    // over the DNS-pinned TLS channel for the domain the SIGNED callback
    // payload named. That is not the same as the redemption response
    // actually agreeing with the payload: a compromised/malicious IDP could
    // hand back claims for a different user than the one it cryptographically
    // vouched for in the signed callback (e.g. to launder an approval given
    // to user A onto user B's claims). Cross-check unconditionally, and treat
    // any mismatch as fatal — never fall back to either identity alone.
    if redemption.user_id != payload.user_id || redemption.user_domain != payload.user_domain {
        return Err(Error::IdentityMismatch(format!(
            "ticket redemption identity ({:?}, {:?}) does not match the signed callback payload's identity ({:?}, {:?})",
            redemption.user_id, redemption.user_domain, payload.user_id, payload.user_domain
        )));
    }

    // 8. Verify every returned claim's signatures against ITS signer
    // domain's keys, fetched the same pinned way (a claim may be attested by
    // a domain other than the user's home domain). Reuse the home domain's
    // already-fetched keys; fetch any additional signer domains on demand.
    //
    // The redemption response's claim signatures name their signing domains
    // as plain, not-yet-verified strings — a malicious/compromised home IDP
    // could otherwise list an unbounded number of distinct "signer domains"
    // purely to make this SDK perform many outbound DNS/TCP calls to
    // attacker-chosen targets before any signature is actually checked
    // (an SSRF/DoS amplification vector against the app's own process). Cap
    // the number of distinct signer domains this SDK will fetch keys for per
    // completion; a legitimate claim set names very few (typically one: the
    // home domain).
    let mut domain_key_sets: Vec<DomainKeySet> = vec![DomainKeySet {
        domain: config.pending.user_domain.clone(),
        keys: user_domain_keys.clone(),
    }];
    for claim in &redemption.claims {
        for sig in &claim.signatures {
            if !domain_key_sets.iter().any(|s| s.domain == sig.domain) {
                if domain_key_sets.len() >= MAX_CLAIM_SIGNER_DOMAINS {
                    return Err(Error::InvalidInput(format!(
                        "claim set names more than {MAX_CLAIM_SIGNER_DOMAINS} distinct signer domains; refusing to fetch further keys"
                    )));
                }
                let keys =
                    crate::rpc::fetch_domain_keys(config.transport, config.dns, &sig.domain)?;
                domain_key_sets.push(DomainKeySet {
                    domain: sig.domain.clone(),
                    keys,
                });
            }
        }
    }
    // Each claim must also name the SAME user the signed payload vouched
    // for — without this, a malicious IDP could splice in a claim belonging
    // to a different user_id inside an otherwise-valid, correctly-signed
    // redemption response (the claim's own signature only proves the issuing
    // domain signed *that* claim, not that it's the claim for *this* login).
    // Verified against `payload.user_id` — the SIGNED source of truth, not
    // `redemption.user_id` (equal at this point, but the payload is what was
    // actually cryptographically attested).
    for claim in &redemption.claims {
        if claim.user_id != payload.user_id {
            return Err(Error::IdentityMismatch(format!(
                "claim {:?} names user_id {:?}, expected {:?} (the signed callback payload's subject)",
                claim.claim_id, claim.user_id, payload.user_id
            )));
        }
        claims::verify_claim(claim, &payload.user_domain, &domain_key_sets).map_err(Error::from)?;
    }

    // Enforce the required_claims the login was BEGUN with (SEC checklist:
    // "the app-declared required claims are actually enforced"). Only claim
    // types that survived signature verification above count — an
    // unsigned/unverifiable claim can never satisfy a requirement. An empty
    // or insufficient claim set against a non-empty requirement is fatal.
    let verified_claim_types: std::collections::BTreeSet<&str> = redemption
        .claims
        .iter()
        .map(|c| c.claim_type.as_str())
        .collect();
    let missing_required: Vec<String> = config
        .pending
        .required_claims
        .iter()
        .filter(|rc| !verified_claim_types.contains(rc.as_str()))
        .cloned()
        .collect();
    if !missing_required.is_empty() {
        return Err(Error::RequiredClaimsNotSatisfied(missing_required));
    }

    Ok(VerifiedLocalLogin {
        // Sourced from the VERIFIED, SIGNED payload — not the redemption
        // response — even though the two are now known to agree (checked
        // above). The payload is the thing that was actually cryptographically
        // attested by the domain; the redemption response is merely
        // corroborating data fetched over a channel that is pinned but
        // otherwise unsigned.
        user_id: payload.user_id.clone(),
        user_domain: payload.user_domain.clone(),
        claims: redemption.claims,
        domain_public_keys: user_domain_keys,
        local_rp_fingerprint: config.key_material.fingerprint.clone(),
        issued_at: parse_rfc3339("callback issued_at", &payload.issued_at)?,
        expires_at: parse_rfc3339("callback expires_at", &payload.expires_at)?,
        ticket_expires_at: parse_rfc3339("ticket_expires_at", &redemption.ticket_expires_at)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_encrypted_token_param_recovers_original_url_both_separators() {
        assert_eq!(
            strip_encrypted_token_param("http://localhost/cb?encrypted_token=abc123"),
            "http://localhost/cb"
        );
        assert_eq!(
            strip_encrypted_token_param("http://localhost/cb?x=1&encrypted_token=abc123"),
            "http://localhost/cb?x=1"
        );
    }

    #[test]
    fn strip_encrypted_token_param_passthrough_when_absent() {
        assert_eq!(
            strip_encrypted_token_param("http://localhost/cb?x=1"),
            "http://localhost/cb?x=1"
        );
    }
}
