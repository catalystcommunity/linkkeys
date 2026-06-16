use crate::crypto::fingerprint;
use crate::generated::types::DomainPublicKey;
use std::fmt;

/// Default TCP port for the LinkKeys protocol service. Advertised `tcp=` values
/// omit the port when it equals this, and parsing fills it in. Operators are
/// encouraged to run on this port and leave it unspecified.
pub const DEFAULT_TCP_PORT: u16 = 4987;

/// Maximum length of a single DNS TXT character-string (RFC 1035). A record
/// longer than this must be split into multiple strings, which many resolvers
/// and zone tools handle poorly — so we warn when an advertised record exceeds
/// it.
pub const MAX_TXT_STRING_LEN: usize = 255;

/// Parsed `_linkkeys.{domain}` TXT record — the trust anchor.
///
/// Expected format: `v=lk1 fp={fingerprint1} fp={fingerprint2} ...`
///
/// The `v=lk1` tag identifies this as a LinkKeys v1 record. The `fp=` fields are
/// SHA-256 hex fingerprints of the domain's signing keys. Service *endpoints*
/// (where to actually connect) live in the separate `_linkkeys_apis` record, so
/// the trust anchor stays stable while endpoints move.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkKeysRecord {
    pub fingerprints: Vec<String>,
}

/// Parsed `_linkkeys_apis.{domain}` TXT record — service endpoints.
///
/// Expected format: `v=lk1 tcp={host[:port]} https={host[:port][/path]}`
///
/// - `tcp=` is the LinkKeys protocol service (the first-class, server-to-server
///   transport). The port defaults to [`DEFAULT_TCP_PORT`] when omitted; parsed
///   values are normalized to always carry an explicit `host:port`.
/// - `https=` is the browser-facing HTTPS API base. The scheme is implied; the
///   port defaults to 443 (left implicit in the resulting URL). Parsed into a
///   full `https://…` base.
///
/// At least one of the two must be present.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkKeysApis {
    /// `host:port` for the TCP service, with the default port filled in.
    pub tcp: Option<String>,
    /// Full `https://host[:port][/path]` base for the HTTPS API.
    pub https_base: Option<String>,
}

#[derive(Debug)]
pub enum DnsParseError {
    NoLinkKeysRecord,
    MissingVersion,
    UnsupportedVersion(String),
    /// The `_linkkeys_apis` record carried neither a `tcp=` nor an `https=` field.
    MissingApisEndpoint,
    InvalidFormat(String),
}

impl fmt::Display for DnsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsParseError::NoLinkKeysRecord => write!(f, "no _linkkeys TXT record found"),
            DnsParseError::MissingVersion => write!(f, "missing v= tag in TXT record"),
            DnsParseError::UnsupportedVersion(v) => {
                write!(f, "unsupported linkkeys version: {}", v)
            }
            DnsParseError::MissingApisEndpoint => {
                write!(f, "_linkkeys_apis record has neither tcp= nor https=")
            }
            DnsParseError::InvalidFormat(msg) => write!(f, "invalid TXT record format: {}", msg),
        }
    }
}

impl std::error::Error for DnsParseError {}

/// The `_linkkeys` (trust-anchor) DNS name for a domain.
pub fn linkkeys_dns_name(domain: &str) -> String {
    format!("_linkkeys.{}", domain)
}

/// The `_linkkeys_apis` (service-endpoint) DNS name for a domain.
pub fn linkkeys_apis_dns_name(domain: &str) -> String {
    format!("_linkkeys_apis.{}", domain)
}

/// Require a `v=lk1` version tag among the whitespace-split parts.
fn require_lk1_version(parts: &[&str]) -> Result<(), DnsParseError> {
    let version = parts
        .iter()
        .find(|p| p.starts_with("v="))
        .map(|p| &p[2..])
        .ok_or(DnsParseError::MissingVersion)?;
    if version != "lk1" {
        return Err(DnsParseError::UnsupportedVersion(version.to_string()));
    }
    Ok(())
}

/// Parse a single `_linkkeys` TXT record string into a [`LinkKeysRecord`].
/// Errors if it isn't a LinkKeys v1 record (no `v=lk1` tag).
pub fn parse_linkkeys_txt(txt: &str) -> Result<LinkKeysRecord, DnsParseError> {
    let parts: Vec<&str> = txt.split_whitespace().collect();
    require_lk1_version(&parts)?;

    let fingerprints: Vec<String> = parts
        .iter()
        .filter(|p| p.starts_with("fp="))
        .map(|p| p[3..].to_string())
        .collect();

    Ok(LinkKeysRecord { fingerprints })
}

/// Parse a single `_linkkeys_apis` TXT record string into [`LinkKeysApis`].
/// Errors if it isn't a LinkKeys v1 record or carries no endpoint.
pub fn parse_linkkeys_apis_txt(txt: &str) -> Result<LinkKeysApis, DnsParseError> {
    let parts: Vec<&str> = txt.split_whitespace().collect();
    require_lk1_version(&parts)?;

    let tcp = parts
        .iter()
        .find(|p| p.starts_with("tcp="))
        .map(|p| normalize_tcp_endpoint(&p[4..]))
        .filter(|v| !v.is_empty());

    let https_base = parts
        .iter()
        .find(|p| p.starts_with("https="))
        .map(|p| p[6..].to_string())
        .filter(|v| !v.is_empty())
        .map(|v| format!("https://{}", v));

    if tcp.is_none() && https_base.is_none() {
        return Err(DnsParseError::MissingApisEndpoint);
    }

    Ok(LinkKeysApis { tcp, https_base })
}

/// Normalize a published `tcp=` value (`host` or `host:port`) into an explicit
/// `host:port`, filling in [`DEFAULT_TCP_PORT`] when the port is omitted. A raw
/// TCP connect needs the port, unlike an HTTPS URL where it can stay implicit.
///
/// The host is always a hostname (IPv6 is reached via its AAAA record, never an
/// inline literal), so a bare `:` unambiguously separates host from port.
fn normalize_tcp_endpoint(value: &str) -> String {
    if value.is_empty() || value.contains(':') {
        value.to_string()
    } else {
        format!("{}:{}", value, DEFAULT_TCP_PORT)
    }
}

/// True if `fp` is a syntactically valid key fingerprint: 64 hex chars
/// (a SHA-256 digest). Case-insensitive. Used to reject malformed `fp=`
/// values before pinning so garbage can never be mistaken for a pin.
pub fn is_valid_fingerprint(fp: &str) -> bool {
    fp.len() == 64 && fp.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Pin fetched keys to the DNS-published fingerprint set.
///
/// This is the trust anchor for the discovery flow: the `_linkkeys` TXT
/// record's `fp=` values are authoritative for *which* keys speak for a
/// domain; the HTTP key-fetch endpoint only supplies the key *bodies*.
///
/// For each candidate key we **recompute** `fingerprint(public_key)` (never
/// trusting the wire `fingerprint` field, which is attacker-controlled) and
/// keep only keys whose recomputed fingerprint is a member of `pinned`.
/// Comparison is case-insensitive hex. Invalid `pinned` entries are ignored.
/// A key matching no pinned fingerprint is dropped. Callers MUST treat an
/// empty result as "no trustworthy keys" and fail closed.
pub fn pin_keys_to_fingerprints(
    keys: Vec<DomainPublicKey>,
    pinned: &[String],
) -> Vec<DomainPublicKey> {
    let pinned_lower: Vec<String> = pinned
        .iter()
        .filter(|f| is_valid_fingerprint(f))
        .map(|f| f.to_ascii_lowercase())
        .collect();
    keys.into_iter()
        .filter(|k| {
            let fp = fingerprint(&k.public_key).to_ascii_lowercase();
            pinned_lower.contains(&fp)
        })
        .collect()
}

/// Domain-separation tag for a signing key's vouch over an encryption key.
const KEY_VOUCH_TAG: &str = "linkkeys-key-vouch-v1";

/// Canonical bytes a signing key signs to vouch for an encryption key:
/// `(tag, encrypt-key fingerprint, encrypt-key expires_at)` as deterministic
/// CBOR. The fingerprint is the SHA-256 of the encryption key's public bytes.
pub fn key_vouch_payload(enc_fingerprint: &str, enc_expires_at: &str) -> Vec<u8> {
    let payload = (KEY_VOUCH_TAG, enc_fingerprint, enc_expires_at);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&payload, &mut out)
        .expect("CBOR serialization of key-vouch payload cannot fail");
    out
}

/// Sign a vouch for an encryption key with a signing key's private key. The
/// returned signature is stored in the encryption key's `key_signature`, and
/// the signing key's id in `signed_by_key_id`.
pub fn sign_key_vouch(
    enc_fingerprint: &str,
    enc_expires_at: &str,
    algorithm: crate::crypto::SigningAlgorithm,
    signing_private_key: &[u8],
) -> Result<Vec<u8>, crate::crypto::CryptoError> {
    let payload = key_vouch_payload(enc_fingerprint, enc_expires_at);
    crate::crypto::sign_with_algorithm(algorithm, &payload, signing_private_key)
}

/// Verify that `signing_key` vouches for `enc_key`: the encryption key names
/// this signing key, the signing key is itself valid (not revoked/expired),
/// and its signature covers the *recomputed* encrypt-key fingerprint + expiry.
/// The wire `fingerprint` field is never trusted — it is recomputed.
pub fn verify_key_vouch(enc_key: &DomainPublicKey, signing_key: &DomainPublicKey) -> bool {
    if enc_key.signed_by_key_id.as_deref() != Some(signing_key.key_id.as_str()) {
        return false;
    }
    if crate::crypto::signing_key_validity(
        &signing_key.expires_at,
        signing_key.revoked_at.as_deref(),
    ) != crate::crypto::KeyValidity::Valid
    {
        return false;
    }
    let sig = match &enc_key.key_signature {
        Some(s) => s,
        None => return false,
    };
    let recomputed_fp = fingerprint(&enc_key.public_key);
    let payload = key_vouch_payload(&recomputed_fp, &enc_key.expires_at);
    crate::crypto::resolve_and_verify(
        &signing_key.algorithm,
        &payload,
        sig,
        &signing_key.public_key,
    )
    .is_ok()
}

/// Establish the trusted key set from a fetched key list and the DNS-pinned
/// fingerprint set.
///
/// - **Signing keys** (`key_usage == "sign"`) are pinned directly against the
///   DNS `fp=` set (recomputed fingerprint must match).
/// - **Encryption keys** (`key_usage == "encrypt"`) are NOT in DNS; they are
///   trusted only when a DNS-pinned signing key vouches for them
///   (`verify_key_vouch`). This keeps DNS lean and lets encryption keys rotate
///   without DNS edits (re-vouch + republish in-protocol).
///
/// Anything not pinned or not vouched is dropped. An empty result means "no
/// trustworthy keys" — callers MUST fail closed.
pub fn trust_keys(keys: Vec<DomainPublicKey>, pinned: &[String]) -> Vec<DomainPublicKey> {
    let signing: Vec<DomainPublicKey> = keys
        .iter()
        .filter(|k| k.key_usage == "sign")
        .cloned()
        .collect();
    let pinned_signing = pin_keys_to_fingerprints(signing, pinned);

    let mut trusted = pinned_signing.clone();
    for k in keys.into_iter().filter(|k| k.key_usage == "encrypt") {
        if pinned_signing.iter().any(|sk| verify_key_vouch(&k, sk)) {
            trusted.push(k);
        }
    }
    trusted
}

/// Build the `_linkkeys` (trust-anchor) TXT record string from fingerprints.
pub fn build_linkkeys_txt(fingerprints: &[String]) -> String {
    let mut parts = vec!["v=lk1".to_string()];
    for fp in fingerprints {
        parts.push(format!("fp={}", fp));
    }
    parts.join(" ")
}

/// Build the `_linkkeys_apis` (service-endpoint) TXT record string. Each value
/// is published as the operator would type it (`tcp=host[:port]`,
/// `https=host[:port][/path]`); omit the TCP port to use [`DEFAULT_TCP_PORT`].
pub fn build_linkkeys_apis_txt(tcp: Option<&str>, https: Option<&str>) -> String {
    let mut parts = vec!["v=lk1".to_string()];
    if let Some(tcp) = tcp {
        parts.push(format!("tcp={}", tcp));
    }
    if let Some(https) = https {
        parts.push(format!("https={}", https));
    }
    parts.join(" ")
}

/// True if a TXT record string exceeds the single-character-string limit
/// ([`MAX_TXT_STRING_LEN`]) and would need splitting to publish reliably.
pub fn txt_exceeds_single_string(txt: &str) -> bool {
    txt.len() > MAX_TXT_STRING_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_record() {
        let txt = "v=lk1 fp=abcdef123456 fp=789012345678";
        let record = parse_linkkeys_txt(txt).unwrap();
        assert_eq!(record.fingerprints, vec!["abcdef123456", "789012345678"]);
    }

    #[test]
    fn test_parse_no_fingerprints() {
        // A bare versioned record parses to an empty fingerprint set (fail-closed
        // pinning downstream rejects it; parsing itself does not).
        let record = parse_linkkeys_txt("v=lk1").unwrap();
        assert!(record.fingerprints.is_empty());
    }

    #[test]
    fn test_parse_missing_version() {
        let txt = "fp=abc";
        assert!(matches!(
            parse_linkkeys_txt(txt),
            Err(DnsParseError::MissingVersion)
        ));
    }

    #[test]
    fn test_parse_wrong_version() {
        let txt = "v=lk99 fp=abc";
        assert!(matches!(
            parse_linkkeys_txt(txt),
            Err(DnsParseError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn test_dns_names() {
        assert_eq!(linkkeys_dns_name("example.com"), "_linkkeys.example.com");
        assert_eq!(
            linkkeys_apis_dns_name("auth.example.com"),
            "_linkkeys_apis.auth.example.com"
        );
    }

    #[test]
    fn test_build_and_parse_roundtrip() {
        let fps = vec!["abc123".to_string(), "def456".to_string()];
        let txt = build_linkkeys_txt(&fps);
        assert_eq!(parse_linkkeys_txt(&txt).unwrap().fingerprints, fps);
    }

    #[test]
    fn test_order_independence() {
        let txt = "fp=aaa v=lk1 fp=bbb fp=ccc";
        let record = parse_linkkeys_txt(txt).unwrap();
        assert_eq!(record.fingerprints, vec!["aaa", "bbb", "ccc"]);
    }

    // -- _linkkeys_apis record --

    #[test]
    fn test_parse_apis_full() {
        let txt = "v=lk1 tcp=auth.example.com:6000 https=auth.example.com/linkkeys";
        let apis = parse_linkkeys_apis_txt(txt).unwrap();
        assert_eq!(apis.tcp.as_deref(), Some("auth.example.com:6000"));
        assert_eq!(
            apis.https_base.as_deref(),
            Some("https://auth.example.com/linkkeys")
        );
    }

    #[test]
    fn test_parse_apis_defaults_tcp_port() {
        // Omitted TCP port is filled with DEFAULT_TCP_PORT; HTTPS port stays
        // implicit (443) in the URL.
        let apis =
            parse_linkkeys_apis_txt("v=lk1 tcp=idp.example.com https=idp.example.com").unwrap();
        assert_eq!(apis.tcp.as_deref(), Some("idp.example.com:4987"));
        assert_eq!(apis.https_base.as_deref(), Some("https://idp.example.com"));
    }

    #[test]
    fn test_parse_apis_tcp_only_and_https_only() {
        let tcp_only = parse_linkkeys_apis_txt("v=lk1 tcp=idp.example.com:6000").unwrap();
        assert_eq!(tcp_only.tcp.as_deref(), Some("idp.example.com:6000"));
        assert!(tcp_only.https_base.is_none());

        let https_only = parse_linkkeys_apis_txt("v=lk1 https=idp.example.com:8443/x").unwrap();
        assert!(https_only.tcp.is_none());
        assert_eq!(
            https_only.https_base.as_deref(),
            Some("https://idp.example.com:8443/x")
        );
    }

    #[test]
    fn test_parse_apis_missing_endpoint() {
        assert!(matches!(
            parse_linkkeys_apis_txt("v=lk1"),
            Err(DnsParseError::MissingApisEndpoint)
        ));
    }

    #[test]
    fn test_build_apis_roundtrip() {
        let txt = build_linkkeys_apis_txt(Some("idp.example.com"), Some("idp.example.com/api"));
        let apis = parse_linkkeys_apis_txt(&txt).unwrap();
        assert_eq!(apis.tcp.as_deref(), Some("idp.example.com:4987"));
        assert_eq!(
            apis.https_base.as_deref(),
            Some("https://idp.example.com/api")
        );
    }

    #[test]
    fn test_txt_length_guard() {
        assert!(!txt_exceeds_single_string("v=lk1 tcp=idp.example.com"));
        assert!(txt_exceeds_single_string(
            &"x".repeat(MAX_TXT_STRING_LEN + 1)
        ));
    }

    use crate::crypto::{fingerprint, generate_keypair, SigningAlgorithm, ALGORITHM_ED25519};
    use chrono::Utc;

    fn make_key(pk_bytes: &[u8]) -> DomainPublicKey {
        DomainPublicKey {
            key_id: "k".to_string(),
            public_key: pk_bytes.to_vec(),
            fingerprint: "ignored-wire-value".to_string(),
            algorithm: ALGORITHM_ED25519.to_string(),
            key_usage: "sign".to_string(),
            signed_by_key_id: None,
            key_signature: None,
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            revoked_at: None,
        }
    }

    #[test]
    fn test_is_valid_fingerprint() {
        assert!(is_valid_fingerprint(&"a".repeat(64)));
        assert!(is_valid_fingerprint(&"0123456789abcdef".repeat(4)));
        assert!(is_valid_fingerprint(&"ABCDEF0123456789".repeat(4))); // case-insensitive
        assert!(!is_valid_fingerprint("short"));
        assert!(!is_valid_fingerprint(&"a".repeat(63)));
        assert!(!is_valid_fingerprint(&"g".repeat(64))); // non-hex
    }

    #[test]
    fn test_pin_keeps_only_matching_keys() {
        let (pk_a, _) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk_b, _) = generate_keypair(SigningAlgorithm::Ed25519);
        let fp_a = fingerprint(&pk_a);

        // Only A is pinned; B must be dropped even though it's a real key.
        let pinned = vec![fp_a.clone()];
        let kept = pin_keys_to_fingerprints(vec![make_key(&pk_a), make_key(&pk_b)], &pinned);
        assert_eq!(kept.len(), 1);
        assert_eq!(fingerprint(&kept[0].public_key), fp_a);
    }

    #[test]
    fn test_pin_recomputes_ignoring_wire_fingerprint() {
        // A key whose wire `fingerprint` field claims a pinned value but whose
        // bytes hash to something else must NOT pass — we recompute.
        let (pk_a, _) = generate_keypair(SigningAlgorithm::Ed25519);
        let (pk_evil, _) = generate_keypair(SigningAlgorithm::Ed25519);
        let mut evil = make_key(&pk_evil);
        evil.fingerprint = fingerprint(&pk_a); // lie about identity
        let kept = pin_keys_to_fingerprints(vec![evil], &[fingerprint(&pk_a)]);
        assert!(kept.is_empty());
    }

    #[test]
    fn test_pin_empty_when_no_fingerprints() {
        let (pk_a, _) = generate_keypair(SigningAlgorithm::Ed25519);
        assert!(pin_keys_to_fingerprints(vec![make_key(&pk_a)], &[]).is_empty());
        // Invalid pins are ignored, so still empty.
        assert!(
            pin_keys_to_fingerprints(vec![make_key(&pk_a)], &["nothex".to_string()]).is_empty()
        );
    }

    #[test]
    fn test_trust_keys_pins_sign_and_vouches_encrypt() {
        // A signing key pinned in DNS; an encryption key vouched by that signing key.
        let (sign_pk, sign_sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let sign_fp = fingerprint(&sign_pk);
        let mut sign_key = make_key(&sign_pk);
        sign_key.key_id = "sign-1".to_string();

        let (enc_pk, _) = generate_keypair(SigningAlgorithm::Ed25519);
        let enc_fp = fingerprint(&enc_pk);
        let enc_expires = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let vouch =
            sign_key_vouch(&enc_fp, &enc_expires, SigningAlgorithm::Ed25519, &sign_sk).unwrap();
        let mut enc_key = make_key(&enc_pk);
        enc_key.key_id = "enc-1".to_string();
        enc_key.key_usage = "encrypt".to_string();
        enc_key.expires_at = enc_expires;
        enc_key.signed_by_key_id = Some("sign-1".to_string());
        enc_key.key_signature = Some(vouch);

        // DNS pins ONLY the signing key fingerprint; encrypt key is vouched.
        let trusted = trust_keys(
            vec![sign_key.clone(), enc_key.clone()],
            std::slice::from_ref(&sign_fp),
        );
        assert_eq!(trusted.len(), 2, "sign pinned + encrypt vouched");

        // Tampered vouch -> encrypt dropped, sign kept.
        let mut bad = enc_key.clone();
        if let Some(s) = bad.key_signature.as_mut() {
            if let Some(b) = s.first_mut() {
                *b ^= 0xff;
            }
        }
        assert_eq!(trust_keys(vec![sign_key.clone(), bad], &[sign_fp]).len(), 1);

        // Encrypt key whose signing key isn't pinned -> dropped (fail closed).
        assert!(trust_keys(vec![enc_key], &[]).is_empty());
    }
}
