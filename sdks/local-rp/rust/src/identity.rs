//! `generate_local_rp_identity` and the raw-byte storage helpers (design doc:
//! "SDK API Shape", "Byte Storage Helpers").
//!
//! A local RP identity is exactly one Ed25519 signing keypair, one X25519
//! encryption keypair, and a self-signed [`SignedLocalRpDescriptor`] binding
//! them together (`liblinkkeys::local_rp`). There is no continuity story
//! across rotation — generating a new identity means a new fingerprint, full
//! stop.
//!
//! Security note (design doc, "Byte Storage Helpers"): the private key
//! fields in [`LocalRpKeyMaterial`] do not directly identify a user, but they
//! control this app's entire local RP identity — anyone holding them can
//! sign login requests and redeem claim tickets as this app. Store them with
//! ordinary application-secret care (the same care as a database credential
//! or API key), not merely as configuration.

use crate::Error;
use chrono::{DateTime, Duration, Utc};
use liblinkkeys::crypto::{self, AeadSuite};
use liblinkkeys::generated::types::SignedLocalRpDescriptor;
use liblinkkeys::local_rp;

/// Default local RP key lifetime: 10 years (design doc, "One Signing Key and
/// One Encryption Key" — "Default lifetime: 10 years. Rotation is a
/// deliberate operator event.").
pub const DEFAULT_LIFETIME: Duration = Duration::days(3650);

/// Input to [`generate_local_rp_identity`]. Big-config, single struct, per the
/// design doc's "SDK API Shape" ("Every SDK should have big-config,
/// single-function APIs first").
#[derive(Debug, Clone)]
pub struct GenerateLocalRpIdentityConfig {
    /// Display name shown on the IDP's consent screen. **Not identity** — the
    /// design doc is explicit that approval keys on the fingerprint alone;
    /// this is audit/display metadata only.
    pub app_name: String,
    /// Optional local domain/origin hint (e.g. `jukebox.lan`), also
    /// display/audit metadata, never an identity input.
    pub local_domain_hint: Option<String>,
    /// AEAD suites this app can decrypt callbacks with, in preference order.
    /// Defaults to both registry suites (`aes-256-gcm` first, mandatory
    /// baseline; `chacha20-poly1305` second, optional) when `None`.
    pub supported_suites: Option<Vec<String>>,
    /// Key/descriptor lifetime from `now`. Defaults to [`DEFAULT_LIFETIME`]
    /// (10 years) when `None`.
    pub lifetime: Option<Duration>,
    /// The current time — never read from the system clock inside this
    /// crate, so callers control determinism (and so this crate could in
    /// principle run on WASM, mirroring `liblinkkeys`'s own no-`Utc::now()`
    /// discipline, even though this SDK crate itself does its own I/O).
    pub now: DateTime<Utc>,
}

impl GenerateLocalRpIdentityConfig {
    /// Convenience constructor for the common case (both suites, default
    /// 10-year lifetime).
    pub fn new(app_name: impl Into<String>, now: DateTime<Utc>) -> Self {
        Self {
            app_name: app_name.into(),
            local_domain_hint: None,
            supported_suites: None,
            lifetime: None,
            now,
        }
    }
}

/// A local RP's full key material: signing keypair, encryption keypair, the
/// self-signed descriptor binding them (which also carries `app_name`,
/// `local_domain_hint`, `supported_suites`, and the created/expires
/// timestamps), and the identity fingerprint.
///
/// Private key fields are raw 32-byte arrays — see the module docs' security
/// note before persisting them.
#[derive(Debug, Clone)]
pub struct LocalRpKeyMaterial {
    pub signing_private_key: [u8; 32],
    pub signing_public_key: [u8; 32],
    pub encryption_private_key: [u8; 32],
    pub encryption_public_key: [u8; 32],
    /// The self-signed envelope (`liblinkkeys::local_rp::sign_local_rp_descriptor`)
    /// — reused as-is in every `begin_local_login` call rather than re-signed
    /// per login, so the identity's descriptor stays a single stable object
    /// for the key's whole lifetime (consistent with "Rotation creates a new
    /// identity" — there is deliberately no per-login descriptor churn).
    pub descriptor: SignedLocalRpDescriptor,
    /// `sha256(signing_public_key)` hex — the canonical identity anchor
    /// (design doc: "local_rp_id = fingerprint(local_rp_signing_public_key)").
    pub fingerprint: String,
}

/// `generate_local_rp_identity(config) -> LocalRpKeyMaterial` (design doc,
/// "SDK API Shape"). Generates a fresh Ed25519 signing keypair and a
/// *separate* X25519 encryption keypair (never algebraically derived — see
/// the design doc's "Encryption Key Is Separate, Not Derived"), builds and
/// self-signs the [`SignedLocalRpDescriptor`] binding them, and returns
/// everything the app needs to persist.
pub fn generate_local_rp_identity(
    config: GenerateLocalRpIdentityConfig,
) -> Result<LocalRpKeyMaterial, Error> {
    if config.app_name.trim().is_empty() {
        return Err(Error::InvalidInput(
            "app_name must not be empty".to_string(),
        ));
    }

    let (signing_verifying_key, signing_key) = crypto::generate_ed25519_keypair();
    let signing_public_key = *signing_verifying_key.as_bytes();
    let signing_private_key = signing_key.to_bytes();

    let (enc_pub_vec, enc_priv_vec) = crypto::generate_x25519_keypair();
    let encryption_public_key: [u8; 32] = enc_pub_vec.try_into().map_err(|_| {
        Error::InvalidInput("generated encryption public key was not 32 bytes".to_string())
    })?;
    let encryption_private_key: [u8; 32] = enc_priv_vec.try_into().map_err(|_| {
        Error::InvalidInput("generated encryption private key was not 32 bytes".to_string())
    })?;

    let suites = config.supported_suites.unwrap_or_else(|| {
        AeadSuite::all_supported()
            .iter()
            .map(|s| s.to_string())
            .collect()
    });
    if suites.is_empty() {
        return Err(Error::InvalidInput(
            "supported_suites must not be empty".to_string(),
        ));
    }

    let lifetime = config.lifetime.unwrap_or(DEFAULT_LIFETIME);
    let created_at = config.now.to_rfc3339();
    let expires_at = (config.now + lifetime).to_rfc3339();

    let descriptor = local_rp::build_local_rp_descriptor(
        &config.app_name,
        config.local_domain_hint.as_deref(),
        &signing_public_key,
        &encryption_public_key,
        suites,
        &created_at,
        &expires_at,
    );
    let fingerprint = descriptor.fingerprint.clone();
    let signed_descriptor = local_rp::sign_local_rp_descriptor(&descriptor, &signing_private_key)
        .map_err(Error::from)?;

    Ok(LocalRpKeyMaterial {
        signing_private_key,
        signing_public_key,
        encryption_private_key,
        encryption_public_key,
        descriptor: signed_descriptor,
        fingerprint,
    })
}

// ---------------------------------------------------------------------
// Byte storage helpers (design doc: "Byte Storage Helpers")
// ---------------------------------------------------------------------

/// Raw 32-byte signing key (public or private) -> bytes. Trivial, but
/// provided so callers never invent their own encoding.
pub fn signing_key_to_bytes(key: &[u8; 32]) -> Vec<u8> {
    key.to_vec()
}

/// Bytes -> raw 32-byte signing key. Errors if the input is not exactly 32
/// bytes.
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| {
        Error::InvalidInput(format!("signing key must be 32 bytes, got {}", bytes.len()))
    })
}

/// Raw 32-byte encryption key (public or private) -> bytes.
pub fn encryption_key_to_bytes(key: &[u8; 32]) -> Vec<u8> {
    key.to_vec()
}

/// Bytes -> raw 32-byte encryption key. Errors if the input is not exactly 32
/// bytes.
pub fn encryption_key_from_bytes(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|_| {
        Error::InvalidInput(format!(
            "encryption key must be 32 bytes, got {}",
            bytes.len()
        ))
    })
}

/// The canonical fingerprint string form — a pass-through, since in this SDK
/// the fingerprint IS a hex `String` (design doc: "fingerprint: hex string
/// ... the existing LinkKeys fingerprint format, everywhere, with no bytes
/// variant" — so there is no separate `Fingerprint` type to convert from).
pub fn fingerprint_to_string(fingerprint: &str) -> String {
    fingerprint.to_string()
}

/// Parse/validate a fingerprint string: exactly 64 lowercase-normalized hex
/// characters (a SHA-256 digest), per
/// `liblinkkeys::dns::is_valid_fingerprint`. Rejects anything else so a
/// malformed value can never silently pass as a pin or an identity.
pub fn fingerprint_from_string(s: &str) -> Result<String, Error> {
    if liblinkkeys::dns::is_valid_fingerprint(s) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(Error::InvalidInput(format!(
            "not a valid fingerprint (want 64 hex chars): {s:?}"
        )))
    }
}

/// Magic prefix for the identity-bundle byte format below. This is an
/// SDK-local storage convenience, NOT a protocol wire format — nothing in
/// `dns-less-local-rp-design.md`'s Wire Precision governs it, and no
/// conformance vector covers it. Versioned so a future incompatible layout
/// change fails loudly (`InvalidInput`) instead of silently misparsing.
const IDENTITY_BUNDLE_MAGIC: &[u8; 4] = b"LKI1";

/// `local_rp_identity_to_bytes(identity) -> bytes` (design doc, "SDK API
/// Shape" + "Byte Storage Helpers": "identity bundle"). Packs both private
/// keys and the signed descriptor (which already carries both public keys,
/// `app_name`, `local_domain_hint`, `supported_suites`, and the
/// created/expires timestamps) into one opaque blob an app can store as a
/// single secret/config value. Layout: `MAGIC(4) || signing_private_key(32)
/// || encryption_private_key(32) || descriptor_len(4, BE) || descriptor_cbor`.
pub fn local_rp_identity_to_bytes(identity: &LocalRpKeyMaterial) -> Vec<u8> {
    let descriptor_bytes =
        liblinkkeys::generated::encode_signed_local_rp_descriptor(&identity.descriptor);
    let mut out = Vec::with_capacity(4 + 32 + 32 + 4 + descriptor_bytes.len());
    out.extend_from_slice(IDENTITY_BUNDLE_MAGIC);
    out.extend_from_slice(&identity.signing_private_key);
    out.extend_from_slice(&identity.encryption_private_key);
    out.extend_from_slice(&(descriptor_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&descriptor_bytes);
    out
}

/// `local_rp_identity_from_bytes(bytes) -> LocalRpIdentity` — the inverse of
/// [`local_rp_identity_to_bytes`]. Public keys and the fingerprint are read
/// back out of the embedded descriptor rather than re-derived from the
/// private keys, exactly mirroring what was stored; this function does no
/// signature/expiry verification (that is [`crate::check_expirations`]'s and
/// the protocol verification chain's job, both of which need an explicit
/// `now` that this byte-decoding step deliberately does not take, per the
/// design doc's literal `local_rp_identity_from_bytes(bytes) -> LocalRpIdentity`
/// signature).
pub fn local_rp_identity_from_bytes(bytes: &[u8]) -> Result<LocalRpKeyMaterial, Error> {
    const HEADER_LEN: usize = 4 + 32 + 32 + 4;
    if bytes.len() < HEADER_LEN {
        return Err(Error::InvalidInput("identity bundle too short".to_string()));
    }
    if &bytes[0..4] != IDENTITY_BUNDLE_MAGIC {
        return Err(Error::InvalidInput(
            "identity bundle has an unrecognized magic prefix".to_string(),
        ));
    }
    let signing_private_key: [u8; 32] = bytes[4..36].try_into().expect("slice is exactly 32 bytes");
    let encryption_private_key: [u8; 32] =
        bytes[36..68].try_into().expect("slice is exactly 32 bytes");
    let descriptor_len =
        u32::from_be_bytes(bytes[68..72].try_into().expect("slice is exactly 4 bytes")) as usize;
    let descriptor_bytes = bytes
        .get(HEADER_LEN..HEADER_LEN + descriptor_len)
        .ok_or_else(|| {
            Error::InvalidInput(
                "identity bundle descriptor length exceeds available bytes".to_string(),
            )
        })?;

    let signed_descriptor =
        liblinkkeys::generated::decode_signed_local_rp_descriptor(descriptor_bytes)
            .map_err(|e| Error::Decode(format!("identity bundle descriptor: {e}")))?;
    let descriptor =
        liblinkkeys::generated::decode_local_rp_descriptor(&signed_descriptor.descriptor)
            .map_err(|e| Error::Decode(format!("identity bundle descriptor payload: {e}")))?;

    let signing_public_key: [u8; 32] = descriptor
        .signing_public_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            Error::InvalidInput("descriptor signing_public_key was not 32 bytes".to_string())
        })?;
    let encryption_public_key: [u8; 32] = descriptor
        .encryption_public_key
        .as_slice()
        .try_into()
        .map_err(|_| {
            Error::InvalidInput("descriptor encryption_public_key was not 32 bytes".to_string())
        })?;

    Ok(LocalRpKeyMaterial {
        signing_private_key,
        signing_public_key,
        encryption_private_key,
        encryption_public_key,
        descriptor: signed_descriptor,
        fingerprint: descriptor.fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn generate_identity_defaults_both_suites_and_ten_year_lifetime() {
        let material =
            generate_local_rp_identity(GenerateLocalRpIdentityConfig::new("Test App", now()))
                .unwrap();
        assert_eq!(material.fingerprint.len(), 64);
        assert_eq!(
            material.fingerprint,
            crypto::fingerprint(&material.signing_public_key)
        );

        let descriptor =
            liblinkkeys::generated::decode_local_rp_descriptor(&material.descriptor.descriptor)
                .unwrap();
        assert_eq!(descriptor.app_name, "Test App");
        let expected_suites: Vec<String> = AeadSuite::all_supported()
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(descriptor.supported_suites, expected_suites);
    }

    #[test]
    fn generate_identity_rejects_empty_app_name() {
        assert!(matches!(
            generate_local_rp_identity(GenerateLocalRpIdentityConfig::new("", now())),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn generate_identity_rejects_empty_suite_list() {
        let mut config = GenerateLocalRpIdentityConfig::new("Test App", now());
        config.supported_suites = Some(vec![]);
        assert!(matches!(
            generate_local_rp_identity(config),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn signing_and_encryption_key_byte_round_trips() {
        let key = [7u8; 32];
        assert_eq!(
            signing_key_from_bytes(&signing_key_to_bytes(&key)).unwrap(),
            key
        );
        assert_eq!(
            encryption_key_from_bytes(&encryption_key_to_bytes(&key)).unwrap(),
            key
        );
        assert!(signing_key_from_bytes(&[0u8; 31]).is_err());
        assert!(encryption_key_from_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn fingerprint_string_round_trip_validates_hex() {
        let material =
            generate_local_rp_identity(GenerateLocalRpIdentityConfig::new("Test App", now()))
                .unwrap();
        let s = fingerprint_to_string(&material.fingerprint);
        assert_eq!(fingerprint_from_string(&s).unwrap(), material.fingerprint);
        assert!(fingerprint_from_string("not-hex").is_err());
        assert!(fingerprint_from_string(&"a".repeat(63)).is_err());
    }

    #[test]
    fn identity_bundle_byte_round_trip() {
        let material =
            generate_local_rp_identity(GenerateLocalRpIdentityConfig::new("Test App", now()))
                .unwrap();
        let bytes = local_rp_identity_to_bytes(&material);
        let round_tripped = local_rp_identity_from_bytes(&bytes).unwrap();
        assert_eq!(
            round_tripped.signing_private_key,
            material.signing_private_key
        );
        assert_eq!(
            round_tripped.signing_public_key,
            material.signing_public_key
        );
        assert_eq!(
            round_tripped.encryption_private_key,
            material.encryption_private_key
        );
        assert_eq!(
            round_tripped.encryption_public_key,
            material.encryption_public_key
        );
        assert_eq!(round_tripped.fingerprint, material.fingerprint);
        assert_eq!(
            round_tripped.descriptor.descriptor,
            material.descriptor.descriptor
        );
        assert_eq!(
            round_tripped.descriptor.signature,
            material.descriptor.signature
        );
    }

    #[test]
    fn identity_bundle_rejects_bad_magic_and_truncation() {
        let material =
            generate_local_rp_identity(GenerateLocalRpIdentityConfig::new("Test App", now()))
                .unwrap();
        let mut bytes = local_rp_identity_to_bytes(&material);
        bytes[0] ^= 0xff;
        assert!(local_rp_identity_from_bytes(&bytes).is_err());

        let short = local_rp_identity_to_bytes(&material);
        assert!(local_rp_identity_from_bytes(&short[..10]).is_err());
    }
}
