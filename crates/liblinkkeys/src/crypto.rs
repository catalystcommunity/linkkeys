use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce as AesGcmNonce,
};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub const ALGORITHM_ED25519: &str = "ed25519";

/// Supported signing algorithms. New algorithms are added as enum variants.
/// The protocol negotiates which algorithms both sides support before
/// exchanging signed data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    Ed25519,
}

impl SigningAlgorithm {
    /// Parse a wire-format algorithm string (e.g. "ed25519") into the
    /// enum. Returns None for unsupported algorithms. Named `parse_str`
    /// rather than `from_str` to avoid confusion with `std::str::FromStr`,
    /// whose contract differs (returns `Result`, takes ownership of the
    /// error type).
    pub fn parse_str(s: &str) -> Option<SigningAlgorithm> {
        match s {
            "ed25519" => Some(SigningAlgorithm::Ed25519),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SigningAlgorithm::Ed25519 => "ed25519",
        }
    }

    pub fn all_supported() -> &'static [&'static str] {
        &["ed25519"]
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub const AEAD_SUITE_AES_256_GCM: &str = "aes-256-gcm";
pub const AEAD_SUITE_CHACHA20_POLY1305: &str = "chacha20-poly1305";

/// Registry of negotiated AEAD suites for encrypted-payload constructions:
/// the local-RP callback sealed box (`local_rp::seal_local_rp_callback` /
/// `open_local_rp_callback`) and, after the S2S retrofit, the
/// `AlgorithmSupport.encryption` list exchanged via the `Handshake` service.
/// One registry, two advertisement surfaces (see dns-less-local-rp-design.md,
/// "Wire Precision: AEAD suite registry"). `aes-256-gcm` is
/// mandatory-to-implement; `chacha20-poly1305` is optional. Same
/// parse_str/as_str/all_supported shape as [`SigningAlgorithm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadSuite {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadSuite {
    /// Parse a wire-format suite id string. Returns None for an id outside
    /// the registry — never "close enough".
    pub fn parse_str(s: &str) -> Option<AeadSuite> {
        match s {
            AEAD_SUITE_AES_256_GCM => Some(AeadSuite::Aes256Gcm),
            AEAD_SUITE_CHACHA20_POLY1305 => Some(AeadSuite::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AeadSuite::Aes256Gcm => AEAD_SUITE_AES_256_GCM,
            AeadSuite::ChaCha20Poly1305 => AEAD_SUITE_CHACHA20_POLY1305,
        }
    }

    pub fn all_supported() -> &'static [&'static str] {
        &[AEAD_SUITE_AES_256_GCM, AEAD_SUITE_CHACHA20_POLY1305]
    }

    /// Pick the first suite in `advertised` (preference order) that this
    /// implementation supports. Used by the side that chooses among an
    /// advertised list (the IDP picking from a local RP descriptor's
    /// `supported_suites`, or a `Handshake` responder) so a suite outside the
    /// advertised list can never be selected.
    pub fn select_supported(advertised: &[String]) -> Option<AeadSuite> {
        advertised.iter().find_map(|s| AeadSuite::parse_str(s))
    }
}

impl fmt::Display for AeadSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub enum CryptoError {
    SigningFailed(String),
    VerificationFailed,
    UnsupportedAlgorithm(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    InvalidKeyLength,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::SigningFailed(msg) => write!(f, "signing failed: {}", msg),
            CryptoError::VerificationFailed => write!(f, "signature verification failed"),
            CryptoError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported algorithm: {}", alg)
            }
            CryptoError::EncryptionFailed(msg) => write!(f, "encryption failed: {}", msg),
            CryptoError::DecryptionFailed(msg) => write!(f, "decryption failed: {}", msg),
            CryptoError::InvalidKeyLength => write!(f, "invalid key length"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub fn generate_ed25519_keypair() -> (VerifyingKey, SigningKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (verifying_key, signing_key)
}

pub fn sign(message: &[u8], secret_key: &SigningKey) -> Vec<u8> {
    let signature = secret_key.sign(message);
    signature.to_bytes().to_vec()
}

pub fn verify(
    message: &[u8],
    signature_bytes: &[u8],
    public_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| CryptoError::VerificationFailed)?;
    // verify_strict rejects non-canonical signatures and small-order public
    // keys, closing the Ed25519 malleability / weak-key surface (crypto-07).
    public_key
        .verify_strict(message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Sign a message using the specified algorithm. Currently only Ed25519.
/// New algorithms are added as match arms here.
pub fn sign_with_algorithm(
    algorithm: SigningAlgorithm,
    message: &[u8],
    private_key_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        SigningAlgorithm::Ed25519 => {
            let sk = SigningKey::from_bytes(
                private_key_bytes
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyLength)?,
            );
            Ok(sign(message, &sk))
        }
    }
}

/// Verify a signature using the specified algorithm. Currently only Ed25519.
/// New algorithms are added as match arms here.
pub fn verify_with_algorithm(
    algorithm: SigningAlgorithm,
    message: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<(), CryptoError> {
    match algorithm {
        SigningAlgorithm::Ed25519 => {
            let vk = VerifyingKey::from_bytes(
                public_key_bytes
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKeyLength)?,
            )
            .map_err(|_| CryptoError::VerificationFailed)?;
            verify(message, signature_bytes, &vk)
        }
    }
}

/// Generate a keypair for the specified algorithm. Returns (public_key_bytes, private_key_bytes).
pub fn generate_keypair(algorithm: SigningAlgorithm) -> (Vec<u8>, Vec<u8>) {
    match algorithm {
        SigningAlgorithm::Ed25519 => {
            let (vk, sk) = generate_ed25519_keypair();
            (vk.as_bytes().to_vec(), sk.to_bytes().to_vec())
        }
    }
}

/// Generate a fresh X25519 encryption keypair. Returns (public_key_bytes,
/// private_key_bytes), both 32 bytes. Used for sealed-box recipient keys — a
/// dedicated encryption key, NOT derived from an Ed25519 signing key.
pub fn generate_x25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let secret = X25519StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (public.as_bytes().to_vec(), secret.to_bytes().to_vec())
}

/// Resolve an algorithm string and public key bytes into a verified signature check.
/// This is the entry point for assertions and claims verification — it validates
/// the algorithm is supported before attempting verification.
pub fn resolve_and_verify(
    algorithm: &str,
    message: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<(), CryptoError> {
    let alg = SigningAlgorithm::parse_str(algorithm)
        .ok_or_else(|| CryptoError::UnsupportedAlgorithm(algorithm.to_string()))?;
    verify_with_algorithm(alg, message, signature_bytes, public_key_bytes)
}

/// Validity of a signing key at the current instant, independent of any
/// signature it produced. Every verify path (assertions, auth requests, claims)
/// must consult this so a revoked or expired key cannot validate anything.
///
/// Per the trust model: a revoked key is rejected outright for live
/// verification — issued_at-based leniency is unsafe here because the key
/// holder controls issued_at — and `expires_at` is the automatic backstop that
/// bounds trust when no signed revocation is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyValidity {
    Valid,
    Revoked,
    Expired,
    BadExpiry,
}

pub fn signing_key_validity(expires_at: &str, revoked_at: Option<&str>) -> KeyValidity {
    if revoked_at.is_some() {
        return KeyValidity::Revoked;
    }
    match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(exp) => {
            if chrono::Utc::now() > exp {
                KeyValidity::Expired
            } else {
                KeyValidity::Valid
            }
        }
        Err(_) => KeyValidity::BadExpiry,
    }
}

pub fn fingerprint(public_key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let result = hasher.finalize();
    result.iter().fold(String::with_capacity(64), |mut s, b| {
        use fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    })
}

/// Magic prefix identifying the versioned (v2) encrypted-private-key format,
/// which embeds the Argon2id parameters so they can be tuned later without
/// making already-stored blobs undecryptable. A blob NOT starting with this is
/// treated as the legacy (headerless) format. The 4th byte is the version.
const KEYENC_MAGIC_V2: [u8; 4] = *b"LK2\x01";

/// Default Argon2id parameters for newly-encrypted keys (m=19 MiB is an
/// OWASP-recommended config; t raised to 3 for additional margin). Embedded in
/// each v2 blob, so future raises don't break old blobs (crypto-11).
const ARGON2_M_COST: u32 = 19456;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// Parameters used by legacy (pre-v2, headerless) blobs. Must not change.
const LEGACY_ARGON2_M_COST: u32 = 19456;
const LEGACY_ARGON2_T_COST: u32 = 2;
const LEGACY_ARGON2_P_COST: u32 = 1;

fn derive_key_argon2id(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    Ok(key)
}

/// Encrypt a private key using AES-256-GCM with Argon2id key derivation.
///
/// Output (v2): `magic(4) || m_cost(4 BE) || t_cost(4 BE) || p_cost(4 BE) ||
/// salt(16) || nonce(12) || ciphertext`. The Argon2 parameters are embedded so
/// they can be strengthened over time while old blobs remain decryptable.
pub fn encrypt_private_key(key_bytes: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let salt: [u8; 16] = rand::random();
    let derived_key = derive_key_argon2id(
        passphrase,
        &salt,
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
    )?;
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = AesGcmNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, key_bytes)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(4 + 12 + 16 + 12 + ciphertext.len());
    result.extend_from_slice(&KEYENC_MAGIC_V2);
    result.extend_from_slice(&ARGON2_M_COST.to_be_bytes());
    result.extend_from_slice(&ARGON2_T_COST.to_be_bytes());
    result.extend_from_slice(&ARGON2_P_COST.to_be_bytes());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a private key encrypted with `encrypt_private_key`.
///
/// Detects the v2 (magic-prefixed, params-embedded) format and falls back to
/// the legacy headerless format (`salt(16) || nonce(12) || ciphertext`, fixed
/// legacy params) so keys stored before the format change still decrypt.
pub fn decrypt_private_key(encrypted: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() >= 4 && encrypted[..4] == KEYENC_MAGIC_V2 {
        // v2: magic(4) || m(4) || t(4) || p(4) || salt(16) || nonce(12) || ct
        if encrypted.len() < 4 + 12 + 16 + 12 {
            return Err(CryptoError::DecryptionFailed(
                "ciphertext too short".to_string(),
            ));
        }
        let m = u32::from_be_bytes(encrypted[4..8].try_into().unwrap());
        let t = u32::from_be_bytes(encrypted[8..12].try_into().unwrap());
        let p = u32::from_be_bytes(encrypted[12..16].try_into().unwrap());
        let salt = &encrypted[16..32];
        let nonce_bytes = &encrypted[32..44];
        let ciphertext = &encrypted[44..];
        let derived_key = derive_key_argon2id(passphrase, salt, m, t, p)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        return cipher
            .decrypt(AesGcmNonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()));
    }

    // Legacy headerless format.
    if encrypted.len() < 28 {
        return Err(CryptoError::DecryptionFailed(
            "ciphertext too short".to_string(),
        ));
    }
    let (salt, rest) = encrypted.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    let derived_key = derive_key_argon2id(
        passphrase,
        salt,
        LEGACY_ARGON2_M_COST,
        LEGACY_ARGON2_T_COST,
        LEGACY_ARGON2_P_COST,
    )
    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let nonce = AesGcmNonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Magic header for backup bundles encrypted with a full-entropy 256-bit key.
const BACKUP_MAGIC_V1: [u8; 4] = *b"LKB1";

/// Encrypt arbitrary bytes under a full-entropy 256-bit key using AES-256-GCM.
///
/// Unlike [`encrypt_private_key`], this takes the AES key directly — no Argon2id
/// key-derivation — because the key is already 256 bits of randomness (e.g. a
/// per-domain backup key). This is the right primitive when the secret is a
/// generated key stored separately, not a human passphrase.
///
/// Output (v1): `magic(4) || nonce(12) || ciphertext`.
pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let nonce_bytes: [u8; 12] = rand::random();
    let ciphertext = cipher
        .encrypt(AesGcmNonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(4 + 12 + ciphertext.len());
    result.extend_from_slice(&BACKUP_MAGIC_V1);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt bytes produced by [`encrypt_with_key`]. Fails (AEAD auth error) on a
/// wrong key or any tampering.
pub fn decrypt_with_key(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() < 4 + 12 || encrypted[..4] != BACKUP_MAGIC_V1 {
        return Err(CryptoError::DecryptionFailed(
            "not a recognized backup bundle (bad magic or too short)".to_string(),
        ));
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let nonce_bytes = &encrypted[4..16];
    let ciphertext = &encrypted[16..];
    cipher
        .decrypt(AesGcmNonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

// NOTE: Ed25519→X25519 conversion helpers were removed (crypto-03). Signing and
// encryption keys are now separate: encryption keys are generated independently
// via `generate_x25519_keypair`, never derived from a signing key.

/// Domain-separation tag / version for the sealed-box construction. Bumped to
/// v2 when the KDF moved from a bare SHA-256 hash to HKDF-SHA256 with the
/// context bound as AES-GCM associated data. Sealed boxes are ephemeral
/// (single-use auth-token transport), so there is no stored ciphertext to stay
/// backward-compatible with; both peers run the same construction.
const SEALED_BOX_TAG: &[u8] = b"linkkeys-sealed-box-v2";

/// Derive the AEAD key for a sealed box via HKDF-SHA256, and return the
/// context bytes that double as AEAD associated data (AAD). The context binds
/// the protocol tag, the negotiated suite id, and both X25519 public keys, so
/// a ciphertext is cryptographically tied to this exact exchange AND cannot be
/// replayed/reinterpreted under a different suite (suite-id-swap is a
/// tampering attempt like any other field here).
///
/// Layout: `tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)`
/// — same pattern as `local_rp::local_rp_callback_kdf`, with the suite id
/// inserted after the tag (Wire Precision, "Callback sealed box").
fn sealed_box_kdf(
    suite: AeadSuite,
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
    shared_secret: &[u8],
) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    let suite_id = suite.as_str().as_bytes();
    let mut context = Vec::with_capacity(SEALED_BOX_TAG.len() + suite_id.len() + 64);
    context.extend_from_slice(SEALED_BOX_TAG);
    context.extend_from_slice(suite_id);
    context.extend_from_slice(ephemeral_public);
    context.extend_from_slice(recipient_public);

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(&context, &mut key)
        .map_err(|_| CryptoError::EncryptionFailed("HKDF expand failed".to_string()))?;
    Ok((key, context))
}

/// Encrypt `plaintext` under `suite`, dispatching to the concrete AEAD
/// implementation. Shared by [`sealed_box_encrypt`] and the local-RP callback
/// box (`crate::local_rp::seal_local_rp_callback`) — one dispatch point for
/// every negotiated-suite AEAD use in this crate, so a new suite is added in
/// exactly one place.
pub(crate) fn aead_encrypt(
    suite: AeadSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match suite {
        AeadSuite::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            cipher
                .encrypt(
                    AesGcmNonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
        }
        AeadSuite::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            cipher
                .encrypt(
                    ChaChaNonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
        }
    }
}

/// Decrypt `ciphertext` under `suite`. See [`aead_encrypt`].
pub(crate) fn aead_decrypt(
    suite: AeadSuite,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match suite {
        AeadSuite::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            cipher
                .decrypt(
                    AesGcmNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
        }
        AeadSuite::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            cipher
                .decrypt(
                    ChaChaNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
        }
    }
}

/// Resolve a wire-format optional suite id (e.g. `EncryptedToken.suite`) into
/// a concrete [`AeadSuite`], defaulting to the mandatory-to-implement baseline
/// when absent (`aes-256-gcm` — see Wire Precision, "AEAD suite registry": the
/// hard-cutover retrofit makes every existing encrypted-payload use
/// "negotiated, with aes-256-gcm as the baseline"). Returns
/// [`CryptoError::UnsupportedAlgorithm`] for a present-but-unrecognized id —
/// this never silently falls back to the baseline for a wire value the
/// producer actually claimed.
pub fn resolve_aead_suite(wire_suite: Option<&str>) -> Result<AeadSuite, CryptoError> {
    match wire_suite {
        None => Ok(AeadSuite::Aes256Gcm),
        Some(s) => {
            AeadSuite::parse_str(s).ok_or_else(|| CryptoError::UnsupportedAlgorithm(s.to_string()))
        }
    }
}

/// Reject a non-contributory / low-order ECDH result (an all-zero shared
/// secret), which a malicious peer can force by supplying a low-order point.
///
/// `pub(crate)` so other sealed-box-style constructions in this crate (e.g.
/// `local_rp`'s callback box) can reuse the same check rather than
/// reimplementing it.
pub(crate) fn reject_low_order(shared_secret: &[u8; 32]) -> Result<(), CryptoError> {
    if shared_secret == &[0u8; 32] {
        return Err(CryptoError::EncryptionFailed(
            "non-contributory (low-order) public key rejected".to_string(),
        ));
    }
    Ok(())
}

/// Sealed-box encrypt a message to a recipient's X25519 public key, under the
/// negotiated `suite` (`aes-256-gcm` is the mandatory-to-implement baseline;
/// `chacha20-poly1305` is optional).
///
/// 1. Generate an ephemeral X25519 keypair
/// 2. ECDH key agreement (rejecting low-order / non-contributory results)
/// 3. Derive an AEAD key via HKDF-SHA256 over the shared secret, bound to the
///    protocol tag + suite id + both public keys
/// 4. Encrypt with the negotiated suite (random 12-byte nonce, context bound
///    as AAD, so a suite-id swap is detected like any other tampering)
///
/// Returns the parts needed to construct an `EncryptedToken`.
pub fn sealed_box_encrypt(
    plaintext: &[u8],
    recipient_x25519_public: &[u8; 32],
    suite: AeadSuite,
) -> Result<SealedBox, CryptoError> {
    let recipient_pk = X25519PublicKey::from(*recipient_x25519_public);

    // Generate ephemeral X25519 keypair
    let ephemeral_secret = X25519StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // ECDH key agreement
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);
    reject_low_order(shared_secret.as_bytes())?;

    let (aead_key, aad) = sealed_box_kdf(
        suite,
        ephemeral_public.as_bytes(),
        recipient_x25519_public,
        shared_secret.as_bytes(),
    )?;

    let nonce_bytes: [u8; 12] = rand::random();
    let ciphertext = aead_encrypt(suite, &aead_key, &nonce_bytes, &aad, plaintext)?;

    Ok(SealedBox {
        ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Output of `sealed_box_encrypt`: the three byte vectors needed to
/// construct an `EncryptedToken` for the wire.
#[derive(Debug, Clone)]
pub struct SealedBox {
    pub ephemeral_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Sealed-box decrypt using the recipient's X25519 private key. `suite` must
/// be the same suite the encrypting side selected (callers typically resolve
/// it from the wire via [`resolve_aead_suite`]); a mismatched suite fails the
/// HKDF/AAD binding rather than merely picking the wrong cipher, since the
/// suite id is baked into the KDF context.
///
/// 1. ECDH with the ephemeral public key and recipient's private key
///    (rejecting low-order / non-contributory results)
/// 2. Derive the AEAD key via HKDF-SHA256, bound to tag + suite id + both
///    public keys
/// 3. Decrypt with the negotiated suite, verifying the same context as AAD
pub fn sealed_box_decrypt(
    ephemeral_public_key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    recipient_x25519_private: &[u8; 32],
    suite: AeadSuite,
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral_pk_bytes: [u8; 32] = ephemeral_public_key
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("invalid ephemeral key length".to_string()))?;
    let ephemeral_pk = X25519PublicKey::from(ephemeral_pk_bytes);

    let nonce_bytes: [u8; 12] = nonce
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("invalid nonce length".to_string()))?;

    // Reconstruct the static secret from bytes
    let recipient_secret = X25519StaticSecret::from(*recipient_x25519_private);

    // Derive recipient's public key from their static secret (needed for KDF)
    let recipient_public = X25519PublicKey::from(&recipient_secret);

    // ECDH key agreement — same shared secret as the encrypting side
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_pk);
    reject_low_order(shared_secret.as_bytes())
        .map_err(|_| CryptoError::DecryptionFailed("non-contributory ephemeral key".to_string()))?;

    // Must match the encrypt side: tag + suite id + both public keys, HKDF over the secret.
    let (aead_key, aad) = sealed_box_kdf(
        suite,
        &ephemeral_pk_bytes,
        recipient_public.as_bytes(),
        shared_secret.as_bytes(),
    )
    .map_err(|_| CryptoError::DecryptionFailed("HKDF derivation failed".to_string()))?;

    aead_decrypt(suite, &aead_key, &nonce_bytes, &aad, ciphertext)
}

/// Hash a password for storage using Argon2id, returning a PHC string
/// (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`). The cost parameters are
/// embedded in the string, so verification is self-describing and the cost can
/// be raised later without invalidating already-stored hashes. Argon2id has no
/// input-length ceiling — unlike bcrypt's silent 72-byte truncation — so the
/// full password is always hashed.
///
/// Uses the same Argon2id cost as private-key encryption (m=19 MiB, t=3, p=1).
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
}

/// Verify a password against a stored Argon2 PHC string. The cost parameters are
/// read from the stored string, so hashes produced with older parameters still
/// verify. Returns false on any parse error or mismatch — a malformed hash must
/// be indistinguishable from a wrong password to the caller.
pub fn verify_password(password: &str, phc: &str) -> bool {
    let parsed = match PasswordHash::new(phc) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_sign_verify_roundtrip() {
        let (public_key, secret_key) = generate_ed25519_keypair();
        let message = b"hello linkkeys";
        let signature = sign(message, &secret_key);
        assert!(verify(message, &signature, &public_key).is_ok());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (_pk1, sk1) = generate_ed25519_keypair();
        let (pk2, _sk2) = generate_ed25519_keypair();
        let message = b"hello linkkeys";
        let signature = sign(message, &sk1);
        assert!(verify(message, &signature, &pk2).is_err());
    }

    #[test]
    fn test_verify_tampered_message_fails() {
        let (public_key, secret_key) = generate_ed25519_keypair();
        let message = b"hello linkkeys";
        let signature = sign(message, &secret_key);
        assert!(verify(b"tampered message", &signature, &public_key).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key_bytes = b"this is a 32-byte secret key!!!";
        let passphrase = b"my-passphrase";
        let encrypted = encrypt_private_key(key_bytes, passphrase).unwrap();
        let decrypted = decrypt_private_key(&encrypted, passphrase).unwrap();
        assert_eq!(key_bytes.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_wrong_passphrase_fails() {
        let key_bytes = b"secret key material";
        let encrypted = encrypt_private_key(key_bytes, b"correct").unwrap();
        assert!(decrypt_private_key(&encrypted, b"wrong").is_err());
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let (public_key, _) = generate_ed25519_keypair();
        let bytes = public_key.as_bytes();
        let fp1 = fingerprint(bytes);
        let fp2 = fingerprint(bytes);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_decrypt_too_short_fails() {
        assert!(decrypt_private_key(b"short", b"pass").is_err());
    }

    #[test]
    fn test_encrypt_with_key_roundtrip() {
        let key: [u8; 32] = rand::random();
        let plaintext = b"a backup bundle of arbitrary length \x00\x01\x02";
        let blob = encrypt_with_key(&key, plaintext).unwrap();
        assert_eq!(&blob[..4], &BACKUP_MAGIC_V1);
        let out = decrypt_with_key(&key, &blob).unwrap();
        assert_eq!(plaintext.as_slice(), out.as_slice());
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key: [u8; 32] = rand::random();
        let wrong: [u8; 32] = rand::random();
        let blob = encrypt_with_key(&key, b"secret").unwrap();
        assert!(decrypt_with_key(&wrong, &blob).is_err());
    }

    #[test]
    fn test_decrypt_with_key_tamper_fails() {
        let key: [u8; 32] = rand::random();
        let mut blob = encrypt_with_key(&key, b"secret payload").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(decrypt_with_key(&key, &blob).is_err());
    }

    #[test]
    fn test_decrypt_with_key_bad_magic_fails() {
        let key: [u8; 32] = rand::random();
        assert!(decrypt_with_key(&key, b"XXXXnotabundle").is_err());
    }

    #[test]
    fn test_decrypt_legacy_headerless_format() {
        // A blob in the old headerless format (no magic, legacy params) must
        // still decrypt, so keys stored before the v2 format change keep working.
        let key_bytes = b"legacy secret key material!!";
        let passphrase = b"correct horse";
        let salt: [u8; 16] = [7u8; 16];
        let derived = derive_key_argon2id(
            passphrase,
            &salt,
            LEGACY_ARGON2_M_COST,
            LEGACY_ARGON2_T_COST,
            LEGACY_ARGON2_P_COST,
        )
        .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&derived).unwrap();
        let nonce_bytes = [9u8; 12];
        let ct = cipher
            .encrypt(AesGcmNonce::from_slice(&nonce_bytes), key_bytes.as_slice())
            .unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        let decrypted = decrypt_private_key(&blob, passphrase).unwrap();
        assert_eq!(decrypted.as_slice(), key_bytes.as_slice());
    }

    #[test]
    fn test_v2_format_has_magic_prefix() {
        let blob = encrypt_private_key(b"k", b"pass").unwrap();
        assert_eq!(&blob[..4], &KEYENC_MAGIC_V2);
    }

    /// A fresh X25519 (public, private) pair as fixed 32-byte arrays.
    fn x25519_pair() -> ([u8; 32], [u8; 32]) {
        let (pubk, privk) = generate_x25519_keypair();
        (pubk.try_into().unwrap(), privk.try_into().unwrap())
    }

    #[test]
    fn test_sealed_box_encrypt_decrypt_roundtrip() {
        for suite in [AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305] {
            let (x_pub, x_priv) = x25519_pair();
            let plaintext = b"hello sealed box";
            let sealed = sealed_box_encrypt(plaintext, &x_pub, suite).unwrap();
            let decrypted = sealed_box_decrypt(
                &sealed.ephemeral_public_key,
                &sealed.nonce,
                &sealed.ciphertext,
                &x_priv,
                suite,
            )
            .unwrap();
            assert_eq!(plaintext.as_slice(), decrypted.as_slice(), "suite {suite}");
        }
    }

    #[test]
    fn test_sealed_box_decrypt_wrong_key_fails() {
        let (x_pub, _) = x25519_pair();
        let (_, x_priv_wrong) = x25519_pair();
        let plaintext = b"secret message";
        let sealed = sealed_box_encrypt(plaintext, &x_pub, AeadSuite::Aes256Gcm).unwrap();
        assert!(sealed_box_decrypt(
            &sealed.ephemeral_public_key,
            &sealed.nonce,
            &sealed.ciphertext,
            &x_priv_wrong,
            AeadSuite::Aes256Gcm,
        )
        .is_err());
    }

    #[test]
    fn test_sealed_box_rejects_low_order_ephemeral_key() {
        // An all-zero ephemeral public key is low-order: ECDH yields an all-zero
        // shared secret, which must be rejected rather than used as a key.
        let (x_pub, x_priv) = x25519_pair();
        let plaintext = b"secret";
        let sealed = sealed_box_encrypt(plaintext, &x_pub, AeadSuite::Aes256Gcm).unwrap();
        // Replace the ephemeral public key with an all-zero (low-order) point.
        let result = sealed_box_decrypt(
            &[0u8; 32],
            &sealed.nonce,
            &sealed.ciphertext,
            &x_priv,
            AeadSuite::Aes256Gcm,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sealed_box_decrypt_tampered_ciphertext_fails() {
        let (x_pub, x_priv) = x25519_pair();
        let plaintext = b"secret message";
        let mut sealed = sealed_box_encrypt(plaintext, &x_pub, AeadSuite::Aes256Gcm).unwrap();
        // Tamper with ciphertext
        if let Some(byte) = sealed.ciphertext.first_mut() {
            *byte ^= 0xff;
        }
        assert!(sealed_box_decrypt(
            &sealed.ephemeral_public_key,
            &sealed.nonce,
            &sealed.ciphertext,
            &x_priv,
            AeadSuite::Aes256Gcm,
        )
        .is_err());
    }

    #[test]
    fn test_sealed_box_decrypt_wrong_suite_fails() {
        // Decrypting with a different suite than was used to encrypt must fail:
        // the suite id is baked into the KDF context/AAD, so a mismatched
        // suite is indistinguishable from tampering.
        let (x_pub, x_priv) = x25519_pair();
        let plaintext = b"secret message";
        let sealed = sealed_box_encrypt(plaintext, &x_pub, AeadSuite::Aes256Gcm).unwrap();
        assert!(sealed_box_decrypt(
            &sealed.ephemeral_public_key,
            &sealed.nonce,
            &sealed.ciphertext,
            &x_priv,
            AeadSuite::ChaCha20Poly1305,
        )
        .is_err());
    }

    #[test]
    fn test_resolve_aead_suite_absent_defaults_to_baseline() {
        assert_eq!(resolve_aead_suite(None).unwrap(), AeadSuite::Aes256Gcm);
    }

    #[test]
    fn test_resolve_aead_suite_present_parses() {
        assert_eq!(
            resolve_aead_suite(Some("chacha20-poly1305")).unwrap(),
            AeadSuite::ChaCha20Poly1305
        );
        assert_eq!(
            resolve_aead_suite(Some("aes-256-gcm")).unwrap(),
            AeadSuite::Aes256Gcm
        );
    }

    #[test]
    fn test_resolve_aead_suite_rejects_unknown() {
        assert!(matches!(
            resolve_aead_suite(Some("made-up-suite")),
            Err(CryptoError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn test_hash_password_roundtrip() {
        let phc = hash_password("correct horse battery staple").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery staple", &phc));
        assert!(!verify_password("wrong password", &phc));
    }

    #[test]
    fn test_hash_password_salts_are_unique() {
        // Same password hashed twice must yield different PHC strings (random
        // salt), but both must verify.
        let a = hash_password("same-password").unwrap();
        let b = hash_password("same-password").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("same-password", &a));
        assert!(verify_password("same-password", &b));
    }

    #[test]
    fn test_hash_password_no_72_byte_truncation() {
        // Two passwords identical in their first 72 bytes but differing after
        // must NOT verify against each other — the bug bcrypt's 72-byte limit
        // caused. Argon2id hashes the whole input.
        let base = "a".repeat(72);
        let phc = hash_password(&format!("{base}-suffix-one")).unwrap();
        assert!(verify_password(&format!("{base}-suffix-one"), &phc));
        assert!(!verify_password(&format!("{base}-suffix-two"), &phc));
    }

    #[test]
    fn test_aead_suite_parse_and_as_str_roundtrip() {
        for id in AeadSuite::all_supported() {
            let suite = AeadSuite::parse_str(id).expect("registered id must parse");
            assert_eq!(suite.as_str(), *id);
        }
    }

    #[test]
    fn test_aead_suite_parse_rejects_unknown() {
        assert!(AeadSuite::parse_str("made-up-suite").is_none());
        assert!(AeadSuite::parse_str("").is_none());
        assert!(AeadSuite::parse_str("AES-256-GCM").is_none()); // exact-string registry, no case folding
    }

    #[test]
    fn test_aead_suite_select_supported_prefers_first_match() {
        let advertised = vec!["chacha20-poly1305".to_string(), "aes-256-gcm".to_string()];
        assert_eq!(
            AeadSuite::select_supported(&advertised),
            Some(AeadSuite::ChaCha20Poly1305)
        );
    }

    #[test]
    fn test_aead_suite_select_supported_skips_unknown_entries() {
        let advertised = vec!["made-up-suite".to_string(), "aes-256-gcm".to_string()];
        assert_eq!(
            AeadSuite::select_supported(&advertised),
            Some(AeadSuite::Aes256Gcm)
        );
    }

    #[test]
    fn test_aead_suite_select_supported_never_picks_outside_advertised() {
        // Never selects a suite this implementation supports if it wasn't
        // actually advertised.
        let advertised = vec!["made-up-suite".to_string()];
        assert_eq!(AeadSuite::select_supported(&advertised), None);
        assert_eq!(AeadSuite::select_supported(&[]), None);
    }

    #[test]
    fn test_verify_password_rejects_malformed_hash() {
        // A non-PHC string (e.g. a legacy bcrypt hash, or garbage) must return
        // false rather than panic — scheme detection lives in the caller.
        assert!(!verify_password("anything", "not-a-phc-string"));
        assert!(!verify_password(
            "anything",
            "$2b$12$abcdefghijklmnopqrstuv"
        ));
        assert!(!verify_password("anything", ""));
    }
}
