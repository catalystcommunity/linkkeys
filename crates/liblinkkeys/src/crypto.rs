use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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
    pub fn from_str(s: &str) -> Option<SigningAlgorithm> {
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
    public_key
        .verify(message, &signature)
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

/// Resolve an algorithm string and public key bytes into a verified signature check.
/// This is the entry point for assertions and claims verification — it validates
/// the algorithm is supported before attempting verification.
pub fn resolve_and_verify(
    algorithm: &str,
    message: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<(), CryptoError> {
    let alg = SigningAlgorithm::from_str(algorithm)
        .ok_or_else(|| CryptoError::UnsupportedAlgorithm(algorithm.to_string()))?;
    verify_with_algorithm(alg, message, signature_bytes, public_key_bytes)
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

fn derive_key_argon2id(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(19456, 2, 1, Some(32))
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    Ok(key)
}

/// Encrypt a private key using AES-256-GCM with Argon2id key derivation.
/// Returns: 16-byte salt || 12-byte nonce || ciphertext (with appended GCM tag).
pub fn encrypt_private_key(
    key_bytes: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let salt: [u8; 16] = rand::random();
    let derived_key = derive_key_argon2id(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, key_bytes)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(16 + 12 + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a private key encrypted with `encrypt_private_key`.
/// Input format: 16-byte salt || 12-byte nonce || ciphertext (with appended GCM tag).
pub fn decrypt_private_key(
    encrypted: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() < 28 {
        return Err(CryptoError::DecryptionFailed(
            "ciphertext too short".to_string(),
        ));
    }

    let (salt, rest) = encrypted.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    let derived_key = derive_key_argon2id(passphrase, salt)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Convert an Ed25519 public key (32 bytes) to an X25519 public key (32 bytes).
/// The Ed25519 Edwards point is converted to its Montgomery form.
pub fn ed25519_public_to_x25519(ed25519_public: &[u8]) -> Result<[u8; 32], CryptoError> {
    let vk = VerifyingKey::from_bytes(
        ed25519_public
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?,
    )
    .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(vk.to_montgomery().to_bytes())
}

/// Convert an Ed25519 private key (32-byte seed) to X25519 static secret bytes.
/// Returns the unclamped lower 32 bytes of SHA-512(seed). These bytes MUST be used
/// with `x25519_dalek::StaticSecret::from()`, which applies clamping internally.
/// Do not use the returned bytes directly as a scalar without clamping.
pub fn ed25519_private_to_x25519(ed25519_private: &[u8]) -> Result<[u8; 32], CryptoError> {
    let sk = SigningKey::from_bytes(
        ed25519_private
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?,
    );
    // to_scalar_bytes() returns the unclamped lower 32 bytes of SHA-512(seed).
    // Constructing an X25519StaticSecret from these bytes applies clamping internally.
    Ok(sk.to_scalar_bytes())
}

/// Sealed-box encrypt a message to a recipient's X25519 public key.
///
/// 1. Generate an ephemeral X25519 keypair
/// 2. Perform ECDH key agreement to derive a shared secret
/// 3. Derive an AES-256 key from the shared secret via SHA-256
/// 4. Encrypt with AES-256-GCM using a random 12-byte nonce
///
/// Returns (ephemeral_public_key, nonce, ciphertext) for constructing an EncryptedToken.
pub fn sealed_box_encrypt(
    plaintext: &[u8],
    recipient_x25519_public: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), CryptoError> {
    let recipient_pk = X25519PublicKey::from(*recipient_x25519_public);

    // Generate ephemeral X25519 keypair
    let ephemeral_secret = X25519StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // ECDH key agreement
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

    // Derive AES-256 key from shared secret via SHA-256 with domain separation.
    // Include both public keys to bind the key to this specific exchange.
    let mut hasher = Sha256::new();
    hasher.update(b"linkkeys-sealed-box-v1");
    hasher.update(ephemeral_public.as_bytes());
    hasher.update(recipient_x25519_public);
    hasher.update(shared_secret.as_bytes());
    let aes_key = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    Ok((
        ephemeral_public.as_bytes().to_vec(),
        nonce_bytes.to_vec(),
        ciphertext,
    ))
}

/// Sealed-box decrypt using the recipient's X25519 private key.
///
/// 1. Perform ECDH with the ephemeral public key and recipient's private key
/// 2. Derive AES-256 key from shared secret via SHA-256
/// 3. Decrypt with AES-256-GCM
pub fn sealed_box_decrypt(
    ephemeral_public_key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    recipient_x25519_private: &[u8; 32],
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

    // Derive AES-256 key from shared secret via SHA-256 with domain separation.
    // Must match the encrypt side: protocol tag + both public keys + shared secret.
    let mut hasher = Sha256::new();
    hasher.update(b"linkkeys-sealed-box-v1");
    hasher.update(ephemeral_pk_bytes);
    hasher.update(recipient_public.as_bytes());
    hasher.update(shared_secret.as_bytes());
    let aes_key = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let gcm_nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(gcm_nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
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
    fn test_ed25519_to_x25519_public_deterministic() {
        let (vk, _sk) = generate_ed25519_keypair();
        let x1 = ed25519_public_to_x25519(vk.as_bytes()).unwrap();
        let x2 = ed25519_public_to_x25519(vk.as_bytes()).unwrap();
        assert_eq!(x1, x2);
        // X25519 public key is 32 bytes
        assert_eq!(x1.len(), 32);
    }

    #[test]
    fn test_ed25519_to_x25519_ecdh_roundtrip() {
        // Generate two Ed25519 keypairs and convert to X25519
        let (vk_a, sk_a) = generate_ed25519_keypair();
        let (vk_b, sk_b) = generate_ed25519_keypair();

        let x_pub_a = ed25519_public_to_x25519(vk_a.as_bytes()).unwrap();
        let x_priv_a = ed25519_private_to_x25519(sk_a.as_bytes()).unwrap();
        let x_pub_b = ed25519_public_to_x25519(vk_b.as_bytes()).unwrap();
        let x_priv_b = ed25519_private_to_x25519(sk_b.as_bytes()).unwrap();

        // ECDH from both sides should produce the same shared secret
        let secret_a = X25519StaticSecret::from(x_priv_a);
        let secret_b = X25519StaticSecret::from(x_priv_b);
        let shared_ab = secret_a.diffie_hellman(&X25519PublicKey::from(x_pub_b));
        let shared_ba = secret_b.diffie_hellman(&X25519PublicKey::from(x_pub_a));
        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
    }

    #[test]
    fn test_sealed_box_encrypt_decrypt_roundtrip() {
        let (vk, sk) = generate_ed25519_keypair();
        let x_pub = ed25519_public_to_x25519(vk.as_bytes()).unwrap();
        let x_priv = ed25519_private_to_x25519(sk.as_bytes()).unwrap();

        let plaintext = b"hello sealed box";
        let (ephemeral_pk, nonce, ciphertext) = sealed_box_encrypt(plaintext, &x_pub).unwrap();
        let decrypted = sealed_box_decrypt(&ephemeral_pk, &nonce, &ciphertext, &x_priv).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_sealed_box_decrypt_wrong_key_fails() {
        let (vk, _sk) = generate_ed25519_keypair();
        let (_vk2, sk2) = generate_ed25519_keypair();
        let x_pub = ed25519_public_to_x25519(vk.as_bytes()).unwrap();
        let x_priv_wrong = ed25519_private_to_x25519(sk2.as_bytes()).unwrap();

        let plaintext = b"secret message";
        let (ephemeral_pk, nonce, ciphertext) = sealed_box_encrypt(plaintext, &x_pub).unwrap();
        assert!(sealed_box_decrypt(&ephemeral_pk, &nonce, &ciphertext, &x_priv_wrong).is_err());
    }

    #[test]
    fn test_sealed_box_decrypt_tampered_ciphertext_fails() {
        let (vk, sk) = generate_ed25519_keypair();
        let x_pub = ed25519_public_to_x25519(vk.as_bytes()).unwrap();
        let x_priv = ed25519_private_to_x25519(sk.as_bytes()).unwrap();

        let plaintext = b"secret message";
        let (ephemeral_pk, nonce, mut ciphertext) = sealed_box_encrypt(plaintext, &x_pub).unwrap();
        // Tamper with ciphertext
        if let Some(byte) = ciphertext.first_mut() {
            *byte ^= 0xff;
        }
        assert!(sealed_box_decrypt(&ephemeral_pk, &nonce, &ciphertext, &x_priv).is_err());
    }
}
