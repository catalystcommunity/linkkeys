use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

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
}
