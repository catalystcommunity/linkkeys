use crate::generated::types::{EncryptedToken, SignedAuthRequest, SignedIdentityAssertion};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::fmt;

#[derive(Debug)]
pub enum DecodeError {
    Base64Failed(String),
    CborFailed(String),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Base64Failed(msg) => write!(f, "base64url decode failed: {}", msg),
            DecodeError::CborFailed(msg) => write!(f, "CBOR decode failed: {}", msg),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode a SignedIdentityAssertion to a URL-safe string.
/// CBOR-encodes the struct, then base64url-encodes (no padding).
pub fn assertion_to_url_param(signed: &SignedIdentityAssertion) -> Result<String, DecodeError> {
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(signed, &mut cbor_bytes)
        .map_err(|e| DecodeError::CborFailed(format!("encode: {}", e)))?;
    Ok(Base64UrlUnpadded::encode_string(&cbor_bytes))
}

/// Decode a SignedIdentityAssertion from a URL-safe string.
/// Base64url-decodes (no padding), then CBOR-decodes.
pub fn assertion_from_url_param(param: &str) -> Result<SignedIdentityAssertion, DecodeError> {
    let cbor_bytes = Base64UrlUnpadded::decode_vec(param)
        .map_err(|e| DecodeError::Base64Failed(e.to_string()))?;
    ciborium::de::from_reader(cbor_bytes.as_slice())
        .map_err(|e| DecodeError::CborFailed(format!("decode: {}", e)))
}

/// Encode a SignedAuthRequest to a URL-safe string.
pub fn signed_auth_request_to_url_param(signed: &SignedAuthRequest) -> Result<String, DecodeError> {
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(signed, &mut cbor_bytes)
        .map_err(|e| DecodeError::CborFailed(format!("encode: {}", e)))?;
    Ok(Base64UrlUnpadded::encode_string(&cbor_bytes))
}

/// Decode a SignedAuthRequest from a URL-safe string.
pub fn signed_auth_request_from_url_param(param: &str) -> Result<SignedAuthRequest, DecodeError> {
    let cbor_bytes = Base64UrlUnpadded::decode_vec(param)
        .map_err(|e| DecodeError::Base64Failed(e.to_string()))?;
    ciborium::de::from_reader(cbor_bytes.as_slice())
        .map_err(|e| DecodeError::CborFailed(format!("decode: {}", e)))
}

/// Encode an EncryptedToken to a URL-safe string.
pub fn encrypted_token_to_url_param(token: &EncryptedToken) -> Result<String, DecodeError> {
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(token, &mut cbor_bytes)
        .map_err(|e| DecodeError::CborFailed(format!("encode: {}", e)))?;
    Ok(Base64UrlUnpadded::encode_string(&cbor_bytes))
}

/// Decode an EncryptedToken from a URL-safe string.
pub fn encrypted_token_from_url_param(param: &str) -> Result<EncryptedToken, DecodeError> {
    let cbor_bytes = Base64UrlUnpadded::decode_vec(param)
        .map_err(|e| DecodeError::Base64Failed(e.to_string()))?;
    ciborium::de::from_reader(cbor_bytes.as_slice())
        .map_err(|e| DecodeError::CborFailed(format!("decode: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assertions::{build_assertion, sign_assertion};
    use crate::crypto::{generate_keypair, SigningAlgorithm};

    #[test]
    fn test_url_param_roundtrip() {
        let (_pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let assertion = build_assertion(
            "user-123",
            "example.com",
            "app.example.com",
            "nonce-xyz",
            Some("Alice"),
            300,
        );
        let signed = sign_assertion(&assertion, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        let encoded = assertion_to_url_param(&signed).unwrap();
        let decoded = assertion_from_url_param(&encoded).unwrap();

        assert_eq!(signed.signing_key_id, decoded.signing_key_id);
        assert_eq!(signed.assertion, decoded.assertion);
        assert_eq!(signed.signature, decoded.signature);
    }

    #[test]
    fn test_invalid_base64_fails() {
        let result = assertion_from_url_param("not!valid!base64!");
        assert!(matches!(result, Err(DecodeError::Base64Failed(_))));
    }

    #[test]
    fn test_invalid_cbor_fails() {
        let encoded = Base64UrlUnpadded::encode_string(b"not valid cbor");
        let result = assertion_from_url_param(&encoded);
        assert!(matches!(result, Err(DecodeError::CborFailed(_))));
    }

    #[test]
    fn test_signed_auth_request_url_param_roundtrip() {
        use crate::auth_request::{build_auth_request, sign_auth_request};

        let (_pk, sk) = generate_keypair(SigningAlgorithm::Ed25519);
        let request = build_auth_request(
            "linkidspec.com",
            "https://linkidspec.com/callback",
            "nonce-xyz",
            "key-1",
        );
        let signed = sign_auth_request(&request, "key-1", SigningAlgorithm::Ed25519, &sk).unwrap();

        let encoded = signed_auth_request_to_url_param(&signed).unwrap();
        let decoded = signed_auth_request_from_url_param(&encoded).unwrap();

        assert_eq!(signed.signing_key_id, decoded.signing_key_id);
        assert_eq!(signed.request, decoded.request);
        assert_eq!(signed.signature, decoded.signature);
    }

    #[test]
    fn test_encrypted_token_url_param_roundtrip() {
        let token = EncryptedToken {
            ephemeral_public_key: vec![1; 32],
            ciphertext: vec![2; 64],
            nonce: vec![3; 12],
        };

        let encoded = encrypted_token_to_url_param(&token).unwrap();
        let decoded = encrypted_token_from_url_param(&encoded).unwrap();

        assert_eq!(token.ephemeral_public_key, decoded.ephemeral_public_key);
        assert_eq!(token.ciphertext, decoded.ciphertext);
        assert_eq!(token.nonce, decoded.nonce);
    }
}
