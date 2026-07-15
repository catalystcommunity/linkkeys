use crate::generated::types::{
    EncryptedToken, LocalRpEncryptedCallback, SignedAuthRequest, SignedIdentityAssertion,
    SignedLocalRpLoginRequest,
};
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
    let cbor_bytes = crate::generated::encode_signed_identity_assertion(signed);
    Ok(Base64UrlUnpadded::encode_string(&cbor_bytes))
}

/// Decode a SignedIdentityAssertion from a URL-safe string.
/// Base64url-decodes (no padding), then CBOR-decodes.
pub fn assertion_from_url_param(param: &str) -> Result<SignedIdentityAssertion, DecodeError> {
    let cbor_bytes = Base64UrlUnpadded::decode_vec(param)
        .map_err(|e| DecodeError::Base64Failed(e.to_string()))?;
    crate::generated::decode_signed_identity_assertion(cbor_bytes.as_slice())
        .map_err(|e| DecodeError::CborFailed(format!("decode: {}", e)))
}

/// Encode a SignedAuthRequest to a URL-safe string.
pub fn signed_auth_request_to_url_param(signed: &SignedAuthRequest) -> Result<String, DecodeError> {
    let cbor_bytes = crate::generated::encode_signed_auth_request(signed);
    Ok(Base64UrlUnpadded::encode_string(&cbor_bytes))
}

/// Decode a SignedAuthRequest from a URL-safe string.
pub fn signed_auth_request_from_url_param(param: &str) -> Result<SignedAuthRequest, DecodeError> {
    let cbor_bytes = Base64UrlUnpadded::decode_vec(param)
        .map_err(|e| DecodeError::Base64Failed(e.to_string()))?;
    crate::generated::decode_signed_auth_request(cbor_bytes.as_slice())
        .map_err(|e| DecodeError::CborFailed(format!("decode: {}", e)))
}

/// Encode an EncryptedToken to a URL-safe string.
pub fn encrypted_token_to_url_param(token: &EncryptedToken) -> Result<String, DecodeError> {
    let cbor_bytes = crate::generated::encode_encrypted_token(token);
    Ok(Base64UrlUnpadded::encode_string(&cbor_bytes))
}

/// Decode an EncryptedToken from a URL-safe string.
pub fn encrypted_token_from_url_param(param: &str) -> Result<EncryptedToken, DecodeError> {
    let cbor_bytes = Base64UrlUnpadded::decode_vec(param)
        .map_err(|e| DecodeError::Base64Failed(e.to_string()))?;
    crate::generated::decode_encrypted_token(cbor_bytes.as_slice())
        .map_err(|e| DecodeError::CborFailed(format!("decode: {}", e)))
}

/// Encode a SignedLocalRpLoginRequest to a URL-safe string, for the
/// `GET /auth/local-rp?signed_request=<...>` begin route (Wire Precision:
/// "URL and parameter conventions").
pub fn signed_local_rp_login_request_to_url_param(
    signed: &SignedLocalRpLoginRequest,
) -> Result<String, DecodeError> {
    let cbor_bytes = crate::generated::encode_signed_local_rp_login_request(signed);
    Ok(Base64UrlUnpadded::encode_string(&cbor_bytes))
}

/// Decode a SignedLocalRpLoginRequest from a URL-safe string.
pub fn signed_local_rp_login_request_from_url_param(
    param: &str,
) -> Result<SignedLocalRpLoginRequest, DecodeError> {
    let cbor_bytes = Base64UrlUnpadded::decode_vec(param)
        .map_err(|e| DecodeError::Base64Failed(e.to_string()))?;
    crate::generated::decode_signed_local_rp_login_request(cbor_bytes.as_slice())
        .map_err(|e| DecodeError::CborFailed(format!("decode: {}", e)))
}

/// Encode a LocalRpEncryptedCallback to a URL-safe string, for the
/// `encrypted_token=<...>` callback-delivery query parameter (Wire
/// Precision: same name/mechanics as the existing DNS-pinned flow's
/// `encrypted_token` parameter in `web/mod.rs`).
pub fn local_rp_encrypted_callback_to_url_param(
    callback: &LocalRpEncryptedCallback,
) -> Result<String, DecodeError> {
    let cbor_bytes = crate::generated::encode_local_rp_encrypted_callback(callback);
    Ok(Base64UrlUnpadded::encode_string(&cbor_bytes))
}

/// Decode a LocalRpEncryptedCallback from a URL-safe string.
pub fn local_rp_encrypted_callback_from_url_param(
    param: &str,
) -> Result<LocalRpEncryptedCallback, DecodeError> {
    let cbor_bytes = Base64UrlUnpadded::decode_vec(param)
        .map_err(|e| DecodeError::Base64Failed(e.to_string()))?;
    crate::generated::decode_local_rp_encrypted_callback(cbor_bytes.as_slice())
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
            vec![],
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
            None,
            None,
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
            suite: None,
        };

        let encoded = encrypted_token_to_url_param(&token).unwrap();
        let decoded = encrypted_token_from_url_param(&encoded).unwrap();

        assert_eq!(token.ephemeral_public_key, decoded.ephemeral_public_key);
        assert_eq!(token.ciphertext, decoded.ciphertext);
        assert_eq!(token.nonce, decoded.nonce);
        assert_eq!(token.suite, decoded.suite);
    }

    #[test]
    fn test_encrypted_token_url_param_roundtrip_with_suite() {
        // A present `suite` field must round-trip too — absence isn't the
        // only supported shape.
        let token = EncryptedToken {
            ephemeral_public_key: vec![1; 32],
            ciphertext: vec![2; 64],
            nonce: vec![3; 12],
            suite: Some("chacha20-poly1305".to_string()),
        };

        let encoded = encrypted_token_to_url_param(&token).unwrap();
        let decoded = encrypted_token_from_url_param(&encoded).unwrap();

        assert_eq!(token.suite, decoded.suite);
    }

    #[test]
    fn test_signed_local_rp_login_request_url_param_roundtrip() {
        use crate::crypto::{generate_ed25519_keypair, generate_x25519_keypair};
        use crate::local_rp::{
            build_local_rp_descriptor, build_local_rp_login_request, sign_local_rp_descriptor,
            sign_local_rp_login_request,
        };
        use chrono::Utc;

        let (pk, sk) = generate_ed25519_keypair();
        let (enc_pk, _enc_sk) = generate_x25519_keypair();
        let pk_arr: [u8; 32] = pk.as_bytes().to_owned();
        let enc_pk_arr: [u8; 32] = enc_pk.try_into().unwrap();
        let now = Utc::now();

        let descriptor = build_local_rp_descriptor(
            "Test App",
            None,
            &pk_arr,
            &enc_pk_arr,
            vec!["aes-256-gcm".to_string()],
            &now.to_rfc3339(),
            &(now + chrono::Duration::days(3650)).to_rfc3339(),
        );
        let signed_descriptor = sign_local_rp_descriptor(&descriptor, &sk.to_bytes()).unwrap();
        let request = build_local_rp_login_request(
            signed_descriptor,
            "http://localhost:8080/callback",
            b"nonce".to_vec(),
            b"state".to_vec(),
            vec!["email".to_string()],
            vec!["handle".to_string()],
            &now.to_rfc3339(),
            &(now + chrono::Duration::minutes(5)).to_rfc3339(),
        );
        let signed = sign_local_rp_login_request(&request, &sk.to_bytes()).unwrap();

        let encoded = signed_local_rp_login_request_to_url_param(&signed).unwrap();
        let decoded = signed_local_rp_login_request_from_url_param(&encoded).unwrap();

        assert_eq!(signed.request, decoded.request);
        assert_eq!(signed.signature, decoded.signature);
    }

    #[test]
    fn test_signed_local_rp_login_request_invalid_base64_fails() {
        let result = signed_local_rp_login_request_from_url_param("not!valid!base64!");
        assert!(matches!(result, Err(DecodeError::Base64Failed(_))));
    }

    #[test]
    fn test_local_rp_encrypted_callback_url_param_roundtrip() {
        let callback = LocalRpEncryptedCallback {
            header: vec![9; 40],
            ciphertext: vec![8; 96],
        };

        let encoded = local_rp_encrypted_callback_to_url_param(&callback).unwrap();
        let decoded = local_rp_encrypted_callback_from_url_param(&encoded).unwrap();

        assert_eq!(callback.header, decoded.header);
        assert_eq!(callback.ciphertext, decoded.ciphertext);
    }

    #[test]
    fn test_local_rp_encrypted_callback_invalid_cbor_fails() {
        let encoded = Base64UrlUnpadded::encode_string(b"not valid cbor");
        let result = local_rp_encrypted_callback_from_url_param(&encoded);
        assert!(matches!(result, Err(DecodeError::CborFailed(_))));
    }
}
