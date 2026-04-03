use liblinkkeys::generated::services::{Handshake, ServiceError};
use liblinkkeys::generated::types::{AlgorithmSupport, HandshakeRequest, HandshakeResponse};

const PROTOCOL_VERSION: &str = "v1alpha";

pub struct HandshakeHandler;

impl Handshake for HandshakeHandler {
    type Context = ();

    fn handshake(&self, _ctx: &(), input: HandshakeRequest) -> Result<HandshakeResponse, ServiceError> {
        let server_signing = liblinkkeys::crypto::SigningAlgorithm::all_supported();
        let negotiated_signing: Vec<String> = input
            .algorithms
            .signing
            .iter()
            .filter(|a| server_signing.contains(&a.as_str()))
            .cloned()
            .collect();

        Ok(HandshakeResponse {
            version: PROTOCOL_VERSION.to_string(),
            algorithms: AlgorithmSupport {
                signing: negotiated_signing,
                encryption: None,
            },
        })
    }
}
