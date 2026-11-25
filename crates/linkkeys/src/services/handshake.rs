use liblinkkeys::generated::services::{Handshake, ServiceError};
use liblinkkeys::generated::types::{
    AeadSuite, AlgorithmSupport, HandshakeRequest, HandshakeResponse, KeyAlgorithm,
};

const PROTOCOL_VERSION: &str = "v1alpha";

pub struct HandshakeHandler;

impl Handshake for HandshakeHandler {
    type Context = ();

    fn handshake(
        &self,
        _ctx: &(),
        input: HandshakeRequest,
    ) -> Result<HandshakeResponse, ServiceError> {
        let server_signing = liblinkkeys::crypto::SigningAlgorithm::all_supported();
        let negotiated_signing: Vec<KeyAlgorithm> = input
            .algorithms
            .signing
            .iter()
            .filter(|a| server_signing.contains(a))
            .cloned()
            .collect();

        // AEAD suite negotiation (dns-less-local-rp-design.md, "Cipher Suites
        // Are Negotiated" / Wire Precision "AEAD suite registry"): same shape
        // as `signing` above. When the caller advertises an `encryption` list,
        // respond with the subset we also support (never a suite outside what
        // the caller asked for). When the caller advertises nothing (absent
        // `encryption`, e.g. an older peer or one that hasn't opted into
        // suite negotiation yet), respond with everything we support so a
        // caller that DOES understand this field can still discover it.
        let server_encryption = liblinkkeys::crypto::AeadSuite::all_supported();
        let negotiated_encryption: Vec<AeadSuite> = match &input.algorithms.encryption {
            Some(requested) => requested
                .iter()
                .filter(|a| server_encryption.contains(a))
                .cloned()
                .collect(),
            None => server_encryption,
        };

        Ok(HandshakeResponse {
            version: PROTOCOL_VERSION.to_string(),
            algorithms: AlgorithmSupport {
                signing: negotiated_signing,
                encryption: Some(negotiated_encryption),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(signing: Vec<KeyAlgorithm>, encryption: Option<Vec<AeadSuite>>) -> HandshakeRequest {
        HandshakeRequest {
            version: PROTOCOL_VERSION.to_string(),
            algorithms: AlgorithmSupport {
                signing,
                encryption,
            },
        }
    }

    #[test]
    fn advertises_all_supported_encryption_when_caller_sends_none() {
        // An absent `encryption` list (caller hasn't opted into suite
        // negotiation, or is an older peer) must not be treated as "caller
        // supports nothing" — we advertise our own full support list so a
        // caller that DOES understand the field can discover it.
        let resp = HandshakeHandler
            .handshake(&(), request(vec![KeyAlgorithm::Ed25519], None))
            .unwrap();
        let encryption = resp.algorithms.encryption.expect("must be populated");
        assert_eq!(encryption, liblinkkeys::crypto::AeadSuite::all_supported());
    }

    #[test]
    fn negotiates_intersection_when_caller_advertises_encryption() {
        let resp = HandshakeHandler
            .handshake(
                &(),
                request(
                    vec![KeyAlgorithm::Ed25519],
                    Some(vec![AeadSuite::Chacha20Poly1305]),
                ),
            )
            .unwrap();
        assert_eq!(
            resp.algorithms.encryption,
            Some(vec![AeadSuite::Chacha20Poly1305])
        );
    }

    #[test]
    fn never_selects_a_suite_outside_the_advertised_list() {
        // The caller advertised an empty list: the response must not include
        // anything the caller did not ask for.
        let resp = HandshakeHandler
            .handshake(&(), request(vec![KeyAlgorithm::Ed25519], Some(vec![])))
            .unwrap();
        assert_eq!(resp.algorithms.encryption, Some(vec![]));
    }

    #[test]
    fn signing_negotiation_drops_algorithms_that_cannot_sign() {
        let resp = HandshakeHandler
            .handshake(
                &(),
                request(vec![KeyAlgorithm::Ed25519, KeyAlgorithm::X25519], None),
            )
            .unwrap();
        assert_eq!(resp.algorithms.signing, vec![KeyAlgorithm::Ed25519]);
    }
}
