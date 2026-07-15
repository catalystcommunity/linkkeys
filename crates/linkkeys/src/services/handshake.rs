use liblinkkeys::generated::services::{Handshake, ServiceError};
use liblinkkeys::generated::types::{AlgorithmSupport, HandshakeRequest, HandshakeResponse};

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
        let negotiated_signing: Vec<String> = input
            .algorithms
            .signing
            .iter()
            .filter(|a| server_signing.contains(&a.as_str()))
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
        let negotiated_encryption: Vec<String> = match &input.algorithms.encryption {
            Some(requested) => requested
                .iter()
                .filter(|a| server_encryption.contains(&a.as_str()))
                .cloned()
                .collect(),
            None => server_encryption.iter().map(|s| s.to_string()).collect(),
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

    fn request(signing: Vec<&str>, encryption: Option<Vec<&str>>) -> HandshakeRequest {
        HandshakeRequest {
            version: PROTOCOL_VERSION.to_string(),
            algorithms: AlgorithmSupport {
                signing: signing.into_iter().map(String::from).collect(),
                encryption: encryption.map(|list| list.into_iter().map(String::from).collect()),
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
            .handshake(&(), request(vec!["ed25519"], None))
            .unwrap();
        let encryption = resp.algorithms.encryption.expect("must be populated");
        assert_eq!(
            encryption,
            liblinkkeys::crypto::AeadSuite::all_supported().to_vec()
        );
    }

    #[test]
    fn negotiates_intersection_when_caller_advertises_encryption() {
        let resp = HandshakeHandler
            .handshake(
                &(),
                request(vec!["ed25519"], Some(vec!["chacha20-poly1305"])),
            )
            .unwrap();
        assert_eq!(
            resp.algorithms.encryption,
            Some(vec!["chacha20-poly1305".to_string()])
        );
    }

    #[test]
    fn never_selects_a_suite_outside_the_advertised_list() {
        // The server supports both suites, but the caller only advertised an
        // unrecognized id — the response must not include anything the
        // caller didn't ask for, and must not include unknown ids either.
        let resp = HandshakeHandler
            .handshake(&(), request(vec!["ed25519"], Some(vec!["made-up-suite"])))
            .unwrap();
        assert_eq!(resp.algorithms.encryption, Some(vec![]));
    }

    #[test]
    fn signing_negotiation_is_unaffected_by_encryption_wiring() {
        let resp = HandshakeHandler
            .handshake(&(), request(vec!["ed25519", "made-up-algo"], None))
            .unwrap();
        assert_eq!(resp.algorithms.signing, vec!["ed25519".to_string()]);
    }
}
