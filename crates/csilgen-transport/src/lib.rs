//! # csilgen-transport
//!
//! Reference implementation of the CSIL transport family — **CSIL-RPC**,
//! **CSIL-Events**, and **CSIL-Datagrams** — for Rust. It owns the envelope
//! codecs, framing, and connection lifecycle; the byte/datagram **carrier** is
//! injected (bring-your-own-carrier), so a host plugs HTTP, WebSocket, QUIC,
//! WebRTC, or a platform media stack without changing this library.
//!
//! See the spec documents at the repo root: `csil-transport-conventions.md`,
//! `csil-rpc-transport.md`, `csil-events-transport.md`, `csil-datagrams-transport.md`.
//! The byte layout is pinned by the conformance vectors in `transports/conformance/`.

pub mod carrier;
pub mod conventions;
pub mod datagrams;
pub mod events;
pub mod rpc;

pub use conventions::{Result, Status, TransportError, VERSION};

/// A UDP-backed `DatagramCarrier`. Built-in convenience for the native datagram
/// path; the browser path (WebRTC unreliable / WebTransport) implements the same
/// `DatagramCarrier` trait in the host.
pub mod udp {
    use crate::carrier::DatagramCarrier;
    use crate::conventions::{Result, TransportError};
    use crate::datagrams::MAX_DATAGRAM_DEFAULT;
    use std::net::UdpSocket;

    pub struct UdpDatagramCarrier {
        socket: UdpSocket,
        recv_buf: Vec<u8>,
    }

    impl UdpDatagramCarrier {
        pub fn new(socket: UdpSocket) -> Self {
            Self {
                socket,
                recv_buf: vec![0u8; MAX_DATAGRAM_DEFAULT],
            }
        }
    }

    impl DatagramCarrier for UdpDatagramCarrier {
        fn send_datagram(&mut self, bytes: &[u8]) -> Result<()> {
            self.socket
                .send(bytes)
                .map_err(|e| TransportError::Carrier(e.to_string()))?;
            Ok(())
        }

        fn recv_datagram(&mut self) -> Result<Option<Vec<u8>>> {
            match self.socket.recv(&mut self.recv_buf) {
                Ok(n) => Ok(Some(self.recv_buf[..n].to_vec())),
                Err(e) => Err(TransportError::Carrier(e.to_string())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::carrier::{FrameCarrier, LoopbackFrameCarrier};
    use crate::conventions::Status;
    use crate::datagrams::*;
    use crate::events::*;
    use crate::rpc::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Byte-exact match against the published CSIL-RPC v1 conformance vectors
    /// (`transports/conformance/rpc.json`). Guards this vendored copy from
    /// drifting off the standard until we swap to the git dependency.
    #[test]
    fn matches_published_rpc_vectors() {
        let req = RpcRequest::new("Attestation", "deposit-claim", vec![0xa0]);
        assert_eq!(
            req.encode().unwrap(),
            hex(
                "a4617601626f706d6465706f7369742d636c61696d677061796c6f6164d81841a067736572766963656b4174746573746174696f6e"
            )
        );
        let resp = RpcResponse::ok("DepositClaimResponse", vec![0xa0]).with_id(Some(7));
        assert_eq!(
            resp.encode().unwrap(),
            hex(
                "a5617601626964076673746174757300677061796c6f6164d81841a06776617269616e74744465706f736974436c61696d526573706f6e7365"
            )
        );
    }

    #[test]
    fn rpc_request_round_trip() {
        let req = RpcRequest::new("Attestation", "deposit-claim", vec![0xa0]).with_id(7);
        let bytes = req.encode().unwrap();
        assert_eq!(RpcRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn rpc_response_success_and_error() {
        let ok = RpcResponse::ok("DepositClaimResponse", vec![0xa0]).with_id(Some(7));
        let bytes = ok.encode().unwrap();
        let decoded = RpcResponse::decode(&bytes).unwrap();
        assert_eq!(decoded.status, Status::Ok);
        assert_eq!(decoded.variant.as_deref(), Some("DepositClaimResponse"));
        assert!(decoded.into_transport_error().is_ok());

        let err = RpcResponse::transport_error(Status::UnknownServiceOrOp, "no such op");
        let bytes = err.encode().unwrap();
        let decoded = RpcResponse::decode(&bytes).unwrap();
        assert_eq!(decoded.status, Status::UnknownServiceOrOp);
        assert!(decoded.into_transport_error().is_err());
    }

    #[test]
    fn rpc_application_error_is_status_ok() {
        // An application error rides as a typed variant with transport status 0.
        let app_err = RpcResponse::ok("ServiceError", vec![0xa1, 0x00, 0x01]);
        let decoded = RpcResponse::decode(&app_err.encode().unwrap()).unwrap();
        assert_eq!(decoded.status, Status::Ok);
        assert_eq!(decoded.variant.as_deref(), Some("ServiceError"));
        // into_transport_error leaves it Ok — the caller routes it by variant.
        assert!(decoded.into_transport_error().is_ok());
    }

    #[test]
    fn rpc_client_server_over_loopback() {
        // Server replies to a request placed on the loopback's inbound queue.
        let req = RpcRequest::new("Echo", "say", vec![0x63, b'h', b'i']).with_id(1);
        let mut server_carrier = LoopbackFrameCarrier::new();
        server_carrier.push_inbound(req.encode().unwrap());
        let mut server = RpcServer::new(server_carrier);
        let served = server
            .serve_one(&mut |r: &RpcRequest| HandlerOutcome::Reply {
                variant: "SayResponse".into(),
                payload: r.payload.clone(),
            })
            .unwrap();
        assert!(served);
    }

    #[test]
    fn rpc_version_mismatch_rejected() {
        // Hand-craft an envelope with v=2; decode must reject, not misparse.
        use ciborium::value::Value;
        let bad = crate::conventions::canon_map(vec![
            ("v", Value::Integer(2.into())),
            ("service", Value::Text("S".into())),
            ("op", Value::Text("o".into())),
            ("payload", crate::conventions::tag24(vec![0xa0])),
        ])
        .unwrap();
        let bytes = crate::conventions::encode_value(&bad).unwrap();
        assert!(RpcRequest::decode(&bytes).is_err());
    }

    #[test]
    fn events_verbose_round_trip() {
        let ev = Event::verbose(Some("World".into()), "chat", vec![0x60]).with_id(3);
        let bytes = ev.encode(Profile::Verbose).unwrap();
        assert_eq!(Event::decode(&bytes, Profile::Verbose).unwrap(), ev);
    }

    #[test]
    fn events_compact_round_trip_both_shapes() {
        let fire = Event::compact(1, 0, vec![0x60]);
        let bytes = fire.encode(Profile::Compact).unwrap();
        assert_eq!(Event::decode(&bytes, Profile::Compact).unwrap(), fire);

        let corr = Event::compact(1, 2, vec![0x60]).with_id(42);
        let bytes = corr.encode(Profile::Compact).unwrap();
        let decoded = Event::decode(&bytes, Profile::Compact).unwrap();
        assert_eq!(decoded.id, Some(42));
        assert_eq!(decoded, corr);
    }

    #[test]
    fn events_hello_negotiation() {
        let hello = Hello {
            versions: vec![1],
            profiles: vec!["compact".into(), "verbose".into()],
            service: Some("World".into()),
            auth: None,
        };
        let round = Hello::decode(&hello.encode().unwrap()).unwrap();
        assert_eq!(round, hello);
        let (v, p) = round
            .negotiate(&[Profile::Verbose, Profile::Compact])
            .unwrap();
        assert_eq!(v, 1);
        assert_eq!(p, Profile::Compact); // peer prefers compact, server supports it
    }

    #[test]
    fn events_hello_negotiation_fails_on_version() {
        let hello = Hello {
            versions: vec![99],
            profiles: vec!["verbose".into()],
            service: None,
            auth: None,
        };
        assert!(hello.negotiate(&[Profile::Verbose]).is_none());
    }

    #[test]
    fn datagram_cbor_array_round_trip() {
        let dg = Datagram::new(0, 5, vec![0x60]);
        let bytes = dg.encode().unwrap();
        assert_eq!(Datagram::decode(&bytes).unwrap(), dg);
        // Wrong arity rejected.
        use ciborium::value::Value;
        let three = crate::conventions::encode_value(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Integer(0.into()),
            crate::conventions::tag24(vec![0x60]),
        ]))
        .unwrap();
        assert!(Datagram::decode(&three).is_err());
    }

    #[test]
    fn datagram_compact_header_round_trip() {
        let dg = CompactDatagram::new(1, 0x1234, vec![1, 2, 3]);
        let bytes = dg.encode();
        assert_eq!(bytes[0] >> 4, 1); // version nibble
        assert_eq!(CompactDatagram::decode(&bytes).unwrap(), dg);

        let with_epoch = CompactDatagram::new(2, 7, vec![9]).with_epoch(4);
        let decoded = CompactDatagram::decode(&with_epoch.encode()).unwrap();
        assert_eq!(decoded.epoch, Some(4));
        assert_eq!(decoded, with_epoch);
    }

    #[test]
    fn seq_tracker_detects_loss_reorder_restart() {
        let mut t = SeqTracker::new();
        assert_eq!(t.observe(1, Some(0)), SeqEvent::First);
        assert_eq!(t.observe(2, Some(0)), SeqEvent::Advanced { gap: 0 });
        assert_eq!(t.observe(5, Some(0)), SeqEvent::Advanced { gap: 2 }); // lost 3,4
        assert_eq!(t.observe(3, Some(0)), SeqEvent::LateOrDuplicate);
        assert_eq!(t.observe(1, Some(1)), SeqEvent::Restart); // epoch bumped
    }

    #[test]
    fn seq_tracker_treats_unsequenced_as_advanced() {
        // An all-unsequenced (seq 0) channel must never report LateOrDuplicate,
        // or an app that drops late/dup datagrams would discard everything.
        let mut t = SeqTracker::new();
        assert_eq!(t.observe(0, None), SeqEvent::Advanced { gap: 0 });
        assert_eq!(t.observe(0, None), SeqEvent::Advanced { gap: 0 });
        assert_eq!(t.observe(0, None), SeqEvent::Advanced { gap: 0 });
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // A valid empty-map envelope (0xa0) followed by a stray byte must be rejected.
        let mut bytes = crate::rpc::RpcPush::new("S", "e", vec![0xa0])
            .encode()
            .unwrap();
        bytes.push(0x00);
        assert!(crate::rpc::RpcPush::decode(&bytes).is_err());
    }

    #[test]
    fn length_prefix_framing_round_trips_over_loopback() {
        let mut c = LoopbackFrameCarrier::new();
        c.send_frame(&[1, 2, 3]).unwrap();
        let framed = c.take_outbound().unwrap();
        c.push_inbound(framed);
        assert_eq!(c.recv_frame().unwrap().unwrap(), vec![1, 2, 3]);
    }
}
