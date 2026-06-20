//! CSIL-RPC transport — request/response/push envelopes — see `csil-rpc-transport.md`.

use crate::carrier::FrameCarrier;
use crate::conventions::*;
use ciborium::value::Value;

/// A CSIL-RPC request (client → server).
#[derive(Debug, Clone, PartialEq)]
pub struct RpcRequest {
    pub service: String,
    pub op: String,
    pub id: Option<u64>,
    /// Opaque CBOR(request type) bytes (wrapped in tag 24 on the wire).
    pub payload: Vec<u8>,
    pub auth: Option<String>,
}

/// A CSIL-RPC response (server → client).
#[derive(Debug, Clone, PartialEq)]
pub struct RpcResponse {
    pub id: Option<u64>,
    pub status: Status,
    /// Which declared output-choice arm `payload` decodes to (the CSIL type name).
    pub variant: Option<String>,
    pub error: Option<String>,
    /// Opaque CBOR(output type) bytes; empty when `status` is non-zero.
    pub payload: Vec<u8>,
}

/// A CSIL-RPC server push (server → client) for `<-` operations.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcPush {
    pub service: String,
    pub event: String,
    pub payload: Vec<u8>,
}

impl RpcRequest {
    pub fn new(service: impl Into<String>, op: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            service: service.into(),
            op: op.into(),
            id: None,
            payload,
            auth: None,
        }
    }

    pub fn with_id(mut self, id: u64) -> Self {
        self.id = Some(id);
        self
    }

    pub fn with_auth(mut self, auth: impl Into<String>) -> Self {
        self.auth = Some(auth.into());
        self
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut entries: Vec<(&'static str, Value)> = vec![
            ("v", Value::Integer(VERSION.into())),
            ("service", Value::Text(self.service.clone())),
            ("op", Value::Text(self.op.clone())),
            ("payload", tag24(self.payload.clone())),
        ];
        if let Some(id) = self.id {
            entries.push(("id", Value::Integer(id.into())));
        }
        if let Some(auth) = &self.auth {
            entries.push(("auth", Value::Text(auth.clone())));
        }
        encode_value(&canon_map(entries)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let v = decode_value(bytes)?;
        check_version(get_uint(&v, "v")?)?;
        let payload = untag24(
            map_get(&v, "payload")
                .ok_or_else(|| TransportError::Malformed("missing 'payload'".into()))?,
        )?;
        Ok(Self {
            service: get_text(&v, "service")?,
            op: get_text(&v, "op")?,
            id: get_uint_opt(&v, "id"),
            payload,
            auth: get_text_opt(&v, "auth"),
        })
    }
}

impl RpcResponse {
    /// A successful (`status: Ok`) typed reply.
    pub fn ok(variant: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            id: None,
            status: Status::Ok,
            variant: Some(variant.into()),
            error: None,
            payload,
        }
    }

    /// A transport-level failure (no typed payload).
    pub fn transport_error(status: Status, message: impl Into<String>) -> Self {
        Self {
            id: None,
            status,
            variant: None,
            error: Some(message.into()),
            payload: Vec::new(),
        }
    }

    pub fn with_id(mut self, id: Option<u64>) -> Self {
        self.id = id;
        self
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut entries: Vec<(&'static str, Value)> = vec![
            ("v", Value::Integer(VERSION.into())),
            ("status", Value::Integer(self.status.code().into())),
            ("payload", tag24(self.payload.clone())),
        ];
        if let Some(id) = self.id {
            entries.push(("id", Value::Integer(id.into())));
        }
        if let Some(variant) = &self.variant {
            entries.push(("variant", Value::Text(variant.clone())));
        }
        if let Some(error) = &self.error {
            entries.push(("error", Value::Text(error.clone())));
        }
        encode_value(&canon_map(entries)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let v = decode_value(bytes)?;
        check_version(get_uint(&v, "v")?)?;
        // payload is present but may be an empty byte string on error.
        let payload = match map_get(&v, "payload") {
            Some(p) => untag24(p)?,
            None => Vec::new(),
        };
        Ok(Self {
            id: get_uint_opt(&v, "id"),
            status: Status::from_code(get_int(&v, "status")?),
            variant: get_text_opt(&v, "variant"),
            error: get_text_opt(&v, "error"),
            payload,
        })
    }

    /// Convert a non-ok response into a `TransportError::Status`. Callers use this
    /// after `decode` to surface transport failures distinctly from app errors.
    pub fn into_transport_error(self) -> Result<Self> {
        if self.status.is_ok() {
            Ok(self)
        } else {
            Err(TransportError::Status {
                status: status_name(self.status),
                code: self.status.code(),
                message: self.error,
            })
        }
    }
}

impl RpcPush {
    pub fn new(service: impl Into<String>, event: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            service: service.into(),
            event: event.into(),
            payload,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let entries: Vec<(&'static str, Value)> = vec![
            ("v", Value::Integer(VERSION.into())),
            ("service", Value::Text(self.service.clone())),
            ("event", Value::Text(self.event.clone())),
            ("payload", tag24(self.payload.clone())),
        ];
        encode_value(&canon_map(entries)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let v = decode_value(bytes)?;
        check_version(get_uint(&v, "v")?)?;
        let payload = untag24(
            map_get(&v, "payload")
                .ok_or_else(|| TransportError::Malformed("missing 'payload'".into()))?,
        )?;
        Ok(Self {
            service: get_text(&v, "service")?,
            event: get_text(&v, "event")?,
            payload,
        })
    }
}

fn status_name(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::MalformedEnvelope => "malformed-envelope",
        Status::UnknownServiceOrOp => "unknown-service-or-op",
        Status::Unauthenticated => "unauthenticated",
        Status::Forbidden => "forbidden",
        Status::VersionUnsupported => "version-unsupported",
        Status::Internal => "internal",
        Status::Unavailable => "unavailable",
        Status::DeadlineExceeded => "deadline-exceeded",
        Status::Other(_) => "other",
    }
}

/// A CSIL-RPC client over a frame carrier. The carrier is injected (bring your own);
/// the client owns the envelope and a per-connection monotonic correlation id.
pub struct RpcClient<C: FrameCarrier> {
    carrier: C,
    next_id: u64,
    multiplexed: bool,
}

impl<C: FrameCarrier> RpcClient<C> {
    /// Create a client. `multiplexed` true assigns a correlation `id` to every
    /// request (required on WS / pipelined streams); false omits it (one-in-flight).
    pub fn new(carrier: C, multiplexed: bool) -> Self {
        Self {
            carrier,
            next_id: 1,
            multiplexed,
        }
    }

    /// Invoke `service/op` with an encoded request payload, returning the decoded
    /// response. A non-zero transport status is surfaced as `TransportError::Status`.
    pub fn call(
        &mut self,
        service: &str,
        op: &str,
        payload: Vec<u8>,
        auth: Option<String>,
    ) -> Result<RpcResponse> {
        let mut req = RpcRequest::new(service, op, payload);
        req.auth = auth;
        if self.multiplexed {
            req.id = Some(self.next_id);
            self.next_id += 1;
        }
        self.carrier.send_frame(&req.encode()?)?;
        let frame = self
            .carrier
            .recv_frame()?
            .ok_or_else(|| TransportError::Carrier("connection closed before response".into()))?;
        RpcResponse::decode(&frame)?.into_transport_error()
    }

    pub fn into_carrier(self) -> C {
        self.carrier
    }
}

/// The outcome a server handler returns for one request: the variant name and the
/// encoded payload on success, or a transport status on failure.
pub enum HandlerOutcome {
    Reply { variant: String, payload: Vec<u8> },
    Transport(Status, String),
}

/// A CSIL-RPC server over a frame carrier. The host supplies a handler mapping
/// `(service, op, request-payload)` to an outcome; the generated router is the
/// natural implementation of that handler.
pub struct RpcServer<C: FrameCarrier> {
    carrier: C,
}

impl<C: FrameCarrier> RpcServer<C> {
    pub fn new(carrier: C) -> Self {
        Self { carrier }
    }

    /// Read one request, dispatch it through `handler`, and write the response.
    /// Returns `Ok(false)` at a clean end of stream.
    pub fn serve_one<H>(&mut self, handler: &mut H) -> Result<bool>
    where
        H: FnMut(&RpcRequest) -> HandlerOutcome,
    {
        let frame = match self.carrier.recv_frame()? {
            Some(f) => f,
            None => return Ok(false),
        };
        let resp = match RpcRequest::decode(&frame) {
            Ok(req) => {
                let id = req.id;
                match handler(&req) {
                    HandlerOutcome::Reply { variant, payload } => {
                        RpcResponse::ok(variant, payload).with_id(id)
                    }
                    HandlerOutcome::Transport(status, msg) => {
                        RpcResponse::transport_error(status, msg).with_id(id)
                    }
                }
            }
            Err(e) => RpcResponse::transport_error(Status::MalformedEnvelope, e.to_string()),
        };
        self.carrier.send_frame(&resp.encode()?)?;
        Ok(true)
    }
}
