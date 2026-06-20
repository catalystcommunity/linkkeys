//! Conventions shared by every CSIL transport — see `csil-transport-conventions.md`.
//!
//! This module owns the parts the three transports agree on: the CBOR rules
//! (deterministic encoding, tag-24 payloads), the version constant, the transport
//! status registry, and the max-frame guard. The transport modules build their
//! envelopes from the canonical-CBOR helpers here so the bytes match the
//! conformance vectors regardless of struct layout.

use ciborium::value::Value;

/// Current transport version. A new value is minted only for a breaking change to
/// envelope layout or semantics.
pub const VERSION: u64 = 1;

/// CBOR semantic tag wrapping an embedded, opaque CBOR data item (RFC 8949 §3.4.5.1).
pub const TAG_ENCODED_CBOR: u64 = 24;

/// Reserved service ordinal for the transport control plane (Events lifecycle).
pub const CONTROL_SERVICE_ORD: u64 = 0;

/// Default max encoded envelope size for stream/message carriers (16 MiB). A
/// carrier rejects anything larger before allocating for it.
pub const MAX_FRAME_DEFAULT: usize = 16 * 1024 * 1024;

/// Transport-level status. Distinct from application errors, which ride inside the
/// payload as a declared `/ ErrorType` arm. See the conventions doc registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    MalformedEnvelope,
    UnknownServiceOrOp,
    Unauthenticated,
    Forbidden,
    VersionUnsupported,
    Internal,
    Unavailable,
    DeadlineExceeded,
    /// A host-defined transport-extension code (>= 64) or any unrecognized code.
    Other(i64),
}

impl Status {
    pub fn code(self) -> i64 {
        match self {
            Status::Ok => 0,
            Status::MalformedEnvelope => 1,
            Status::UnknownServiceOrOp => 2,
            Status::Unauthenticated => 3,
            Status::Forbidden => 4,
            Status::VersionUnsupported => 5,
            Status::Internal => 6,
            Status::Unavailable => 7,
            Status::DeadlineExceeded => 8,
            Status::Other(c) => c,
        }
    }

    pub fn from_code(code: i64) -> Status {
        match code {
            0 => Status::Ok,
            1 => Status::MalformedEnvelope,
            2 => Status::UnknownServiceOrOp,
            3 => Status::Unauthenticated,
            4 => Status::Forbidden,
            5 => Status::VersionUnsupported,
            6 => Status::Internal,
            7 => Status::Unavailable,
            8 => Status::DeadlineExceeded,
            other => Status::Other(other),
        }
    }

    pub fn is_ok(self) -> bool {
        self.code() == 0
    }
}

/// Errors surfaced by the transport layer (the wire), distinct from a host's
/// application errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("CBOR encode error: {0}")]
    Encode(String),
    #[error("CBOR decode error: {0}")]
    Decode(String),
    #[error("malformed envelope: {0}")]
    Malformed(String),
    #[error("frame of {got} bytes exceeds max-frame guard of {max} bytes")]
    FrameTooLarge { got: usize, max: usize },
    #[error("unsupported transport version {0}")]
    UnsupportedVersion(u64),
    /// A non-zero transport status returned by the peer.
    #[error("transport status {status} ({code}){}", .message.as_deref().map(|m| format!(": {m}")).unwrap_or_default())]
    Status {
        status: &'static str,
        code: i64,
        message: Option<String>,
    },
    #[error("carrier error: {0}")]
    Carrier(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;

/// Wrap opaque payload bytes (themselves a CBOR item) in tag 24.
pub fn tag24(payload: Vec<u8>) -> Value {
    Value::Tag(TAG_ENCODED_CBOR, Box::new(Value::Bytes(payload)))
}

/// Extract the opaque payload bytes from a tag-24 value.
pub fn untag24(value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::Tag(TAG_ENCODED_CBOR, inner) => match inner.as_ref() {
            Value::Bytes(b) => Ok(b.clone()),
            _ => Err(TransportError::Malformed(
                "tag-24 payload is not a byte string".into(),
            )),
        },
        _ => Err(TransportError::Malformed(
            "expected a tag-24 (encoded-cbor) payload".into(),
        )),
    }
}

/// Encode a CBOR value to bytes.
pub fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e| TransportError::Encode(e.to_string()))?;
    Ok(buf)
}

/// Decode bytes into a CBOR value. An envelope is a single self-contained CBOR
/// item (conventions doc §1), so trailing bytes after the item are rejected —
/// matching the other reference libraries instead of silently ignoring them.
pub fn decode_value(bytes: &[u8]) -> Result<Value> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|e| TransportError::Decode(e.to_string()))?;
    if (cursor.position() as usize) != bytes.len() {
        return Err(TransportError::Decode(
            "trailing bytes after CBOR item".into(),
        ));
    }
    Ok(value)
}

/// Build a deterministically-keyed CBOR map. Entries are sorted by the bytewise
/// lexicographic order of their *encoded* keys (RFC 8949 core deterministic
/// encoding), so the same logical envelope always yields the same bytes.
pub fn canon_map(entries: Vec<(&'static str, Value)>) -> Result<Value> {
    let mut keyed: Vec<(Vec<u8>, Value, Value)> = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        let key = Value::Text(k.to_string());
        let encoded_key = encode_value(&key)?;
        keyed.push((encoded_key, key, v));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Value::Map(
        keyed.into_iter().map(|(_, k, v)| (k, v)).collect(),
    ))
}

/// Look up a text key in a CBOR map value.
pub fn map_get<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    if let Value::Map(entries) = map {
        for (k, v) in entries {
            if let Value::Text(t) = k
                && t == key
            {
                return Some(v);
            }
        }
    }
    None
}

/// Read a required unsigned integer field from a CBOR map.
pub fn get_uint(map: &Value, key: &str) -> Result<u64> {
    match map_get(map, key) {
        Some(Value::Integer(i)) => {
            let n: i128 = (*i).into();
            u64::try_from(n).map_err(|_| {
                TransportError::Malformed(format!("field '{key}' is not a non-negative integer"))
            })
        }
        _ => Err(TransportError::Malformed(format!(
            "missing or non-integer field '{key}'"
        ))),
    }
}

/// Read a required signed integer field from a CBOR map.
pub fn get_int(map: &Value, key: &str) -> Result<i64> {
    match map_get(map, key) {
        Some(Value::Integer(i)) => {
            let n: i128 = (*i).into();
            i64::try_from(n)
                .map_err(|_| TransportError::Malformed(format!("field '{key}' out of i64 range")))
        }
        _ => Err(TransportError::Malformed(format!(
            "missing or non-integer field '{key}'"
        ))),
    }
}

/// Read a required text field from a CBOR map.
pub fn get_text(map: &Value, key: &str) -> Result<String> {
    match map_get(map, key) {
        Some(Value::Text(t)) => Ok(t.clone()),
        _ => Err(TransportError::Malformed(format!(
            "missing or non-text field '{key}'"
        ))),
    }
}

/// Read an optional text field from a CBOR map.
pub fn get_text_opt(map: &Value, key: &str) -> Option<String> {
    match map_get(map, key) {
        Some(Value::Text(t)) => Some(t.clone()),
        _ => None,
    }
}

/// Read an optional unsigned integer field from a CBOR map.
pub fn get_uint_opt(map: &Value, key: &str) -> Option<u64> {
    match map_get(map, key) {
        Some(Value::Integer(i)) => {
            let n: i128 = (*i).into();
            u64::try_from(n).ok()
        }
        _ => None,
    }
}

/// Verify a decoded envelope's version field, returning a clear error otherwise.
pub fn check_version(v: u64) -> Result<()> {
    if v == VERSION {
        Ok(())
    } else {
        Err(TransportError::UnsupportedVersion(v))
    }
}
