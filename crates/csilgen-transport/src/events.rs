//! CSIL-Events transport — typed bidirectional event streams — see
//! `csil-events-transport.md`. Verbose (text-keyed) and compact (positional)
//! profiles, plus the control plane (service ordinal 0) lifecycle events.

use crate::conventions::*;
use ciborium::value::Value;

/// Which wire profile a connection uses for its lifetime, fixed by `hello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Verbose,
    Compact,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Verbose => "verbose",
            Profile::Compact => "compact",
        }
    }

    pub fn parse(s: &str) -> Option<Profile> {
        match s {
            "verbose" => Some(Profile::Verbose),
            "compact" => Some(Profile::Compact),
            _ => None,
        }
    }
}

/// One typed event flowing in either direction. Identified by service+operation
/// (verbose) or by their ordinals (compact); carries an optional correlation `id`
/// when it is a request expecting a reply, or that reply.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// CSIL service name (verbose). `None` on a single-service verbose connection.
    pub service: Option<String>,
    /// Service ordinal (compact). Always present in compact frames.
    pub service_ord: Option<u64>,
    /// CSIL operation name (verbose).
    pub event: Option<String>,
    /// Operation ordinal (compact).
    pub op_ord: Option<u64>,
    pub id: Option<u64>,
    /// Opaque CBOR(event type) bytes.
    pub payload: Vec<u8>,
}

impl Event {
    /// A verbose event by name.
    pub fn verbose(service: Option<String>, event: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            service,
            service_ord: None,
            event: Some(event.into()),
            op_ord: None,
            id: None,
            payload,
        }
    }

    /// A compact event by ordinals.
    pub fn compact(service_ord: u64, op_ord: u64, payload: Vec<u8>) -> Self {
        Self {
            service: None,
            service_ord: Some(service_ord),
            event: None,
            op_ord: Some(op_ord),
            id: None,
            payload,
        }
    }

    pub fn with_id(mut self, id: u64) -> Self {
        self.id = Some(id);
        self
    }

    /// Encode under the given profile.
    pub fn encode(&self, profile: Profile) -> Result<Vec<u8>> {
        match profile {
            Profile::Verbose => self.encode_verbose(),
            Profile::Compact => self.encode_compact(),
        }
    }

    fn encode_verbose(&self) -> Result<Vec<u8>> {
        let event = self.event.clone().ok_or_else(|| {
            TransportError::Malformed("verbose event missing 'event' name".into())
        })?;
        let mut entries: Vec<(&'static str, Value)> = vec![
            ("event", Value::Text(event)),
            ("payload", tag24(self.payload.clone())),
        ];
        if let Some(service) = &self.service {
            entries.push(("service", Value::Text(service.clone())));
        }
        if let Some(id) = self.id {
            entries.push(("id", Value::Integer(id.into())));
        }
        encode_value(&canon_map(entries)?)
    }

    fn encode_compact(&self) -> Result<Vec<u8>> {
        let service_ord = self.service_ord.ok_or_else(|| {
            TransportError::Malformed("compact event missing service ordinal".into())
        })?;
        let op_ord = self
            .op_ord
            .ok_or_else(|| TransportError::Malformed("compact event missing op ordinal".into()))?;
        let mut arr = vec![
            Value::Integer(service_ord.into()),
            Value::Integer(op_ord.into()),
        ];
        if let Some(id) = self.id {
            arr.push(Value::Integer(id.into()));
        }
        arr.push(tag24(self.payload.clone()));
        encode_value(&Value::Array(arr))
    }

    pub fn decode(bytes: &[u8], profile: Profile) -> Result<Self> {
        match profile {
            Profile::Verbose => Self::decode_verbose(bytes),
            Profile::Compact => Self::decode_compact(bytes),
        }
    }

    fn decode_verbose(bytes: &[u8]) -> Result<Self> {
        let v = decode_value(bytes)?;
        let payload = untag24(
            map_get(&v, "payload")
                .ok_or_else(|| TransportError::Malformed("missing 'payload'".into()))?,
        )?;
        Ok(Self {
            service: get_text_opt(&v, "service"),
            service_ord: None,
            event: Some(get_text(&v, "event")?),
            op_ord: None,
            id: get_uint_opt(&v, "id"),
            payload,
        })
    }

    fn decode_compact(bytes: &[u8]) -> Result<Self> {
        let v = decode_value(bytes)?;
        let arr = match &v {
            Value::Array(a) => a,
            _ => {
                return Err(TransportError::Malformed(
                    "compact event is not an array".into(),
                ));
            }
        };
        // 3 elements => [service_ord, op_ord, payload]; 4 => with correlation id.
        let (service_ord, op_ord, id, payload_val) = match arr.len() {
            3 => (&arr[0], &arr[1], None, &arr[2]),
            4 => (&arr[0], &arr[1], Some(&arr[2]), &arr[3]),
            n => {
                return Err(TransportError::Malformed(format!(
                    "compact event array has {n} elements, expected 3 or 4"
                )));
            }
        };
        let as_u64 = |val: &Value| -> Result<u64> {
            match val {
                Value::Integer(i) => {
                    let n: i128 = (*i).into();
                    u64::try_from(n)
                        .map_err(|_| TransportError::Malformed("ordinal out of range".into()))
                }
                _ => Err(TransportError::Malformed(
                    "ordinal is not an integer".into(),
                )),
            }
        };
        Ok(Self {
            service: None,
            service_ord: Some(as_u64(service_ord)?),
            event: None,
            op_ord: Some(as_u64(op_ord)?),
            id: match id {
                Some(v) => Some(as_u64(v)?),
                None => None,
            },
            payload: untag24(payload_val)?,
        })
    }
}

/// Control-plane operation ordinals (under service ordinal 0).
pub mod control {
    pub const HELLO: u64 = 0;
    pub const HELLO_ACK: u64 = 1;
    pub const PING: u64 = 2;
    pub const PONG: u64 = 3;
    pub const CLOSE: u64 = 4;
    pub const ERROR: u64 = 5;

    /// Verbose control-event names (the `$`-sigil names).
    pub const HELLO_NAME: &str = "$hello";
    pub const HELLO_ACK_NAME: &str = "$hello-ack";
    pub const PING_NAME: &str = "$ping";
    pub const PONG_NAME: &str = "$pong";
    pub const CLOSE_NAME: &str = "$close";
    pub const ERROR_NAME: &str = "$error";
}

/// The `$hello` payload offered by the connection initiator.
#[derive(Debug, Clone, PartialEq)]
pub struct Hello {
    pub versions: Vec<u64>,
    pub profiles: Vec<String>,
    pub service: Option<String>,
    pub auth: Option<String>,
}

impl Hello {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut entries: Vec<(&'static str, Value)> = vec![
            (
                "versions",
                Value::Array(
                    self.versions
                        .iter()
                        .map(|v| Value::Integer((*v).into()))
                        .collect(),
                ),
            ),
            (
                "profiles",
                Value::Array(
                    self.profiles
                        .iter()
                        .map(|p| Value::Text(p.clone()))
                        .collect(),
                ),
            ),
        ];
        if let Some(service) = &self.service {
            entries.push(("service", Value::Text(service.clone())));
        }
        if let Some(auth) = &self.auth {
            entries.push(("auth", Value::Text(auth.clone())));
        }
        encode_value(&canon_map(entries)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let v = decode_value(bytes)?;
        let versions = match map_get(&v, "versions") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| match x {
                    Value::Integer(i) => u64::try_from(Into::<i128>::into(*i)).ok(),
                    _ => None,
                })
                .collect(),
            _ => return Err(TransportError::Malformed("hello missing 'versions'".into())),
        };
        let profiles = match map_get(&v, "profiles") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| match x {
                    Value::Text(t) => Some(t.clone()),
                    _ => None,
                })
                .collect(),
            _ => return Err(TransportError::Malformed("hello missing 'profiles'".into())),
        };
        Ok(Self {
            versions,
            profiles,
            service: get_text_opt(&v, "service"),
            auth: get_text_opt(&v, "auth"),
        })
    }

    /// Select a profile from this hello's offers, honoring the peer's preference
    /// order and what the server supports. Returns the chosen `(version, profile)`,
    /// or `None` if nothing is mutually supported.
    pub fn negotiate(&self, supported: &[Profile]) -> Option<(u64, Profile)> {
        let version = self.versions.iter().copied().find(|v| *v == VERSION)?;
        for offered in &self.profiles {
            if let Some(p) = Profile::parse(offered)
                && supported.contains(&p)
            {
                return Some((version, p));
            }
        }
        None
    }
}

/// The `$hello-ack` payload returned by the peer.
#[derive(Debug, Clone, PartialEq)]
pub struct HelloAck {
    pub v: u64,
    pub profile: String,
    pub session: Option<String>,
}

impl HelloAck {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut entries: Vec<(&'static str, Value)> = vec![
            ("v", Value::Integer(self.v.into())),
            ("profile", Value::Text(self.profile.clone())),
        ];
        if let Some(session) = &self.session {
            entries.push(("session", Value::Text(session.clone())));
        }
        encode_value(&canon_map(entries)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let v = decode_value(bytes)?;
        Ok(Self {
            v: get_uint(&v, "v")?,
            profile: get_text(&v, "profile")?,
            session: get_text_opt(&v, "session"),
        })
    }
}

/// A `$ping`/`$pong` heartbeat payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Heartbeat {
    pub nonce: u64,
    pub at: Option<u64>,
}

impl Heartbeat {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut entries: Vec<(&'static str, Value)> =
            vec![("nonce", Value::Integer(self.nonce.into()))];
        if let Some(at) = self.at {
            entries.push(("at", Value::Integer(at.into())));
        }
        encode_value(&canon_map(entries)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let v = decode_value(bytes)?;
        Ok(Self {
            nonce: get_uint(&v, "nonce")?,
            at: get_uint_opt(&v, "at"),
        })
    }
}

/// A `$close` payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Close {
    pub status: Status,
    pub reason: Option<String>,
}

impl Close {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut entries: Vec<(&'static str, Value)> =
            vec![("status", Value::Integer(self.status.code().into()))];
        if let Some(reason) = &self.reason {
            entries.push(("reason", Value::Text(reason.clone())));
        }
        encode_value(&canon_map(entries)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let v = decode_value(bytes)?;
        Ok(Self {
            status: Status::from_code(get_int(&v, "status")?),
            reason: get_text_opt(&v, "reason"),
        })
    }
}
