//! CSIL-Datagrams transport — unreliable, unordered, message-oriented — see
//! `csil-datagrams-transport.md`. CBOR-array (default), compact fixed-header, and
//! payload-only profiles. A datagram channel is single-service: the service is
//! bound at channel setup, so datagrams carry no service ordinal.

use crate::conventions::*;
use ciborium::value::Value;

/// Conservative max datagram size (envelope + payload) safe across UDP/WebRTC/QUIC.
pub const MAX_DATAGRAM_DEFAULT: usize = 1200;

/// A datagram in the CBOR-array (default) profile: `[v, op_ord, seq, payload]`.
#[derive(Debug, Clone, PartialEq)]
pub struct Datagram {
    pub op_ord: u64,
    /// Per-channel sequence; 0 means "unsequenced".
    pub seq: u64,
    /// Opaque CBOR(message type) bytes.
    pub payload: Vec<u8>,
}

impl Datagram {
    pub fn new(op_ord: u64, seq: u64, payload: Vec<u8>) -> Self {
        Self {
            op_ord,
            seq,
            payload,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let arr = Value::Array(vec![
            Value::Integer(VERSION.into()),
            Value::Integer(self.op_ord.into()),
            Value::Integer(self.seq.into()),
            tag24(self.payload.clone()),
        ]);
        encode_value(&arr)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let v = decode_value(bytes)?;
        let arr = match &v {
            Value::Array(a) => a,
            _ => return Err(TransportError::Malformed("datagram is not an array".into())),
        };
        if arr.len() != 4 {
            return Err(TransportError::Malformed(format!(
                "datagram array has {} elements, expected 4",
                arr.len()
            )));
        }
        let as_u64 = |val: &Value| -> Result<u64> {
            match val {
                Value::Integer(i) => u64::try_from(Into::<i128>::into(*i))
                    .map_err(|_| TransportError::Malformed("datagram field out of range".into())),
                _ => Err(TransportError::Malformed(
                    "datagram field not an integer".into(),
                )),
            }
        };
        check_version(as_u64(&arr[0])?)?;
        Ok(Self {
            op_ord: as_u64(&arr[1])?,
            seq: as_u64(&arr[2])?,
            payload: untag24(&arr[3])?,
        })
    }
}

/// A datagram in the compact fixed-header profile. Header layout:
/// `[ver|flags][op_ord:u8][seq:u16 BE]([epoch:u8])` then the opaque body.
#[derive(Debug, Clone, PartialEq)]
pub struct CompactDatagram {
    pub op_ord: u8,
    pub seq: u16,
    /// Present when the sender tracks restarts (sets the flags epoch bit).
    pub epoch: Option<u8>,
    /// Opaque body bytes (tag-24 CBOR or a raw media frame, by channel agreement).
    pub body: Vec<u8>,
}

const COMPACT_VER: u8 = 1;
const FLAG_EPOCH: u8 = 0b0001;

impl CompactDatagram {
    pub fn new(op_ord: u8, seq: u16, body: Vec<u8>) -> Self {
        Self {
            op_ord,
            seq,
            epoch: None,
            body,
        }
    }

    pub fn with_epoch(mut self, epoch: u8) -> Self {
        self.epoch = Some(epoch);
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        let flags = if self.epoch.is_some() { FLAG_EPOCH } else { 0 };
        let mut out = Vec::with_capacity(5 + self.body.len());
        out.push((COMPACT_VER << 4) | (flags & 0x0f));
        out.push(self.op_ord);
        out.extend_from_slice(&self.seq.to_be_bytes());
        if let Some(epoch) = self.epoch {
            out.push(epoch);
        }
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(TransportError::Malformed(
                "compact datagram shorter than the 4-byte header".into(),
            ));
        }
        let ver = bytes[0] >> 4;
        if ver != COMPACT_VER {
            return Err(TransportError::UnsupportedVersion(ver as u64));
        }
        let flags = bytes[0] & 0x0f;
        let op_ord = bytes[1];
        let seq = u16::from_be_bytes([bytes[2], bytes[3]]);
        let (epoch, body_start) = if flags & FLAG_EPOCH != 0 {
            if bytes.len() < 5 {
                return Err(TransportError::Malformed(
                    "compact datagram flags claim an epoch byte that is absent".into(),
                ));
            }
            (Some(bytes[4]), 5)
        } else {
            (None, 4)
        };
        Ok(Self {
            op_ord,
            seq,
            epoch,
            body: bytes[body_start..].to_vec(),
        })
    }
}

/// Classification of an incoming sequence number relative to what was last seen,
/// for loss/reorder/restart detection. The transport detects; the app decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqEvent {
    /// First datagram seen on the channel.
    First,
    /// Strictly newer than the last (possibly skipping some — a gap/loss).
    Advanced { gap: u64 },
    /// Not newer (a late or duplicate datagram).
    LateOrDuplicate,
    /// The sender restarted (epoch changed); seq numbering reset.
    Restart,
}

/// Tracks the last sequence/epoch per channel to classify arrivals. Unsequenced
/// datagrams (seq 0) are always reported as `Advanced { gap: 0 }`.
#[derive(Debug, Default)]
pub struct SeqTracker {
    last_seq: Option<u64>,
    last_epoch: Option<u8>,
}

impl SeqTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, seq: u64, epoch: Option<u8>) -> SeqEvent {
        if epoch != self.last_epoch && self.last_epoch.is_some() {
            self.last_epoch = epoch;
            self.last_seq = Some(seq);
            return SeqEvent::Restart;
        }
        self.last_epoch = epoch;
        // seq 0 marks an unsequenced datagram: it carries no ordering information,
        // so it is never late or duplicate. Report a zero-gap advance and leave the
        // running sequence untouched (a mix of sequenced and unsequenced still
        // tracks the sequenced ones).
        if seq == 0 {
            return SeqEvent::Advanced { gap: 0 };
        }
        match self.last_seq {
            None => {
                self.last_seq = Some(seq);
                SeqEvent::First
            }
            Some(last) if seq > last => {
                let gap = seq - last - 1;
                self.last_seq = Some(seq);
                SeqEvent::Advanced { gap }
            }
            Some(_) => SeqEvent::LateOrDuplicate,
        }
    }
}
