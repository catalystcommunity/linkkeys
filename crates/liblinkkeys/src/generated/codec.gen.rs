//! Generated self-contained canonical-CBOR codec from CSIL specification.
//!
//! CSIL is the CBOR Service Interface Language; this codec owns the payload
//! wire (a CBOR map keyed by the verbatim CSIL field name in canonical RFC
//! 8949 order) so the generated types need no serde derive. One
//! `encode_`/`decode_` pair is emitted per record type.
#![allow(dead_code, clippy::vec_init_then_push)]

use super::types::*;

/// A decode failure: the CBOR was malformed or did not match the expected shape.
#[derive(Debug, Clone, PartialEq)]
pub struct CsilCborError(pub String);

impl std::fmt::Display for CsilCborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CsilCborError {}

/// A minimal canonical-CBOR value tree: a closed set of variants the generated codec
/// builds and walks. A map is an ordered list of pairs, so the encoder controls the
/// wire order of a record's keys explicitly (laid down in canonical order).
#[derive(Debug, Clone, PartialEq)]
pub enum CsilCborValue {
    Uint(u64),
    Int(i64),
    Bool(bool),
    Float(f64),
    Null,
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<CsilCborValue>),
    Map(Vec<(CsilCborValue, CsilCborValue)>),
    Tag(u64, Box<CsilCborValue>),
}

fn cbor_int(x: i64) -> CsilCborValue {
    CsilCborValue::Int(x)
}
fn cbor_uint(x: u64) -> CsilCborValue {
    CsilCborValue::Uint(x)
}
fn cbor_float(x: f64) -> CsilCborValue {
    CsilCborValue::Float(x)
}
fn cbor_bool(x: bool) -> CsilCborValue {
    CsilCborValue::Bool(x)
}
fn cbor_text(x: &str) -> CsilCborValue {
    CsilCborValue::Text(x.to_string())
}
fn cbor_bytes(x: &[u8]) -> CsilCborValue {
    CsilCborValue::Bytes(x.to_vec())
}

/// Serialize a value tree to canonical CBOR bytes.
fn cbor_encode(v: &CsilCborValue) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_enc(v, &mut out);
    out
}

fn cbor_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let mt = major << 5;
    if n < 24 {
        out.push(mt | n as u8);
    } else if n < 0x100 {
        out.push(mt | 24);
        out.push(n as u8);
    } else if n < 0x10000 {
        out.push(mt | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n < 0x1_0000_0000 {
        out.push(mt | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn cbor_enc(v: &CsilCborValue, out: &mut Vec<u8>) {
    match v {
        CsilCborValue::Uint(x) => cbor_head(0, *x, out),
        // A non-negative `Int` rides major type 0 so it is byte-identical to a `Uint`
        // of the same magnitude; only a genuinely negative value uses major type 1.
        CsilCborValue::Int(x) => {
            if *x >= 0 {
                cbor_head(0, *x as u64, out);
            } else {
                cbor_head(1, (-(*x + 1)) as u64, out);
            }
        }
        CsilCborValue::Bool(x) => out.push(if *x { 0xf5 } else { 0xf4 }),
        CsilCborValue::Null => out.push(0xf6),
        CsilCborValue::Float(x) => {
            out.push(0xfb);
            out.extend_from_slice(&x.to_bits().to_be_bytes());
        }
        CsilCborValue::Text(s) => {
            let bytes = s.as_bytes();
            cbor_head(3, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        CsilCborValue::Bytes(b) => {
            cbor_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        CsilCborValue::Array(items) => {
            cbor_head(4, items.len() as u64, out);
            for item in items {
                cbor_enc(item, out);
            }
        }
        CsilCborValue::Map(entries) => {
            cbor_head(5, entries.len() as u64, out);
            for (k, val) in entries {
                cbor_enc(k, out);
                cbor_enc(val, out);
            }
        }
        CsilCborValue::Tag(num, inner) => {
            cbor_head(6, *num, out);
            cbor_enc(inner, out);
        }
    }
}

/// Parse a full CBOR item and reject trailing bytes, so a payload that is not
/// exactly one value is an error rather than a silently-truncated read.
fn cbor_decode(b: &[u8]) -> Result<CsilCborValue, CsilCborError> {
    let mut pos = 0usize;
    let v = cbor_dec(b, &mut pos)?;
    if pos != b.len() {
        return Err(CsilCborError(format!(
            "csil cbor: {} trailing bytes",
            b.len() - pos
        )));
    }
    Ok(v)
}

fn cbor_read_arg(b: &[u8], pos: &mut usize, low: u8) -> Result<u64, CsilCborError> {
    if low < 24 {
        *pos += 1;
        return Ok(low as u64);
    }
    let width = match low {
        24 => 1usize,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => {
            return Err(CsilCborError(format!(
                "csil cbor: reserved additional info {low}"
            )))
        }
    };
    if *pos + 1 + width > b.len() {
        return Err(CsilCborError("csil cbor: truncated argument".to_string()));
    }
    let mut v = 0u64;
    for &byte in &b[*pos + 1..*pos + 1 + width] {
        v = (v << 8) | byte as u64;
    }
    *pos += 1 + width;
    Ok(v)
}

fn cbor_dec(b: &[u8], pos: &mut usize) -> Result<CsilCborValue, CsilCborError> {
    if *pos >= b.len() {
        return Err(CsilCborError(
            "csil cbor: unexpected end of input".to_string(),
        ));
    }
    let ib = b[*pos];
    let major = ib >> 5;
    let low = ib & 0x1f;
    if major == 7 {
        return match low {
            20 => {
                *pos += 1;
                Ok(CsilCborValue::Bool(false))
            }
            21 => {
                *pos += 1;
                Ok(CsilCborValue::Bool(true))
            }
            22 | 23 => {
                *pos += 1;
                Ok(CsilCborValue::Null)
            }
            26 => {
                let bits = cbor_read_arg(b, pos, low)?;
                Ok(CsilCborValue::Float(f32::from_bits(bits as u32) as f64))
            }
            27 => {
                let bits = cbor_read_arg(b, pos, low)?;
                Ok(CsilCborValue::Float(f64::from_bits(bits)))
            }
            _ => Err(CsilCborError(format!(
                "csil cbor: unsupported simple value {low}"
            ))),
        };
    }
    let arg = cbor_read_arg(b, pos, low)?;
    match major {
        0 => Ok(CsilCborValue::Uint(arg)),
        1 => {
            if arg > i64::MAX as u64 {
                return Err(CsilCborError(
                    "csil cbor: negative integer out of range".to_string(),
                ));
            }
            Ok(CsilCborValue::Int(-1 - arg as i64))
        }
        2 => {
            let n = arg as usize;
            if *pos + n > b.len() {
                return Err(CsilCborError(
                    "csil cbor: truncated byte string".to_string(),
                ));
            }
            let slice = b[*pos..*pos + n].to_vec();
            *pos += n;
            Ok(CsilCborValue::Bytes(slice))
        }
        3 => {
            let n = arg as usize;
            if *pos + n > b.len() {
                return Err(CsilCborError(
                    "csil cbor: truncated text string".to_string(),
                ));
            }
            let s = std::str::from_utf8(&b[*pos..*pos + n])
                .map_err(|e| CsilCborError(format!("csil cbor: invalid utf-8: {e}")))?
                .to_string();
            *pos += n;
            Ok(CsilCborValue::Text(s))
        }
        4 => {
            let n = arg as usize;
            let mut items = Vec::with_capacity(n);
            for _ in 0..n {
                items.push(cbor_dec(b, pos)?);
            }
            Ok(CsilCborValue::Array(items))
        }
        5 => {
            let n = arg as usize;
            let mut entries = Vec::with_capacity(n);
            for _ in 0..n {
                let k = cbor_dec(b, pos)?;
                let val = cbor_dec(b, pos)?;
                entries.push((k, val));
            }
            Ok(CsilCborValue::Map(entries))
        }
        6 => {
            let inner = cbor_dec(b, pos)?;
            Ok(CsilCborValue::Tag(arg, Box::new(inner)))
        }
        _ => Err(CsilCborError(format!(
            "csil cbor: unexpected major type {major}"
        ))),
    }
}

/// Map a typed slice to a CBOR array via the per-element encoder.
fn cbor_enc_array<E>(xs: &[E], f: impl Fn(&E) -> CsilCborValue) -> CsilCborValue {
    CsilCborValue::Array(xs.iter().map(f).collect())
}

/// Map a typed map to a CBOR map. Rust `HashMap` iteration is unordered, so the inner
/// map's entry order is not canonicalized; the record's own keys (laid down at
/// generation time) are what the cross-language wire contract pins.
fn cbor_enc_map<K, V>(
    m: &std::collections::HashMap<K, V>,
    kf: impl Fn(&K) -> CsilCborValue,
    vf: impl Fn(&V) -> CsilCborValue,
) -> CsilCborValue {
    CsilCborValue::Map(m.iter().map(|(k, v)| (kf(k), vf(v))).collect())
}

fn cbor_dec_array<E>(
    v: &CsilCborValue,
    f: impl Fn(&CsilCborValue) -> Result<E, CsilCborError>,
) -> Result<Vec<E>, CsilCborError> {
    cbor_as_array(v)?.iter().map(f).collect()
}

fn cbor_dec_map<K: std::cmp::Eq + std::hash::Hash, V>(
    v: &CsilCborValue,
    kf: impl Fn(&CsilCborValue) -> Result<K, CsilCborError>,
    vf: impl Fn(&CsilCborValue) -> Result<V, CsilCborError>,
) -> Result<std::collections::HashMap<K, V>, CsilCborError> {
    let entries = cbor_as_map(v)?;
    let mut out = std::collections::HashMap::with_capacity(entries.len());
    for (k, val) in entries {
        out.insert(kf(k)?, vf(val)?);
    }
    Ok(out)
}

fn cbor_map_get<'a>(v: &'a CsilCborValue, key: &str) -> Option<&'a CsilCborValue> {
    if let CsilCborValue::Map(entries) = v {
        for (k, val) in entries {
            if matches!(k, CsilCborValue::Text(name) if name == key) {
                return Some(val);
            }
        }
    }
    None
}

fn cbor_expect_value(v: &CsilCborValue, expected: &CsilCborValue) -> Result<(), CsilCborError> {
    if v == expected {
        Ok(())
    } else {
        Err(CsilCborError(format!(
            "csil cbor: expected literal {expected:?}, got {v:?}"
        )))
    }
}

fn cbor_require<'a>(v: &'a CsilCborValue, key: &str) -> Result<&'a CsilCborValue, CsilCborError> {
    cbor_map_get(v, key).ok_or_else(|| CsilCborError(format!("csil cbor: missing field {key:?}")))
}

fn cbor_as_i64(v: &CsilCborValue) -> Result<i64, CsilCborError> {
    match v {
        CsilCborValue::Uint(x) => i64::try_from(*x)
            .map_err(|_| CsilCborError("csil cbor: integer overflows i64".to_string())),
        CsilCborValue::Int(x) => Ok(*x),
        _ => Err(CsilCborError("csil cbor: expected integer".to_string())),
    }
}

fn cbor_as_u64(v: &CsilCborValue) -> Result<u64, CsilCborError> {
    match v {
        CsilCborValue::Uint(x) => Ok(*x),
        CsilCborValue::Int(x) if *x >= 0 => Ok(*x as u64),
        CsilCborValue::Int(_) => Err(CsilCborError(
            "csil cbor: negative integer where unsigned expected".to_string(),
        )),
        _ => Err(CsilCborError(
            "csil cbor: expected unsigned integer".to_string(),
        )),
    }
}

fn cbor_as_f64(v: &CsilCborValue) -> Result<f64, CsilCborError> {
    match v {
        CsilCborValue::Float(x) => Ok(*x),
        CsilCborValue::Uint(x) => Ok(*x as f64),
        CsilCborValue::Int(x) => Ok(*x as f64),
        _ => Err(CsilCborError("csil cbor: expected float".to_string())),
    }
}

fn cbor_as_bool(v: &CsilCborValue) -> Result<bool, CsilCborError> {
    match v {
        CsilCborValue::Bool(b) => Ok(*b),
        _ => Err(CsilCborError("csil cbor: expected bool".to_string())),
    }
}

fn cbor_as_text(v: &CsilCborValue) -> Result<String, CsilCborError> {
    match v {
        CsilCborValue::Text(s) => Ok(s.clone()),
        _ => Err(CsilCborError("csil cbor: expected text".to_string())),
    }
}

fn cbor_as_bytes(v: &CsilCborValue) -> Result<Vec<u8>, CsilCborError> {
    match v {
        CsilCborValue::Bytes(b) => Ok(b.clone()),
        _ => Err(CsilCborError("csil cbor: expected byte string".to_string())),
    }
}

fn cbor_as_array(v: &CsilCborValue) -> Result<&[CsilCborValue], CsilCborError> {
    match v {
        CsilCborValue::Array(a) => Ok(a),
        _ => Err(CsilCborError("csil cbor: expected array".to_string())),
    }
}

fn cbor_as_map(v: &CsilCborValue) -> Result<&[(CsilCborValue, CsilCborValue)], CsilCborError> {
    match v {
        CsilCborValue::Map(m) => Ok(m),
        _ => Err(CsilCborError("csil cbor: expected map".to_string())),
    }
}

/// Build the canonical CBOR value tree for a CheckResult.
fn csil_enc_check_result(csil_v: &CheckResult) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("result"), cbor_bool(csil_v.result)));
    csil_entries.push((
        cbor_text("entries"),
        cbor_enc_map(
            &csil_v.entries,
            |csil_mk| cbor_text(csil_mk),
            csil_enc_check_value,
        ),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a CheckResult from a decoded CBOR value tree.
fn csil_dec_check_result(csil_root: &CsilCborValue) -> Result<CheckResult, CsilCborError> {
    let result = {
        let csil_field = cbor_require(csil_root, "result")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let entries = {
        let csil_field = cbor_require(csil_root, "entries")?;
        let csil_decode = |csil_v| cbor_dec_map(csil_v, cbor_as_text, csil_dec_check_value);
        csil_decode(csil_field)?
    };
    Ok(CheckResult { result, entries })
}

/// Encode a CheckResult to canonical CSIL CBOR bytes.
pub fn encode_check_result(csil_v: &CheckResult) -> Vec<u8> {
    cbor_encode(&csil_enc_check_result(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a CheckResult.
pub fn decode_check_result(csil_data: &[u8]) -> Result<CheckResult, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_check_result(&csil_root)
}

/// Build the canonical CBOR value tree for a HelloRequest.
fn csil_enc_hello_request(csil_v: &HelloRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    if let Some(csil_inner) = &csil_v.name {
        csil_entries.push((cbor_text("name"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a HelloRequest from a decoded CBOR value tree.
fn csil_dec_hello_request(csil_root: &CsilCborValue) -> Result<HelloRequest, CsilCborError> {
    let name = match cbor_map_get(csil_root, "name") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(HelloRequest { name })
}

/// Encode a HelloRequest to canonical CSIL CBOR bytes.
pub fn encode_hello_request(csil_v: &HelloRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_hello_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a HelloRequest.
pub fn decode_hello_request(csil_data: &[u8]) -> Result<HelloRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_hello_request(&csil_root)
}

/// Build the canonical CBOR value tree for a HelloResponse.
fn csil_enc_hello_response(csil_v: &HelloResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("greeting"), cbor_text(&csil_v.greeting)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a HelloResponse from a decoded CBOR value tree.
fn csil_dec_hello_response(csil_root: &CsilCborValue) -> Result<HelloResponse, CsilCborError> {
    let greeting = {
        let csil_field = cbor_require(csil_root, "greeting")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(HelloResponse { greeting })
}

/// Encode a HelloResponse to canonical CSIL CBOR bytes.
pub fn encode_hello_response(csil_v: &HelloResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_hello_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a HelloResponse.
pub fn decode_hello_response(csil_data: &[u8]) -> Result<HelloResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_hello_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GuestbookEntry.
fn csil_enc_guestbook_entry(csil_v: &GuestbookEntry) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("name"), cbor_text(&csil_v.name)));
    csil_entries.push((cbor_text("created_at"), cbor_text(&csil_v.created_at)));
    csil_entries.push((cbor_text("updated_at"), cbor_text(&csil_v.updated_at)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GuestbookEntry from a decoded CBOR value tree.
fn csil_dec_guestbook_entry(csil_root: &CsilCborValue) -> Result<GuestbookEntry, CsilCborError> {
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let name = {
        let csil_field = cbor_require(csil_root, "name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let updated_at = {
        let csil_field = cbor_require(csil_root, "updated_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GuestbookEntry {
        id,
        name,
        created_at,
        updated_at,
    })
}

/// Encode a GuestbookEntry to canonical CSIL CBOR bytes.
pub fn encode_guestbook_entry(csil_v: &GuestbookEntry) -> Vec<u8> {
    cbor_encode(&csil_enc_guestbook_entry(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GuestbookEntry.
pub fn decode_guestbook_entry(csil_data: &[u8]) -> Result<GuestbookEntry, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_guestbook_entry(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateGuestbookRequest.
fn csil_enc_create_guestbook_request(csil_v: &CreateGuestbookRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("name"), cbor_text(&csil_v.name)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a CreateGuestbookRequest from a decoded CBOR value tree.
fn csil_dec_create_guestbook_request(
    csil_root: &CsilCborValue,
) -> Result<CreateGuestbookRequest, CsilCborError> {
    let name = {
        let csil_field = cbor_require(csil_root, "name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(CreateGuestbookRequest { name })
}

/// Encode a CreateGuestbookRequest to canonical CSIL CBOR bytes.
pub fn encode_create_guestbook_request(csil_v: &CreateGuestbookRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_create_guestbook_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a CreateGuestbookRequest.
pub fn decode_create_guestbook_request(
    csil_data: &[u8],
) -> Result<CreateGuestbookRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_guestbook_request(&csil_root)
}

/// Build the canonical CBOR value tree for a UpdateGuestbookRequest.
fn csil_enc_update_guestbook_request(csil_v: &UpdateGuestbookRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("name"), cbor_text(&csil_v.name)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a UpdateGuestbookRequest from a decoded CBOR value tree.
fn csil_dec_update_guestbook_request(
    csil_root: &CsilCborValue,
) -> Result<UpdateGuestbookRequest, CsilCborError> {
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let name = {
        let csil_field = cbor_require(csil_root, "name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(UpdateGuestbookRequest { id, name })
}

/// Encode a UpdateGuestbookRequest to canonical CSIL CBOR bytes.
pub fn encode_update_guestbook_request(csil_v: &UpdateGuestbookRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_update_guestbook_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a UpdateGuestbookRequest.
pub fn decode_update_guestbook_request(
    csil_data: &[u8],
) -> Result<UpdateGuestbookRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_update_guestbook_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DeleteGuestbookRequest.
fn csil_enc_delete_guestbook_request(csil_v: &DeleteGuestbookRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a DeleteGuestbookRequest from a decoded CBOR value tree.
fn csil_dec_delete_guestbook_request(
    csil_root: &CsilCborValue,
) -> Result<DeleteGuestbookRequest, CsilCborError> {
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(DeleteGuestbookRequest { id })
}

/// Encode a DeleteGuestbookRequest to canonical CSIL CBOR bytes.
pub fn encode_delete_guestbook_request(csil_v: &DeleteGuestbookRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_delete_guestbook_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a DeleteGuestbookRequest.
pub fn decode_delete_guestbook_request(
    csil_data: &[u8],
) -> Result<DeleteGuestbookRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_delete_guestbook_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DeleteGuestbookResponse.
fn csil_enc_delete_guestbook_response(csil_v: &DeleteGuestbookResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a DeleteGuestbookResponse from a decoded CBOR value tree.
fn csil_dec_delete_guestbook_response(
    csil_root: &CsilCborValue,
) -> Result<DeleteGuestbookResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(DeleteGuestbookResponse { success })
}

/// Encode a DeleteGuestbookResponse to canonical CSIL CBOR bytes.
pub fn encode_delete_guestbook_response(csil_v: &DeleteGuestbookResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_delete_guestbook_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a DeleteGuestbookResponse.
pub fn decode_delete_guestbook_response(
    csil_data: &[u8],
) -> Result<DeleteGuestbookResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_delete_guestbook_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GuestbookListRequest.
fn csil_enc_guestbook_list_request(csil_v: &GuestbookListRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.limit {
        csil_entries.push((cbor_text("limit"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.offset {
        csil_entries.push((cbor_text("offset"), cbor_int(*csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GuestbookListRequest from a decoded CBOR value tree.
fn csil_dec_guestbook_list_request(
    csil_root: &CsilCborValue,
) -> Result<GuestbookListRequest, CsilCborError> {
    let offset = match cbor_map_get(csil_root, "offset") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let limit = match cbor_map_get(csil_root, "limit") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(GuestbookListRequest { offset, limit })
}

/// Encode a GuestbookListRequest to canonical CSIL CBOR bytes.
pub fn encode_guestbook_list_request(csil_v: &GuestbookListRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_guestbook_list_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GuestbookListRequest.
pub fn decode_guestbook_list_request(
    csil_data: &[u8],
) -> Result<GuestbookListRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_guestbook_list_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GuestbookListResponse.
fn csil_enc_guestbook_list_response(csil_v: &GuestbookListResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("entries"),
        cbor_enc_array(&csil_v.entries, csil_enc_guestbook_entry),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GuestbookListResponse from a decoded CBOR value tree.
fn csil_dec_guestbook_list_response(
    csil_root: &CsilCborValue,
) -> Result<GuestbookListResponse, CsilCborError> {
    let entries = {
        let csil_field = cbor_require(csil_root, "entries")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_guestbook_entry);
        csil_decode(csil_field)?
    };
    Ok(GuestbookListResponse { entries })
}

/// Encode a GuestbookListResponse to canonical CSIL CBOR bytes.
pub fn encode_guestbook_list_response(csil_v: &GuestbookListResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_guestbook_list_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GuestbookListResponse.
pub fn decode_guestbook_list_response(
    csil_data: &[u8],
) -> Result<GuestbookListResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_guestbook_list_response(&csil_root)
}

/// Build the canonical CBOR value tree for a EmptyRequest.
fn csil_enc_empty_request(_csil_v: &EmptyRequest) -> CsilCborValue {
    CsilCborValue::Map(Vec::new())
}

/// Reconstruct a EmptyRequest from a decoded CBOR value tree.
fn csil_dec_empty_request(_csil_root: &CsilCborValue) -> Result<EmptyRequest, CsilCborError> {
    Ok(EmptyRequest {})
}

/// Encode a EmptyRequest to canonical CSIL CBOR bytes.
pub fn encode_empty_request(csil_v: &EmptyRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_empty_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a EmptyRequest.
pub fn decode_empty_request(csil_data: &[u8]) -> Result<EmptyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_empty_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DomainPublicKey.
fn csil_enc_domain_public_key(csil_v: &DomainPublicKey) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(10);
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    csil_entries.push((cbor_text("algorithm"), cbor_text(&csil_v.algorithm)));
    csil_entries.push((cbor_text("key_usage"), cbor_text(&csil_v.key_usage)));
    csil_entries.push((cbor_text("created_at"), cbor_text(&csil_v.created_at)));
    csil_entries.push((cbor_text("expires_at"), cbor_text(&csil_v.expires_at)));
    csil_entries.push((cbor_text("public_key"), cbor_bytes(&csil_v.public_key)));
    if let Some(csil_inner) = &csil_v.revoked_at {
        csil_entries.push((cbor_text("revoked_at"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    if let Some(csil_inner) = &csil_v.key_signature {
        csil_entries.push((cbor_text("key_signature"), cbor_bytes(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.signed_by_key_id {
        csil_entries.push((cbor_text("signed_by_key_id"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a DomainPublicKey from a decoded CBOR value tree.
fn csil_dec_domain_public_key(csil_root: &CsilCborValue) -> Result<DomainPublicKey, CsilCborError> {
    let key_id = {
        let csil_field = cbor_require(csil_root, "key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let public_key = {
        let csil_field = cbor_require(csil_root, "public_key")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let algorithm = {
        let csil_field = cbor_require(csil_root, "algorithm")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let key_usage = {
        let csil_field = cbor_require(csil_root, "key_usage")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let revoked_at = match cbor_map_get(csil_root, "revoked_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let signed_by_key_id = match cbor_map_get(csil_root, "signed_by_key_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let key_signature = match cbor_map_get(csil_root, "key_signature") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bytes;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(DomainPublicKey {
        key_id,
        public_key,
        fingerprint,
        algorithm,
        key_usage,
        created_at,
        expires_at,
        revoked_at,
        signed_by_key_id,
        key_signature,
    })
}

/// Encode a DomainPublicKey to canonical CSIL CBOR bytes.
pub fn encode_domain_public_key(csil_v: &DomainPublicKey) -> Vec<u8> {
    cbor_encode(&csil_enc_domain_public_key(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a DomainPublicKey.
pub fn decode_domain_public_key(csil_data: &[u8]) -> Result<DomainPublicKey, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_domain_public_key(&csil_root)
}

/// Build the canonical CBOR value tree for a GetDomainKeysResponse.
fn csil_enc_get_domain_keys_response(csil_v: &GetDomainKeysResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("keys"),
        cbor_enc_array(&csil_v.keys, csil_enc_domain_public_key),
    ));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    if let Some(csil_inner) = &csil_v.recent_revocations_available {
        csil_entries.push((
            cbor_text("recent_revocations_available"),
            cbor_bool(*csil_inner),
        ));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetDomainKeysResponse from a decoded CBOR value tree.
fn csil_dec_get_domain_keys_response(
    csil_root: &CsilCborValue,
) -> Result<GetDomainKeysResponse, CsilCborError> {
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let keys = {
        let csil_field = cbor_require(csil_root, "keys")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_domain_public_key);
        csil_decode(csil_field)?
    };
    let recent_revocations_available = match cbor_map_get(csil_root, "recent_revocations_available")
    {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(GetDomainKeysResponse {
        domain,
        keys,
        recent_revocations_available,
    })
}

/// Encode a GetDomainKeysResponse to canonical CSIL CBOR bytes.
pub fn encode_get_domain_keys_response(csil_v: &GetDomainKeysResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_get_domain_keys_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetDomainKeysResponse.
pub fn decode_get_domain_keys_response(
    csil_data: &[u8],
) -> Result<GetDomainKeysResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_domain_keys_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetRevocationsRequest.
fn csil_enc_get_revocations_request(csil_v: &GetRevocationsRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    if let Some(csil_inner) = &csil_v.since {
        csil_entries.push((cbor_text("since"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetRevocationsRequest from a decoded CBOR value tree.
fn csil_dec_get_revocations_request(
    csil_root: &CsilCborValue,
) -> Result<GetRevocationsRequest, CsilCborError> {
    let since = match cbor_map_get(csil_root, "since") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(GetRevocationsRequest { since })
}

/// Encode a GetRevocationsRequest to canonical CSIL CBOR bytes.
pub fn encode_get_revocations_request(csil_v: &GetRevocationsRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_get_revocations_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetRevocationsRequest.
pub fn decode_get_revocations_request(
    csil_data: &[u8],
) -> Result<GetRevocationsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_revocations_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetRevocationsResponse.
fn csil_enc_get_revocations_response(csil_v: &GetRevocationsResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("revocations"),
        cbor_enc_array(&csil_v.revocations, csil_enc_revocation_certificate),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetRevocationsResponse from a decoded CBOR value tree.
fn csil_dec_get_revocations_response(
    csil_root: &CsilCborValue,
) -> Result<GetRevocationsResponse, CsilCborError> {
    let revocations = {
        let csil_field = cbor_require(csil_root, "revocations")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_revocation_certificate);
        csil_decode(csil_field)?
    };
    Ok(GetRevocationsResponse { revocations })
}

/// Encode a GetRevocationsResponse to canonical CSIL CBOR bytes.
pub fn encode_get_revocations_response(csil_v: &GetRevocationsResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_get_revocations_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetRevocationsResponse.
pub fn decode_get_revocations_response(
    csil_data: &[u8],
) -> Result<GetRevocationsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_revocations_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RecheckPinsRequest.
fn csil_enc_recheck_pins_request(csil_v: &RecheckPinsRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    if let Some(csil_inner) = &csil_v.domain {
        csil_entries.push((cbor_text("domain"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RecheckPinsRequest from a decoded CBOR value tree.
fn csil_dec_recheck_pins_request(
    csil_root: &CsilCborValue,
) -> Result<RecheckPinsRequest, CsilCborError> {
    let domain = match cbor_map_get(csil_root, "domain") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(RecheckPinsRequest { domain })
}

/// Encode a RecheckPinsRequest to canonical CSIL CBOR bytes.
pub fn encode_recheck_pins_request(csil_v: &RecheckPinsRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_recheck_pins_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RecheckPinsRequest.
pub fn decode_recheck_pins_request(csil_data: &[u8]) -> Result<RecheckPinsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_recheck_pins_request(&csil_root)
}

/// Build the canonical CBOR value tree for a PinRecheckResult.
fn csil_enc_pin_recheck_result(csil_v: &PinRecheckResult) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("outcome"), cbor_text(&csil_v.outcome)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a PinRecheckResult from a decoded CBOR value tree.
fn csil_dec_pin_recheck_result(
    csil_root: &CsilCborValue,
) -> Result<PinRecheckResult, CsilCborError> {
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let outcome = {
        let csil_field = cbor_require(csil_root, "outcome")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(PinRecheckResult { domain, outcome })
}

/// Encode a PinRecheckResult to canonical CSIL CBOR bytes.
pub fn encode_pin_recheck_result(csil_v: &PinRecheckResult) -> Vec<u8> {
    cbor_encode(&csil_enc_pin_recheck_result(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a PinRecheckResult.
pub fn decode_pin_recheck_result(csil_data: &[u8]) -> Result<PinRecheckResult, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_pin_recheck_result(&csil_root)
}

/// Build the canonical CBOR value tree for a RecheckPinsResponse.
fn csil_enc_recheck_pins_response(csil_v: &RecheckPinsResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("results"),
        cbor_enc_array(&csil_v.results, csil_enc_pin_recheck_result),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RecheckPinsResponse from a decoded CBOR value tree.
fn csil_dec_recheck_pins_response(
    csil_root: &CsilCborValue,
) -> Result<RecheckPinsResponse, CsilCborError> {
    let results = {
        let csil_field = cbor_require(csil_root, "results")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_pin_recheck_result);
        csil_decode(csil_field)?
    };
    Ok(RecheckPinsResponse { results })
}

/// Encode a RecheckPinsResponse to canonical CSIL CBOR bytes.
pub fn encode_recheck_pins_response(csil_v: &RecheckPinsResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_recheck_pins_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RecheckPinsResponse.
pub fn decode_recheck_pins_response(
    csil_data: &[u8],
) -> Result<RecheckPinsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_recheck_pins_response(&csil_root)
}

/// Build the canonical CBOR value tree for a UserPublicKey.
fn csil_enc_user_public_key(csil_v: &UserPublicKey) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("algorithm"), cbor_text(&csil_v.algorithm)));
    csil_entries.push((cbor_text("key_usage"), cbor_text(&csil_v.key_usage)));
    csil_entries.push((cbor_text("created_at"), cbor_text(&csil_v.created_at)));
    csil_entries.push((cbor_text("expires_at"), cbor_text(&csil_v.expires_at)));
    csil_entries.push((cbor_text("public_key"), cbor_bytes(&csil_v.public_key)));
    if let Some(csil_inner) = &csil_v.revoked_at {
        csil_entries.push((cbor_text("revoked_at"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    if let Some(csil_inner) = &csil_v.key_signature {
        csil_entries.push((cbor_text("key_signature"), cbor_bytes(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.signed_by_key_id {
        csil_entries.push((cbor_text("signed_by_key_id"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a UserPublicKey from a decoded CBOR value tree.
fn csil_dec_user_public_key(csil_root: &CsilCborValue) -> Result<UserPublicKey, CsilCborError> {
    let key_id = {
        let csil_field = cbor_require(csil_root, "key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let public_key = {
        let csil_field = cbor_require(csil_root, "public_key")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let algorithm = {
        let csil_field = cbor_require(csil_root, "algorithm")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let key_usage = {
        let csil_field = cbor_require(csil_root, "key_usage")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let revoked_at = match cbor_map_get(csil_root, "revoked_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let signed_by_key_id = match cbor_map_get(csil_root, "signed_by_key_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let key_signature = match cbor_map_get(csil_root, "key_signature") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bytes;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(UserPublicKey {
        key_id,
        user_id,
        public_key,
        fingerprint,
        algorithm,
        key_usage,
        created_at,
        expires_at,
        revoked_at,
        signed_by_key_id,
        key_signature,
    })
}

/// Encode a UserPublicKey to canonical CSIL CBOR bytes.
pub fn encode_user_public_key(csil_v: &UserPublicKey) -> Vec<u8> {
    cbor_encode(&csil_enc_user_public_key(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a UserPublicKey.
pub fn decode_user_public_key(csil_data: &[u8]) -> Result<UserPublicKey, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_user_public_key(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserKeysRequest.
fn csil_enc_get_user_keys_request(csil_v: &GetUserKeysRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetUserKeysRequest from a decoded CBOR value tree.
fn csil_dec_get_user_keys_request(
    csil_root: &CsilCborValue,
) -> Result<GetUserKeysRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GetUserKeysRequest { user_id })
}

/// Encode a GetUserKeysRequest to canonical CSIL CBOR bytes.
pub fn encode_get_user_keys_request(csil_v: &GetUserKeysRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_get_user_keys_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetUserKeysRequest.
pub fn decode_get_user_keys_request(csil_data: &[u8]) -> Result<GetUserKeysRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_keys_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserKeysResponse.
fn csil_enc_get_user_keys_response(csil_v: &GetUserKeysResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("keys"),
        cbor_enc_array(&csil_v.keys, csil_enc_user_public_key),
    ));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetUserKeysResponse from a decoded CBOR value tree.
fn csil_dec_get_user_keys_response(
    csil_root: &CsilCborValue,
) -> Result<GetUserKeysResponse, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let keys = {
        let csil_field = cbor_require(csil_root, "keys")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_user_public_key);
        csil_decode(csil_field)?
    };
    Ok(GetUserKeysResponse {
        user_id,
        domain,
        keys,
    })
}

/// Encode a GetUserKeysResponse to canonical CSIL CBOR bytes.
pub fn encode_get_user_keys_response(csil_v: &GetUserKeysResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_get_user_keys_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetUserKeysResponse.
pub fn decode_get_user_keys_response(
    csil_data: &[u8],
) -> Result<GetUserKeysResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_keys_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimSignature.
fn csil_enc_claim_signature(csil_v: &ClaimSignature) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((
        cbor_text("signed_by_key_id"),
        cbor_text(&csil_v.signed_by_key_id),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ClaimSignature from a decoded CBOR value tree.
fn csil_dec_claim_signature(csil_root: &CsilCborValue) -> Result<ClaimSignature, CsilCborError> {
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signed_by_key_id = {
        let csil_field = cbor_require(csil_root, "signed_by_key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signature = {
        let csil_field = cbor_require(csil_root, "signature")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(ClaimSignature {
        domain,
        signed_by_key_id,
        signature,
    })
}

/// Encode a ClaimSignature to canonical CSIL CBOR bytes.
pub fn encode_claim_signature(csil_v: &ClaimSignature) -> Vec<u8> {
    cbor_encode(&csil_enc_claim_signature(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ClaimSignature.
pub fn decode_claim_signature(csil_data: &[u8]) -> Result<ClaimSignature, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_signature(&csil_root)
}

/// Build the canonical CBOR value tree for a RevocationCertificate.
fn csil_enc_revocation_certificate(csil_v: &RevocationCertificate) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("revoked_at"), cbor_text(&csil_v.revoked_at)));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature),
    ));
    csil_entries.push((cbor_text("target_key_id"), cbor_text(&csil_v.target_key_id)));
    csil_entries.push((
        cbor_text("target_fingerprint"),
        cbor_text(&csil_v.target_fingerprint),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RevocationCertificate from a decoded CBOR value tree.
fn csil_dec_revocation_certificate(
    csil_root: &CsilCborValue,
) -> Result<RevocationCertificate, CsilCborError> {
    let target_key_id = {
        let csil_field = cbor_require(csil_root, "target_key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let target_fingerprint = {
        let csil_field = cbor_require(csil_root, "target_fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let revoked_at = {
        let csil_field = cbor_require(csil_root, "revoked_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_signature);
        csil_decode(csil_field)?
    };
    Ok(RevocationCertificate {
        target_key_id,
        target_fingerprint,
        revoked_at,
        signatures,
    })
}

/// Encode a RevocationCertificate to canonical CSIL CBOR bytes.
pub fn encode_revocation_certificate(csil_v: &RevocationCertificate) -> Vec<u8> {
    cbor_encode(&csil_enc_revocation_certificate(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RevocationCertificate.
pub fn decode_revocation_certificate(
    csil_data: &[u8],
) -> Result<RevocationCertificate, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revocation_certificate(&csil_root)
}

/// Build the canonical CBOR value tree for a Claim.
fn csil_enc_claim(csil_v: &Claim) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("claim_id"), cbor_text(&csil_v.claim_id)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("created_at"), cbor_text(&csil_v.created_at)));
    if let Some(csil_inner) = &csil_v.expires_at {
        csil_entries.push((cbor_text("expires_at"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.revoked_at {
        csil_entries.push((cbor_text("revoked_at"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature),
    ));
    csil_entries.push((cbor_text("attested_at"), cbor_text(&csil_v.attested_at)));
    csil_entries.push((cbor_text("claim_value"), cbor_bytes(&csil_v.claim_value)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a Claim from a decoded CBOR value tree.
fn csil_dec_claim(csil_root: &CsilCborValue) -> Result<Claim, CsilCborError> {
    let claim_id = {
        let csil_field = cbor_require(csil_root, "claim_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_value = {
        let csil_field = cbor_require(csil_root, "claim_value")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_signature);
        csil_decode(csil_field)?
    };
    let attested_at = {
        let csil_field = cbor_require(csil_root, "attested_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = match cbor_map_get(csil_root, "expires_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let revoked_at = match cbor_map_get(csil_root, "revoked_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(Claim {
        claim_id,
        user_id,
        claim_type,
        claim_value,
        signatures,
        attested_at,
        created_at,
        expires_at,
        revoked_at,
    })
}

/// Encode a Claim to canonical CSIL CBOR bytes.
pub fn encode_claim(csil_v: &Claim) -> Vec<u8> {
    cbor_encode(&csil_enc_claim(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a Claim.
pub fn decode_claim(csil_data: &[u8]) -> Result<Claim, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserClaimsRequest.
fn csil_enc_get_user_claims_request(csil_v: &GetUserClaimsRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("token"), cbor_bytes(&csil_v.token)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetUserClaimsRequest from a decoded CBOR value tree.
fn csil_dec_get_user_claims_request(
    csil_root: &CsilCborValue,
) -> Result<GetUserClaimsRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let token = {
        let csil_field = cbor_require(csil_root, "token")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(GetUserClaimsRequest { user_id, token })
}

/// Encode a GetUserClaimsRequest to canonical CSIL CBOR bytes.
pub fn encode_get_user_claims_request(csil_v: &GetUserClaimsRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_get_user_claims_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetUserClaimsRequest.
pub fn decode_get_user_claims_request(
    csil_data: &[u8],
) -> Result<GetUserClaimsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_claims_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserClaimsResponse.
fn csil_enc_get_user_claims_response(csil_v: &GetUserClaimsResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim),
    ));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetUserClaimsResponse from a decoded CBOR value tree.
fn csil_dec_get_user_claims_response(
    csil_root: &CsilCborValue,
) -> Result<GetUserClaimsResponse, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claims = {
        let csil_field = cbor_require(csil_root, "claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim);
        csil_decode(csil_field)?
    };
    Ok(GetUserClaimsResponse {
        user_id,
        domain,
        claims,
    })
}

/// Encode a GetUserClaimsResponse to canonical CSIL CBOR bytes.
pub fn encode_get_user_claims_response(csil_v: &GetUserClaimsResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_get_user_claims_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetUserClaimsResponse.
pub fn decode_get_user_claims_response(
    csil_data: &[u8],
) -> Result<GetUserClaimsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_claims_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RequestedClaim.
fn csil_enc_requested_claim(csil_v: &RequestedClaim) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("datatype"), cbor_text(&csil_v.datatype)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RequestedClaim from a decoded CBOR value tree.
fn csil_dec_requested_claim(csil_root: &CsilCborValue) -> Result<RequestedClaim, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let datatype = {
        let csil_field = cbor_require(csil_root, "datatype")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RequestedClaim {
        claim_type,
        datatype,
    })
}

/// Encode a RequestedClaim to canonical CSIL CBOR bytes.
pub fn encode_requested_claim(csil_v: &RequestedClaim) -> Vec<u8> {
    cbor_encode(&csil_enc_requested_claim(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RequestedClaim.
pub fn decode_requested_claim(csil_data: &[u8]) -> Result<RequestedClaim, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_requested_claim(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimRequest.
fn csil_enc_claim_request(csil_v: &ClaimRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("optional"),
        cbor_enc_array(&csil_v.optional, csil_enc_requested_claim),
    ));
    csil_entries.push((
        cbor_text("required"),
        cbor_enc_array(&csil_v.required, csil_enc_requested_claim),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ClaimRequest from a decoded CBOR value tree.
fn csil_dec_claim_request(csil_root: &CsilCborValue) -> Result<ClaimRequest, CsilCborError> {
    let required = {
        let csil_field = cbor_require(csil_root, "required")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_requested_claim);
        csil_decode(csil_field)?
    };
    let optional = {
        let csil_field = cbor_require(csil_root, "optional")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_requested_claim);
        csil_decode(csil_field)?
    };
    Ok(ClaimRequest { required, optional })
}

/// Encode a ClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_claim_request(csil_v: &ClaimRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_claim_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ClaimRequest.
pub fn decode_claim_request(csil_data: &[u8]) -> Result<ClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthFlowContext.
fn csil_enc_auth_flow_context(csil_v: &AuthFlowContext) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("flow"), cbor_text(&csil_v.flow)));
    if let Some(csil_inner) = &csil_v.prior_session {
        csil_entries.push((cbor_text("prior_session"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.request_reason {
        csil_entries.push((cbor_text("request_reason"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AuthFlowContext from a decoded CBOR value tree.
fn csil_dec_auth_flow_context(csil_root: &CsilCborValue) -> Result<AuthFlowContext, CsilCborError> {
    let flow = {
        let csil_field = cbor_require(csil_root, "flow")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let prior_session = match cbor_map_get(csil_root, "prior_session") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let request_reason = match cbor_map_get(csil_root, "request_reason") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(AuthFlowContext {
        flow,
        prior_session,
        request_reason,
    })
}

/// Encode a AuthFlowContext to canonical CSIL CBOR bytes.
pub fn encode_auth_flow_context(csil_v: &AuthFlowContext) -> Vec<u8> {
    cbor_encode(&csil_enc_auth_flow_context(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AuthFlowContext.
pub fn decode_auth_flow_context(csil_data: &[u8]) -> Result<AuthFlowContext, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_auth_flow_context(&csil_root)
}

/// Build the canonical CBOR value tree for a ConsentGrant.
fn csil_enc_consent_grant(csil_v: &ConsentGrant) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((cbor_text("grant_id"), cbor_text(&csil_v.grant_id)));
    csil_entries.push((cbor_text("issued_at"), cbor_text(&csil_v.issued_at)));
    csil_entries.push((cbor_text("expires_at"), cbor_text(&csil_v.expires_at)));
    if let Some(csil_inner) = &csil_v.revoked_at {
        csil_entries.push((cbor_text("revoked_at"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("claim_types"),
        cbor_enc_array(&csil_v.claim_types, |csil_elem| cbor_text(csil_elem)),
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ConsentGrant from a decoded CBOR value tree.
fn csil_dec_consent_grant(csil_root: &CsilCborValue) -> Result<ConsentGrant, CsilCborError> {
    let grant_id = {
        let csil_field = cbor_require(csil_root, "grant_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let subject_domain = {
        let csil_field = cbor_require(csil_root, "subject_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_types = {
        let csil_field = cbor_require(csil_root, "claim_types")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let revoked_at = match cbor_map_get(csil_root, "revoked_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ConsentGrant {
        grant_id,
        user_id,
        subject_domain,
        audience,
        claim_types,
        issued_at,
        expires_at,
        revoked_at,
    })
}

/// Encode a ConsentGrant to canonical CSIL CBOR bytes.
pub fn encode_consent_grant(csil_v: &ConsentGrant) -> Vec<u8> {
    cbor_encode(&csil_enc_consent_grant(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ConsentGrant.
pub fn decode_consent_grant(csil_data: &[u8]) -> Result<ConsentGrant, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_consent_grant(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedConsentGrant.
fn csil_enc_signed_consent_grant(csil_v: &SignedConsentGrant) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("grant"), cbor_bytes(&csil_v.grant)));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SignedConsentGrant from a decoded CBOR value tree.
fn csil_dec_signed_consent_grant(
    csil_root: &CsilCborValue,
) -> Result<SignedConsentGrant, CsilCborError> {
    let grant = {
        let csil_field = cbor_require(csil_root, "grant")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_signature);
        csil_decode(csil_field)?
    };
    Ok(SignedConsentGrant { grant, signatures })
}

/// Encode a SignedConsentGrant to canonical CSIL CBOR bytes.
pub fn encode_signed_consent_grant(csil_v: &SignedConsentGrant) -> Vec<u8> {
    cbor_encode(&csil_enc_signed_consent_grant(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SignedConsentGrant.
pub fn decode_signed_consent_grant(csil_data: &[u8]) -> Result<SignedConsentGrant, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_consent_grant(&csil_root)
}

/// Build the canonical CBOR value tree for a DomainClaim.
fn csil_enc_domain_claim(csil_v: &DomainClaim) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    if let Some(csil_inner) = &csil_v.expires_at {
        csil_entries.push((cbor_text("expires_at"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature),
    ));
    csil_entries.push((cbor_text("claim_value"), cbor_bytes(&csil_v.claim_value)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a DomainClaim from a decoded CBOR value tree.
fn csil_dec_domain_claim(csil_root: &CsilCborValue) -> Result<DomainClaim, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_value = {
        let csil_field = cbor_require(csil_root, "claim_value")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_signature);
        csil_decode(csil_field)?
    };
    let expires_at = match cbor_map_get(csil_root, "expires_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(DomainClaim {
        claim_type,
        claim_value,
        signatures,
        expires_at,
    })
}

/// Encode a DomainClaim to canonical CSIL CBOR bytes.
pub fn encode_domain_claim(csil_v: &DomainClaim) -> Vec<u8> {
    cbor_encode(&csil_enc_domain_claim(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a DomainClaim.
pub fn decode_domain_claim(csil_data: &[u8]) -> Result<DomainClaim, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_domain_claim(&csil_root)
}

/// Build the canonical CBOR value tree for a SigningRequest.
fn csil_enc_signing_request(csil_v: &SigningRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    if let Some(csil_inner) = &csil_v.callback {
        csil_entries.push((cbor_text("callback"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("issued_at"), cbor_text(&csil_v.issued_at)));
    csil_entries.push((cbor_text("expires_at"), cbor_text(&csil_v.expires_at)));
    csil_entries.push((cbor_text("request_id"), cbor_text(&csil_v.request_id)));
    csil_entries.push((cbor_text("issuer_domain"), cbor_text(&csil_v.issuer_domain)));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    csil_entries.push((
        cbor_text("requested_claim_types"),
        cbor_enc_array(&csil_v.requested_claim_types, |csil_elem| {
            cbor_text(csil_elem)
        }),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SigningRequest from a decoded CBOR value tree.
fn csil_dec_signing_request(csil_root: &CsilCborValue) -> Result<SigningRequest, CsilCborError> {
    let request_id = {
        let csil_field = cbor_require(csil_root, "request_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let subject_user_id = {
        let csil_field = cbor_require(csil_root, "subject_user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let subject_domain = {
        let csil_field = cbor_require(csil_root, "subject_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let issuer_domain = {
        let csil_field = cbor_require(csil_root, "issuer_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let requested_claim_types = {
        let csil_field = cbor_require(csil_root, "requested_claim_types")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let callback = match cbor_map_get(csil_root, "callback") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(SigningRequest {
        request_id,
        subject_user_id,
        subject_domain,
        issuer_domain,
        requested_claim_types,
        nonce,
        issued_at,
        expires_at,
        callback,
    })
}

/// Encode a SigningRequest to canonical CSIL CBOR bytes.
pub fn encode_signing_request(csil_v: &SigningRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_signing_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SigningRequest.
pub fn decode_signing_request(csil_data: &[u8]) -> Result<SigningRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signing_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedSigningRequest.
fn csil_enc_signed_signing_request(csil_v: &SignedSigningRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SignedSigningRequest from a decoded CBOR value tree.
fn csil_dec_signed_signing_request(
    csil_root: &CsilCborValue,
) -> Result<SignedSigningRequest, CsilCborError> {
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_signature);
        csil_decode(csil_field)?
    };
    Ok(SignedSigningRequest {
        request,
        signatures,
    })
}

/// Encode a SignedSigningRequest to canonical CSIL CBOR bytes.
pub fn encode_signed_signing_request(csil_v: &SignedSigningRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_signed_signing_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SignedSigningRequest.
pub fn decode_signed_signing_request(
    csil_data: &[u8],
) -> Result<SignedSigningRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_signing_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DepositClaimRequest.
fn csil_enc_deposit_claim_request(csil_v: &DepositClaimRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim"), csil_enc_claim(&csil_v.claim)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a DepositClaimRequest from a decoded CBOR value tree.
fn csil_dec_deposit_claim_request(
    csil_root: &CsilCborValue,
) -> Result<DepositClaimRequest, CsilCborError> {
    let claim = {
        let csil_field = cbor_require(csil_root, "claim")?;
        let csil_decode = csil_dec_claim;
        csil_decode(csil_field)?
    };
    Ok(DepositClaimRequest { claim })
}

/// Encode a DepositClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_deposit_claim_request(csil_v: &DepositClaimRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_deposit_claim_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a DepositClaimRequest.
pub fn decode_deposit_claim_request(
    csil_data: &[u8],
) -> Result<DepositClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deposit_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DepositClaimResponse.
fn csil_enc_deposit_claim_response(csil_v: &DepositClaimResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("stored"), cbor_bool(csil_v.stored)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a DepositClaimResponse from a decoded CBOR value tree.
fn csil_dec_deposit_claim_response(
    csil_root: &CsilCborValue,
) -> Result<DepositClaimResponse, CsilCborError> {
    let stored = {
        let csil_field = cbor_require(csil_root, "stored")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(DepositClaimResponse { stored })
}

/// Encode a DepositClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_deposit_claim_response(csil_v: &DepositClaimResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_deposit_claim_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a DepositClaimResponse.
pub fn decode_deposit_claim_response(
    csil_data: &[u8],
) -> Result<DepositClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deposit_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a IdentityAssertion.
fn csil_enc_identity_assertion(csil_v: &IdentityAssertion) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((cbor_text("issued_at"), cbor_text(&csil_v.issued_at)));
    csil_entries.push((cbor_text("expires_at"), cbor_text(&csil_v.expires_at)));
    if let Some(csil_inner) = &csil_v.display_name {
        csil_entries.push((cbor_text("display_name"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("authorized_claims"),
        cbor_enc_array(&csil_v.authorized_claims, |csil_elem| cbor_text(csil_elem)),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a IdentityAssertion from a decoded CBOR value tree.
fn csil_dec_identity_assertion(
    csil_root: &CsilCborValue,
) -> Result<IdentityAssertion, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let authorized_claims = {
        let csil_field = cbor_require(csil_root, "authorized_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let display_name = match cbor_map_get(csil_root, "display_name") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(IdentityAssertion {
        user_id,
        domain,
        audience,
        nonce,
        issued_at,
        expires_at,
        authorized_claims,
        display_name,
    })
}

/// Encode a IdentityAssertion to canonical CSIL CBOR bytes.
pub fn encode_identity_assertion(csil_v: &IdentityAssertion) -> Vec<u8> {
    cbor_encode(&csil_enc_identity_assertion(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a IdentityAssertion.
pub fn decode_identity_assertion(csil_data: &[u8]) -> Result<IdentityAssertion, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_identity_assertion(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedIdentityAssertion.
fn csil_enc_signed_identity_assertion(csil_v: &SignedIdentityAssertion) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("assertion"), cbor_bytes(&csil_v.assertion)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((
        cbor_text("signing_key_id"),
        cbor_text(&csil_v.signing_key_id),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SignedIdentityAssertion from a decoded CBOR value tree.
fn csil_dec_signed_identity_assertion(
    csil_root: &CsilCborValue,
) -> Result<SignedIdentityAssertion, CsilCborError> {
    let assertion = {
        let csil_field = cbor_require(csil_root, "assertion")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signing_key_id = {
        let csil_field = cbor_require(csil_root, "signing_key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signature = {
        let csil_field = cbor_require(csil_root, "signature")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(SignedIdentityAssertion {
        assertion,
        signing_key_id,
        signature,
    })
}

/// Encode a SignedIdentityAssertion to canonical CSIL CBOR bytes.
pub fn encode_signed_identity_assertion(csil_v: &SignedIdentityAssertion) -> Vec<u8> {
    cbor_encode(&csil_enc_signed_identity_assertion(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SignedIdentityAssertion.
pub fn decode_signed_identity_assertion(
    csil_data: &[u8],
) -> Result<SignedIdentityAssertion, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_identity_assertion(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserInfoRequest.
fn csil_enc_get_user_info_request(csil_v: &GetUserInfoRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("token"), cbor_bytes(&csil_v.token)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetUserInfoRequest from a decoded CBOR value tree.
fn csil_dec_get_user_info_request(
    csil_root: &CsilCborValue,
) -> Result<GetUserInfoRequest, CsilCborError> {
    let token = {
        let csil_field = cbor_require(csil_root, "token")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(GetUserInfoRequest { token })
}

/// Encode a GetUserInfoRequest to canonical CSIL CBOR bytes.
pub fn encode_get_user_info_request(csil_v: &GetUserInfoRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_get_user_info_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetUserInfoRequest.
pub fn decode_get_user_info_request(csil_data: &[u8]) -> Result<GetUserInfoRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_info_request(&csil_root)
}

/// Build the canonical CBOR value tree for a UserInfoRequest.
fn csil_enc_user_info_request(csil_v: &UserInfoRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    csil_entries.push((cbor_text("token"), cbor_bytes(&csil_v.token)));
    csil_entries.push((cbor_text("timestamp"), cbor_text(&csil_v.timestamp)));
    csil_entries.push((cbor_text("relying_party"), cbor_text(&csil_v.relying_party)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a UserInfoRequest from a decoded CBOR value tree.
fn csil_dec_user_info_request(csil_root: &CsilCborValue) -> Result<UserInfoRequest, CsilCborError> {
    let token = {
        let csil_field = cbor_require(csil_root, "token")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let relying_party = {
        let csil_field = cbor_require(csil_root, "relying_party")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let timestamp = {
        let csil_field = cbor_require(csil_root, "timestamp")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(UserInfoRequest {
        token,
        relying_party,
        timestamp,
        nonce,
    })
}

/// Encode a UserInfoRequest to canonical CSIL CBOR bytes.
pub fn encode_user_info_request(csil_v: &UserInfoRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_user_info_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a UserInfoRequest.
pub fn decode_user_info_request(csil_data: &[u8]) -> Result<UserInfoRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_user_info_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedUserInfoRequest.
fn csil_enc_signed_user_info_request(csil_v: &SignedUserInfoRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    if let Some(csil_inner) = &csil_v.public_keys {
        csil_entries.push((
            cbor_text("public_keys"),
            cbor_enc_array(csil_inner, csil_enc_domain_public_key),
        ));
    }
    csil_entries.push((
        cbor_text("signing_key_id"),
        cbor_text(&csil_v.signing_key_id),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SignedUserInfoRequest from a decoded CBOR value tree.
fn csil_dec_signed_user_info_request(
    csil_root: &CsilCborValue,
) -> Result<SignedUserInfoRequest, CsilCborError> {
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signing_key_id = {
        let csil_field = cbor_require(csil_root, "signing_key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signature = {
        let csil_field = cbor_require(csil_root, "signature")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let public_keys = match cbor_map_get(csil_root, "public_keys") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_domain_public_key);
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(SignedUserInfoRequest {
        request,
        signing_key_id,
        signature,
        public_keys,
    })
}

/// Encode a SignedUserInfoRequest to canonical CSIL CBOR bytes.
pub fn encode_signed_user_info_request(csil_v: &SignedUserInfoRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_signed_user_info_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SignedUserInfoRequest.
pub fn decode_signed_user_info_request(
    csil_data: &[u8],
) -> Result<SignedUserInfoRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_user_info_request(&csil_root)
}

/// Build the canonical CBOR value tree for a UserInfo.
fn csil_enc_user_info(csil_v: &UserInfo) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim),
    ));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("display_name"), cbor_text(&csil_v.display_name)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a UserInfo from a decoded CBOR value tree.
fn csil_dec_user_info(csil_root: &CsilCborValue) -> Result<UserInfo, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let display_name = {
        let csil_field = cbor_require(csil_root, "display_name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claims = {
        let csil_field = cbor_require(csil_root, "claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim);
        csil_decode(csil_field)?
    };
    Ok(UserInfo {
        user_id,
        domain,
        display_name,
        claims,
    })
}

/// Encode a UserInfo to canonical CSIL CBOR bytes.
pub fn encode_user_info(csil_v: &UserInfo) -> Vec<u8> {
    cbor_encode(&csil_enc_user_info(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a UserInfo.
pub fn decode_user_info(csil_data: &[u8]) -> Result<UserInfo, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_user_info(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthRequest.
fn csil_enc_auth_request(csil_v: &AuthRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    csil_entries.push((cbor_text("timestamp"), cbor_text(&csil_v.timestamp)));
    csil_entries.push((cbor_text("callback_url"), cbor_text(&csil_v.callback_url)));
    if let Some(csil_inner) = &csil_v.flow_context {
        csil_entries.push((
            cbor_text("flow_context"),
            csil_enc_auth_flow_context(csil_inner),
        ));
    }
    csil_entries.push((cbor_text("relying_party"), cbor_text(&csil_v.relying_party)));
    csil_entries.push((
        cbor_text("signing_key_id"),
        cbor_text(&csil_v.signing_key_id),
    ));
    if let Some(csil_inner) = &csil_v.requested_claims {
        csil_entries.push((
            cbor_text("requested_claims"),
            csil_enc_claim_request(csil_inner),
        ));
    }
    if let Some(csil_inner) = &csil_v.relying_party_claims {
        csil_entries.push((
            cbor_text("relying_party_claims"),
            cbor_enc_array(csil_inner, csil_enc_domain_claim),
        ));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AuthRequest from a decoded CBOR value tree.
fn csil_dec_auth_request(csil_root: &CsilCborValue) -> Result<AuthRequest, CsilCborError> {
    let relying_party = {
        let csil_field = cbor_require(csil_root, "relying_party")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let callback_url = {
        let csil_field = cbor_require(csil_root, "callback_url")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let timestamp = {
        let csil_field = cbor_require(csil_root, "timestamp")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signing_key_id = {
        let csil_field = cbor_require(csil_root, "signing_key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let requested_claims = match cbor_map_get(csil_root, "requested_claims") {
        Some(csil_field) => {
            let csil_decode = csil_dec_claim_request;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let flow_context = match cbor_map_get(csil_root, "flow_context") {
        Some(csil_field) => {
            let csil_decode = csil_dec_auth_flow_context;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let relying_party_claims = match cbor_map_get(csil_root, "relying_party_claims") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_domain_claim);
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(AuthRequest {
        relying_party,
        callback_url,
        nonce,
        timestamp,
        signing_key_id,
        requested_claims,
        flow_context,
        relying_party_claims,
    })
}

/// Encode a AuthRequest to canonical CSIL CBOR bytes.
pub fn encode_auth_request(csil_v: &AuthRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_auth_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AuthRequest.
pub fn decode_auth_request(csil_data: &[u8]) -> Result<AuthRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_auth_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedAuthRequest.
fn csil_enc_signed_auth_request(csil_v: &SignedAuthRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((
        cbor_text("signing_key_id"),
        cbor_text(&csil_v.signing_key_id),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SignedAuthRequest from a decoded CBOR value tree.
fn csil_dec_signed_auth_request(
    csil_root: &CsilCborValue,
) -> Result<SignedAuthRequest, CsilCborError> {
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signing_key_id = {
        let csil_field = cbor_require(csil_root, "signing_key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signature = {
        let csil_field = cbor_require(csil_root, "signature")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(SignedAuthRequest {
        request,
        signing_key_id,
        signature,
    })
}

/// Encode a SignedAuthRequest to canonical CSIL CBOR bytes.
pub fn encode_signed_auth_request(csil_v: &SignedAuthRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_signed_auth_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SignedAuthRequest.
pub fn decode_signed_auth_request(csil_data: &[u8]) -> Result<SignedAuthRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_auth_request(&csil_root)
}

/// Build the canonical CBOR value tree for a EncryptedToken.
fn csil_enc_encrypted_token(csil_v: &EncryptedToken) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("nonce"), cbor_bytes(&csil_v.nonce)));
    if let Some(csil_inner) = &csil_v.suite {
        csil_entries.push((cbor_text("suite"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("ciphertext"), cbor_bytes(&csil_v.ciphertext)));
    csil_entries.push((
        cbor_text("ephemeral_public_key"),
        cbor_bytes(&csil_v.ephemeral_public_key),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a EncryptedToken from a decoded CBOR value tree.
fn csil_dec_encrypted_token(csil_root: &CsilCborValue) -> Result<EncryptedToken, CsilCborError> {
    let ephemeral_public_key = {
        let csil_field = cbor_require(csil_root, "ephemeral_public_key")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let ciphertext = {
        let csil_field = cbor_require(csil_root, "ciphertext")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let suite = match cbor_map_get(csil_root, "suite") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(EncryptedToken {
        ephemeral_public_key,
        ciphertext,
        nonce,
        suite,
    })
}

/// Encode a EncryptedToken to canonical CSIL CBOR bytes.
pub fn encode_encrypted_token(csil_v: &EncryptedToken) -> Vec<u8> {
    cbor_encode(&csil_enc_encrypted_token(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a EncryptedToken.
pub fn decode_encrypted_token(csil_data: &[u8]) -> Result<EncryptedToken, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_encrypted_token(&csil_root)
}

/// Build the canonical CBOR value tree for a AlgorithmSupport.
fn csil_enc_algorithm_support(csil_v: &AlgorithmSupport) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("signing"),
        cbor_enc_array(&csil_v.signing, |csil_elem| cbor_text(csil_elem)),
    ));
    if let Some(csil_inner) = &csil_v.encryption {
        csil_entries.push((
            cbor_text("encryption"),
            cbor_enc_array(csil_inner, |csil_elem| cbor_text(csil_elem)),
        ));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AlgorithmSupport from a decoded CBOR value tree.
fn csil_dec_algorithm_support(
    csil_root: &CsilCborValue,
) -> Result<AlgorithmSupport, CsilCborError> {
    let signing = {
        let csil_field = cbor_require(csil_root, "signing")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let encryption = match cbor_map_get(csil_root, "encryption") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(AlgorithmSupport {
        signing,
        encryption,
    })
}

/// Encode a AlgorithmSupport to canonical CSIL CBOR bytes.
pub fn encode_algorithm_support(csil_v: &AlgorithmSupport) -> Vec<u8> {
    cbor_encode(&csil_enc_algorithm_support(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AlgorithmSupport.
pub fn decode_algorithm_support(csil_data: &[u8]) -> Result<AlgorithmSupport, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_algorithm_support(&csil_root)
}

/// Build the canonical CBOR value tree for a HandshakeRequest.
fn csil_enc_handshake_request(csil_v: &HandshakeRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("version"), cbor_text(&csil_v.version)));
    csil_entries.push((
        cbor_text("algorithms"),
        csil_enc_algorithm_support(&csil_v.algorithms),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a HandshakeRequest from a decoded CBOR value tree.
fn csil_dec_handshake_request(
    csil_root: &CsilCborValue,
) -> Result<HandshakeRequest, CsilCborError> {
    let version = {
        let csil_field = cbor_require(csil_root, "version")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let algorithms = {
        let csil_field = cbor_require(csil_root, "algorithms")?;
        let csil_decode = csil_dec_algorithm_support;
        csil_decode(csil_field)?
    };
    Ok(HandshakeRequest {
        version,
        algorithms,
    })
}

/// Encode a HandshakeRequest to canonical CSIL CBOR bytes.
pub fn encode_handshake_request(csil_v: &HandshakeRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_handshake_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a HandshakeRequest.
pub fn decode_handshake_request(csil_data: &[u8]) -> Result<HandshakeRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_handshake_request(&csil_root)
}

/// Build the canonical CBOR value tree for a HandshakeResponse.
fn csil_enc_handshake_response(csil_v: &HandshakeResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("version"), cbor_text(&csil_v.version)));
    csil_entries.push((
        cbor_text("algorithms"),
        csil_enc_algorithm_support(&csil_v.algorithms),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a HandshakeResponse from a decoded CBOR value tree.
fn csil_dec_handshake_response(
    csil_root: &CsilCborValue,
) -> Result<HandshakeResponse, CsilCborError> {
    let version = {
        let csil_field = cbor_require(csil_root, "version")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let algorithms = {
        let csil_field = cbor_require(csil_root, "algorithms")?;
        let csil_decode = csil_dec_algorithm_support;
        csil_decode(csil_field)?
    };
    Ok(HandshakeResponse {
        version,
        algorithms,
    })
}

/// Encode a HandshakeResponse to canonical CSIL CBOR bytes.
pub fn encode_handshake_response(csil_v: &HandshakeResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_handshake_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a HandshakeResponse.
pub fn decode_handshake_response(csil_data: &[u8]) -> Result<HandshakeResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_handshake_response(&csil_root)
}

/// Build the canonical CBOR value tree for a Relation.
fn csil_enc_relation(csil_v: &Relation) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("relation"), cbor_text(&csil_v.relation)));
    csil_entries.push((cbor_text("object_id"), cbor_text(&csil_v.object_id)));
    csil_entries.push((cbor_text("created_at"), cbor_text(&csil_v.created_at)));
    if let Some(csil_inner) = &csil_v.removed_at {
        csil_entries.push((cbor_text("removed_at"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("subject_id"), cbor_text(&csil_v.subject_id)));
    csil_entries.push((cbor_text("object_type"), cbor_text(&csil_v.object_type)));
    csil_entries.push((cbor_text("subject_type"), cbor_text(&csil_v.subject_type)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a Relation from a decoded CBOR value tree.
fn csil_dec_relation(csil_root: &CsilCborValue) -> Result<Relation, CsilCborError> {
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let subject_type = {
        let csil_field = cbor_require(csil_root, "subject_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let subject_id = {
        let csil_field = cbor_require(csil_root, "subject_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let relation = {
        let csil_field = cbor_require(csil_root, "relation")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let object_type = {
        let csil_field = cbor_require(csil_root, "object_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let object_id = {
        let csil_field = cbor_require(csil_root, "object_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let removed_at = match cbor_map_get(csil_root, "removed_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(Relation {
        id,
        subject_type,
        subject_id,
        relation,
        object_type,
        object_id,
        created_at,
        removed_at,
    })
}

/// Encode a Relation to canonical CSIL CBOR bytes.
pub fn encode_relation(csil_v: &Relation) -> Vec<u8> {
    cbor_encode(&csil_enc_relation(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a Relation.
pub fn decode_relation(csil_data: &[u8]) -> Result<Relation, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_relation(&csil_root)
}

/// Build the canonical CBOR value tree for a AdminUser.
fn csil_enc_admin_user(csil_v: &AdminUser) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(6);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("username"), cbor_text(&csil_v.username)));
    csil_entries.push((cbor_text("is_active"), cbor_bool(csil_v.is_active)));
    csil_entries.push((cbor_text("created_at"), cbor_text(&csil_v.created_at)));
    csil_entries.push((cbor_text("updated_at"), cbor_text(&csil_v.updated_at)));
    csil_entries.push((cbor_text("display_name"), cbor_text(&csil_v.display_name)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AdminUser from a decoded CBOR value tree.
fn csil_dec_admin_user(csil_root: &CsilCborValue) -> Result<AdminUser, CsilCborError> {
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let username = {
        let csil_field = cbor_require(csil_root, "username")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let display_name = {
        let csil_field = cbor_require(csil_root, "display_name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let is_active = {
        let csil_field = cbor_require(csil_root, "is_active")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let updated_at = {
        let csil_field = cbor_require(csil_root, "updated_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(AdminUser {
        id,
        username,
        display_name,
        is_active,
        created_at,
        updated_at,
    })
}

/// Encode a AdminUser to canonical CSIL CBOR bytes.
pub fn encode_admin_user(csil_v: &AdminUser) -> Vec<u8> {
    cbor_encode(&csil_enc_admin_user(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AdminUser.
pub fn decode_admin_user(csil_data: &[u8]) -> Result<AdminUser, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_admin_user(&csil_root)
}

/// Build the canonical CBOR value tree for a ListUsersRequest.
fn csil_enc_list_users_request(csil_v: &ListUsersRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.limit {
        csil_entries.push((cbor_text("limit"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.offset {
        csil_entries.push((cbor_text("offset"), cbor_int(*csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListUsersRequest from a decoded CBOR value tree.
fn csil_dec_list_users_request(
    csil_root: &CsilCborValue,
) -> Result<ListUsersRequest, CsilCborError> {
    let offset = match cbor_map_get(csil_root, "offset") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let limit = match cbor_map_get(csil_root, "limit") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ListUsersRequest { offset, limit })
}

/// Encode a ListUsersRequest to canonical CSIL CBOR bytes.
pub fn encode_list_users_request(csil_v: &ListUsersRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_list_users_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListUsersRequest.
pub fn decode_list_users_request(csil_data: &[u8]) -> Result<ListUsersRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_users_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ListUsersResponse.
fn csil_enc_list_users_response(csil_v: &ListUsersResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("users"),
        cbor_enc_array(&csil_v.users, csil_enc_admin_user),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListUsersResponse from a decoded CBOR value tree.
fn csil_dec_list_users_response(
    csil_root: &CsilCborValue,
) -> Result<ListUsersResponse, CsilCborError> {
    let users = {
        let csil_field = cbor_require(csil_root, "users")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_admin_user);
        csil_decode(csil_field)?
    };
    Ok(ListUsersResponse { users })
}

/// Encode a ListUsersResponse to canonical CSIL CBOR bytes.
pub fn encode_list_users_response(csil_v: &ListUsersResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_list_users_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListUsersResponse.
pub fn decode_list_users_response(csil_data: &[u8]) -> Result<ListUsersResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_users_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserRequest.
fn csil_enc_get_user_request(csil_v: &GetUserRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetUserRequest from a decoded CBOR value tree.
fn csil_dec_get_user_request(csil_root: &CsilCborValue) -> Result<GetUserRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GetUserRequest { user_id })
}

/// Encode a GetUserRequest to canonical CSIL CBOR bytes.
pub fn encode_get_user_request(csil_v: &GetUserRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_get_user_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetUserRequest.
pub fn decode_get_user_request(csil_data: &[u8]) -> Result<GetUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserResponse.
fn csil_enc_get_user_response(csil_v: &GetUserResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetUserResponse from a decoded CBOR value tree.
fn csil_dec_get_user_response(csil_root: &CsilCborValue) -> Result<GetUserResponse, CsilCborError> {
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(GetUserResponse { user })
}

/// Encode a GetUserResponse to canonical CSIL CBOR bytes.
pub fn encode_get_user_response(csil_v: &GetUserResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_get_user_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetUserResponse.
pub fn decode_get_user_response(csil_data: &[u8]) -> Result<GetUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateUserRequest.
fn csil_enc_create_user_request(csil_v: &CreateUserRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    if let Some(csil_inner) = &csil_v.password {
        csil_entries.push((cbor_text("password"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("username"), cbor_text(&csil_v.username)));
    csil_entries.push((cbor_text("display_name"), cbor_text(&csil_v.display_name)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a CreateUserRequest from a decoded CBOR value tree.
fn csil_dec_create_user_request(
    csil_root: &CsilCborValue,
) -> Result<CreateUserRequest, CsilCborError> {
    let username = {
        let csil_field = cbor_require(csil_root, "username")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let display_name = {
        let csil_field = cbor_require(csil_root, "display_name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let password = match cbor_map_get(csil_root, "password") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(CreateUserRequest {
        username,
        display_name,
        password,
    })
}

/// Encode a CreateUserRequest to canonical CSIL CBOR bytes.
pub fn encode_create_user_request(csil_v: &CreateUserRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_create_user_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a CreateUserRequest.
pub fn decode_create_user_request(csil_data: &[u8]) -> Result<CreateUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateUserResponse.
fn csil_enc_create_user_response(csil_v: &CreateUserResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)));
    if let Some(csil_inner) = &csil_v.api_key {
        csil_entries.push((cbor_text("api_key"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a CreateUserResponse from a decoded CBOR value tree.
fn csil_dec_create_user_response(
    csil_root: &CsilCborValue,
) -> Result<CreateUserResponse, CsilCborError> {
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    let api_key = match cbor_map_get(csil_root, "api_key") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(CreateUserResponse { user, api_key })
}

/// Encode a CreateUserResponse to canonical CSIL CBOR bytes.
pub fn encode_create_user_response(csil_v: &CreateUserResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_create_user_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a CreateUserResponse.
pub fn decode_create_user_response(csil_data: &[u8]) -> Result<CreateUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a UpdateUserRequest.
fn csil_enc_update_user_request(csil_v: &UpdateUserRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    if let Some(csil_inner) = &csil_v.display_name {
        csil_entries.push((cbor_text("display_name"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a UpdateUserRequest from a decoded CBOR value tree.
fn csil_dec_update_user_request(
    csil_root: &CsilCborValue,
) -> Result<UpdateUserRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let display_name = match cbor_map_get(csil_root, "display_name") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(UpdateUserRequest {
        user_id,
        display_name,
    })
}

/// Encode a UpdateUserRequest to canonical CSIL CBOR bytes.
pub fn encode_update_user_request(csil_v: &UpdateUserRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_update_user_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a UpdateUserRequest.
pub fn decode_update_user_request(csil_data: &[u8]) -> Result<UpdateUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_update_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a UpdateUserResponse.
fn csil_enc_update_user_response(csil_v: &UpdateUserResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a UpdateUserResponse from a decoded CBOR value tree.
fn csil_dec_update_user_response(
    csil_root: &CsilCborValue,
) -> Result<UpdateUserResponse, CsilCborError> {
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(UpdateUserResponse { user })
}

/// Encode a UpdateUserResponse to canonical CSIL CBOR bytes.
pub fn encode_update_user_response(csil_v: &UpdateUserResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_update_user_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a UpdateUserResponse.
pub fn decode_update_user_response(csil_data: &[u8]) -> Result<UpdateUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_update_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a DeactivateUserRequest.
fn csil_enc_deactivate_user_request(csil_v: &DeactivateUserRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a DeactivateUserRequest from a decoded CBOR value tree.
fn csil_dec_deactivate_user_request(
    csil_root: &CsilCborValue,
) -> Result<DeactivateUserRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(DeactivateUserRequest { user_id })
}

/// Encode a DeactivateUserRequest to canonical CSIL CBOR bytes.
pub fn encode_deactivate_user_request(csil_v: &DeactivateUserRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_deactivate_user_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a DeactivateUserRequest.
pub fn decode_deactivate_user_request(
    csil_data: &[u8],
) -> Result<DeactivateUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deactivate_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DeactivateUserResponse.
fn csil_enc_deactivate_user_response(csil_v: &DeactivateUserResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a DeactivateUserResponse from a decoded CBOR value tree.
fn csil_dec_deactivate_user_response(
    csil_root: &CsilCborValue,
) -> Result<DeactivateUserResponse, CsilCborError> {
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(DeactivateUserResponse { user })
}

/// Encode a DeactivateUserResponse to canonical CSIL CBOR bytes.
pub fn encode_deactivate_user_response(csil_v: &DeactivateUserResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_deactivate_user_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a DeactivateUserResponse.
pub fn decode_deactivate_user_response(
    csil_data: &[u8],
) -> Result<DeactivateUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deactivate_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ActivateUserRequest.
fn csil_enc_activate_user_request(csil_v: &ActivateUserRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ActivateUserRequest from a decoded CBOR value tree.
fn csil_dec_activate_user_request(
    csil_root: &CsilCborValue,
) -> Result<ActivateUserRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ActivateUserRequest { user_id })
}

/// Encode a ActivateUserRequest to canonical CSIL CBOR bytes.
pub fn encode_activate_user_request(csil_v: &ActivateUserRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_activate_user_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ActivateUserRequest.
pub fn decode_activate_user_request(
    csil_data: &[u8],
) -> Result<ActivateUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_activate_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ActivateUserResponse.
fn csil_enc_activate_user_response(csil_v: &ActivateUserResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ActivateUserResponse from a decoded CBOR value tree.
fn csil_dec_activate_user_response(
    csil_root: &CsilCborValue,
) -> Result<ActivateUserResponse, CsilCborError> {
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(ActivateUserResponse { user })
}

/// Encode a ActivateUserResponse to canonical CSIL CBOR bytes.
pub fn encode_activate_user_response(csil_v: &ActivateUserResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_activate_user_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ActivateUserResponse.
pub fn decode_activate_user_response(
    csil_data: &[u8],
) -> Result<ActivateUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_activate_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a PurgeUserRequest.
fn csil_enc_purge_user_request(csil_v: &PurgeUserRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.reason {
        csil_entries.push((cbor_text("reason"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a PurgeUserRequest from a decoded CBOR value tree.
fn csil_dec_purge_user_request(
    csil_root: &CsilCborValue,
) -> Result<PurgeUserRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let reason = match cbor_map_get(csil_root, "reason") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(PurgeUserRequest { user_id, reason })
}

/// Encode a PurgeUserRequest to canonical CSIL CBOR bytes.
pub fn encode_purge_user_request(csil_v: &PurgeUserRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_purge_user_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a PurgeUserRequest.
pub fn decode_purge_user_request(csil_data: &[u8]) -> Result<PurgeUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_purge_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a PurgeUserResponse.
fn csil_enc_purge_user_response(csil_v: &PurgeUserResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)));
    csil_entries.push((cbor_text("keys_revoked"), cbor_int(csil_v.keys_revoked)));
    csil_entries.push((cbor_text("claims_revoked"), cbor_int(csil_v.claims_revoked)));
    csil_entries.push((
        cbor_text("profiles_deleted"),
        cbor_int(csil_v.profiles_deleted),
    ));
    csil_entries.push((
        cbor_text("reviews_resolved"),
        cbor_int(csil_v.reviews_resolved),
    ));
    csil_entries.push((
        cbor_text("relations_removed"),
        cbor_int(csil_v.relations_removed),
    ));
    csil_entries.push((
        cbor_text("credentials_revoked"),
        cbor_int(csil_v.credentials_revoked),
    ));
    csil_entries.push((
        cbor_text("release_prefs_deleted"),
        cbor_int(csil_v.release_prefs_deleted),
    ));
    csil_entries.push((
        cbor_text("consent_grants_deleted"),
        cbor_int(csil_v.consent_grants_deleted),
    ));
    csil_entries.push((
        cbor_text("email_verifications_deleted"),
        cbor_int(csil_v.email_verifications_deleted),
    ));
    csil_entries.push((
        cbor_text("local_rp_claim_tickets_deleted"),
        cbor_int(csil_v.local_rp_claim_tickets_deleted),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a PurgeUserResponse from a decoded CBOR value tree.
fn csil_dec_purge_user_response(
    csil_root: &CsilCborValue,
) -> Result<PurgeUserResponse, CsilCborError> {
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    let credentials_revoked = {
        let csil_field = cbor_require(csil_root, "credentials_revoked")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let keys_revoked = {
        let csil_field = cbor_require(csil_root, "keys_revoked")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let claims_revoked = {
        let csil_field = cbor_require(csil_root, "claims_revoked")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let relations_removed = {
        let csil_field = cbor_require(csil_root, "relations_removed")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let profiles_deleted = {
        let csil_field = cbor_require(csil_root, "profiles_deleted")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let consent_grants_deleted = {
        let csil_field = cbor_require(csil_root, "consent_grants_deleted")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let release_prefs_deleted = {
        let csil_field = cbor_require(csil_root, "release_prefs_deleted")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let email_verifications_deleted = {
        let csil_field = cbor_require(csil_root, "email_verifications_deleted")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let reviews_resolved = {
        let csil_field = cbor_require(csil_root, "reviews_resolved")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let local_rp_claim_tickets_deleted = {
        let csil_field = cbor_require(csil_root, "local_rp_claim_tickets_deleted")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(PurgeUserResponse {
        user,
        credentials_revoked,
        keys_revoked,
        claims_revoked,
        relations_removed,
        profiles_deleted,
        consent_grants_deleted,
        release_prefs_deleted,
        email_verifications_deleted,
        reviews_resolved,
        local_rp_claim_tickets_deleted,
    })
}

/// Encode a PurgeUserResponse to canonical CSIL CBOR bytes.
pub fn encode_purge_user_response(csil_v: &PurgeUserResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_purge_user_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a PurgeUserResponse.
pub fn decode_purge_user_response(csil_data: &[u8]) -> Result<PurgeUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_purge_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeDomainKeyRequest.
fn csil_enc_revoke_domain_key_request(csil_v: &RevokeDomainKeyRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RevokeDomainKeyRequest from a decoded CBOR value tree.
fn csil_dec_revoke_domain_key_request(
    csil_root: &CsilCborValue,
) -> Result<RevokeDomainKeyRequest, CsilCborError> {
    let key_id = {
        let csil_field = cbor_require(csil_root, "key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RevokeDomainKeyRequest { key_id })
}

/// Encode a RevokeDomainKeyRequest to canonical CSIL CBOR bytes.
pub fn encode_revoke_domain_key_request(csil_v: &RevokeDomainKeyRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_revoke_domain_key_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RevokeDomainKeyRequest.
pub fn decode_revoke_domain_key_request(
    csil_data: &[u8],
) -> Result<RevokeDomainKeyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_domain_key_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeDomainKeyResponse.
fn csil_enc_revoke_domain_key_response(csil_v: &RevokeDomainKeyResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("revoked_key"),
        csil_enc_domain_public_key(&csil_v.revoked_key),
    ));
    csil_entries.push((
        cbor_text("certificate_issued"),
        cbor_bool(csil_v.certificate_issued),
    ));
    csil_entries.push((
        cbor_text("dns_removal_reminder"),
        cbor_text(&csil_v.dns_removal_reminder),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RevokeDomainKeyResponse from a decoded CBOR value tree.
fn csil_dec_revoke_domain_key_response(
    csil_root: &CsilCborValue,
) -> Result<RevokeDomainKeyResponse, CsilCborError> {
    let revoked_key = {
        let csil_field = cbor_require(csil_root, "revoked_key")?;
        let csil_decode = csil_dec_domain_public_key;
        csil_decode(csil_field)?
    };
    let certificate_issued = {
        let csil_field = cbor_require(csil_root, "certificate_issued")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let dns_removal_reminder = {
        let csil_field = cbor_require(csil_root, "dns_removal_reminder")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RevokeDomainKeyResponse {
        revoked_key,
        certificate_issued,
        dns_removal_reminder,
    })
}

/// Encode a RevokeDomainKeyResponse to canonical CSIL CBOR bytes.
pub fn encode_revoke_domain_key_response(csil_v: &RevokeDomainKeyResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_revoke_domain_key_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RevokeDomainKeyResponse.
pub fn decode_revoke_domain_key_response(
    csil_data: &[u8],
) -> Result<RevokeDomainKeyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_domain_key_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ResetPasswordRequest.
fn csil_enc_reset_password_request(csil_v: &ResetPasswordRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("new_password"), cbor_text(&csil_v.new_password)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ResetPasswordRequest from a decoded CBOR value tree.
fn csil_dec_reset_password_request(
    csil_root: &CsilCborValue,
) -> Result<ResetPasswordRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let new_password = {
        let csil_field = cbor_require(csil_root, "new_password")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ResetPasswordRequest {
        user_id,
        new_password,
    })
}

/// Encode a ResetPasswordRequest to canonical CSIL CBOR bytes.
pub fn encode_reset_password_request(csil_v: &ResetPasswordRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_reset_password_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ResetPasswordRequest.
pub fn decode_reset_password_request(
    csil_data: &[u8],
) -> Result<ResetPasswordRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_reset_password_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ResetPasswordResponse.
fn csil_enc_reset_password_response(csil_v: &ResetPasswordResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ResetPasswordResponse from a decoded CBOR value tree.
fn csil_dec_reset_password_response(
    csil_root: &CsilCborValue,
) -> Result<ResetPasswordResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(ResetPasswordResponse { success })
}

/// Encode a ResetPasswordResponse to canonical CSIL CBOR bytes.
pub fn encode_reset_password_response(csil_v: &ResetPasswordResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_reset_password_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ResetPasswordResponse.
pub fn decode_reset_password_response(
    csil_data: &[u8],
) -> Result<ResetPasswordResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_reset_password_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthenticateRequest.
fn csil_enc_authenticate_request(csil_v: &AuthenticateRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("password"), cbor_text(&csil_v.password)));
    csil_entries.push((cbor_text("username"), cbor_text(&csil_v.username)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AuthenticateRequest from a decoded CBOR value tree.
fn csil_dec_authenticate_request(
    csil_root: &CsilCborValue,
) -> Result<AuthenticateRequest, CsilCborError> {
    let username = {
        let csil_field = cbor_require(csil_root, "username")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let password = {
        let csil_field = cbor_require(csil_root, "password")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(AuthenticateRequest { username, password })
}

/// Encode a AuthenticateRequest to canonical CSIL CBOR bytes.
pub fn encode_authenticate_request(csil_v: &AuthenticateRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_authenticate_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AuthenticateRequest.
pub fn decode_authenticate_request(csil_data: &[u8]) -> Result<AuthenticateRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_authenticate_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthenticateResponse.
fn csil_enc_authenticate_response(csil_v: &AuthenticateResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AuthenticateResponse from a decoded CBOR value tree.
fn csil_dec_authenticate_response(
    csil_root: &CsilCborValue,
) -> Result<AuthenticateResponse, CsilCborError> {
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(AuthenticateResponse { user })
}

/// Encode a AuthenticateResponse to canonical CSIL CBOR bytes.
pub fn encode_authenticate_response(csil_v: &AuthenticateResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_authenticate_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AuthenticateResponse.
pub fn decode_authenticate_response(
    csil_data: &[u8],
) -> Result<AuthenticateResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_authenticate_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveCredentialRequest.
fn csil_enc_remove_credential_request(csil_v: &RemoveCredentialRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("credential_id"), cbor_text(&csil_v.credential_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveCredentialRequest from a decoded CBOR value tree.
fn csil_dec_remove_credential_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveCredentialRequest, CsilCborError> {
    let credential_id = {
        let csil_field = cbor_require(csil_root, "credential_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveCredentialRequest { credential_id })
}

/// Encode a RemoveCredentialRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_credential_request(csil_v: &RemoveCredentialRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_credential_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveCredentialRequest.
pub fn decode_remove_credential_request(
    csil_data: &[u8],
) -> Result<RemoveCredentialRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_credential_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveCredentialResponse.
fn csil_enc_remove_credential_response(csil_v: &RemoveCredentialResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveCredentialResponse from a decoded CBOR value tree.
fn csil_dec_remove_credential_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveCredentialResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveCredentialResponse { success })
}

/// Encode a RemoveCredentialResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_credential_response(csil_v: &RemoveCredentialResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_credential_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveCredentialResponse.
pub fn decode_remove_credential_response(
    csil_data: &[u8],
) -> Result<RemoveCredentialResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_credential_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimRequest.
fn csil_enc_set_claim_request(csil_v: &SetClaimRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    if let Some(csil_inner) = &csil_v.expires_at {
        csil_entries.push((cbor_text("expires_at"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("claim_value"), cbor_text(&csil_v.claim_value)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetClaimRequest from a decoded CBOR value tree.
fn csil_dec_set_claim_request(csil_root: &CsilCborValue) -> Result<SetClaimRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_value = {
        let csil_field = cbor_require(csil_root, "claim_value")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = match cbor_map_get(csil_root, "expires_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(SetClaimRequest {
        user_id,
        claim_type,
        claim_value,
        expires_at,
    })
}

/// Encode a SetClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_set_claim_request(csil_v: &SetClaimRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_set_claim_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimRequest.
pub fn decode_set_claim_request(csil_data: &[u8]) -> Result<SetClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimResponse.
fn csil_enc_set_claim_response(csil_v: &SetClaimResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim"), csil_enc_claim(&csil_v.claim)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetClaimResponse from a decoded CBOR value tree.
fn csil_dec_set_claim_response(
    csil_root: &CsilCborValue,
) -> Result<SetClaimResponse, CsilCborError> {
    let claim = {
        let csil_field = cbor_require(csil_root, "claim")?;
        let csil_decode = csil_dec_claim;
        csil_decode(csil_field)?
    };
    Ok(SetClaimResponse { claim })
}

/// Encode a SetClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_set_claim_response(csil_v: &SetClaimResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_set_claim_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimResponse.
pub fn decode_set_claim_response(csil_data: &[u8]) -> Result<SetClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimRequest.
fn csil_enc_remove_claim_request(csil_v: &RemoveClaimRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim_id"), cbor_text(&csil_v.claim_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveClaimRequest from a decoded CBOR value tree.
fn csil_dec_remove_claim_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimRequest, CsilCborError> {
    let claim_id = {
        let csil_field = cbor_require(csil_root, "claim_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimRequest { claim_id })
}

/// Encode a RemoveClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_request(csil_v: &RemoveClaimRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_claim_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimRequest.
pub fn decode_remove_claim_request(csil_data: &[u8]) -> Result<RemoveClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimResponse.
fn csil_enc_remove_claim_response(csil_v: &RemoveClaimResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveClaimResponse from a decoded CBOR value tree.
fn csil_dec_remove_claim_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimResponse { success })
}

/// Encode a RemoveClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_response(csil_v: &RemoveClaimResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_claim_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimResponse.
pub fn decode_remove_claim_response(
    csil_data: &[u8],
) -> Result<RemoveClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ListUserClaimsRequest.
fn csil_enc_list_user_claims_request(csil_v: &ListUserClaimsRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListUserClaimsRequest from a decoded CBOR value tree.
fn csil_dec_list_user_claims_request(
    csil_root: &CsilCborValue,
) -> Result<ListUserClaimsRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ListUserClaimsRequest { user_id })
}

/// Encode a ListUserClaimsRequest to canonical CSIL CBOR bytes.
pub fn encode_list_user_claims_request(csil_v: &ListUserClaimsRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_list_user_claims_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListUserClaimsRequest.
pub fn decode_list_user_claims_request(
    csil_data: &[u8],
) -> Result<ListUserClaimsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_user_claims_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ListUserClaimsResponse.
fn csil_enc_list_user_claims_response(csil_v: &ListUserClaimsResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("claim_types"),
        cbor_enc_array(&csil_v.claim_types, |csil_elem| cbor_text(csil_elem)),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListUserClaimsResponse from a decoded CBOR value tree.
fn csil_dec_list_user_claims_response(
    csil_root: &CsilCborValue,
) -> Result<ListUserClaimsResponse, CsilCborError> {
    let claim_types = {
        let csil_field = cbor_require(csil_root, "claim_types")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(ListUserClaimsResponse { claim_types })
}

/// Encode a ListUserClaimsResponse to canonical CSIL CBOR bytes.
pub fn encode_list_user_claims_response(csil_v: &ListUserClaimsResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_list_user_claims_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListUserClaimsResponse.
pub fn decode_list_user_claims_response(
    csil_data: &[u8],
) -> Result<ListUserClaimsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_user_claims_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetUserClaimRequest.
fn csil_enc_set_user_claim_request(csil_v: &SetUserClaimRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("claim_value"), cbor_text(&csil_v.claim_value)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetUserClaimRequest from a decoded CBOR value tree.
fn csil_dec_set_user_claim_request(
    csil_root: &CsilCborValue,
) -> Result<SetUserClaimRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_value = {
        let csil_field = cbor_require(csil_root, "claim_value")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(SetUserClaimRequest {
        user_id,
        claim_type,
        claim_value,
    })
}

/// Encode a SetUserClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_set_user_claim_request(csil_v: &SetUserClaimRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_set_user_claim_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetUserClaimRequest.
pub fn decode_set_user_claim_request(
    csil_data: &[u8],
) -> Result<SetUserClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_user_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetUserClaimResponse.
fn csil_enc_set_user_claim_response(csil_v: &SetUserClaimResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.claim {
        csil_entries.push((cbor_text("claim"), csil_enc_claim(csil_inner)));
    }
    csil_entries.push((cbor_text("outcome"), cbor_text(&csil_v.outcome)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetUserClaimResponse from a decoded CBOR value tree.
fn csil_dec_set_user_claim_response(
    csil_root: &CsilCborValue,
) -> Result<SetUserClaimResponse, CsilCborError> {
    let outcome = {
        let csil_field = cbor_require(csil_root, "outcome")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim = match cbor_map_get(csil_root, "claim") {
        Some(csil_field) => {
            let csil_decode = csil_dec_claim;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(SetUserClaimResponse { outcome, claim })
}

/// Encode a SetUserClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_set_user_claim_response(csil_v: &SetUserClaimResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_set_user_claim_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetUserClaimResponse.
pub fn decode_set_user_claim_response(
    csil_data: &[u8],
) -> Result<SetUserClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_user_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SettableClaimPolicy.
fn csil_enc_settable_claim_policy(csil_v: &SettableClaimPolicy) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("datatype"), cbor_text(&csil_v.datatype)));
    csil_entries.push((cbor_text("set_rule"), cbor_text(&csil_v.set_rule)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("signing_rule"), cbor_text(&csil_v.signing_rule)));
    csil_entries.push((
        cbor_text("requires_approval"),
        cbor_bool(csil_v.requires_approval),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SettableClaimPolicy from a decoded CBOR value tree.
fn csil_dec_settable_claim_policy(
    csil_root: &CsilCborValue,
) -> Result<SettableClaimPolicy, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let datatype = {
        let csil_field = cbor_require(csil_root, "datatype")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let set_rule = {
        let csil_field = cbor_require(csil_root, "set_rule")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let requires_approval = {
        let csil_field = cbor_require(csil_root, "requires_approval")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let signing_rule = {
        let csil_field = cbor_require(csil_root, "signing_rule")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(SettableClaimPolicy {
        claim_type,
        datatype,
        set_rule,
        requires_approval,
        signing_rule,
    })
}

/// Encode a SettableClaimPolicy to canonical CSIL CBOR bytes.
pub fn encode_settable_claim_policy(csil_v: &SettableClaimPolicy) -> Vec<u8> {
    cbor_encode(&csil_enc_settable_claim_policy(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SettableClaimPolicy.
pub fn decode_settable_claim_policy(
    csil_data: &[u8],
) -> Result<SettableClaimPolicy, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_settable_claim_policy(&csil_root)
}

/// Build the canonical CBOR value tree for a ListSettablePoliciesResponse.
fn csil_enc_list_settable_policies_response(
    csil_v: &ListSettablePoliciesResponse,
) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("policies"),
        cbor_enc_array(&csil_v.policies, csil_enc_settable_claim_policy),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListSettablePoliciesResponse from a decoded CBOR value tree.
fn csil_dec_list_settable_policies_response(
    csil_root: &CsilCborValue,
) -> Result<ListSettablePoliciesResponse, CsilCborError> {
    let policies = {
        let csil_field = cbor_require(csil_root, "policies")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_settable_claim_policy);
        csil_decode(csil_field)?
    };
    Ok(ListSettablePoliciesResponse { policies })
}

/// Encode a ListSettablePoliciesResponse to canonical CSIL CBOR bytes.
pub fn encode_list_settable_policies_response(csil_v: &ListSettablePoliciesResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_list_settable_policies_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListSettablePoliciesResponse.
pub fn decode_list_settable_policies_response(
    csil_data: &[u8],
) -> Result<ListSettablePoliciesResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_settable_policies_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimTypePolicy.
fn csil_enc_claim_type_policy(csil_v: &ClaimTypePolicy) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((cbor_text("label"), cbor_text(&csil_v.label)));
    csil_entries.push((cbor_text("set_rule"), cbor_text(&csil_v.set_rule)));
    csil_entries.push((cbor_text("max_bytes"), cbor_int(csil_v.max_bytes)));
    csil_entries.push((cbor_text("suggested"), cbor_bool(csil_v.suggested)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("value_type"), cbor_text(&csil_v.value_type)));
    csil_entries.push((cbor_text("description"), cbor_text(&csil_v.description)));
    csil_entries.push((cbor_text("signing_rule"), cbor_text(&csil_v.signing_rule)));
    csil_entries.push((cbor_text("user_settable"), cbor_bool(csil_v.user_settable)));
    csil_entries.push((
        cbor_text("default_auto_sign"),
        cbor_bool(csil_v.default_auto_sign),
    ));
    csil_entries.push((
        cbor_text("requires_approval"),
        cbor_bool(csil_v.requires_approval),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ClaimTypePolicy from a decoded CBOR value tree.
fn csil_dec_claim_type_policy(csil_root: &CsilCborValue) -> Result<ClaimTypePolicy, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let label = {
        let csil_field = cbor_require(csil_root, "label")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let description = {
        let csil_field = cbor_require(csil_root, "description")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let value_type = {
        let csil_field = cbor_require(csil_root, "value_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let max_bytes = {
        let csil_field = cbor_require(csil_root, "max_bytes")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let set_rule = {
        let csil_field = cbor_require(csil_root, "set_rule")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signing_rule = {
        let csil_field = cbor_require(csil_root, "signing_rule")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let requires_approval = {
        let csil_field = cbor_require(csil_root, "requires_approval")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let user_settable = {
        let csil_field = cbor_require(csil_root, "user_settable")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let default_auto_sign = {
        let csil_field = cbor_require(csil_root, "default_auto_sign")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let suggested = {
        let csil_field = cbor_require(csil_root, "suggested")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(ClaimTypePolicy {
        claim_type,
        label,
        description,
        value_type,
        max_bytes,
        set_rule,
        signing_rule,
        requires_approval,
        user_settable,
        default_auto_sign,
        suggested,
    })
}

/// Encode a ClaimTypePolicy to canonical CSIL CBOR bytes.
pub fn encode_claim_type_policy(csil_v: &ClaimTypePolicy) -> Vec<u8> {
    cbor_encode(&csil_enc_claim_type_policy(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ClaimTypePolicy.
pub fn decode_claim_type_policy(csil_data: &[u8]) -> Result<ClaimTypePolicy, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_type_policy(&csil_root)
}

/// Build the canonical CBOR value tree for a ListClaimTypesResponse.
fn csil_enc_list_claim_types_response(csil_v: &ListClaimTypesResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("claim_types"),
        cbor_enc_array(&csil_v.claim_types, csil_enc_claim_type_policy),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListClaimTypesResponse from a decoded CBOR value tree.
fn csil_dec_list_claim_types_response(
    csil_root: &CsilCborValue,
) -> Result<ListClaimTypesResponse, CsilCborError> {
    let claim_types = {
        let csil_field = cbor_require(csil_root, "claim_types")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_type_policy);
        csil_decode(csil_field)?
    };
    Ok(ListClaimTypesResponse { claim_types })
}

/// Encode a ListClaimTypesResponse to canonical CSIL CBOR bytes.
pub fn encode_list_claim_types_response(csil_v: &ListClaimTypesResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_list_claim_types_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListClaimTypesResponse.
pub fn decode_list_claim_types_response(
    csil_data: &[u8],
) -> Result<ListClaimTypesResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_claim_types_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimTypeRequest.
fn csil_enc_set_claim_type_request(csil_v: &SetClaimTypeRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((cbor_text("label"), cbor_text(&csil_v.label)));
    csil_entries.push((cbor_text("set_rule"), cbor_text(&csil_v.set_rule)));
    csil_entries.push((cbor_text("max_bytes"), cbor_int(csil_v.max_bytes)));
    csil_entries.push((cbor_text("suggested"), cbor_bool(csil_v.suggested)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("value_type"), cbor_text(&csil_v.value_type)));
    if let Some(csil_inner) = &csil_v.description {
        csil_entries.push((cbor_text("description"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("signing_rule"), cbor_text(&csil_v.signing_rule)));
    csil_entries.push((cbor_text("user_settable"), cbor_bool(csil_v.user_settable)));
    csil_entries.push((
        cbor_text("default_auto_sign"),
        cbor_bool(csil_v.default_auto_sign),
    ));
    csil_entries.push((
        cbor_text("requires_approval"),
        cbor_bool(csil_v.requires_approval),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetClaimTypeRequest from a decoded CBOR value tree.
fn csil_dec_set_claim_type_request(
    csil_root: &CsilCborValue,
) -> Result<SetClaimTypeRequest, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let label = {
        let csil_field = cbor_require(csil_root, "label")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let description = match cbor_map_get(csil_root, "description") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let value_type = {
        let csil_field = cbor_require(csil_root, "value_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let max_bytes = {
        let csil_field = cbor_require(csil_root, "max_bytes")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let set_rule = {
        let csil_field = cbor_require(csil_root, "set_rule")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signing_rule = {
        let csil_field = cbor_require(csil_root, "signing_rule")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let user_settable = {
        let csil_field = cbor_require(csil_root, "user_settable")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let default_auto_sign = {
        let csil_field = cbor_require(csil_root, "default_auto_sign")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let requires_approval = {
        let csil_field = cbor_require(csil_root, "requires_approval")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let suggested = {
        let csil_field = cbor_require(csil_root, "suggested")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(SetClaimTypeRequest {
        claim_type,
        label,
        description,
        value_type,
        max_bytes,
        set_rule,
        signing_rule,
        user_settable,
        default_auto_sign,
        requires_approval,
        suggested,
    })
}

/// Encode a SetClaimTypeRequest to canonical CSIL CBOR bytes.
pub fn encode_set_claim_type_request(csil_v: &SetClaimTypeRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_set_claim_type_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimTypeRequest.
pub fn decode_set_claim_type_request(
    csil_data: &[u8],
) -> Result<SetClaimTypeRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_type_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimTypeResponse.
fn csil_enc_set_claim_type_response(csil_v: &SetClaimTypeResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("claim_type"),
        csil_enc_claim_type_policy(&csil_v.claim_type),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetClaimTypeResponse from a decoded CBOR value tree.
fn csil_dec_set_claim_type_response(
    csil_root: &CsilCborValue,
) -> Result<SetClaimTypeResponse, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = csil_dec_claim_type_policy;
        csil_decode(csil_field)?
    };
    Ok(SetClaimTypeResponse { claim_type })
}

/// Encode a SetClaimTypeResponse to canonical CSIL CBOR bytes.
pub fn encode_set_claim_type_response(csil_v: &SetClaimTypeResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_set_claim_type_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimTypeResponse.
pub fn decode_set_claim_type_response(
    csil_data: &[u8],
) -> Result<SetClaimTypeResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_type_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimTypeRequest.
fn csil_enc_remove_claim_type_request(csil_v: &RemoveClaimTypeRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveClaimTypeRequest from a decoded CBOR value tree.
fn csil_dec_remove_claim_type_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimTypeRequest, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimTypeRequest { claim_type })
}

/// Encode a RemoveClaimTypeRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_type_request(csil_v: &RemoveClaimTypeRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_claim_type_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimTypeRequest.
pub fn decode_remove_claim_type_request(
    csil_data: &[u8],
) -> Result<RemoveClaimTypeRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_type_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimTypeResponse.
fn csil_enc_remove_claim_type_response(csil_v: &RemoveClaimTypeResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveClaimTypeResponse from a decoded CBOR value tree.
fn csil_dec_remove_claim_type_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimTypeResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimTypeResponse { success })
}

/// Encode a RemoveClaimTypeResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_type_response(csil_v: &RemoveClaimTypeResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_claim_type_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimTypeResponse.
pub fn decode_remove_claim_type_response(
    csil_data: &[u8],
) -> Result<RemoveClaimTypeResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_type_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimTypeLabel.
fn csil_enc_claim_type_label(csil_v: &ClaimTypeLabel) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("label"), cbor_text(&csil_v.label)));
    csil_entries.push((cbor_text("locale"), cbor_text(&csil_v.locale)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    if let Some(csil_inner) = &csil_v.description {
        csil_entries.push((cbor_text("description"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ClaimTypeLabel from a decoded CBOR value tree.
fn csil_dec_claim_type_label(csil_root: &CsilCborValue) -> Result<ClaimTypeLabel, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let locale = {
        let csil_field = cbor_require(csil_root, "locale")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let label = {
        let csil_field = cbor_require(csil_root, "label")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let description = match cbor_map_get(csil_root, "description") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ClaimTypeLabel {
        claim_type,
        locale,
        label,
        description,
    })
}

/// Encode a ClaimTypeLabel to canonical CSIL CBOR bytes.
pub fn encode_claim_type_label(csil_v: &ClaimTypeLabel) -> Vec<u8> {
    cbor_encode(&csil_enc_claim_type_label(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ClaimTypeLabel.
pub fn decode_claim_type_label(csil_data: &[u8]) -> Result<ClaimTypeLabel, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_type_label(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimTypeLabelRequest.
fn csil_enc_set_claim_type_label_request(csil_v: &SetClaimTypeLabelRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("label"), cbor_text(&csil_v.label)));
    csil_entries.push((cbor_text("locale"), cbor_text(&csil_v.locale)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    if let Some(csil_inner) = &csil_v.description {
        csil_entries.push((cbor_text("description"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetClaimTypeLabelRequest from a decoded CBOR value tree.
fn csil_dec_set_claim_type_label_request(
    csil_root: &CsilCborValue,
) -> Result<SetClaimTypeLabelRequest, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let locale = {
        let csil_field = cbor_require(csil_root, "locale")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let label = {
        let csil_field = cbor_require(csil_root, "label")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let description = match cbor_map_get(csil_root, "description") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(SetClaimTypeLabelRequest {
        claim_type,
        locale,
        label,
        description,
    })
}

/// Encode a SetClaimTypeLabelRequest to canonical CSIL CBOR bytes.
pub fn encode_set_claim_type_label_request(csil_v: &SetClaimTypeLabelRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_set_claim_type_label_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimTypeLabelRequest.
pub fn decode_set_claim_type_label_request(
    csil_data: &[u8],
) -> Result<SetClaimTypeLabelRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_type_label_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimTypeLabelResponse.
fn csil_enc_set_claim_type_label_response(csil_v: &SetClaimTypeLabelResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("label"), csil_enc_claim_type_label(&csil_v.label)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetClaimTypeLabelResponse from a decoded CBOR value tree.
fn csil_dec_set_claim_type_label_response(
    csil_root: &CsilCborValue,
) -> Result<SetClaimTypeLabelResponse, CsilCborError> {
    let label = {
        let csil_field = cbor_require(csil_root, "label")?;
        let csil_decode = csil_dec_claim_type_label;
        csil_decode(csil_field)?
    };
    Ok(SetClaimTypeLabelResponse { label })
}

/// Encode a SetClaimTypeLabelResponse to canonical CSIL CBOR bytes.
pub fn encode_set_claim_type_label_response(csil_v: &SetClaimTypeLabelResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_set_claim_type_label_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimTypeLabelResponse.
pub fn decode_set_claim_type_label_response(
    csil_data: &[u8],
) -> Result<SetClaimTypeLabelResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_type_label_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimTypeLabelRequest.
fn csil_enc_remove_claim_type_label_request(csil_v: &RemoveClaimTypeLabelRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("locale"), cbor_text(&csil_v.locale)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveClaimTypeLabelRequest from a decoded CBOR value tree.
fn csil_dec_remove_claim_type_label_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimTypeLabelRequest, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let locale = {
        let csil_field = cbor_require(csil_root, "locale")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimTypeLabelRequest { claim_type, locale })
}

/// Encode a RemoveClaimTypeLabelRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_type_label_request(csil_v: &RemoveClaimTypeLabelRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_claim_type_label_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimTypeLabelRequest.
pub fn decode_remove_claim_type_label_request(
    csil_data: &[u8],
) -> Result<RemoveClaimTypeLabelRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_type_label_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimTypeLabelResponse.
fn csil_enc_remove_claim_type_label_response(
    csil_v: &RemoveClaimTypeLabelResponse,
) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveClaimTypeLabelResponse from a decoded CBOR value tree.
fn csil_dec_remove_claim_type_label_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimTypeLabelResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimTypeLabelResponse { success })
}

/// Encode a RemoveClaimTypeLabelResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_type_label_response(csil_v: &RemoveClaimTypeLabelResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_claim_type_label_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimTypeLabelResponse.
pub fn decode_remove_claim_type_label_response(
    csil_data: &[u8],
) -> Result<RemoveClaimTypeLabelResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_type_label_response(&csil_root)
}

/// Build the canonical CBOR value tree for a TrustedIssuer.
fn csil_enc_trusted_issuer(csil_v: &TrustedIssuer) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("issuer_domain"), cbor_text(&csil_v.issuer_domain)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a TrustedIssuer from a decoded CBOR value tree.
fn csil_dec_trusted_issuer(csil_root: &CsilCborValue) -> Result<TrustedIssuer, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let issuer_domain = {
        let csil_field = cbor_require(csil_root, "issuer_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(TrustedIssuer {
        claim_type,
        issuer_domain,
    })
}

/// Encode a TrustedIssuer to canonical CSIL CBOR bytes.
pub fn encode_trusted_issuer(csil_v: &TrustedIssuer) -> Vec<u8> {
    cbor_encode(&csil_enc_trusted_issuer(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a TrustedIssuer.
pub fn decode_trusted_issuer(csil_data: &[u8]) -> Result<TrustedIssuer, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_trusted_issuer(&csil_root)
}

/// Build the canonical CBOR value tree for a ListTrustedIssuersResponse.
fn csil_enc_list_trusted_issuers_response(csil_v: &ListTrustedIssuersResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("trusted_issuers"),
        cbor_enc_array(&csil_v.trusted_issuers, csil_enc_trusted_issuer),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListTrustedIssuersResponse from a decoded CBOR value tree.
fn csil_dec_list_trusted_issuers_response(
    csil_root: &CsilCborValue,
) -> Result<ListTrustedIssuersResponse, CsilCborError> {
    let trusted_issuers = {
        let csil_field = cbor_require(csil_root, "trusted_issuers")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_trusted_issuer);
        csil_decode(csil_field)?
    };
    Ok(ListTrustedIssuersResponse { trusted_issuers })
}

/// Encode a ListTrustedIssuersResponse to canonical CSIL CBOR bytes.
pub fn encode_list_trusted_issuers_response(csil_v: &ListTrustedIssuersResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_list_trusted_issuers_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListTrustedIssuersResponse.
pub fn decode_list_trusted_issuers_response(
    csil_data: &[u8],
) -> Result<ListTrustedIssuersResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_trusted_issuers_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AddTrustedIssuerRequest.
fn csil_enc_add_trusted_issuer_request(csil_v: &AddTrustedIssuerRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("issuer_domain"), cbor_text(&csil_v.issuer_domain)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AddTrustedIssuerRequest from a decoded CBOR value tree.
fn csil_dec_add_trusted_issuer_request(
    csil_root: &CsilCborValue,
) -> Result<AddTrustedIssuerRequest, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let issuer_domain = {
        let csil_field = cbor_require(csil_root, "issuer_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(AddTrustedIssuerRequest {
        claim_type,
        issuer_domain,
    })
}

/// Encode a AddTrustedIssuerRequest to canonical CSIL CBOR bytes.
pub fn encode_add_trusted_issuer_request(csil_v: &AddTrustedIssuerRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_add_trusted_issuer_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AddTrustedIssuerRequest.
pub fn decode_add_trusted_issuer_request(
    csil_data: &[u8],
) -> Result<AddTrustedIssuerRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_add_trusted_issuer_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AddTrustedIssuerResponse.
fn csil_enc_add_trusted_issuer_response(csil_v: &AddTrustedIssuerResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("trusted_issuer"),
        csil_enc_trusted_issuer(&csil_v.trusted_issuer),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AddTrustedIssuerResponse from a decoded CBOR value tree.
fn csil_dec_add_trusted_issuer_response(
    csil_root: &CsilCborValue,
) -> Result<AddTrustedIssuerResponse, CsilCborError> {
    let trusted_issuer = {
        let csil_field = cbor_require(csil_root, "trusted_issuer")?;
        let csil_decode = csil_dec_trusted_issuer;
        csil_decode(csil_field)?
    };
    Ok(AddTrustedIssuerResponse { trusted_issuer })
}

/// Encode a AddTrustedIssuerResponse to canonical CSIL CBOR bytes.
pub fn encode_add_trusted_issuer_response(csil_v: &AddTrustedIssuerResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_add_trusted_issuer_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AddTrustedIssuerResponse.
pub fn decode_add_trusted_issuer_response(
    csil_data: &[u8],
) -> Result<AddTrustedIssuerResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_add_trusted_issuer_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveTrustedIssuerRequest.
fn csil_enc_remove_trusted_issuer_request(csil_v: &RemoveTrustedIssuerRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("issuer_domain"), cbor_text(&csil_v.issuer_domain)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveTrustedIssuerRequest from a decoded CBOR value tree.
fn csil_dec_remove_trusted_issuer_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveTrustedIssuerRequest, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let issuer_domain = {
        let csil_field = cbor_require(csil_root, "issuer_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveTrustedIssuerRequest {
        claim_type,
        issuer_domain,
    })
}

/// Encode a RemoveTrustedIssuerRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_trusted_issuer_request(csil_v: &RemoveTrustedIssuerRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_trusted_issuer_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveTrustedIssuerRequest.
pub fn decode_remove_trusted_issuer_request(
    csil_data: &[u8],
) -> Result<RemoveTrustedIssuerRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_trusted_issuer_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveTrustedIssuerResponse.
fn csil_enc_remove_trusted_issuer_response(csil_v: &RemoveTrustedIssuerResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveTrustedIssuerResponse from a decoded CBOR value tree.
fn csil_dec_remove_trusted_issuer_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveTrustedIssuerResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveTrustedIssuerResponse { success })
}

/// Encode a RemoveTrustedIssuerResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_trusted_issuer_response(csil_v: &RemoveTrustedIssuerResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_trusted_issuer_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveTrustedIssuerResponse.
pub fn decode_remove_trusted_issuer_response(
    csil_data: &[u8],
) -> Result<RemoveTrustedIssuerResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_trusted_issuer_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ReleaseRule.
fn csil_enc_release_rule(csil_v: &ReleaseRule) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("disposition"), cbor_text(&csil_v.disposition)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ReleaseRule from a decoded CBOR value tree.
fn csil_dec_release_rule(csil_root: &CsilCborValue) -> Result<ReleaseRule, CsilCborError> {
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let disposition = {
        let csil_field = cbor_require(csil_root, "disposition")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ReleaseRule {
        audience,
        claim_type,
        disposition,
    })
}

/// Encode a ReleaseRule to canonical CSIL CBOR bytes.
pub fn encode_release_rule(csil_v: &ReleaseRule) -> Vec<u8> {
    cbor_encode(&csil_enc_release_rule(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ReleaseRule.
pub fn decode_release_rule(csil_data: &[u8]) -> Result<ReleaseRule, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_release_rule(&csil_root)
}

/// Build the canonical CBOR value tree for a ListReleaseRulesResponse.
fn csil_enc_list_release_rules_response(csil_v: &ListReleaseRulesResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("release_rules"),
        cbor_enc_array(&csil_v.release_rules, csil_enc_release_rule),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListReleaseRulesResponse from a decoded CBOR value tree.
fn csil_dec_list_release_rules_response(
    csil_root: &CsilCborValue,
) -> Result<ListReleaseRulesResponse, CsilCborError> {
    let release_rules = {
        let csil_field = cbor_require(csil_root, "release_rules")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_release_rule);
        csil_decode(csil_field)?
    };
    Ok(ListReleaseRulesResponse { release_rules })
}

/// Encode a ListReleaseRulesResponse to canonical CSIL CBOR bytes.
pub fn encode_list_release_rules_response(csil_v: &ListReleaseRulesResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_list_release_rules_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListReleaseRulesResponse.
pub fn decode_list_release_rules_response(
    csil_data: &[u8],
) -> Result<ListReleaseRulesResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_release_rules_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetReleaseRuleRequest.
fn csil_enc_set_release_rule_request(csil_v: &SetReleaseRuleRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("disposition"), cbor_text(&csil_v.disposition)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetReleaseRuleRequest from a decoded CBOR value tree.
fn csil_dec_set_release_rule_request(
    csil_root: &CsilCborValue,
) -> Result<SetReleaseRuleRequest, CsilCborError> {
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let disposition = {
        let csil_field = cbor_require(csil_root, "disposition")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(SetReleaseRuleRequest {
        audience,
        claim_type,
        disposition,
    })
}

/// Encode a SetReleaseRuleRequest to canonical CSIL CBOR bytes.
pub fn encode_set_release_rule_request(csil_v: &SetReleaseRuleRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_set_release_rule_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetReleaseRuleRequest.
pub fn decode_set_release_rule_request(
    csil_data: &[u8],
) -> Result<SetReleaseRuleRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_release_rule_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetReleaseRuleResponse.
fn csil_enc_set_release_rule_response(csil_v: &SetReleaseRuleResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("release_rule"),
        csil_enc_release_rule(&csil_v.release_rule),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetReleaseRuleResponse from a decoded CBOR value tree.
fn csil_dec_set_release_rule_response(
    csil_root: &CsilCborValue,
) -> Result<SetReleaseRuleResponse, CsilCborError> {
    let release_rule = {
        let csil_field = cbor_require(csil_root, "release_rule")?;
        let csil_decode = csil_dec_release_rule;
        csil_decode(csil_field)?
    };
    Ok(SetReleaseRuleResponse { release_rule })
}

/// Encode a SetReleaseRuleResponse to canonical CSIL CBOR bytes.
pub fn encode_set_release_rule_response(csil_v: &SetReleaseRuleResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_set_release_rule_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetReleaseRuleResponse.
pub fn decode_set_release_rule_response(
    csil_data: &[u8],
) -> Result<SetReleaseRuleResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_release_rule_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveReleaseRuleRequest.
fn csil_enc_remove_release_rule_request(csil_v: &RemoveReleaseRuleRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveReleaseRuleRequest from a decoded CBOR value tree.
fn csil_dec_remove_release_rule_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveReleaseRuleRequest, CsilCborError> {
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveReleaseRuleRequest {
        audience,
        claim_type,
    })
}

/// Encode a RemoveReleaseRuleRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_release_rule_request(csil_v: &RemoveReleaseRuleRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_release_rule_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveReleaseRuleRequest.
pub fn decode_remove_release_rule_request(
    csil_data: &[u8],
) -> Result<RemoveReleaseRuleRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_release_rule_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveReleaseRuleResponse.
fn csil_enc_remove_release_rule_response(csil_v: &RemoveReleaseRuleResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveReleaseRuleResponse from a decoded CBOR value tree.
fn csil_dec_remove_release_rule_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveReleaseRuleResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveReleaseRuleResponse { success })
}

/// Encode a RemoveReleaseRuleResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_release_rule_response(csil_v: &RemoveReleaseRuleResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_release_rule_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveReleaseRuleResponse.
pub fn decode_remove_release_rule_response(
    csil_data: &[u8],
) -> Result<RemoveReleaseRuleResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_release_rule_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimApproval.
fn csil_enc_claim_approval(csil_v: &ClaimApproval) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("status"), cbor_text(&csil_v.status)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("created_at"), cbor_text(&csil_v.created_at)));
    csil_entries.push((cbor_text("claim_value"), cbor_bytes(&csil_v.claim_value)));
    if let Some(csil_inner) = &csil_v.resolved_at {
        csil_entries.push((cbor_text("resolved_at"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.resolved_by {
        csil_entries.push((cbor_text("resolved_by"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ClaimApproval from a decoded CBOR value tree.
fn csil_dec_claim_approval(csil_root: &CsilCborValue) -> Result<ClaimApproval, CsilCborError> {
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_value = {
        let csil_field = cbor_require(csil_root, "claim_value")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let status = {
        let csil_field = cbor_require(csil_root, "status")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let resolved_by = match cbor_map_get(csil_root, "resolved_by") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let resolved_at = match cbor_map_get(csil_root, "resolved_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ClaimApproval {
        id,
        user_id,
        claim_type,
        claim_value,
        status,
        resolved_by,
        resolved_at,
        created_at,
    })
}

/// Encode a ClaimApproval to canonical CSIL CBOR bytes.
pub fn encode_claim_approval(csil_v: &ClaimApproval) -> Vec<u8> {
    cbor_encode(&csil_enc_claim_approval(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ClaimApproval.
pub fn decode_claim_approval(csil_data: &[u8]) -> Result<ClaimApproval, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_approval(&csil_root)
}

/// Build the canonical CBOR value tree for a ListPendingClaimApprovalsResponse.
fn csil_enc_list_pending_claim_approvals_response(
    csil_v: &ListPendingClaimApprovalsResponse,
) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("approvals"),
        cbor_enc_array(&csil_v.approvals, csil_enc_claim_approval),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListPendingClaimApprovalsResponse from a decoded CBOR value tree.
fn csil_dec_list_pending_claim_approvals_response(
    csil_root: &CsilCborValue,
) -> Result<ListPendingClaimApprovalsResponse, CsilCborError> {
    let approvals = {
        let csil_field = cbor_require(csil_root, "approvals")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_approval);
        csil_decode(csil_field)?
    };
    Ok(ListPendingClaimApprovalsResponse { approvals })
}

/// Encode a ListPendingClaimApprovalsResponse to canonical CSIL CBOR bytes.
pub fn encode_list_pending_claim_approvals_response(
    csil_v: &ListPendingClaimApprovalsResponse,
) -> Vec<u8> {
    cbor_encode(&csil_enc_list_pending_claim_approvals_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListPendingClaimApprovalsResponse.
pub fn decode_list_pending_claim_approvals_response(
    csil_data: &[u8],
) -> Result<ListPendingClaimApprovalsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_pending_claim_approvals_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ApproveClaimRequest.
fn csil_enc_approve_claim_request(csil_v: &ApproveClaimRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("approval_id"), cbor_text(&csil_v.approval_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ApproveClaimRequest from a decoded CBOR value tree.
fn csil_dec_approve_claim_request(
    csil_root: &CsilCborValue,
) -> Result<ApproveClaimRequest, CsilCborError> {
    let approval_id = {
        let csil_field = cbor_require(csil_root, "approval_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ApproveClaimRequest { approval_id })
}

/// Encode a ApproveClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_approve_claim_request(csil_v: &ApproveClaimRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_approve_claim_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ApproveClaimRequest.
pub fn decode_approve_claim_request(
    csil_data: &[u8],
) -> Result<ApproveClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_approve_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ApproveClaimResponse.
fn csil_enc_approve_claim_response(csil_v: &ApproveClaimResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ApproveClaimResponse from a decoded CBOR value tree.
fn csil_dec_approve_claim_response(
    csil_root: &CsilCborValue,
) -> Result<ApproveClaimResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(ApproveClaimResponse { success })
}

/// Encode a ApproveClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_approve_claim_response(csil_v: &ApproveClaimResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_approve_claim_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ApproveClaimResponse.
pub fn decode_approve_claim_response(
    csil_data: &[u8],
) -> Result<ApproveClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_approve_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RejectClaimRequest.
fn csil_enc_reject_claim_request(csil_v: &RejectClaimRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("approval_id"), cbor_text(&csil_v.approval_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RejectClaimRequest from a decoded CBOR value tree.
fn csil_dec_reject_claim_request(
    csil_root: &CsilCborValue,
) -> Result<RejectClaimRequest, CsilCborError> {
    let approval_id = {
        let csil_field = cbor_require(csil_root, "approval_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RejectClaimRequest { approval_id })
}

/// Encode a RejectClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_reject_claim_request(csil_v: &RejectClaimRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_reject_claim_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RejectClaimRequest.
pub fn decode_reject_claim_request(csil_data: &[u8]) -> Result<RejectClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_reject_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RejectClaimResponse.
fn csil_enc_reject_claim_response(csil_v: &RejectClaimResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RejectClaimResponse from a decoded CBOR value tree.
fn csil_dec_reject_claim_response(
    csil_root: &CsilCborValue,
) -> Result<RejectClaimResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RejectClaimResponse { success })
}

/// Encode a RejectClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_reject_claim_response(csil_v: &RejectClaimResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_reject_claim_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RejectClaimResponse.
pub fn decode_reject_claim_response(
    csil_data: &[u8],
) -> Result<RejectClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_reject_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AdminIssueAttestationRequest.
fn csil_enc_admin_issue_attestation_request(
    csil_v: &AdminIssueAttestationRequest,
) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("claim_value"), cbor_bytes(&csil_v.claim_value)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AdminIssueAttestationRequest from a decoded CBOR value tree.
fn csil_dec_admin_issue_attestation_request(
    csil_root: &CsilCborValue,
) -> Result<AdminIssueAttestationRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_value = {
        let csil_field = cbor_require(csil_root, "claim_value")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(AdminIssueAttestationRequest {
        user_id,
        claim_type,
        claim_value,
    })
}

/// Encode a AdminIssueAttestationRequest to canonical CSIL CBOR bytes.
pub fn encode_admin_issue_attestation_request(csil_v: &AdminIssueAttestationRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_admin_issue_attestation_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AdminIssueAttestationRequest.
pub fn decode_admin_issue_attestation_request(
    csil_data: &[u8],
) -> Result<AdminIssueAttestationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_admin_issue_attestation_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AdminIssueAttestationResponse.
fn csil_enc_admin_issue_attestation_response(
    csil_v: &AdminIssueAttestationResponse,
) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim"), csil_enc_claim(&csil_v.claim)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AdminIssueAttestationResponse from a decoded CBOR value tree.
fn csil_dec_admin_issue_attestation_response(
    csil_root: &CsilCborValue,
) -> Result<AdminIssueAttestationResponse, CsilCborError> {
    let claim = {
        let csil_field = cbor_require(csil_root, "claim")?;
        let csil_decode = csil_dec_claim;
        csil_decode(csil_field)?
    };
    Ok(AdminIssueAttestationResponse { claim })
}

/// Encode a AdminIssueAttestationResponse to canonical CSIL CBOR bytes.
pub fn encode_admin_issue_attestation_response(csil_v: &AdminIssueAttestationResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_admin_issue_attestation_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AdminIssueAttestationResponse.
pub fn decode_admin_issue_attestation_response(
    csil_data: &[u8],
) -> Result<AdminIssueAttestationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_admin_issue_attestation_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GrantRelationRequest.
fn csil_enc_grant_relation_request(csil_v: &GrantRelationRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("relation"), cbor_text(&csil_v.relation)));
    csil_entries.push((cbor_text("object_id"), cbor_text(&csil_v.object_id)));
    csil_entries.push((cbor_text("subject_id"), cbor_text(&csil_v.subject_id)));
    csil_entries.push((cbor_text("object_type"), cbor_text(&csil_v.object_type)));
    csil_entries.push((cbor_text("subject_type"), cbor_text(&csil_v.subject_type)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GrantRelationRequest from a decoded CBOR value tree.
fn csil_dec_grant_relation_request(
    csil_root: &CsilCborValue,
) -> Result<GrantRelationRequest, CsilCborError> {
    let subject_type = {
        let csil_field = cbor_require(csil_root, "subject_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let subject_id = {
        let csil_field = cbor_require(csil_root, "subject_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let relation = {
        let csil_field = cbor_require(csil_root, "relation")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let object_type = {
        let csil_field = cbor_require(csil_root, "object_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let object_id = {
        let csil_field = cbor_require(csil_root, "object_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GrantRelationRequest {
        subject_type,
        subject_id,
        relation,
        object_type,
        object_id,
    })
}

/// Encode a GrantRelationRequest to canonical CSIL CBOR bytes.
pub fn encode_grant_relation_request(csil_v: &GrantRelationRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_grant_relation_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GrantRelationRequest.
pub fn decode_grant_relation_request(
    csil_data: &[u8],
) -> Result<GrantRelationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_grant_relation_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GrantRelationResponse.
fn csil_enc_grant_relation_response(csil_v: &GrantRelationResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("relation"), csil_enc_relation(&csil_v.relation)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GrantRelationResponse from a decoded CBOR value tree.
fn csil_dec_grant_relation_response(
    csil_root: &CsilCborValue,
) -> Result<GrantRelationResponse, CsilCborError> {
    let relation = {
        let csil_field = cbor_require(csil_root, "relation")?;
        let csil_decode = csil_dec_relation;
        csil_decode(csil_field)?
    };
    Ok(GrantRelationResponse { relation })
}

/// Encode a GrantRelationResponse to canonical CSIL CBOR bytes.
pub fn encode_grant_relation_response(csil_v: &GrantRelationResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_grant_relation_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GrantRelationResponse.
pub fn decode_grant_relation_response(
    csil_data: &[u8],
) -> Result<GrantRelationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_grant_relation_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveRelationRequest.
fn csil_enc_remove_relation_request(csil_v: &RemoveRelationRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("relation_id"), cbor_text(&csil_v.relation_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveRelationRequest from a decoded CBOR value tree.
fn csil_dec_remove_relation_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveRelationRequest, CsilCborError> {
    let relation_id = {
        let csil_field = cbor_require(csil_root, "relation_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveRelationRequest { relation_id })
}

/// Encode a RemoveRelationRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_relation_request(csil_v: &RemoveRelationRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_relation_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveRelationRequest.
pub fn decode_remove_relation_request(
    csil_data: &[u8],
) -> Result<RemoveRelationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_relation_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveRelationResponse.
fn csil_enc_remove_relation_response(csil_v: &RemoveRelationResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveRelationResponse from a decoded CBOR value tree.
fn csil_dec_remove_relation_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveRelationResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveRelationResponse { success })
}

/// Encode a RemoveRelationResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_relation_response(csil_v: &RemoveRelationResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_relation_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveRelationResponse.
pub fn decode_remove_relation_response(
    csil_data: &[u8],
) -> Result<RemoveRelationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_relation_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ListRelationsRequest.
fn csil_enc_list_relations_request(csil_v: &ListRelationsRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    if let Some(csil_inner) = &csil_v.object_id {
        csil_entries.push((cbor_text("object_id"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.subject_id {
        csil_entries.push((cbor_text("subject_id"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.object_type {
        csil_entries.push((cbor_text("object_type"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.subject_type {
        csil_entries.push((cbor_text("subject_type"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListRelationsRequest from a decoded CBOR value tree.
fn csil_dec_list_relations_request(
    csil_root: &CsilCborValue,
) -> Result<ListRelationsRequest, CsilCborError> {
    let subject_type = match cbor_map_get(csil_root, "subject_type") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let subject_id = match cbor_map_get(csil_root, "subject_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let object_type = match cbor_map_get(csil_root, "object_type") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let object_id = match cbor_map_get(csil_root, "object_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ListRelationsRequest {
        subject_type,
        subject_id,
        object_type,
        object_id,
    })
}

/// Encode a ListRelationsRequest to canonical CSIL CBOR bytes.
pub fn encode_list_relations_request(csil_v: &ListRelationsRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_list_relations_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListRelationsRequest.
pub fn decode_list_relations_request(
    csil_data: &[u8],
) -> Result<ListRelationsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_relations_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ListRelationsResponse.
fn csil_enc_list_relations_response(csil_v: &ListRelationsResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("relations"),
        cbor_enc_array(&csil_v.relations, csil_enc_relation),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListRelationsResponse from a decoded CBOR value tree.
fn csil_dec_list_relations_response(
    csil_root: &CsilCborValue,
) -> Result<ListRelationsResponse, CsilCborError> {
    let relations = {
        let csil_field = cbor_require(csil_root, "relations")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_relation);
        csil_decode(csil_field)?
    };
    Ok(ListRelationsResponse { relations })
}

/// Encode a ListRelationsResponse to canonical CSIL CBOR bytes.
pub fn encode_list_relations_response(csil_v: &ListRelationsResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_list_relations_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListRelationsResponse.
pub fn decode_list_relations_response(
    csil_data: &[u8],
) -> Result<ListRelationsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_relations_response(&csil_root)
}

/// Build the canonical CBOR value tree for a CheckPermissionRequest.
fn csil_enc_check_permission_request(csil_v: &CheckPermissionRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("relation"), cbor_text(&csil_v.relation)));
    csil_entries.push((cbor_text("object_id"), cbor_text(&csil_v.object_id)));
    csil_entries.push((cbor_text("object_type"), cbor_text(&csil_v.object_type)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a CheckPermissionRequest from a decoded CBOR value tree.
fn csil_dec_check_permission_request(
    csil_root: &CsilCborValue,
) -> Result<CheckPermissionRequest, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let relation = {
        let csil_field = cbor_require(csil_root, "relation")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let object_type = {
        let csil_field = cbor_require(csil_root, "object_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let object_id = {
        let csil_field = cbor_require(csil_root, "object_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(CheckPermissionRequest {
        user_id,
        relation,
        object_type,
        object_id,
    })
}

/// Encode a CheckPermissionRequest to canonical CSIL CBOR bytes.
pub fn encode_check_permission_request(csil_v: &CheckPermissionRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_check_permission_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a CheckPermissionRequest.
pub fn decode_check_permission_request(
    csil_data: &[u8],
) -> Result<CheckPermissionRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_check_permission_request(&csil_root)
}

/// Build the canonical CBOR value tree for a CheckPermissionResponse.
fn csil_enc_check_permission_response(csil_v: &CheckPermissionResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("allowed"), cbor_bool(csil_v.allowed)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a CheckPermissionResponse from a decoded CBOR value tree.
fn csil_dec_check_permission_response(
    csil_root: &CsilCborValue,
) -> Result<CheckPermissionResponse, CsilCborError> {
    let allowed = {
        let csil_field = cbor_require(csil_root, "allowed")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(CheckPermissionResponse { allowed })
}

/// Encode a CheckPermissionResponse to canonical CSIL CBOR bytes.
pub fn encode_check_permission_response(csil_v: &CheckPermissionResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_check_permission_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a CheckPermissionResponse.
pub fn decode_check_permission_response(
    csil_data: &[u8],
) -> Result<CheckPermissionResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_check_permission_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ChangePasswordRequest.
fn csil_enc_change_password_request(csil_v: &ChangePasswordRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("new_password"), cbor_text(&csil_v.new_password)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ChangePasswordRequest from a decoded CBOR value tree.
fn csil_dec_change_password_request(
    csil_root: &CsilCborValue,
) -> Result<ChangePasswordRequest, CsilCborError> {
    let new_password = {
        let csil_field = cbor_require(csil_root, "new_password")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ChangePasswordRequest { new_password })
}

/// Encode a ChangePasswordRequest to canonical CSIL CBOR bytes.
pub fn encode_change_password_request(csil_v: &ChangePasswordRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_change_password_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ChangePasswordRequest.
pub fn decode_change_password_request(
    csil_data: &[u8],
) -> Result<ChangePasswordRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_change_password_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ChangePasswordResponse.
fn csil_enc_change_password_response(csil_v: &ChangePasswordResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ChangePasswordResponse from a decoded CBOR value tree.
fn csil_dec_change_password_response(
    csil_root: &CsilCborValue,
) -> Result<ChangePasswordResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(ChangePasswordResponse { success })
}

/// Encode a ChangePasswordResponse to canonical CSIL CBOR bytes.
pub fn encode_change_password_response(csil_v: &ChangePasswordResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_change_password_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ChangePasswordResponse.
pub fn decode_change_password_response(
    csil_data: &[u8],
) -> Result<ChangePasswordResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_change_password_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetMyInfoResponse.
fn csil_enc_get_my_info_response(csil_v: &GetMyInfoResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)));
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim),
    ));
    csil_entries.push((
        cbor_text("relations"),
        cbor_enc_array(&csil_v.relations, csil_enc_relation),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetMyInfoResponse from a decoded CBOR value tree.
fn csil_dec_get_my_info_response(
    csil_root: &CsilCborValue,
) -> Result<GetMyInfoResponse, CsilCborError> {
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    let relations = {
        let csil_field = cbor_require(csil_root, "relations")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_relation);
        csil_decode(csil_field)?
    };
    let claims = {
        let csil_field = cbor_require(csil_root, "claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim);
        csil_decode(csil_field)?
    };
    Ok(GetMyInfoResponse {
        user,
        relations,
        claims,
    })
}

/// Encode a GetMyInfoResponse to canonical CSIL CBOR bytes.
pub fn encode_get_my_info_response(csil_v: &GetMyInfoResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_get_my_info_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetMyInfoResponse.
pub fn decode_get_my_info_response(csil_data: &[u8]) -> Result<GetMyInfoResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_my_info_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetMyClaimRequest.
fn csil_enc_set_my_claim_request(csil_v: &SetMyClaimRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("claim_value"), cbor_text(&csil_v.claim_value)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetMyClaimRequest from a decoded CBOR value tree.
fn csil_dec_set_my_claim_request(
    csil_root: &CsilCborValue,
) -> Result<SetMyClaimRequest, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_value = {
        let csil_field = cbor_require(csil_root, "claim_value")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(SetMyClaimRequest {
        claim_type,
        claim_value,
    })
}

/// Encode a SetMyClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_set_my_claim_request(csil_v: &SetMyClaimRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_set_my_claim_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetMyClaimRequest.
pub fn decode_set_my_claim_request(csil_data: &[u8]) -> Result<SetMyClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_my_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetMyClaimResponse.
fn csil_enc_set_my_claim_response(csil_v: &SetMyClaimResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.claim {
        csil_entries.push((cbor_text("claim"), csil_enc_claim(csil_inner)));
    }
    csil_entries.push((cbor_text("outcome"), cbor_text(&csil_v.outcome)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetMyClaimResponse from a decoded CBOR value tree.
fn csil_dec_set_my_claim_response(
    csil_root: &CsilCborValue,
) -> Result<SetMyClaimResponse, CsilCborError> {
    let outcome = {
        let csil_field = cbor_require(csil_root, "outcome")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim = match cbor_map_get(csil_root, "claim") {
        Some(csil_field) => {
            let csil_decode = csil_dec_claim;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(SetMyClaimResponse { outcome, claim })
}

/// Encode a SetMyClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_set_my_claim_response(csil_v: &SetMyClaimResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_set_my_claim_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetMyClaimResponse.
pub fn decode_set_my_claim_response(csil_data: &[u8]) -> Result<SetMyClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_my_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveMyClaimRequest.
fn csil_enc_remove_my_claim_request(csil_v: &RemoveMyClaimRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim_id"), cbor_text(&csil_v.claim_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveMyClaimRequest from a decoded CBOR value tree.
fn csil_dec_remove_my_claim_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveMyClaimRequest, CsilCborError> {
    let claim_id = {
        let csil_field = cbor_require(csil_root, "claim_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveMyClaimRequest { claim_id })
}

/// Encode a RemoveMyClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_my_claim_request(csil_v: &RemoveMyClaimRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_my_claim_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveMyClaimRequest.
pub fn decode_remove_my_claim_request(
    csil_data: &[u8],
) -> Result<RemoveMyClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_my_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveMyClaimResponse.
fn csil_enc_remove_my_claim_response(csil_v: &RemoveMyClaimResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RemoveMyClaimResponse from a decoded CBOR value tree.
fn csil_dec_remove_my_claim_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveMyClaimResponse, CsilCborError> {
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveMyClaimResponse { success })
}

/// Encode a RemoveMyClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_my_claim_response(csil_v: &RemoveMyClaimResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_remove_my_claim_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RemoveMyClaimResponse.
pub fn decode_remove_my_claim_response(
    csil_data: &[u8],
) -> Result<RemoveMyClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_my_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetMyClaimSharingRequest.
fn csil_enc_set_my_claim_sharing_request(csil_v: &SetMyClaimSharingRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("share"), cbor_bool(csil_v.share)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetMyClaimSharingRequest from a decoded CBOR value tree.
fn csil_dec_set_my_claim_sharing_request(
    csil_root: &CsilCborValue,
) -> Result<SetMyClaimSharingRequest, CsilCborError> {
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let share = {
        let csil_field = cbor_require(csil_root, "share")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(SetMyClaimSharingRequest { claim_type, share })
}

/// Encode a SetMyClaimSharingRequest to canonical CSIL CBOR bytes.
pub fn encode_set_my_claim_sharing_request(csil_v: &SetMyClaimSharingRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_set_my_claim_sharing_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetMyClaimSharingRequest.
pub fn decode_set_my_claim_sharing_request(
    csil_data: &[u8],
) -> Result<SetMyClaimSharingRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_my_claim_sharing_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetMyClaimSharingResponse.
fn csil_enc_set_my_claim_sharing_response(_csil_v: &SetMyClaimSharingResponse) -> CsilCborValue {
    CsilCborValue::Map(Vec::new())
}

/// Reconstruct a SetMyClaimSharingResponse from a decoded CBOR value tree.
fn csil_dec_set_my_claim_sharing_response(
    _csil_root: &CsilCborValue,
) -> Result<SetMyClaimSharingResponse, CsilCborError> {
    Ok(SetMyClaimSharingResponse {})
}

/// Encode a SetMyClaimSharingResponse to canonical CSIL CBOR bytes.
pub fn encode_set_my_claim_sharing_response(csil_v: &SetMyClaimSharingResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_set_my_claim_sharing_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetMyClaimSharingResponse.
pub fn decode_set_my_claim_sharing_response(
    csil_data: &[u8],
) -> Result<SetMyClaimSharingResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_my_claim_sharing_response(&csil_root)
}

/// Build the canonical CBOR value tree for a Profile.
fn csil_enc_profile(csil_v: &Profile) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    if let Some(csil_inner) = &csil_v.label {
        csil_entries.push((cbor_text("label"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("is_root"), cbor_bool(csil_v.is_root)));
    csil_entries.push((cbor_text("account_id"), cbor_text(&csil_v.account_id)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a Profile from a decoded CBOR value tree.
fn csil_dec_profile(csil_root: &CsilCborValue) -> Result<Profile, CsilCborError> {
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let account_id = {
        let csil_field = cbor_require(csil_root, "account_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let is_root = {
        let csil_field = cbor_require(csil_root, "is_root")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let label = match cbor_map_get(csil_root, "label") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(Profile {
        id,
        account_id,
        domain,
        is_root,
        label,
    })
}

/// Encode a Profile to canonical CSIL CBOR bytes.
pub fn encode_profile(csil_v: &Profile) -> Vec<u8> {
    cbor_encode(&csil_enc_profile(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a Profile.
pub fn decode_profile(csil_data: &[u8]) -> Result<Profile, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_profile(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateProfileRequest.
fn csil_enc_create_profile_request(csil_v: &CreateProfileRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    if let Some(csil_inner) = &csil_v.label {
        csil_entries.push((cbor_text("label"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a CreateProfileRequest from a decoded CBOR value tree.
fn csil_dec_create_profile_request(
    csil_root: &CsilCborValue,
) -> Result<CreateProfileRequest, CsilCborError> {
    let label = match cbor_map_get(csil_root, "label") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(CreateProfileRequest { label })
}

/// Encode a CreateProfileRequest to canonical CSIL CBOR bytes.
pub fn encode_create_profile_request(csil_v: &CreateProfileRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_create_profile_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a CreateProfileRequest.
pub fn decode_create_profile_request(
    csil_data: &[u8],
) -> Result<CreateProfileRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_profile_request(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateProfileResponse.
fn csil_enc_create_profile_response(csil_v: &CreateProfileResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("profile"), csil_enc_profile(&csil_v.profile)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a CreateProfileResponse from a decoded CBOR value tree.
fn csil_dec_create_profile_response(
    csil_root: &CsilCborValue,
) -> Result<CreateProfileResponse, CsilCborError> {
    let profile = {
        let csil_field = cbor_require(csil_root, "profile")?;
        let csil_decode = csil_dec_profile;
        csil_decode(csil_field)?
    };
    Ok(CreateProfileResponse { profile })
}

/// Encode a CreateProfileResponse to canonical CSIL CBOR bytes.
pub fn encode_create_profile_response(csil_v: &CreateProfileResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_create_profile_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a CreateProfileResponse.
pub fn decode_create_profile_response(
    csil_data: &[u8],
) -> Result<CreateProfileResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_profile_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RequestVerificationRequest.
fn csil_enc_request_verification_request(csil_v: &RequestVerificationRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("issuer_domain"), cbor_text(&csil_v.issuer_domain)));
    csil_entries.push((
        cbor_text("requested_claim_types"),
        cbor_enc_array(&csil_v.requested_claim_types, |csil_elem| {
            cbor_text(csil_elem)
        }),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RequestVerificationRequest from a decoded CBOR value tree.
fn csil_dec_request_verification_request(
    csil_root: &CsilCborValue,
) -> Result<RequestVerificationRequest, CsilCborError> {
    let issuer_domain = {
        let csil_field = cbor_require(csil_root, "issuer_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let requested_claim_types = {
        let csil_field = cbor_require(csil_root, "requested_claim_types")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(RequestVerificationRequest {
        issuer_domain,
        requested_claim_types,
    })
}

/// Encode a RequestVerificationRequest to canonical CSIL CBOR bytes.
pub fn encode_request_verification_request(csil_v: &RequestVerificationRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_request_verification_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RequestVerificationRequest.
pub fn decode_request_verification_request(
    csil_data: &[u8],
) -> Result<RequestVerificationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_request_verification_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RequestVerificationResponse.
fn csil_enc_request_verification_response(csil_v: &RequestVerificationResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("signed_request"),
        csil_enc_signed_signing_request(&csil_v.signed_request),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RequestVerificationResponse from a decoded CBOR value tree.
fn csil_dec_request_verification_response(
    csil_root: &CsilCborValue,
) -> Result<RequestVerificationResponse, CsilCborError> {
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = csil_dec_signed_signing_request;
        csil_decode(csil_field)?
    };
    Ok(RequestVerificationResponse { signed_request })
}

/// Encode a RequestVerificationResponse to canonical CSIL CBOR bytes.
pub fn encode_request_verification_response(csil_v: &RequestVerificationResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_request_verification_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RequestVerificationResponse.
pub fn decode_request_verification_response(
    csil_data: &[u8],
) -> Result<RequestVerificationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_request_verification_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpSignRequest.
fn csil_enc_rp_sign_request(csil_v: &RpSignRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    csil_entries.push((cbor_text("callback_url"), cbor_text(&csil_v.callback_url)));
    if let Some(csil_inner) = &csil_v.flow_context {
        csil_entries.push((
            cbor_text("flow_context"),
            csil_enc_auth_flow_context(csil_inner),
        ));
    }
    if let Some(csil_inner) = &csil_v.requested_claims {
        csil_entries.push((
            cbor_text("requested_claims"),
            csil_enc_claim_request(csil_inner),
        ));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RpSignRequest from a decoded CBOR value tree.
fn csil_dec_rp_sign_request(csil_root: &CsilCborValue) -> Result<RpSignRequest, CsilCborError> {
    let callback_url = {
        let csil_field = cbor_require(csil_root, "callback_url")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let requested_claims = match cbor_map_get(csil_root, "requested_claims") {
        Some(csil_field) => {
            let csil_decode = csil_dec_claim_request;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let flow_context = match cbor_map_get(csil_root, "flow_context") {
        Some(csil_field) => {
            let csil_decode = csil_dec_auth_flow_context;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(RpSignRequest {
        callback_url,
        nonce,
        requested_claims,
        flow_context,
    })
}

/// Encode a RpSignRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_sign_request(csil_v: &RpSignRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_rp_sign_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RpSignRequest.
pub fn decode_rp_sign_request(csil_data: &[u8]) -> Result<RpSignRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_sign_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpSignResponse.
fn csil_enc_rp_sign_response(csil_v: &RpSignResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RpSignResponse from a decoded CBOR value tree.
fn csil_dec_rp_sign_response(csil_root: &CsilCborValue) -> Result<RpSignResponse, CsilCborError> {
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RpSignResponse { signed_request })
}

/// Encode a RpSignResponse to canonical CSIL CBOR bytes.
pub fn encode_rp_sign_response(csil_v: &RpSignResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_rp_sign_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RpSignResponse.
pub fn decode_rp_sign_response(csil_data: &[u8]) -> Result<RpSignResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_sign_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpDecryptRequest.
fn csil_enc_rp_decrypt_request(csil_v: &RpDecryptRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("encrypted_token"),
        cbor_text(&csil_v.encrypted_token),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RpDecryptRequest from a decoded CBOR value tree.
fn csil_dec_rp_decrypt_request(
    csil_root: &CsilCborValue,
) -> Result<RpDecryptRequest, CsilCborError> {
    let encrypted_token = {
        let csil_field = cbor_require(csil_root, "encrypted_token")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RpDecryptRequest { encrypted_token })
}

/// Encode a RpDecryptRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_decrypt_request(csil_v: &RpDecryptRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_rp_decrypt_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RpDecryptRequest.
pub fn decode_rp_decrypt_request(csil_data: &[u8]) -> Result<RpDecryptRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_decrypt_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpDecryptResponse.
fn csil_enc_rp_decrypt_response(csil_v: &RpDecryptResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("signed_assertion"),
        cbor_text(&csil_v.signed_assertion),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RpDecryptResponse from a decoded CBOR value tree.
fn csil_dec_rp_decrypt_response(
    csil_root: &CsilCborValue,
) -> Result<RpDecryptResponse, CsilCborError> {
    let signed_assertion = {
        let csil_field = cbor_require(csil_root, "signed_assertion")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RpDecryptResponse { signed_assertion })
}

/// Encode a RpDecryptResponse to canonical CSIL CBOR bytes.
pub fn encode_rp_decrypt_response(csil_v: &RpDecryptResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_rp_decrypt_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RpDecryptResponse.
pub fn decode_rp_decrypt_response(csil_data: &[u8]) -> Result<RpDecryptResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_decrypt_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpVerifyRequest.
fn csil_enc_rp_verify_request(csil_v: &RpVerifyRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("expected_domain"),
        cbor_text(&csil_v.expected_domain),
    ));
    csil_entries.push((
        cbor_text("signed_assertion"),
        cbor_text(&csil_v.signed_assertion),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RpVerifyRequest from a decoded CBOR value tree.
fn csil_dec_rp_verify_request(csil_root: &CsilCborValue) -> Result<RpVerifyRequest, CsilCborError> {
    let signed_assertion = {
        let csil_field = cbor_require(csil_root, "signed_assertion")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expected_domain = {
        let csil_field = cbor_require(csil_root, "expected_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RpVerifyRequest {
        signed_assertion,
        expected_domain,
    })
}

/// Encode a RpVerifyRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_verify_request(csil_v: &RpVerifyRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_rp_verify_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RpVerifyRequest.
pub fn decode_rp_verify_request(csil_data: &[u8]) -> Result<RpVerifyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_verify_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpVerifyResponse.
fn csil_enc_rp_verify_response(csil_v: &RpVerifyResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("verified"), cbor_bool(csil_v.verified)));
    csil_entries.push((
        cbor_text("assertion"),
        csil_enc_identity_assertion(&csil_v.assertion),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RpVerifyResponse from a decoded CBOR value tree.
fn csil_dec_rp_verify_response(
    csil_root: &CsilCborValue,
) -> Result<RpVerifyResponse, CsilCborError> {
    let assertion = {
        let csil_field = cbor_require(csil_root, "assertion")?;
        let csil_decode = csil_dec_identity_assertion;
        csil_decode(csil_field)?
    };
    let verified = {
        let csil_field = cbor_require(csil_root, "verified")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RpVerifyResponse {
        assertion,
        verified,
    })
}

/// Encode a RpVerifyResponse to canonical CSIL CBOR bytes.
pub fn encode_rp_verify_response(csil_v: &RpVerifyResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_rp_verify_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RpVerifyResponse.
pub fn decode_rp_verify_response(csil_data: &[u8]) -> Result<RpVerifyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_verify_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpUserInfoRequest.
fn csil_enc_rp_user_info_request(csil_v: &RpUserInfoRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("token"), cbor_text(&csil_v.token)));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("api_base"), cbor_text(&csil_v.api_base)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RpUserInfoRequest from a decoded CBOR value tree.
fn csil_dec_rp_user_info_request(
    csil_root: &CsilCborValue,
) -> Result<RpUserInfoRequest, CsilCborError> {
    let token = {
        let csil_field = cbor_require(csil_root, "token")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let api_base = {
        let csil_field = cbor_require(csil_root, "api_base")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RpUserInfoRequest {
        token,
        api_base,
        domain,
    })
}

/// Encode a RpUserInfoRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_user_info_request(csil_v: &RpUserInfoRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_rp_user_info_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RpUserInfoRequest.
pub fn decode_rp_user_info_request(csil_data: &[u8]) -> Result<RpUserInfoRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_user_info_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpIssueAttestationRequest.
fn csil_enc_rp_issue_attestation_request(csil_v: &RpIssueAttestationRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("claim_value"), cbor_bytes(&csil_v.claim_value)));
    csil_entries.push((
        cbor_text("signed_request"),
        csil_enc_signed_signing_request(&csil_v.signed_request),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RpIssueAttestationRequest from a decoded CBOR value tree.
fn csil_dec_rp_issue_attestation_request(
    csil_root: &CsilCborValue,
) -> Result<RpIssueAttestationRequest, CsilCborError> {
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = csil_dec_signed_signing_request;
        csil_decode(csil_field)?
    };
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_value = {
        let csil_field = cbor_require(csil_root, "claim_value")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(RpIssueAttestationRequest {
        signed_request,
        claim_type,
        claim_value,
    })
}

/// Encode a RpIssueAttestationRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_issue_attestation_request(csil_v: &RpIssueAttestationRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_rp_issue_attestation_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RpIssueAttestationRequest.
pub fn decode_rp_issue_attestation_request(
    csil_data: &[u8],
) -> Result<RpIssueAttestationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_issue_attestation_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpIssueAttestationResponse.
fn csil_enc_rp_issue_attestation_response(csil_v: &RpIssueAttestationResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim"), csil_enc_claim(&csil_v.claim)));
    csil_entries.push((cbor_text("deposited"), cbor_bool(csil_v.deposited)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RpIssueAttestationResponse from a decoded CBOR value tree.
fn csil_dec_rp_issue_attestation_response(
    csil_root: &CsilCborValue,
) -> Result<RpIssueAttestationResponse, CsilCborError> {
    let claim = {
        let csil_field = cbor_require(csil_root, "claim")?;
        let csil_decode = csil_dec_claim;
        csil_decode(csil_field)?
    };
    let deposited = {
        let csil_field = cbor_require(csil_root, "deposited")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RpIssueAttestationResponse { claim, deposited })
}

/// Encode a RpIssueAttestationResponse to canonical CSIL CBOR bytes.
pub fn encode_rp_issue_attestation_response(csil_v: &RpIssueAttestationResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_rp_issue_attestation_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RpIssueAttestationResponse.
pub fn decode_rp_issue_attestation_response(
    csil_data: &[u8],
) -> Result<RpIssueAttestationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_issue_attestation_response(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpDescriptor.
fn csil_enc_local_rp_descriptor(csil_v: &LocalRpDescriptor) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("app_name"), cbor_text(&csil_v.app_name)));
    csil_entries.push((cbor_text("created_at"), cbor_text(&csil_v.created_at)));
    csil_entries.push((cbor_text("expires_at"), cbor_text(&csil_v.expires_at)));
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    csil_entries.push((
        cbor_text("supported_suites"),
        cbor_enc_array(&csil_v.supported_suites, |csil_elem| cbor_text(csil_elem)),
    ));
    if let Some(csil_inner) = &csil_v.local_domain_hint {
        csil_entries.push((cbor_text("local_domain_hint"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("signing_public_key"),
        cbor_bytes(&csil_v.signing_public_key),
    ));
    csil_entries.push((
        cbor_text("encryption_public_key"),
        cbor_bytes(&csil_v.encryption_public_key),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a LocalRpDescriptor from a decoded CBOR value tree.
fn csil_dec_local_rp_descriptor(
    csil_root: &CsilCborValue,
) -> Result<LocalRpDescriptor, CsilCborError> {
    let app_name = {
        let csil_field = cbor_require(csil_root, "app_name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let local_domain_hint = match cbor_map_get(csil_root, "local_domain_hint") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let signing_public_key = {
        let csil_field = cbor_require(csil_root, "signing_public_key")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let encryption_public_key = {
        let csil_field = cbor_require(csil_root, "encryption_public_key")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let supported_suites = {
        let csil_field = cbor_require(csil_root, "supported_suites")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(LocalRpDescriptor {
        app_name,
        local_domain_hint,
        signing_public_key,
        encryption_public_key,
        fingerprint,
        supported_suites,
        created_at,
        expires_at,
    })
}

/// Encode a LocalRpDescriptor to canonical CSIL CBOR bytes.
pub fn encode_local_rp_descriptor(csil_v: &LocalRpDescriptor) -> Vec<u8> {
    cbor_encode(&csil_enc_local_rp_descriptor(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpDescriptor.
pub fn decode_local_rp_descriptor(csil_data: &[u8]) -> Result<LocalRpDescriptor, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_descriptor(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedLocalRpDescriptor.
fn csil_enc_signed_local_rp_descriptor(csil_v: &SignedLocalRpDescriptor) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((cbor_text("descriptor"), cbor_bytes(&csil_v.descriptor)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SignedLocalRpDescriptor from a decoded CBOR value tree.
fn csil_dec_signed_local_rp_descriptor(
    csil_root: &CsilCborValue,
) -> Result<SignedLocalRpDescriptor, CsilCborError> {
    let descriptor = {
        let csil_field = cbor_require(csil_root, "descriptor")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signature = {
        let csil_field = cbor_require(csil_root, "signature")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(SignedLocalRpDescriptor {
        descriptor,
        signature,
    })
}

/// Encode a SignedLocalRpDescriptor to canonical CSIL CBOR bytes.
pub fn encode_signed_local_rp_descriptor(csil_v: &SignedLocalRpDescriptor) -> Vec<u8> {
    cbor_encode(&csil_enc_signed_local_rp_descriptor(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SignedLocalRpDescriptor.
pub fn decode_signed_local_rp_descriptor(
    csil_data: &[u8],
) -> Result<SignedLocalRpDescriptor, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_local_rp_descriptor(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpLoginRequest.
fn csil_enc_local_rp_login_request(csil_v: &LocalRpLoginRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("nonce"), cbor_bytes(&csil_v.nonce)));
    csil_entries.push((cbor_text("state"), cbor_bytes(&csil_v.state)));
    csil_entries.push((cbor_text("issued_at"), cbor_text(&csil_v.issued_at)));
    csil_entries.push((
        cbor_text("descriptor"),
        csil_enc_signed_local_rp_descriptor(&csil_v.descriptor),
    ));
    csil_entries.push((cbor_text("expires_at"), cbor_text(&csil_v.expires_at)));
    csil_entries.push((cbor_text("callback_url"), cbor_text(&csil_v.callback_url)));
    csil_entries.push((
        cbor_text("required_claims"),
        cbor_enc_array(&csil_v.required_claims, |csil_elem| cbor_text(csil_elem)),
    ));
    csil_entries.push((
        cbor_text("requested_claims"),
        cbor_enc_array(&csil_v.requested_claims, |csil_elem| cbor_text(csil_elem)),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a LocalRpLoginRequest from a decoded CBOR value tree.
fn csil_dec_local_rp_login_request(
    csil_root: &CsilCborValue,
) -> Result<LocalRpLoginRequest, CsilCborError> {
    let descriptor = {
        let csil_field = cbor_require(csil_root, "descriptor")?;
        let csil_decode = csil_dec_signed_local_rp_descriptor;
        csil_decode(csil_field)?
    };
    let callback_url = {
        let csil_field = cbor_require(csil_root, "callback_url")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let state = {
        let csil_field = cbor_require(csil_root, "state")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let requested_claims = {
        let csil_field = cbor_require(csil_root, "requested_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let required_claims = {
        let csil_field = cbor_require(csil_root, "required_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(LocalRpLoginRequest {
        descriptor,
        callback_url,
        nonce,
        state,
        requested_claims,
        required_claims,
        issued_at,
        expires_at,
    })
}

/// Encode a LocalRpLoginRequest to canonical CSIL CBOR bytes.
pub fn encode_local_rp_login_request(csil_v: &LocalRpLoginRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_local_rp_login_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpLoginRequest.
pub fn decode_local_rp_login_request(
    csil_data: &[u8],
) -> Result<LocalRpLoginRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_login_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedLocalRpLoginRequest.
fn csil_enc_signed_local_rp_login_request(csil_v: &SignedLocalRpLoginRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SignedLocalRpLoginRequest from a decoded CBOR value tree.
fn csil_dec_signed_local_rp_login_request(
    csil_root: &CsilCborValue,
) -> Result<SignedLocalRpLoginRequest, CsilCborError> {
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signature = {
        let csil_field = cbor_require(csil_root, "signature")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(SignedLocalRpLoginRequest { request, signature })
}

/// Encode a SignedLocalRpLoginRequest to canonical CSIL CBOR bytes.
pub fn encode_signed_local_rp_login_request(csil_v: &SignedLocalRpLoginRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_signed_local_rp_login_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SignedLocalRpLoginRequest.
pub fn decode_signed_local_rp_login_request(
    csil_data: &[u8],
) -> Result<SignedLocalRpLoginRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_local_rp_login_request(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpCallbackHeader.
fn csil_enc_local_rp_callback_header(csil_v: &LocalRpCallbackHeader) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("nonce"), cbor_bytes(&csil_v.nonce)));
    csil_entries.push((cbor_text("state"), cbor_bytes(&csil_v.state)));
    csil_entries.push((cbor_text("suite"), cbor_text(&csil_v.suite)));
    csil_entries.push((cbor_text("issued_at"), cbor_text(&csil_v.issued_at)));
    csil_entries.push((cbor_text("aead_nonce"), cbor_bytes(&csil_v.aead_nonce)));
    csil_entries.push((cbor_text("expires_at"), cbor_text(&csil_v.expires_at)));
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    csil_entries.push((
        cbor_text("ephemeral_public_key"),
        cbor_bytes(&csil_v.ephemeral_public_key),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a LocalRpCallbackHeader from a decoded CBOR value tree.
fn csil_dec_local_rp_callback_header(
    csil_root: &CsilCborValue,
) -> Result<LocalRpCallbackHeader, CsilCborError> {
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let state = {
        let csil_field = cbor_require(csil_root, "state")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let suite = {
        let csil_field = cbor_require(csil_root, "suite")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let ephemeral_public_key = {
        let csil_field = cbor_require(csil_root, "ephemeral_public_key")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let aead_nonce = {
        let csil_field = cbor_require(csil_root, "aead_nonce")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(LocalRpCallbackHeader {
        fingerprint,
        nonce,
        state,
        suite,
        ephemeral_public_key,
        aead_nonce,
        issued_at,
        expires_at,
    })
}

/// Encode a LocalRpCallbackHeader to canonical CSIL CBOR bytes.
pub fn encode_local_rp_callback_header(csil_v: &LocalRpCallbackHeader) -> Vec<u8> {
    cbor_encode(&csil_enc_local_rp_callback_header(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpCallbackHeader.
pub fn decode_local_rp_callback_header(
    csil_data: &[u8],
) -> Result<LocalRpCallbackHeader, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_callback_header(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpEncryptedCallback.
fn csil_enc_local_rp_encrypted_callback(csil_v: &LocalRpEncryptedCallback) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("header"), cbor_bytes(&csil_v.header)));
    csil_entries.push((cbor_text("ciphertext"), cbor_bytes(&csil_v.ciphertext)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a LocalRpEncryptedCallback from a decoded CBOR value tree.
fn csil_dec_local_rp_encrypted_callback(
    csil_root: &CsilCborValue,
) -> Result<LocalRpEncryptedCallback, CsilCborError> {
    let header = {
        let csil_field = cbor_require(csil_root, "header")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let ciphertext = {
        let csil_field = cbor_require(csil_root, "ciphertext")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(LocalRpEncryptedCallback { header, ciphertext })
}

/// Encode a LocalRpEncryptedCallback to canonical CSIL CBOR bytes.
pub fn encode_local_rp_encrypted_callback(csil_v: &LocalRpEncryptedCallback) -> Vec<u8> {
    cbor_encode(&csil_enc_local_rp_encrypted_callback(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpEncryptedCallback.
pub fn decode_local_rp_encrypted_callback(
    csil_data: &[u8],
) -> Result<LocalRpEncryptedCallback, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_encrypted_callback(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpCallbackPayload.
fn csil_enc_local_rp_callback_payload(csil_v: &LocalRpCallbackPayload) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((cbor_text("nonce"), cbor_bytes(&csil_v.nonce)));
    csil_entries.push((cbor_text("state"), cbor_bytes(&csil_v.state)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("issued_at"), cbor_text(&csil_v.issued_at)));
    csil_entries.push((cbor_text("expires_at"), cbor_text(&csil_v.expires_at)));
    csil_entries.push((cbor_text("user_domain"), cbor_text(&csil_v.user_domain)));
    csil_entries.push((cbor_text("callback_url"), cbor_text(&csil_v.callback_url)));
    csil_entries.push((cbor_text("claim_ticket"), cbor_bytes(&csil_v.claim_ticket)));
    csil_entries.push((
        cbor_text("audience_fingerprint"),
        cbor_text(&csil_v.audience_fingerprint),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a LocalRpCallbackPayload from a decoded CBOR value tree.
fn csil_dec_local_rp_callback_payload(
    csil_root: &CsilCborValue,
) -> Result<LocalRpCallbackPayload, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let user_domain = {
        let csil_field = cbor_require(csil_root, "user_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_ticket = {
        let csil_field = cbor_require(csil_root, "claim_ticket")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let audience_fingerprint = {
        let csil_field = cbor_require(csil_root, "audience_fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let callback_url = {
        let csil_field = cbor_require(csil_root, "callback_url")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let state = {
        let csil_field = cbor_require(csil_root, "state")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(LocalRpCallbackPayload {
        user_id,
        user_domain,
        claim_ticket,
        audience_fingerprint,
        callback_url,
        nonce,
        state,
        issued_at,
        expires_at,
    })
}

/// Encode a LocalRpCallbackPayload to canonical CSIL CBOR bytes.
pub fn encode_local_rp_callback_payload(csil_v: &LocalRpCallbackPayload) -> Vec<u8> {
    cbor_encode(&csil_enc_local_rp_callback_payload(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpCallbackPayload.
pub fn decode_local_rp_callback_payload(
    csil_data: &[u8],
) -> Result<LocalRpCallbackPayload, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_callback_payload(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedLocalRpCallbackPayload.
fn csil_enc_signed_local_rp_callback_payload(
    csil_v: &SignedLocalRpCallbackPayload,
) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("payload"), cbor_bytes(&csil_v.payload)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((
        cbor_text("signing_key_id"),
        cbor_text(&csil_v.signing_key_id),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SignedLocalRpCallbackPayload from a decoded CBOR value tree.
fn csil_dec_signed_local_rp_callback_payload(
    csil_root: &CsilCborValue,
) -> Result<SignedLocalRpCallbackPayload, CsilCborError> {
    let payload = {
        let csil_field = cbor_require(csil_root, "payload")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signing_key_id = {
        let csil_field = cbor_require(csil_root, "signing_key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signature = {
        let csil_field = cbor_require(csil_root, "signature")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(SignedLocalRpCallbackPayload {
        payload,
        signing_key_id,
        signature,
    })
}

/// Encode a SignedLocalRpCallbackPayload to canonical CSIL CBOR bytes.
pub fn encode_signed_local_rp_callback_payload(csil_v: &SignedLocalRpCallbackPayload) -> Vec<u8> {
    cbor_encode(&csil_enc_signed_local_rp_callback_payload(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SignedLocalRpCallbackPayload.
pub fn decode_signed_local_rp_callback_payload(
    csil_data: &[u8],
) -> Result<SignedLocalRpCallbackPayload, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_local_rp_callback_payload(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpTicketRedemptionRequest.
fn csil_enc_local_rp_ticket_redemption_request(
    csil_v: &LocalRpTicketRedemptionRequest,
) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("issued_at"), cbor_text(&csil_v.issued_at)));
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    csil_entries.push((cbor_text("claim_ticket"), cbor_bytes(&csil_v.claim_ticket)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a LocalRpTicketRedemptionRequest from a decoded CBOR value tree.
fn csil_dec_local_rp_ticket_redemption_request(
    csil_root: &CsilCborValue,
) -> Result<LocalRpTicketRedemptionRequest, CsilCborError> {
    let claim_ticket = {
        let csil_field = cbor_require(csil_root, "claim_ticket")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(LocalRpTicketRedemptionRequest {
        claim_ticket,
        fingerprint,
        issued_at,
    })
}

/// Encode a LocalRpTicketRedemptionRequest to canonical CSIL CBOR bytes.
pub fn encode_local_rp_ticket_redemption_request(
    csil_v: &LocalRpTicketRedemptionRequest,
) -> Vec<u8> {
    cbor_encode(&csil_enc_local_rp_ticket_redemption_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpTicketRedemptionRequest.
pub fn decode_local_rp_ticket_redemption_request(
    csil_data: &[u8],
) -> Result<LocalRpTicketRedemptionRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_ticket_redemption_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedLocalRpTicketRedemptionRequest.
fn csil_enc_signed_local_rp_ticket_redemption_request(
    csil_v: &SignedLocalRpTicketRedemptionRequest,
) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SignedLocalRpTicketRedemptionRequest from a decoded CBOR value tree.
fn csil_dec_signed_local_rp_ticket_redemption_request(
    csil_root: &CsilCborValue,
) -> Result<SignedLocalRpTicketRedemptionRequest, CsilCborError> {
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signature = {
        let csil_field = cbor_require(csil_root, "signature")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(SignedLocalRpTicketRedemptionRequest { request, signature })
}

/// Encode a SignedLocalRpTicketRedemptionRequest to canonical CSIL CBOR bytes.
pub fn encode_signed_local_rp_ticket_redemption_request(
    csil_v: &SignedLocalRpTicketRedemptionRequest,
) -> Vec<u8> {
    cbor_encode(&csil_enc_signed_local_rp_ticket_redemption_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SignedLocalRpTicketRedemptionRequest.
pub fn decode_signed_local_rp_ticket_redemption_request(
    csil_data: &[u8],
) -> Result<SignedLocalRpTicketRedemptionRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_local_rp_ticket_redemption_request(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpTicketRedemptionResponse.
fn csil_enc_local_rp_ticket_redemption_response(
    csil_v: &LocalRpTicketRedemptionResponse,
) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim),
    ));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("user_domain"), cbor_text(&csil_v.user_domain)));
    csil_entries.push((
        cbor_text("ticket_expires_at"),
        cbor_text(&csil_v.ticket_expires_at),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a LocalRpTicketRedemptionResponse from a decoded CBOR value tree.
fn csil_dec_local_rp_ticket_redemption_response(
    csil_root: &CsilCborValue,
) -> Result<LocalRpTicketRedemptionResponse, CsilCborError> {
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let user_domain = {
        let csil_field = cbor_require(csil_root, "user_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claims = {
        let csil_field = cbor_require(csil_root, "claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim);
        csil_decode(csil_field)?
    };
    let ticket_expires_at = {
        let csil_field = cbor_require(csil_root, "ticket_expires_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(LocalRpTicketRedemptionResponse {
        user_id,
        user_domain,
        claims,
        ticket_expires_at,
    })
}

/// Encode a LocalRpTicketRedemptionResponse to canonical CSIL CBOR bytes.
pub fn encode_local_rp_ticket_redemption_response(
    csil_v: &LocalRpTicketRedemptionResponse,
) -> Vec<u8> {
    cbor_encode(&csil_enc_local_rp_ticket_redemption_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpTicketRedemptionResponse.
pub fn decode_local_rp_ticket_redemption_response(
    csil_data: &[u8],
) -> Result<LocalRpTicketRedemptionResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_ticket_redemption_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AdminLocalRp.
fn csil_enc_admin_local_rp(csil_v: &AdminLocalRp) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((cbor_text("status"), cbor_text(&csil_v.status)));
    csil_entries.push((cbor_text("app_name"), cbor_text(&csil_v.app_name)));
    csil_entries.push((cbor_text("created_at"), cbor_text(&csil_v.created_at)));
    if let Some(csil_inner) = &csil_v.expires_at {
        csil_entries.push((cbor_text("expires_at"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("updated_at"), cbor_text(&csil_v.updated_at)));
    if let Some(csil_inner) = &csil_v.admin_notes {
        csil_entries.push((cbor_text("admin_notes"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    if let Some(csil_inner) = &csil_v.last_seen_at {
        csil_entries.push((cbor_text("last_seen_at"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.local_domain_hint {
        csil_entries.push((cbor_text("local_domain_hint"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("signing_public_key"),
        cbor_bytes(&csil_v.signing_public_key),
    ));
    csil_entries.push((
        cbor_text("encryption_public_key"),
        cbor_bytes(&csil_v.encryption_public_key),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a AdminLocalRp from a decoded CBOR value tree.
fn csil_dec_admin_local_rp(csil_root: &CsilCborValue) -> Result<AdminLocalRp, CsilCborError> {
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signing_public_key = {
        let csil_field = cbor_require(csil_root, "signing_public_key")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let encryption_public_key = {
        let csil_field = cbor_require(csil_root, "encryption_public_key")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let app_name = {
        let csil_field = cbor_require(csil_root, "app_name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let local_domain_hint = match cbor_map_get(csil_root, "local_domain_hint") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let status = {
        let csil_field = cbor_require(csil_root, "status")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let updated_at = {
        let csil_field = cbor_require(csil_root, "updated_at")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let expires_at = match cbor_map_get(csil_root, "expires_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let last_seen_at = match cbor_map_get(csil_root, "last_seen_at") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let admin_notes = match cbor_map_get(csil_root, "admin_notes") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(AdminLocalRp {
        fingerprint,
        signing_public_key,
        encryption_public_key,
        app_name,
        local_domain_hint,
        status,
        created_at,
        updated_at,
        expires_at,
        last_seen_at,
        admin_notes,
    })
}

/// Encode a AdminLocalRp to canonical CSIL CBOR bytes.
pub fn encode_admin_local_rp(csil_v: &AdminLocalRp) -> Vec<u8> {
    cbor_encode(&csil_enc_admin_local_rp(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a AdminLocalRp.
pub fn decode_admin_local_rp(csil_data: &[u8]) -> Result<AdminLocalRp, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_admin_local_rp(&csil_root)
}

/// Build the canonical CBOR value tree for a ListLocalRpsRequest.
fn csil_enc_list_local_rps_request(csil_v: &ListLocalRpsRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    if let Some(csil_inner) = &csil_v.limit {
        csil_entries.push((cbor_text("limit"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.offset {
        csil_entries.push((cbor_text("offset"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.status {
        csil_entries.push((cbor_text("status"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListLocalRpsRequest from a decoded CBOR value tree.
fn csil_dec_list_local_rps_request(
    csil_root: &CsilCborValue,
) -> Result<ListLocalRpsRequest, CsilCborError> {
    let offset = match cbor_map_get(csil_root, "offset") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let limit = match cbor_map_get(csil_root, "limit") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let status = match cbor_map_get(csil_root, "status") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ListLocalRpsRequest {
        offset,
        limit,
        status,
    })
}

/// Encode a ListLocalRpsRequest to canonical CSIL CBOR bytes.
pub fn encode_list_local_rps_request(csil_v: &ListLocalRpsRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_list_local_rps_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListLocalRpsRequest.
pub fn decode_list_local_rps_request(
    csil_data: &[u8],
) -> Result<ListLocalRpsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_local_rps_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ListLocalRpsResponse.
fn csil_enc_list_local_rps_response(csil_v: &ListLocalRpsResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("local_rps"),
        cbor_enc_array(&csil_v.local_rps, csil_enc_admin_local_rp),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListLocalRpsResponse from a decoded CBOR value tree.
fn csil_dec_list_local_rps_response(
    csil_root: &CsilCborValue,
) -> Result<ListLocalRpsResponse, CsilCborError> {
    let local_rps = {
        let csil_field = cbor_require(csil_root, "local_rps")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_admin_local_rp);
        csil_decode(csil_field)?
    };
    Ok(ListLocalRpsResponse { local_rps })
}

/// Encode a ListLocalRpsResponse to canonical CSIL CBOR bytes.
pub fn encode_list_local_rps_response(csil_v: &ListLocalRpsResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_list_local_rps_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListLocalRpsResponse.
pub fn decode_list_local_rps_response(
    csil_data: &[u8],
) -> Result<ListLocalRpsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_local_rps_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetLocalRpRequest.
fn csil_enc_get_local_rp_request(csil_v: &GetLocalRpRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetLocalRpRequest from a decoded CBOR value tree.
fn csil_dec_get_local_rp_request(
    csil_root: &CsilCborValue,
) -> Result<GetLocalRpRequest, CsilCborError> {
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GetLocalRpRequest { fingerprint })
}

/// Encode a GetLocalRpRequest to canonical CSIL CBOR bytes.
pub fn encode_get_local_rp_request(csil_v: &GetLocalRpRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_get_local_rp_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetLocalRpRequest.
pub fn decode_get_local_rp_request(csil_data: &[u8]) -> Result<GetLocalRpRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_local_rp_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetLocalRpResponse.
fn csil_enc_get_local_rp_response(csil_v: &GetLocalRpResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("local_rp"),
        csil_enc_admin_local_rp(&csil_v.local_rp),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetLocalRpResponse from a decoded CBOR value tree.
fn csil_dec_get_local_rp_response(
    csil_root: &CsilCborValue,
) -> Result<GetLocalRpResponse, CsilCborError> {
    let local_rp = {
        let csil_field = cbor_require(csil_root, "local_rp")?;
        let csil_decode = csil_dec_admin_local_rp;
        csil_decode(csil_field)?
    };
    Ok(GetLocalRpResponse { local_rp })
}

/// Encode a GetLocalRpResponse to canonical CSIL CBOR bytes.
pub fn encode_get_local_rp_response(csil_v: &GetLocalRpResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_get_local_rp_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetLocalRpResponse.
pub fn decode_get_local_rp_response(csil_data: &[u8]) -> Result<GetLocalRpResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_local_rp_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ApproveLocalRpRequest.
fn csil_enc_approve_local_rp_request(csil_v: &ApproveLocalRpRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.admin_notes {
        csil_entries.push((cbor_text("admin_notes"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ApproveLocalRpRequest from a decoded CBOR value tree.
fn csil_dec_approve_local_rp_request(
    csil_root: &CsilCborValue,
) -> Result<ApproveLocalRpRequest, CsilCborError> {
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let admin_notes = match cbor_map_get(csil_root, "admin_notes") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ApproveLocalRpRequest {
        fingerprint,
        admin_notes,
    })
}

/// Encode a ApproveLocalRpRequest to canonical CSIL CBOR bytes.
pub fn encode_approve_local_rp_request(csil_v: &ApproveLocalRpRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_approve_local_rp_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ApproveLocalRpRequest.
pub fn decode_approve_local_rp_request(
    csil_data: &[u8],
) -> Result<ApproveLocalRpRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_approve_local_rp_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ApproveLocalRpResponse.
fn csil_enc_approve_local_rp_response(csil_v: &ApproveLocalRpResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("local_rp"),
        csil_enc_admin_local_rp(&csil_v.local_rp),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ApproveLocalRpResponse from a decoded CBOR value tree.
fn csil_dec_approve_local_rp_response(
    csil_root: &CsilCborValue,
) -> Result<ApproveLocalRpResponse, CsilCborError> {
    let local_rp = {
        let csil_field = cbor_require(csil_root, "local_rp")?;
        let csil_decode = csil_dec_admin_local_rp;
        csil_decode(csil_field)?
    };
    Ok(ApproveLocalRpResponse { local_rp })
}

/// Encode a ApproveLocalRpResponse to canonical CSIL CBOR bytes.
pub fn encode_approve_local_rp_response(csil_v: &ApproveLocalRpResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_approve_local_rp_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ApproveLocalRpResponse.
pub fn decode_approve_local_rp_response(
    csil_data: &[u8],
) -> Result<ApproveLocalRpResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_approve_local_rp_response(&csil_root)
}

/// Build the canonical CBOR value tree for a DenyLocalRpRequest.
fn csil_enc_deny_local_rp_request(csil_v: &DenyLocalRpRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.admin_notes {
        csil_entries.push((cbor_text("admin_notes"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a DenyLocalRpRequest from a decoded CBOR value tree.
fn csil_dec_deny_local_rp_request(
    csil_root: &CsilCborValue,
) -> Result<DenyLocalRpRequest, CsilCborError> {
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let admin_notes = match cbor_map_get(csil_root, "admin_notes") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(DenyLocalRpRequest {
        fingerprint,
        admin_notes,
    })
}

/// Encode a DenyLocalRpRequest to canonical CSIL CBOR bytes.
pub fn encode_deny_local_rp_request(csil_v: &DenyLocalRpRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_deny_local_rp_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a DenyLocalRpRequest.
pub fn decode_deny_local_rp_request(csil_data: &[u8]) -> Result<DenyLocalRpRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deny_local_rp_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DenyLocalRpResponse.
fn csil_enc_deny_local_rp_response(csil_v: &DenyLocalRpResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("local_rp"),
        csil_enc_admin_local_rp(&csil_v.local_rp),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a DenyLocalRpResponse from a decoded CBOR value tree.
fn csil_dec_deny_local_rp_response(
    csil_root: &CsilCborValue,
) -> Result<DenyLocalRpResponse, CsilCborError> {
    let local_rp = {
        let csil_field = cbor_require(csil_root, "local_rp")?;
        let csil_decode = csil_dec_admin_local_rp;
        csil_decode(csil_field)?
    };
    Ok(DenyLocalRpResponse { local_rp })
}

/// Encode a DenyLocalRpResponse to canonical CSIL CBOR bytes.
pub fn encode_deny_local_rp_response(csil_v: &DenyLocalRpResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_deny_local_rp_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a DenyLocalRpResponse.
pub fn decode_deny_local_rp_response(
    csil_data: &[u8],
) -> Result<DenyLocalRpResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deny_local_rp_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeLocalRpRequest.
fn csil_enc_revoke_local_rp_request(csil_v: &RevokeLocalRpRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.admin_notes {
        csil_entries.push((cbor_text("admin_notes"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RevokeLocalRpRequest from a decoded CBOR value tree.
fn csil_dec_revoke_local_rp_request(
    csil_root: &CsilCborValue,
) -> Result<RevokeLocalRpRequest, CsilCborError> {
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let admin_notes = match cbor_map_get(csil_root, "admin_notes") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(RevokeLocalRpRequest {
        fingerprint,
        admin_notes,
    })
}

/// Encode a RevokeLocalRpRequest to canonical CSIL CBOR bytes.
pub fn encode_revoke_local_rp_request(csil_v: &RevokeLocalRpRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_revoke_local_rp_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RevokeLocalRpRequest.
pub fn decode_revoke_local_rp_request(
    csil_data: &[u8],
) -> Result<RevokeLocalRpRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_local_rp_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeLocalRpResponse.
fn csil_enc_revoke_local_rp_response(csil_v: &RevokeLocalRpResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("local_rp"),
        csil_enc_admin_local_rp(&csil_v.local_rp),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a RevokeLocalRpResponse from a decoded CBOR value tree.
fn csil_dec_revoke_local_rp_response(
    csil_root: &CsilCborValue,
) -> Result<RevokeLocalRpResponse, CsilCborError> {
    let local_rp = {
        let csil_field = cbor_require(csil_root, "local_rp")?;
        let csil_decode = csil_dec_admin_local_rp;
        csil_decode(csil_field)?
    };
    Ok(RevokeLocalRpResponse { local_rp })
}

/// Encode a RevokeLocalRpResponse to canonical CSIL CBOR bytes.
pub fn encode_revoke_local_rp_response(csil_v: &RevokeLocalRpResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_revoke_local_rp_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a RevokeLocalRpResponse.
pub fn decode_revoke_local_rp_response(
    csil_data: &[u8],
) -> Result<RevokeLocalRpResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_local_rp_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetLocalRpPolicyRequest.
fn csil_enc_get_local_rp_policy_request(_csil_v: &GetLocalRpPolicyRequest) -> CsilCborValue {
    CsilCborValue::Map(Vec::new())
}

/// Reconstruct a GetLocalRpPolicyRequest from a decoded CBOR value tree.
fn csil_dec_get_local_rp_policy_request(
    _csil_root: &CsilCborValue,
) -> Result<GetLocalRpPolicyRequest, CsilCborError> {
    Ok(GetLocalRpPolicyRequest {})
}

/// Encode a GetLocalRpPolicyRequest to canonical CSIL CBOR bytes.
pub fn encode_get_local_rp_policy_request(csil_v: &GetLocalRpPolicyRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_get_local_rp_policy_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetLocalRpPolicyRequest.
pub fn decode_get_local_rp_policy_request(
    csil_data: &[u8],
) -> Result<GetLocalRpPolicyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_local_rp_policy_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetLocalRpPolicyResponse.
fn csil_enc_get_local_rp_policy_response(csil_v: &GetLocalRpPolicyResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("policy"), cbor_text(&csil_v.policy)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a GetLocalRpPolicyResponse from a decoded CBOR value tree.
fn csil_dec_get_local_rp_policy_response(
    csil_root: &CsilCborValue,
) -> Result<GetLocalRpPolicyResponse, CsilCborError> {
    let policy = {
        let csil_field = cbor_require(csil_root, "policy")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GetLocalRpPolicyResponse { policy })
}

/// Encode a GetLocalRpPolicyResponse to canonical CSIL CBOR bytes.
pub fn encode_get_local_rp_policy_response(csil_v: &GetLocalRpPolicyResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_get_local_rp_policy_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a GetLocalRpPolicyResponse.
pub fn decode_get_local_rp_policy_response(
    csil_data: &[u8],
) -> Result<GetLocalRpPolicyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_local_rp_policy_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetLocalRpPolicyRequest.
fn csil_enc_set_local_rp_policy_request(csil_v: &SetLocalRpPolicyRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("policy"), cbor_text(&csil_v.policy)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetLocalRpPolicyRequest from a decoded CBOR value tree.
fn csil_dec_set_local_rp_policy_request(
    csil_root: &CsilCborValue,
) -> Result<SetLocalRpPolicyRequest, CsilCborError> {
    let policy = {
        let csil_field = cbor_require(csil_root, "policy")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(SetLocalRpPolicyRequest { policy })
}

/// Encode a SetLocalRpPolicyRequest to canonical CSIL CBOR bytes.
pub fn encode_set_local_rp_policy_request(csil_v: &SetLocalRpPolicyRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_set_local_rp_policy_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetLocalRpPolicyRequest.
pub fn decode_set_local_rp_policy_request(
    csil_data: &[u8],
) -> Result<SetLocalRpPolicyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_local_rp_policy_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetLocalRpPolicyResponse.
fn csil_enc_set_local_rp_policy_response(csil_v: &SetLocalRpPolicyResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("policy"), cbor_text(&csil_v.policy)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a SetLocalRpPolicyResponse from a decoded CBOR value tree.
fn csil_dec_set_local_rp_policy_response(
    csil_root: &CsilCborValue,
) -> Result<SetLocalRpPolicyResponse, CsilCborError> {
    let policy = {
        let csil_field = cbor_require(csil_root, "policy")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(SetLocalRpPolicyResponse { policy })
}

/// Encode a SetLocalRpPolicyResponse to canonical CSIL CBOR bytes.
pub fn encode_set_local_rp_policy_response(csil_v: &SetLocalRpPolicyResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_set_local_rp_policy_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a SetLocalRpPolicyResponse.
pub fn decode_set_local_rp_policy_response(
    csil_data: &[u8],
) -> Result<SetLocalRpPolicyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_local_rp_policy_response(&csil_root)
}

/// Build the canonical CBOR value tree for a PurgeLocalRpTicketsRequest.
fn csil_enc_purge_local_rp_tickets_request(_csil_v: &PurgeLocalRpTicketsRequest) -> CsilCborValue {
    CsilCborValue::Map(Vec::new())
}

/// Reconstruct a PurgeLocalRpTicketsRequest from a decoded CBOR value tree.
fn csil_dec_purge_local_rp_tickets_request(
    _csil_root: &CsilCborValue,
) -> Result<PurgeLocalRpTicketsRequest, CsilCborError> {
    Ok(PurgeLocalRpTicketsRequest {})
}

/// Encode a PurgeLocalRpTicketsRequest to canonical CSIL CBOR bytes.
pub fn encode_purge_local_rp_tickets_request(csil_v: &PurgeLocalRpTicketsRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_purge_local_rp_tickets_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a PurgeLocalRpTicketsRequest.
pub fn decode_purge_local_rp_tickets_request(
    csil_data: &[u8],
) -> Result<PurgeLocalRpTicketsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_purge_local_rp_tickets_request(&csil_root)
}

/// Build the canonical CBOR value tree for a PurgeLocalRpTicketsResponse.
fn csil_enc_purge_local_rp_tickets_response(csil_v: &PurgeLocalRpTicketsResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("purged_count"), cbor_int(csil_v.purged_count)));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a PurgeLocalRpTicketsResponse from a decoded CBOR value tree.
fn csil_dec_purge_local_rp_tickets_response(
    csil_root: &CsilCborValue,
) -> Result<PurgeLocalRpTicketsResponse, CsilCborError> {
    let purged_count = {
        let csil_field = cbor_require(csil_root, "purged_count")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(PurgeLocalRpTicketsResponse { purged_count })
}

/// Encode a PurgeLocalRpTicketsResponse to canonical CSIL CBOR bytes.
pub fn encode_purge_local_rp_tickets_response(csil_v: &PurgeLocalRpTicketsResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_purge_local_rp_tickets_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a PurgeLocalRpTicketsResponse.
pub fn decode_purge_local_rp_tickets_response(
    csil_data: &[u8],
) -> Result<PurgeLocalRpTicketsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_purge_local_rp_tickets_response(&csil_root)
}

/// Build the canonical CBOR value tree for a TranslationsRequest.
fn csil_enc_translations_request(csil_v: &TranslationsRequest) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.locale {
        csil_entries.push((cbor_text("locale"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.accept_language {
        csil_entries.push((cbor_text("accept_language"), cbor_text(csil_inner)));
    }
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a TranslationsRequest from a decoded CBOR value tree.
fn csil_dec_translations_request(
    csil_root: &CsilCborValue,
) -> Result<TranslationsRequest, CsilCborError> {
    let locale = match cbor_map_get(csil_root, "locale") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let accept_language = match cbor_map_get(csil_root, "accept_language") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(TranslationsRequest {
        locale,
        accept_language,
    })
}

/// Encode a TranslationsRequest to canonical CSIL CBOR bytes.
pub fn encode_translations_request(csil_v: &TranslationsRequest) -> Vec<u8> {
    cbor_encode(&csil_enc_translations_request(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a TranslationsRequest.
pub fn decode_translations_request(csil_data: &[u8]) -> Result<TranslationsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_translations_request(&csil_root)
}

/// Build the canonical CBOR value tree for a TranslationsResponse.
fn csil_enc_translations_response(csil_v: &TranslationsResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("locale"), cbor_text(&csil_v.locale)));
    csil_entries.push((
        cbor_text("messages"),
        cbor_enc_map(
            &csil_v.messages,
            |csil_mk| cbor_text(csil_mk),
            |csil_mv| cbor_text(csil_mv),
        ),
    ));
    csil_entries.push((
        cbor_text("available_locales"),
        cbor_enc_array(&csil_v.available_locales, |csil_elem| cbor_text(csil_elem)),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a TranslationsResponse from a decoded CBOR value tree.
fn csil_dec_translations_response(
    csil_root: &CsilCborValue,
) -> Result<TranslationsResponse, CsilCborError> {
    let locale = {
        let csil_field = cbor_require(csil_root, "locale")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let available_locales = {
        let csil_field = cbor_require(csil_root, "available_locales")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let messages = {
        let csil_field = cbor_require(csil_root, "messages")?;
        let csil_decode = |csil_v| cbor_dec_map(csil_v, cbor_as_text, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(TranslationsResponse {
        locale,
        available_locales,
        messages,
    })
}

/// Encode a TranslationsResponse to canonical CSIL CBOR bytes.
pub fn encode_translations_response(csil_v: &TranslationsResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_translations_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a TranslationsResponse.
pub fn decode_translations_response(
    csil_data: &[u8],
) -> Result<TranslationsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_translations_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ListLocalesResponse.
fn csil_enc_list_locales_response(csil_v: &ListLocalesResponse) -> CsilCborValue {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("available_locales"),
        cbor_enc_array(&csil_v.available_locales, |csil_elem| cbor_text(csil_elem)),
    ));
    CsilCborValue::Map(csil_entries)
}

/// Reconstruct a ListLocalesResponse from a decoded CBOR value tree.
fn csil_dec_list_locales_response(
    csil_root: &CsilCborValue,
) -> Result<ListLocalesResponse, CsilCborError> {
    let available_locales = {
        let csil_field = cbor_require(csil_root, "available_locales")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(ListLocalesResponse { available_locales })
}

/// Encode a ListLocalesResponse to canonical CSIL CBOR bytes.
pub fn encode_list_locales_response(csil_v: &ListLocalesResponse) -> Vec<u8> {
    cbor_encode(&csil_enc_list_locales_response(csil_v))
}

/// Decode canonical CSIL CBOR bytes into a ListLocalesResponse.
pub fn decode_list_locales_response(
    csil_data: &[u8],
) -> Result<ListLocalesResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_locales_response(&csil_root)
}

/// Encode a CheckValue union as a tagged sum `[variant_index, value]`.
fn csil_enc_check_value(csil_v: &CheckValue) -> CsilCborValue {
    match csil_v {
        CheckValue::Variant0(csil_x) => {
            CsilCborValue::Array(vec![CsilCborValue::Uint(0), cbor_text(csil_x)])
        }
        CheckValue::Variant1(csil_x) => {
            CsilCborValue::Array(vec![CsilCborValue::Uint(1), cbor_int(*csil_x)])
        }
        CheckValue::Variant2(csil_x) => {
            CsilCborValue::Array(vec![CsilCborValue::Uint(2), cbor_float(*csil_x)])
        }
    }
}

/// Decode a tagged sum `[variant_index, value]` into a CheckValue union.
fn csil_dec_check_value(csil_v: &CsilCborValue) -> Result<CheckValue, CsilCborError> {
    let csil_arr = match csil_v {
        CsilCborValue::Array(csil_a) => csil_a,
        _ => {
            return Err(CsilCborError(
                "csil cbor: union expects a 2-element array".to_string(),
            ))
        }
    };
    if csil_arr.len() != 2 {
        return Err(CsilCborError(format!(
            "csil cbor: union array has {} elements, expected 2",
            csil_arr.len()
        )));
    }
    let csil_idx = cbor_as_u64(&csil_arr[0])?;
    match csil_idx {
        0 => {
            let csil_decode = cbor_as_text;
            Ok(CheckValue::Variant0(csil_decode(&csil_arr[1])?))
        }
        1 => {
            let csil_decode = cbor_as_i64;
            Ok(CheckValue::Variant1(csil_decode(&csil_arr[1])?))
        }
        2 => {
            let csil_decode = cbor_as_f64;
            Ok(CheckValue::Variant2(csil_decode(&csil_arr[1])?))
        }
        csil_other => Err(CsilCborError(format!(
            "csil cbor: unknown CheckValue variant {csil_other}"
        ))),
    }
}
