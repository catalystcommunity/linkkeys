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
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("nonce"), cbor_bytes(&csil_v.nonce)));
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
    Ok(EncryptedToken {
        ephemeral_public_key,
        ciphertext,
        nonce,
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
