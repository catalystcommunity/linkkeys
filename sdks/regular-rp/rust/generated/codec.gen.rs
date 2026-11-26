//! Generated self-contained canonical-CBOR codec from CSIL specification.
//!
//! CSIL is the CBOR Service Interface Language; this codec owns the payload
//! wire (a CBOR map keyed by the verbatim CSIL field name in canonical RFC
//! 8949 order) so the generated types need no serde derive. One
//! `encode_`/`decode_` pair is emitted per record type.
#![allow(dead_code, clippy::vec_init_then_push, clippy::let_unit_value)]

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
    let v = cbor_dec(b, &mut pos, 0)?;
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
            )));
        }
    };
    let bytes = pos
        .checked_add(1)
        .and_then(|start| b.get(start..start.checked_add(width)?))
        .ok_or_else(|| CsilCborError("csil cbor: truncated argument".to_string()))?;
    let mut v = 0u64;
    for &byte in bytes {
        v = (v << 8) | byte as u64;
    }
    *pos += 1 + width;
    Ok(v)
}

/// Whether the item head at `at` uses the shortest argument for its value or
/// length (RFC 8949 section 4.2.1). A map key with a longer head has a second byte
/// form, and the canonical order check could then accept a map that no canonical
/// encoder writes. Floats and simple values (major type 7) are not checked here,
/// and a truncated head is left to the decoder to report.
fn cbor_head_is_shortest(b: &[u8], at: usize) -> bool {
    let Some(&ib) = b.get(at) else {
        return true;
    };
    let (major, low) = (ib >> 5, ib & 0x1f);
    let width = match low {
        24 => 1usize,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return true,
    };
    if major == 7 {
        return true;
    }
    let Some(bytes) = b.get(at + 1..at + 1 + width) else {
        return true;
    };
    let value = bytes.iter().fold(0u64, |v, &byte| (v << 8) | byte as u64);
    match width {
        1 => value >= 24,
        2 => value > 0xff,
        4 => value > 0xffff,
        _ => value > 0xffff_ffff,
    }
}

/// The most elements a decoded array or map reserves before it reads them. The
/// declared length is checked against the remaining input, but one input byte can
/// become a much larger value, so reserving the full declared length lets a small
/// frame reserve a large multiple of its size at every nesting level. Past this
/// bound, the vector grows only as elements are actually read.
const CSIL_CBOR_PREALLOC_LIMIT: usize = 1024;

/// The `len` bytes at `start`, or `None` when the input is shorter. `get` is
/// used instead of indexing so a bad length can never panic.
fn cbor_take(b: &[u8], start: usize, len: u64) -> Option<&[u8]> {
    let end = start.checked_add(usize::try_from(len).ok()?)?;
    b.get(start..end)
}

/// Widen an IEEE 754 half-precision value (RFC 8949 Appendix D) exactly to binary64.
fn cbor_half_to_f64(half: u16) -> f64 {
    let exp = (half >> 10) & 0x1f;
    let mant = f64::from(half & 0x3ff);
    let magnitude = match exp {
        0 => mant * 2f64.powi(-24),
        31 if mant == 0.0 => f64::INFINITY,
        31 => f64::NAN,
        _ => (mant + 1024.0) * 2f64.powi(i32::from(exp) - 25),
    };
    if half & 0x8000 != 0 {
        -magnitude
    } else {
        magnitude
    }
}

fn cbor_dec(b: &[u8], pos: &mut usize, depth: usize) -> Result<CsilCborValue, CsilCborError> {
    if depth > 64 {
        return Err(CsilCborError(
            "csil cbor: nesting limit exceeded".to_string(),
        ));
    }
    let Some(&ib) = b.get(*pos) else {
        return Err(CsilCborError(
            "csil cbor: unexpected end of input".to_string(),
        ));
    };
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
            25 => {
                let bits = cbor_read_arg(b, pos, low)?;
                Ok(CsilCborValue::Float(cbor_half_to_f64(bits as u16)))
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
            let slice = cbor_take(b, *pos, arg)
                .ok_or_else(|| CsilCborError("csil cbor: truncated byte string".to_string()))?;
            *pos += slice.len();
            Ok(CsilCborValue::Bytes(slice.to_vec()))
        }
        3 => {
            let slice = cbor_take(b, *pos, arg)
                .ok_or_else(|| CsilCborError("csil cbor: truncated text string".to_string()))?;
            let s = std::str::from_utf8(slice)
                .map_err(|e| CsilCborError(format!("csil cbor: invalid utf-8: {e}")))?
                .to_string();
            *pos += slice.len();
            Ok(CsilCborValue::Text(s))
        }
        4 => {
            if arg > b.len().saturating_sub(*pos) as u64 {
                return Err(CsilCborError(
                    "csil cbor: array length exceeds remaining input".to_string(),
                ));
            }
            let n = arg as usize;
            let mut items = Vec::with_capacity(n.min(CSIL_CBOR_PREALLOC_LIMIT));
            for _ in 0..n {
                items.push(cbor_dec(b, pos, depth + 1)?);
            }
            Ok(CsilCborValue::Array(items))
        }
        5 => {
            if arg > b.len().saturating_sub(*pos) as u64 {
                return Err(CsilCborError(
                    "csil cbor: map length exceeds remaining input".to_string(),
                ));
            }
            let n = arg as usize;
            let mut entries = Vec::with_capacity(n.min(CSIL_CBOR_PREALLOC_LIMIT));
            for _ in 0..n {
                if !cbor_head_is_shortest(b, *pos) {
                    return Err(CsilCborError(
                        "csil cbor: map key is not in shortest form".to_string(),
                    ));
                }
                let k = cbor_dec(b, pos, depth + 1)?;
                let val = cbor_dec(b, pos, depth + 1)?;
                entries.push((k, val));
            }
            Ok(CsilCborValue::Map(entries))
        }
        6 => {
            let inner = cbor_dec(b, pos, depth + 1)?;
            Ok(CsilCborValue::Tag(arg, Box::new(inner)))
        }
        _ => Err(CsilCborError(format!(
            "csil cbor: unexpected major type {major}"
        ))),
    }
}

/// Map a typed slice to a CBOR array via the per-element encoder.
fn cbor_enc_array<E>(
    xs: &[E],
    f: impl Fn(&E) -> Result<CsilCborValue, CsilCborError>,
) -> Result<CsilCborValue, CsilCborError> {
    xs.iter()
        .map(f)
        .collect::<Result<Vec<_>, _>>()
        .map(CsilCborValue::Array)
}

/// Map a typed map to a CBOR map with its entries in canonical order: the bytewise
/// order of each encoded key (RFC 8949 section 4.2.1). `HashMap` iteration order is
/// arbitrary, and a peer rejects a map whose keys are not in that order.
fn cbor_enc_map<K, V>(
    m: &std::collections::HashMap<K, V>,
    kf: impl Fn(&K) -> Result<CsilCborValue, CsilCborError>,
    vf: impl Fn(&V) -> Result<CsilCborValue, CsilCborError>,
) -> Result<CsilCborValue, CsilCborError> {
    let mut entries = m
        .iter()
        .map(|(k, v)| Ok((kf(k)?, vf(v)?)))
        .collect::<Result<Vec<_>, CsilCborError>>()?;
    entries.sort_by_cached_key(|(k, _)| cbor_encode(k));
    Ok(CsilCborValue::Map(entries))
}

fn cbor_dec_array<E>(
    v: &CsilCborValue,
    f: impl Fn(&CsilCborValue) -> Result<E, CsilCborError>,
) -> Result<Vec<E>, CsilCborError> {
    cbor_as_array(v)?.iter().map(f).collect()
}

/// Decode a dynamic map. Its keys must be in strictly ascending canonical order, so
/// each key is compared with the one before it only: one pass, no sort, and a key
/// that comes twice is refused too.
fn cbor_dec_map<K: std::cmp::Eq + std::hash::Hash, V>(
    v: &CsilCborValue,
    kf: impl Fn(&CsilCborValue) -> Result<K, CsilCborError>,
    vf: impl Fn(&CsilCborValue) -> Result<V, CsilCborError>,
) -> Result<std::collections::HashMap<K, V>, CsilCborError> {
    let entries = cbor_as_map(v)?;
    let mut out = std::collections::HashMap::with_capacity(entries.len());
    let mut previous: Option<Vec<u8>> = None;
    for (k, val) in entries {
        let key = cbor_encode(k);
        match previous.as_deref().map(|p| p.cmp(key.as_slice())) {
            Some(std::cmp::Ordering::Equal) => return Err(cbor_duplicate_key(k)),
            Some(std::cmp::Ordering::Greater) => {
                return Err(CsilCborError(
                    "csil cbor: map keys are not in canonical order".to_string(),
                ));
            }
            _ => {}
        }
        out.insert(kf(k)?, vf(val)?);
        previous = Some(key);
    }
    Ok(out)
}

fn cbor_duplicate_key(k: &CsilCborValue) -> CsilCborError {
    match k {
        CsilCborValue::Text(name) => CsilCborError(format!("csil cbor: duplicate key {name:?}")),
        other => CsilCborError(format!("csil cbor: duplicate key {other:?}")),
    }
}

/// Refuse a record map that names one key twice. Record fields may come in any
/// order, so a set of the encoded keys finds a repeat in one pass.
fn cbor_check_record(v: &CsilCborValue) -> Result<(), CsilCborError> {
    let entries = cbor_as_map(v)?;
    let mut seen = std::collections::HashSet::with_capacity(entries.len());
    for (k, _) in entries {
        if !seen.insert(cbor_encode(k)) {
            return Err(cbor_duplicate_key(k));
        }
    }
    Ok(())
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

fn csil_rt_enc_date(date: &time::Date) -> Result<CsilCborValue, CsilCborError> {
    let text = date.to_string();
    if !(1..=9999).contains(&date.year()) || text.len() != 10 {
        return Err(CsilCborError(
            "csil cbor: date outside years 0001-9999".to_string(),
        ));
    }
    Ok(CsilCborValue::Tag(
        1004,
        Box::new(CsilCborValue::Text(text)),
    ))
}

fn csil_as_date(v: &CsilCborValue) -> Result<time::Date, CsilCborError> {
    let CsilCborValue::Tag(1004, inner) = v else {
        return Err(CsilCborError("expected calendar date tag 1004".into()));
    };
    let CsilCborValue::Text(text) = inner.as_ref() else {
        return Err(CsilCborError("expected calendar date text".into()));
    };
    time::Date::parse(text, &time::format_description::well_known::Iso8601::DATE)
        .ok()
        .filter(|date| text.len() == 10 && date.to_string() == *text)
        .ok_or_else(|| CsilCborError("expected a YYYY-MM-DD date".into()))
}

fn csil_rt_enc_timestamp(t: &time::OffsetDateTime) -> Result<CsilCborValue, CsilCborError> {
    let out_of_range = || CsilCborError("csil cbor: timestamp outside UTC years 0001-9999".into());
    // `to_offset` panics when the shifted instant leaves the `time` range.
    let utc = t
        .checked_to_offset(time::UtcOffset::UTC)
        .filter(|utc| (1..=9999).contains(&utc.year()))
        .ok_or_else(out_of_range)?;
    let mut text = utc
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| out_of_range())?;
    // Keep the wire spelling used by earlier Rust releases (3, 6, or 9 fractional digits).
    if let Some(point) = text.find('.') {
        let end = text.len().saturating_sub(1); // final Z
        let digits = end.saturating_sub(point + 1);
        let padding = match digits % 3 {
            1 => "00",
            2 => "0",
            _ => "",
        };
        text.insert_str(end, padding);
    }
    Ok(CsilCborValue::Tag(0, Box::new(CsilCborValue::Text(text))))
}

pub(super) fn csil_parse_timestamp(s: &str) -> Result<time::OffsetDateTime, CsilCborError> {
    let invalid = || CsilCborError(format!("csil cbor: invalid timestamp {s:?}"));
    let b = s.as_bytes();
    // Every field is read by position so that no parser leniency (space separator,
    // offsets without a colon, rounding of a leap second) can widen the wire form.
    let field = |from: usize, len: usize| -> Result<u32, CsilCborError> {
        b.get(from..from + len)
            .and_then(|part| {
                part.iter().try_fold(0u32, |n, c| {
                    c.is_ascii_digit().then(|| n * 10 + u32::from(c - b'0'))
                })
            })
            .ok_or_else(invalid)
    };
    let at = |i: usize| b.get(i).copied();
    if b.len() < 20
        || at(4) != Some(b'-')
        || at(7) != Some(b'-')
        || !matches!(at(10), Some(b'T' | b't'))
        || at(13) != Some(b':')
        || at(16) != Some(b':')
    {
        return Err(invalid());
    }
    let (year, month, day) = (field(0, 4)?, field(5, 2)?, field(8, 2)?);
    // A written year 0000 is refused even when the offset carries it into 0001.
    if year == 0 {
        return Err(invalid());
    }
    let (hour, minute, second) = (field(11, 2)?, field(14, 2)?, field(17, 2)?);
    let mut pos = 19;
    let mut nanos = 0;
    if at(pos) == Some(b'.') {
        let digits = b
            .get(pos + 1..)
            .unwrap_or_default()
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if !(1..=9).contains(&digits) {
            return Err(invalid());
        }
        nanos = field(pos + 1, digits)? * 10u32.pow(9 - digits as u32);
        pos += 1 + digits;
    }
    let offset = match b.get(pos..).unwrap_or_default() {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (h, m) = (field(pos + 1, 2)?, field(pos + 4, 2)?);
            if h > 23 || m > 59 {
                return Err(invalid());
            }
            let total = (h * 3600 + m * 60) as i32;
            // A `match`, because rustfmt's 2021 and 2024 styles lay out a short
            // `if`/`else` tail differently.
            match *sign {
                b'-' => -total,
                _ => total,
            }
        }
        _ => return Err(invalid()),
    };
    let month = u8::try_from(month)
        .ok()
        .and_then(|m| time::Month::try_from(m).ok())
        .ok_or_else(invalid)?;
    let date =
        time::Date::from_calendar_date(year as i32, month, day as u8).map_err(|_| invalid())?;
    // `Time` refuses hour 24, minute 60, and second 60, so a leap second is an error.
    let clock = time::Time::from_hms_nano(hour as u8, minute as u8, second as u8, nanos)
        .map_err(|_| invalid())?;
    let offset = time::UtcOffset::from_whole_seconds(offset).map_err(|_| invalid())?;
    time::PrimitiveDateTime::new(date, clock)
        .assume_offset(offset)
        .checked_to_offset(time::UtcOffset::UTC)
        .filter(|utc| (1..=9999).contains(&utc.year()))
        .ok_or_else(|| CsilCborError("timestamp outside UTC years 0001-9999".into()))
}

fn csil_as_timestamp(v: &CsilCborValue) -> Result<time::OffsetDateTime, CsilCborError> {
    let CsilCborValue::Tag(0, inner) = v else {
        return Err(CsilCborError(
            "csil cbor: expected CBOR tag 0 timestamp".to_string(),
        ));
    };
    let CsilCborValue::Text(s) = inner.as_ref() else {
        return Err(CsilCborError(
            "csil cbor: timestamp content must be text".to_string(),
        ));
    };
    csil_parse_timestamp(s)
}

/// Build the canonical CBOR value tree for a CheckResult.
fn csil_enc_check_result(csil_v: &CheckResult) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("result"), cbor_bool(csil_v.result)));
    csil_entries.push((
        cbor_text("entries"),
        cbor_enc_map(
            &csil_v.entries,
            |csil_mk| Ok(cbor_text(csil_mk)),
            csil_enc_check_value,
        )?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CheckResult from a decoded CBOR value tree.
fn csil_dec_check_result(csil_root: &CsilCborValue) -> Result<CheckResult, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_check_result(csil_v: &CheckResult) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_check_result(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CheckResult.
pub fn decode_check_result(csil_data: &[u8]) -> Result<CheckResult, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_check_result(&csil_root)
}

/// Build the canonical CBOR value tree for a HelloRequest.
fn csil_enc_hello_request(csil_v: &HelloRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    if let Some(csil_inner) = &csil_v.name {
        csil_entries.push((cbor_text("name"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a HelloRequest from a decoded CBOR value tree.
fn csil_dec_hello_request(csil_root: &CsilCborValue) -> Result<HelloRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_hello_request(csil_v: &HelloRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_hello_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a HelloRequest.
pub fn decode_hello_request(csil_data: &[u8]) -> Result<HelloRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_hello_request(&csil_root)
}

/// Build the canonical CBOR value tree for a HelloResponse.
fn csil_enc_hello_response(csil_v: &HelloResponse) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("greeting"), cbor_text(&csil_v.greeting)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a HelloResponse from a decoded CBOR value tree.
fn csil_dec_hello_response(csil_root: &CsilCborValue) -> Result<HelloResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let greeting = {
        let csil_field = cbor_require(csil_root, "greeting")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(HelloResponse { greeting })
}

/// Encode a HelloResponse to canonical CSIL CBOR bytes.
pub fn encode_hello_response(csil_v: &HelloResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_hello_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a HelloResponse.
pub fn decode_hello_response(csil_data: &[u8]) -> Result<HelloResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_hello_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GuestbookEntry.
fn csil_enc_guestbook_entry(csil_v: &GuestbookEntry) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("name"), cbor_text(&csil_v.name)));
    csil_entries.push((
        cbor_text("created_at"),
        csil_rt_enc_timestamp(&csil_v.created_at)?,
    ));
    csil_entries.push((
        cbor_text("updated_at"),
        csil_rt_enc_timestamp(&csil_v.updated_at)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GuestbookEntry from a decoded CBOR value tree.
fn csil_dec_guestbook_entry(csil_root: &CsilCborValue) -> Result<GuestbookEntry, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let updated_at = {
        let csil_field = cbor_require(csil_root, "updated_at")?;
        let csil_decode = csil_as_timestamp;
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
pub fn encode_guestbook_entry(csil_v: &GuestbookEntry) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_guestbook_entry(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GuestbookEntry.
pub fn decode_guestbook_entry(csil_data: &[u8]) -> Result<GuestbookEntry, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_guestbook_entry(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateGuestbookRequest.
fn csil_enc_create_guestbook_request(
    csil_v: &CreateGuestbookRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("name"), cbor_text(&csil_v.name)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CreateGuestbookRequest from a decoded CBOR value tree.
fn csil_dec_create_guestbook_request(
    csil_root: &CsilCborValue,
) -> Result<CreateGuestbookRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let name = {
        let csil_field = cbor_require(csil_root, "name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(CreateGuestbookRequest { name })
}

/// Encode a CreateGuestbookRequest to canonical CSIL CBOR bytes.
pub fn encode_create_guestbook_request(
    csil_v: &CreateGuestbookRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_create_guestbook_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CreateGuestbookRequest.
pub fn decode_create_guestbook_request(
    csil_data: &[u8],
) -> Result<CreateGuestbookRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_guestbook_request(&csil_root)
}

/// Build the canonical CBOR value tree for a UpdateGuestbookRequest.
fn csil_enc_update_guestbook_request(
    csil_v: &UpdateGuestbookRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("name"), cbor_text(&csil_v.name)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a UpdateGuestbookRequest from a decoded CBOR value tree.
fn csil_dec_update_guestbook_request(
    csil_root: &CsilCborValue,
) -> Result<UpdateGuestbookRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_update_guestbook_request(
    csil_v: &UpdateGuestbookRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_update_guestbook_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a UpdateGuestbookRequest.
pub fn decode_update_guestbook_request(
    csil_data: &[u8],
) -> Result<UpdateGuestbookRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_update_guestbook_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DeleteGuestbookRequest.
fn csil_enc_delete_guestbook_request(
    csil_v: &DeleteGuestbookRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DeleteGuestbookRequest from a decoded CBOR value tree.
fn csil_dec_delete_guestbook_request(
    csil_root: &CsilCborValue,
) -> Result<DeleteGuestbookRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(DeleteGuestbookRequest { id })
}

/// Encode a DeleteGuestbookRequest to canonical CSIL CBOR bytes.
pub fn encode_delete_guestbook_request(
    csil_v: &DeleteGuestbookRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_delete_guestbook_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DeleteGuestbookRequest.
pub fn decode_delete_guestbook_request(
    csil_data: &[u8],
) -> Result<DeleteGuestbookRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_delete_guestbook_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DeleteGuestbookResponse.
fn csil_enc_delete_guestbook_response(
    csil_v: &DeleteGuestbookResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DeleteGuestbookResponse from a decoded CBOR value tree.
fn csil_dec_delete_guestbook_response(
    csil_root: &CsilCborValue,
) -> Result<DeleteGuestbookResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(DeleteGuestbookResponse { success })
}

/// Encode a DeleteGuestbookResponse to canonical CSIL CBOR bytes.
pub fn encode_delete_guestbook_response(
    csil_v: &DeleteGuestbookResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_delete_guestbook_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DeleteGuestbookResponse.
pub fn decode_delete_guestbook_response(
    csil_data: &[u8],
) -> Result<DeleteGuestbookResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_delete_guestbook_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GuestbookListRequest.
fn csil_enc_guestbook_list_request(
    csil_v: &GuestbookListRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.limit {
        csil_entries.push((cbor_text("limit"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.offset {
        csil_entries.push((cbor_text("offset"), cbor_int(*csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GuestbookListRequest from a decoded CBOR value tree.
fn csil_dec_guestbook_list_request(
    csil_root: &CsilCborValue,
) -> Result<GuestbookListRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_guestbook_list_request(
    csil_v: &GuestbookListRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_guestbook_list_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GuestbookListRequest.
pub fn decode_guestbook_list_request(
    csil_data: &[u8],
) -> Result<GuestbookListRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_guestbook_list_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GuestbookListResponse.
fn csil_enc_guestbook_list_response(
    csil_v: &GuestbookListResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("entries"),
        cbor_enc_array(&csil_v.entries, csil_enc_guestbook_entry)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GuestbookListResponse from a decoded CBOR value tree.
fn csil_dec_guestbook_list_response(
    csil_root: &CsilCborValue,
) -> Result<GuestbookListResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let entries = {
        let csil_field = cbor_require(csil_root, "entries")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_guestbook_entry);
        csil_decode(csil_field)?
    };
    Ok(GuestbookListResponse { entries })
}

/// Encode a GuestbookListResponse to canonical CSIL CBOR bytes.
pub fn encode_guestbook_list_response(
    csil_v: &GuestbookListResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_guestbook_list_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GuestbookListResponse.
pub fn decode_guestbook_list_response(
    csil_data: &[u8],
) -> Result<GuestbookListResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_guestbook_list_response(&csil_root)
}

/// Build the canonical CBOR value tree for a EmptyRequest.
fn csil_enc_empty_request(_csil_v: &EmptyRequest) -> Result<CsilCborValue, CsilCborError> {
    Ok(CsilCborValue::Map(Vec::new()))
}

/// Reconstruct a EmptyRequest from a decoded CBOR value tree.
fn csil_dec_empty_request(csil_root: &CsilCborValue) -> Result<EmptyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    Ok(EmptyRequest {})
}

/// Encode a EmptyRequest to canonical CSIL CBOR bytes.
pub fn encode_empty_request(csil_v: &EmptyRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_empty_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a EmptyRequest.
pub fn decode_empty_request(csil_data: &[u8]) -> Result<EmptyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_empty_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DomainPublicKey.
fn csil_enc_domain_public_key(csil_v: &DomainPublicKey) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(10);
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    csil_entries.push((
        cbor_text("algorithm"),
        csil_enc_key_algorithm(&csil_v.algorithm)?,
    ));
    csil_entries.push((
        cbor_text("key_usage"),
        csil_enc_key_usage(&csil_v.key_usage)?,
    ));
    csil_entries.push((
        cbor_text("created_at"),
        csil_rt_enc_timestamp(&csil_v.created_at)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("public_key"), cbor_bytes(&csil_v.public_key)));
    if let Some(csil_inner) = &csil_v.revoked_at {
        csil_entries.push((cbor_text("revoked_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    if let Some(csil_inner) = &csil_v.key_signature {
        csil_entries.push((cbor_text("key_signature"), cbor_bytes(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.signed_by_key_id {
        csil_entries.push((cbor_text("signed_by_key_id"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DomainPublicKey from a decoded CBOR value tree.
fn csil_dec_domain_public_key(csil_root: &CsilCborValue) -> Result<DomainPublicKey, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_dec_key_algorithm;
        csil_decode(csil_field)?
    };
    let key_usage = {
        let csil_field = cbor_require(csil_root, "key_usage")?;
        let csil_decode = csil_dec_key_usage;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let revoked_at = match cbor_map_get(csil_root, "revoked_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
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
pub fn encode_domain_public_key(csil_v: &DomainPublicKey) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_domain_public_key(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DomainPublicKey.
pub fn decode_domain_public_key(csil_data: &[u8]) -> Result<DomainPublicKey, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_domain_public_key(&csil_root)
}

/// Build the canonical CBOR value tree for a GetDomainKeysResponse.
fn csil_enc_get_domain_keys_response(
    csil_v: &GetDomainKeysResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("keys"),
        cbor_enc_array(&csil_v.keys, csil_enc_domain_public_key)?,
    ));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    if let Some(csil_inner) = &csil_v.recent_revocations_available {
        csil_entries.push((
            cbor_text("recent_revocations_available"),
            cbor_bool(*csil_inner),
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetDomainKeysResponse from a decoded CBOR value tree.
fn csil_dec_get_domain_keys_response(
    csil_root: &CsilCborValue,
) -> Result<GetDomainKeysResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let csil_key = "recent_revocations_available";
    let csil_opt = match cbor_map_get(csil_root, csil_key) {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let recent_revocations_available = csil_opt;
    Ok(GetDomainKeysResponse {
        domain,
        keys,
        recent_revocations_available,
    })
}

/// Encode a GetDomainKeysResponse to canonical CSIL CBOR bytes.
pub fn encode_get_domain_keys_response(
    csil_v: &GetDomainKeysResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_domain_keys_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetDomainKeysResponse.
pub fn decode_get_domain_keys_response(
    csil_data: &[u8],
) -> Result<GetDomainKeysResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_domain_keys_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetRevocationsRequest.
fn csil_enc_get_revocations_request(
    csil_v: &GetRevocationsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    if let Some(csil_inner) = &csil_v.since {
        csil_entries.push((cbor_text("since"), csil_rt_enc_timestamp(csil_inner)?));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetRevocationsRequest from a decoded CBOR value tree.
fn csil_dec_get_revocations_request(
    csil_root: &CsilCborValue,
) -> Result<GetRevocationsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let since = match cbor_map_get(csil_root, "since") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(GetRevocationsRequest { since })
}

/// Encode a GetRevocationsRequest to canonical CSIL CBOR bytes.
pub fn encode_get_revocations_request(
    csil_v: &GetRevocationsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_revocations_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetRevocationsRequest.
pub fn decode_get_revocations_request(
    csil_data: &[u8],
) -> Result<GetRevocationsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_revocations_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetRevocationsResponse.
fn csil_enc_get_revocations_response(
    csil_v: &GetRevocationsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("revocations"),
        cbor_enc_array(&csil_v.revocations, csil_enc_revocation_certificate)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetRevocationsResponse from a decoded CBOR value tree.
fn csil_dec_get_revocations_response(
    csil_root: &CsilCborValue,
) -> Result<GetRevocationsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let revocations = {
        let csil_field = cbor_require(csil_root, "revocations")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_revocation_certificate);
        csil_decode(csil_field)?
    };
    Ok(GetRevocationsResponse { revocations })
}

/// Encode a GetRevocationsResponse to canonical CSIL CBOR bytes.
pub fn encode_get_revocations_response(
    csil_v: &GetRevocationsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_revocations_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetRevocationsResponse.
pub fn decode_get_revocations_response(
    csil_data: &[u8],
) -> Result<GetRevocationsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_revocations_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RecheckPinsRequest.
fn csil_enc_recheck_pins_request(
    csil_v: &RecheckPinsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    if let Some(csil_inner) = &csil_v.domain {
        csil_entries.push((cbor_text("domain"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RecheckPinsRequest from a decoded CBOR value tree.
fn csil_dec_recheck_pins_request(
    csil_root: &CsilCborValue,
) -> Result<RecheckPinsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_recheck_pins_request(csil_v: &RecheckPinsRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_recheck_pins_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RecheckPinsRequest.
pub fn decode_recheck_pins_request(csil_data: &[u8]) -> Result<RecheckPinsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_recheck_pins_request(&csil_root)
}

/// Build the canonical CBOR value tree for a PinRecheckResult.
fn csil_enc_pin_recheck_result(csil_v: &PinRecheckResult) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    if let Some(csil_inner) = &csil_v.message {
        csil_entries.push((cbor_text("message"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("outcome"),
        csil_enc_pin_recheck_outcome(&csil_v.outcome)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PinRecheckResult from a decoded CBOR value tree.
fn csil_dec_pin_recheck_result(
    csil_root: &CsilCborValue,
) -> Result<PinRecheckResult, CsilCborError> {
    cbor_check_record(csil_root)?;
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let outcome = {
        let csil_field = cbor_require(csil_root, "outcome")?;
        let csil_decode = csil_dec_pin_recheck_outcome;
        csil_decode(csil_field)?
    };
    let message = match cbor_map_get(csil_root, "message") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(PinRecheckResult {
        domain,
        outcome,
        message,
    })
}

/// Encode a PinRecheckResult to canonical CSIL CBOR bytes.
pub fn encode_pin_recheck_result(csil_v: &PinRecheckResult) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_pin_recheck_result(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PinRecheckResult.
pub fn decode_pin_recheck_result(csil_data: &[u8]) -> Result<PinRecheckResult, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_pin_recheck_result(&csil_root)
}

/// Build the canonical CBOR value tree for a RecheckPinsResponse.
fn csil_enc_recheck_pins_response(
    csil_v: &RecheckPinsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("results"),
        cbor_enc_array(&csil_v.results, csil_enc_pin_recheck_result)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RecheckPinsResponse from a decoded CBOR value tree.
fn csil_dec_recheck_pins_response(
    csil_root: &CsilCborValue,
) -> Result<RecheckPinsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let results = {
        let csil_field = cbor_require(csil_root, "results")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_pin_recheck_result);
        csil_decode(csil_field)?
    };
    Ok(RecheckPinsResponse { results })
}

/// Encode a RecheckPinsResponse to canonical CSIL CBOR bytes.
pub fn encode_recheck_pins_response(
    csil_v: &RecheckPinsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_recheck_pins_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RecheckPinsResponse.
pub fn decode_recheck_pins_response(
    csil_data: &[u8],
) -> Result<RecheckPinsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_recheck_pins_response(&csil_root)
}

/// Build the canonical CBOR value tree for a UserPublicKey.
fn csil_enc_user_public_key(csil_v: &UserPublicKey) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((
        cbor_text("algorithm"),
        csil_enc_key_algorithm(&csil_v.algorithm)?,
    ));
    csil_entries.push((
        cbor_text("key_usage"),
        csil_enc_key_usage(&csil_v.key_usage)?,
    ));
    csil_entries.push((
        cbor_text("created_at"),
        csil_rt_enc_timestamp(&csil_v.created_at)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("public_key"), cbor_bytes(&csil_v.public_key)));
    if let Some(csil_inner) = &csil_v.revoked_at {
        csil_entries.push((cbor_text("revoked_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    if let Some(csil_inner) = &csil_v.key_signature {
        csil_entries.push((cbor_text("key_signature"), cbor_bytes(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.signed_by_key_id {
        csil_entries.push((cbor_text("signed_by_key_id"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a UserPublicKey from a decoded CBOR value tree.
fn csil_dec_user_public_key(csil_root: &CsilCborValue) -> Result<UserPublicKey, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_dec_key_algorithm;
        csil_decode(csil_field)?
    };
    let key_usage = {
        let csil_field = cbor_require(csil_root, "key_usage")?;
        let csil_decode = csil_dec_key_usage;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let revoked_at = match cbor_map_get(csil_root, "revoked_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
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
pub fn encode_user_public_key(csil_v: &UserPublicKey) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_user_public_key(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a UserPublicKey.
pub fn decode_user_public_key(csil_data: &[u8]) -> Result<UserPublicKey, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_user_public_key(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserKeysRequest.
fn csil_enc_get_user_keys_request(
    csil_v: &GetUserKeysRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetUserKeysRequest from a decoded CBOR value tree.
fn csil_dec_get_user_keys_request(
    csil_root: &CsilCborValue,
) -> Result<GetUserKeysRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GetUserKeysRequest { user_id })
}

/// Encode a GetUserKeysRequest to canonical CSIL CBOR bytes.
pub fn encode_get_user_keys_request(csil_v: &GetUserKeysRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_user_keys_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetUserKeysRequest.
pub fn decode_get_user_keys_request(csil_data: &[u8]) -> Result<GetUserKeysRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_keys_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserKeysResponse.
fn csil_enc_get_user_keys_response(
    csil_v: &GetUserKeysResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("keys"),
        cbor_enc_array(&csil_v.keys, csil_enc_user_public_key)?,
    ));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetUserKeysResponse from a decoded CBOR value tree.
fn csil_dec_get_user_keys_response(
    csil_root: &CsilCborValue,
) -> Result<GetUserKeysResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_get_user_keys_response(
    csil_v: &GetUserKeysResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_user_keys_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetUserKeysResponse.
pub fn decode_get_user_keys_response(
    csil_data: &[u8],
) -> Result<GetUserKeysResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_keys_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimSignature.
fn csil_enc_claim_signature(csil_v: &ClaimSignature) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((
        cbor_text("signed_by_key_id"),
        cbor_text(&csil_v.signed_by_key_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ClaimSignature from a decoded CBOR value tree.
fn csil_dec_claim_signature(csil_root: &CsilCborValue) -> Result<ClaimSignature, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_claim_signature(csil_v: &ClaimSignature) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim_signature(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ClaimSignature.
pub fn decode_claim_signature(csil_data: &[u8]) -> Result<ClaimSignature, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_signature(&csil_root)
}

/// Build the canonical CBOR value tree for a RevocationCertificate.
fn csil_enc_revocation_certificate(
    csil_v: &RevocationCertificate,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((
        cbor_text("revoked_at"),
        csil_rt_enc_timestamp(&csil_v.revoked_at)?,
    ));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature)?,
    ));
    csil_entries.push((cbor_text("target_key_id"), cbor_text(&csil_v.target_key_id)));
    csil_entries.push((
        cbor_text("target_fingerprint"),
        cbor_text(&csil_v.target_fingerprint),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevocationCertificate from a decoded CBOR value tree.
fn csil_dec_revocation_certificate(
    csil_root: &CsilCborValue,
) -> Result<RevocationCertificate, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
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
pub fn encode_revocation_certificate(
    csil_v: &RevocationCertificate,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revocation_certificate(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevocationCertificate.
pub fn decode_revocation_certificate(
    csil_data: &[u8],
) -> Result<RevocationCertificate, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revocation_certificate(&csil_root)
}

/// Build the canonical CBOR value tree for a Claim.
fn csil_enc_claim(csil_v: &Claim) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("claim_id"), cbor_text(&csil_v.claim_id)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((
        cbor_text("created_at"),
        csil_rt_enc_timestamp(&csil_v.created_at)?,
    ));
    if let Some(csil_inner) = &csil_v.expires_at {
        csil_entries.push((cbor_text("expires_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    if let Some(csil_inner) = &csil_v.revoked_at {
        csil_entries.push((cbor_text("revoked_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature)?,
    ));
    csil_entries.push((
        cbor_text("attested_at"),
        csil_rt_enc_timestamp(&csil_v.attested_at)?,
    ));
    csil_entries.push((cbor_text("claim_value"), cbor_bytes(&csil_v.claim_value)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a Claim from a decoded CBOR value tree.
fn csil_dec_claim(csil_root: &CsilCborValue) -> Result<Claim, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = match cbor_map_get(csil_root, "expires_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let revoked_at = match cbor_map_get(csil_root, "revoked_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
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
pub fn encode_claim(csil_v: &Claim) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a Claim.
pub fn decode_claim(csil_data: &[u8]) -> Result<Claim, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserClaimsRequest.
fn csil_enc_get_user_claims_request(
    csil_v: &GetUserClaimsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("token"), cbor_bytes(&csil_v.token)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetUserClaimsRequest from a decoded CBOR value tree.
fn csil_dec_get_user_claims_request(
    csil_root: &CsilCborValue,
) -> Result<GetUserClaimsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_get_user_claims_request(
    csil_v: &GetUserClaimsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_user_claims_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetUserClaimsRequest.
pub fn decode_get_user_claims_request(
    csil_data: &[u8],
) -> Result<GetUserClaimsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_claims_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserClaimsResponse.
fn csil_enc_get_user_claims_response(
    csil_v: &GetUserClaimsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim)?,
    ));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetUserClaimsResponse from a decoded CBOR value tree.
fn csil_dec_get_user_claims_response(
    csil_root: &CsilCborValue,
) -> Result<GetUserClaimsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_get_user_claims_response(
    csil_v: &GetUserClaimsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_user_claims_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetUserClaimsResponse.
pub fn decode_get_user_claims_response(
    csil_data: &[u8],
) -> Result<GetUserClaimsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_claims_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RequestedClaim.
fn csil_enc_requested_claim(csil_v: &RequestedClaim) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("datatype"),
        csil_enc_claim_value_type(&csil_v.datatype)?,
    ));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    if let Some(csil_inner) = &csil_v.verified_by {
        csil_entries.push((
            cbor_text("verified_by"),
            csil_enc_verifying_party(csil_inner)?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RequestedClaim from a decoded CBOR value tree.
fn csil_dec_requested_claim(csil_root: &CsilCborValue) -> Result<RequestedClaim, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let datatype = {
        let csil_field = cbor_require(csil_root, "datatype")?;
        let csil_decode = csil_dec_claim_value_type;
        csil_decode(csil_field)?
    };
    let verified_by = match cbor_map_get(csil_root, "verified_by") {
        Some(csil_field) => {
            let csil_decode = csil_dec_verifying_party;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(RequestedClaim {
        claim_type,
        datatype,
        verified_by,
    })
}

/// Encode a RequestedClaim to canonical CSIL CBOR bytes.
pub fn encode_requested_claim(csil_v: &RequestedClaim) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_requested_claim(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RequestedClaim.
pub fn decode_requested_claim(csil_data: &[u8]) -> Result<RequestedClaim, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_requested_claim(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimRequest.
fn csil_enc_claim_request(csil_v: &ClaimRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("optional"),
        cbor_enc_array(&csil_v.optional, csil_enc_requested_claim)?,
    ));
    csil_entries.push((
        cbor_text("required"),
        cbor_enc_array(&csil_v.required, csil_enc_requested_claim)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ClaimRequest from a decoded CBOR value tree.
fn csil_dec_claim_request(csil_root: &CsilCborValue) -> Result<ClaimRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_claim_request(csil_v: &ClaimRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ClaimRequest.
pub fn decode_claim_request(csil_data: &[u8]) -> Result<ClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthenticationRequirements.
fn csil_enc_authentication_requirements(
    csil_v: &AuthenticationRequirements,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("minimum_factor_count"),
        cbor_int(csil_v.minimum_factor_count),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AuthenticationRequirements from a decoded CBOR value tree.
fn csil_dec_authentication_requirements(
    csil_root: &CsilCborValue,
) -> Result<AuthenticationRequirements, CsilCborError> {
    cbor_check_record(csil_root)?;
    let minimum_factor_count = {
        let csil_field = cbor_require(csil_root, "minimum_factor_count")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(AuthenticationRequirements {
        minimum_factor_count,
    })
}

/// Encode a AuthenticationRequirements to canonical CSIL CBOR bytes.
pub fn encode_authentication_requirements(
    csil_v: &AuthenticationRequirements,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_authentication_requirements(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AuthenticationRequirements.
pub fn decode_authentication_requirements(
    csil_data: &[u8],
) -> Result<AuthenticationRequirements, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_authentication_requirements(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthFlowContext.
fn csil_enc_auth_flow_context(csil_v: &AuthFlowContext) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("flow"), csil_enc_auth_flow(&csil_v.flow)?));
    if let Some(csil_inner) = &csil_v.prior_session {
        csil_entries.push((cbor_text("prior_session"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.request_reason {
        csil_entries.push((cbor_text("request_reason"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AuthFlowContext from a decoded CBOR value tree.
fn csil_dec_auth_flow_context(csil_root: &CsilCborValue) -> Result<AuthFlowContext, CsilCborError> {
    cbor_check_record(csil_root)?;
    let flow = {
        let csil_field = cbor_require(csil_root, "flow")?;
        let csil_decode = csil_dec_auth_flow;
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
pub fn encode_auth_flow_context(csil_v: &AuthFlowContext) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_auth_flow_context(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AuthFlowContext.
pub fn decode_auth_flow_context(csil_data: &[u8]) -> Result<AuthFlowContext, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_auth_flow_context(&csil_root)
}

/// Build the canonical CBOR value tree for a ConsentGrant.
fn csil_enc_consent_grant(csil_v: &ConsentGrant) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((cbor_text("grant_id"), cbor_text(&csil_v.grant_id)));
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    if let Some(csil_inner) = &csil_v.revoked_at {
        csil_entries.push((cbor_text("revoked_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    if let Some(csil_inner) = &csil_v.application {
        csil_entries.push((
            cbor_text("application"),
            csil_enc_application_ref(csil_inner)?,
        ));
    }
    csil_entries.push((
        cbor_text("claim_types"),
        cbor_enc_array(&csil_v.claim_types, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ConsentGrant from a decoded CBOR value tree.
fn csil_dec_consent_grant(csil_root: &CsilCborValue) -> Result<ConsentGrant, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let revoked_at = match cbor_map_get(csil_root, "revoked_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let application = match cbor_map_get(csil_root, "application") {
        Some(csil_field) => {
            let csil_decode = csil_dec_application_ref;
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
        application,
    })
}

/// Encode a ConsentGrant to canonical CSIL CBOR bytes.
pub fn encode_consent_grant(csil_v: &ConsentGrant) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_consent_grant(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ConsentGrant.
pub fn decode_consent_grant(csil_data: &[u8]) -> Result<ConsentGrant, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_consent_grant(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedConsentGrant.
fn csil_enc_signed_consent_grant(
    csil_v: &SignedConsentGrant,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("grant"), cbor_bytes(&csil_v.grant)));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedConsentGrant from a decoded CBOR value tree.
fn csil_dec_signed_consent_grant(
    csil_root: &CsilCborValue,
) -> Result<SignedConsentGrant, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_signed_consent_grant(csil_v: &SignedConsentGrant) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_consent_grant(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedConsentGrant.
pub fn decode_signed_consent_grant(csil_data: &[u8]) -> Result<SignedConsentGrant, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_consent_grant(&csil_root)
}

/// Build the canonical CBOR value tree for a DomainClaim.
fn csil_enc_domain_claim(csil_v: &DomainClaim) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    if let Some(csil_inner) = &csil_v.expires_at {
        csil_entries.push((cbor_text("expires_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature)?,
    ));
    csil_entries.push((
        cbor_text("attested_at"),
        csil_rt_enc_timestamp(&csil_v.attested_at)?,
    ));
    csil_entries.push((cbor_text("claim_value"), cbor_bytes(&csil_v.claim_value)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DomainClaim from a decoded CBOR value tree.
fn csil_dec_domain_claim(csil_root: &CsilCborValue) -> Result<DomainClaim, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = match cbor_map_get(csil_root, "expires_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(DomainClaim {
        claim_type,
        claim_value,
        signatures,
        attested_at,
        expires_at,
    })
}

/// Encode a DomainClaim to canonical CSIL CBOR bytes.
pub fn encode_domain_claim(csil_v: &DomainClaim) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_domain_claim(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DomainClaim.
pub fn decode_domain_claim(csil_data: &[u8]) -> Result<DomainClaim, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_domain_claim(&csil_root)
}

/// Build the canonical CBOR value tree for a SigningRequest.
fn csil_enc_signing_request(csil_v: &SigningRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    if let Some(csil_inner) = &csil_v.callback {
        csil_entries.push((cbor_text("callback"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
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
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SigningRequest from a decoded CBOR value tree.
fn csil_dec_signing_request(csil_root: &CsilCborValue) -> Result<SigningRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
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
pub fn encode_signing_request(csil_v: &SigningRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signing_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SigningRequest.
pub fn decode_signing_request(csil_data: &[u8]) -> Result<SigningRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signing_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedSigningRequest.
fn csil_enc_signed_signing_request(
    csil_v: &SignedSigningRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedSigningRequest from a decoded CBOR value tree.
fn csil_dec_signed_signing_request(
    csil_root: &CsilCborValue,
) -> Result<SignedSigningRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_signed_signing_request(
    csil_v: &SignedSigningRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_signing_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedSigningRequest.
pub fn decode_signed_signing_request(
    csil_data: &[u8],
) -> Result<SignedSigningRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_signing_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DepositClaimRequest.
fn csil_enc_deposit_claim_request(
    csil_v: &DepositClaimRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim"), csil_enc_claim(&csil_v.claim)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DepositClaimRequest from a decoded CBOR value tree.
fn csil_dec_deposit_claim_request(
    csil_root: &CsilCborValue,
) -> Result<DepositClaimRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim = {
        let csil_field = cbor_require(csil_root, "claim")?;
        let csil_decode = csil_dec_claim;
        csil_decode(csil_field)?
    };
    Ok(DepositClaimRequest { claim })
}

/// Encode a DepositClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_deposit_claim_request(
    csil_v: &DepositClaimRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_deposit_claim_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DepositClaimRequest.
pub fn decode_deposit_claim_request(
    csil_data: &[u8],
) -> Result<DepositClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deposit_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DepositClaimResponse.
fn csil_enc_deposit_claim_response(
    csil_v: &DepositClaimResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("stored"), cbor_bool(csil_v.stored)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DepositClaimResponse from a decoded CBOR value tree.
fn csil_dec_deposit_claim_response(
    csil_root: &CsilCborValue,
) -> Result<DepositClaimResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let stored = {
        let csil_field = cbor_require(csil_root, "stored")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(DepositClaimResponse { stored })
}

/// Encode a DepositClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_deposit_claim_response(
    csil_v: &DepositClaimResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_deposit_claim_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DepositClaimResponse.
pub fn decode_deposit_claim_response(
    csil_data: &[u8],
) -> Result<DepositClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deposit_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a IdentityAssertion.
fn csil_enc_identity_assertion(csil_v: &IdentityAssertion) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((
        cbor_text("application"),
        csil_enc_application_ref(&csil_v.application)?,
    ));
    if let Some(csil_inner) = &csil_v.display_name {
        csil_entries.push((cbor_text("display_name"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("authorized_claims"),
        cbor_enc_array(&csil_v.authorized_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a IdentityAssertion from a decoded CBOR value tree.
fn csil_dec_identity_assertion(
    csil_root: &CsilCborValue,
) -> Result<IdentityAssertion, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
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
    let application = {
        let csil_field = cbor_require(csil_root, "application")?;
        let csil_decode = csil_dec_application_ref;
        csil_decode(csil_field)?
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
        application,
    })
}

/// Encode a IdentityAssertion to canonical CSIL CBOR bytes.
pub fn encode_identity_assertion(csil_v: &IdentityAssertion) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_identity_assertion(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a IdentityAssertion.
pub fn decode_identity_assertion(csil_data: &[u8]) -> Result<IdentityAssertion, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_identity_assertion(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedIdentityAssertion.
fn csil_enc_signed_identity_assertion(
    csil_v: &SignedIdentityAssertion,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("assertion"), cbor_bytes(&csil_v.assertion)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((
        cbor_text("signing_key_id"),
        cbor_text(&csil_v.signing_key_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedIdentityAssertion from a decoded CBOR value tree.
fn csil_dec_signed_identity_assertion(
    csil_root: &CsilCborValue,
) -> Result<SignedIdentityAssertion, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_signed_identity_assertion(
    csil_v: &SignedIdentityAssertion,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_identity_assertion(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedIdentityAssertion.
pub fn decode_signed_identity_assertion(
    csil_data: &[u8],
) -> Result<SignedIdentityAssertion, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_identity_assertion(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserInfoRequest.
fn csil_enc_get_user_info_request(
    csil_v: &GetUserInfoRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("token"), cbor_bytes(&csil_v.token)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetUserInfoRequest from a decoded CBOR value tree.
fn csil_dec_get_user_info_request(
    csil_root: &CsilCborValue,
) -> Result<GetUserInfoRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let token = {
        let csil_field = cbor_require(csil_root, "token")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(GetUserInfoRequest { token })
}

/// Encode a GetUserInfoRequest to canonical CSIL CBOR bytes.
pub fn encode_get_user_info_request(csil_v: &GetUserInfoRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_user_info_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetUserInfoRequest.
pub fn decode_get_user_info_request(csil_data: &[u8]) -> Result<GetUserInfoRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_info_request(&csil_root)
}

/// Build the canonical CBOR value tree for a UserInfoRequest.
fn csil_enc_user_info_request(csil_v: &UserInfoRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    csil_entries.push((cbor_text("token"), cbor_bytes(&csil_v.token)));
    csil_entries.push((
        cbor_text("timestamp"),
        csil_rt_enc_timestamp(&csil_v.timestamp)?,
    ));
    csil_entries.push((cbor_text("relying_party"), cbor_text(&csil_v.relying_party)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a UserInfoRequest from a decoded CBOR value tree.
fn csil_dec_user_info_request(csil_root: &CsilCborValue) -> Result<UserInfoRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
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
pub fn encode_user_info_request(csil_v: &UserInfoRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_user_info_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a UserInfoRequest.
pub fn decode_user_info_request(csil_data: &[u8]) -> Result<UserInfoRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_user_info_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedUserInfoRequest.
fn csil_enc_signed_user_info_request(
    csil_v: &SignedUserInfoRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    if let Some(csil_inner) = &csil_v.public_keys {
        csil_entries.push((
            cbor_text("public_keys"),
            cbor_enc_array(csil_inner, csil_enc_domain_public_key)?,
        ));
    }
    csil_entries.push((
        cbor_text("signing_key_id"),
        cbor_text(&csil_v.signing_key_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedUserInfoRequest from a decoded CBOR value tree.
fn csil_dec_signed_user_info_request(
    csil_root: &CsilCborValue,
) -> Result<SignedUserInfoRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_signed_user_info_request(
    csil_v: &SignedUserInfoRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_user_info_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedUserInfoRequest.
pub fn decode_signed_user_info_request(
    csil_data: &[u8],
) -> Result<SignedUserInfoRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_user_info_request(&csil_root)
}

/// Build the canonical CBOR value tree for a UserInfo.
fn csil_enc_user_info(csil_v: &UserInfo) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim)?,
    ));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("display_name"), cbor_text(&csil_v.display_name)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a UserInfo from a decoded CBOR value tree.
fn csil_dec_user_info(csil_root: &CsilCborValue) -> Result<UserInfo, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_user_info(csil_v: &UserInfo) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_user_info(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a UserInfo.
pub fn decode_user_info(csil_data: &[u8]) -> Result<UserInfo, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_user_info(&csil_root)
}

/// Build the canonical CBOR value tree for a RelyingPartyApplication.
fn csil_enc_relying_party_application(
    csil_v: &RelyingPartyApplication,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("application"),
        csil_enc_application_ref(&csil_v.application)?,
    ));
    csil_entries.push((cbor_text("display_name"), cbor_text(&csil_v.display_name)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RelyingPartyApplication from a decoded CBOR value tree.
fn csil_dec_relying_party_application(
    csil_root: &CsilCborValue,
) -> Result<RelyingPartyApplication, CsilCborError> {
    cbor_check_record(csil_root)?;
    let application = {
        let csil_field = cbor_require(csil_root, "application")?;
        let csil_decode = csil_dec_application_ref;
        csil_decode(csil_field)?
    };
    let display_name = {
        let csil_field = cbor_require(csil_root, "display_name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RelyingPartyApplication {
        application,
        display_name,
    })
}

/// Encode a RelyingPartyApplication to canonical CSIL CBOR bytes.
pub fn encode_relying_party_application(
    csil_v: &RelyingPartyApplication,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_relying_party_application(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RelyingPartyApplication.
pub fn decode_relying_party_application(
    csil_data: &[u8],
) -> Result<RelyingPartyApplication, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_relying_party_application(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthRequest.
fn csil_enc_auth_request(csil_v: &AuthRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(10);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    csil_entries.push((
        cbor_text("timestamp"),
        csil_rt_enc_timestamp(&csil_v.timestamp)?,
    ));
    csil_entries.push((
        cbor_text("application"),
        csil_enc_relying_party_application(&csil_v.application)?,
    ));
    csil_entries.push((cbor_text("callback_url"), cbor_text(&csil_v.callback_url)));
    if let Some(csil_inner) = &csil_v.flow_context {
        csil_entries.push((
            cbor_text("flow_context"),
            csil_enc_auth_flow_context(csil_inner)?,
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
            csil_enc_claim_request(csil_inner)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.relying_party_claims {
        csil_entries.push((
            cbor_text("relying_party_claims"),
            cbor_enc_array(csil_inner, csil_enc_domain_claim)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.authentication_requirements {
        csil_entries.push((
            cbor_text("authentication_requirements"),
            csil_enc_authentication_requirements(csil_inner)?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AuthRequest from a decoded CBOR value tree.
fn csil_dec_auth_request(csil_root: &CsilCborValue) -> Result<AuthRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
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
    let authentication_requirements = match cbor_map_get(csil_root, "authentication_requirements") {
        Some(csil_field) => {
            let csil_decode = csil_dec_authentication_requirements;
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
    let application = {
        let csil_field = cbor_require(csil_root, "application")?;
        let csil_decode = csil_dec_relying_party_application;
        csil_decode(csil_field)?
    };
    Ok(AuthRequest {
        relying_party,
        callback_url,
        nonce,
        timestamp,
        signing_key_id,
        requested_claims,
        authentication_requirements,
        flow_context,
        relying_party_claims,
        application,
    })
}

/// Encode a AuthRequest to canonical CSIL CBOR bytes.
pub fn encode_auth_request(csil_v: &AuthRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_auth_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AuthRequest.
pub fn decode_auth_request(csil_data: &[u8]) -> Result<AuthRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_auth_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedAuthRequest.
fn csil_enc_signed_auth_request(
    csil_v: &SignedAuthRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((
        cbor_text("signing_key_id"),
        cbor_text(&csil_v.signing_key_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedAuthRequest from a decoded CBOR value tree.
fn csil_dec_signed_auth_request(
    csil_root: &CsilCborValue,
) -> Result<SignedAuthRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_signed_auth_request(csil_v: &SignedAuthRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_auth_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedAuthRequest.
pub fn decode_signed_auth_request(csil_data: &[u8]) -> Result<SignedAuthRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_auth_request(&csil_root)
}

/// Build the canonical CBOR value tree for a EncryptedToken.
fn csil_enc_encrypted_token(csil_v: &EncryptedToken) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("nonce"), cbor_bytes(&csil_v.nonce)));
    if let Some(csil_inner) = &csil_v.suite {
        csil_entries.push((cbor_text("suite"), csil_enc_aead_suite(csil_inner)?));
    }
    csil_entries.push((cbor_text("ciphertext"), cbor_bytes(&csil_v.ciphertext)));
    csil_entries.push((
        cbor_text("ephemeral_public_key"),
        cbor_bytes(&csil_v.ephemeral_public_key),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a EncryptedToken from a decoded CBOR value tree.
fn csil_dec_encrypted_token(csil_root: &CsilCborValue) -> Result<EncryptedToken, CsilCborError> {
    cbor_check_record(csil_root)?;
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
            let csil_decode = csil_dec_aead_suite;
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
pub fn encode_encrypted_token(csil_v: &EncryptedToken) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_encrypted_token(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a EncryptedToken.
pub fn decode_encrypted_token(csil_data: &[u8]) -> Result<EncryptedToken, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_encrypted_token(&csil_root)
}

/// Build the canonical CBOR value tree for a AlgorithmSupport.
fn csil_enc_algorithm_support(csil_v: &AlgorithmSupport) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("signing"),
        cbor_enc_array(&csil_v.signing, csil_enc_key_algorithm)?,
    ));
    if let Some(csil_inner) = &csil_v.encryption {
        csil_entries.push((
            cbor_text("encryption"),
            cbor_enc_array(csil_inner, csil_enc_aead_suite)?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AlgorithmSupport from a decoded CBOR value tree.
fn csil_dec_algorithm_support(
    csil_root: &CsilCborValue,
) -> Result<AlgorithmSupport, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signing = {
        let csil_field = cbor_require(csil_root, "signing")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_key_algorithm);
        csil_decode(csil_field)?
    };
    let encryption = match cbor_map_get(csil_root, "encryption") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_aead_suite);
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
pub fn encode_algorithm_support(csil_v: &AlgorithmSupport) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_algorithm_support(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AlgorithmSupport.
pub fn decode_algorithm_support(csil_data: &[u8]) -> Result<AlgorithmSupport, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_algorithm_support(&csil_root)
}

/// Build the canonical CBOR value tree for a HandshakeRequest.
fn csil_enc_handshake_request(csil_v: &HandshakeRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("version"), cbor_text(&csil_v.version)));
    csil_entries.push((
        cbor_text("algorithms"),
        csil_enc_algorithm_support(&csil_v.algorithms)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a HandshakeRequest from a decoded CBOR value tree.
fn csil_dec_handshake_request(
    csil_root: &CsilCborValue,
) -> Result<HandshakeRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_handshake_request(csil_v: &HandshakeRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_handshake_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a HandshakeRequest.
pub fn decode_handshake_request(csil_data: &[u8]) -> Result<HandshakeRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_handshake_request(&csil_root)
}

/// Build the canonical CBOR value tree for a HandshakeResponse.
fn csil_enc_handshake_response(csil_v: &HandshakeResponse) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("version"), cbor_text(&csil_v.version)));
    csil_entries.push((
        cbor_text("algorithms"),
        csil_enc_algorithm_support(&csil_v.algorithms)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a HandshakeResponse from a decoded CBOR value tree.
fn csil_dec_handshake_response(
    csil_root: &CsilCborValue,
) -> Result<HandshakeResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_handshake_response(csil_v: &HandshakeResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_handshake_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a HandshakeResponse.
pub fn decode_handshake_response(csil_data: &[u8]) -> Result<HandshakeResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_handshake_response(&csil_root)
}

/// Build the canonical CBOR value tree for a Relation.
fn csil_enc_relation(csil_v: &Relation) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("relation"), cbor_text(&csil_v.relation)));
    csil_entries.push((cbor_text("object_id"), cbor_text(&csil_v.object_id)));
    csil_entries.push((
        cbor_text("created_at"),
        csil_rt_enc_timestamp(&csil_v.created_at)?,
    ));
    if let Some(csil_inner) = &csil_v.removed_at {
        csil_entries.push((cbor_text("removed_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    csil_entries.push((cbor_text("subject_id"), cbor_text(&csil_v.subject_id)));
    csil_entries.push((cbor_text("object_type"), cbor_text(&csil_v.object_type)));
    csil_entries.push((cbor_text("subject_type"), cbor_text(&csil_v.subject_type)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a Relation from a decoded CBOR value tree.
fn csil_dec_relation(csil_root: &CsilCborValue) -> Result<Relation, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let removed_at = match cbor_map_get(csil_root, "removed_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
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
pub fn encode_relation(csil_v: &Relation) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_relation(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a Relation.
pub fn decode_relation(csil_data: &[u8]) -> Result<Relation, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_relation(&csil_root)
}

/// Build the canonical CBOR value tree for a AdminUser.
fn csil_enc_admin_user(csil_v: &AdminUser) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("kind"), csil_enc_account_kind(&csil_v.kind)?));
    csil_entries.push((cbor_text("username"), cbor_text(&csil_v.username)));
    csil_entries.push((cbor_text("is_active"), cbor_bool(csil_v.is_active)));
    if let Some(csil_inner) = &csil_v.purged_at {
        csil_entries.push((cbor_text("purged_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    csil_entries.push((
        cbor_text("created_at"),
        csil_rt_enc_timestamp(&csil_v.created_at)?,
    ));
    csil_entries.push((
        cbor_text("updated_at"),
        csil_rt_enc_timestamp(&csil_v.updated_at)?,
    ));
    csil_entries.push((cbor_text("display_name"), cbor_text(&csil_v.display_name)));
    if let Some(csil_inner) = &csil_v.purge_reason {
        csil_entries.push((cbor_text("purge_reason"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.application_id {
        csil_entries.push((cbor_text("application_id"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.password_locked {
        csil_entries.push((cbor_text("password_locked"), cbor_bool(*csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AdminUser from a decoded CBOR value tree.
fn csil_dec_admin_user(csil_root: &CsilCborValue) -> Result<AdminUser, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let kind = {
        let csil_field = cbor_require(csil_root, "kind")?;
        let csil_decode = csil_dec_account_kind;
        csil_decode(csil_field)?
    };
    let application_id = match cbor_map_get(csil_root, "application_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let is_active = {
        let csil_field = cbor_require(csil_root, "is_active")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let updated_at = {
        let csil_field = cbor_require(csil_root, "updated_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let purged_at = match cbor_map_get(csil_root, "purged_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let purge_reason = match cbor_map_get(csil_root, "purge_reason") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let password_locked = match cbor_map_get(csil_root, "password_locked") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(AdminUser {
        id,
        username,
        display_name,
        kind,
        application_id,
        is_active,
        created_at,
        updated_at,
        purged_at,
        purge_reason,
        password_locked,
    })
}

/// Encode a AdminUser to canonical CSIL CBOR bytes.
pub fn encode_admin_user(csil_v: &AdminUser) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_admin_user(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AdminUser.
pub fn decode_admin_user(csil_data: &[u8]) -> Result<AdminUser, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_admin_user(&csil_root)
}

/// Build the canonical CBOR value tree for a ListUsersRequest.
fn csil_enc_list_users_request(csil_v: &ListUsersRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    if let Some(csil_inner) = &csil_v.limit {
        csil_entries.push((cbor_text("limit"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.offset {
        csil_entries.push((cbor_text("offset"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.include_purged {
        csil_entries.push((cbor_text("include_purged"), cbor_bool(*csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListUsersRequest from a decoded CBOR value tree.
fn csil_dec_list_users_request(
    csil_root: &CsilCborValue,
) -> Result<ListUsersRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let include_purged = match cbor_map_get(csil_root, "include_purged") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ListUsersRequest {
        offset,
        limit,
        include_purged,
    })
}

/// Encode a ListUsersRequest to canonical CSIL CBOR bytes.
pub fn encode_list_users_request(csil_v: &ListUsersRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_users_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListUsersRequest.
pub fn decode_list_users_request(csil_data: &[u8]) -> Result<ListUsersRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_users_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ListUsersResponse.
fn csil_enc_list_users_response(
    csil_v: &ListUsersResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("users"),
        cbor_enc_array(&csil_v.users, csil_enc_admin_user)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListUsersResponse from a decoded CBOR value tree.
fn csil_dec_list_users_response(
    csil_root: &CsilCborValue,
) -> Result<ListUsersResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let users = {
        let csil_field = cbor_require(csil_root, "users")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_admin_user);
        csil_decode(csil_field)?
    };
    Ok(ListUsersResponse { users })
}

/// Encode a ListUsersResponse to canonical CSIL CBOR bytes.
pub fn encode_list_users_response(csil_v: &ListUsersResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_users_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListUsersResponse.
pub fn decode_list_users_response(csil_data: &[u8]) -> Result<ListUsersResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_users_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserRequest.
fn csil_enc_get_user_request(csil_v: &GetUserRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetUserRequest from a decoded CBOR value tree.
fn csil_dec_get_user_request(csil_root: &CsilCborValue) -> Result<GetUserRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GetUserRequest { user_id })
}

/// Encode a GetUserRequest to canonical CSIL CBOR bytes.
pub fn encode_get_user_request(csil_v: &GetUserRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_user_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetUserRequest.
pub fn decode_get_user_request(csil_data: &[u8]) -> Result<GetUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserResponse.
fn csil_enc_get_user_response(csil_v: &GetUserResponse) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetUserResponse from a decoded CBOR value tree.
fn csil_dec_get_user_response(csil_root: &CsilCborValue) -> Result<GetUserResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(GetUserResponse { user })
}

/// Encode a GetUserResponse to canonical CSIL CBOR bytes.
pub fn encode_get_user_response(csil_v: &GetUserResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_user_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetUserResponse.
pub fn decode_get_user_response(csil_data: &[u8]) -> Result<GetUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a UserAuthenticationActivity.
fn csil_enc_user_authentication_activity(
    csil_v: &UserAuthenticationActivity,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    if let Some(csil_inner) = &csil_v.last_seen_at {
        csil_entries.push((
            cbor_text("last_seen_at"),
            csil_rt_enc_timestamp(csil_inner)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.last_authenticated_at {
        csil_entries.push((
            cbor_text("last_authenticated_at"),
            csil_rt_enc_timestamp(csil_inner)?,
        ));
    }
    csil_entries.push((
        cbor_text("active_browser_session_count"),
        cbor_int(csil_v.active_browser_session_count),
    ));
    csil_entries.push((
        cbor_text("successful_authentication_count"),
        cbor_int(csil_v.successful_authentication_count),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a UserAuthenticationActivity from a decoded CBOR value tree.
fn csil_dec_user_authentication_activity(
    csil_root: &CsilCborValue,
) -> Result<UserAuthenticationActivity, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let last_authenticated_at = match cbor_map_get(csil_root, "last_authenticated_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let last_seen_at = match cbor_map_get(csil_root, "last_seen_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let successful_authentication_count = {
        let csil_field = cbor_require(csil_root, "successful_authentication_count")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let active_browser_session_count = {
        let csil_field = cbor_require(csil_root, "active_browser_session_count")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(UserAuthenticationActivity {
        user_id,
        last_authenticated_at,
        last_seen_at,
        successful_authentication_count,
        active_browser_session_count,
    })
}

/// Encode a UserAuthenticationActivity to canonical CSIL CBOR bytes.
pub fn encode_user_authentication_activity(
    csil_v: &UserAuthenticationActivity,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_user_authentication_activity(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a UserAuthenticationActivity.
pub fn decode_user_authentication_activity(
    csil_data: &[u8],
) -> Result<UserAuthenticationActivity, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_user_authentication_activity(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserAuthenticationActivityRequest.
fn csil_enc_get_user_authentication_activity_request(
    csil_v: &GetUserAuthenticationActivityRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetUserAuthenticationActivityRequest from a decoded CBOR value tree.
fn csil_dec_get_user_authentication_activity_request(
    csil_root: &CsilCborValue,
) -> Result<GetUserAuthenticationActivityRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GetUserAuthenticationActivityRequest { user_id })
}

/// Encode a GetUserAuthenticationActivityRequest to canonical CSIL CBOR bytes.
pub fn encode_get_user_authentication_activity_request(
    csil_v: &GetUserAuthenticationActivityRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_user_authentication_activity_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetUserAuthenticationActivityRequest.
pub fn decode_get_user_authentication_activity_request(
    csil_data: &[u8],
) -> Result<GetUserAuthenticationActivityRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_authentication_activity_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUserAuthenticationActivityResponse.
fn csil_enc_get_user_authentication_activity_response(
    csil_v: &GetUserAuthenticationActivityResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("activity"),
        csil_enc_user_authentication_activity(&csil_v.activity)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetUserAuthenticationActivityResponse from a decoded CBOR value tree.
fn csil_dec_get_user_authentication_activity_response(
    csil_root: &CsilCborValue,
) -> Result<GetUserAuthenticationActivityResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let activity = {
        let csil_field = cbor_require(csil_root, "activity")?;
        let csil_decode = csil_dec_user_authentication_activity;
        csil_decode(csil_field)?
    };
    Ok(GetUserAuthenticationActivityResponse { activity })
}

/// Encode a GetUserAuthenticationActivityResponse to canonical CSIL CBOR bytes.
pub fn encode_get_user_authentication_activity_response(
    csil_v: &GetUserAuthenticationActivityResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_user_authentication_activity_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetUserAuthenticationActivityResponse.
pub fn decode_get_user_authentication_activity_response(
    csil_data: &[u8],
) -> Result<GetUserAuthenticationActivityResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_user_authentication_activity_response(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateUserRequest.
fn csil_enc_create_user_request(
    csil_v: &CreateUserRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    if let Some(csil_inner) = &csil_v.password {
        csil_entries.push((cbor_text("password"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("username"), cbor_text(&csil_v.username)));
    csil_entries.push((cbor_text("display_name"), cbor_text(&csil_v.display_name)));
    if let Some(csil_inner) = &csil_v.application_id {
        csil_entries.push((cbor_text("application_id"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CreateUserRequest from a decoded CBOR value tree.
fn csil_dec_create_user_request(
    csil_root: &CsilCborValue,
) -> Result<CreateUserRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let application_id = match cbor_map_get(csil_root, "application_id") {
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
        application_id,
    })
}

/// Encode a CreateUserRequest to canonical CSIL CBOR bytes.
pub fn encode_create_user_request(csil_v: &CreateUserRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_create_user_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CreateUserRequest.
pub fn decode_create_user_request(csil_data: &[u8]) -> Result<CreateUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateUserResponse.
fn csil_enc_create_user_response(
    csil_v: &CreateUserResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    if let Some(csil_inner) = &csil_v.api_key {
        csil_entries.push((cbor_text("api_key"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CreateUserResponse from a decoded CBOR value tree.
fn csil_dec_create_user_response(
    csil_root: &CsilCborValue,
) -> Result<CreateUserResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_create_user_response(csil_v: &CreateUserResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_create_user_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CreateUserResponse.
pub fn decode_create_user_response(csil_data: &[u8]) -> Result<CreateUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RenameUserRequest.
fn csil_enc_rename_user_request(
    csil_v: &RenameUserRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("username"), cbor_text(&csil_v.username)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RenameUserRequest from a decoded CBOR value tree.
fn csil_dec_rename_user_request(
    csil_root: &CsilCborValue,
) -> Result<RenameUserRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let username = {
        let csil_field = cbor_require(csil_root, "username")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RenameUserRequest { user_id, username })
}

/// Encode a RenameUserRequest to canonical CSIL CBOR bytes.
pub fn encode_rename_user_request(csil_v: &RenameUserRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rename_user_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RenameUserRequest.
pub fn decode_rename_user_request(csil_data: &[u8]) -> Result<RenameUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rename_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RenameUserResponse.
fn csil_enc_rename_user_response(
    csil_v: &RenameUserResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RenameUserResponse from a decoded CBOR value tree.
fn csil_dec_rename_user_response(
    csil_root: &CsilCborValue,
) -> Result<RenameUserResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(RenameUserResponse { user })
}

/// Encode a RenameUserResponse to canonical CSIL CBOR bytes.
pub fn encode_rename_user_response(csil_v: &RenameUserResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rename_user_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RenameUserResponse.
pub fn decode_rename_user_response(csil_data: &[u8]) -> Result<RenameUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rename_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetApplicationIdRequest.
fn csil_enc_set_application_id_request(
    csil_v: &SetApplicationIdRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetApplicationIdRequest from a decoded CBOR value tree.
fn csil_dec_set_application_id_request(
    csil_root: &CsilCborValue,
) -> Result<SetApplicationIdRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(SetApplicationIdRequest {
        user_id,
        application_id,
    })
}

/// Encode a SetApplicationIdRequest to canonical CSIL CBOR bytes.
pub fn encode_set_application_id_request(
    csil_v: &SetApplicationIdRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_application_id_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetApplicationIdRequest.
pub fn decode_set_application_id_request(
    csil_data: &[u8],
) -> Result<SetApplicationIdRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_application_id_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetApplicationIdResponse.
fn csil_enc_set_application_id_response(
    csil_v: &SetApplicationIdResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetApplicationIdResponse from a decoded CBOR value tree.
fn csil_dec_set_application_id_response(
    csil_root: &CsilCborValue,
) -> Result<SetApplicationIdResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(SetApplicationIdResponse { user })
}

/// Encode a SetApplicationIdResponse to canonical CSIL CBOR bytes.
pub fn encode_set_application_id_response(
    csil_v: &SetApplicationIdResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_application_id_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetApplicationIdResponse.
pub fn decode_set_application_id_response(
    csil_data: &[u8],
) -> Result<SetApplicationIdResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_application_id_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ApiKeyInfo.
fn csil_enc_api_key_info(csil_v: &ApiKeyInfo) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("hint"), cbor_text(&csil_v.hint)));
    csil_entries.push((cbor_text("name"), cbor_text(&csil_v.name)));
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    csil_entries.push((
        cbor_text("created_at"),
        csil_rt_enc_timestamp(&csil_v.created_at)?,
    ));
    if let Some(csil_inner) = &csil_v.last_used_at {
        csil_entries.push((
            cbor_text("last_used_at"),
            csil_rt_enc_timestamp(csil_inner)?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApiKeyInfo from a decoded CBOR value tree.
fn csil_dec_api_key_info(csil_root: &CsilCborValue) -> Result<ApiKeyInfo, CsilCborError> {
    cbor_check_record(csil_root)?;
    let key_id = {
        let csil_field = cbor_require(csil_root, "key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let name = {
        let csil_field = cbor_require(csil_root, "name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let hint = {
        let csil_field = cbor_require(csil_root, "hint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let last_used_at = match cbor_map_get(csil_root, "last_used_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ApiKeyInfo {
        key_id,
        name,
        hint,
        created_at,
        last_used_at,
    })
}

/// Encode a ApiKeyInfo to canonical CSIL CBOR bytes.
pub fn encode_api_key_info(csil_v: &ApiKeyInfo) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_api_key_info(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApiKeyInfo.
pub fn decode_api_key_info(csil_data: &[u8]) -> Result<ApiKeyInfo, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_api_key_info(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateApiKeyRequest.
fn csil_enc_create_api_key_request(
    csil_v: &CreateApiKeyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("name"), cbor_text(&csil_v.name)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CreateApiKeyRequest from a decoded CBOR value tree.
fn csil_dec_create_api_key_request(
    csil_root: &CsilCborValue,
) -> Result<CreateApiKeyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let name = {
        let csil_field = cbor_require(csil_root, "name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(CreateApiKeyRequest { user_id, name })
}

/// Encode a CreateApiKeyRequest to canonical CSIL CBOR bytes.
pub fn encode_create_api_key_request(
    csil_v: &CreateApiKeyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_create_api_key_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CreateApiKeyRequest.
pub fn decode_create_api_key_request(
    csil_data: &[u8],
) -> Result<CreateApiKeyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_api_key_request(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateApiKeyResponse.
fn csil_enc_create_api_key_response(
    csil_v: &CreateApiKeyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("key"), csil_enc_api_key_info(&csil_v.key)?));
    csil_entries.push((cbor_text("api_key"), cbor_text(&csil_v.api_key)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CreateApiKeyResponse from a decoded CBOR value tree.
fn csil_dec_create_api_key_response(
    csil_root: &CsilCborValue,
) -> Result<CreateApiKeyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let key = {
        let csil_field = cbor_require(csil_root, "key")?;
        let csil_decode = csil_dec_api_key_info;
        csil_decode(csil_field)?
    };
    let api_key = {
        let csil_field = cbor_require(csil_root, "api_key")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(CreateApiKeyResponse { key, api_key })
}

/// Encode a CreateApiKeyResponse to canonical CSIL CBOR bytes.
pub fn encode_create_api_key_response(
    csil_v: &CreateApiKeyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_create_api_key_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CreateApiKeyResponse.
pub fn decode_create_api_key_response(
    csil_data: &[u8],
) -> Result<CreateApiKeyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_api_key_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ListApiKeysRequest.
fn csil_enc_list_api_keys_request(
    csil_v: &ListApiKeysRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListApiKeysRequest from a decoded CBOR value tree.
fn csil_dec_list_api_keys_request(
    csil_root: &CsilCborValue,
) -> Result<ListApiKeysRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ListApiKeysRequest { user_id })
}

/// Encode a ListApiKeysRequest to canonical CSIL CBOR bytes.
pub fn encode_list_api_keys_request(csil_v: &ListApiKeysRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_api_keys_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListApiKeysRequest.
pub fn decode_list_api_keys_request(csil_data: &[u8]) -> Result<ListApiKeysRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_api_keys_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ListApiKeysResponse.
fn csil_enc_list_api_keys_response(
    csil_v: &ListApiKeysResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("keys"),
        cbor_enc_array(&csil_v.keys, csil_enc_api_key_info)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListApiKeysResponse from a decoded CBOR value tree.
fn csil_dec_list_api_keys_response(
    csil_root: &CsilCborValue,
) -> Result<ListApiKeysResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let keys = {
        let csil_field = cbor_require(csil_root, "keys")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_api_key_info);
        csil_decode(csil_field)?
    };
    Ok(ListApiKeysResponse { keys })
}

/// Encode a ListApiKeysResponse to canonical CSIL CBOR bytes.
pub fn encode_list_api_keys_response(
    csil_v: &ListApiKeysResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_api_keys_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListApiKeysResponse.
pub fn decode_list_api_keys_response(
    csil_data: &[u8],
) -> Result<ListApiKeysResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_api_keys_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeApiKeyRequest.
fn csil_enc_revoke_api_key_request(
    csil_v: &RevokeApiKeyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeApiKeyRequest from a decoded CBOR value tree.
fn csil_dec_revoke_api_key_request(
    csil_root: &CsilCborValue,
) -> Result<RevokeApiKeyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let key_id = {
        let csil_field = cbor_require(csil_root, "key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RevokeApiKeyRequest { user_id, key_id })
}

/// Encode a RevokeApiKeyRequest to canonical CSIL CBOR bytes.
pub fn encode_revoke_api_key_request(
    csil_v: &RevokeApiKeyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_api_key_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeApiKeyRequest.
pub fn decode_revoke_api_key_request(
    csil_data: &[u8],
) -> Result<RevokeApiKeyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_api_key_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeApiKeyResponse.
fn csil_enc_revoke_api_key_response(
    csil_v: &RevokeApiKeyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("revoked"), cbor_bool(csil_v.revoked)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeApiKeyResponse from a decoded CBOR value tree.
fn csil_dec_revoke_api_key_response(
    csil_root: &CsilCborValue,
) -> Result<RevokeApiKeyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let revoked = {
        let csil_field = cbor_require(csil_root, "revoked")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RevokeApiKeyResponse { revoked })
}

/// Encode a RevokeApiKeyResponse to canonical CSIL CBOR bytes.
pub fn encode_revoke_api_key_response(
    csil_v: &RevokeApiKeyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_api_key_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeApiKeyResponse.
pub fn decode_revoke_api_key_response(
    csil_data: &[u8],
) -> Result<RevokeApiKeyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_api_key_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AccountLimits.
fn csil_enc_account_limits(csil_v: &AccountLimits) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    if let Some(csil_inner) = &csil_v.max_api_keys {
        csil_entries.push((cbor_text("max_api_keys"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.request_burst {
        csil_entries.push((cbor_text("request_burst"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.max_distinct_users {
        csil_entries.push((cbor_text("max_distinct_users"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.requests_per_minute {
        csil_entries.push((cbor_text("requests_per_minute"), cbor_int(*csil_inner)));
    }
    csil_entries.push((
        cbor_text("distinct_user_window_days"),
        cbor_int(csil_v.distinct_user_window_days),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AccountLimits from a decoded CBOR value tree.
fn csil_dec_account_limits(csil_root: &CsilCborValue) -> Result<AccountLimits, CsilCborError> {
    cbor_check_record(csil_root)?;
    let max_api_keys = match cbor_map_get(csil_root, "max_api_keys") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let max_distinct_users = match cbor_map_get(csil_root, "max_distinct_users") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let distinct_user_window_days = {
        let csil_field = cbor_require(csil_root, "distinct_user_window_days")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let requests_per_minute = match cbor_map_get(csil_root, "requests_per_minute") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let request_burst = match cbor_map_get(csil_root, "request_burst") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(AccountLimits {
        max_api_keys,
        max_distinct_users,
        distinct_user_window_days,
        requests_per_minute,
        request_burst,
    })
}

/// Encode a AccountLimits to canonical CSIL CBOR bytes.
pub fn encode_account_limits(csil_v: &AccountLimits) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_account_limits(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AccountLimits.
pub fn decode_account_limits(csil_data: &[u8]) -> Result<AccountLimits, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_account_limits(&csil_root)
}

/// Build the canonical CBOR value tree for a GetAccountLimitsRequest.
fn csil_enc_get_account_limits_request(
    csil_v: &GetAccountLimitsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetAccountLimitsRequest from a decoded CBOR value tree.
fn csil_dec_get_account_limits_request(
    csil_root: &CsilCborValue,
) -> Result<GetAccountLimitsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GetAccountLimitsRequest { user_id })
}

/// Encode a GetAccountLimitsRequest to canonical CSIL CBOR bytes.
pub fn encode_get_account_limits_request(
    csil_v: &GetAccountLimitsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_account_limits_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetAccountLimitsRequest.
pub fn decode_get_account_limits_request(
    csil_data: &[u8],
) -> Result<GetAccountLimitsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_account_limits_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetAccountLimitsResponse.
fn csil_enc_get_account_limits_response(
    csil_v: &GetAccountLimitsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("limits"),
        csil_enc_account_limits(&csil_v.limits)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetAccountLimitsResponse from a decoded CBOR value tree.
fn csil_dec_get_account_limits_response(
    csil_root: &CsilCborValue,
) -> Result<GetAccountLimitsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let limits = {
        let csil_field = cbor_require(csil_root, "limits")?;
        let csil_decode = csil_dec_account_limits;
        csil_decode(csil_field)?
    };
    Ok(GetAccountLimitsResponse { limits })
}

/// Encode a GetAccountLimitsResponse to canonical CSIL CBOR bytes.
pub fn encode_get_account_limits_response(
    csil_v: &GetAccountLimitsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_account_limits_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetAccountLimitsResponse.
pub fn decode_get_account_limits_response(
    csil_data: &[u8],
) -> Result<GetAccountLimitsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_account_limits_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetAccountLimitsRequest.
fn csil_enc_set_account_limits_request(
    csil_v: &SetAccountLimitsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("limits"),
        csil_enc_account_limits(&csil_v.limits)?,
    ));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetAccountLimitsRequest from a decoded CBOR value tree.
fn csil_dec_set_account_limits_request(
    csil_root: &CsilCborValue,
) -> Result<SetAccountLimitsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let limits = {
        let csil_field = cbor_require(csil_root, "limits")?;
        let csil_decode = csil_dec_account_limits;
        csil_decode(csil_field)?
    };
    Ok(SetAccountLimitsRequest { user_id, limits })
}

/// Encode a SetAccountLimitsRequest to canonical CSIL CBOR bytes.
pub fn encode_set_account_limits_request(
    csil_v: &SetAccountLimitsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_account_limits_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetAccountLimitsRequest.
pub fn decode_set_account_limits_request(
    csil_data: &[u8],
) -> Result<SetAccountLimitsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_account_limits_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetAccountLimitsResponse.
fn csil_enc_set_account_limits_response(
    csil_v: &SetAccountLimitsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("limits"),
        csil_enc_account_limits(&csil_v.limits)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetAccountLimitsResponse from a decoded CBOR value tree.
fn csil_dec_set_account_limits_response(
    csil_root: &CsilCborValue,
) -> Result<SetAccountLimitsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let limits = {
        let csil_field = cbor_require(csil_root, "limits")?;
        let csil_decode = csil_dec_account_limits;
        csil_decode(csil_field)?
    };
    Ok(SetAccountLimitsResponse { limits })
}

/// Encode a SetAccountLimitsResponse to canonical CSIL CBOR bytes.
pub fn encode_set_account_limits_response(
    csil_v: &SetAccountLimitsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_account_limits_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetAccountLimitsResponse.
pub fn decode_set_account_limits_response(
    csil_data: &[u8],
) -> Result<SetAccountLimitsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_account_limits_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpUsageDay.
fn csil_enc_rp_usage_day(csil_v: &RpUsageDay) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("day"), csil_rt_enc_date(&csil_v.day)?));
    csil_entries.push((cbor_text("failed"), cbor_int(csil_v.failed)));
    csil_entries.push((cbor_text("operation"), cbor_text(&csil_v.operation)));
    csil_entries.push((cbor_text("succeeded"), cbor_int(csil_v.succeeded)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpUsageDay from a decoded CBOR value tree.
fn csil_dec_rp_usage_day(csil_root: &CsilCborValue) -> Result<RpUsageDay, CsilCborError> {
    cbor_check_record(csil_root)?;
    let day = {
        let csil_field = cbor_require(csil_root, "day")?;
        let csil_decode = csil_as_date;
        csil_decode(csil_field)?
    };
    let operation = {
        let csil_field = cbor_require(csil_root, "operation")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let succeeded = {
        let csil_field = cbor_require(csil_root, "succeeded")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let failed = {
        let csil_field = cbor_require(csil_root, "failed")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(RpUsageDay {
        day,
        operation,
        succeeded,
        failed,
    })
}

/// Encode a RpUsageDay to canonical CSIL CBOR bytes.
pub fn encode_rp_usage_day(csil_v: &RpUsageDay) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_usage_day(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpUsageDay.
pub fn decode_rp_usage_day(csil_data: &[u8]) -> Result<RpUsageDay, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_usage_day(&csil_root)
}

/// Build the canonical CBOR value tree for a GetApplicationUsageRequest.
fn csil_enc_get_application_usage_request(
    csil_v: &GetApplicationUsageRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("last_day"), csil_rt_enc_date(&csil_v.last_day)?));
    csil_entries.push((cbor_text("first_day"), csil_rt_enc_date(&csil_v.first_day)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetApplicationUsageRequest from a decoded CBOR value tree.
fn csil_dec_get_application_usage_request(
    csil_root: &CsilCborValue,
) -> Result<GetApplicationUsageRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let first_day = {
        let csil_field = cbor_require(csil_root, "first_day")?;
        let csil_decode = csil_as_date;
        csil_decode(csil_field)?
    };
    let last_day = {
        let csil_field = cbor_require(csil_root, "last_day")?;
        let csil_decode = csil_as_date;
        csil_decode(csil_field)?
    };
    Ok(GetApplicationUsageRequest {
        user_id,
        first_day,
        last_day,
    })
}

/// Encode a GetApplicationUsageRequest to canonical CSIL CBOR bytes.
pub fn encode_get_application_usage_request(
    csil_v: &GetApplicationUsageRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_application_usage_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetApplicationUsageRequest.
pub fn decode_get_application_usage_request(
    csil_data: &[u8],
) -> Result<GetApplicationUsageRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_application_usage_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetApplicationUsageResponse.
fn csil_enc_get_application_usage_response(
    csil_v: &GetApplicationUsageResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((
        cbor_text("days"),
        cbor_enc_array(&csil_v.days, csil_enc_rp_usage_day)?,
    ));
    csil_entries.push((cbor_text("distinct_users"), cbor_int(csil_v.distinct_users)));
    if let Some(csil_inner) = &csil_v.max_distinct_users {
        csil_entries.push((cbor_text("max_distinct_users"), cbor_int(*csil_inner)));
    }
    csil_entries.push((
        cbor_text("distinct_user_window_days"),
        cbor_int(csil_v.distinct_user_window_days),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetApplicationUsageResponse from a decoded CBOR value tree.
fn csil_dec_get_application_usage_response(
    csil_root: &CsilCborValue,
) -> Result<GetApplicationUsageResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let distinct_users = {
        let csil_field = cbor_require(csil_root, "distinct_users")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let distinct_user_window_days = {
        let csil_field = cbor_require(csil_root, "distinct_user_window_days")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let max_distinct_users = match cbor_map_get(csil_root, "max_distinct_users") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let days = {
        let csil_field = cbor_require(csil_root, "days")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_rp_usage_day);
        csil_decode(csil_field)?
    };
    Ok(GetApplicationUsageResponse {
        distinct_users,
        distinct_user_window_days,
        max_distinct_users,
        days,
    })
}

/// Encode a GetApplicationUsageResponse to canonical CSIL CBOR bytes.
pub fn encode_get_application_usage_response(
    csil_v: &GetApplicationUsageResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_application_usage_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetApplicationUsageResponse.
pub fn decode_get_application_usage_response(
    csil_data: &[u8],
) -> Result<GetApplicationUsageResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_application_usage_response(&csil_root)
}

/// Build the canonical CBOR value tree for a UpdateUserRequest.
fn csil_enc_update_user_request(
    csil_v: &UpdateUserRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    if let Some(csil_inner) = &csil_v.display_name {
        csil_entries.push((cbor_text("display_name"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a UpdateUserRequest from a decoded CBOR value tree.
fn csil_dec_update_user_request(
    csil_root: &CsilCborValue,
) -> Result<UpdateUserRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_update_user_request(csil_v: &UpdateUserRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_update_user_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a UpdateUserRequest.
pub fn decode_update_user_request(csil_data: &[u8]) -> Result<UpdateUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_update_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a UpdateUserResponse.
fn csil_enc_update_user_response(
    csil_v: &UpdateUserResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a UpdateUserResponse from a decoded CBOR value tree.
fn csil_dec_update_user_response(
    csil_root: &CsilCborValue,
) -> Result<UpdateUserResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(UpdateUserResponse { user })
}

/// Encode a UpdateUserResponse to canonical CSIL CBOR bytes.
pub fn encode_update_user_response(csil_v: &UpdateUserResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_update_user_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a UpdateUserResponse.
pub fn decode_update_user_response(csil_data: &[u8]) -> Result<UpdateUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_update_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a DeactivateUserRequest.
fn csil_enc_deactivate_user_request(
    csil_v: &DeactivateUserRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DeactivateUserRequest from a decoded CBOR value tree.
fn csil_dec_deactivate_user_request(
    csil_root: &CsilCborValue,
) -> Result<DeactivateUserRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(DeactivateUserRequest { user_id })
}

/// Encode a DeactivateUserRequest to canonical CSIL CBOR bytes.
pub fn encode_deactivate_user_request(
    csil_v: &DeactivateUserRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_deactivate_user_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DeactivateUserRequest.
pub fn decode_deactivate_user_request(
    csil_data: &[u8],
) -> Result<DeactivateUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deactivate_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DeactivateUserResponse.
fn csil_enc_deactivate_user_response(
    csil_v: &DeactivateUserResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DeactivateUserResponse from a decoded CBOR value tree.
fn csil_dec_deactivate_user_response(
    csil_root: &CsilCborValue,
) -> Result<DeactivateUserResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(DeactivateUserResponse { user })
}

/// Encode a DeactivateUserResponse to canonical CSIL CBOR bytes.
pub fn encode_deactivate_user_response(
    csil_v: &DeactivateUserResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_deactivate_user_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DeactivateUserResponse.
pub fn decode_deactivate_user_response(
    csil_data: &[u8],
) -> Result<DeactivateUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deactivate_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ActivateUserRequest.
fn csil_enc_activate_user_request(
    csil_v: &ActivateUserRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActivateUserRequest from a decoded CBOR value tree.
fn csil_dec_activate_user_request(
    csil_root: &CsilCborValue,
) -> Result<ActivateUserRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ActivateUserRequest { user_id })
}

/// Encode a ActivateUserRequest to canonical CSIL CBOR bytes.
pub fn encode_activate_user_request(
    csil_v: &ActivateUserRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_activate_user_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActivateUserRequest.
pub fn decode_activate_user_request(
    csil_data: &[u8],
) -> Result<ActivateUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_activate_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ActivateUserResponse.
fn csil_enc_activate_user_response(
    csil_v: &ActivateUserResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActivateUserResponse from a decoded CBOR value tree.
fn csil_dec_activate_user_response(
    csil_root: &CsilCborValue,
) -> Result<ActivateUserResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(ActivateUserResponse { user })
}

/// Encode a ActivateUserResponse to canonical CSIL CBOR bytes.
pub fn encode_activate_user_response(
    csil_v: &ActivateUserResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_activate_user_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActivateUserResponse.
pub fn decode_activate_user_response(
    csil_data: &[u8],
) -> Result<ActivateUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_activate_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a PurgeUserRequest.
fn csil_enc_purge_user_request(csil_v: &PurgeUserRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.reason {
        csil_entries.push((cbor_text("reason"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PurgeUserRequest from a decoded CBOR value tree.
fn csil_dec_purge_user_request(
    csil_root: &CsilCborValue,
) -> Result<PurgeUserRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_purge_user_request(csil_v: &PurgeUserRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_purge_user_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PurgeUserRequest.
pub fn decode_purge_user_request(csil_data: &[u8]) -> Result<PurgeUserRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_purge_user_request(&csil_root)
}

/// Build the canonical CBOR value tree for a PurgeUserResponse.
fn csil_enc_purge_user_response(
    csil_v: &PurgeUserResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
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
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PurgeUserResponse from a decoded CBOR value tree.
fn csil_dec_purge_user_response(
    csil_root: &CsilCborValue,
) -> Result<PurgeUserResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_purge_user_response(csil_v: &PurgeUserResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_purge_user_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PurgeUserResponse.
pub fn decode_purge_user_response(csil_data: &[u8]) -> Result<PurgeUserResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_purge_user_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeDomainKeyRequest.
fn csil_enc_revoke_domain_key_request(
    csil_v: &RevokeDomainKeyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeDomainKeyRequest from a decoded CBOR value tree.
fn csil_dec_revoke_domain_key_request(
    csil_root: &CsilCborValue,
) -> Result<RevokeDomainKeyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let key_id = {
        let csil_field = cbor_require(csil_root, "key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RevokeDomainKeyRequest { key_id })
}

/// Encode a RevokeDomainKeyRequest to canonical CSIL CBOR bytes.
pub fn encode_revoke_domain_key_request(
    csil_v: &RevokeDomainKeyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_domain_key_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeDomainKeyRequest.
pub fn decode_revoke_domain_key_request(
    csil_data: &[u8],
) -> Result<RevokeDomainKeyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_domain_key_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeDomainKeyResponse.
fn csil_enc_revoke_domain_key_response(
    csil_v: &RevokeDomainKeyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("revoked_key"),
        csil_enc_domain_public_key(&csil_v.revoked_key)?,
    ));
    csil_entries.push((
        cbor_text("certificate_issued"),
        cbor_bool(csil_v.certificate_issued),
    ));
    csil_entries.push((
        cbor_text("dns_removal_reminder"),
        cbor_text(&csil_v.dns_removal_reminder),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeDomainKeyResponse from a decoded CBOR value tree.
fn csil_dec_revoke_domain_key_response(
    csil_root: &CsilCborValue,
) -> Result<RevokeDomainKeyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_revoke_domain_key_response(
    csil_v: &RevokeDomainKeyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_domain_key_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeDomainKeyResponse.
pub fn decode_revoke_domain_key_response(
    csil_data: &[u8],
) -> Result<RevokeDomainKeyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_domain_key_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ResetPasswordRequest.
fn csil_enc_reset_password_request(
    csil_v: &ResetPasswordRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("new_password"), cbor_text(&csil_v.new_password)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ResetPasswordRequest from a decoded CBOR value tree.
fn csil_dec_reset_password_request(
    csil_root: &CsilCborValue,
) -> Result<ResetPasswordRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_reset_password_request(
    csil_v: &ResetPasswordRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_reset_password_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ResetPasswordRequest.
pub fn decode_reset_password_request(
    csil_data: &[u8],
) -> Result<ResetPasswordRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_reset_password_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ResetPasswordResponse.
fn csil_enc_reset_password_response(
    csil_v: &ResetPasswordResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ResetPasswordResponse from a decoded CBOR value tree.
fn csil_dec_reset_password_response(
    csil_root: &CsilCborValue,
) -> Result<ResetPasswordResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(ResetPasswordResponse { success })
}

/// Encode a ResetPasswordResponse to canonical CSIL CBOR bytes.
pub fn encode_reset_password_response(
    csil_v: &ResetPasswordResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_reset_password_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ResetPasswordResponse.
pub fn decode_reset_password_response(
    csil_data: &[u8],
) -> Result<ResetPasswordResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_reset_password_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthenticateRequest.
fn csil_enc_authenticate_request(
    csil_v: &AuthenticateRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("password"), cbor_text(&csil_v.password)));
    csil_entries.push((cbor_text("username"), cbor_text(&csil_v.username)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AuthenticateRequest from a decoded CBOR value tree.
fn csil_dec_authenticate_request(
    csil_root: &CsilCborValue,
) -> Result<AuthenticateRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_authenticate_request(csil_v: &AuthenticateRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_authenticate_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AuthenticateRequest.
pub fn decode_authenticate_request(csil_data: &[u8]) -> Result<AuthenticateRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_authenticate_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthenticateResponse.
fn csil_enc_authenticate_response(
    csil_v: &AuthenticateResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AuthenticateResponse from a decoded CBOR value tree.
fn csil_dec_authenticate_response(
    csil_root: &CsilCborValue,
) -> Result<AuthenticateResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(AuthenticateResponse { user })
}

/// Encode a AuthenticateResponse to canonical CSIL CBOR bytes.
pub fn encode_authenticate_response(
    csil_v: &AuthenticateResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_authenticate_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AuthenticateResponse.
pub fn decode_authenticate_response(
    csil_data: &[u8],
) -> Result<AuthenticateResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_authenticate_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveCredentialRequest.
fn csil_enc_remove_credential_request(
    csil_v: &RemoveCredentialRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("credential_id"), cbor_text(&csil_v.credential_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveCredentialRequest from a decoded CBOR value tree.
fn csil_dec_remove_credential_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveCredentialRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let credential_id = {
        let csil_field = cbor_require(csil_root, "credential_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveCredentialRequest { credential_id })
}

/// Encode a RemoveCredentialRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_credential_request(
    csil_v: &RemoveCredentialRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_credential_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveCredentialRequest.
pub fn decode_remove_credential_request(
    csil_data: &[u8],
) -> Result<RemoveCredentialRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_credential_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveCredentialResponse.
fn csil_enc_remove_credential_response(
    csil_v: &RemoveCredentialResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveCredentialResponse from a decoded CBOR value tree.
fn csil_dec_remove_credential_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveCredentialResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveCredentialResponse { success })
}

/// Encode a RemoveCredentialResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_credential_response(
    csil_v: &RemoveCredentialResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_credential_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveCredentialResponse.
pub fn decode_remove_credential_response(
    csil_data: &[u8],
) -> Result<RemoveCredentialResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_credential_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimRequest.
fn csil_enc_set_claim_request(csil_v: &SetClaimRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    if let Some(csil_inner) = &csil_v.expires_at {
        csil_entries.push((cbor_text("expires_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    csil_entries.push((cbor_text("claim_value"), cbor_text(&csil_v.claim_value)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetClaimRequest from a decoded CBOR value tree.
fn csil_dec_set_claim_request(csil_root: &CsilCborValue) -> Result<SetClaimRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
            let csil_decode = csil_as_timestamp;
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
pub fn encode_set_claim_request(csil_v: &SetClaimRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_claim_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimRequest.
pub fn decode_set_claim_request(csil_data: &[u8]) -> Result<SetClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimResponse.
fn csil_enc_set_claim_response(csil_v: &SetClaimResponse) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim"), csil_enc_claim(&csil_v.claim)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetClaimResponse from a decoded CBOR value tree.
fn csil_dec_set_claim_response(
    csil_root: &CsilCborValue,
) -> Result<SetClaimResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim = {
        let csil_field = cbor_require(csil_root, "claim")?;
        let csil_decode = csil_dec_claim;
        csil_decode(csil_field)?
    };
    Ok(SetClaimResponse { claim })
}

/// Encode a SetClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_set_claim_response(csil_v: &SetClaimResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_claim_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimResponse.
pub fn decode_set_claim_response(csil_data: &[u8]) -> Result<SetClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimRequest.
fn csil_enc_remove_claim_request(
    csil_v: &RemoveClaimRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim_id"), cbor_text(&csil_v.claim_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveClaimRequest from a decoded CBOR value tree.
fn csil_dec_remove_claim_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_id = {
        let csil_field = cbor_require(csil_root, "claim_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimRequest { claim_id })
}

/// Encode a RemoveClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_request(csil_v: &RemoveClaimRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_claim_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimRequest.
pub fn decode_remove_claim_request(csil_data: &[u8]) -> Result<RemoveClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimResponse.
fn csil_enc_remove_claim_response(
    csil_v: &RemoveClaimResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveClaimResponse from a decoded CBOR value tree.
fn csil_dec_remove_claim_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimResponse { success })
}

/// Encode a RemoveClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_response(
    csil_v: &RemoveClaimResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_claim_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimResponse.
pub fn decode_remove_claim_response(
    csil_data: &[u8],
) -> Result<RemoveClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ListUserClaimsRequest.
fn csil_enc_list_user_claims_request(
    csil_v: &ListUserClaimsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListUserClaimsRequest from a decoded CBOR value tree.
fn csil_dec_list_user_claims_request(
    csil_root: &CsilCborValue,
) -> Result<ListUserClaimsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ListUserClaimsRequest { user_id })
}

/// Encode a ListUserClaimsRequest to canonical CSIL CBOR bytes.
pub fn encode_list_user_claims_request(
    csil_v: &ListUserClaimsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_user_claims_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListUserClaimsRequest.
pub fn decode_list_user_claims_request(
    csil_data: &[u8],
) -> Result<ListUserClaimsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_user_claims_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ListUserClaimsResponse.
fn csil_enc_list_user_claims_response(
    csil_v: &ListUserClaimsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("claim_types"),
        cbor_enc_array(&csil_v.claim_types, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListUserClaimsResponse from a decoded CBOR value tree.
fn csil_dec_list_user_claims_response(
    csil_root: &CsilCborValue,
) -> Result<ListUserClaimsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_types = {
        let csil_field = cbor_require(csil_root, "claim_types")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(ListUserClaimsResponse { claim_types })
}

/// Encode a ListUserClaimsResponse to canonical CSIL CBOR bytes.
pub fn encode_list_user_claims_response(
    csil_v: &ListUserClaimsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_user_claims_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListUserClaimsResponse.
pub fn decode_list_user_claims_response(
    csil_data: &[u8],
) -> Result<ListUserClaimsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_user_claims_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AdminUserClaimsRequest.
fn csil_enc_admin_user_claims_request(
    csil_v: &AdminUserClaimsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AdminUserClaimsRequest from a decoded CBOR value tree.
fn csil_dec_admin_user_claims_request(
    csil_root: &CsilCborValue,
) -> Result<AdminUserClaimsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(AdminUserClaimsRequest { user_id })
}

/// Encode a AdminUserClaimsRequest to canonical CSIL CBOR bytes.
pub fn encode_admin_user_claims_request(
    csil_v: &AdminUserClaimsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_admin_user_claims_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AdminUserClaimsRequest.
pub fn decode_admin_user_claims_request(
    csil_data: &[u8],
) -> Result<AdminUserClaimsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_admin_user_claims_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AdminUserClaimsResponse.
fn csil_enc_admin_user_claims_response(
    csil_v: &AdminUserClaimsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AdminUserClaimsResponse from a decoded CBOR value tree.
fn csil_dec_admin_user_claims_response(
    csil_root: &CsilCborValue,
) -> Result<AdminUserClaimsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claims = {
        let csil_field = cbor_require(csil_root, "claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim);
        csil_decode(csil_field)?
    };
    Ok(AdminUserClaimsResponse { claims })
}

/// Encode a AdminUserClaimsResponse to canonical CSIL CBOR bytes.
pub fn encode_admin_user_claims_response(
    csil_v: &AdminUserClaimsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_admin_user_claims_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AdminUserClaimsResponse.
pub fn decode_admin_user_claims_response(
    csil_data: &[u8],
) -> Result<AdminUserClaimsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_admin_user_claims_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetUserClaimRequest.
fn csil_enc_set_user_claim_request(
    csil_v: &SetUserClaimRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("claim_value"), cbor_text(&csil_v.claim_value)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetUserClaimRequest from a decoded CBOR value tree.
fn csil_dec_set_user_claim_request(
    csil_root: &CsilCborValue,
) -> Result<SetUserClaimRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_set_user_claim_request(
    csil_v: &SetUserClaimRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_user_claim_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetUserClaimRequest.
pub fn decode_set_user_claim_request(
    csil_data: &[u8],
) -> Result<SetUserClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_user_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetUserClaimResponse.
fn csil_enc_set_user_claim_response(
    csil_v: &SetUserClaimResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.claim {
        csil_entries.push((cbor_text("claim"), csil_enc_claim(csil_inner)?));
    }
    csil_entries.push((
        cbor_text("outcome"),
        csil_enc_set_claim_outcome(&csil_v.outcome)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetUserClaimResponse from a decoded CBOR value tree.
fn csil_dec_set_user_claim_response(
    csil_root: &CsilCborValue,
) -> Result<SetUserClaimResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let outcome = {
        let csil_field = cbor_require(csil_root, "outcome")?;
        let csil_decode = csil_dec_set_claim_outcome;
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
pub fn encode_set_user_claim_response(
    csil_v: &SetUserClaimResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_user_claim_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetUserClaimResponse.
pub fn decode_set_user_claim_response(
    csil_data: &[u8],
) -> Result<SetUserClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_user_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SettableClaimPolicy.
fn csil_enc_settable_claim_policy(
    csil_v: &SettableClaimPolicy,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("label"), cbor_text(&csil_v.label)));
    csil_entries.push((
        cbor_text("datatype"),
        csil_enc_claim_value_type(&csil_v.datatype)?,
    ));
    csil_entries.push((cbor_text("set_rule"), csil_enc_set_rule(&csil_v.set_rule)?));
    csil_entries.push((cbor_text("max_bytes"), cbor_int(csil_v.max_bytes)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("description"), cbor_text(&csil_v.description)));
    csil_entries.push((
        cbor_text("signing_rule"),
        csil_enc_signing_rule(&csil_v.signing_rule)?,
    ));
    csil_entries.push((
        cbor_text("requires_approval"),
        cbor_bool(csil_v.requires_approval),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SettableClaimPolicy from a decoded CBOR value tree.
fn csil_dec_settable_claim_policy(
    csil_root: &CsilCborValue,
) -> Result<SettableClaimPolicy, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let datatype = {
        let csil_field = cbor_require(csil_root, "datatype")?;
        let csil_decode = csil_dec_claim_value_type;
        csil_decode(csil_field)?
    };
    let max_bytes = {
        let csil_field = cbor_require(csil_root, "max_bytes")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let set_rule = {
        let csil_field = cbor_require(csil_root, "set_rule")?;
        let csil_decode = csil_dec_set_rule;
        csil_decode(csil_field)?
    };
    let requires_approval = {
        let csil_field = cbor_require(csil_root, "requires_approval")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let signing_rule = {
        let csil_field = cbor_require(csil_root, "signing_rule")?;
        let csil_decode = csil_dec_signing_rule;
        csil_decode(csil_field)?
    };
    Ok(SettableClaimPolicy {
        claim_type,
        label,
        description,
        datatype,
        max_bytes,
        set_rule,
        requires_approval,
        signing_rule,
    })
}

/// Encode a SettableClaimPolicy to canonical CSIL CBOR bytes.
pub fn encode_settable_claim_policy(
    csil_v: &SettableClaimPolicy,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_settable_claim_policy(csil_v)?;
    Ok(cbor_encode(&csil_tree))
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
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("policies"),
        cbor_enc_array(&csil_v.policies, csil_enc_settable_claim_policy)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListSettablePoliciesResponse from a decoded CBOR value tree.
fn csil_dec_list_settable_policies_response(
    csil_root: &CsilCborValue,
) -> Result<ListSettablePoliciesResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let policies = {
        let csil_field = cbor_require(csil_root, "policies")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_settable_claim_policy);
        csil_decode(csil_field)?
    };
    Ok(ListSettablePoliciesResponse { policies })
}

/// Encode a ListSettablePoliciesResponse to canonical CSIL CBOR bytes.
pub fn encode_list_settable_policies_response(
    csil_v: &ListSettablePoliciesResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_settable_policies_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListSettablePoliciesResponse.
pub fn decode_list_settable_policies_response(
    csil_data: &[u8],
) -> Result<ListSettablePoliciesResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_settable_policies_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimTypePolicy.
fn csil_enc_claim_type_policy(csil_v: &ClaimTypePolicy) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((cbor_text("label"), cbor_text(&csil_v.label)));
    csil_entries.push((cbor_text("set_rule"), csil_enc_set_rule(&csil_v.set_rule)?));
    csil_entries.push((cbor_text("max_bytes"), cbor_int(csil_v.max_bytes)));
    csil_entries.push((cbor_text("suggested"), cbor_bool(csil_v.suggested)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((
        cbor_text("value_type"),
        csil_enc_claim_value_type(&csil_v.value_type)?,
    ));
    csil_entries.push((cbor_text("description"), cbor_text(&csil_v.description)));
    csil_entries.push((
        cbor_text("signing_rule"),
        csil_enc_signing_rule(&csil_v.signing_rule)?,
    ));
    csil_entries.push((cbor_text("user_settable"), cbor_bool(csil_v.user_settable)));
    csil_entries.push((
        cbor_text("default_auto_sign"),
        cbor_bool(csil_v.default_auto_sign),
    ));
    csil_entries.push((
        cbor_text("requires_approval"),
        cbor_bool(csil_v.requires_approval),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ClaimTypePolicy from a decoded CBOR value tree.
fn csil_dec_claim_type_policy(csil_root: &CsilCborValue) -> Result<ClaimTypePolicy, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_dec_claim_value_type;
        csil_decode(csil_field)?
    };
    let max_bytes = {
        let csil_field = cbor_require(csil_root, "max_bytes")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let set_rule = {
        let csil_field = cbor_require(csil_root, "set_rule")?;
        let csil_decode = csil_dec_set_rule;
        csil_decode(csil_field)?
    };
    let signing_rule = {
        let csil_field = cbor_require(csil_root, "signing_rule")?;
        let csil_decode = csil_dec_signing_rule;
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
pub fn encode_claim_type_policy(csil_v: &ClaimTypePolicy) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim_type_policy(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ClaimTypePolicy.
pub fn decode_claim_type_policy(csil_data: &[u8]) -> Result<ClaimTypePolicy, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_type_policy(&csil_root)
}

/// Build the canonical CBOR value tree for a ListClaimTypesResponse.
fn csil_enc_list_claim_types_response(
    csil_v: &ListClaimTypesResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("claim_types"),
        cbor_enc_array(&csil_v.claim_types, csil_enc_claim_type_policy)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListClaimTypesResponse from a decoded CBOR value tree.
fn csil_dec_list_claim_types_response(
    csil_root: &CsilCborValue,
) -> Result<ListClaimTypesResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_types = {
        let csil_field = cbor_require(csil_root, "claim_types")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_type_policy);
        csil_decode(csil_field)?
    };
    Ok(ListClaimTypesResponse { claim_types })
}

/// Encode a ListClaimTypesResponse to canonical CSIL CBOR bytes.
pub fn encode_list_claim_types_response(
    csil_v: &ListClaimTypesResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_claim_types_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListClaimTypesResponse.
pub fn decode_list_claim_types_response(
    csil_data: &[u8],
) -> Result<ListClaimTypesResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_claim_types_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimTypeRequest.
fn csil_enc_set_claim_type_request(
    csil_v: &SetClaimTypeRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((cbor_text("label"), cbor_text(&csil_v.label)));
    csil_entries.push((cbor_text("set_rule"), csil_enc_set_rule(&csil_v.set_rule)?));
    csil_entries.push((cbor_text("max_bytes"), cbor_int(csil_v.max_bytes)));
    csil_entries.push((cbor_text("suggested"), cbor_bool(csil_v.suggested)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((
        cbor_text("value_type"),
        csil_enc_claim_value_type(&csil_v.value_type)?,
    ));
    if let Some(csil_inner) = &csil_v.description {
        csil_entries.push((cbor_text("description"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("signing_rule"),
        csil_enc_signing_rule(&csil_v.signing_rule)?,
    ));
    csil_entries.push((cbor_text("user_settable"), cbor_bool(csil_v.user_settable)));
    csil_entries.push((
        cbor_text("default_auto_sign"),
        cbor_bool(csil_v.default_auto_sign),
    ));
    csil_entries.push((
        cbor_text("requires_approval"),
        cbor_bool(csil_v.requires_approval),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetClaimTypeRequest from a decoded CBOR value tree.
fn csil_dec_set_claim_type_request(
    csil_root: &CsilCborValue,
) -> Result<SetClaimTypeRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_dec_claim_value_type;
        csil_decode(csil_field)?
    };
    let max_bytes = {
        let csil_field = cbor_require(csil_root, "max_bytes")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let set_rule = {
        let csil_field = cbor_require(csil_root, "set_rule")?;
        let csil_decode = csil_dec_set_rule;
        csil_decode(csil_field)?
    };
    let signing_rule = {
        let csil_field = cbor_require(csil_root, "signing_rule")?;
        let csil_decode = csil_dec_signing_rule;
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
pub fn encode_set_claim_type_request(
    csil_v: &SetClaimTypeRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_claim_type_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimTypeRequest.
pub fn decode_set_claim_type_request(
    csil_data: &[u8],
) -> Result<SetClaimTypeRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_type_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimTypeResponse.
fn csil_enc_set_claim_type_response(
    csil_v: &SetClaimTypeResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("claim_type"),
        csil_enc_claim_type_policy(&csil_v.claim_type)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetClaimTypeResponse from a decoded CBOR value tree.
fn csil_dec_set_claim_type_response(
    csil_root: &CsilCborValue,
) -> Result<SetClaimTypeResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = csil_dec_claim_type_policy;
        csil_decode(csil_field)?
    };
    Ok(SetClaimTypeResponse { claim_type })
}

/// Encode a SetClaimTypeResponse to canonical CSIL CBOR bytes.
pub fn encode_set_claim_type_response(
    csil_v: &SetClaimTypeResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_claim_type_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimTypeResponse.
pub fn decode_set_claim_type_response(
    csil_data: &[u8],
) -> Result<SetClaimTypeResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_type_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimTypeRequest.
fn csil_enc_remove_claim_type_request(
    csil_v: &RemoveClaimTypeRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveClaimTypeRequest from a decoded CBOR value tree.
fn csil_dec_remove_claim_type_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimTypeRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimTypeRequest { claim_type })
}

/// Encode a RemoveClaimTypeRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_type_request(
    csil_v: &RemoveClaimTypeRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_claim_type_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimTypeRequest.
pub fn decode_remove_claim_type_request(
    csil_data: &[u8],
) -> Result<RemoveClaimTypeRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_type_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimTypeResponse.
fn csil_enc_remove_claim_type_response(
    csil_v: &RemoveClaimTypeResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveClaimTypeResponse from a decoded CBOR value tree.
fn csil_dec_remove_claim_type_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimTypeResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimTypeResponse { success })
}

/// Encode a RemoveClaimTypeResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_type_response(
    csil_v: &RemoveClaimTypeResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_claim_type_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimTypeResponse.
pub fn decode_remove_claim_type_response(
    csil_data: &[u8],
) -> Result<RemoveClaimTypeResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_type_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimTypeLabel.
fn csil_enc_claim_type_label(csil_v: &ClaimTypeLabel) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("label"), cbor_text(&csil_v.label)));
    csil_entries.push((cbor_text("locale"), cbor_text(&csil_v.locale)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    if let Some(csil_inner) = &csil_v.description {
        csil_entries.push((cbor_text("description"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ClaimTypeLabel from a decoded CBOR value tree.
fn csil_dec_claim_type_label(csil_root: &CsilCborValue) -> Result<ClaimTypeLabel, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_claim_type_label(csil_v: &ClaimTypeLabel) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim_type_label(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ClaimTypeLabel.
pub fn decode_claim_type_label(csil_data: &[u8]) -> Result<ClaimTypeLabel, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_type_label(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimTypeLabelRequest.
fn csil_enc_set_claim_type_label_request(
    csil_v: &SetClaimTypeLabelRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("label"), cbor_text(&csil_v.label)));
    csil_entries.push((cbor_text("locale"), cbor_text(&csil_v.locale)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    if let Some(csil_inner) = &csil_v.description {
        csil_entries.push((cbor_text("description"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetClaimTypeLabelRequest from a decoded CBOR value tree.
fn csil_dec_set_claim_type_label_request(
    csil_root: &CsilCborValue,
) -> Result<SetClaimTypeLabelRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_set_claim_type_label_request(
    csil_v: &SetClaimTypeLabelRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_claim_type_label_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimTypeLabelRequest.
pub fn decode_set_claim_type_label_request(
    csil_data: &[u8],
) -> Result<SetClaimTypeLabelRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_type_label_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetClaimTypeLabelResponse.
fn csil_enc_set_claim_type_label_response(
    csil_v: &SetClaimTypeLabelResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("label"),
        csil_enc_claim_type_label(&csil_v.label)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetClaimTypeLabelResponse from a decoded CBOR value tree.
fn csil_dec_set_claim_type_label_response(
    csil_root: &CsilCborValue,
) -> Result<SetClaimTypeLabelResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let label = {
        let csil_field = cbor_require(csil_root, "label")?;
        let csil_decode = csil_dec_claim_type_label;
        csil_decode(csil_field)?
    };
    Ok(SetClaimTypeLabelResponse { label })
}

/// Encode a SetClaimTypeLabelResponse to canonical CSIL CBOR bytes.
pub fn encode_set_claim_type_label_response(
    csil_v: &SetClaimTypeLabelResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_claim_type_label_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimTypeLabelResponse.
pub fn decode_set_claim_type_label_response(
    csil_data: &[u8],
) -> Result<SetClaimTypeLabelResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_type_label_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ListClaimTypeLabelsResponse.
fn csil_enc_list_claim_type_labels_response(
    csil_v: &ListClaimTypeLabelsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("labels"),
        cbor_enc_array(&csil_v.labels, csil_enc_claim_type_label)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListClaimTypeLabelsResponse from a decoded CBOR value tree.
fn csil_dec_list_claim_type_labels_response(
    csil_root: &CsilCborValue,
) -> Result<ListClaimTypeLabelsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let labels = {
        let csil_field = cbor_require(csil_root, "labels")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_type_label);
        csil_decode(csil_field)?
    };
    Ok(ListClaimTypeLabelsResponse { labels })
}

/// Encode a ListClaimTypeLabelsResponse to canonical CSIL CBOR bytes.
pub fn encode_list_claim_type_labels_response(
    csil_v: &ListClaimTypeLabelsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_claim_type_labels_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListClaimTypeLabelsResponse.
pub fn decode_list_claim_type_labels_response(
    csil_data: &[u8],
) -> Result<ListClaimTypeLabelsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_claim_type_labels_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveClaimTypeLabelRequest.
fn csil_enc_remove_claim_type_label_request(
    csil_v: &RemoveClaimTypeLabelRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("locale"), cbor_text(&csil_v.locale)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveClaimTypeLabelRequest from a decoded CBOR value tree.
fn csil_dec_remove_claim_type_label_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimTypeLabelRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_remove_claim_type_label_request(
    csil_v: &RemoveClaimTypeLabelRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_claim_type_label_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
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
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveClaimTypeLabelResponse from a decoded CBOR value tree.
fn csil_dec_remove_claim_type_label_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveClaimTypeLabelResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveClaimTypeLabelResponse { success })
}

/// Encode a RemoveClaimTypeLabelResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_claim_type_label_response(
    csil_v: &RemoveClaimTypeLabelResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_claim_type_label_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveClaimTypeLabelResponse.
pub fn decode_remove_claim_type_label_response(
    csil_data: &[u8],
) -> Result<RemoveClaimTypeLabelResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_claim_type_label_response(&csil_root)
}

/// Build the canonical CBOR value tree for a TrustedIssuer.
fn csil_enc_trusted_issuer(csil_v: &TrustedIssuer) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("issuer_domain"), cbor_text(&csil_v.issuer_domain)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a TrustedIssuer from a decoded CBOR value tree.
fn csil_dec_trusted_issuer(csil_root: &CsilCborValue) -> Result<TrustedIssuer, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_trusted_issuer(csil_v: &TrustedIssuer) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_trusted_issuer(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a TrustedIssuer.
pub fn decode_trusted_issuer(csil_data: &[u8]) -> Result<TrustedIssuer, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_trusted_issuer(&csil_root)
}

/// Build the canonical CBOR value tree for a ListTrustedIssuersResponse.
fn csil_enc_list_trusted_issuers_response(
    csil_v: &ListTrustedIssuersResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("trusted_issuers"),
        cbor_enc_array(&csil_v.trusted_issuers, csil_enc_trusted_issuer)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListTrustedIssuersResponse from a decoded CBOR value tree.
fn csil_dec_list_trusted_issuers_response(
    csil_root: &CsilCborValue,
) -> Result<ListTrustedIssuersResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let trusted_issuers = {
        let csil_field = cbor_require(csil_root, "trusted_issuers")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_trusted_issuer);
        csil_decode(csil_field)?
    };
    Ok(ListTrustedIssuersResponse { trusted_issuers })
}

/// Encode a ListTrustedIssuersResponse to canonical CSIL CBOR bytes.
pub fn encode_list_trusted_issuers_response(
    csil_v: &ListTrustedIssuersResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_trusted_issuers_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListTrustedIssuersResponse.
pub fn decode_list_trusted_issuers_response(
    csil_data: &[u8],
) -> Result<ListTrustedIssuersResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_trusted_issuers_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AddTrustedIssuerRequest.
fn csil_enc_add_trusted_issuer_request(
    csil_v: &AddTrustedIssuerRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("issuer_domain"), cbor_text(&csil_v.issuer_domain)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AddTrustedIssuerRequest from a decoded CBOR value tree.
fn csil_dec_add_trusted_issuer_request(
    csil_root: &CsilCborValue,
) -> Result<AddTrustedIssuerRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_add_trusted_issuer_request(
    csil_v: &AddTrustedIssuerRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_add_trusted_issuer_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AddTrustedIssuerRequest.
pub fn decode_add_trusted_issuer_request(
    csil_data: &[u8],
) -> Result<AddTrustedIssuerRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_add_trusted_issuer_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AddTrustedIssuerResponse.
fn csil_enc_add_trusted_issuer_response(
    csil_v: &AddTrustedIssuerResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("trusted_issuer"),
        csil_enc_trusted_issuer(&csil_v.trusted_issuer)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AddTrustedIssuerResponse from a decoded CBOR value tree.
fn csil_dec_add_trusted_issuer_response(
    csil_root: &CsilCborValue,
) -> Result<AddTrustedIssuerResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let trusted_issuer = {
        let csil_field = cbor_require(csil_root, "trusted_issuer")?;
        let csil_decode = csil_dec_trusted_issuer;
        csil_decode(csil_field)?
    };
    Ok(AddTrustedIssuerResponse { trusted_issuer })
}

/// Encode a AddTrustedIssuerResponse to canonical CSIL CBOR bytes.
pub fn encode_add_trusted_issuer_response(
    csil_v: &AddTrustedIssuerResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_add_trusted_issuer_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AddTrustedIssuerResponse.
pub fn decode_add_trusted_issuer_response(
    csil_data: &[u8],
) -> Result<AddTrustedIssuerResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_add_trusted_issuer_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveTrustedIssuerRequest.
fn csil_enc_remove_trusted_issuer_request(
    csil_v: &RemoveTrustedIssuerRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("issuer_domain"), cbor_text(&csil_v.issuer_domain)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveTrustedIssuerRequest from a decoded CBOR value tree.
fn csil_dec_remove_trusted_issuer_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveTrustedIssuerRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_remove_trusted_issuer_request(
    csil_v: &RemoveTrustedIssuerRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_trusted_issuer_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveTrustedIssuerRequest.
pub fn decode_remove_trusted_issuer_request(
    csil_data: &[u8],
) -> Result<RemoveTrustedIssuerRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_trusted_issuer_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveTrustedIssuerResponse.
fn csil_enc_remove_trusted_issuer_response(
    csil_v: &RemoveTrustedIssuerResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveTrustedIssuerResponse from a decoded CBOR value tree.
fn csil_dec_remove_trusted_issuer_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveTrustedIssuerResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveTrustedIssuerResponse { success })
}

/// Encode a RemoveTrustedIssuerResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_trusted_issuer_response(
    csil_v: &RemoveTrustedIssuerResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_trusted_issuer_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveTrustedIssuerResponse.
pub fn decode_remove_trusted_issuer_response(
    csil_data: &[u8],
) -> Result<RemoveTrustedIssuerResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_trusted_issuer_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ReleaseRule.
fn csil_enc_release_rule(csil_v: &ReleaseRule) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((
        cbor_text("disposition"),
        csil_enc_release_disposition(&csil_v.disposition)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ReleaseRule from a decoded CBOR value tree.
fn csil_dec_release_rule(csil_root: &CsilCborValue) -> Result<ReleaseRule, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_dec_release_disposition;
        csil_decode(csil_field)?
    };
    Ok(ReleaseRule {
        audience,
        claim_type,
        disposition,
    })
}

/// Encode a ReleaseRule to canonical CSIL CBOR bytes.
pub fn encode_release_rule(csil_v: &ReleaseRule) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_release_rule(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ReleaseRule.
pub fn decode_release_rule(csil_data: &[u8]) -> Result<ReleaseRule, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_release_rule(&csil_root)
}

/// Build the canonical CBOR value tree for a ListReleaseRulesResponse.
fn csil_enc_list_release_rules_response(
    csil_v: &ListReleaseRulesResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("release_rules"),
        cbor_enc_array(&csil_v.release_rules, csil_enc_release_rule)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListReleaseRulesResponse from a decoded CBOR value tree.
fn csil_dec_list_release_rules_response(
    csil_root: &CsilCborValue,
) -> Result<ListReleaseRulesResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let release_rules = {
        let csil_field = cbor_require(csil_root, "release_rules")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_release_rule);
        csil_decode(csil_field)?
    };
    Ok(ListReleaseRulesResponse { release_rules })
}

/// Encode a ListReleaseRulesResponse to canonical CSIL CBOR bytes.
pub fn encode_list_release_rules_response(
    csil_v: &ListReleaseRulesResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_release_rules_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListReleaseRulesResponse.
pub fn decode_list_release_rules_response(
    csil_data: &[u8],
) -> Result<ListReleaseRulesResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_release_rules_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetReleaseRuleRequest.
fn csil_enc_set_release_rule_request(
    csil_v: &SetReleaseRuleRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((
        cbor_text("disposition"),
        csil_enc_release_disposition(&csil_v.disposition)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetReleaseRuleRequest from a decoded CBOR value tree.
fn csil_dec_set_release_rule_request(
    csil_root: &CsilCborValue,
) -> Result<SetReleaseRuleRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_dec_release_disposition;
        csil_decode(csil_field)?
    };
    Ok(SetReleaseRuleRequest {
        audience,
        claim_type,
        disposition,
    })
}

/// Encode a SetReleaseRuleRequest to canonical CSIL CBOR bytes.
pub fn encode_set_release_rule_request(
    csil_v: &SetReleaseRuleRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_release_rule_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetReleaseRuleRequest.
pub fn decode_set_release_rule_request(
    csil_data: &[u8],
) -> Result<SetReleaseRuleRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_release_rule_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetReleaseRuleResponse.
fn csil_enc_set_release_rule_response(
    csil_v: &SetReleaseRuleResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("release_rule"),
        csil_enc_release_rule(&csil_v.release_rule)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetReleaseRuleResponse from a decoded CBOR value tree.
fn csil_dec_set_release_rule_response(
    csil_root: &CsilCborValue,
) -> Result<SetReleaseRuleResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let release_rule = {
        let csil_field = cbor_require(csil_root, "release_rule")?;
        let csil_decode = csil_dec_release_rule;
        csil_decode(csil_field)?
    };
    Ok(SetReleaseRuleResponse { release_rule })
}

/// Encode a SetReleaseRuleResponse to canonical CSIL CBOR bytes.
pub fn encode_set_release_rule_response(
    csil_v: &SetReleaseRuleResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_release_rule_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetReleaseRuleResponse.
pub fn decode_set_release_rule_response(
    csil_data: &[u8],
) -> Result<SetReleaseRuleResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_release_rule_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveReleaseRuleRequest.
fn csil_enc_remove_release_rule_request(
    csil_v: &RemoveReleaseRuleRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveReleaseRuleRequest from a decoded CBOR value tree.
fn csil_dec_remove_release_rule_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveReleaseRuleRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_remove_release_rule_request(
    csil_v: &RemoveReleaseRuleRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_release_rule_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveReleaseRuleRequest.
pub fn decode_remove_release_rule_request(
    csil_data: &[u8],
) -> Result<RemoveReleaseRuleRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_release_rule_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveReleaseRuleResponse.
fn csil_enc_remove_release_rule_response(
    csil_v: &RemoveReleaseRuleResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveReleaseRuleResponse from a decoded CBOR value tree.
fn csil_dec_remove_release_rule_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveReleaseRuleResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveReleaseRuleResponse { success })
}

/// Encode a RemoveReleaseRuleResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_release_rule_response(
    csil_v: &RemoveReleaseRuleResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_release_rule_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveReleaseRuleResponse.
pub fn decode_remove_release_rule_response(
    csil_data: &[u8],
) -> Result<RemoveReleaseRuleResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_release_rule_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimApproval.
fn csil_enc_claim_approval(csil_v: &ClaimApproval) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((
        cbor_text("status"),
        csil_enc_claim_approval_status(&csil_v.status)?,
    ));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((
        cbor_text("created_at"),
        csil_rt_enc_timestamp(&csil_v.created_at)?,
    ));
    csil_entries.push((cbor_text("claim_value"), cbor_bytes(&csil_v.claim_value)));
    if let Some(csil_inner) = &csil_v.resolved_at {
        csil_entries.push((cbor_text("resolved_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    if let Some(csil_inner) = &csil_v.resolved_by {
        csil_entries.push((cbor_text("resolved_by"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ClaimApproval from a decoded CBOR value tree.
fn csil_dec_claim_approval(csil_root: &CsilCborValue) -> Result<ClaimApproval, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_dec_claim_approval_status;
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
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = csil_as_timestamp;
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
pub fn encode_claim_approval(csil_v: &ClaimApproval) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim_approval(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ClaimApproval.
pub fn decode_claim_approval(csil_data: &[u8]) -> Result<ClaimApproval, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_approval(&csil_root)
}

/// Build the canonical CBOR value tree for a ListPendingClaimApprovalsResponse.
fn csil_enc_list_pending_claim_approvals_response(
    csil_v: &ListPendingClaimApprovalsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("approvals"),
        cbor_enc_array(&csil_v.approvals, csil_enc_claim_approval)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListPendingClaimApprovalsResponse from a decoded CBOR value tree.
fn csil_dec_list_pending_claim_approvals_response(
    csil_root: &CsilCborValue,
) -> Result<ListPendingClaimApprovalsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_pending_claim_approvals_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListPendingClaimApprovalsResponse.
pub fn decode_list_pending_claim_approvals_response(
    csil_data: &[u8],
) -> Result<ListPendingClaimApprovalsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_pending_claim_approvals_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ApproveClaimRequest.
fn csil_enc_approve_claim_request(
    csil_v: &ApproveClaimRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("approval_id"), cbor_text(&csil_v.approval_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApproveClaimRequest from a decoded CBOR value tree.
fn csil_dec_approve_claim_request(
    csil_root: &CsilCborValue,
) -> Result<ApproveClaimRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let approval_id = {
        let csil_field = cbor_require(csil_root, "approval_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ApproveClaimRequest { approval_id })
}

/// Encode a ApproveClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_approve_claim_request(
    csil_v: &ApproveClaimRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_approve_claim_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApproveClaimRequest.
pub fn decode_approve_claim_request(
    csil_data: &[u8],
) -> Result<ApproveClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_approve_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ApproveClaimResponse.
fn csil_enc_approve_claim_response(
    csil_v: &ApproveClaimResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApproveClaimResponse from a decoded CBOR value tree.
fn csil_dec_approve_claim_response(
    csil_root: &CsilCborValue,
) -> Result<ApproveClaimResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(ApproveClaimResponse { success })
}

/// Encode a ApproveClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_approve_claim_response(
    csil_v: &ApproveClaimResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_approve_claim_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApproveClaimResponse.
pub fn decode_approve_claim_response(
    csil_data: &[u8],
) -> Result<ApproveClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_approve_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RejectClaimRequest.
fn csil_enc_reject_claim_request(
    csil_v: &RejectClaimRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("approval_id"), cbor_text(&csil_v.approval_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RejectClaimRequest from a decoded CBOR value tree.
fn csil_dec_reject_claim_request(
    csil_root: &CsilCborValue,
) -> Result<RejectClaimRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let approval_id = {
        let csil_field = cbor_require(csil_root, "approval_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RejectClaimRequest { approval_id })
}

/// Encode a RejectClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_reject_claim_request(csil_v: &RejectClaimRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_reject_claim_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RejectClaimRequest.
pub fn decode_reject_claim_request(csil_data: &[u8]) -> Result<RejectClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_reject_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RejectClaimResponse.
fn csil_enc_reject_claim_response(
    csil_v: &RejectClaimResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RejectClaimResponse from a decoded CBOR value tree.
fn csil_dec_reject_claim_response(
    csil_root: &CsilCborValue,
) -> Result<RejectClaimResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RejectClaimResponse { success })
}

/// Encode a RejectClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_reject_claim_response(
    csil_v: &RejectClaimResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_reject_claim_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
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
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("claim_value"), cbor_bytes(&csil_v.claim_value)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AdminIssueAttestationRequest from a decoded CBOR value tree.
fn csil_dec_admin_issue_attestation_request(
    csil_root: &CsilCborValue,
) -> Result<AdminIssueAttestationRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_admin_issue_attestation_request(
    csil_v: &AdminIssueAttestationRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_admin_issue_attestation_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
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
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim"), csil_enc_claim(&csil_v.claim)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AdminIssueAttestationResponse from a decoded CBOR value tree.
fn csil_dec_admin_issue_attestation_response(
    csil_root: &CsilCborValue,
) -> Result<AdminIssueAttestationResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim = {
        let csil_field = cbor_require(csil_root, "claim")?;
        let csil_decode = csil_dec_claim;
        csil_decode(csil_field)?
    };
    Ok(AdminIssueAttestationResponse { claim })
}

/// Encode a AdminIssueAttestationResponse to canonical CSIL CBOR bytes.
pub fn encode_admin_issue_attestation_response(
    csil_v: &AdminIssueAttestationResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_admin_issue_attestation_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AdminIssueAttestationResponse.
pub fn decode_admin_issue_attestation_response(
    csil_data: &[u8],
) -> Result<AdminIssueAttestationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_admin_issue_attestation_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GrantRelationRequest.
fn csil_enc_grant_relation_request(
    csil_v: &GrantRelationRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("relation"), cbor_text(&csil_v.relation)));
    csil_entries.push((cbor_text("object_id"), cbor_text(&csil_v.object_id)));
    csil_entries.push((cbor_text("subject_id"), cbor_text(&csil_v.subject_id)));
    csil_entries.push((cbor_text("object_type"), cbor_text(&csil_v.object_type)));
    csil_entries.push((cbor_text("subject_type"), cbor_text(&csil_v.subject_type)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GrantRelationRequest from a decoded CBOR value tree.
fn csil_dec_grant_relation_request(
    csil_root: &CsilCborValue,
) -> Result<GrantRelationRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_grant_relation_request(
    csil_v: &GrantRelationRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_grant_relation_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GrantRelationRequest.
pub fn decode_grant_relation_request(
    csil_data: &[u8],
) -> Result<GrantRelationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_grant_relation_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GrantRelationResponse.
fn csil_enc_grant_relation_response(
    csil_v: &GrantRelationResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("relation"), csil_enc_relation(&csil_v.relation)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GrantRelationResponse from a decoded CBOR value tree.
fn csil_dec_grant_relation_response(
    csil_root: &CsilCborValue,
) -> Result<GrantRelationResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let relation = {
        let csil_field = cbor_require(csil_root, "relation")?;
        let csil_decode = csil_dec_relation;
        csil_decode(csil_field)?
    };
    Ok(GrantRelationResponse { relation })
}

/// Encode a GrantRelationResponse to canonical CSIL CBOR bytes.
pub fn encode_grant_relation_response(
    csil_v: &GrantRelationResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_grant_relation_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GrantRelationResponse.
pub fn decode_grant_relation_response(
    csil_data: &[u8],
) -> Result<GrantRelationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_grant_relation_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveRelationRequest.
fn csil_enc_remove_relation_request(
    csil_v: &RemoveRelationRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("relation_id"), cbor_text(&csil_v.relation_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveRelationRequest from a decoded CBOR value tree.
fn csil_dec_remove_relation_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveRelationRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let relation_id = {
        let csil_field = cbor_require(csil_root, "relation_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveRelationRequest { relation_id })
}

/// Encode a RemoveRelationRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_relation_request(
    csil_v: &RemoveRelationRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_relation_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveRelationRequest.
pub fn decode_remove_relation_request(
    csil_data: &[u8],
) -> Result<RemoveRelationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_relation_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveRelationResponse.
fn csil_enc_remove_relation_response(
    csil_v: &RemoveRelationResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveRelationResponse from a decoded CBOR value tree.
fn csil_dec_remove_relation_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveRelationResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveRelationResponse { success })
}

/// Encode a RemoveRelationResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_relation_response(
    csil_v: &RemoveRelationResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_relation_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveRelationResponse.
pub fn decode_remove_relation_response(
    csil_data: &[u8],
) -> Result<RemoveRelationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_relation_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ListRelationsRequest.
fn csil_enc_list_relations_request(
    csil_v: &ListRelationsRequest,
) -> Result<CsilCborValue, CsilCborError> {
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
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListRelationsRequest from a decoded CBOR value tree.
fn csil_dec_list_relations_request(
    csil_root: &CsilCborValue,
) -> Result<ListRelationsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_list_relations_request(
    csil_v: &ListRelationsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_relations_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListRelationsRequest.
pub fn decode_list_relations_request(
    csil_data: &[u8],
) -> Result<ListRelationsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_relations_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ListRelationsResponse.
fn csil_enc_list_relations_response(
    csil_v: &ListRelationsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("relations"),
        cbor_enc_array(&csil_v.relations, csil_enc_relation)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListRelationsResponse from a decoded CBOR value tree.
fn csil_dec_list_relations_response(
    csil_root: &CsilCborValue,
) -> Result<ListRelationsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let relations = {
        let csil_field = cbor_require(csil_root, "relations")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_relation);
        csil_decode(csil_field)?
    };
    Ok(ListRelationsResponse { relations })
}

/// Encode a ListRelationsResponse to canonical CSIL CBOR bytes.
pub fn encode_list_relations_response(
    csil_v: &ListRelationsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_relations_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListRelationsResponse.
pub fn decode_list_relations_response(
    csil_data: &[u8],
) -> Result<ListRelationsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_relations_response(&csil_root)
}

/// Build the canonical CBOR value tree for a CheckPermissionRequest.
fn csil_enc_check_permission_request(
    csil_v: &CheckPermissionRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("relation"), cbor_text(&csil_v.relation)));
    csil_entries.push((cbor_text("object_id"), cbor_text(&csil_v.object_id)));
    csil_entries.push((cbor_text("object_type"), cbor_text(&csil_v.object_type)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CheckPermissionRequest from a decoded CBOR value tree.
fn csil_dec_check_permission_request(
    csil_root: &CsilCborValue,
) -> Result<CheckPermissionRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_check_permission_request(
    csil_v: &CheckPermissionRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_check_permission_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CheckPermissionRequest.
pub fn decode_check_permission_request(
    csil_data: &[u8],
) -> Result<CheckPermissionRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_check_permission_request(&csil_root)
}

/// Build the canonical CBOR value tree for a CheckPermissionResponse.
fn csil_enc_check_permission_response(
    csil_v: &CheckPermissionResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("allowed"), cbor_bool(csil_v.allowed)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CheckPermissionResponse from a decoded CBOR value tree.
fn csil_dec_check_permission_response(
    csil_root: &CsilCborValue,
) -> Result<CheckPermissionResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let allowed = {
        let csil_field = cbor_require(csil_root, "allowed")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(CheckPermissionResponse { allowed })
}

/// Encode a CheckPermissionResponse to canonical CSIL CBOR bytes.
pub fn encode_check_permission_response(
    csil_v: &CheckPermissionResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_check_permission_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CheckPermissionResponse.
pub fn decode_check_permission_response(
    csil_data: &[u8],
) -> Result<CheckPermissionResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_check_permission_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ChangePasswordRequest.
fn csil_enc_change_password_request(
    csil_v: &ChangePasswordRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("new_password"), cbor_text(&csil_v.new_password)));
    csil_entries.push((
        cbor_text("current_password"),
        cbor_text(&csil_v.current_password),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ChangePasswordRequest from a decoded CBOR value tree.
fn csil_dec_change_password_request(
    csil_root: &CsilCborValue,
) -> Result<ChangePasswordRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let current_password = {
        let csil_field = cbor_require(csil_root, "current_password")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let new_password = {
        let csil_field = cbor_require(csil_root, "new_password")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ChangePasswordRequest {
        current_password,
        new_password,
    })
}

/// Encode a ChangePasswordRequest to canonical CSIL CBOR bytes.
pub fn encode_change_password_request(
    csil_v: &ChangePasswordRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_change_password_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ChangePasswordRequest.
pub fn decode_change_password_request(
    csil_data: &[u8],
) -> Result<ChangePasswordRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_change_password_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ChangePasswordResponse.
fn csil_enc_change_password_response(
    csil_v: &ChangePasswordResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ChangePasswordResponse from a decoded CBOR value tree.
fn csil_dec_change_password_response(
    csil_root: &CsilCborValue,
) -> Result<ChangePasswordResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(ChangePasswordResponse { success })
}

/// Encode a ChangePasswordResponse to canonical CSIL CBOR bytes.
pub fn encode_change_password_response(
    csil_v: &ChangePasswordResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_change_password_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ChangePasswordResponse.
pub fn decode_change_password_response(
    csil_data: &[u8],
) -> Result<ChangePasswordResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_change_password_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetMyInfoResponse.
fn csil_enc_get_my_info_response(
    csil_v: &GetMyInfoResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim)?,
    ));
    csil_entries.push((
        cbor_text("relations"),
        cbor_enc_array(&csil_v.relations, csil_enc_relation)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetMyInfoResponse from a decoded CBOR value tree.
fn csil_dec_get_my_info_response(
    csil_root: &CsilCborValue,
) -> Result<GetMyInfoResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_get_my_info_response(csil_v: &GetMyInfoResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_my_info_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetMyInfoResponse.
pub fn decode_get_my_info_response(csil_data: &[u8]) -> Result<GetMyInfoResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_my_info_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetMyClaimRequest.
fn csil_enc_set_my_claim_request(
    csil_v: &SetMyClaimRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("claim_value"), cbor_text(&csil_v.claim_value)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetMyClaimRequest from a decoded CBOR value tree.
fn csil_dec_set_my_claim_request(
    csil_root: &CsilCborValue,
) -> Result<SetMyClaimRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_set_my_claim_request(csil_v: &SetMyClaimRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_my_claim_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetMyClaimRequest.
pub fn decode_set_my_claim_request(csil_data: &[u8]) -> Result<SetMyClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_my_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetMyClaimResponse.
fn csil_enc_set_my_claim_response(
    csil_v: &SetMyClaimResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.claim {
        csil_entries.push((cbor_text("claim"), csil_enc_claim(csil_inner)?));
    }
    csil_entries.push((
        cbor_text("outcome"),
        csil_enc_set_claim_outcome(&csil_v.outcome)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetMyClaimResponse from a decoded CBOR value tree.
fn csil_dec_set_my_claim_response(
    csil_root: &CsilCborValue,
) -> Result<SetMyClaimResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let outcome = {
        let csil_field = cbor_require(csil_root, "outcome")?;
        let csil_decode = csil_dec_set_claim_outcome;
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
pub fn encode_set_my_claim_response(csil_v: &SetMyClaimResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_my_claim_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetMyClaimResponse.
pub fn decode_set_my_claim_response(csil_data: &[u8]) -> Result<SetMyClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_my_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveMyClaimRequest.
fn csil_enc_remove_my_claim_request(
    csil_v: &RemoveMyClaimRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("claim_id"), cbor_text(&csil_v.claim_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveMyClaimRequest from a decoded CBOR value tree.
fn csil_dec_remove_my_claim_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveMyClaimRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_id = {
        let csil_field = cbor_require(csil_root, "claim_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveMyClaimRequest { claim_id })
}

/// Encode a RemoveMyClaimRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_my_claim_request(
    csil_v: &RemoveMyClaimRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_my_claim_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveMyClaimRequest.
pub fn decode_remove_my_claim_request(
    csil_data: &[u8],
) -> Result<RemoveMyClaimRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_my_claim_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveMyClaimResponse.
fn csil_enc_remove_my_claim_response(
    csil_v: &RemoveMyClaimResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveMyClaimResponse from a decoded CBOR value tree.
fn csil_dec_remove_my_claim_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveMyClaimResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveMyClaimResponse { success })
}

/// Encode a RemoveMyClaimResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_my_claim_response(
    csil_v: &RemoveMyClaimResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_my_claim_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveMyClaimResponse.
pub fn decode_remove_my_claim_response(
    csil_data: &[u8],
) -> Result<RemoveMyClaimResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_my_claim_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetMyClaimSharingRequest.
fn csil_enc_set_my_claim_sharing_request(
    csil_v: &SetMyClaimSharingRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("share"), cbor_bool(csil_v.share)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetMyClaimSharingRequest from a decoded CBOR value tree.
fn csil_dec_set_my_claim_sharing_request(
    csil_root: &CsilCborValue,
) -> Result<SetMyClaimSharingRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_set_my_claim_sharing_request(
    csil_v: &SetMyClaimSharingRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_my_claim_sharing_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetMyClaimSharingRequest.
pub fn decode_set_my_claim_sharing_request(
    csil_data: &[u8],
) -> Result<SetMyClaimSharingRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_my_claim_sharing_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetMyClaimSharingResponse.
fn csil_enc_set_my_claim_sharing_response(
    _csil_v: &SetMyClaimSharingResponse,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(CsilCborValue::Map(Vec::new()))
}

/// Reconstruct a SetMyClaimSharingResponse from a decoded CBOR value tree.
fn csil_dec_set_my_claim_sharing_response(
    csil_root: &CsilCborValue,
) -> Result<SetMyClaimSharingResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    Ok(SetMyClaimSharingResponse {})
}

/// Encode a SetMyClaimSharingResponse to canonical CSIL CBOR bytes.
pub fn encode_set_my_claim_sharing_response(
    csil_v: &SetMyClaimSharingResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_my_claim_sharing_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetMyClaimSharingResponse.
pub fn decode_set_my_claim_sharing_response(
    csil_data: &[u8],
) -> Result<SetMyClaimSharingResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_my_claim_sharing_response(&csil_root)
}

/// Build the canonical CBOR value tree for a MyClaimSetting.
fn csil_enc_my_claim_setting(csil_v: &MyClaimSetting) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("keep_verified"), cbor_bool(csil_v.keep_verified)));
    csil_entries.push((
        cbor_text("shared_with_every_app"),
        cbor_bool(csil_v.shared_with_every_app),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a MyClaimSetting from a decoded CBOR value tree.
fn csil_dec_my_claim_setting(csil_root: &CsilCborValue) -> Result<MyClaimSetting, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let keep_verified = {
        let csil_field = cbor_require(csil_root, "keep_verified")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let shared_with_every_app = {
        let csil_field = cbor_require(csil_root, "shared_with_every_app")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(MyClaimSetting {
        claim_type,
        keep_verified,
        shared_with_every_app,
    })
}

/// Encode a MyClaimSetting to canonical CSIL CBOR bytes.
pub fn encode_my_claim_setting(csil_v: &MyClaimSetting) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_my_claim_setting(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a MyClaimSetting.
pub fn decode_my_claim_setting(csil_data: &[u8]) -> Result<MyClaimSetting, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_my_claim_setting(&csil_root)
}

/// Build the canonical CBOR value tree for a MyClaimSettingsResponse.
fn csil_enc_my_claim_settings_response(
    csil_v: &MyClaimSettingsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("profiles"),
        cbor_enc_array(&csil_v.profiles, csil_enc_profile)?,
    ));
    csil_entries.push((
        cbor_text("settings"),
        cbor_enc_array(&csil_v.settings, csil_enc_my_claim_setting)?,
    ));
    csil_entries.push((cbor_text("max_profiles"), cbor_int(csil_v.max_profiles)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a MyClaimSettingsResponse from a decoded CBOR value tree.
fn csil_dec_my_claim_settings_response(
    csil_root: &CsilCborValue,
) -> Result<MyClaimSettingsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let settings = {
        let csil_field = cbor_require(csil_root, "settings")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_my_claim_setting);
        csil_decode(csil_field)?
    };
    let profiles = {
        let csil_field = cbor_require(csil_root, "profiles")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_profile);
        csil_decode(csil_field)?
    };
    let max_profiles = {
        let csil_field = cbor_require(csil_root, "max_profiles")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(MyClaimSettingsResponse {
        settings,
        profiles,
        max_profiles,
    })
}

/// Encode a MyClaimSettingsResponse to canonical CSIL CBOR bytes.
pub fn encode_my_claim_settings_response(
    csil_v: &MyClaimSettingsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_my_claim_settings_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a MyClaimSettingsResponse.
pub fn decode_my_claim_settings_response(
    csil_data: &[u8],
) -> Result<MyClaimSettingsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_my_claim_settings_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetMyClaimKeepVerifiedRequest.
fn csil_enc_set_my_claim_keep_verified_request(
    csil_v: &SetMyClaimKeepVerifiedRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("keep_verified"), cbor_bool(csil_v.keep_verified)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetMyClaimKeepVerifiedRequest from a decoded CBOR value tree.
fn csil_dec_set_my_claim_keep_verified_request(
    csil_root: &CsilCborValue,
) -> Result<SetMyClaimKeepVerifiedRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let keep_verified = {
        let csil_field = cbor_require(csil_root, "keep_verified")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(SetMyClaimKeepVerifiedRequest {
        claim_type,
        keep_verified,
    })
}

/// Encode a SetMyClaimKeepVerifiedRequest to canonical CSIL CBOR bytes.
pub fn encode_set_my_claim_keep_verified_request(
    csil_v: &SetMyClaimKeepVerifiedRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_my_claim_keep_verified_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetMyClaimKeepVerifiedRequest.
pub fn decode_set_my_claim_keep_verified_request(
    csil_data: &[u8],
) -> Result<SetMyClaimKeepVerifiedRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_my_claim_keep_verified_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetMyClaimKeepVerifiedResponse.
fn csil_enc_set_my_claim_keep_verified_response(
    _csil_v: &SetMyClaimKeepVerifiedResponse,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(CsilCborValue::Map(Vec::new()))
}

/// Reconstruct a SetMyClaimKeepVerifiedResponse from a decoded CBOR value tree.
fn csil_dec_set_my_claim_keep_verified_response(
    csil_root: &CsilCborValue,
) -> Result<SetMyClaimKeepVerifiedResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    Ok(SetMyClaimKeepVerifiedResponse {})
}

/// Encode a SetMyClaimKeepVerifiedResponse to canonical CSIL CBOR bytes.
pub fn encode_set_my_claim_keep_verified_response(
    csil_v: &SetMyClaimKeepVerifiedResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_my_claim_keep_verified_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetMyClaimKeepVerifiedResponse.
pub fn decode_set_my_claim_keep_verified_response(
    csil_data: &[u8],
) -> Result<SetMyClaimKeepVerifiedResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_my_claim_keep_verified_response(&csil_root)
}

/// Build the canonical CBOR value tree for a Profile.
fn csil_enc_profile(csil_v: &Profile) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    if let Some(csil_inner) = &csil_v.label {
        csil_entries.push((cbor_text("label"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("is_root"), cbor_bool(csil_v.is_root)));
    csil_entries.push((cbor_text("account_id"), cbor_text(&csil_v.account_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a Profile from a decoded CBOR value tree.
fn csil_dec_profile(csil_root: &CsilCborValue) -> Result<Profile, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_profile(csil_v: &Profile) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_profile(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a Profile.
pub fn decode_profile(csil_data: &[u8]) -> Result<Profile, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_profile(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateProfileRequest.
fn csil_enc_create_profile_request(
    csil_v: &CreateProfileRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    if let Some(csil_inner) = &csil_v.label {
        csil_entries.push((cbor_text("label"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CreateProfileRequest from a decoded CBOR value tree.
fn csil_dec_create_profile_request(
    csil_root: &CsilCborValue,
) -> Result<CreateProfileRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_create_profile_request(
    csil_v: &CreateProfileRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_create_profile_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CreateProfileRequest.
pub fn decode_create_profile_request(
    csil_data: &[u8],
) -> Result<CreateProfileRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_profile_request(&csil_root)
}

/// Build the canonical CBOR value tree for a CreateProfileResponse.
fn csil_enc_create_profile_response(
    csil_v: &CreateProfileResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("profile"), csil_enc_profile(&csil_v.profile)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CreateProfileResponse from a decoded CBOR value tree.
fn csil_dec_create_profile_response(
    csil_root: &CsilCborValue,
) -> Result<CreateProfileResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let profile = {
        let csil_field = cbor_require(csil_root, "profile")?;
        let csil_decode = csil_dec_profile;
        csil_decode(csil_field)?
    };
    Ok(CreateProfileResponse { profile })
}

/// Encode a CreateProfileResponse to canonical CSIL CBOR bytes.
pub fn encode_create_profile_response(
    csil_v: &CreateProfileResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_create_profile_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CreateProfileResponse.
pub fn decode_create_profile_response(
    csil_data: &[u8],
) -> Result<CreateProfileResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_create_profile_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RequestVerificationRequest.
fn csil_enc_request_verification_request(
    csil_v: &RequestVerificationRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("issuer_domain"), cbor_text(&csil_v.issuer_domain)));
    csil_entries.push((
        cbor_text("requested_claim_types"),
        cbor_enc_array(&csil_v.requested_claim_types, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RequestVerificationRequest from a decoded CBOR value tree.
fn csil_dec_request_verification_request(
    csil_root: &CsilCborValue,
) -> Result<RequestVerificationRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_request_verification_request(
    csil_v: &RequestVerificationRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_request_verification_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RequestVerificationRequest.
pub fn decode_request_verification_request(
    csil_data: &[u8],
) -> Result<RequestVerificationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_request_verification_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RequestVerificationResponse.
fn csil_enc_request_verification_response(
    csil_v: &RequestVerificationResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("signed_request"),
        csil_enc_signed_signing_request(&csil_v.signed_request)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RequestVerificationResponse from a decoded CBOR value tree.
fn csil_dec_request_verification_response(
    csil_root: &CsilCborValue,
) -> Result<RequestVerificationResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = csil_dec_signed_signing_request;
        csil_decode(csil_field)?
    };
    Ok(RequestVerificationResponse { signed_request })
}

/// Encode a RequestVerificationResponse to canonical CSIL CBOR bytes.
pub fn encode_request_verification_response(
    csil_v: &RequestVerificationResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_request_verification_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RequestVerificationResponse.
pub fn decode_request_verification_response(
    csil_data: &[u8],
) -> Result<RequestVerificationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_request_verification_response(&csil_root)
}

/// Build the canonical CBOR value tree for a PasswordPolicy.
fn csil_enc_password_policy(csil_v: &PasswordPolicy) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("max_length"), cbor_int(csil_v.max_length)));
    csil_entries.push((cbor_text("min_length"), cbor_int(csil_v.min_length)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PasswordPolicy from a decoded CBOR value tree.
fn csil_dec_password_policy(csil_root: &CsilCborValue) -> Result<PasswordPolicy, CsilCborError> {
    cbor_check_record(csil_root)?;
    let min_length = {
        let csil_field = cbor_require(csil_root, "min_length")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let max_length = {
        let csil_field = cbor_require(csil_root, "max_length")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(PasswordPolicy {
        min_length,
        max_length,
    })
}

/// Encode a PasswordPolicy to canonical CSIL CBOR bytes.
pub fn encode_password_policy(csil_v: &PasswordPolicy) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_password_policy(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PasswordPolicy.
pub fn decode_password_policy(csil_data: &[u8]) -> Result<PasswordPolicy, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_password_policy(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserSessionInfo.
fn csil_enc_browser_session_info(
    csil_v: &BrowserSessionInfo,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((
        cbor_text("authenticated_at"),
        csil_rt_enc_timestamp(&csil_v.authenticated_at)?,
    ));
    csil_entries.push((
        cbor_text("authentication_methods"),
        cbor_enc_array(&csil_v.authentication_methods, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserSessionInfo from a decoded CBOR value tree.
fn csil_dec_browser_session_info(
    csil_root: &CsilCborValue,
) -> Result<BrowserSessionInfo, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let authenticated_at = {
        let csil_field = cbor_require(csil_root, "authenticated_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let authentication_methods = {
        let csil_field = cbor_require(csil_root, "authentication_methods")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(BrowserSessionInfo {
        user,
        issued_at,
        authenticated_at,
        expires_at,
        authentication_methods,
    })
}

/// Encode a BrowserSessionInfo to canonical CSIL CBOR bytes.
pub fn encode_browser_session_info(csil_v: &BrowserSessionInfo) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_session_info(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserSessionInfo.
pub fn decode_browser_session_info(csil_data: &[u8]) -> Result<BrowserSessionInfo, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_session_info(&csil_root)
}

/// Build the canonical CBOR value tree for a SessionPasswordLoginRequest.
fn csil_enc_session_password_login_request(
    csil_v: &SessionPasswordLoginRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("password"), cbor_text(&csil_v.password)));
    csil_entries.push((cbor_text("username"), cbor_text(&csil_v.username)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SessionPasswordLoginRequest from a decoded CBOR value tree.
fn csil_dec_session_password_login_request(
    csil_root: &CsilCborValue,
) -> Result<SessionPasswordLoginRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    Ok(SessionPasswordLoginRequest { username, password })
}

/// Encode a SessionPasswordLoginRequest to canonical CSIL CBOR bytes.
pub fn encode_session_password_login_request(
    csil_v: &SessionPasswordLoginRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_session_password_login_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SessionPasswordLoginRequest.
pub fn decode_session_password_login_request(
    csil_data: &[u8],
) -> Result<SessionPasswordLoginRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_session_password_login_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SessionPasswordLoginResponse.
fn csil_enc_session_password_login_response(
    csil_v: &SessionPasswordLoginResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("session"),
        csil_enc_browser_session_info(&csil_v.session)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SessionPasswordLoginResponse from a decoded CBOR value tree.
fn csil_dec_session_password_login_response(
    csil_root: &CsilCborValue,
) -> Result<SessionPasswordLoginResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let session = {
        let csil_field = cbor_require(csil_root, "session")?;
        let csil_decode = csil_dec_browser_session_info;
        csil_decode(csil_field)?
    };
    Ok(SessionPasswordLoginResponse { session })
}

/// Encode a SessionPasswordLoginResponse to canonical CSIL CBOR bytes.
pub fn encode_session_password_login_response(
    csil_v: &SessionPasswordLoginResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_session_password_login_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SessionPasswordLoginResponse.
pub fn decode_session_password_login_response(
    csil_data: &[u8],
) -> Result<SessionPasswordLoginResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_session_password_login_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SessionCurrentResponse.
fn csil_enc_session_current_response(
    csil_v: &SessionCurrentResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("session"),
        csil_enc_browser_session_info(&csil_v.session)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SessionCurrentResponse from a decoded CBOR value tree.
fn csil_dec_session_current_response(
    csil_root: &CsilCborValue,
) -> Result<SessionCurrentResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let session = {
        let csil_field = cbor_require(csil_root, "session")?;
        let csil_decode = csil_dec_browser_session_info;
        csil_decode(csil_field)?
    };
    Ok(SessionCurrentResponse { session })
}

/// Encode a SessionCurrentResponse to canonical CSIL CBOR bytes.
pub fn encode_session_current_response(
    csil_v: &SessionCurrentResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_session_current_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SessionCurrentResponse.
pub fn decode_session_current_response(
    csil_data: &[u8],
) -> Result<SessionCurrentResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_session_current_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SessionLogoutResponse.
fn csil_enc_session_logout_response(
    csil_v: &SessionLogoutResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SessionLogoutResponse from a decoded CBOR value tree.
fn csil_dec_session_logout_response(
    csil_root: &CsilCborValue,
) -> Result<SessionLogoutResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(SessionLogoutResponse { success })
}

/// Encode a SessionLogoutResponse to canonical CSIL CBOR bytes.
pub fn encode_session_logout_response(
    csil_v: &SessionLogoutResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_session_logout_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SessionLogoutResponse.
pub fn decode_session_logout_response(
    csil_data: &[u8],
) -> Result<SessionLogoutResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_session_logout_response(&csil_root)
}

/// Build the canonical CBOR value tree for a IntrospectBrowserSessionRequest.
fn csil_enc_introspect_browser_session_request(
    csil_v: &IntrospectBrowserSessionRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("session_cookie"),
        cbor_text(&csil_v.session_cookie),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a IntrospectBrowserSessionRequest from a decoded CBOR value tree.
fn csil_dec_introspect_browser_session_request(
    csil_root: &CsilCborValue,
) -> Result<IntrospectBrowserSessionRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let session_cookie = {
        let csil_field = cbor_require(csil_root, "session_cookie")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(IntrospectBrowserSessionRequest { session_cookie })
}

/// Encode a IntrospectBrowserSessionRequest to canonical CSIL CBOR bytes.
pub fn encode_introspect_browser_session_request(
    csil_v: &IntrospectBrowserSessionRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_introspect_browser_session_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a IntrospectBrowserSessionRequest.
pub fn decode_introspect_browser_session_request(
    csil_data: &[u8],
) -> Result<IntrospectBrowserSessionRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_introspect_browser_session_request(&csil_root)
}

/// Build the canonical CBOR value tree for a IntrospectBrowserSessionResponse.
fn csil_enc_introspect_browser_session_response(
    csil_v: &IntrospectBrowserSessionResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("user_domain"), cbor_text(&csil_v.user_domain)));
    csil_entries.push((
        cbor_text("authenticated_at"),
        csil_rt_enc_timestamp(&csil_v.authenticated_at)?,
    ));
    csil_entries.push((
        cbor_text("authentication_methods"),
        cbor_enc_array(&csil_v.authentication_methods, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a IntrospectBrowserSessionResponse from a decoded CBOR value tree.
fn csil_dec_introspect_browser_session_response(
    csil_root: &CsilCborValue,
) -> Result<IntrospectBrowserSessionResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let authenticated_at = {
        let csil_field = cbor_require(csil_root, "authenticated_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let authentication_methods = {
        let csil_field = cbor_require(csil_root, "authentication_methods")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(IntrospectBrowserSessionResponse {
        user_id,
        user_domain,
        authenticated_at,
        expires_at,
        authentication_methods,
    })
}

/// Encode a IntrospectBrowserSessionResponse to canonical CSIL CBOR bytes.
pub fn encode_introspect_browser_session_response(
    csil_v: &IntrospectBrowserSessionResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_introspect_browser_session_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a IntrospectBrowserSessionResponse.
pub fn decode_introspect_browser_session_response(
    csil_data: &[u8],
) -> Result<IntrospectBrowserSessionResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_introspect_browser_session_response(&csil_root)
}

/// Build the canonical CBOR value tree for a NotificationCapability.
fn csil_enc_notification_capability(
    csil_v: &NotificationCapability,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("channel"),
        csil_enc_notification_channel(&csil_v.channel)?,
    ));
    csil_entries.push((
        cbor_text("purpose"),
        csil_enc_notification_purpose(&csil_v.purpose)?,
    ));
    csil_entries.push((
        cbor_text("destination_kind"),
        csil_enc_destination_kind(&csil_v.destination_kind)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a NotificationCapability from a decoded CBOR value tree.
fn csil_dec_notification_capability(
    csil_root: &CsilCborValue,
) -> Result<NotificationCapability, CsilCborError> {
    cbor_check_record(csil_root)?;
    let purpose = {
        let csil_field = cbor_require(csil_root, "purpose")?;
        let csil_decode = csil_dec_notification_purpose;
        csil_decode(csil_field)?
    };
    let channel = {
        let csil_field = cbor_require(csil_root, "channel")?;
        let csil_decode = csil_dec_notification_channel;
        csil_decode(csil_field)?
    };
    let destination_kind = {
        let csil_field = cbor_require(csil_root, "destination_kind")?;
        let csil_decode = csil_dec_destination_kind;
        csil_decode(csil_field)?
    };
    Ok(NotificationCapability {
        purpose,
        channel,
        destination_kind,
    })
}

/// Encode a NotificationCapability to canonical CSIL CBOR bytes.
pub fn encode_notification_capability(
    csil_v: &NotificationCapability,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_notification_capability(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a NotificationCapability.
pub fn decode_notification_capability(
    csil_data: &[u8],
) -> Result<NotificationCapability, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_notification_capability(&csil_root)
}

/// Build the canonical CBOR value tree for a GetNotificationCapabilitiesResponse.
fn csil_enc_get_notification_capabilities_response(
    csil_v: &GetNotificationCapabilitiesResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("capabilities"),
        cbor_enc_array(&csil_v.capabilities, csil_enc_notification_capability)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetNotificationCapabilitiesResponse from a decoded CBOR value tree.
fn csil_dec_get_notification_capabilities_response(
    csil_root: &CsilCborValue,
) -> Result<GetNotificationCapabilitiesResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let capabilities = {
        let csil_field = cbor_require(csil_root, "capabilities")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_notification_capability);
        csil_decode(csil_field)?
    };
    Ok(GetNotificationCapabilitiesResponse { capabilities })
}

/// Encode a GetNotificationCapabilitiesResponse to canonical CSIL CBOR bytes.
pub fn encode_get_notification_capabilities_response(
    csil_v: &GetNotificationCapabilitiesResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_notification_capabilities_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetNotificationCapabilitiesResponse.
pub fn decode_get_notification_capabilities_response(
    csil_data: &[u8],
) -> Result<GetNotificationCapabilitiesResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_notification_capabilities_response(&csil_root)
}

/// Build the canonical CBOR value tree for a VerifiedContactMethod.
fn csil_enc_verified_contact_method(
    csil_v: &VerifiedContactMethod,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(6);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((
        cbor_text("channel"),
        csil_enc_notification_channel(&csil_v.channel)?,
    ));
    csil_entries.push((
        cbor_text("purposes"),
        cbor_enc_array(&csil_v.purposes, csil_enc_notification_purpose)?,
    ));
    if let Some(csil_inner) = &csil_v.revoked_at {
        csil_entries.push((cbor_text("revoked_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    csil_entries.push((cbor_text("destination"), cbor_text(&csil_v.destination)));
    csil_entries.push((
        cbor_text("verified_at"),
        csil_rt_enc_timestamp(&csil_v.verified_at)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a VerifiedContactMethod from a decoded CBOR value tree.
fn csil_dec_verified_contact_method(
    csil_root: &CsilCborValue,
) -> Result<VerifiedContactMethod, CsilCborError> {
    cbor_check_record(csil_root)?;
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let channel = {
        let csil_field = cbor_require(csil_root, "channel")?;
        let csil_decode = csil_dec_notification_channel;
        csil_decode(csil_field)?
    };
    let destination = {
        let csil_field = cbor_require(csil_root, "destination")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let verified_at = {
        let csil_field = cbor_require(csil_root, "verified_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let purposes = {
        let csil_field = cbor_require(csil_root, "purposes")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_notification_purpose);
        csil_decode(csil_field)?
    };
    let revoked_at = match cbor_map_get(csil_root, "revoked_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(VerifiedContactMethod {
        id,
        channel,
        destination,
        verified_at,
        purposes,
        revoked_at,
    })
}

/// Encode a VerifiedContactMethod to canonical CSIL CBOR bytes.
pub fn encode_verified_contact_method(
    csil_v: &VerifiedContactMethod,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_verified_contact_method(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a VerifiedContactMethod.
pub fn decode_verified_contact_method(
    csil_data: &[u8],
) -> Result<VerifiedContactMethod, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_verified_contact_method(&csil_root)
}

/// Build the canonical CBOR value tree for a ListVerifiedContactMethodsResponse.
fn csil_enc_list_verified_contact_methods_response(
    csil_v: &ListVerifiedContactMethodsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("contact_methods"),
        cbor_enc_array(&csil_v.contact_methods, csil_enc_verified_contact_method)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListVerifiedContactMethodsResponse from a decoded CBOR value tree.
fn csil_dec_list_verified_contact_methods_response(
    csil_root: &CsilCborValue,
) -> Result<ListVerifiedContactMethodsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let contact_methods = {
        let csil_field = cbor_require(csil_root, "contact_methods")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_verified_contact_method);
        csil_decode(csil_field)?
    };
    Ok(ListVerifiedContactMethodsResponse { contact_methods })
}

/// Encode a ListVerifiedContactMethodsResponse to canonical CSIL CBOR bytes.
pub fn encode_list_verified_contact_methods_response(
    csil_v: &ListVerifiedContactMethodsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_verified_contact_methods_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListVerifiedContactMethodsResponse.
pub fn decode_list_verified_contact_methods_response(
    csil_data: &[u8],
) -> Result<ListVerifiedContactMethodsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_verified_contact_methods_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeVerifiedContactMethodRequest.
fn csil_enc_revoke_verified_contact_method_request(
    csil_v: &RevokeVerifiedContactMethodRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("current_password"),
        cbor_text(&csil_v.current_password),
    ));
    csil_entries.push((
        cbor_text("contact_method_id"),
        cbor_text(&csil_v.contact_method_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeVerifiedContactMethodRequest from a decoded CBOR value tree.
fn csil_dec_revoke_verified_contact_method_request(
    csil_root: &CsilCborValue,
) -> Result<RevokeVerifiedContactMethodRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let contact_method_id = {
        let csil_field = cbor_require(csil_root, "contact_method_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let current_password = {
        let csil_field = cbor_require(csil_root, "current_password")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RevokeVerifiedContactMethodRequest {
        contact_method_id,
        current_password,
    })
}

/// Encode a RevokeVerifiedContactMethodRequest to canonical CSIL CBOR bytes.
pub fn encode_revoke_verified_contact_method_request(
    csil_v: &RevokeVerifiedContactMethodRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_verified_contact_method_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeVerifiedContactMethodRequest.
pub fn decode_revoke_verified_contact_method_request(
    csil_data: &[u8],
) -> Result<RevokeVerifiedContactMethodRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_verified_contact_method_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeVerifiedContactMethodResponse.
fn csil_enc_revoke_verified_contact_method_response(
    csil_v: &RevokeVerifiedContactMethodResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeVerifiedContactMethodResponse from a decoded CBOR value tree.
fn csil_dec_revoke_verified_contact_method_response(
    csil_root: &CsilCborValue,
) -> Result<RevokeVerifiedContactMethodResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RevokeVerifiedContactMethodResponse { success })
}

/// Encode a RevokeVerifiedContactMethodResponse to canonical CSIL CBOR bytes.
pub fn encode_revoke_verified_contact_method_response(
    csil_v: &RevokeVerifiedContactMethodResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_verified_contact_method_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeVerifiedContactMethodResponse.
pub fn decode_revoke_verified_contact_method_response(
    csil_data: &[u8],
) -> Result<RevokeVerifiedContactMethodResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_verified_contact_method_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RequestContactVerificationRequest.
fn csil_enc_request_contact_verification_request(
    csil_v: &RequestContactVerificationRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("channel"),
        csil_enc_notification_channel(&csil_v.channel)?,
    ));
    csil_entries.push((cbor_text("destination"), cbor_text(&csil_v.destination)));
    csil_entries.push((
        cbor_text("current_password"),
        cbor_text(&csil_v.current_password),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RequestContactVerificationRequest from a decoded CBOR value tree.
fn csil_dec_request_contact_verification_request(
    csil_root: &CsilCborValue,
) -> Result<RequestContactVerificationRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let channel = {
        let csil_field = cbor_require(csil_root, "channel")?;
        let csil_decode = csil_dec_notification_channel;
        csil_decode(csil_field)?
    };
    let destination = {
        let csil_field = cbor_require(csil_root, "destination")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let current_password = {
        let csil_field = cbor_require(csil_root, "current_password")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RequestContactVerificationRequest {
        channel,
        destination,
        current_password,
    })
}

/// Encode a RequestContactVerificationRequest to canonical CSIL CBOR bytes.
pub fn encode_request_contact_verification_request(
    csil_v: &RequestContactVerificationRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_request_contact_verification_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RequestContactVerificationRequest.
pub fn decode_request_contact_verification_request(
    csil_data: &[u8],
) -> Result<RequestContactVerificationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_request_contact_verification_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RequestContactVerificationResponse.
fn csil_enc_request_contact_verification_response(
    csil_v: &RequestContactVerificationResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RequestContactVerificationResponse from a decoded CBOR value tree.
fn csil_dec_request_contact_verification_response(
    csil_root: &CsilCborValue,
) -> Result<RequestContactVerificationResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(RequestContactVerificationResponse { expires_at })
}

/// Encode a RequestContactVerificationResponse to canonical CSIL CBOR bytes.
pub fn encode_request_contact_verification_response(
    csil_v: &RequestContactVerificationResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_request_contact_verification_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RequestContactVerificationResponse.
pub fn decode_request_contact_verification_response(
    csil_data: &[u8],
) -> Result<RequestContactVerificationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_request_contact_verification_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ConfirmContactVerificationRequest.
fn csil_enc_confirm_contact_verification_request(
    csil_v: &ConfirmContactVerificationRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("token"), cbor_text(&csil_v.token)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ConfirmContactVerificationRequest from a decoded CBOR value tree.
fn csil_dec_confirm_contact_verification_request(
    csil_root: &CsilCborValue,
) -> Result<ConfirmContactVerificationRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let token = {
        let csil_field = cbor_require(csil_root, "token")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ConfirmContactVerificationRequest { token })
}

/// Encode a ConfirmContactVerificationRequest to canonical CSIL CBOR bytes.
pub fn encode_confirm_contact_verification_request(
    csil_v: &ConfirmContactVerificationRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_confirm_contact_verification_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ConfirmContactVerificationRequest.
pub fn decode_confirm_contact_verification_request(
    csil_data: &[u8],
) -> Result<ConfirmContactVerificationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_confirm_contact_verification_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ConfirmContactVerificationResponse.
fn csil_enc_confirm_contact_verification_response(
    csil_v: &ConfirmContactVerificationResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim)?,
    ));
    csil_entries.push((
        cbor_text("contact_method"),
        csil_enc_verified_contact_method(&csil_v.contact_method)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ConfirmContactVerificationResponse from a decoded CBOR value tree.
fn csil_dec_confirm_contact_verification_response(
    csil_root: &CsilCborValue,
) -> Result<ConfirmContactVerificationResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let contact_method = {
        let csil_field = cbor_require(csil_root, "contact_method")?;
        let csil_decode = csil_dec_verified_contact_method;
        csil_decode(csil_field)?
    };
    let claims = {
        let csil_field = cbor_require(csil_root, "claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim);
        csil_decode(csil_field)?
    };
    Ok(ConfirmContactVerificationResponse {
        contact_method,
        claims,
    })
}

/// Encode a ConfirmContactVerificationResponse to canonical CSIL CBOR bytes.
pub fn encode_confirm_contact_verification_response(
    csil_v: &ConfirmContactVerificationResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_confirm_contact_verification_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ConfirmContactVerificationResponse.
pub fn decode_confirm_contact_verification_response(
    csil_data: &[u8],
) -> Result<ConfirmContactVerificationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_confirm_contact_verification_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RequestPasswordRecoveryRequest.
fn csil_enc_request_password_recovery_request(
    csil_v: &RequestPasswordRecoveryRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("identifier"), cbor_text(&csil_v.identifier)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RequestPasswordRecoveryRequest from a decoded CBOR value tree.
fn csil_dec_request_password_recovery_request(
    csil_root: &CsilCborValue,
) -> Result<RequestPasswordRecoveryRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let identifier = {
        let csil_field = cbor_require(csil_root, "identifier")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RequestPasswordRecoveryRequest { identifier })
}

/// Encode a RequestPasswordRecoveryRequest to canonical CSIL CBOR bytes.
pub fn encode_request_password_recovery_request(
    csil_v: &RequestPasswordRecoveryRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_request_password_recovery_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RequestPasswordRecoveryRequest.
pub fn decode_request_password_recovery_request(
    csil_data: &[u8],
) -> Result<RequestPasswordRecoveryRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_request_password_recovery_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RequestPasswordRecoveryResponse.
fn csil_enc_request_password_recovery_response(
    _csil_v: &RequestPasswordRecoveryResponse,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(CsilCborValue::Map(Vec::new()))
}

/// Reconstruct a RequestPasswordRecoveryResponse from a decoded CBOR value tree.
fn csil_dec_request_password_recovery_response(
    csil_root: &CsilCborValue,
) -> Result<RequestPasswordRecoveryResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    Ok(RequestPasswordRecoveryResponse {})
}

/// Encode a RequestPasswordRecoveryResponse to canonical CSIL CBOR bytes.
pub fn encode_request_password_recovery_response(
    csil_v: &RequestPasswordRecoveryResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_request_password_recovery_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RequestPasswordRecoveryResponse.
pub fn decode_request_password_recovery_response(
    csil_data: &[u8],
) -> Result<RequestPasswordRecoveryResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_request_password_recovery_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ValidatePasswordRecoveryRequest.
fn csil_enc_validate_password_recovery_request(
    csil_v: &ValidatePasswordRecoveryRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("token"), cbor_text(&csil_v.token)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ValidatePasswordRecoveryRequest from a decoded CBOR value tree.
fn csil_dec_validate_password_recovery_request(
    csil_root: &CsilCborValue,
) -> Result<ValidatePasswordRecoveryRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let token = {
        let csil_field = cbor_require(csil_root, "token")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ValidatePasswordRecoveryRequest { token })
}

/// Encode a ValidatePasswordRecoveryRequest to canonical CSIL CBOR bytes.
pub fn encode_validate_password_recovery_request(
    csil_v: &ValidatePasswordRecoveryRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_validate_password_recovery_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ValidatePasswordRecoveryRequest.
pub fn decode_validate_password_recovery_request(
    csil_data: &[u8],
) -> Result<ValidatePasswordRecoveryRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_validate_password_recovery_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ValidatePasswordRecoveryResponse.
fn csil_enc_validate_password_recovery_response(
    csil_v: &ValidatePasswordRecoveryResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((
        cbor_text("password_policy"),
        csil_enc_password_policy(&csil_v.password_policy)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ValidatePasswordRecoveryResponse from a decoded CBOR value tree.
fn csil_dec_validate_password_recovery_response(
    csil_root: &CsilCborValue,
) -> Result<ValidatePasswordRecoveryResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let password_policy = {
        let csil_field = cbor_require(csil_root, "password_policy")?;
        let csil_decode = csil_dec_password_policy;
        csil_decode(csil_field)?
    };
    Ok(ValidatePasswordRecoveryResponse {
        expires_at,
        password_policy,
    })
}

/// Encode a ValidatePasswordRecoveryResponse to canonical CSIL CBOR bytes.
pub fn encode_validate_password_recovery_response(
    csil_v: &ValidatePasswordRecoveryResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_validate_password_recovery_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ValidatePasswordRecoveryResponse.
pub fn decode_validate_password_recovery_response(
    csil_data: &[u8],
) -> Result<ValidatePasswordRecoveryResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_validate_password_recovery_response(&csil_root)
}

/// Build the canonical CBOR value tree for a CompletePasswordRecoveryRequest.
fn csil_enc_complete_password_recovery_request(
    csil_v: &CompletePasswordRecoveryRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("token"), cbor_text(&csil_v.token)));
    csil_entries.push((cbor_text("new_password"), cbor_text(&csil_v.new_password)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CompletePasswordRecoveryRequest from a decoded CBOR value tree.
fn csil_dec_complete_password_recovery_request(
    csil_root: &CsilCborValue,
) -> Result<CompletePasswordRecoveryRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let token = {
        let csil_field = cbor_require(csil_root, "token")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let new_password = {
        let csil_field = cbor_require(csil_root, "new_password")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(CompletePasswordRecoveryRequest {
        token,
        new_password,
    })
}

/// Encode a CompletePasswordRecoveryRequest to canonical CSIL CBOR bytes.
pub fn encode_complete_password_recovery_request(
    csil_v: &CompletePasswordRecoveryRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_complete_password_recovery_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CompletePasswordRecoveryRequest.
pub fn decode_complete_password_recovery_request(
    csil_data: &[u8],
) -> Result<CompletePasswordRecoveryRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_complete_password_recovery_request(&csil_root)
}

/// Build the canonical CBOR value tree for a CompletePasswordRecoveryResponse.
fn csil_enc_complete_password_recovery_response(
    csil_v: &CompletePasswordRecoveryResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a CompletePasswordRecoveryResponse from a decoded CBOR value tree.
fn csil_dec_complete_password_recovery_response(
    csil_root: &CsilCborValue,
) -> Result<CompletePasswordRecoveryResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(CompletePasswordRecoveryResponse { success })
}

/// Encode a CompletePasswordRecoveryResponse to canonical CSIL CBOR bytes.
pub fn encode_complete_password_recovery_response(
    csil_v: &CompletePasswordRecoveryResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_complete_password_recovery_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CompletePasswordRecoveryResponse.
pub fn decode_complete_password_recovery_response(
    csil_data: &[u8],
) -> Result<CompletePasswordRecoveryResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_complete_password_recovery_response(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserAuthorizationInspectRequest.
fn csil_enc_browser_authorization_inspect_request(
    csil_v: &BrowserAuthorizationInspectRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserAuthorizationInspectRequest from a decoded CBOR value tree.
fn csil_dec_browser_authorization_inspect_request(
    csil_root: &CsilCborValue,
) -> Result<BrowserAuthorizationInspectRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(BrowserAuthorizationInspectRequest { signed_request })
}

/// Encode a BrowserAuthorizationInspectRequest to canonical CSIL CBOR bytes.
pub fn encode_browser_authorization_inspect_request(
    csil_v: &BrowserAuthorizationInspectRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_authorization_inspect_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserAuthorizationInspectRequest.
pub fn decode_browser_authorization_inspect_request(
    csil_data: &[u8],
) -> Result<BrowserAuthorizationInspectRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_authorization_inspect_request(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserConsentClaim.
fn csil_enc_browser_consent_claim(
    csil_v: &BrowserConsentClaim,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(12);
    csil_entries.push((cbor_text("label"), cbor_text(&csil_v.label)));
    csil_entries.push((
        cbor_text("policy"),
        csil_enc_consent_row_policy(&csil_v.policy)?,
    ));
    csil_entries.push((
        cbor_text("datatype"),
        csil_enc_claim_value_type(&csil_v.datatype)?,
    ));
    csil_entries.push((cbor_text("required"), cbor_bool(csil_v.required)));
    csil_entries.push((cbor_text("available"), cbor_bool(csil_v.available)));
    csil_entries.push((cbor_text("max_bytes"), cbor_int(csil_v.max_bytes)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    if let Some(csil_inner) = &csil_v.home_verified {
        csil_entries.push((cbor_text("home_verified"), cbor_bool(*csil_inner)));
    }
    csil_entries.push((cbor_text("user_settable"), cbor_bool(csil_v.user_settable)));
    csil_entries.push((
        cbor_text("default_granted"),
        cbor_bool(csil_v.default_granted),
    ));
    if let Some(csil_inner) = &csil_v.newly_requested {
        csil_entries.push((cbor_text("newly_requested"), cbor_bool(*csil_inner)));
    }
    csil_entries.push((
        cbor_text("requires_approval"),
        cbor_bool(csil_v.requires_approval),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserConsentClaim from a decoded CBOR value tree.
fn csil_dec_browser_consent_claim(
    csil_root: &CsilCborValue,
) -> Result<BrowserConsentClaim, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let datatype = {
        let csil_field = cbor_require(csil_root, "datatype")?;
        let csil_decode = csil_dec_claim_value_type;
        csil_decode(csil_field)?
    };
    let required = {
        let csil_field = cbor_require(csil_root, "required")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let available = {
        let csil_field = cbor_require(csil_root, "available")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let default_granted = {
        let csil_field = cbor_require(csil_root, "default_granted")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let policy = {
        let csil_field = cbor_require(csil_root, "policy")?;
        let csil_decode = csil_dec_consent_row_policy;
        csil_decode(csil_field)?
    };
    let user_settable = {
        let csil_field = cbor_require(csil_root, "user_settable")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let max_bytes = {
        let csil_field = cbor_require(csil_root, "max_bytes")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let requires_approval = {
        let csil_field = cbor_require(csil_root, "requires_approval")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let newly_requested = match cbor_map_get(csil_root, "newly_requested") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let home_verified = match cbor_map_get(csil_root, "home_verified") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(BrowserConsentClaim {
        claim_type,
        label,
        datatype,
        required,
        available,
        default_granted,
        policy,
        user_settable,
        max_bytes,
        requires_approval,
        newly_requested,
        home_verified,
    })
}

/// Encode a BrowserConsentClaim to canonical CSIL CBOR bytes.
pub fn encode_browser_consent_claim(
    csil_v: &BrowserConsentClaim,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_consent_claim(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserConsentClaim.
pub fn decode_browser_consent_claim(
    csil_data: &[u8],
) -> Result<BrowserConsentClaim, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_consent_claim(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserAuthorizationInspectResponse.
fn csil_enc_browser_authorization_inspect_response(
    csil_v: &BrowserAuthorizationInspectResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_browser_consent_claim)?,
    ));
    if let Some(csil_inner) = &csil_v.application {
        csil_entries.push((
            cbor_text("application"),
            csil_enc_relying_party_application(csil_inner)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.return_host {
        csil_entries.push((cbor_text("return_host"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.access_denied {
        csil_entries.push((
            cbor_text("access_denied"),
            csil_enc_app_access_denial(csil_inner)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.callback_host {
        csil_entries.push((cbor_text("callback_host"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("relying_party"), cbor_text(&csil_v.relying_party)));
    if let Some(csil_inner) = &csil_v.request_reason {
        csil_entries.push((cbor_text("request_reason"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.already_consented {
        csil_entries.push((cbor_text("already_consented"), cbor_bool(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.authorized_claims {
        csil_entries.push((
            cbor_text("authorized_claims"),
            cbor_enc_array(csil_inner, |csil_elem| Ok(cbor_text(csil_elem)))?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserAuthorizationInspectResponse from a decoded CBOR value tree.
fn csil_dec_browser_authorization_inspect_response(
    csil_root: &CsilCborValue,
) -> Result<BrowserAuthorizationInspectResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let relying_party = {
        let csil_field = cbor_require(csil_root, "relying_party")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claims = {
        let csil_field = cbor_require(csil_root, "claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_browser_consent_claim);
        csil_decode(csil_field)?
    };
    let request_reason = match cbor_map_get(csil_root, "request_reason") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let already_consented = match cbor_map_get(csil_root, "already_consented") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let authorized_claims = match cbor_map_get(csil_root, "authorized_claims") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let access_denied = match cbor_map_get(csil_root, "access_denied") {
        Some(csil_field) => {
            let csil_decode = csil_dec_app_access_denial;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let application = match cbor_map_get(csil_root, "application") {
        Some(csil_field) => {
            let csil_decode = csil_dec_relying_party_application;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let callback_host = match cbor_map_get(csil_root, "callback_host") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let return_host = match cbor_map_get(csil_root, "return_host") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(BrowserAuthorizationInspectResponse {
        relying_party,
        claims,
        request_reason,
        already_consented,
        authorized_claims,
        access_denied,
        application,
        callback_host,
        return_host,
    })
}

/// Encode a BrowserAuthorizationInspectResponse to canonical CSIL CBOR bytes.
pub fn encode_browser_authorization_inspect_response(
    csil_v: &BrowserAuthorizationInspectResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_authorization_inspect_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserAuthorizationInspectResponse.
pub fn decode_browser_authorization_inspect_response(
    csil_data: &[u8],
) -> Result<BrowserAuthorizationInspectResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_authorization_inspect_response(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserAuthorizationCompleteRequest.
fn csil_enc_browser_authorization_complete_request(
    csil_v: &BrowserAuthorizationCompleteRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    csil_entries.push((
        cbor_text("authorized_claims"),
        cbor_enc_array(&csil_v.authorized_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    csil_entries.push((
        cbor_text("claim_types_to_set"),
        cbor_enc_array(&csil_v.claim_types_to_set, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    if let Some(csil_inner) = &csil_v.use_standing_grant {
        csil_entries.push((cbor_text("use_standing_grant"), cbor_bool(*csil_inner)));
    }
    csil_entries.push((
        cbor_text("claim_values_to_set"),
        cbor_enc_array(&csil_v.claim_values_to_set, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserAuthorizationCompleteRequest from a decoded CBOR value tree.
fn csil_dec_browser_authorization_complete_request(
    csil_root: &CsilCborValue,
) -> Result<BrowserAuthorizationCompleteRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let authorized_claims = {
        let csil_field = cbor_require(csil_root, "authorized_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let claim_types_to_set = {
        let csil_field = cbor_require(csil_root, "claim_types_to_set")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let claim_values_to_set = {
        let csil_field = cbor_require(csil_root, "claim_values_to_set")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let use_standing_grant = match cbor_map_get(csil_root, "use_standing_grant") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(BrowserAuthorizationCompleteRequest {
        signed_request,
        authorized_claims,
        claim_types_to_set,
        claim_values_to_set,
        use_standing_grant,
    })
}

/// Encode a BrowserAuthorizationCompleteRequest to canonical CSIL CBOR bytes.
pub fn encode_browser_authorization_complete_request(
    csil_v: &BrowserAuthorizationCompleteRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_authorization_complete_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserAuthorizationCompleteRequest.
pub fn decode_browser_authorization_complete_request(
    csil_data: &[u8],
) -> Result<BrowserAuthorizationCompleteRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_authorization_complete_request(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserAuthorizationCompleteResponse.
fn csil_enc_browser_authorization_complete_response(
    csil_v: &BrowserAuthorizationCompleteResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("redirect_url"), cbor_text(&csil_v.redirect_url)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserAuthorizationCompleteResponse from a decoded CBOR value tree.
fn csil_dec_browser_authorization_complete_response(
    csil_root: &CsilCborValue,
) -> Result<BrowserAuthorizationCompleteResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let redirect_url = {
        let csil_field = cbor_require(csil_root, "redirect_url")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(BrowserAuthorizationCompleteResponse { redirect_url })
}

/// Encode a BrowserAuthorizationCompleteResponse to canonical CSIL CBOR bytes.
pub fn encode_browser_authorization_complete_response(
    csil_v: &BrowserAuthorizationCompleteResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_authorization_complete_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserAuthorizationCompleteResponse.
pub fn decode_browser_authorization_complete_response(
    csil_data: &[u8],
) -> Result<BrowserAuthorizationCompleteResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_authorization_complete_response(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserLocalRpInspectRequest.
fn csil_enc_browser_local_rp_inspect_request(
    csil_v: &BrowserLocalRpInspectRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserLocalRpInspectRequest from a decoded CBOR value tree.
fn csil_dec_browser_local_rp_inspect_request(
    csil_root: &CsilCborValue,
) -> Result<BrowserLocalRpInspectRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(BrowserLocalRpInspectRequest { signed_request })
}

/// Encode a BrowserLocalRpInspectRequest to canonical CSIL CBOR bytes.
pub fn encode_browser_local_rp_inspect_request(
    csil_v: &BrowserLocalRpInspectRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_local_rp_inspect_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserLocalRpInspectRequest.
pub fn decode_browser_local_rp_inspect_request(
    csil_data: &[u8],
) -> Result<BrowserLocalRpInspectRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_local_rp_inspect_request(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserLocalRpInspectResponse.
fn csil_enc_browser_local_rp_inspect_response(
    csil_v: &BrowserLocalRpInspectResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(10);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_browser_consent_claim)?,
    ));
    csil_entries.push((cbor_text("app_name"), cbor_text(&csil_v.app_name)));
    csil_entries.push((
        cbor_text("admission"),
        csil_enc_local_rp_admission(&csil_v.admission)?,
    ));
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    if let Some(csil_inner) = &csil_v.access_denied {
        csil_entries.push((
            cbor_text("access_denied"),
            csil_enc_app_access_denial(csil_inner)?,
        ));
    }
    csil_entries.push((cbor_text("callback_host"), cbor_text(&csil_v.callback_host)));
    if let Some(csil_inner) = &csil_v.first_seen_at {
        csil_entries.push((
            cbor_text("first_seen_at"),
            csil_rt_enc_timestamp(csil_inner)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.request_reason {
        csil_entries.push((cbor_text("request_reason"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.already_consented {
        csil_entries.push((cbor_text("already_consented"), cbor_bool(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.authorized_claims {
        csil_entries.push((
            cbor_text("authorized_claims"),
            cbor_enc_array(csil_inner, |csil_elem| Ok(cbor_text(csil_elem)))?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserLocalRpInspectResponse from a decoded CBOR value tree.
fn csil_dec_browser_local_rp_inspect_response(
    csil_root: &CsilCborValue,
) -> Result<BrowserLocalRpInspectResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let admission = {
        let csil_field = cbor_require(csil_root, "admission")?;
        let csil_decode = csil_dec_local_rp_admission;
        csil_decode(csil_field)?
    };
    let app_name = {
        let csil_field = cbor_require(csil_root, "app_name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let callback_host = {
        let csil_field = cbor_require(csil_root, "callback_host")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let first_seen_at = match cbor_map_get(csil_root, "first_seen_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let claims = {
        let csil_field = cbor_require(csil_root, "claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_browser_consent_claim);
        csil_decode(csil_field)?
    };
    let request_reason = match cbor_map_get(csil_root, "request_reason") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let already_consented = match cbor_map_get(csil_root, "already_consented") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let authorized_claims = match cbor_map_get(csil_root, "authorized_claims") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let access_denied = match cbor_map_get(csil_root, "access_denied") {
        Some(csil_field) => {
            let csil_decode = csil_dec_app_access_denial;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(BrowserLocalRpInspectResponse {
        admission,
        app_name,
        fingerprint,
        callback_host,
        first_seen_at,
        claims,
        request_reason,
        already_consented,
        authorized_claims,
        access_denied,
    })
}

/// Encode a BrowserLocalRpInspectResponse to canonical CSIL CBOR bytes.
pub fn encode_browser_local_rp_inspect_response(
    csil_v: &BrowserLocalRpInspectResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_local_rp_inspect_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserLocalRpInspectResponse.
pub fn decode_browser_local_rp_inspect_response(
    csil_data: &[u8],
) -> Result<BrowserLocalRpInspectResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_local_rp_inspect_response(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserLocalRpCompleteRequest.
fn csil_enc_browser_local_rp_complete_request(
    csil_v: &BrowserLocalRpCompleteRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    csil_entries.push((
        cbor_text("authorized_claims"),
        cbor_enc_array(&csil_v.authorized_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    csil_entries.push((
        cbor_text("claim_types_to_set"),
        cbor_enc_array(&csil_v.claim_types_to_set, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    if let Some(csil_inner) = &csil_v.use_standing_grant {
        csil_entries.push((cbor_text("use_standing_grant"), cbor_bool(*csil_inner)));
    }
    csil_entries.push((
        cbor_text("claim_values_to_set"),
        cbor_enc_array(&csil_v.claim_values_to_set, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserLocalRpCompleteRequest from a decoded CBOR value tree.
fn csil_dec_browser_local_rp_complete_request(
    csil_root: &CsilCborValue,
) -> Result<BrowserLocalRpCompleteRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let authorized_claims = {
        let csil_field = cbor_require(csil_root, "authorized_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let claim_types_to_set = {
        let csil_field = cbor_require(csil_root, "claim_types_to_set")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let claim_values_to_set = {
        let csil_field = cbor_require(csil_root, "claim_values_to_set")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let use_standing_grant = match cbor_map_get(csil_root, "use_standing_grant") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(BrowserLocalRpCompleteRequest {
        signed_request,
        authorized_claims,
        claim_types_to_set,
        claim_values_to_set,
        use_standing_grant,
    })
}

/// Encode a BrowserLocalRpCompleteRequest to canonical CSIL CBOR bytes.
pub fn encode_browser_local_rp_complete_request(
    csil_v: &BrowserLocalRpCompleteRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_local_rp_complete_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserLocalRpCompleteRequest.
pub fn decode_browser_local_rp_complete_request(
    csil_data: &[u8],
) -> Result<BrowserLocalRpCompleteRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_local_rp_complete_request(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserLocalRpCompleteResponse.
fn csil_enc_browser_local_rp_complete_response(
    csil_v: &BrowserLocalRpCompleteResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("redirect_url"), cbor_text(&csil_v.redirect_url)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserLocalRpCompleteResponse from a decoded CBOR value tree.
fn csil_dec_browser_local_rp_complete_response(
    csil_root: &CsilCborValue,
) -> Result<BrowserLocalRpCompleteResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let redirect_url = {
        let csil_field = cbor_require(csil_root, "redirect_url")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(BrowserLocalRpCompleteResponse { redirect_url })
}

/// Encode a BrowserLocalRpCompleteResponse to canonical CSIL CBOR bytes.
pub fn encode_browser_local_rp_complete_response(
    csil_v: &BrowserLocalRpCompleteResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_local_rp_complete_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserLocalRpCompleteResponse.
pub fn decode_browser_local_rp_complete_response(
    csil_data: &[u8],
) -> Result<BrowserLocalRpCompleteResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_local_rp_complete_response(&csil_root)
}

/// Build the canonical CBOR value tree for a UiTheme.
fn csil_enc_ui_theme(csil_v: &UiTheme) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    if let Some(csil_inner) = &csil_v.logo_url {
        csil_entries.push((cbor_text("logo_url"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.favicon_url {
        csil_entries.push((cbor_text("favicon_url"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.stylesheet_url {
        csil_entries.push((cbor_text("stylesheet_url"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a UiTheme from a decoded CBOR value tree.
fn csil_dec_ui_theme(csil_root: &CsilCborValue) -> Result<UiTheme, CsilCborError> {
    cbor_check_record(csil_root)?;
    let stylesheet_url = match cbor_map_get(csil_root, "stylesheet_url") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let logo_url = match cbor_map_get(csil_root, "logo_url") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let favicon_url = match cbor_map_get(csil_root, "favicon_url") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(UiTheme {
        stylesheet_url,
        logo_url,
        favicon_url,
    })
}

/// Encode a UiTheme to canonical CSIL CBOR bytes.
pub fn encode_ui_theme(csil_v: &UiTheme) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_ui_theme(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a UiTheme.
pub fn decode_ui_theme(csil_data: &[u8]) -> Result<UiTheme, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_ui_theme(&csil_root)
}

/// Build the canonical CBOR value tree for a UiExtension.
fn csil_enc_ui_extension(csil_v: &UiExtension) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("module_url"), cbor_text(&csil_v.module_url)));
    csil_entries.push((cbor_text("api_version"), cbor_int(csil_v.api_version)));
    if let Some(csil_inner) = &csil_v.stylesheet_url {
        csil_entries.push((cbor_text("stylesheet_url"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a UiExtension from a decoded CBOR value tree.
fn csil_dec_ui_extension(csil_root: &CsilCborValue) -> Result<UiExtension, CsilCborError> {
    cbor_check_record(csil_root)?;
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let module_url = {
        let csil_field = cbor_require(csil_root, "module_url")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let api_version = {
        let csil_field = cbor_require(csil_root, "api_version")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let stylesheet_url = match cbor_map_get(csil_root, "stylesheet_url") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(UiExtension {
        id,
        module_url,
        api_version,
        stylesheet_url,
    })
}

/// Encode a UiExtension to canonical CSIL CBOR bytes.
pub fn encode_ui_extension(csil_v: &UiExtension) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_ui_extension(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a UiExtension.
pub fn decode_ui_extension(csil_data: &[u8]) -> Result<UiExtension, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_ui_extension(&csil_root)
}

/// Build the canonical CBOR value tree for a UiDisplaySettings.
fn csil_enc_ui_display_settings(
    csil_v: &UiDisplaySettings,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("site_name"), cbor_text(&csil_v.site_name)));
    if let Some(csil_inner) = &csil_v.support_url {
        csil_entries.push((cbor_text("support_url"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a UiDisplaySettings from a decoded CBOR value tree.
fn csil_dec_ui_display_settings(
    csil_root: &CsilCborValue,
) -> Result<UiDisplaySettings, CsilCborError> {
    cbor_check_record(csil_root)?;
    let site_name = {
        let csil_field = cbor_require(csil_root, "site_name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let support_url = match cbor_map_get(csil_root, "support_url") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(UiDisplaySettings {
        site_name,
        support_url,
    })
}

/// Encode a UiDisplaySettings to canonical CSIL CBOR bytes.
pub fn encode_ui_display_settings(csil_v: &UiDisplaySettings) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_ui_display_settings(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a UiDisplaySettings.
pub fn decode_ui_display_settings(csil_data: &[u8]) -> Result<UiDisplaySettings, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_ui_display_settings(&csil_root)
}

/// Build the canonical CBOR value tree for a GetUiConfigurationResponse.
fn csil_enc_get_ui_configuration_response(
    csil_v: &GetUiConfigurationResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    if let Some(csil_inner) = &csil_v.theme {
        csil_entries.push((cbor_text("theme"), csil_enc_ui_theme(csil_inner)?));
    }
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((
        cbor_text("display"),
        csil_enc_ui_display_settings(&csil_v.display)?,
    ));
    csil_entries.push((
        cbor_text("extensions"),
        cbor_enc_array(&csil_v.extensions, csil_enc_ui_extension)?,
    ));
    csil_entries.push((
        cbor_text("capabilities"),
        cbor_enc_array(&csil_v.capabilities, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    if let Some(csil_inner) = &csil_v.public_origin {
        csil_entries.push((cbor_text("public_origin"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.password_policy {
        csil_entries.push((
            cbor_text("password_policy"),
            csil_enc_password_policy(csil_inner)?,
        ));
    }
    csil_entries.push((
        cbor_text("host_api_version"),
        cbor_int(csil_v.host_api_version),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetUiConfigurationResponse from a decoded CBOR value tree.
fn csil_dec_get_ui_configuration_response(
    csil_root: &CsilCborValue,
) -> Result<GetUiConfigurationResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let host_api_version = {
        let csil_field = cbor_require(csil_root, "host_api_version")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let public_origin = match cbor_map_get(csil_root, "public_origin") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let capabilities = {
        let csil_field = cbor_require(csil_root, "capabilities")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let display = {
        let csil_field = cbor_require(csil_root, "display")?;
        let csil_decode = csil_dec_ui_display_settings;
        csil_decode(csil_field)?
    };
    let theme = match cbor_map_get(csil_root, "theme") {
        Some(csil_field) => {
            let csil_decode = csil_dec_ui_theme;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let extensions = {
        let csil_field = cbor_require(csil_root, "extensions")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_ui_extension);
        csil_decode(csil_field)?
    };
    let password_policy = match cbor_map_get(csil_root, "password_policy") {
        Some(csil_field) => {
            let csil_decode = csil_dec_password_policy;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(GetUiConfigurationResponse {
        host_api_version,
        domain,
        public_origin,
        capabilities,
        display,
        theme,
        extensions,
        password_policy,
    })
}

/// Encode a GetUiConfigurationResponse to canonical CSIL CBOR bytes.
pub fn encode_get_ui_configuration_response(
    csil_v: &GetUiConfigurationResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_ui_configuration_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetUiConfigurationResponse.
pub fn decode_get_ui_configuration_response(
    csil_data: &[u8],
) -> Result<GetUiConfigurationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_ui_configuration_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpSignRequest.
fn csil_enc_rp_sign_request(csil_v: &RpSignRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    csil_entries.push((cbor_text("callback_url"), cbor_text(&csil_v.callback_url)));
    if let Some(csil_inner) = &csil_v.flow_context {
        csil_entries.push((
            cbor_text("flow_context"),
            csil_enc_auth_flow_context(csil_inner)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.requested_claims {
        csil_entries.push((
            cbor_text("requested_claims"),
            csil_enc_claim_request(csil_inner)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.authentication_requirements {
        csil_entries.push((
            cbor_text("authentication_requirements"),
            csil_enc_authentication_requirements(csil_inner)?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpSignRequest from a decoded CBOR value tree.
fn csil_dec_rp_sign_request(csil_root: &CsilCborValue) -> Result<RpSignRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let authentication_requirements = match cbor_map_get(csil_root, "authentication_requirements") {
        Some(csil_field) => {
            let csil_decode = csil_dec_authentication_requirements;
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
        authentication_requirements,
        flow_context,
    })
}

/// Encode a RpSignRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_sign_request(csil_v: &RpSignRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_sign_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpSignRequest.
pub fn decode_rp_sign_request(csil_data: &[u8]) -> Result<RpSignRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_sign_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpSignResponse.
fn csil_enc_rp_sign_response(csil_v: &RpSignResponse) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpSignResponse from a decoded CBOR value tree.
fn csil_dec_rp_sign_response(csil_root: &CsilCborValue) -> Result<RpSignResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RpSignResponse { signed_request })
}

/// Encode a RpSignResponse to canonical CSIL CBOR bytes.
pub fn encode_rp_sign_response(csil_v: &RpSignResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_sign_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpSignResponse.
pub fn decode_rp_sign_response(csil_data: &[u8]) -> Result<RpSignResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_sign_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpDecryptRequest.
fn csil_enc_rp_decrypt_request(csil_v: &RpDecryptRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("encrypted_token"),
        cbor_text(&csil_v.encrypted_token),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpDecryptRequest from a decoded CBOR value tree.
fn csil_dec_rp_decrypt_request(
    csil_root: &CsilCborValue,
) -> Result<RpDecryptRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let encrypted_token = {
        let csil_field = cbor_require(csil_root, "encrypted_token")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RpDecryptRequest { encrypted_token })
}

/// Encode a RpDecryptRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_decrypt_request(csil_v: &RpDecryptRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_decrypt_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpDecryptRequest.
pub fn decode_rp_decrypt_request(csil_data: &[u8]) -> Result<RpDecryptRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_decrypt_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpDecryptResponse.
fn csil_enc_rp_decrypt_response(
    csil_v: &RpDecryptResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("signed_assertion"),
        cbor_text(&csil_v.signed_assertion),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpDecryptResponse from a decoded CBOR value tree.
fn csil_dec_rp_decrypt_response(
    csil_root: &CsilCborValue,
) -> Result<RpDecryptResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_assertion = {
        let csil_field = cbor_require(csil_root, "signed_assertion")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RpDecryptResponse { signed_assertion })
}

/// Encode a RpDecryptResponse to canonical CSIL CBOR bytes.
pub fn encode_rp_decrypt_response(csil_v: &RpDecryptResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_decrypt_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpDecryptResponse.
pub fn decode_rp_decrypt_response(csil_data: &[u8]) -> Result<RpDecryptResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_decrypt_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpVerifyRequest.
fn csil_enc_rp_verify_request(csil_v: &RpVerifyRequest) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("expected_domain"),
        cbor_text(&csil_v.expected_domain),
    ));
    csil_entries.push((
        cbor_text("signed_assertion"),
        cbor_text(&csil_v.signed_assertion),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpVerifyRequest from a decoded CBOR value tree.
fn csil_dec_rp_verify_request(csil_root: &CsilCborValue) -> Result<RpVerifyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_rp_verify_request(csil_v: &RpVerifyRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_verify_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpVerifyRequest.
pub fn decode_rp_verify_request(csil_data: &[u8]) -> Result<RpVerifyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_verify_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpVerifyResponse.
fn csil_enc_rp_verify_response(csil_v: &RpVerifyResponse) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("verified"), cbor_bool(csil_v.verified)));
    csil_entries.push((
        cbor_text("assertion"),
        csil_enc_identity_assertion(&csil_v.assertion)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpVerifyResponse from a decoded CBOR value tree.
fn csil_dec_rp_verify_response(
    csil_root: &CsilCborValue,
) -> Result<RpVerifyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_rp_verify_response(csil_v: &RpVerifyResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_verify_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpVerifyResponse.
pub fn decode_rp_verify_response(csil_data: &[u8]) -> Result<RpVerifyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_verify_response(&csil_root)
}

/// Build the canonical CBOR value tree for a DomainSignatureCheck.
fn csil_enc_domain_signature_check(
    csil_v: &DomainSignatureCheck,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((
        cbor_text("status"),
        csil_enc_claim_check_status(&csil_v.status)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DomainSignatureCheck from a decoded CBOR value tree.
fn csil_dec_domain_signature_check(
    csil_root: &CsilCborValue,
) -> Result<DomainSignatureCheck, CsilCborError> {
    cbor_check_record(csil_root)?;
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let status = {
        let csil_field = cbor_require(csil_root, "status")?;
        let csil_decode = csil_dec_claim_check_status;
        csil_decode(csil_field)?
    };
    Ok(DomainSignatureCheck { domain, status })
}

/// Encode a DomainSignatureCheck to canonical CSIL CBOR bytes.
pub fn encode_domain_signature_check(
    csil_v: &DomainSignatureCheck,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_domain_signature_check(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DomainSignatureCheck.
pub fn decode_domain_signature_check(
    csil_data: &[u8],
) -> Result<DomainSignatureCheck, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_domain_signature_check(&csil_root)
}

/// Build the canonical CBOR value tree for a ClaimCheck.
fn csil_enc_claim_check(csil_v: &ClaimCheck) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("claim_id"), cbor_text(&csil_v.claim_id)));
    csil_entries.push((cbor_text("verified"), cbor_bool(csil_v.verified)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((
        cbor_text("claim_status"),
        csil_enc_claim_check_status(&csil_v.claim_status)?,
    ));
    csil_entries.push((
        cbor_text("signing_domains"),
        cbor_enc_array(&csil_v.signing_domains, csil_enc_domain_signature_check)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ClaimCheck from a decoded CBOR value tree.
fn csil_dec_claim_check(csil_root: &CsilCborValue) -> Result<ClaimCheck, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_id = {
        let csil_field = cbor_require(csil_root, "claim_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_status = {
        let csil_field = cbor_require(csil_root, "claim_status")?;
        let csil_decode = csil_dec_claim_check_status;
        csil_decode(csil_field)?
    };
    let signing_domains = {
        let csil_field = cbor_require(csil_root, "signing_domains")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_domain_signature_check);
        csil_decode(csil_field)?
    };
    let verified = {
        let csil_field = cbor_require(csil_root, "verified")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(ClaimCheck {
        claim_id,
        claim_type,
        claim_status,
        signing_domains,
        verified,
    })
}

/// Encode a ClaimCheck to canonical CSIL CBOR bytes.
pub fn encode_claim_check(csil_v: &ClaimCheck) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim_check(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ClaimCheck.
pub fn decode_claim_check(csil_data: &[u8]) -> Result<ClaimCheck, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_check(&csil_root)
}

/// Build the canonical CBOR value tree for a RpVerifyClaimsRequest.
fn csil_enc_rp_verify_claims_request(
    csil_v: &RpVerifyClaimsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim)?,
    ));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpVerifyClaimsRequest from a decoded CBOR value tree.
fn csil_dec_rp_verify_claims_request(
    csil_root: &CsilCborValue,
) -> Result<RpVerifyClaimsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let subject_domain = {
        let csil_field = cbor_require(csil_root, "subject_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claims = {
        let csil_field = cbor_require(csil_root, "claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim);
        csil_decode(csil_field)?
    };
    Ok(RpVerifyClaimsRequest {
        subject_domain,
        user_id,
        claims,
    })
}

/// Encode a RpVerifyClaimsRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_verify_claims_request(
    csil_v: &RpVerifyClaimsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_verify_claims_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpVerifyClaimsRequest.
pub fn decode_rp_verify_claims_request(
    csil_data: &[u8],
) -> Result<RpVerifyClaimsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_verify_claims_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpVerifyClaimsResponse.
fn csil_enc_rp_verify_claims_response(
    csil_v: &RpVerifyClaimsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("checks"),
        cbor_enc_array(&csil_v.checks, csil_enc_claim_check)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpVerifyClaimsResponse from a decoded CBOR value tree.
fn csil_dec_rp_verify_claims_response(
    csil_root: &CsilCborValue,
) -> Result<RpVerifyClaimsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let checks = {
        let csil_field = cbor_require(csil_root, "checks")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_check);
        csil_decode(csil_field)?
    };
    Ok(RpVerifyClaimsResponse { checks })
}

/// Encode a RpVerifyClaimsResponse to canonical CSIL CBOR bytes.
pub fn encode_rp_verify_claims_response(
    csil_v: &RpVerifyClaimsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_verify_claims_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpVerifyClaimsResponse.
pub fn decode_rp_verify_claims_response(
    csil_data: &[u8],
) -> Result<RpVerifyClaimsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_verify_claims_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpUserInfoRequest.
fn csil_enc_rp_user_info_request(
    csil_v: &RpUserInfoRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("token"), cbor_text(&csil_v.token)));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((cbor_text("api_base"), cbor_text(&csil_v.api_base)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpUserInfoRequest from a decoded CBOR value tree.
fn csil_dec_rp_user_info_request(
    csil_root: &CsilCborValue,
) -> Result<RpUserInfoRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_rp_user_info_request(csil_v: &RpUserInfoRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_user_info_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpUserInfoRequest.
pub fn decode_rp_user_info_request(csil_data: &[u8]) -> Result<RpUserInfoRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_user_info_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpError.
fn csil_enc_rp_error(csil_v: &RpError) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("code"), csil_enc_rp_error_code(&csil_v.code)?));
    csil_entries.push((cbor_text("message"), cbor_text(&csil_v.message)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpError from a decoded CBOR value tree.
fn csil_dec_rp_error(csil_root: &CsilCborValue) -> Result<RpError, CsilCborError> {
    cbor_check_record(csil_root)?;
    let code = {
        let csil_field = cbor_require(csil_root, "code")?;
        let csil_decode = csil_dec_rp_error_code;
        csil_decode(csil_field)?
    };
    let message = {
        let csil_field = cbor_require(csil_root, "message")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RpError { code, message })
}

/// Encode a RpError to canonical CSIL CBOR bytes.
pub fn encode_rp_error(csil_v: &RpError) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_error(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpError.
pub fn decode_rp_error(csil_data: &[u8]) -> Result<RpError, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_error(&csil_root)
}

/// Build the canonical CBOR value tree for a RpIssueAttestationRequest.
fn csil_enc_rp_issue_attestation_request(
    csil_v: &RpIssueAttestationRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((cbor_text("claim_value"), cbor_bytes(&csil_v.claim_value)));
    csil_entries.push((
        cbor_text("signed_request"),
        csil_enc_signed_signing_request(&csil_v.signed_request)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpIssueAttestationRequest from a decoded CBOR value tree.
fn csil_dec_rp_issue_attestation_request(
    csil_root: &CsilCborValue,
) -> Result<RpIssueAttestationRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_rp_issue_attestation_request(
    csil_v: &RpIssueAttestationRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_issue_attestation_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpIssueAttestationRequest.
pub fn decode_rp_issue_attestation_request(
    csil_data: &[u8],
) -> Result<RpIssueAttestationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_issue_attestation_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpIssueAttestationResponse.
fn csil_enc_rp_issue_attestation_response(
    csil_v: &RpIssueAttestationResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("claim"), csil_enc_claim(&csil_v.claim)?));
    csil_entries.push((cbor_text("deposited"), cbor_bool(csil_v.deposited)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpIssueAttestationResponse from a decoded CBOR value tree.
fn csil_dec_rp_issue_attestation_response(
    csil_root: &CsilCborValue,
) -> Result<RpIssueAttestationResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_rp_issue_attestation_response(
    csil_v: &RpIssueAttestationResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_issue_attestation_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpIssueAttestationResponse.
pub fn decode_rp_issue_attestation_response(
    csil_data: &[u8],
) -> Result<RpIssueAttestationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_issue_attestation_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthorizeValidateRequest.
fn csil_enc_authorize_validate_request(
    csil_v: &AuthorizeValidateRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.user_id {
        csil_entries.push((cbor_text("user_id"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AuthorizeValidateRequest from a decoded CBOR value tree.
fn csil_dec_authorize_validate_request(
    csil_root: &CsilCborValue,
) -> Result<AuthorizeValidateRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let user_id = match cbor_map_get(csil_root, "user_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(AuthorizeValidateRequest {
        signed_request,
        user_id,
    })
}

/// Encode a AuthorizeValidateRequest to canonical CSIL CBOR bytes.
pub fn encode_authorize_validate_request(
    csil_v: &AuthorizeValidateRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_authorize_validate_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AuthorizeValidateRequest.
pub fn decode_authorize_validate_request(
    csil_data: &[u8],
) -> Result<AuthorizeValidateRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_authorize_validate_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthorizeValidateResponse.
fn csil_enc_authorize_validate_response(
    csil_v: &AuthorizeValidateResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    if let Some(csil_inner) = &csil_v.application {
        csil_entries.push((
            cbor_text("application"),
            csil_enc_relying_party_application(csil_inner)?,
        ));
    }
    csil_entries.push((cbor_text("callback_url"), cbor_text(&csil_v.callback_url)));
    if let Some(csil_inner) = &csil_v.access_denied {
        csil_entries.push((
            cbor_text("access_denied"),
            csil_enc_app_access_denial(csil_inner)?,
        ));
    }
    csil_entries.push((cbor_text("relying_party"), cbor_text(&csil_v.relying_party)));
    csil_entries.push((
        cbor_text("requested_claims"),
        cbor_enc_array(&csil_v.requested_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    if let Some(csil_inner) = &csil_v.already_consented {
        csil_entries.push((cbor_text("already_consented"), cbor_bool(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.authorized_claims {
        csil_entries.push((
            cbor_text("authorized_claims"),
            cbor_enc_array(csil_inner, |csil_elem| Ok(cbor_text(csil_elem)))?,
        ));
    }
    if let Some(csil_inner) = &csil_v.newly_requested_claims {
        csil_entries.push((
            cbor_text("newly_requested_claims"),
            cbor_enc_array(csil_inner, |csil_elem| Ok(cbor_text(csil_elem)))?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AuthorizeValidateResponse from a decoded CBOR value tree.
fn csil_dec_authorize_validate_response(
    csil_root: &CsilCborValue,
) -> Result<AuthorizeValidateResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let requested_claims = {
        let csil_field = cbor_require(csil_root, "requested_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let already_consented = match cbor_map_get(csil_root, "already_consented") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let authorized_claims = match cbor_map_get(csil_root, "authorized_claims") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let newly_requested_claims = match cbor_map_get(csil_root, "newly_requested_claims") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let access_denied = match cbor_map_get(csil_root, "access_denied") {
        Some(csil_field) => {
            let csil_decode = csil_dec_app_access_denial;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let application = match cbor_map_get(csil_root, "application") {
        Some(csil_field) => {
            let csil_decode = csil_dec_relying_party_application;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(AuthorizeValidateResponse {
        relying_party,
        callback_url,
        requested_claims,
        already_consented,
        authorized_claims,
        newly_requested_claims,
        access_denied,
        application,
    })
}

/// Encode a AuthorizeValidateResponse to canonical CSIL CBOR bytes.
pub fn encode_authorize_validate_response(
    csil_v: &AuthorizeValidateResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_authorize_validate_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AuthorizeValidateResponse.
pub fn decode_authorize_validate_response(
    csil_data: &[u8],
) -> Result<AuthorizeValidateResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_authorize_validate_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthorizeFinalizeRequest.
fn csil_enc_authorize_finalize_request(
    csil_v: &AuthorizeFinalizeRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    csil_entries.push((
        cbor_text("authorized_claims"),
        cbor_enc_array(&csil_v.authorized_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AuthorizeFinalizeRequest from a decoded CBOR value tree.
fn csil_dec_authorize_finalize_request(
    csil_root: &CsilCborValue,
) -> Result<AuthorizeFinalizeRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let authorized_claims = {
        let csil_field = cbor_require(csil_root, "authorized_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(AuthorizeFinalizeRequest {
        user_id,
        signed_request,
        authorized_claims,
    })
}

/// Encode a AuthorizeFinalizeRequest to canonical CSIL CBOR bytes.
pub fn encode_authorize_finalize_request(
    csil_v: &AuthorizeFinalizeRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_authorize_finalize_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AuthorizeFinalizeRequest.
pub fn decode_authorize_finalize_request(
    csil_data: &[u8],
) -> Result<AuthorizeFinalizeRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_authorize_finalize_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AuthorizeFinalizeResponse.
fn csil_enc_authorize_finalize_response(
    csil_v: &AuthorizeFinalizeResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("redirect_url"), cbor_text(&csil_v.redirect_url)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AuthorizeFinalizeResponse from a decoded CBOR value tree.
fn csil_dec_authorize_finalize_response(
    csil_root: &CsilCborValue,
) -> Result<AuthorizeFinalizeResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let redirect_url = {
        let csil_field = cbor_require(csil_root, "redirect_url")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(AuthorizeFinalizeResponse { redirect_url })
}

/// Encode a AuthorizeFinalizeResponse to canonical CSIL CBOR bytes.
pub fn encode_authorize_finalize_response(
    csil_v: &AuthorizeFinalizeResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_authorize_finalize_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AuthorizeFinalizeResponse.
pub fn decode_authorize_finalize_response(
    csil_data: &[u8],
) -> Result<AuthorizeFinalizeResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_authorize_finalize_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ApiError.
fn csil_enc_api_error(csil_v: &ApiError) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("code"), csil_enc_api_error_code(&csil_v.code)?));
    csil_entries.push((cbor_text("message"), cbor_text(&csil_v.message)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApiError from a decoded CBOR value tree.
fn csil_dec_api_error(csil_root: &CsilCborValue) -> Result<ApiError, CsilCborError> {
    cbor_check_record(csil_root)?;
    let code = {
        let csil_field = cbor_require(csil_root, "code")?;
        let csil_decode = csil_dec_api_error_code;
        csil_decode(csil_field)?
    };
    let message = {
        let csil_field = cbor_require(csil_root, "message")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ApiError { code, message })
}

/// Encode a ApiError to canonical CSIL CBOR bytes.
pub fn encode_api_error(csil_v: &ApiError) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_api_error(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApiError.
pub fn decode_api_error(csil_data: &[u8]) -> Result<ApiError, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_api_error(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpDescriptor.
fn csil_enc_local_rp_descriptor(
    csil_v: &LocalRpDescriptor,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("app_name"), cbor_text(&csil_v.app_name)));
    csil_entries.push((
        cbor_text("created_at"),
        csil_rt_enc_timestamp(&csil_v.created_at)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    csil_entries.push((
        cbor_text("supported_suites"),
        cbor_enc_array(&csil_v.supported_suites, csil_enc_aead_suite)?,
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
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a LocalRpDescriptor from a decoded CBOR value tree.
fn csil_dec_local_rp_descriptor(
    csil_root: &CsilCborValue,
) -> Result<LocalRpDescriptor, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_aead_suite);
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
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
pub fn encode_local_rp_descriptor(csil_v: &LocalRpDescriptor) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_local_rp_descriptor(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpDescriptor.
pub fn decode_local_rp_descriptor(csil_data: &[u8]) -> Result<LocalRpDescriptor, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_descriptor(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedLocalRpDescriptor.
fn csil_enc_signed_local_rp_descriptor(
    csil_v: &SignedLocalRpDescriptor,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((cbor_text("descriptor"), cbor_bytes(&csil_v.descriptor)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedLocalRpDescriptor from a decoded CBOR value tree.
fn csil_dec_signed_local_rp_descriptor(
    csil_root: &CsilCborValue,
) -> Result<SignedLocalRpDescriptor, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_signed_local_rp_descriptor(
    csil_v: &SignedLocalRpDescriptor,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_local_rp_descriptor(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedLocalRpDescriptor.
pub fn decode_signed_local_rp_descriptor(
    csil_data: &[u8],
) -> Result<SignedLocalRpDescriptor, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_local_rp_descriptor(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpLoginRequest.
fn csil_enc_local_rp_login_request(
    csil_v: &LocalRpLoginRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(10);
    csil_entries.push((cbor_text("nonce"), cbor_bytes(&csil_v.nonce)));
    csil_entries.push((cbor_text("state"), cbor_bytes(&csil_v.state)));
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((
        cbor_text("descriptor"),
        csil_enc_signed_local_rp_descriptor(&csil_v.descriptor)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("callback_url"), cbor_text(&csil_v.callback_url)));
    if let Some(csil_inner) = &csil_v.flow_context {
        csil_entries.push((
            cbor_text("flow_context"),
            csil_enc_auth_flow_context(csil_inner)?,
        ));
    }
    csil_entries.push((
        cbor_text("required_claims"),
        cbor_enc_array(&csil_v.required_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    csil_entries.push((
        cbor_text("requested_claims"),
        cbor_enc_array(&csil_v.requested_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    if let Some(csil_inner) = &csil_v.authentication_requirements {
        csil_entries.push((
            cbor_text("authentication_requirements"),
            csil_enc_authentication_requirements(csil_inner)?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a LocalRpLoginRequest from a decoded CBOR value tree.
fn csil_dec_local_rp_login_request(
    csil_root: &CsilCborValue,
) -> Result<LocalRpLoginRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let authentication_requirements = match cbor_map_get(csil_root, "authentication_requirements") {
        Some(csil_field) => {
            let csil_decode = csil_dec_authentication_requirements;
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
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(LocalRpLoginRequest {
        descriptor,
        callback_url,
        nonce,
        state,
        requested_claims,
        required_claims,
        authentication_requirements,
        flow_context,
        issued_at,
        expires_at,
    })
}

/// Encode a LocalRpLoginRequest to canonical CSIL CBOR bytes.
pub fn encode_local_rp_login_request(
    csil_v: &LocalRpLoginRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_local_rp_login_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpLoginRequest.
pub fn decode_local_rp_login_request(
    csil_data: &[u8],
) -> Result<LocalRpLoginRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_login_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedLocalRpLoginRequest.
fn csil_enc_signed_local_rp_login_request(
    csil_v: &SignedLocalRpLoginRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedLocalRpLoginRequest from a decoded CBOR value tree.
fn csil_dec_signed_local_rp_login_request(
    csil_root: &CsilCborValue,
) -> Result<SignedLocalRpLoginRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_signed_local_rp_login_request(
    csil_v: &SignedLocalRpLoginRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_local_rp_login_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedLocalRpLoginRequest.
pub fn decode_signed_local_rp_login_request(
    csil_data: &[u8],
) -> Result<SignedLocalRpLoginRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_local_rp_login_request(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpCallbackHeader.
fn csil_enc_local_rp_callback_header(
    csil_v: &LocalRpCallbackHeader,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("nonce"), cbor_bytes(&csil_v.nonce)));
    csil_entries.push((cbor_text("state"), cbor_bytes(&csil_v.state)));
    csil_entries.push((cbor_text("suite"), csil_enc_aead_suite(&csil_v.suite)?));
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((cbor_text("aead_nonce"), cbor_bytes(&csil_v.aead_nonce)));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    csil_entries.push((
        cbor_text("ephemeral_public_key"),
        cbor_bytes(&csil_v.ephemeral_public_key),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a LocalRpCallbackHeader from a decoded CBOR value tree.
fn csil_dec_local_rp_callback_header(
    csil_root: &CsilCborValue,
) -> Result<LocalRpCallbackHeader, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_dec_aead_suite;
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
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
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
pub fn encode_local_rp_callback_header(
    csil_v: &LocalRpCallbackHeader,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_local_rp_callback_header(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpCallbackHeader.
pub fn decode_local_rp_callback_header(
    csil_data: &[u8],
) -> Result<LocalRpCallbackHeader, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_callback_header(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpEncryptedCallback.
fn csil_enc_local_rp_encrypted_callback(
    csil_v: &LocalRpEncryptedCallback,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("header"), cbor_bytes(&csil_v.header)));
    csil_entries.push((cbor_text("ciphertext"), cbor_bytes(&csil_v.ciphertext)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a LocalRpEncryptedCallback from a decoded CBOR value tree.
fn csil_dec_local_rp_encrypted_callback(
    csil_root: &CsilCborValue,
) -> Result<LocalRpEncryptedCallback, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_local_rp_encrypted_callback(
    csil_v: &LocalRpEncryptedCallback,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_local_rp_encrypted_callback(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpEncryptedCallback.
pub fn decode_local_rp_encrypted_callback(
    csil_data: &[u8],
) -> Result<LocalRpEncryptedCallback, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_encrypted_callback(&csil_root)
}

/// Build the canonical CBOR value tree for a LocalRpCallbackPayload.
fn csil_enc_local_rp_callback_payload(
    csil_v: &LocalRpCallbackPayload,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((cbor_text("nonce"), cbor_bytes(&csil_v.nonce)));
    csil_entries.push((cbor_text("state"), cbor_bytes(&csil_v.state)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("user_domain"), cbor_text(&csil_v.user_domain)));
    csil_entries.push((cbor_text("callback_url"), cbor_text(&csil_v.callback_url)));
    csil_entries.push((cbor_text("claim_ticket"), cbor_bytes(&csil_v.claim_ticket)));
    csil_entries.push((
        cbor_text("audience_fingerprint"),
        cbor_text(&csil_v.audience_fingerprint),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a LocalRpCallbackPayload from a decoded CBOR value tree.
fn csil_dec_local_rp_callback_payload(
    csil_root: &CsilCborValue,
) -> Result<LocalRpCallbackPayload, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
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
pub fn encode_local_rp_callback_payload(
    csil_v: &LocalRpCallbackPayload,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_local_rp_callback_payload(csil_v)?;
    Ok(cbor_encode(&csil_tree))
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
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("payload"), cbor_bytes(&csil_v.payload)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((
        cbor_text("signing_key_id"),
        cbor_text(&csil_v.signing_key_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedLocalRpCallbackPayload from a decoded CBOR value tree.
fn csil_dec_signed_local_rp_callback_payload(
    csil_root: &CsilCborValue,
) -> Result<SignedLocalRpCallbackPayload, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_signed_local_rp_callback_payload(
    csil_v: &SignedLocalRpCallbackPayload,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_local_rp_callback_payload(csil_v)?;
    Ok(cbor_encode(&csil_tree))
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
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    csil_entries.push((cbor_text("claim_ticket"), cbor_bytes(&csil_v.claim_ticket)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a LocalRpTicketRedemptionRequest from a decoded CBOR value tree.
fn csil_dec_local_rp_ticket_redemption_request(
    csil_root: &CsilCborValue,
) -> Result<LocalRpTicketRedemptionRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
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
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_local_rp_ticket_redemption_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
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
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedLocalRpTicketRedemptionRequest from a decoded CBOR value tree.
fn csil_dec_signed_local_rp_ticket_redemption_request(
    csil_root: &CsilCborValue,
) -> Result<SignedLocalRpTicketRedemptionRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_local_rp_ticket_redemption_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
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
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((
        cbor_text("claims"),
        cbor_enc_array(&csil_v.claims, csil_enc_claim)?,
    ));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("user_domain"), cbor_text(&csil_v.user_domain)));
    csil_entries.push((
        cbor_text("ticket_expires_at"),
        csil_rt_enc_timestamp(&csil_v.ticket_expires_at)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a LocalRpTicketRedemptionResponse from a decoded CBOR value tree.
fn csil_dec_local_rp_ticket_redemption_response(
    csil_root: &CsilCborValue,
) -> Result<LocalRpTicketRedemptionResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_as_timestamp;
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
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_local_rp_ticket_redemption_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpTicketRedemptionResponse.
pub fn decode_local_rp_ticket_redemption_response(
    csil_data: &[u8],
) -> Result<LocalRpTicketRedemptionResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_ticket_redemption_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AdminLocalRp.
fn csil_enc_admin_local_rp(csil_v: &AdminLocalRp) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((
        cbor_text("status"),
        csil_enc_local_rp_status(&csil_v.status)?,
    ));
    csil_entries.push((cbor_text("app_name"), cbor_text(&csil_v.app_name)));
    csil_entries.push((
        cbor_text("created_at"),
        csil_rt_enc_timestamp(&csil_v.created_at)?,
    ));
    if let Some(csil_inner) = &csil_v.expires_at {
        csil_entries.push((cbor_text("expires_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    csil_entries.push((
        cbor_text("updated_at"),
        csil_rt_enc_timestamp(&csil_v.updated_at)?,
    ));
    if let Some(csil_inner) = &csil_v.admin_notes {
        csil_entries.push((cbor_text("admin_notes"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    if let Some(csil_inner) = &csil_v.last_seen_at {
        csil_entries.push((
            cbor_text("last_seen_at"),
            csil_rt_enc_timestamp(csil_inner)?,
        ));
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
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AdminLocalRp from a decoded CBOR value tree.
fn csil_dec_admin_local_rp(csil_root: &CsilCborValue) -> Result<AdminLocalRp, CsilCborError> {
    cbor_check_record(csil_root)?;
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
        let csil_decode = csil_dec_local_rp_status;
        csil_decode(csil_field)?
    };
    let created_at = {
        let csil_field = cbor_require(csil_root, "created_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let updated_at = {
        let csil_field = cbor_require(csil_root, "updated_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = match cbor_map_get(csil_root, "expires_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let last_seen_at = match cbor_map_get(csil_root, "last_seen_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
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
pub fn encode_admin_local_rp(csil_v: &AdminLocalRp) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_admin_local_rp(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AdminLocalRp.
pub fn decode_admin_local_rp(csil_data: &[u8]) -> Result<AdminLocalRp, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_admin_local_rp(&csil_root)
}

/// Build the canonical CBOR value tree for a ListLocalRpsRequest.
fn csil_enc_list_local_rps_request(
    csil_v: &ListLocalRpsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    if let Some(csil_inner) = &csil_v.limit {
        csil_entries.push((cbor_text("limit"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.offset {
        csil_entries.push((cbor_text("offset"), cbor_int(*csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.status {
        csil_entries.push((cbor_text("status"), csil_enc_local_rp_status(csil_inner)?));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListLocalRpsRequest from a decoded CBOR value tree.
fn csil_dec_list_local_rps_request(
    csil_root: &CsilCborValue,
) -> Result<ListLocalRpsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
            let csil_decode = csil_dec_local_rp_status;
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
pub fn encode_list_local_rps_request(
    csil_v: &ListLocalRpsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_local_rps_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListLocalRpsRequest.
pub fn decode_list_local_rps_request(
    csil_data: &[u8],
) -> Result<ListLocalRpsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_local_rps_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ListLocalRpsResponse.
fn csil_enc_list_local_rps_response(
    csil_v: &ListLocalRpsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("local_rps"),
        cbor_enc_array(&csil_v.local_rps, csil_enc_admin_local_rp)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListLocalRpsResponse from a decoded CBOR value tree.
fn csil_dec_list_local_rps_response(
    csil_root: &CsilCborValue,
) -> Result<ListLocalRpsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let local_rps = {
        let csil_field = cbor_require(csil_root, "local_rps")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_admin_local_rp);
        csil_decode(csil_field)?
    };
    Ok(ListLocalRpsResponse { local_rps })
}

/// Encode a ListLocalRpsResponse to canonical CSIL CBOR bytes.
pub fn encode_list_local_rps_response(
    csil_v: &ListLocalRpsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_local_rps_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListLocalRpsResponse.
pub fn decode_list_local_rps_response(
    csil_data: &[u8],
) -> Result<ListLocalRpsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_local_rps_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetLocalRpRequest.
fn csil_enc_get_local_rp_request(
    csil_v: &GetLocalRpRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetLocalRpRequest from a decoded CBOR value tree.
fn csil_dec_get_local_rp_request(
    csil_root: &CsilCborValue,
) -> Result<GetLocalRpRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let fingerprint = {
        let csil_field = cbor_require(csil_root, "fingerprint")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GetLocalRpRequest { fingerprint })
}

/// Encode a GetLocalRpRequest to canonical CSIL CBOR bytes.
pub fn encode_get_local_rp_request(csil_v: &GetLocalRpRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_local_rp_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetLocalRpRequest.
pub fn decode_get_local_rp_request(csil_data: &[u8]) -> Result<GetLocalRpRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_local_rp_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetLocalRpResponse.
fn csil_enc_get_local_rp_response(
    csil_v: &GetLocalRpResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("local_rp"),
        csil_enc_admin_local_rp(&csil_v.local_rp)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetLocalRpResponse from a decoded CBOR value tree.
fn csil_dec_get_local_rp_response(
    csil_root: &CsilCborValue,
) -> Result<GetLocalRpResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let local_rp = {
        let csil_field = cbor_require(csil_root, "local_rp")?;
        let csil_decode = csil_dec_admin_local_rp;
        csil_decode(csil_field)?
    };
    Ok(GetLocalRpResponse { local_rp })
}

/// Encode a GetLocalRpResponse to canonical CSIL CBOR bytes.
pub fn encode_get_local_rp_response(csil_v: &GetLocalRpResponse) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_local_rp_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetLocalRpResponse.
pub fn decode_get_local_rp_response(csil_data: &[u8]) -> Result<GetLocalRpResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_local_rp_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ApproveLocalRpRequest.
fn csil_enc_approve_local_rp_request(
    csil_v: &ApproveLocalRpRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.admin_notes {
        csil_entries.push((cbor_text("admin_notes"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApproveLocalRpRequest from a decoded CBOR value tree.
fn csil_dec_approve_local_rp_request(
    csil_root: &CsilCborValue,
) -> Result<ApproveLocalRpRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_approve_local_rp_request(
    csil_v: &ApproveLocalRpRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_approve_local_rp_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApproveLocalRpRequest.
pub fn decode_approve_local_rp_request(
    csil_data: &[u8],
) -> Result<ApproveLocalRpRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_approve_local_rp_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ApproveLocalRpResponse.
fn csil_enc_approve_local_rp_response(
    csil_v: &ApproveLocalRpResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("local_rp"),
        csil_enc_admin_local_rp(&csil_v.local_rp)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApproveLocalRpResponse from a decoded CBOR value tree.
fn csil_dec_approve_local_rp_response(
    csil_root: &CsilCborValue,
) -> Result<ApproveLocalRpResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let local_rp = {
        let csil_field = cbor_require(csil_root, "local_rp")?;
        let csil_decode = csil_dec_admin_local_rp;
        csil_decode(csil_field)?
    };
    Ok(ApproveLocalRpResponse { local_rp })
}

/// Encode a ApproveLocalRpResponse to canonical CSIL CBOR bytes.
pub fn encode_approve_local_rp_response(
    csil_v: &ApproveLocalRpResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_approve_local_rp_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApproveLocalRpResponse.
pub fn decode_approve_local_rp_response(
    csil_data: &[u8],
) -> Result<ApproveLocalRpResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_approve_local_rp_response(&csil_root)
}

/// Build the canonical CBOR value tree for a DenyLocalRpRequest.
fn csil_enc_deny_local_rp_request(
    csil_v: &DenyLocalRpRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.admin_notes {
        csil_entries.push((cbor_text("admin_notes"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DenyLocalRpRequest from a decoded CBOR value tree.
fn csil_dec_deny_local_rp_request(
    csil_root: &CsilCborValue,
) -> Result<DenyLocalRpRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_deny_local_rp_request(csil_v: &DenyLocalRpRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_deny_local_rp_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DenyLocalRpRequest.
pub fn decode_deny_local_rp_request(csil_data: &[u8]) -> Result<DenyLocalRpRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deny_local_rp_request(&csil_root)
}

/// Build the canonical CBOR value tree for a DenyLocalRpResponse.
fn csil_enc_deny_local_rp_response(
    csil_v: &DenyLocalRpResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("local_rp"),
        csil_enc_admin_local_rp(&csil_v.local_rp)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a DenyLocalRpResponse from a decoded CBOR value tree.
fn csil_dec_deny_local_rp_response(
    csil_root: &CsilCborValue,
) -> Result<DenyLocalRpResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let local_rp = {
        let csil_field = cbor_require(csil_root, "local_rp")?;
        let csil_decode = csil_dec_admin_local_rp;
        csil_decode(csil_field)?
    };
    Ok(DenyLocalRpResponse { local_rp })
}

/// Encode a DenyLocalRpResponse to canonical CSIL CBOR bytes.
pub fn encode_deny_local_rp_response(
    csil_v: &DenyLocalRpResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_deny_local_rp_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DenyLocalRpResponse.
pub fn decode_deny_local_rp_response(
    csil_data: &[u8],
) -> Result<DenyLocalRpResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_deny_local_rp_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeLocalRpRequest.
fn csil_enc_revoke_local_rp_request(
    csil_v: &RevokeLocalRpRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.admin_notes {
        csil_entries.push((cbor_text("admin_notes"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeLocalRpRequest from a decoded CBOR value tree.
fn csil_dec_revoke_local_rp_request(
    csil_root: &CsilCborValue,
) -> Result<RevokeLocalRpRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_revoke_local_rp_request(
    csil_v: &RevokeLocalRpRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_local_rp_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeLocalRpRequest.
pub fn decode_revoke_local_rp_request(
    csil_data: &[u8],
) -> Result<RevokeLocalRpRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_local_rp_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeLocalRpResponse.
fn csil_enc_revoke_local_rp_response(
    csil_v: &RevokeLocalRpResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("local_rp"),
        csil_enc_admin_local_rp(&csil_v.local_rp)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeLocalRpResponse from a decoded CBOR value tree.
fn csil_dec_revoke_local_rp_response(
    csil_root: &CsilCborValue,
) -> Result<RevokeLocalRpResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let local_rp = {
        let csil_field = cbor_require(csil_root, "local_rp")?;
        let csil_decode = csil_dec_admin_local_rp;
        csil_decode(csil_field)?
    };
    Ok(RevokeLocalRpResponse { local_rp })
}

/// Encode a RevokeLocalRpResponse to canonical CSIL CBOR bytes.
pub fn encode_revoke_local_rp_response(
    csil_v: &RevokeLocalRpResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_local_rp_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeLocalRpResponse.
pub fn decode_revoke_local_rp_response(
    csil_data: &[u8],
) -> Result<RevokeLocalRpResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_local_rp_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetLocalRpPolicyRequest.
fn csil_enc_get_local_rp_policy_request(
    _csil_v: &GetLocalRpPolicyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(CsilCborValue::Map(Vec::new()))
}

/// Reconstruct a GetLocalRpPolicyRequest from a decoded CBOR value tree.
fn csil_dec_get_local_rp_policy_request(
    csil_root: &CsilCborValue,
) -> Result<GetLocalRpPolicyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    Ok(GetLocalRpPolicyRequest {})
}

/// Encode a GetLocalRpPolicyRequest to canonical CSIL CBOR bytes.
pub fn encode_get_local_rp_policy_request(
    csil_v: &GetLocalRpPolicyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_local_rp_policy_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetLocalRpPolicyRequest.
pub fn decode_get_local_rp_policy_request(
    csil_data: &[u8],
) -> Result<GetLocalRpPolicyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_local_rp_policy_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetLocalRpPolicyResponse.
fn csil_enc_get_local_rp_policy_response(
    csil_v: &GetLocalRpPolicyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("policy"),
        csil_enc_local_rp_policy(&csil_v.policy)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetLocalRpPolicyResponse from a decoded CBOR value tree.
fn csil_dec_get_local_rp_policy_response(
    csil_root: &CsilCborValue,
) -> Result<GetLocalRpPolicyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let policy = {
        let csil_field = cbor_require(csil_root, "policy")?;
        let csil_decode = csil_dec_local_rp_policy;
        csil_decode(csil_field)?
    };
    Ok(GetLocalRpPolicyResponse { policy })
}

/// Encode a GetLocalRpPolicyResponse to canonical CSIL CBOR bytes.
pub fn encode_get_local_rp_policy_response(
    csil_v: &GetLocalRpPolicyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_local_rp_policy_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetLocalRpPolicyResponse.
pub fn decode_get_local_rp_policy_response(
    csil_data: &[u8],
) -> Result<GetLocalRpPolicyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_local_rp_policy_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetLocalRpPolicyRequest.
fn csil_enc_set_local_rp_policy_request(
    csil_v: &SetLocalRpPolicyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("policy"),
        csil_enc_local_rp_policy(&csil_v.policy)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetLocalRpPolicyRequest from a decoded CBOR value tree.
fn csil_dec_set_local_rp_policy_request(
    csil_root: &CsilCborValue,
) -> Result<SetLocalRpPolicyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let policy = {
        let csil_field = cbor_require(csil_root, "policy")?;
        let csil_decode = csil_dec_local_rp_policy;
        csil_decode(csil_field)?
    };
    Ok(SetLocalRpPolicyRequest { policy })
}

/// Encode a SetLocalRpPolicyRequest to canonical CSIL CBOR bytes.
pub fn encode_set_local_rp_policy_request(
    csil_v: &SetLocalRpPolicyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_local_rp_policy_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetLocalRpPolicyRequest.
pub fn decode_set_local_rp_policy_request(
    csil_data: &[u8],
) -> Result<SetLocalRpPolicyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_local_rp_policy_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetLocalRpPolicyResponse.
fn csil_enc_set_local_rp_policy_response(
    csil_v: &SetLocalRpPolicyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("policy"),
        csil_enc_local_rp_policy(&csil_v.policy)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetLocalRpPolicyResponse from a decoded CBOR value tree.
fn csil_dec_set_local_rp_policy_response(
    csil_root: &CsilCborValue,
) -> Result<SetLocalRpPolicyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let policy = {
        let csil_field = cbor_require(csil_root, "policy")?;
        let csil_decode = csil_dec_local_rp_policy;
        csil_decode(csil_field)?
    };
    Ok(SetLocalRpPolicyResponse { policy })
}

/// Encode a SetLocalRpPolicyResponse to canonical CSIL CBOR bytes.
pub fn encode_set_local_rp_policy_response(
    csil_v: &SetLocalRpPolicyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_local_rp_policy_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetLocalRpPolicyResponse.
pub fn decode_set_local_rp_policy_response(
    csil_data: &[u8],
) -> Result<SetLocalRpPolicyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_local_rp_policy_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SignInPolicy.
fn csil_enc_sign_in_policy(csil_v: &SignInPolicy) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("sign_in_hours"), cbor_int(csil_v.sign_in_hours)));
    csil_entries.push((
        cbor_text("max_sign_in_hours"),
        cbor_int(csil_v.max_sign_in_hours),
    ));
    csil_entries.push((
        cbor_text("min_sign_in_hours"),
        cbor_int(csil_v.min_sign_in_hours),
    ));
    csil_entries.push((
        cbor_text("default_sign_in_hours"),
        cbor_int(csil_v.default_sign_in_hours),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignInPolicy from a decoded CBOR value tree.
fn csil_dec_sign_in_policy(csil_root: &CsilCborValue) -> Result<SignInPolicy, CsilCborError> {
    cbor_check_record(csil_root)?;
    let sign_in_hours = {
        let csil_field = cbor_require(csil_root, "sign_in_hours")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let default_sign_in_hours = {
        let csil_field = cbor_require(csil_root, "default_sign_in_hours")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let min_sign_in_hours = {
        let csil_field = cbor_require(csil_root, "min_sign_in_hours")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let max_sign_in_hours = {
        let csil_field = cbor_require(csil_root, "max_sign_in_hours")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(SignInPolicy {
        sign_in_hours,
        default_sign_in_hours,
        min_sign_in_hours,
        max_sign_in_hours,
    })
}

/// Encode a SignInPolicy to canonical CSIL CBOR bytes.
pub fn encode_sign_in_policy(csil_v: &SignInPolicy) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_sign_in_policy(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignInPolicy.
pub fn decode_sign_in_policy(csil_data: &[u8]) -> Result<SignInPolicy, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_sign_in_policy(&csil_root)
}

/// Build the canonical CBOR value tree for a SetSignInPolicyRequest.
fn csil_enc_set_sign_in_policy_request(
    csil_v: &SetSignInPolicyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("sign_in_hours"), cbor_int(csil_v.sign_in_hours)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetSignInPolicyRequest from a decoded CBOR value tree.
fn csil_dec_set_sign_in_policy_request(
    csil_root: &CsilCborValue,
) -> Result<SetSignInPolicyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let sign_in_hours = {
        let csil_field = cbor_require(csil_root, "sign_in_hours")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(SetSignInPolicyRequest { sign_in_hours })
}

/// Encode a SetSignInPolicyRequest to canonical CSIL CBOR bytes.
pub fn encode_set_sign_in_policy_request(
    csil_v: &SetSignInPolicyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_sign_in_policy_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetSignInPolicyRequest.
pub fn decode_set_sign_in_policy_request(
    csil_data: &[u8],
) -> Result<SetSignInPolicyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_sign_in_policy_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetUserPasswordLockRequest.
fn csil_enc_set_user_password_lock_request(
    csil_v: &SetUserPasswordLockRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("locked"), cbor_bool(csil_v.locked)));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetUserPasswordLockRequest from a decoded CBOR value tree.
fn csil_dec_set_user_password_lock_request(
    csil_root: &CsilCborValue,
) -> Result<SetUserPasswordLockRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let locked = {
        let csil_field = cbor_require(csil_root, "locked")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(SetUserPasswordLockRequest { user_id, locked })
}

/// Encode a SetUserPasswordLockRequest to canonical CSIL CBOR bytes.
pub fn encode_set_user_password_lock_request(
    csil_v: &SetUserPasswordLockRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_user_password_lock_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetUserPasswordLockRequest.
pub fn decode_set_user_password_lock_request(
    csil_data: &[u8],
) -> Result<SetUserPasswordLockRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_user_password_lock_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetUserPasswordLockResponse.
fn csil_enc_set_user_password_lock_response(
    csil_v: &SetUserPasswordLockResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("user"), csil_enc_admin_user(&csil_v.user)?));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetUserPasswordLockResponse from a decoded CBOR value tree.
fn csil_dec_set_user_password_lock_response(
    csil_root: &CsilCborValue,
) -> Result<SetUserPasswordLockResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user = {
        let csil_field = cbor_require(csil_root, "user")?;
        let csil_decode = csil_dec_admin_user;
        csil_decode(csil_field)?
    };
    Ok(SetUserPasswordLockResponse { user })
}

/// Encode a SetUserPasswordLockResponse to canonical CSIL CBOR bytes.
pub fn encode_set_user_password_lock_response(
    csil_v: &SetUserPasswordLockResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_user_password_lock_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetUserPasswordLockResponse.
pub fn decode_set_user_password_lock_response(
    csil_data: &[u8],
) -> Result<SetUserPasswordLockResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_user_password_lock_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AppAccessTarget.
fn csil_enc_app_access_target(csil_v: &AppAccessTarget) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(6);
    csil_entries.push((
        cbor_text("kind"),
        csil_enc_app_access_target_kind(&csil_v.kind)?,
    ));
    if let Some(csil_inner) = &csil_v.user_id {
        csil_entries.push((cbor_text("user_id"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.claim_type {
        csil_entries.push((cbor_text("claim_type"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.group_name {
        csil_entries.push((cbor_text("group_name"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.claim_value {
        csil_entries.push((cbor_text("claim_value"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.claim_operator {
        csil_entries.push((
            cbor_text("claim_operator"),
            csil_enc_claim_operator(csil_inner)?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AppAccessTarget from a decoded CBOR value tree.
fn csil_dec_app_access_target(csil_root: &CsilCborValue) -> Result<AppAccessTarget, CsilCborError> {
    cbor_check_record(csil_root)?;
    let kind = {
        let csil_field = cbor_require(csil_root, "kind")?;
        let csil_decode = csil_dec_app_access_target_kind;
        csil_decode(csil_field)?
    };
    let user_id = match cbor_map_get(csil_root, "user_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let group_name = match cbor_map_get(csil_root, "group_name") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let claim_type = match cbor_map_get(csil_root, "claim_type") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let claim_operator = match cbor_map_get(csil_root, "claim_operator") {
        Some(csil_field) => {
            let csil_decode = csil_dec_claim_operator;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let claim_value = match cbor_map_get(csil_root, "claim_value") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(AppAccessTarget {
        kind,
        user_id,
        group_name,
        claim_type,
        claim_operator,
        claim_value,
    })
}

/// Encode a AppAccessTarget to canonical CSIL CBOR bytes.
pub fn encode_app_access_target(csil_v: &AppAccessTarget) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_app_access_target(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AppAccessTarget.
pub fn decode_app_access_target(csil_data: &[u8]) -> Result<AppAccessTarget, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_app_access_target(&csil_root)
}

/// Build the canonical CBOR value tree for a AppAccessPolicy.
fn csil_enc_app_access_policy(csil_v: &AppAccessPolicy) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(6);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    csil_entries.push((cbor_text("mode"), csil_enc_app_access_mode(&csil_v.mode)?));
    csil_entries.push((cbor_text("name"), cbor_text(&csil_v.name)));
    if let Some(csil_inner) = &csil_v.message {
        csil_entries.push((cbor_text("message"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("targets"),
        cbor_enc_array(&csil_v.targets, csil_enc_app_access_target)?,
    ));
    csil_entries.push((
        cbor_text("patterns"),
        cbor_enc_array(&csil_v.patterns, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AppAccessPolicy from a decoded CBOR value tree.
fn csil_dec_app_access_policy(csil_root: &CsilCborValue) -> Result<AppAccessPolicy, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let mode = {
        let csil_field = cbor_require(csil_root, "mode")?;
        let csil_decode = csil_dec_app_access_mode;
        csil_decode(csil_field)?
    };
    let patterns = {
        let csil_field = cbor_require(csil_root, "patterns")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let message = match cbor_map_get(csil_root, "message") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let targets = {
        let csil_field = cbor_require(csil_root, "targets")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_app_access_target);
        csil_decode(csil_field)?
    };
    Ok(AppAccessPolicy {
        id,
        name,
        mode,
        patterns,
        message,
        targets,
    })
}

/// Encode a AppAccessPolicy to canonical CSIL CBOR bytes.
pub fn encode_app_access_policy(csil_v: &AppAccessPolicy) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_app_access_policy(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AppAccessPolicy.
pub fn decode_app_access_policy(csil_data: &[u8]) -> Result<AppAccessPolicy, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_app_access_policy(&csil_root)
}

/// Build the canonical CBOR value tree for a ListAppAccessPoliciesResponse.
fn csil_enc_list_app_access_policies_response(
    csil_v: &ListAppAccessPoliciesResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("policies"),
        cbor_enc_array(&csil_v.policies, csil_enc_app_access_policy)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListAppAccessPoliciesResponse from a decoded CBOR value tree.
fn csil_dec_list_app_access_policies_response(
    csil_root: &CsilCborValue,
) -> Result<ListAppAccessPoliciesResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let policies = {
        let csil_field = cbor_require(csil_root, "policies")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_app_access_policy);
        csil_decode(csil_field)?
    };
    Ok(ListAppAccessPoliciesResponse { policies })
}

/// Encode a ListAppAccessPoliciesResponse to canonical CSIL CBOR bytes.
pub fn encode_list_app_access_policies_response(
    csil_v: &ListAppAccessPoliciesResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_app_access_policies_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListAppAccessPoliciesResponse.
pub fn decode_list_app_access_policies_response(
    csil_data: &[u8],
) -> Result<ListAppAccessPoliciesResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_app_access_policies_response(&csil_root)
}

/// Build the canonical CBOR value tree for a SetAppAccessPolicyRequest.
fn csil_enc_set_app_access_policy_request(
    csil_v: &SetAppAccessPolicyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(6);
    if let Some(csil_inner) = &csil_v.id {
        csil_entries.push((cbor_text("id"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("mode"), csil_enc_app_access_mode(&csil_v.mode)?));
    csil_entries.push((cbor_text("name"), cbor_text(&csil_v.name)));
    if let Some(csil_inner) = &csil_v.message {
        csil_entries.push((cbor_text("message"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("targets"),
        cbor_enc_array(&csil_v.targets, csil_enc_app_access_target)?,
    ));
    csil_entries.push((
        cbor_text("patterns"),
        cbor_enc_array(&csil_v.patterns, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetAppAccessPolicyRequest from a decoded CBOR value tree.
fn csil_dec_set_app_access_policy_request(
    csil_root: &CsilCborValue,
) -> Result<SetAppAccessPolicyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let id = match cbor_map_get(csil_root, "id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let name = {
        let csil_field = cbor_require(csil_root, "name")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let mode = {
        let csil_field = cbor_require(csil_root, "mode")?;
        let csil_decode = csil_dec_app_access_mode;
        csil_decode(csil_field)?
    };
    let patterns = {
        let csil_field = cbor_require(csil_root, "patterns")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let message = match cbor_map_get(csil_root, "message") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let targets = {
        let csil_field = cbor_require(csil_root, "targets")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_app_access_target);
        csil_decode(csil_field)?
    };
    Ok(SetAppAccessPolicyRequest {
        id,
        name,
        mode,
        patterns,
        message,
        targets,
    })
}

/// Encode a SetAppAccessPolicyRequest to canonical CSIL CBOR bytes.
pub fn encode_set_app_access_policy_request(
    csil_v: &SetAppAccessPolicyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_app_access_policy_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetAppAccessPolicyRequest.
pub fn decode_set_app_access_policy_request(
    csil_data: &[u8],
) -> Result<SetAppAccessPolicyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_app_access_policy_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SetAppAccessPolicyResponse.
fn csil_enc_set_app_access_policy_response(
    csil_v: &SetAppAccessPolicyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("policy"),
        csil_enc_app_access_policy(&csil_v.policy)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SetAppAccessPolicyResponse from a decoded CBOR value tree.
fn csil_dec_set_app_access_policy_response(
    csil_root: &CsilCborValue,
) -> Result<SetAppAccessPolicyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let policy = {
        let csil_field = cbor_require(csil_root, "policy")?;
        let csil_decode = csil_dec_app_access_policy;
        csil_decode(csil_field)?
    };
    Ok(SetAppAccessPolicyResponse { policy })
}

/// Encode a SetAppAccessPolicyResponse to canonical CSIL CBOR bytes.
pub fn encode_set_app_access_policy_response(
    csil_v: &SetAppAccessPolicyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_app_access_policy_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetAppAccessPolicyResponse.
pub fn decode_set_app_access_policy_response(
    csil_data: &[u8],
) -> Result<SetAppAccessPolicyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_app_access_policy_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveAppAccessPolicyRequest.
fn csil_enc_remove_app_access_policy_request(
    csil_v: &RemoveAppAccessPolicyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("id"), cbor_text(&csil_v.id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveAppAccessPolicyRequest from a decoded CBOR value tree.
fn csil_dec_remove_app_access_policy_request(
    csil_root: &CsilCborValue,
) -> Result<RemoveAppAccessPolicyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let id = {
        let csil_field = cbor_require(csil_root, "id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RemoveAppAccessPolicyRequest { id })
}

/// Encode a RemoveAppAccessPolicyRequest to canonical CSIL CBOR bytes.
pub fn encode_remove_app_access_policy_request(
    csil_v: &RemoveAppAccessPolicyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_app_access_policy_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveAppAccessPolicyRequest.
pub fn decode_remove_app_access_policy_request(
    csil_data: &[u8],
) -> Result<RemoveAppAccessPolicyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_app_access_policy_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RemoveAppAccessPolicyResponse.
fn csil_enc_remove_app_access_policy_response(
    csil_v: &RemoveAppAccessPolicyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("success"), cbor_bool(csil_v.success)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RemoveAppAccessPolicyResponse from a decoded CBOR value tree.
fn csil_dec_remove_app_access_policy_response(
    csil_root: &CsilCborValue,
) -> Result<RemoveAppAccessPolicyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let success = {
        let csil_field = cbor_require(csil_root, "success")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RemoveAppAccessPolicyResponse { success })
}

/// Encode a RemoveAppAccessPolicyResponse to canonical CSIL CBOR bytes.
pub fn encode_remove_app_access_policy_response(
    csil_v: &RemoveAppAccessPolicyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_remove_app_access_policy_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RemoveAppAccessPolicyResponse.
pub fn decode_remove_app_access_policy_response(
    csil_data: &[u8],
) -> Result<RemoveAppAccessPolicyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_remove_app_access_policy_response(&csil_root)
}

/// Build the canonical CBOR value tree for a PreviewAppAccessRequest.
fn csil_enc_preview_app_access_request(
    csil_v: &PreviewAppAccessRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.domain {
        csil_entries.push((cbor_text("domain"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PreviewAppAccessRequest from a decoded CBOR value tree.
fn csil_dec_preview_app_access_request(
    csil_root: &CsilCborValue,
) -> Result<PreviewAppAccessRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let user_id = {
        let csil_field = cbor_require(csil_root, "user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let domain = match cbor_map_get(csil_root, "domain") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(PreviewAppAccessRequest { user_id, domain })
}

/// Encode a PreviewAppAccessRequest to canonical CSIL CBOR bytes.
pub fn encode_preview_app_access_request(
    csil_v: &PreviewAppAccessRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_preview_app_access_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PreviewAppAccessRequest.
pub fn decode_preview_app_access_request(
    csil_data: &[u8],
) -> Result<PreviewAppAccessRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_preview_app_access_request(&csil_root)
}

/// Build the canonical CBOR value tree for a PreviewAppAccessResponse.
fn csil_enc_preview_app_access_response(
    csil_v: &PreviewAppAccessResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("allowed"), cbor_bool(csil_v.allowed)));
    csil_entries.push((
        cbor_text("messages"),
        cbor_enc_array(&csil_v.messages, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("applied_policies"),
        cbor_enc_array(&csil_v.applied_policies, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    csil_entries.push((
        cbor_text("blocking_policies"),
        cbor_enc_array(&csil_v.blocking_policies, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PreviewAppAccessResponse from a decoded CBOR value tree.
fn csil_dec_preview_app_access_response(
    csil_root: &CsilCborValue,
) -> Result<PreviewAppAccessResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let allowed = {
        let csil_field = cbor_require(csil_root, "allowed")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let applied_policies = {
        let csil_field = cbor_require(csil_root, "applied_policies")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let blocking_policies = {
        let csil_field = cbor_require(csil_root, "blocking_policies")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let messages = {
        let csil_field = cbor_require(csil_root, "messages")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(PreviewAppAccessResponse {
        allowed,
        applied_policies,
        blocking_policies,
        messages,
    })
}

/// Encode a PreviewAppAccessResponse to canonical CSIL CBOR bytes.
pub fn encode_preview_app_access_response(
    csil_v: &PreviewAppAccessResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_preview_app_access_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PreviewAppAccessResponse.
pub fn decode_preview_app_access_response(
    csil_data: &[u8],
) -> Result<PreviewAppAccessResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_preview_app_access_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AppAccessDenial.
fn csil_enc_app_access_denial(csil_v: &AppAccessDenial) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.domain {
        csil_entries.push((cbor_text("domain"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("messages"),
        cbor_enc_array(&csil_v.messages, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AppAccessDenial from a decoded CBOR value tree.
fn csil_dec_app_access_denial(csil_root: &CsilCborValue) -> Result<AppAccessDenial, CsilCborError> {
    cbor_check_record(csil_root)?;
    let domain = match cbor_map_get(csil_root, "domain") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let messages = {
        let csil_field = cbor_require(csil_root, "messages")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(AppAccessDenial { domain, messages })
}

/// Encode a AppAccessDenial to canonical CSIL CBOR bytes.
pub fn encode_app_access_denial(csil_v: &AppAccessDenial) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_app_access_denial(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AppAccessDenial.
pub fn decode_app_access_denial(csil_data: &[u8]) -> Result<AppAccessDenial, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_app_access_denial(&csil_root)
}

/// Build the canonical CBOR value tree for a PurgeLocalRpTicketsRequest.
fn csil_enc_purge_local_rp_tickets_request(
    _csil_v: &PurgeLocalRpTicketsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(CsilCborValue::Map(Vec::new()))
}

/// Reconstruct a PurgeLocalRpTicketsRequest from a decoded CBOR value tree.
fn csil_dec_purge_local_rp_tickets_request(
    csil_root: &CsilCborValue,
) -> Result<PurgeLocalRpTicketsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    Ok(PurgeLocalRpTicketsRequest {})
}

/// Encode a PurgeLocalRpTicketsRequest to canonical CSIL CBOR bytes.
pub fn encode_purge_local_rp_tickets_request(
    csil_v: &PurgeLocalRpTicketsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_purge_local_rp_tickets_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PurgeLocalRpTicketsRequest.
pub fn decode_purge_local_rp_tickets_request(
    csil_data: &[u8],
) -> Result<PurgeLocalRpTicketsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_purge_local_rp_tickets_request(&csil_root)
}

/// Build the canonical CBOR value tree for a PurgeLocalRpTicketsResponse.
fn csil_enc_purge_local_rp_tickets_response(
    csil_v: &PurgeLocalRpTicketsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("purged_count"), cbor_int(csil_v.purged_count)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PurgeLocalRpTicketsResponse from a decoded CBOR value tree.
fn csil_dec_purge_local_rp_tickets_response(
    csil_root: &CsilCborValue,
) -> Result<PurgeLocalRpTicketsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let purged_count = {
        let csil_field = cbor_require(csil_root, "purged_count")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(PurgeLocalRpTicketsResponse { purged_count })
}

/// Encode a PurgeLocalRpTicketsResponse to canonical CSIL CBOR bytes.
pub fn encode_purge_local_rp_tickets_response(
    csil_v: &PurgeLocalRpTicketsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_purge_local_rp_tickets_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PurgeLocalRpTicketsResponse.
pub fn decode_purge_local_rp_tickets_response(
    csil_data: &[u8],
) -> Result<PurgeLocalRpTicketsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_purge_local_rp_tickets_response(&csil_root)
}

/// Build the canonical CBOR value tree for a TranslationsRequest.
fn csil_enc_translations_request(
    csil_v: &TranslationsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.locale {
        csil_entries.push((cbor_text("locale"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.accept_language {
        csil_entries.push((cbor_text("accept_language"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a TranslationsRequest from a decoded CBOR value tree.
fn csil_dec_translations_request(
    csil_root: &CsilCborValue,
) -> Result<TranslationsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_translations_request(csil_v: &TranslationsRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_translations_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a TranslationsRequest.
pub fn decode_translations_request(csil_data: &[u8]) -> Result<TranslationsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_translations_request(&csil_root)
}

/// Build the canonical CBOR value tree for a TranslationsResponse.
fn csil_enc_translations_response(
    csil_v: &TranslationsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("locale"), cbor_text(&csil_v.locale)));
    csil_entries.push((
        cbor_text("messages"),
        cbor_enc_map(
            &csil_v.messages,
            |csil_mk| Ok(cbor_text(csil_mk)),
            |csil_mv| Ok(cbor_text(csil_mv)),
        )?,
    ));
    csil_entries.push((
        cbor_text("available_locales"),
        cbor_enc_array(&csil_v.available_locales, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a TranslationsResponse from a decoded CBOR value tree.
fn csil_dec_translations_response(
    csil_root: &CsilCborValue,
) -> Result<TranslationsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
pub fn encode_translations_response(
    csil_v: &TranslationsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_translations_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a TranslationsResponse.
pub fn decode_translations_response(
    csil_data: &[u8],
) -> Result<TranslationsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_translations_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ListLocalesResponse.
fn csil_enc_list_locales_response(
    csil_v: &ListLocalesResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("available_locales"),
        cbor_enc_array(&csil_v.available_locales, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListLocalesResponse from a decoded CBOR value tree.
fn csil_dec_list_locales_response(
    csil_root: &CsilCborValue,
) -> Result<ListLocalesResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let available_locales = {
        let csil_field = cbor_require(csil_root, "available_locales")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(ListLocalesResponse { available_locales })
}

/// Encode a ListLocalesResponse to canonical CSIL CBOR bytes.
pub fn encode_list_locales_response(
    csil_v: &ListLocalesResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_locales_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListLocalesResponse.
pub fn decode_list_locales_response(
    csil_data: &[u8],
) -> Result<ListLocalesResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_locales_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ApplicationKeySignature.
fn csil_enc_application_key_signature(
    csil_v: &ApplicationKeySignature,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("signature"), cbor_bytes(&csil_v.signature)));
    csil_entries.push((
        cbor_text("signed_by_key_id"),
        cbor_text(&csil_v.signed_by_key_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApplicationKeySignature from a decoded CBOR value tree.
fn csil_dec_application_key_signature(
    csil_root: &CsilCborValue,
) -> Result<ApplicationKeySignature, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    Ok(ApplicationKeySignature {
        signed_by_key_id,
        signature,
    })
}

/// Encode a ApplicationKeySignature to canonical CSIL CBOR bytes.
pub fn encode_application_key_signature(
    csil_v: &ApplicationKeySignature,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_application_key_signature(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApplicationKeySignature.
pub fn decode_application_key_signature(
    csil_data: &[u8],
) -> Result<ApplicationKeySignature, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_application_key_signature(&csil_root)
}

/// Build the canonical CBOR value tree for a ApplicationKeyAttestation.
fn csil_enc_application_key_attestation(
    csil_v: &ApplicationKeyAttestation,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(13);
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    csil_entries.push((
        cbor_text("algorithm"),
        csil_enc_key_algorithm(&csil_v.algorithm)?,
    ));
    csil_entries.push((
        cbor_text("key_usage"),
        csil_enc_key_usage(&csil_v.key_usage)?,
    ));
    csil_entries.push((cbor_text("public_key"), cbor_bytes(&csil_v.public_key)));
    csil_entries.push((
        cbor_text("attested_at"),
        csil_rt_enc_timestamp(&csil_v.attested_at)?,
    ));
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("key_created_at"),
        csil_rt_enc_timestamp(&csil_v.key_created_at)?,
    ));
    csil_entries.push((
        cbor_text("key_expires_at"),
        csil_rt_enc_timestamp(&csil_v.key_expires_at)?,
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    csil_entries.push((
        cbor_text("attestation_expires_at"),
        csil_rt_enc_timestamp(&csil_v.attestation_expires_at)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApplicationKeyAttestation from a decoded CBOR value tree.
fn csil_dec_application_key_attestation(
    csil_root: &CsilCborValue,
) -> Result<ApplicationKeyAttestation, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let key_id = {
        let csil_field = cbor_require(csil_root, "key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let key_usage = {
        let csil_field = cbor_require(csil_root, "key_usage")?;
        let csil_decode = csil_dec_key_usage;
        csil_decode(csil_field)?
    };
    let algorithm = {
        let csil_field = cbor_require(csil_root, "algorithm")?;
        let csil_decode = csil_dec_key_algorithm;
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
    let key_created_at = {
        let csil_field = cbor_require(csil_root, "key_created_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let key_expires_at = {
        let csil_field = cbor_require(csil_root, "key_expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let attested_at = {
        let csil_field = cbor_require(csil_root, "attested_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let attestation_expires_at = {
        let csil_field = cbor_require(csil_root, "attestation_expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(ApplicationKeyAttestation {
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
        key_id,
        key_usage,
        algorithm,
        public_key,
        fingerprint,
        key_created_at,
        key_expires_at,
        attested_at,
        attestation_expires_at,
    })
}

/// Encode a ApplicationKeyAttestation to canonical CSIL CBOR bytes.
pub fn encode_application_key_attestation(
    csil_v: &ApplicationKeyAttestation,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_application_key_attestation(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApplicationKeyAttestation.
pub fn decode_application_key_attestation(
    csil_data: &[u8],
) -> Result<ApplicationKeyAttestation, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_application_key_attestation(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedApplicationKeyAttestation.
fn csil_enc_signed_application_key_attestation(
    csil_v: &SignedApplicationKeyAttestation,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature)?,
    ));
    csil_entries.push((cbor_text("attestation"), cbor_bytes(&csil_v.attestation)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedApplicationKeyAttestation from a decoded CBOR value tree.
fn csil_dec_signed_application_key_attestation(
    csil_root: &CsilCborValue,
) -> Result<SignedApplicationKeyAttestation, CsilCborError> {
    cbor_check_record(csil_root)?;
    let attestation = {
        let csil_field = cbor_require(csil_root, "attestation")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_signature);
        csil_decode(csil_field)?
    };
    Ok(SignedApplicationKeyAttestation {
        attestation,
        signatures,
    })
}

/// Encode a SignedApplicationKeyAttestation to canonical CSIL CBOR bytes.
pub fn encode_signed_application_key_attestation(
    csil_v: &SignedApplicationKeyAttestation,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_application_key_attestation(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedApplicationKeyAttestation.
pub fn decode_signed_application_key_attestation(
    csil_data: &[u8],
) -> Result<SignedApplicationKeyAttestation, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_application_key_attestation(&csil_root)
}

/// Build the canonical CBOR value tree for a ApplicationKeyAddition.
fn csil_enc_application_key_addition(
    csil_v: &ApplicationKeyAddition,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(14);
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    csil_entries.push((
        cbor_text("algorithm"),
        csil_enc_key_algorithm(&csil_v.algorithm)?,
    ));
    csil_entries.push((cbor_text("challenge"), cbor_bytes(&csil_v.challenge)));
    csil_entries.push((
        cbor_text("key_usage"),
        csil_enc_key_usage(&csil_v.key_usage)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("public_key"), cbor_bytes(&csil_v.public_key)));
    csil_entries.push((cbor_text("fingerprint"), cbor_text(&csil_v.fingerprint)));
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((cbor_text("challenge_id"), cbor_text(&csil_v.challenge_id)));
    csil_entries.push((
        cbor_text("requested_at"),
        csil_rt_enc_timestamp(&csil_v.requested_at)?,
    ));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    csil_entries.push((
        cbor_text("requested_key_lifetime_seconds"),
        cbor_int(csil_v.requested_key_lifetime_seconds),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApplicationKeyAddition from a decoded CBOR value tree.
fn csil_dec_application_key_addition(
    csil_root: &CsilCborValue,
) -> Result<ApplicationKeyAddition, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let key_id = {
        let csil_field = cbor_require(csil_root, "key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let key_usage = {
        let csil_field = cbor_require(csil_root, "key_usage")?;
        let csil_decode = csil_dec_key_usage;
        csil_decode(csil_field)?
    };
    let algorithm = {
        let csil_field = cbor_require(csil_root, "algorithm")?;
        let csil_decode = csil_dec_key_algorithm;
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
    let requested_key_lifetime_seconds = {
        let csil_field = cbor_require(csil_root, "requested_key_lifetime_seconds")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let challenge_id = {
        let csil_field = cbor_require(csil_root, "challenge_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let challenge = {
        let csil_field = cbor_require(csil_root, "challenge")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let requested_at = {
        let csil_field = cbor_require(csil_root, "requested_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(ApplicationKeyAddition {
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
        key_id,
        key_usage,
        algorithm,
        public_key,
        fingerprint,
        requested_key_lifetime_seconds,
        challenge_id,
        challenge,
        requested_at,
        expires_at,
    })
}

/// Encode a ApplicationKeyAddition to canonical CSIL CBOR bytes.
pub fn encode_application_key_addition(
    csil_v: &ApplicationKeyAddition,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_application_key_addition(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApplicationKeyAddition.
pub fn decode_application_key_addition(
    csil_data: &[u8],
) -> Result<ApplicationKeyAddition, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_application_key_addition(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedApplicationKeyAddition.
fn csil_enc_signed_application_key_addition(
    csil_v: &SignedApplicationKeyAddition,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("addition"), cbor_bytes(&csil_v.addition)));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_application_key_signature)?,
    ));
    if let Some(csil_inner) = &csil_v.possession_proof {
        csil_entries.push((cbor_text("possession_proof"), cbor_bytes(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedApplicationKeyAddition from a decoded CBOR value tree.
fn csil_dec_signed_application_key_addition(
    csil_root: &CsilCborValue,
) -> Result<SignedApplicationKeyAddition, CsilCborError> {
    cbor_check_record(csil_root)?;
    let addition = {
        let csil_field = cbor_require(csil_root, "addition")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_application_key_signature);
        csil_decode(csil_field)?
    };
    let possession_proof = match cbor_map_get(csil_root, "possession_proof") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bytes;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(SignedApplicationKeyAddition {
        addition,
        signatures,
        possession_proof,
    })
}

/// Encode a SignedApplicationKeyAddition to canonical CSIL CBOR bytes.
pub fn encode_signed_application_key_addition(
    csil_v: &SignedApplicationKeyAddition,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_application_key_addition(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedApplicationKeyAddition.
pub fn decode_signed_application_key_addition(
    csil_data: &[u8],
) -> Result<SignedApplicationKeyAddition, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_application_key_addition(&csil_root)
}

/// Build the canonical CBOR value tree for a ApplicationKeyRenewal.
fn csil_enc_application_key_renewal(
    csil_v: &ApplicationKeyRenewal,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((cbor_text("key_id"), cbor_text(&csil_v.key_id)));
    csil_entries.push((cbor_text("challenge"), cbor_bytes(&csil_v.challenge)));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((cbor_text("challenge_id"), cbor_text(&csil_v.challenge_id)));
    csil_entries.push((
        cbor_text("requested_at"),
        csil_rt_enc_timestamp(&csil_v.requested_at)?,
    ));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApplicationKeyRenewal from a decoded CBOR value tree.
fn csil_dec_application_key_renewal(
    csil_root: &CsilCborValue,
) -> Result<ApplicationKeyRenewal, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let key_id = {
        let csil_field = cbor_require(csil_root, "key_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let challenge_id = {
        let csil_field = cbor_require(csil_root, "challenge_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let challenge = {
        let csil_field = cbor_require(csil_root, "challenge")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let requested_at = {
        let csil_field = cbor_require(csil_root, "requested_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(ApplicationKeyRenewal {
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
        key_id,
        challenge_id,
        challenge,
        requested_at,
        expires_at,
    })
}

/// Encode a ApplicationKeyRenewal to canonical CSIL CBOR bytes.
pub fn encode_application_key_renewal(
    csil_v: &ApplicationKeyRenewal,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_application_key_renewal(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApplicationKeyRenewal.
pub fn decode_application_key_renewal(
    csil_data: &[u8],
) -> Result<ApplicationKeyRenewal, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_application_key_renewal(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedApplicationKeyRenewal.
fn csil_enc_signed_application_key_renewal(
    csil_v: &SignedApplicationKeyRenewal,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("renewal"), cbor_bytes(&csil_v.renewal)));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_application_key_signature)?,
    ));
    if let Some(csil_inner) = &csil_v.possession_proof {
        csil_entries.push((cbor_text("possession_proof"), cbor_bytes(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedApplicationKeyRenewal from a decoded CBOR value tree.
fn csil_dec_signed_application_key_renewal(
    csil_root: &CsilCborValue,
) -> Result<SignedApplicationKeyRenewal, CsilCborError> {
    cbor_check_record(csil_root)?;
    let renewal = {
        let csil_field = cbor_require(csil_root, "renewal")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_application_key_signature);
        csil_decode(csil_field)?
    };
    let possession_proof = match cbor_map_get(csil_root, "possession_proof") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bytes;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(SignedApplicationKeyRenewal {
        renewal,
        signatures,
        possession_proof,
    })
}

/// Encode a SignedApplicationKeyRenewal to canonical CSIL CBOR bytes.
pub fn encode_signed_application_key_renewal(
    csil_v: &SignedApplicationKeyRenewal,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_application_key_renewal(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedApplicationKeyRenewal.
pub fn decode_signed_application_key_renewal(
    csil_data: &[u8],
) -> Result<SignedApplicationKeyRenewal, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_application_key_renewal(&csil_root)
}

/// Build the canonical CBOR value tree for a ApplicationKeyRevocation.
fn csil_enc_application_key_revocation(
    csil_v: &ApplicationKeyRevocation,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((
        cbor_text("revoked_at"),
        csil_rt_enc_timestamp(&csil_v.revoked_at)?,
    ));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_application_key_signature)?,
    ));
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((cbor_text("target_key_id"), cbor_text(&csil_v.target_key_id)));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    csil_entries.push((
        cbor_text("target_fingerprint"),
        cbor_text(&csil_v.target_fingerprint),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApplicationKeyRevocation from a decoded CBOR value tree.
fn csil_dec_application_key_revocation(
    csil_root: &CsilCborValue,
) -> Result<ApplicationKeyRevocation, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
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
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_application_key_signature);
        csil_decode(csil_field)?
    };
    Ok(ApplicationKeyRevocation {
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
        target_key_id,
        target_fingerprint,
        revoked_at,
        signatures,
    })
}

/// Encode a ApplicationKeyRevocation to canonical CSIL CBOR bytes.
pub fn encode_application_key_revocation(
    csil_v: &ApplicationKeyRevocation,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_application_key_revocation(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApplicationKeyRevocation.
pub fn decode_application_key_revocation(
    csil_data: &[u8],
) -> Result<ApplicationKeyRevocation, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_application_key_revocation(&csil_root)
}

/// Build the canonical CBOR value tree for a StartApplicationKeyChallengeRequest.
fn csil_enc_start_application_key_challenge_request(
    csil_v: &StartApplicationKeyChallengeRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(7);
    csil_entries.push((
        cbor_text("purpose"),
        csil_enc_application_key_challenge_purpose(&csil_v.purpose)?,
    ));
    csil_entries.push((
        cbor_text("algorithm"),
        csil_enc_key_algorithm(&csil_v.algorithm)?,
    ));
    csil_entries.push((
        cbor_text("key_usage"),
        csil_enc_key_usage(&csil_v.key_usage)?,
    ));
    csil_entries.push((cbor_text("public_key"), cbor_bytes(&csil_v.public_key)));
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a StartApplicationKeyChallengeRequest from a decoded CBOR value tree.
fn csil_dec_start_application_key_challenge_request(
    csil_root: &CsilCborValue,
) -> Result<StartApplicationKeyChallengeRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let subject_user_id = {
        let csil_field = cbor_require(csil_root, "subject_user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let purpose = {
        let csil_field = cbor_require(csil_root, "purpose")?;
        let csil_decode = csil_dec_application_key_challenge_purpose;
        csil_decode(csil_field)?
    };
    let key_usage = {
        let csil_field = cbor_require(csil_root, "key_usage")?;
        let csil_decode = csil_dec_key_usage;
        csil_decode(csil_field)?
    };
    let algorithm = {
        let csil_field = cbor_require(csil_root, "algorithm")?;
        let csil_decode = csil_dec_key_algorithm;
        csil_decode(csil_field)?
    };
    let public_key = {
        let csil_field = cbor_require(csil_root, "public_key")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(StartApplicationKeyChallengeRequest {
        subject_user_id,
        application_id,
        instance_id,
        purpose,
        key_usage,
        algorithm,
        public_key,
    })
}

/// Encode a StartApplicationKeyChallengeRequest to canonical CSIL CBOR bytes.
pub fn encode_start_application_key_challenge_request(
    csil_v: &StartApplicationKeyChallengeRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_start_application_key_challenge_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a StartApplicationKeyChallengeRequest.
pub fn decode_start_application_key_challenge_request(
    csil_data: &[u8],
) -> Result<StartApplicationKeyChallengeRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_start_application_key_challenge_request(&csil_root)
}

/// Build the canonical CBOR value tree for a StartApplicationKeyChallengeResponse.
fn csil_enc_start_application_key_challenge_response(
    csil_v: &StartApplicationKeyChallengeResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    if let Some(csil_inner) = &csil_v.challenge {
        csil_entries.push((cbor_text("challenge"), cbor_bytes(csil_inner)));
    }
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("challenge_id"), cbor_text(&csil_v.challenge_id)));
    if let Some(csil_inner) = &csil_v.sealed_challenge {
        csil_entries.push((cbor_text("sealed_challenge"), cbor_bytes(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a StartApplicationKeyChallengeResponse from a decoded CBOR value tree.
fn csil_dec_start_application_key_challenge_response(
    csil_root: &CsilCborValue,
) -> Result<StartApplicationKeyChallengeResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let challenge_id = {
        let csil_field = cbor_require(csil_root, "challenge_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let challenge = match cbor_map_get(csil_root, "challenge") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bytes;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let sealed_challenge = match cbor_map_get(csil_root, "sealed_challenge") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bytes;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(StartApplicationKeyChallengeResponse {
        challenge_id,
        challenge,
        sealed_challenge,
        expires_at,
    })
}

/// Encode a StartApplicationKeyChallengeResponse to canonical CSIL CBOR bytes.
pub fn encode_start_application_key_challenge_response(
    csil_v: &StartApplicationKeyChallengeResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_start_application_key_challenge_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a StartApplicationKeyChallengeResponse.
pub fn decode_start_application_key_challenge_response(
    csil_data: &[u8],
) -> Result<StartApplicationKeyChallengeResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_start_application_key_challenge_response(&csil_root)
}

/// Build the canonical CBOR value tree for a AddApplicationKeyRequest.
fn csil_enc_add_application_key_request(
    csil_v: &AddApplicationKeyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("request"),
        csil_enc_signed_application_key_addition(&csil_v.request)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AddApplicationKeyRequest from a decoded CBOR value tree.
fn csil_dec_add_application_key_request(
    csil_root: &CsilCborValue,
) -> Result<AddApplicationKeyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = csil_dec_signed_application_key_addition;
        csil_decode(csil_field)?
    };
    Ok(AddApplicationKeyRequest { request })
}

/// Encode a AddApplicationKeyRequest to canonical CSIL CBOR bytes.
pub fn encode_add_application_key_request(
    csil_v: &AddApplicationKeyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_add_application_key_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AddApplicationKeyRequest.
pub fn decode_add_application_key_request(
    csil_data: &[u8],
) -> Result<AddApplicationKeyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_add_application_key_request(&csil_root)
}

/// Build the canonical CBOR value tree for a AddApplicationKeyResponse.
fn csil_enc_add_application_key_response(
    csil_v: &AddApplicationKeyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("attestation"),
        csil_enc_signed_application_key_attestation(&csil_v.attestation)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a AddApplicationKeyResponse from a decoded CBOR value tree.
fn csil_dec_add_application_key_response(
    csil_root: &CsilCborValue,
) -> Result<AddApplicationKeyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let attestation = {
        let csil_field = cbor_require(csil_root, "attestation")?;
        let csil_decode = csil_dec_signed_application_key_attestation;
        csil_decode(csil_field)?
    };
    Ok(AddApplicationKeyResponse { attestation })
}

/// Encode a AddApplicationKeyResponse to canonical CSIL CBOR bytes.
pub fn encode_add_application_key_response(
    csil_v: &AddApplicationKeyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_add_application_key_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AddApplicationKeyResponse.
pub fn decode_add_application_key_response(
    csil_data: &[u8],
) -> Result<AddApplicationKeyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_add_application_key_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RenewApplicationKeyAttestationRequest.
fn csil_enc_renew_application_key_attestation_request(
    csil_v: &RenewApplicationKeyAttestationRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("request"),
        csil_enc_signed_application_key_renewal(&csil_v.request)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RenewApplicationKeyAttestationRequest from a decoded CBOR value tree.
fn csil_dec_renew_application_key_attestation_request(
    csil_root: &CsilCborValue,
) -> Result<RenewApplicationKeyAttestationRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = csil_dec_signed_application_key_renewal;
        csil_decode(csil_field)?
    };
    Ok(RenewApplicationKeyAttestationRequest { request })
}

/// Encode a RenewApplicationKeyAttestationRequest to canonical CSIL CBOR bytes.
pub fn encode_renew_application_key_attestation_request(
    csil_v: &RenewApplicationKeyAttestationRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_renew_application_key_attestation_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RenewApplicationKeyAttestationRequest.
pub fn decode_renew_application_key_attestation_request(
    csil_data: &[u8],
) -> Result<RenewApplicationKeyAttestationRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_renew_application_key_attestation_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RenewApplicationKeyAttestationResponse.
fn csil_enc_renew_application_key_attestation_response(
    csil_v: &RenewApplicationKeyAttestationResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("signed"), cbor_bool(csil_v.signed)));
    csil_entries.push((
        cbor_text("attestation"),
        csil_enc_signed_application_key_attestation(&csil_v.attestation)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RenewApplicationKeyAttestationResponse from a decoded CBOR value tree.
fn csil_dec_renew_application_key_attestation_response(
    csil_root: &CsilCborValue,
) -> Result<RenewApplicationKeyAttestationResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let attestation = {
        let csil_field = cbor_require(csil_root, "attestation")?;
        let csil_decode = csil_dec_signed_application_key_attestation;
        csil_decode(csil_field)?
    };
    let signed = {
        let csil_field = cbor_require(csil_root, "signed")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RenewApplicationKeyAttestationResponse {
        attestation,
        signed,
    })
}

/// Encode a RenewApplicationKeyAttestationResponse to canonical CSIL CBOR bytes.
pub fn encode_renew_application_key_attestation_response(
    csil_v: &RenewApplicationKeyAttestationResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_renew_application_key_attestation_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RenewApplicationKeyAttestationResponse.
pub fn decode_renew_application_key_attestation_response(
    csil_data: &[u8],
) -> Result<RenewApplicationKeyAttestationResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_renew_application_key_attestation_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeApplicationKeyRequest.
fn csil_enc_revoke_application_key_request(
    csil_v: &RevokeApplicationKeyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("revocation"),
        csil_enc_application_key_revocation(&csil_v.revocation)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeApplicationKeyRequest from a decoded CBOR value tree.
fn csil_dec_revoke_application_key_request(
    csil_root: &CsilCborValue,
) -> Result<RevokeApplicationKeyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let revocation = {
        let csil_field = cbor_require(csil_root, "revocation")?;
        let csil_decode = csil_dec_application_key_revocation;
        csil_decode(csil_field)?
    };
    Ok(RevokeApplicationKeyRequest { revocation })
}

/// Encode a RevokeApplicationKeyRequest to canonical CSIL CBOR bytes.
pub fn encode_revoke_application_key_request(
    csil_v: &RevokeApplicationKeyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_application_key_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeApplicationKeyRequest.
pub fn decode_revoke_application_key_request(
    csil_data: &[u8],
) -> Result<RevokeApplicationKeyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_application_key_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeApplicationKeyResponse.
fn csil_enc_revoke_application_key_response(
    csil_v: &RevokeApplicationKeyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("revoked_at"),
        csil_rt_enc_timestamp(&csil_v.revoked_at)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeApplicationKeyResponse from a decoded CBOR value tree.
fn csil_dec_revoke_application_key_response(
    csil_root: &CsilCborValue,
) -> Result<RevokeApplicationKeyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let revoked_at = {
        let csil_field = cbor_require(csil_root, "revoked_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(RevokeApplicationKeyResponse { revoked_at })
}

/// Encode a RevokeApplicationKeyResponse to canonical CSIL CBOR bytes.
pub fn encode_revoke_application_key_response(
    csil_v: &RevokeApplicationKeyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_application_key_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeApplicationKeyResponse.
pub fn decode_revoke_application_key_response(
    csil_data: &[u8],
) -> Result<RevokeApplicationKeyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_application_key_response(&csil_root)
}

/// Build the canonical CBOR value tree for a EnrollApplicationInstanceRequest.
fn csil_enc_enroll_application_instance_request(
    csil_v: &EnrollApplicationInstanceRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("keys"),
        cbor_enc_array(&csil_v.keys, csil_enc_signed_application_key_addition)?,
    ));
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a EnrollApplicationInstanceRequest from a decoded CBOR value tree.
fn csil_dec_enroll_application_instance_request(
    csil_root: &CsilCborValue,
) -> Result<EnrollApplicationInstanceRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let keys = {
        let csil_field = cbor_require(csil_root, "keys")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_signed_application_key_addition);
        csil_decode(csil_field)?
    };
    Ok(EnrollApplicationInstanceRequest {
        application_id,
        instance_id,
        keys,
    })
}

/// Encode a EnrollApplicationInstanceRequest to canonical CSIL CBOR bytes.
pub fn encode_enroll_application_instance_request(
    csil_v: &EnrollApplicationInstanceRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_enroll_application_instance_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a EnrollApplicationInstanceRequest.
pub fn decode_enroll_application_instance_request(
    csil_data: &[u8],
) -> Result<EnrollApplicationInstanceRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_enroll_application_instance_request(&csil_root)
}

/// Build the canonical CBOR value tree for a EnrollApplicationInstanceResponse.
fn csil_enc_enroll_application_instance_response(
    csil_v: &EnrollApplicationInstanceResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((
        cbor_text("attestations"),
        cbor_enc_array(
            &csil_v.attestations,
            csil_enc_signed_application_key_attestation,
        )?,
    ));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a EnrollApplicationInstanceResponse from a decoded CBOR value tree.
fn csil_dec_enroll_application_instance_response(
    csil_root: &CsilCborValue,
) -> Result<EnrollApplicationInstanceResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let attestations = {
        let csil_field = cbor_require(csil_root, "attestations")?;
        let csil_decode =
            |csil_v| cbor_dec_array(csil_v, csil_dec_signed_application_key_attestation);
        csil_decode(csil_field)?
    };
    Ok(EnrollApplicationInstanceResponse {
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
        attestations,
    })
}

/// Encode a EnrollApplicationInstanceResponse to canonical CSIL CBOR bytes.
pub fn encode_enroll_application_instance_response(
    csil_v: &EnrollApplicationInstanceResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_enroll_application_instance_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a EnrollApplicationInstanceResponse.
pub fn decode_enroll_application_instance_response(
    csil_data: &[u8],
) -> Result<EnrollApplicationInstanceResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_enroll_application_instance_response(&csil_root)
}

/// Build the canonical CBOR value tree for a GetApplicationKeysRequest.
fn csil_enc_get_application_keys_request(
    csil_v: &GetApplicationKeysRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetApplicationKeysRequest from a decoded CBOR value tree.
fn csil_dec_get_application_keys_request(
    csil_root: &CsilCborValue,
) -> Result<GetApplicationKeysRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let subject_user_id = {
        let csil_field = cbor_require(csil_root, "subject_user_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(GetApplicationKeysRequest {
        subject_user_id,
        application_id,
        instance_id,
    })
}

/// Encode a GetApplicationKeysRequest to canonical CSIL CBOR bytes.
pub fn encode_get_application_keys_request(
    csil_v: &GetApplicationKeysRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_application_keys_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetApplicationKeysRequest.
pub fn decode_get_application_keys_request(
    csil_data: &[u8],
) -> Result<GetApplicationKeysRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_application_keys_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetApplicationKeysResponse.
fn csil_enc_get_application_keys_response(
    csil_v: &GetApplicationKeysResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(6);
    csil_entries.push((
        cbor_text("keys"),
        cbor_enc_array(&csil_v.keys, csil_enc_signed_application_key_attestation)?,
    ));
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((
        cbor_text("revocations"),
        cbor_enc_array(&csil_v.revocations, csil_enc_application_key_revocation)?,
    ));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetApplicationKeysResponse from a decoded CBOR value tree.
fn csil_dec_get_application_keys_response(
    csil_root: &CsilCborValue,
) -> Result<GetApplicationKeysResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let keys = {
        let csil_field = cbor_require(csil_root, "keys")?;
        let csil_decode =
            |csil_v| cbor_dec_array(csil_v, csil_dec_signed_application_key_attestation);
        csil_decode(csil_field)?
    };
    let revocations = {
        let csil_field = cbor_require(csil_root, "revocations")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_application_key_revocation);
        csil_decode(csil_field)?
    };
    Ok(GetApplicationKeysResponse {
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
        keys,
        revocations,
    })
}

/// Encode a GetApplicationKeysResponse to canonical CSIL CBOR bytes.
pub fn encode_get_application_keys_response(
    csil_v: &GetApplicationKeysResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_application_keys_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetApplicationKeysResponse.
pub fn decode_get_application_keys_response(
    csil_data: &[u8],
) -> Result<GetApplicationKeysResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_application_keys_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpResolveDomainKeysRequest.
fn csil_enc_rp_resolve_domain_keys_request(
    csil_v: &RpResolveDomainKeysRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    if let Some(csil_inner) = &csil_v.max_cache_age_seconds {
        csil_entries.push((cbor_text("max_cache_age_seconds"), cbor_int(*csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpResolveDomainKeysRequest from a decoded CBOR value tree.
fn csil_dec_rp_resolve_domain_keys_request(
    csil_root: &CsilCborValue,
) -> Result<RpResolveDomainKeysRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let domain = {
        let csil_field = cbor_require(csil_root, "domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let max_cache_age_seconds = match cbor_map_get(csil_root, "max_cache_age_seconds") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(RpResolveDomainKeysRequest {
        domain,
        max_cache_age_seconds,
    })
}

/// Encode a RpResolveDomainKeysRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_resolve_domain_keys_request(
    csil_v: &RpResolveDomainKeysRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_resolve_domain_keys_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpResolveDomainKeysRequest.
pub fn decode_rp_resolve_domain_keys_request(
    csil_data: &[u8],
) -> Result<RpResolveDomainKeysRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_resolve_domain_keys_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpResolveDomainKeysResponse.
fn csil_enc_rp_resolve_domain_keys_response(
    csil_v: &RpResolveDomainKeysResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(6);
    csil_entries.push((
        cbor_text("keys"),
        cbor_enc_array(&csil_v.keys, csil_enc_domain_public_key)?,
    ));
    csil_entries.push((cbor_text("domain"), cbor_text(&csil_v.domain)));
    csil_entries.push((
        cbor_text("fetched_at"),
        csil_rt_enc_timestamp(&csil_v.fetched_at)?,
    ));
    csil_entries.push((
        cbor_text("revocations"),
        cbor_enc_array(&csil_v.revocations, csil_enc_revocation_certificate)?,
    ));
    csil_entries.push((
        cbor_text("cache_status"),
        csil_enc_rp_cache_status(&csil_v.cache_status)?,
    ));
    csil_entries.push((
        cbor_text("revocations_checked_at"),
        csil_rt_enc_timestamp(&csil_v.revocations_checked_at)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpResolveDomainKeysResponse from a decoded CBOR value tree.
fn csil_dec_rp_resolve_domain_keys_response(
    csil_root: &CsilCborValue,
) -> Result<RpResolveDomainKeysResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let revocations = {
        let csil_field = cbor_require(csil_root, "revocations")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_revocation_certificate);
        csil_decode(csil_field)?
    };
    let fetched_at = {
        let csil_field = cbor_require(csil_root, "fetched_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let revocations_checked_at = {
        let csil_field = cbor_require(csil_root, "revocations_checked_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let cache_status = {
        let csil_field = cbor_require(csil_root, "cache_status")?;
        let csil_decode = csil_dec_rp_cache_status;
        csil_decode(csil_field)?
    };
    Ok(RpResolveDomainKeysResponse {
        domain,
        keys,
        revocations,
        fetched_at,
        revocations_checked_at,
        cache_status,
    })
}

/// Encode a RpResolveDomainKeysResponse to canonical CSIL CBOR bytes.
pub fn encode_rp_resolve_domain_keys_response(
    csil_v: &RpResolveDomainKeysResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_resolve_domain_keys_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpResolveDomainKeysResponse.
pub fn decode_rp_resolve_domain_keys_response(
    csil_data: &[u8],
) -> Result<RpResolveDomainKeysResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_resolve_domain_keys_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpResolveApplicationKeysRequest.
fn csil_enc_rp_resolve_application_keys_request(
    csil_v: &RpResolveApplicationKeysRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    if let Some(csil_inner) = &csil_v.max_cache_age_seconds {
        csil_entries.push((cbor_text("max_cache_age_seconds"), cbor_int(*csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpResolveApplicationKeysRequest from a decoded CBOR value tree.
fn csil_dec_rp_resolve_application_keys_request(
    csil_root: &CsilCborValue,
) -> Result<RpResolveApplicationKeysRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let max_cache_age_seconds = match cbor_map_get(csil_root, "max_cache_age_seconds") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(RpResolveApplicationKeysRequest {
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
        max_cache_age_seconds,
    })
}

/// Encode a RpResolveApplicationKeysRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_resolve_application_keys_request(
    csil_v: &RpResolveApplicationKeysRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_resolve_application_keys_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpResolveApplicationKeysRequest.
pub fn decode_rp_resolve_application_keys_request(
    csil_data: &[u8],
) -> Result<RpResolveApplicationKeysRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_resolve_application_keys_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpResolveApplicationKeysResponse.
fn csil_enc_rp_resolve_application_keys_response(
    csil_v: &RpResolveApplicationKeysResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((
        cbor_text("fetched_at"),
        csil_rt_enc_timestamp(&csil_v.fetched_at)?,
    ));
    csil_entries.push((cbor_text("instance_id"), cbor_text(&csil_v.instance_id)));
    csil_entries.push((
        cbor_text("cache_status"),
        csil_enc_rp_cache_status(&csil_v.cache_status)?,
    ));
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    csil_entries.push((
        cbor_text("application_keys"),
        cbor_enc_array(
            &csil_v.application_keys,
            csil_enc_signed_application_key_attestation,
        )?,
    ));
    csil_entries.push((
        cbor_text("home_domain_keys"),
        cbor_enc_array(&csil_v.home_domain_keys, csil_enc_domain_public_key)?,
    ));
    csil_entries.push((
        cbor_text("revocations_checked_at"),
        csil_rt_enc_timestamp(&csil_v.revocations_checked_at)?,
    ));
    csil_entries.push((
        cbor_text("application_key_revocations"),
        cbor_enc_array(
            &csil_v.application_key_revocations,
            csil_enc_application_key_revocation,
        )?,
    ));
    csil_entries.push((
        cbor_text("home_domain_key_revocations"),
        cbor_enc_array(
            &csil_v.home_domain_key_revocations,
            csil_enc_revocation_certificate,
        )?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpResolveApplicationKeysResponse from a decoded CBOR value tree.
fn csil_dec_rp_resolve_application_keys_response(
    csil_root: &CsilCborValue,
) -> Result<RpResolveApplicationKeysResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let instance_id = {
        let csil_field = cbor_require(csil_root, "instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let application_keys = {
        let csil_field = cbor_require(csil_root, "application_keys")?;
        let csil_decode =
            |csil_v| cbor_dec_array(csil_v, csil_dec_signed_application_key_attestation);
        csil_decode(csil_field)?
    };
    let application_key_revocations = {
        let csil_field = cbor_require(csil_root, "application_key_revocations")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_application_key_revocation);
        csil_decode(csil_field)?
    };
    let home_domain_keys = {
        let csil_field = cbor_require(csil_root, "home_domain_keys")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_domain_public_key);
        csil_decode(csil_field)?
    };
    let home_domain_key_revocations = {
        let csil_field = cbor_require(csil_root, "home_domain_key_revocations")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_revocation_certificate);
        csil_decode(csil_field)?
    };
    let fetched_at = {
        let csil_field = cbor_require(csil_root, "fetched_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let revocations_checked_at = {
        let csil_field = cbor_require(csil_root, "revocations_checked_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let cache_status = {
        let csil_field = cbor_require(csil_root, "cache_status")?;
        let csil_decode = csil_dec_rp_cache_status;
        csil_decode(csil_field)?
    };
    Ok(RpResolveApplicationKeysResponse {
        subject_user_id,
        subject_domain,
        application_id,
        instance_id,
        application_keys,
        application_key_revocations,
        home_domain_keys,
        home_domain_key_revocations,
        fetched_at,
        revocations_checked_at,
        cache_status,
    })
}

/// Encode a RpResolveApplicationKeysResponse to canonical CSIL CBOR bytes.
pub fn encode_rp_resolve_application_keys_response(
    csil_v: &RpResolveApplicationKeysResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_resolve_application_keys_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpResolveApplicationKeysResponse.
pub fn decode_rp_resolve_application_keys_response(
    csil_data: &[u8],
) -> Result<RpResolveApplicationKeysResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_resolve_application_keys_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ApplicationRef.
fn csil_enc_application_ref(csil_v: &ApplicationRef) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("application_id"),
        cbor_text(&csil_v.application_id),
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ApplicationRef from a decoded CBOR value tree.
fn csil_dec_application_ref(csil_root: &CsilCborValue) -> Result<ApplicationRef, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let application_id = {
        let csil_field = cbor_require(csil_root, "application_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ApplicationRef {
        subject_user_id,
        subject_domain,
        application_id,
    })
}

/// Encode a ApplicationRef to canonical CSIL CBOR bytes.
pub fn encode_application_ref(csil_v: &ApplicationRef) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_application_ref(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApplicationRef.
pub fn decode_application_ref(csil_data: &[u8]) -> Result<ApplicationRef, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_application_ref(&csil_root)
}

/// Build the canonical CBOR value tree for a GranteeRef.
fn csil_enc_grantee_ref(csil_v: &GranteeRef) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    if let Some(csil_inner) = &csil_v.application {
        csil_entries.push((
            cbor_text("application"),
            csil_enc_application_ref(csil_inner)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.local_rp_descriptor_fingerprint {
        csil_entries.push((
            cbor_text("local_rp_descriptor_fingerprint"),
            cbor_text(csil_inner),
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GranteeRef from a decoded CBOR value tree.
fn csil_dec_grantee_ref(csil_root: &CsilCborValue) -> Result<GranteeRef, CsilCborError> {
    cbor_check_record(csil_root)?;
    let application = match cbor_map_get(csil_root, "application") {
        Some(csil_field) => {
            let csil_decode = csil_dec_application_ref;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let csil_key = "local_rp_descriptor_fingerprint";
    let csil_opt = match cbor_map_get(csil_root, csil_key) {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let local_rp_descriptor_fingerprint = csil_opt;
    Ok(GranteeRef {
        application,
        local_rp_descriptor_fingerprint,
    })
}

/// Encode a GranteeRef to canonical CSIL CBOR bytes.
pub fn encode_grantee_ref(csil_v: &GranteeRef) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_grantee_ref(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GranteeRef.
pub fn decode_grantee_ref(csil_data: &[u8]) -> Result<GranteeRef, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_grantee_ref(&csil_root)
}

/// Build the canonical CBOR value tree for a GranteeProof.
fn csil_enc_grantee_proof(csil_v: &GranteeProof) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("signature"),
        csil_enc_application_key_signature(&csil_v.signature)?,
    ));
    if let Some(csil_inner) = &csil_v.local_rp_descriptor {
        csil_entries.push((
            cbor_text("local_rp_descriptor"),
            csil_enc_signed_local_rp_descriptor(csil_inner)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.application_instance_id {
        csil_entries.push((cbor_text("application_instance_id"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GranteeProof from a decoded CBOR value tree.
fn csil_dec_grantee_proof(csil_root: &CsilCborValue) -> Result<GranteeProof, CsilCborError> {
    cbor_check_record(csil_root)?;
    let application_instance_id = match cbor_map_get(csil_root, "application_instance_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let local_rp_descriptor = match cbor_map_get(csil_root, "local_rp_descriptor") {
        Some(csil_field) => {
            let csil_decode = csil_dec_signed_local_rp_descriptor;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let signature = {
        let csil_field = cbor_require(csil_root, "signature")?;
        let csil_decode = csil_dec_application_key_signature;
        csil_decode(csil_field)?
    };
    Ok(GranteeProof {
        application_instance_id,
        local_rp_descriptor,
        signature,
    })
}

/// Encode a GranteeProof to canonical CSIL CBOR bytes.
pub fn encode_grantee_proof(csil_v: &GranteeProof) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_grantee_proof(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GranteeProof.
pub fn decode_grantee_proof(csil_data: &[u8]) -> Result<GranteeProof, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_grantee_proof(&csil_root)
}

/// Build the canonical CBOR value tree for a ActAsScopeEntry.
fn csil_enc_act_as_scope_entry(csil_v: &ActAsScopeEntry) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("scope"), cbor_text(&csil_v.scope)));
    if let Some(csil_inner) = &csil_v.description {
        csil_entries.push((cbor_text("description"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActAsScopeEntry from a decoded CBOR value tree.
fn csil_dec_act_as_scope_entry(
    csil_root: &CsilCborValue,
) -> Result<ActAsScopeEntry, CsilCborError> {
    cbor_check_record(csil_root)?;
    let scope = {
        let csil_field = cbor_require(csil_root, "scope")?;
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
    Ok(ActAsScopeEntry { scope, description })
}

/// Encode a ActAsScopeEntry to canonical CSIL CBOR bytes.
pub fn encode_act_as_scope_entry(csil_v: &ActAsScopeEntry) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_act_as_scope_entry(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActAsScopeEntry.
pub fn decode_act_as_scope_entry(csil_data: &[u8]) -> Result<ActAsScopeEntry, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_act_as_scope_entry(&csil_root)
}

/// Build the canonical CBOR value tree for a ActAsScopeSet.
fn csil_enc_act_as_scope_set(csil_v: &ActAsScopeSet) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(7);
    csil_entries.push((
        cbor_text("entries"),
        cbor_enc_array(&csil_v.entries, csil_enc_act_as_scope_entry)?,
    ));
    csil_entries.push((cbor_text("grantee"), csil_enc_grantee_ref(&csil_v.grantee)?));
    csil_entries.push((
        cbor_text("audience"),
        csil_enc_application_ref(&csil_v.audience)?,
    ));
    if let Some(csil_inner) = &csil_v.language {
        csil_entries.push((cbor_text("language"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    if let Some(csil_inner) = &csil_v.audience_handle_claim {
        csil_entries.push((
            cbor_text("audience_handle_claim"),
            csil_enc_claim(csil_inner)?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActAsScopeSet from a decoded CBOR value tree.
fn csil_dec_act_as_scope_set(csil_root: &CsilCborValue) -> Result<ActAsScopeSet, CsilCborError> {
    cbor_check_record(csil_root)?;
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = csil_dec_application_ref;
        csil_decode(csil_field)?
    };
    let grantee = {
        let csil_field = cbor_require(csil_root, "grantee")?;
        let csil_decode = csil_dec_grantee_ref;
        csil_decode(csil_field)?
    };
    let entries = {
        let csil_field = cbor_require(csil_root, "entries")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_act_as_scope_entry);
        csil_decode(csil_field)?
    };
    let language = match cbor_map_get(csil_root, "language") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let audience_handle_claim = match cbor_map_get(csil_root, "audience_handle_claim") {
        Some(csil_field) => {
            let csil_decode = csil_dec_claim;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(ActAsScopeSet {
        audience,
        grantee,
        entries,
        language,
        audience_handle_claim,
        issued_at,
        expires_at,
    })
}

/// Encode a ActAsScopeSet to canonical CSIL CBOR bytes.
pub fn encode_act_as_scope_set(csil_v: &ActAsScopeSet) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_act_as_scope_set(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActAsScopeSet.
pub fn decode_act_as_scope_set(csil_data: &[u8]) -> Result<ActAsScopeSet, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_act_as_scope_set(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedActAsScopeSet.
fn csil_enc_signed_act_as_scope_set(
    csil_v: &SignedActAsScopeSet,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("scope_set"), cbor_bytes(&csil_v.scope_set)));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_application_key_signature)?,
    ));
    csil_entries.push((
        cbor_text("signer_instance_id"),
        cbor_text(&csil_v.signer_instance_id),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedActAsScopeSet from a decoded CBOR value tree.
fn csil_dec_signed_act_as_scope_set(
    csil_root: &CsilCborValue,
) -> Result<SignedActAsScopeSet, CsilCborError> {
    cbor_check_record(csil_root)?;
    let scope_set = {
        let csil_field = cbor_require(csil_root, "scope_set")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signer_instance_id = {
        let csil_field = cbor_require(csil_root, "signer_instance_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_application_key_signature);
        csil_decode(csil_field)?
    };
    Ok(SignedActAsScopeSet {
        scope_set,
        signer_instance_id,
        signatures,
    })
}

/// Encode a SignedActAsScopeSet to canonical CSIL CBOR bytes.
pub fn encode_signed_act_as_scope_set(
    csil_v: &SignedActAsScopeSet,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_act_as_scope_set(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedActAsScopeSet.
pub fn decode_signed_act_as_scope_set(
    csil_data: &[u8],
) -> Result<SignedActAsScopeSet, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_act_as_scope_set(&csil_root)
}

/// Build the canonical CBOR value tree for a ActAsScopeSetRequest.
fn csil_enc_act_as_scope_set_request(
    csil_v: &ActAsScopeSetRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("scope"),
        cbor_enc_array(&csil_v.scope, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((cbor_text("grantee"), csil_enc_grantee_ref(&csil_v.grantee)?));
    if let Some(csil_inner) = &csil_v.locale_preferences {
        csil_entries.push((
            cbor_text("locale_preferences"),
            cbor_enc_array(csil_inner, |csil_elem| Ok(cbor_text(csil_elem)))?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActAsScopeSetRequest from a decoded CBOR value tree.
fn csil_dec_act_as_scope_set_request(
    csil_root: &CsilCborValue,
) -> Result<ActAsScopeSetRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grantee = {
        let csil_field = cbor_require(csil_root, "grantee")?;
        let csil_decode = csil_dec_grantee_ref;
        csil_decode(csil_field)?
    };
    let scope = {
        let csil_field = cbor_require(csil_root, "scope")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let locale_preferences = match cbor_map_get(csil_root, "locale_preferences") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ActAsScopeSetRequest {
        grantee,
        scope,
        locale_preferences,
    })
}

/// Encode a ActAsScopeSetRequest to canonical CSIL CBOR bytes.
pub fn encode_act_as_scope_set_request(
    csil_v: &ActAsScopeSetRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_act_as_scope_set_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActAsScopeSetRequest.
pub fn decode_act_as_scope_set_request(
    csil_data: &[u8],
) -> Result<ActAsScopeSetRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_act_as_scope_set_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ActAsGrant.
fn csil_enc_act_as_grant(csil_v: &ActAsGrant) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(12);
    csil_entries.push((cbor_text("grantee"), csil_enc_grantee_ref(&csil_v.grantee)?));
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((
        cbor_text("audience"),
        csil_enc_application_ref(&csil_v.audience)?,
    ));
    csil_entries.push((cbor_text("grant_id"), cbor_text(&csil_v.grant_id)));
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((
        cbor_text("scope_set"),
        csil_enc_signed_act_as_scope_set(&csil_v.scope_set)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((
        cbor_text("approved_scope"),
        cbor_enc_array(&csil_v.approved_scope, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("renewable_until"),
        csil_rt_enc_timestamp(&csil_v.renewable_until)?,
    ));
    csil_entries.push((
        cbor_text("series_issued_at"),
        csil_rt_enc_timestamp(&csil_v.series_issued_at)?,
    ));
    if let Some(csil_inner) = &csil_v.device_fingerprint {
        csil_entries.push((cbor_text("device_fingerprint"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActAsGrant from a decoded CBOR value tree.
fn csil_dec_act_as_grant(csil_root: &CsilCborValue) -> Result<ActAsGrant, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let grantee = {
        let csil_field = cbor_require(csil_root, "grantee")?;
        let csil_decode = csil_dec_grantee_ref;
        csil_decode(csil_field)?
    };
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = csil_dec_application_ref;
        csil_decode(csil_field)?
    };
    let scope_set = {
        let csil_field = cbor_require(csil_root, "scope_set")?;
        let csil_decode = csil_dec_signed_act_as_scope_set;
        csil_decode(csil_field)?
    };
    let approved_scope = {
        let csil_field = cbor_require(csil_root, "approved_scope")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let series_issued_at = {
        let csil_field = cbor_require(csil_root, "series_issued_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let renewable_until = {
        let csil_field = cbor_require(csil_root, "renewable_until")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let device_fingerprint = match cbor_map_get(csil_root, "device_fingerprint") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ActAsGrant {
        grant_id,
        user_id,
        subject_domain,
        grantee,
        audience,
        scope_set,
        approved_scope,
        issued_at,
        expires_at,
        series_issued_at,
        renewable_until,
        device_fingerprint,
    })
}

/// Encode a ActAsGrant to canonical CSIL CBOR bytes.
pub fn encode_act_as_grant(csil_v: &ActAsGrant) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_act_as_grant(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActAsGrant.
pub fn decode_act_as_grant(csil_data: &[u8]) -> Result<ActAsGrant, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_act_as_grant(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedActAsGrant.
fn csil_enc_signed_act_as_grant(csil_v: &SignedActAsGrant) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("grant"), cbor_bytes(&csil_v.grant)));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedActAsGrant from a decoded CBOR value tree.
fn csil_dec_signed_act_as_grant(
    csil_root: &CsilCborValue,
) -> Result<SignedActAsGrant, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    Ok(SignedActAsGrant { grant, signatures })
}

/// Encode a SignedActAsGrant to canonical CSIL CBOR bytes.
pub fn encode_signed_act_as_grant(csil_v: &SignedActAsGrant) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_act_as_grant(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedActAsGrant.
pub fn decode_signed_act_as_grant(csil_data: &[u8]) -> Result<SignedActAsGrant, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_act_as_grant(&csil_root)
}

/// Build the canonical CBOR value tree for a ActAsGrantRequest.
fn csil_enc_act_as_grant_request(
    csil_v: &ActAsGrantRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(9);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    csil_entries.push((cbor_text("grantee"), csil_enc_grantee_ref(&csil_v.grantee)?));
    csil_entries.push((
        cbor_text("scope_set"),
        csil_enc_signed_act_as_scope_set(&csil_v.scope_set)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((cbor_text("callback_url"), cbor_text(&csil_v.callback_url)));
    csil_entries.push((
        cbor_text("requested_at"),
        csil_rt_enc_timestamp(&csil_v.requested_at)?,
    ));
    if let Some(csil_inner) = &csil_v.grantee_handle_claim {
        csil_entries.push((
            cbor_text("grantee_handle_claim"),
            csil_enc_claim(csil_inner)?,
        ));
    }
    if let Some(csil_inner) = &csil_v.requested_lifetime_seconds {
        csil_entries.push((
            cbor_text("requested_lifetime_seconds"),
            cbor_int(*csil_inner),
        ));
    }
    if let Some(csil_inner) = &csil_v.requested_renewal_window_seconds {
        csil_entries.push((
            cbor_text("requested_renewal_window_seconds"),
            cbor_int(*csil_inner),
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActAsGrantRequest from a decoded CBOR value tree.
fn csil_dec_act_as_grant_request(
    csil_root: &CsilCborValue,
) -> Result<ActAsGrantRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grantee = {
        let csil_field = cbor_require(csil_root, "grantee")?;
        let csil_decode = csil_dec_grantee_ref;
        csil_decode(csil_field)?
    };
    let scope_set = {
        let csil_field = cbor_require(csil_root, "scope_set")?;
        let csil_decode = csil_dec_signed_act_as_scope_set;
        csil_decode(csil_field)?
    };
    let requested_lifetime_seconds = match cbor_map_get(csil_root, "requested_lifetime_seconds") {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let csil_key = "requested_renewal_window_seconds";
    let csil_opt = match cbor_map_get(csil_root, csil_key) {
        Some(csil_field) => {
            let csil_decode = cbor_as_i64;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let requested_renewal_window_seconds = csil_opt;
    let grantee_handle_claim = match cbor_map_get(csil_root, "grantee_handle_claim") {
        Some(csil_field) => {
            let csil_decode = csil_dec_claim;
            Some(csil_decode(csil_field)?)
        }
        None => None,
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
    let requested_at = {
        let csil_field = cbor_require(csil_root, "requested_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(ActAsGrantRequest {
        grantee,
        scope_set,
        requested_lifetime_seconds,
        requested_renewal_window_seconds,
        grantee_handle_claim,
        callback_url,
        nonce,
        requested_at,
        expires_at,
    })
}

/// Encode a ActAsGrantRequest to canonical CSIL CBOR bytes.
pub fn encode_act_as_grant_request(csil_v: &ActAsGrantRequest) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_act_as_grant_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActAsGrantRequest.
pub fn decode_act_as_grant_request(csil_data: &[u8]) -> Result<ActAsGrantRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_act_as_grant_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedActAsGrantRequest.
fn csil_enc_signed_act_as_grant_request(
    csil_v: &SignedActAsGrantRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("proof"), csil_enc_grantee_proof(&csil_v.proof)?));
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedActAsGrantRequest from a decoded CBOR value tree.
fn csil_dec_signed_act_as_grant_request(
    csil_root: &CsilCborValue,
) -> Result<SignedActAsGrantRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let proof = {
        let csil_field = cbor_require(csil_root, "proof")?;
        let csil_decode = csil_dec_grantee_proof;
        csil_decode(csil_field)?
    };
    Ok(SignedActAsGrantRequest { request, proof })
}

/// Encode a SignedActAsGrantRequest to canonical CSIL CBOR bytes.
pub fn encode_signed_act_as_grant_request(
    csil_v: &SignedActAsGrantRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_act_as_grant_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedActAsGrantRequest.
pub fn decode_signed_act_as_grant_request(
    csil_data: &[u8],
) -> Result<SignedActAsGrantRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_act_as_grant_request(&csil_root)
}

/// Build the canonical CBOR value tree for a ActAsRefreshRequest.
fn csil_enc_act_as_refresh_request(
    csil_v: &ActAsRefreshRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("nonce"), cbor_text(&csil_v.nonce)));
    csil_entries.push((cbor_text("grantee"), csil_enc_grantee_ref(&csil_v.grantee)?));
    csil_entries.push((cbor_text("grant_id"), cbor_text(&csil_v.grant_id)));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((
        cbor_text("requested_at"),
        csil_rt_enc_timestamp(&csil_v.requested_at)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActAsRefreshRequest from a decoded CBOR value tree.
fn csil_dec_act_as_refresh_request(
    csil_root: &CsilCborValue,
) -> Result<ActAsRefreshRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grant_id = {
        let csil_field = cbor_require(csil_root, "grant_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let grantee = {
        let csil_field = cbor_require(csil_root, "grantee")?;
        let csil_decode = csil_dec_grantee_ref;
        csil_decode(csil_field)?
    };
    let requested_at = {
        let csil_field = cbor_require(csil_root, "requested_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(ActAsRefreshRequest {
        grant_id,
        grantee,
        requested_at,
        expires_at,
        nonce,
    })
}

/// Encode a ActAsRefreshRequest to canonical CSIL CBOR bytes.
pub fn encode_act_as_refresh_request(
    csil_v: &ActAsRefreshRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_act_as_refresh_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActAsRefreshRequest.
pub fn decode_act_as_refresh_request(
    csil_data: &[u8],
) -> Result<ActAsRefreshRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_act_as_refresh_request(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedActAsRefreshRequest.
fn csil_enc_signed_act_as_refresh_request(
    csil_v: &SignedActAsRefreshRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("proof"), csil_enc_grantee_proof(&csil_v.proof)?));
    csil_entries.push((cbor_text("request"), cbor_bytes(&csil_v.request)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedActAsRefreshRequest from a decoded CBOR value tree.
fn csil_dec_signed_act_as_refresh_request(
    csil_root: &CsilCborValue,
) -> Result<SignedActAsRefreshRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let proof = {
        let csil_field = cbor_require(csil_root, "proof")?;
        let csil_decode = csil_dec_grantee_proof;
        csil_decode(csil_field)?
    };
    Ok(SignedActAsRefreshRequest { request, proof })
}

/// Encode a SignedActAsRefreshRequest to canonical CSIL CBOR bytes.
pub fn encode_signed_act_as_refresh_request(
    csil_v: &SignedActAsRefreshRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_act_as_refresh_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedActAsRefreshRequest.
pub fn decode_signed_act_as_refresh_request(
    csil_data: &[u8],
) -> Result<SignedActAsRefreshRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_act_as_refresh_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RefreshActAsGrantRequest.
fn csil_enc_refresh_act_as_grant_request(
    csil_v: &RefreshActAsGrantRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("request"),
        csil_enc_signed_act_as_refresh_request(&csil_v.request)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RefreshActAsGrantRequest from a decoded CBOR value tree.
fn csil_dec_refresh_act_as_grant_request(
    csil_root: &CsilCborValue,
) -> Result<RefreshActAsGrantRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = csil_dec_signed_act_as_refresh_request;
        csil_decode(csil_field)?
    };
    Ok(RefreshActAsGrantRequest { request })
}

/// Encode a RefreshActAsGrantRequest to canonical CSIL CBOR bytes.
pub fn encode_refresh_act_as_grant_request(
    csil_v: &RefreshActAsGrantRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_refresh_act_as_grant_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RefreshActAsGrantRequest.
pub fn decode_refresh_act_as_grant_request(
    csil_data: &[u8],
) -> Result<RefreshActAsGrantRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_refresh_act_as_grant_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RefreshActAsGrantResponse.
fn csil_enc_refresh_act_as_grant_response(
    csil_v: &RefreshActAsGrantResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("grant"),
        csil_enc_signed_act_as_grant(&csil_v.grant)?,
    ));
    csil_entries.push((cbor_text("signed"), cbor_bool(csil_v.signed)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RefreshActAsGrantResponse from a decoded CBOR value tree.
fn csil_dec_refresh_act_as_grant_response(
    csil_root: &CsilCborValue,
) -> Result<RefreshActAsGrantResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grant = {
        let csil_field = cbor_require(csil_root, "grant")?;
        let csil_decode = csil_dec_signed_act_as_grant;
        csil_decode(csil_field)?
    };
    let signed = {
        let csil_field = cbor_require(csil_root, "signed")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(RefreshActAsGrantResponse { grant, signed })
}

/// Encode a RefreshActAsGrantResponse to canonical CSIL CBOR bytes.
pub fn encode_refresh_act_as_grant_response(
    csil_v: &RefreshActAsGrantResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_refresh_act_as_grant_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RefreshActAsGrantResponse.
pub fn decode_refresh_act_as_grant_response(
    csil_data: &[u8],
) -> Result<RefreshActAsGrantResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_refresh_act_as_grant_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ActAsPresentation.
fn csil_enc_act_as_presentation(
    csil_v: &ActAsPresentation,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((cbor_text("nonce"), cbor_bytes(&csil_v.nonce)));
    csil_entries.push((
        cbor_text("audience"),
        csil_enc_application_ref(&csil_v.audience)?,
    ));
    csil_entries.push((cbor_text("grant_hash"), cbor_bytes(&csil_v.grant_hash)));
    csil_entries.push((
        cbor_text("presented_at"),
        csil_rt_enc_timestamp(&csil_v.presented_at)?,
    ));
    csil_entries.push((
        cbor_text("request_digest"),
        cbor_bytes(&csil_v.request_digest),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActAsPresentation from a decoded CBOR value tree.
fn csil_dec_act_as_presentation(
    csil_root: &CsilCborValue,
) -> Result<ActAsPresentation, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grant_hash = {
        let csil_field = cbor_require(csil_root, "grant_hash")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = csil_dec_application_ref;
        csil_decode(csil_field)?
    };
    let request_digest = {
        let csil_field = cbor_require(csil_root, "request_digest")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let presented_at = {
        let csil_field = cbor_require(csil_root, "presented_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let nonce = {
        let csil_field = cbor_require(csil_root, "nonce")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    Ok(ActAsPresentation {
        grant_hash,
        audience,
        request_digest,
        presented_at,
        nonce,
    })
}

/// Encode a ActAsPresentation to canonical CSIL CBOR bytes.
pub fn encode_act_as_presentation(csil_v: &ActAsPresentation) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_act_as_presentation(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActAsPresentation.
pub fn decode_act_as_presentation(csil_data: &[u8]) -> Result<ActAsPresentation, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_act_as_presentation(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedActAsPresentation.
fn csil_enc_signed_act_as_presentation(
    csil_v: &SignedActAsPresentation,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("proof"), csil_enc_grantee_proof(&csil_v.proof)?));
    csil_entries.push((cbor_text("presentation"), cbor_bytes(&csil_v.presentation)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedActAsPresentation from a decoded CBOR value tree.
fn csil_dec_signed_act_as_presentation(
    csil_root: &CsilCborValue,
) -> Result<SignedActAsPresentation, CsilCborError> {
    cbor_check_record(csil_root)?;
    let presentation = {
        let csil_field = cbor_require(csil_root, "presentation")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let proof = {
        let csil_field = cbor_require(csil_root, "proof")?;
        let csil_decode = csil_dec_grantee_proof;
        csil_decode(csil_field)?
    };
    Ok(SignedActAsPresentation {
        presentation,
        proof,
    })
}

/// Encode a SignedActAsPresentation to canonical CSIL CBOR bytes.
pub fn encode_signed_act_as_presentation(
    csil_v: &SignedActAsPresentation,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_act_as_presentation(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedActAsPresentation.
pub fn decode_signed_act_as_presentation(
    csil_data: &[u8],
) -> Result<SignedActAsPresentation, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_act_as_presentation(&csil_root)
}

/// Build the canonical CBOR value tree for a ActAsCredential.
fn csil_enc_act_as_credential(csil_v: &ActAsCredential) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("grant"),
        csil_enc_signed_act_as_grant(&csil_v.grant)?,
    ));
    csil_entries.push((
        cbor_text("presentation"),
        csil_enc_signed_act_as_presentation(&csil_v.presentation)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActAsCredential from a decoded CBOR value tree.
fn csil_dec_act_as_credential(csil_root: &CsilCborValue) -> Result<ActAsCredential, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grant = {
        let csil_field = cbor_require(csil_root, "grant")?;
        let csil_decode = csil_dec_signed_act_as_grant;
        csil_decode(csil_field)?
    };
    let presentation = {
        let csil_field = cbor_require(csil_root, "presentation")?;
        let csil_decode = csil_dec_signed_act_as_presentation;
        csil_decode(csil_field)?
    };
    Ok(ActAsCredential {
        grant,
        presentation,
    })
}

/// Encode a ActAsCredential to canonical CSIL CBOR bytes.
pub fn encode_act_as_credential(csil_v: &ActAsCredential) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_act_as_credential(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActAsCredential.
pub fn decode_act_as_credential(csil_data: &[u8]) -> Result<ActAsCredential, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_act_as_credential(&csil_root)
}

/// Build the canonical CBOR value tree for a ActAsGrantRevocation.
fn csil_enc_act_as_grant_revocation(
    csil_v: &ActAsGrantRevocation,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((cbor_text("user_id"), cbor_text(&csil_v.user_id)));
    csil_entries.push((cbor_text("grant_id"), cbor_text(&csil_v.grant_id)));
    csil_entries.push((
        cbor_text("revoked_at"),
        csil_rt_enc_timestamp(&csil_v.revoked_at)?,
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActAsGrantRevocation from a decoded CBOR value tree.
fn csil_dec_act_as_grant_revocation(
    csil_root: &CsilCborValue,
) -> Result<ActAsGrantRevocation, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let revoked_at = {
        let csil_field = cbor_require(csil_root, "revoked_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(ActAsGrantRevocation {
        grant_id,
        user_id,
        subject_domain,
        revoked_at,
    })
}

/// Encode a ActAsGrantRevocation to canonical CSIL CBOR bytes.
pub fn encode_act_as_grant_revocation(
    csil_v: &ActAsGrantRevocation,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_act_as_grant_revocation(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActAsGrantRevocation.
pub fn decode_act_as_grant_revocation(
    csil_data: &[u8],
) -> Result<ActAsGrantRevocation, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_act_as_grant_revocation(&csil_root)
}

/// Build the canonical CBOR value tree for a SignedActAsGrantRevocation.
fn csil_enc_signed_act_as_grant_revocation(
    csil_v: &SignedActAsGrantRevocation,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((cbor_text("revocation"), cbor_bytes(&csil_v.revocation)));
    csil_entries.push((
        cbor_text("signatures"),
        cbor_enc_array(&csil_v.signatures, csil_enc_claim_signature)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a SignedActAsGrantRevocation from a decoded CBOR value tree.
fn csil_dec_signed_act_as_grant_revocation(
    csil_root: &CsilCborValue,
) -> Result<SignedActAsGrantRevocation, CsilCborError> {
    cbor_check_record(csil_root)?;
    let revocation = {
        let csil_field = cbor_require(csil_root, "revocation")?;
        let csil_decode = cbor_as_bytes;
        csil_decode(csil_field)?
    };
    let signatures = {
        let csil_field = cbor_require(csil_root, "signatures")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_claim_signature);
        csil_decode(csil_field)?
    };
    Ok(SignedActAsGrantRevocation {
        revocation,
        signatures,
    })
}

/// Encode a SignedActAsGrantRevocation to canonical CSIL CBOR bytes.
pub fn encode_signed_act_as_grant_revocation(
    csil_v: &SignedActAsGrantRevocation,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signed_act_as_grant_revocation(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SignedActAsGrantRevocation.
pub fn decode_signed_act_as_grant_revocation(
    csil_data: &[u8],
) -> Result<SignedActAsGrantRevocation, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signed_act_as_grant_revocation(&csil_root)
}

/// Build the canonical CBOR value tree for a GetActAsGrantRevocationsRequest.
fn csil_enc_get_act_as_grant_revocations_request(
    csil_v: &GetActAsGrantRevocationsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("grant_ids"),
        cbor_enc_array(&csil_v.grant_ids, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetActAsGrantRevocationsRequest from a decoded CBOR value tree.
fn csil_dec_get_act_as_grant_revocations_request(
    csil_root: &CsilCborValue,
) -> Result<GetActAsGrantRevocationsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grant_ids = {
        let csil_field = cbor_require(csil_root, "grant_ids")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(GetActAsGrantRevocationsRequest { grant_ids })
}

/// Encode a GetActAsGrantRevocationsRequest to canonical CSIL CBOR bytes.
pub fn encode_get_act_as_grant_revocations_request(
    csil_v: &GetActAsGrantRevocationsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_act_as_grant_revocations_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetActAsGrantRevocationsRequest.
pub fn decode_get_act_as_grant_revocations_request(
    csil_data: &[u8],
) -> Result<GetActAsGrantRevocationsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_act_as_grant_revocations_request(&csil_root)
}

/// Build the canonical CBOR value tree for a GetActAsGrantRevocationsResponse.
fn csil_enc_get_act_as_grant_revocations_response(
    csil_v: &GetActAsGrantRevocationsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("revocations"),
        cbor_enc_array(&csil_v.revocations, csil_enc_signed_act_as_grant_revocation)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a GetActAsGrantRevocationsResponse from a decoded CBOR value tree.
fn csil_dec_get_act_as_grant_revocations_response(
    csil_root: &CsilCborValue,
) -> Result<GetActAsGrantRevocationsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let revocations = {
        let csil_field = cbor_require(csil_root, "revocations")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_signed_act_as_grant_revocation);
        csil_decode(csil_field)?
    };
    Ok(GetActAsGrantRevocationsResponse { revocations })
}

/// Encode a GetActAsGrantRevocationsResponse to canonical CSIL CBOR bytes.
pub fn encode_get_act_as_grant_revocations_response(
    csil_v: &GetActAsGrantRevocationsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_get_act_as_grant_revocations_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a GetActAsGrantRevocationsResponse.
pub fn decode_get_act_as_grant_revocations_response(
    csil_data: &[u8],
) -> Result<GetActAsGrantRevocationsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_get_act_as_grant_revocations_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RpActAsRefreshRequest.
fn csil_enc_rp_act_as_refresh_request(
    csil_v: &RpActAsRefreshRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("request"),
        csil_enc_signed_act_as_refresh_request(&csil_v.request)?,
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpActAsRefreshRequest from a decoded CBOR value tree.
fn csil_dec_rp_act_as_refresh_request(
    csil_root: &CsilCborValue,
) -> Result<RpActAsRefreshRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let subject_domain = {
        let csil_field = cbor_require(csil_root, "subject_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let request = {
        let csil_field = cbor_require(csil_root, "request")?;
        let csil_decode = csil_dec_signed_act_as_refresh_request;
        csil_decode(csil_field)?
    };
    Ok(RpActAsRefreshRequest {
        subject_domain,
        request,
    })
}

/// Encode a RpActAsRefreshRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_act_as_refresh_request(
    csil_v: &RpActAsRefreshRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_act_as_refresh_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpActAsRefreshRequest.
pub fn decode_rp_act_as_refresh_request(
    csil_data: &[u8],
) -> Result<RpActAsRefreshRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_act_as_refresh_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RpResolveActAsRevocationsRequest.
fn csil_enc_rp_resolve_act_as_revocations_request(
    csil_v: &RpResolveActAsRevocationsRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(2);
    csil_entries.push((
        cbor_text("grant_ids"),
        cbor_enc_array(&csil_v.grant_ids, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RpResolveActAsRevocationsRequest from a decoded CBOR value tree.
fn csil_dec_rp_resolve_act_as_revocations_request(
    csil_root: &CsilCborValue,
) -> Result<RpResolveActAsRevocationsRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let subject_domain = {
        let csil_field = cbor_require(csil_root, "subject_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let grant_ids = {
        let csil_field = cbor_require(csil_root, "grant_ids")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(RpResolveActAsRevocationsRequest {
        subject_domain,
        grant_ids,
    })
}

/// Encode a RpResolveActAsRevocationsRequest to canonical CSIL CBOR bytes.
pub fn encode_rp_resolve_act_as_revocations_request(
    csil_v: &RpResolveActAsRevocationsRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_resolve_act_as_revocations_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpResolveActAsRevocationsRequest.
pub fn decode_rp_resolve_act_as_revocations_request(
    csil_data: &[u8],
) -> Result<RpResolveActAsRevocationsRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_resolve_act_as_revocations_request(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserActAsInspectRequest.
fn csil_enc_browser_act_as_inspect_request(
    csil_v: &BrowserActAsInspectRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserActAsInspectRequest from a decoded CBOR value tree.
fn csil_dec_browser_act_as_inspect_request(
    csil_root: &CsilCborValue,
) -> Result<BrowserActAsInspectRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(BrowserActAsInspectRequest { signed_request })
}

/// Encode a BrowserActAsInspectRequest to canonical CSIL CBOR bytes.
pub fn encode_browser_act_as_inspect_request(
    csil_v: &BrowserActAsInspectRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_act_as_inspect_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserActAsInspectRequest.
pub fn decode_browser_act_as_inspect_request(
    csil_data: &[u8],
) -> Result<BrowserActAsInspectRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_act_as_inspect_request(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserActAsScopeEntry.
fn csil_enc_browser_act_as_scope_entry(
    csil_v: &BrowserActAsScopeEntry,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((cbor_text("scope"), cbor_text(&csil_v.scope)));
    if let Some(csil_inner) = &csil_v.description {
        csil_entries.push((cbor_text("description"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("removed_by_policy"),
        cbor_bool(csil_v.removed_by_policy),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserActAsScopeEntry from a decoded CBOR value tree.
fn csil_dec_browser_act_as_scope_entry(
    csil_root: &CsilCborValue,
) -> Result<BrowserActAsScopeEntry, CsilCborError> {
    cbor_check_record(csil_root)?;
    let scope = {
        let csil_field = cbor_require(csil_root, "scope")?;
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
    let removed_by_policy = {
        let csil_field = cbor_require(csil_root, "removed_by_policy")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(BrowserActAsScopeEntry {
        scope,
        description,
        removed_by_policy,
    })
}

/// Encode a BrowserActAsScopeEntry to canonical CSIL CBOR bytes.
pub fn encode_browser_act_as_scope_entry(
    csil_v: &BrowserActAsScopeEntry,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_act_as_scope_entry(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserActAsScopeEntry.
pub fn decode_browser_act_as_scope_entry(
    csil_data: &[u8],
) -> Result<BrowserActAsScopeEntry, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_act_as_scope_entry(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserActAsParty.
fn csil_enc_browser_act_as_party(
    csil_v: &BrowserActAsParty,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(10);
    if let Some(csil_inner) = &csil_v.domain {
        csil_entries.push((cbor_text("domain"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.handle {
        csil_entries.push((cbor_text("handle"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("own_domain"), cbor_bool(csil_v.own_domain)));
    if let Some(csil_inner) = &csil_v.local_rp_name {
        csil_entries.push((cbor_text("local_rp_name"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.application_id {
        csil_entries.push((cbor_text("application_id"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.subject_user_id {
        csil_entries.push((cbor_text("subject_user_id"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("operator_trusted"),
        cbor_bool(csil_v.operator_trusted),
    ));
    csil_entries.push((
        cbor_text("user_has_history"),
        cbor_bool(csil_v.user_has_history),
    ));
    csil_entries.push((
        cbor_text("domain_key_pinned"),
        cbor_bool(csil_v.domain_key_pinned),
    ));
    if let Some(csil_inner) = &csil_v.local_rp_fingerprint {
        csil_entries.push((cbor_text("local_rp_fingerprint"), cbor_text(csil_inner)));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserActAsParty from a decoded CBOR value tree.
fn csil_dec_browser_act_as_party(
    csil_root: &CsilCborValue,
) -> Result<BrowserActAsParty, CsilCborError> {
    cbor_check_record(csil_root)?;
    let domain = match cbor_map_get(csil_root, "domain") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let application_id = match cbor_map_get(csil_root, "application_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let subject_user_id = match cbor_map_get(csil_root, "subject_user_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let handle = match cbor_map_get(csil_root, "handle") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let local_rp_name = match cbor_map_get(csil_root, "local_rp_name") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let local_rp_fingerprint = match cbor_map_get(csil_root, "local_rp_fingerprint") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let own_domain = {
        let csil_field = cbor_require(csil_root, "own_domain")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let user_has_history = {
        let csil_field = cbor_require(csil_root, "user_has_history")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let domain_key_pinned = {
        let csil_field = cbor_require(csil_root, "domain_key_pinned")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let operator_trusted = {
        let csil_field = cbor_require(csil_root, "operator_trusted")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(BrowserActAsParty {
        domain,
        application_id,
        subject_user_id,
        handle,
        local_rp_name,
        local_rp_fingerprint,
        own_domain,
        user_has_history,
        domain_key_pinned,
        operator_trusted,
    })
}

/// Encode a BrowserActAsParty to canonical CSIL CBOR bytes.
pub fn encode_browser_act_as_party(csil_v: &BrowserActAsParty) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_act_as_party(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserActAsParty.
pub fn decode_browser_act_as_party(csil_data: &[u8]) -> Result<BrowserActAsParty, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_act_as_party(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserActAsInspectResponse.
fn csil_enc_browser_act_as_inspect_response(
    csil_v: &BrowserActAsInspectResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(11);
    csil_entries.push((
        cbor_text("entries"),
        cbor_enc_array(&csil_v.entries, csil_enc_browser_act_as_scope_entry)?,
    ));
    csil_entries.push((cbor_text("grantee"), csil_enc_grantee_ref(&csil_v.grantee)?));
    csil_entries.push((
        cbor_text("audience"),
        csil_enc_application_ref(&csil_v.audience)?,
    ));
    if let Some(csil_inner) = &csil_v.language {
        csil_entries.push((cbor_text("language"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.access_denied {
        csil_entries.push((
            cbor_text("access_denied"),
            csil_enc_app_access_denial(csil_inner)?,
        ));
    }
    csil_entries.push((
        cbor_text("grantee_party"),
        csil_enc_browser_act_as_party(&csil_v.grantee_party)?,
    ));
    csil_entries.push((
        cbor_text("audience_party"),
        csil_enc_browser_act_as_party(&csil_v.audience_party)?,
    ));
    csil_entries.push((
        cbor_text("max_lifetime_seconds"),
        cbor_int(csil_v.max_lifetime_seconds),
    ));
    csil_entries.push((
        cbor_text("default_lifetime_seconds"),
        cbor_int(csil_v.default_lifetime_seconds),
    ));
    csil_entries.push((
        cbor_text("max_renewal_window_seconds"),
        cbor_int(csil_v.max_renewal_window_seconds),
    ));
    csil_entries.push((
        cbor_text("default_renewal_window_seconds"),
        cbor_int(csil_v.default_renewal_window_seconds),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserActAsInspectResponse from a decoded CBOR value tree.
fn csil_dec_browser_act_as_inspect_response(
    csil_root: &CsilCborValue,
) -> Result<BrowserActAsInspectResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grantee = {
        let csil_field = cbor_require(csil_root, "grantee")?;
        let csil_decode = csil_dec_grantee_ref;
        csil_decode(csil_field)?
    };
    let grantee_party = {
        let csil_field = cbor_require(csil_root, "grantee_party")?;
        let csil_decode = csil_dec_browser_act_as_party;
        csil_decode(csil_field)?
    };
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = csil_dec_application_ref;
        csil_decode(csil_field)?
    };
    let audience_party = {
        let csil_field = cbor_require(csil_root, "audience_party")?;
        let csil_decode = csil_dec_browser_act_as_party;
        csil_decode(csil_field)?
    };
    let entries = {
        let csil_field = cbor_require(csil_root, "entries")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_browser_act_as_scope_entry);
        csil_decode(csil_field)?
    };
    let language = match cbor_map_get(csil_root, "language") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let default_lifetime_seconds = {
        let csil_field = cbor_require(csil_root, "default_lifetime_seconds")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let max_lifetime_seconds = {
        let csil_field = cbor_require(csil_root, "max_lifetime_seconds")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let default_renewal_window_seconds = {
        let csil_field = cbor_require(csil_root, "default_renewal_window_seconds")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let max_renewal_window_seconds = {
        let csil_field = cbor_require(csil_root, "max_renewal_window_seconds")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let access_denied = match cbor_map_get(csil_root, "access_denied") {
        Some(csil_field) => {
            let csil_decode = csil_dec_app_access_denial;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(BrowserActAsInspectResponse {
        grantee,
        grantee_party,
        audience,
        audience_party,
        entries,
        language,
        default_lifetime_seconds,
        max_lifetime_seconds,
        default_renewal_window_seconds,
        max_renewal_window_seconds,
        access_denied,
    })
}

/// Encode a BrowserActAsInspectResponse to canonical CSIL CBOR bytes.
pub fn encode_browser_act_as_inspect_response(
    csil_v: &BrowserActAsInspectResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_act_as_inspect_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserActAsInspectResponse.
pub fn decode_browser_act_as_inspect_response(
    csil_data: &[u8],
) -> Result<BrowserActAsInspectResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_act_as_inspect_response(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserActAsCompleteRequest.
fn csil_enc_browser_act_as_complete_request(
    csil_v: &BrowserActAsCompleteRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((
        cbor_text("approved_scope"),
        cbor_enc_array(&csil_v.approved_scope, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    csil_entries.push((
        cbor_text("lifetime_seconds"),
        cbor_int(csil_v.lifetime_seconds),
    ));
    csil_entries.push((
        cbor_text("renewal_window_seconds"),
        cbor_int(csil_v.renewal_window_seconds),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserActAsCompleteRequest from a decoded CBOR value tree.
fn csil_dec_browser_act_as_complete_request(
    csil_root: &CsilCborValue,
) -> Result<BrowserActAsCompleteRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let approved_scope = {
        let csil_field = cbor_require(csil_root, "approved_scope")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let lifetime_seconds = {
        let csil_field = cbor_require(csil_root, "lifetime_seconds")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    let renewal_window_seconds = {
        let csil_field = cbor_require(csil_root, "renewal_window_seconds")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(BrowserActAsCompleteRequest {
        signed_request,
        approved_scope,
        lifetime_seconds,
        renewal_window_seconds,
    })
}

/// Encode a BrowserActAsCompleteRequest to canonical CSIL CBOR bytes.
pub fn encode_browser_act_as_complete_request(
    csil_v: &BrowserActAsCompleteRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_act_as_complete_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserActAsCompleteRequest.
pub fn decode_browser_act_as_complete_request(
    csil_data: &[u8],
) -> Result<BrowserActAsCompleteRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_act_as_complete_request(&csil_root)
}

/// Build the canonical CBOR value tree for a BrowserActAsCompleteResponse.
fn csil_enc_browser_act_as_complete_response(
    csil_v: &BrowserActAsCompleteResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("redirect_url"), cbor_text(&csil_v.redirect_url)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a BrowserActAsCompleteResponse from a decoded CBOR value tree.
fn csil_dec_browser_act_as_complete_response(
    csil_root: &CsilCborValue,
) -> Result<BrowserActAsCompleteResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let redirect_url = {
        let csil_field = cbor_require(csil_root, "redirect_url")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(BrowserActAsCompleteResponse { redirect_url })
}

/// Encode a BrowserActAsCompleteResponse to canonical CSIL CBOR bytes.
pub fn encode_browser_act_as_complete_response(
    csil_v: &BrowserActAsCompleteResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_browser_act_as_complete_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a BrowserActAsCompleteResponse.
pub fn decode_browser_act_as_complete_response(
    csil_data: &[u8],
) -> Result<BrowserActAsCompleteResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_browser_act_as_complete_response(&csil_root)
}

/// Build the canonical CBOR value tree for a ActAsGrantSummary.
fn csil_enc_act_as_grant_summary(
    csil_v: &ActAsGrantSummary,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("grantee"), csil_enc_grantee_ref(&csil_v.grantee)?));
    csil_entries.push((
        cbor_text("audience"),
        csil_enc_application_ref(&csil_v.audience)?,
    ));
    csil_entries.push((cbor_text("grant_id"), cbor_text(&csil_v.grant_id)));
    csil_entries.push((
        cbor_text("issued_at"),
        csil_rt_enc_timestamp(&csil_v.issued_at)?,
    ));
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    if let Some(csil_inner) = &csil_v.revoked_at {
        csil_entries.push((cbor_text("revoked_at"), csil_rt_enc_timestamp(csil_inner)?));
    }
    csil_entries.push((
        cbor_text("approved_scope"),
        cbor_enc_array(&csil_v.approved_scope, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("renewable_until"),
        csil_rt_enc_timestamp(&csil_v.renewable_until)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ActAsGrantSummary from a decoded CBOR value tree.
fn csil_dec_act_as_grant_summary(
    csil_root: &CsilCborValue,
) -> Result<ActAsGrantSummary, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grant_id = {
        let csil_field = cbor_require(csil_root, "grant_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let grantee = {
        let csil_field = cbor_require(csil_root, "grantee")?;
        let csil_decode = csil_dec_grantee_ref;
        csil_decode(csil_field)?
    };
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = csil_dec_application_ref;
        csil_decode(csil_field)?
    };
    let approved_scope = {
        let csil_field = cbor_require(csil_root, "approved_scope")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let issued_at = {
        let csil_field = cbor_require(csil_root, "issued_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let renewable_until = {
        let csil_field = cbor_require(csil_root, "renewable_until")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let revoked_at = match cbor_map_get(csil_root, "revoked_at") {
        Some(csil_field) => {
            let csil_decode = csil_as_timestamp;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(ActAsGrantSummary {
        grant_id,
        grantee,
        audience,
        approved_scope,
        issued_at,
        expires_at,
        renewable_until,
        revoked_at,
    })
}

/// Encode a ActAsGrantSummary to canonical CSIL CBOR bytes.
pub fn encode_act_as_grant_summary(csil_v: &ActAsGrantSummary) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_act_as_grant_summary(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ActAsGrantSummary.
pub fn decode_act_as_grant_summary(csil_data: &[u8]) -> Result<ActAsGrantSummary, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_act_as_grant_summary(&csil_root)
}

/// Build the canonical CBOR value tree for a ListActAsGrantsResponse.
fn csil_enc_list_act_as_grants_response(
    csil_v: &ListActAsGrantsResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("grants"),
        cbor_enc_array(&csil_v.grants, csil_enc_act_as_grant_summary)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a ListActAsGrantsResponse from a decoded CBOR value tree.
fn csil_dec_list_act_as_grants_response(
    csil_root: &CsilCborValue,
) -> Result<ListActAsGrantsResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grants = {
        let csil_field = cbor_require(csil_root, "grants")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_act_as_grant_summary);
        csil_decode(csil_field)?
    };
    Ok(ListActAsGrantsResponse { grants })
}

/// Encode a ListActAsGrantsResponse to canonical CSIL CBOR bytes.
pub fn encode_list_act_as_grants_response(
    csil_v: &ListActAsGrantsResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_list_act_as_grants_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ListActAsGrantsResponse.
pub fn decode_list_act_as_grants_response(
    csil_data: &[u8],
) -> Result<ListActAsGrantsResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_list_act_as_grants_response(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeActAsGrantRequest.
fn csil_enc_revoke_act_as_grant_request(
    csil_v: &RevokeActAsGrantRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((cbor_text("grant_id"), cbor_text(&csil_v.grant_id)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeActAsGrantRequest from a decoded CBOR value tree.
fn csil_dec_revoke_act_as_grant_request(
    csil_root: &CsilCborValue,
) -> Result<RevokeActAsGrantRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let grant_id = {
        let csil_field = cbor_require(csil_root, "grant_id")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(RevokeActAsGrantRequest { grant_id })
}

/// Encode a RevokeActAsGrantRequest to canonical CSIL CBOR bytes.
pub fn encode_revoke_act_as_grant_request(
    csil_v: &RevokeActAsGrantRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_act_as_grant_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeActAsGrantRequest.
pub fn decode_revoke_act_as_grant_request(
    csil_data: &[u8],
) -> Result<RevokeActAsGrantRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_act_as_grant_request(&csil_root)
}

/// Build the canonical CBOR value tree for a RevokeActAsGrantResponse.
fn csil_enc_revoke_act_as_grant_response(
    csil_v: &RevokeActAsGrantResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("revoked_at"),
        csil_rt_enc_timestamp(&csil_v.revoked_at)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a RevokeActAsGrantResponse from a decoded CBOR value tree.
fn csil_dec_revoke_act_as_grant_response(
    csil_root: &CsilCborValue,
) -> Result<RevokeActAsGrantResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let revoked_at = {
        let csil_field = cbor_require(csil_root, "revoked_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    Ok(RevokeActAsGrantResponse { revoked_at })
}

/// Encode a RevokeActAsGrantResponse to canonical CSIL CBOR bytes.
pub fn encode_revoke_act_as_grant_response(
    csil_v: &RevokeActAsGrantResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_revoke_act_as_grant_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RevokeActAsGrantResponse.
pub fn decode_revoke_act_as_grant_response(
    csil_data: &[u8],
) -> Result<RevokeActAsGrantResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_revoke_act_as_grant_response(&csil_root)
}

/// Build the canonical CBOR value tree for a PreviewReleasePolicyRequest.
fn csil_enc_preview_release_policy_request(
    csil_v: &PreviewReleasePolicyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(8);
    csil_entries.push((cbor_text("audience"), cbor_text(&csil_v.audience)));
    csil_entries.push((
        cbor_text("user_choices"),
        cbor_enc_array(&csil_v.user_choices, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    if let Some(csil_inner) = &csil_v.temp_audience {
        csil_entries.push((cbor_text("temp_audience"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("optional_claims"),
        cbor_enc_array(&csil_v.optional_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    csil_entries.push((
        cbor_text("required_claims"),
        cbor_enc_array(&csil_v.required_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    if let Some(csil_inner) = &csil_v.temp_claim_type {
        csil_entries.push((cbor_text("temp_claim_type"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("available_claims"),
        cbor_enc_array(&csil_v.available_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    if let Some(csil_inner) = &csil_v.temp_disposition {
        csil_entries.push((
            cbor_text("temp_disposition"),
            csil_enc_release_disposition(csil_inner)?,
        ));
    }
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PreviewReleasePolicyRequest from a decoded CBOR value tree.
fn csil_dec_preview_release_policy_request(
    csil_root: &CsilCborValue,
) -> Result<PreviewReleasePolicyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let audience = {
        let csil_field = cbor_require(csil_root, "audience")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let required_claims = {
        let csil_field = cbor_require(csil_root, "required_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let optional_claims = {
        let csil_field = cbor_require(csil_root, "optional_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let available_claims = {
        let csil_field = cbor_require(csil_root, "available_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let user_choices = {
        let csil_field = cbor_require(csil_root, "user_choices")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let temp_audience = match cbor_map_get(csil_root, "temp_audience") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let temp_claim_type = match cbor_map_get(csil_root, "temp_claim_type") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let temp_disposition = match cbor_map_get(csil_root, "temp_disposition") {
        Some(csil_field) => {
            let csil_decode = csil_dec_release_disposition;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(PreviewReleasePolicyRequest {
        audience,
        required_claims,
        optional_claims,
        available_claims,
        user_choices,
        temp_audience,
        temp_claim_type,
        temp_disposition,
    })
}

/// Encode a PreviewReleasePolicyRequest to canonical CSIL CBOR bytes.
pub fn encode_preview_release_policy_request(
    csil_v: &PreviewReleasePolicyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_preview_release_policy_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PreviewReleasePolicyRequest.
pub fn decode_preview_release_policy_request(
    csil_data: &[u8],
) -> Result<PreviewReleasePolicyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_preview_release_policy_request(&csil_root)
}

/// Build the canonical CBOR value tree for a PreviewReleaseRow.
fn csil_enc_preview_release_row(
    csil_v: &PreviewReleaseRow,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(6);
    csil_entries.push((cbor_text("locked"), cbor_bool(csil_v.locked)));
    csil_entries.push((
        cbor_text("policy"),
        csil_enc_consent_row_policy(&csil_v.policy)?,
    ));
    csil_entries.push((cbor_text("required"), cbor_bool(csil_v.required)));
    csil_entries.push((cbor_text("available"), cbor_bool(csil_v.available)));
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    csil_entries.push((
        cbor_text("default_granted"),
        cbor_bool(csil_v.default_granted),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PreviewReleaseRow from a decoded CBOR value tree.
fn csil_dec_preview_release_row(
    csil_root: &CsilCborValue,
) -> Result<PreviewReleaseRow, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let required = {
        let csil_field = cbor_require(csil_root, "required")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let available = {
        let csil_field = cbor_require(csil_root, "available")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let locked = {
        let csil_field = cbor_require(csil_root, "locked")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let policy = {
        let csil_field = cbor_require(csil_root, "policy")?;
        let csil_decode = csil_dec_consent_row_policy;
        csil_decode(csil_field)?
    };
    let default_granted = {
        let csil_field = cbor_require(csil_root, "default_granted")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    Ok(PreviewReleaseRow {
        claim_type,
        required,
        available,
        locked,
        policy,
        default_granted,
    })
}

/// Encode a PreviewReleaseRow to canonical CSIL CBOR bytes.
pub fn encode_preview_release_row(csil_v: &PreviewReleaseRow) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_preview_release_row(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PreviewReleaseRow.
pub fn decode_preview_release_row(csil_data: &[u8]) -> Result<PreviewReleaseRow, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_preview_release_row(&csil_root)
}

/// Build the canonical CBOR value tree for a PreviewReleasePolicyResponse.
fn csil_enc_preview_release_policy_response(
    csil_v: &PreviewReleasePolicyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    csil_entries.push((
        cbor_text("rows"),
        cbor_enc_array(&csil_v.rows, csil_enc_preview_release_row)?,
    ));
    csil_entries.push((
        cbor_text("forced_deny"),
        cbor_enc_array(&csil_v.forced_deny, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("forced_allow"),
        cbor_enc_array(&csil_v.forced_allow, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("authorized_claims"),
        cbor_enc_array(&csil_v.authorized_claims, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PreviewReleasePolicyResponse from a decoded CBOR value tree.
fn csil_dec_preview_release_policy_response(
    csil_root: &CsilCborValue,
) -> Result<PreviewReleasePolicyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let forced_allow = {
        let csil_field = cbor_require(csil_root, "forced_allow")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let forced_deny = {
        let csil_field = cbor_require(csil_root, "forced_deny")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let authorized_claims = {
        let csil_field = cbor_require(csil_root, "authorized_claims")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let rows = {
        let csil_field = cbor_require(csil_root, "rows")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_preview_release_row);
        csil_decode(csil_field)?
    };
    Ok(PreviewReleasePolicyResponse {
        forced_allow,
        forced_deny,
        authorized_claims,
        rows,
    })
}

/// Encode a PreviewReleasePolicyResponse to canonical CSIL CBOR bytes.
pub fn encode_preview_release_policy_response(
    csil_v: &PreviewReleasePolicyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_preview_release_policy_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PreviewReleasePolicyResponse.
pub fn decode_preview_release_policy_response(
    csil_data: &[u8],
) -> Result<PreviewReleasePolicyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_preview_release_policy_response(&csil_root)
}

/// Build the canonical CBOR value tree for a PreviewIssuerPolicyRequest.
fn csil_enc_preview_issuer_policy_request(
    csil_v: &PreviewIssuerPolicyRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    if let Some(csil_inner) = &csil_v.claim_type {
        csil_entries.push((cbor_text("claim_type"), cbor_text(csil_inner)));
    }
    if let Some(csil_inner) = &csil_v.denied_tlds {
        csil_entries.push((
            cbor_text("denied_tlds"),
            cbor_enc_array(csil_inner, |csil_elem| Ok(cbor_text(csil_elem)))?,
        ));
    }
    if let Some(csil_inner) = &csil_v.denied_domains {
        csil_entries.push((
            cbor_text("denied_domains"),
            cbor_enc_array(csil_inner, |csil_elem| Ok(cbor_text(csil_elem)))?,
        ));
    }
    if let Some(csil_inner) = &csil_v.issuer_user_id {
        csil_entries.push((cbor_text("issuer_user_id"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PreviewIssuerPolicyRequest from a decoded CBOR value tree.
fn csil_dec_preview_issuer_policy_request(
    csil_root: &CsilCborValue,
) -> Result<PreviewIssuerPolicyRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let subject_domain = {
        let csil_field = cbor_require(csil_root, "subject_domain")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let denied_domains = match cbor_map_get(csil_root, "denied_domains") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let denied_tlds = match cbor_map_get(csil_root, "denied_tlds") {
        Some(csil_field) => {
            let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let issuer_user_id = match cbor_map_get(csil_root, "issuer_user_id") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let claim_type = match cbor_map_get(csil_root, "claim_type") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(PreviewIssuerPolicyRequest {
        subject_domain,
        denied_domains,
        denied_tlds,
        issuer_user_id,
        claim_type,
    })
}

/// Encode a PreviewIssuerPolicyRequest to canonical CSIL CBOR bytes.
pub fn encode_preview_issuer_policy_request(
    csil_v: &PreviewIssuerPolicyRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_preview_issuer_policy_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PreviewIssuerPolicyRequest.
pub fn decode_preview_issuer_policy_request(
    csil_data: &[u8],
) -> Result<PreviewIssuerPolicyRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_preview_issuer_policy_request(&csil_root)
}

/// Build the canonical CBOR value tree for a PreviewIssuerPolicyResponse.
fn csil_enc_preview_issuer_policy_response(
    csil_v: &PreviewIssuerPolicyResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(6);
    csil_entries.push((cbor_text("reason"), cbor_text(&csil_v.reason)));
    csil_entries.push((cbor_text("allowed"), cbor_bool(csil_v.allowed)));
    csil_entries.push((
        cbor_text("denied_tlds"),
        cbor_enc_array(&csil_v.denied_tlds, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("denied_domains"),
        cbor_enc_array(&csil_v.denied_domains, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    if let Some(csil_inner) = &csil_v.user_can_issue {
        csil_entries.push((cbor_text("user_can_issue"), cbor_bool(*csil_inner)));
    }
    csil_entries.push((
        cbor_text("attested_claim_ttl_seconds"),
        cbor_int(csil_v.attested_claim_ttl_seconds),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a PreviewIssuerPolicyResponse from a decoded CBOR value tree.
fn csil_dec_preview_issuer_policy_response(
    csil_root: &CsilCborValue,
) -> Result<PreviewIssuerPolicyResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let denied_domains = {
        let csil_field = cbor_require(csil_root, "denied_domains")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let denied_tlds = {
        let csil_field = cbor_require(csil_root, "denied_tlds")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let allowed = {
        let csil_field = cbor_require(csil_root, "allowed")?;
        let csil_decode = cbor_as_bool;
        csil_decode(csil_field)?
    };
    let reason = {
        let csil_field = cbor_require(csil_root, "reason")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let user_can_issue = match cbor_map_get(csil_root, "user_can_issue") {
        Some(csil_field) => {
            let csil_decode = cbor_as_bool;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let attested_claim_ttl_seconds = {
        let csil_field = cbor_require(csil_root, "attested_claim_ttl_seconds")?;
        let csil_decode = cbor_as_i64;
        csil_decode(csil_field)?
    };
    Ok(PreviewIssuerPolicyResponse {
        denied_domains,
        denied_tlds,
        allowed,
        reason,
        user_can_issue,
        attested_claim_ttl_seconds,
    })
}

/// Encode a PreviewIssuerPolicyResponse to canonical CSIL CBOR bytes.
pub fn encode_preview_issuer_policy_response(
    csil_v: &PreviewIssuerPolicyResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_preview_issuer_policy_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PreviewIssuerPolicyResponse.
pub fn decode_preview_issuer_policy_response(
    csil_data: &[u8],
) -> Result<PreviewIssuerPolicyResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_preview_issuer_policy_response(&csil_root)
}

/// Build the canonical CBOR value tree for a InspectSigningRequestRequest.
fn csil_enc_inspect_signing_request_request(
    csil_v: &InspectSigningRequestRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a InspectSigningRequestRequest from a decoded CBOR value tree.
fn csil_dec_inspect_signing_request_request(
    csil_root: &CsilCborValue,
) -> Result<InspectSigningRequestRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    Ok(InspectSigningRequestRequest { signed_request })
}

/// Encode a InspectSigningRequestRequest to canonical CSIL CBOR bytes.
pub fn encode_inspect_signing_request_request(
    csil_v: &InspectSigningRequestRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_inspect_signing_request_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a InspectSigningRequestRequest.
pub fn decode_inspect_signing_request_request(
    csil_data: &[u8],
) -> Result<InspectSigningRequestRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_inspect_signing_request_request(&csil_root)
}

/// Build the canonical CBOR value tree for a InspectSigningRequestResponse.
fn csil_enc_inspect_signing_request_response(
    csil_v: &InspectSigningRequestResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(5);
    csil_entries.push((
        cbor_text("expires_at"),
        csil_rt_enc_timestamp(&csil_v.expires_at)?,
    ));
    csil_entries.push((
        cbor_text("subject_domain"),
        cbor_text(&csil_v.subject_domain),
    ));
    csil_entries.push((
        cbor_text("subject_user_id"),
        cbor_text(&csil_v.subject_user_id),
    ));
    csil_entries.push((
        cbor_text("issuable_claim_types"),
        cbor_enc_array(&csil_v.issuable_claim_types, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    csil_entries.push((
        cbor_text("requested_claim_types"),
        cbor_enc_array(&csil_v.requested_claim_types, |csil_elem| {
            Ok(cbor_text(csil_elem))
        })?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a InspectSigningRequestResponse from a decoded CBOR value tree.
fn csil_dec_inspect_signing_request_response(
    csil_root: &CsilCborValue,
) -> Result<InspectSigningRequestResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
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
    let requested_claim_types = {
        let csil_field = cbor_require(csil_root, "requested_claim_types")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let expires_at = {
        let csil_field = cbor_require(csil_root, "expires_at")?;
        let csil_decode = csil_as_timestamp;
        csil_decode(csil_field)?
    };
    let issuable_claim_types = {
        let csil_field = cbor_require(csil_root, "issuable_claim_types")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(InspectSigningRequestResponse {
        subject_user_id,
        subject_domain,
        requested_claim_types,
        expires_at,
        issuable_claim_types,
    })
}

/// Encode a InspectSigningRequestResponse to canonical CSIL CBOR bytes.
pub fn encode_inspect_signing_request_response(
    csil_v: &InspectSigningRequestResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_inspect_signing_request_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a InspectSigningRequestResponse.
pub fn decode_inspect_signing_request_response(
    csil_data: &[u8],
) -> Result<InspectSigningRequestResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_inspect_signing_request_response(&csil_root)
}

/// Build the canonical CBOR value tree for a IssueForSigningRequestRequest.
fn csil_enc_issue_for_signing_request_request(
    csil_v: &IssueForSigningRequestRequest,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(3);
    csil_entries.push((
        cbor_text("claim_types"),
        cbor_enc_array(&csil_v.claim_types, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("claim_values"),
        cbor_enc_array(&csil_v.claim_values, |csil_elem| Ok(cbor_text(csil_elem)))?,
    ));
    csil_entries.push((
        cbor_text("signed_request"),
        cbor_text(&csil_v.signed_request),
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a IssueForSigningRequestRequest from a decoded CBOR value tree.
fn csil_dec_issue_for_signing_request_request(
    csil_root: &CsilCborValue,
) -> Result<IssueForSigningRequestRequest, CsilCborError> {
    cbor_check_record(csil_root)?;
    let signed_request = {
        let csil_field = cbor_require(csil_root, "signed_request")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let claim_types = {
        let csil_field = cbor_require(csil_root, "claim_types")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    let claim_values = {
        let csil_field = cbor_require(csil_root, "claim_values")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, cbor_as_text);
        csil_decode(csil_field)?
    };
    Ok(IssueForSigningRequestRequest {
        signed_request,
        claim_types,
        claim_values,
    })
}

/// Encode a IssueForSigningRequestRequest to canonical CSIL CBOR bytes.
pub fn encode_issue_for_signing_request_request(
    csil_v: &IssueForSigningRequestRequest,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_issue_for_signing_request_request(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a IssueForSigningRequestRequest.
pub fn decode_issue_for_signing_request_request(
    csil_data: &[u8],
) -> Result<IssueForSigningRequestRequest, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_issue_for_signing_request_request(&csil_root)
}

/// Build the canonical CBOR value tree for a IssuedClaimResult.
fn csil_enc_issued_claim_result(
    csil_v: &IssuedClaimResult,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(4);
    if let Some(csil_inner) = &csil_v.message {
        csil_entries.push((cbor_text("message"), cbor_text(csil_inner)));
    }
    csil_entries.push((
        cbor_text("outcome"),
        csil_enc_issued_claim_outcome(&csil_v.outcome)?,
    ));
    if let Some(csil_inner) = &csil_v.claim_code {
        csil_entries.push((cbor_text("claim_code"), cbor_text(csil_inner)));
    }
    csil_entries.push((cbor_text("claim_type"), cbor_text(&csil_v.claim_type)));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a IssuedClaimResult from a decoded CBOR value tree.
fn csil_dec_issued_claim_result(
    csil_root: &CsilCborValue,
) -> Result<IssuedClaimResult, CsilCborError> {
    cbor_check_record(csil_root)?;
    let claim_type = {
        let csil_field = cbor_require(csil_root, "claim_type")?;
        let csil_decode = cbor_as_text;
        csil_decode(csil_field)?
    };
    let outcome = {
        let csil_field = cbor_require(csil_root, "outcome")?;
        let csil_decode = csil_dec_issued_claim_outcome;
        csil_decode(csil_field)?
    };
    let message = match cbor_map_get(csil_root, "message") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    let claim_code = match cbor_map_get(csil_root, "claim_code") {
        Some(csil_field) => {
            let csil_decode = cbor_as_text;
            Some(csil_decode(csil_field)?)
        }
        None => None,
    };
    Ok(IssuedClaimResult {
        claim_type,
        outcome,
        message,
        claim_code,
    })
}

/// Encode a IssuedClaimResult to canonical CSIL CBOR bytes.
pub fn encode_issued_claim_result(csil_v: &IssuedClaimResult) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_issued_claim_result(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a IssuedClaimResult.
pub fn decode_issued_claim_result(csil_data: &[u8]) -> Result<IssuedClaimResult, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_issued_claim_result(&csil_root)
}

/// Build the canonical CBOR value tree for a IssueForSigningRequestResponse.
fn csil_enc_issue_for_signing_request_response(
    csil_v: &IssueForSigningRequestResponse,
) -> Result<CsilCborValue, CsilCborError> {
    let mut csil_entries: Vec<(CsilCborValue, CsilCborValue)> = Vec::with_capacity(1);
    csil_entries.push((
        cbor_text("results"),
        cbor_enc_array(&csil_v.results, csil_enc_issued_claim_result)?,
    ));
    Ok(CsilCborValue::Map(csil_entries))
}

/// Reconstruct a IssueForSigningRequestResponse from a decoded CBOR value tree.
fn csil_dec_issue_for_signing_request_response(
    csil_root: &CsilCborValue,
) -> Result<IssueForSigningRequestResponse, CsilCborError> {
    cbor_check_record(csil_root)?;
    let results = {
        let csil_field = cbor_require(csil_root, "results")?;
        let csil_decode = |csil_v| cbor_dec_array(csil_v, csil_dec_issued_claim_result);
        csil_decode(csil_field)?
    };
    Ok(IssueForSigningRequestResponse { results })
}

/// Encode a IssueForSigningRequestResponse to canonical CSIL CBOR bytes.
pub fn encode_issue_for_signing_request_response(
    csil_v: &IssueForSigningRequestResponse,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_issue_for_signing_request_response(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a IssueForSigningRequestResponse.
pub fn decode_issue_for_signing_request_response(
    csil_data: &[u8],
) -> Result<IssueForSigningRequestResponse, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_issue_for_signing_request_response(&csil_root)
}

/// Encode a CheckValue union as a tagged sum `[variant_index, value]`.
fn csil_enc_check_value(csil_v: &CheckValue) -> Result<CsilCborValue, CsilCborError> {
    Ok(match csil_v {
        CheckValue::Variant0(csil_x) => {
            CsilCborValue::Array(vec![CsilCborValue::Uint(0), cbor_text(csil_x)])
        }
        CheckValue::Variant1(csil_x) => {
            CsilCborValue::Array(vec![CsilCborValue::Uint(1), cbor_int(*csil_x)])
        }
        CheckValue::Variant2(csil_x) => {
            CsilCborValue::Array(vec![CsilCborValue::Uint(2), cbor_float(*csil_x)])
        }
    })
}

/// Decode a tagged sum `[variant_index, value]` into a CheckValue union.
fn csil_dec_check_value(csil_v: &CsilCborValue) -> Result<CheckValue, CsilCborError> {
    let CsilCborValue::Array(csil_arr) = csil_v else {
        return Err(CsilCborError(
            "csil cbor: union expects a 2-element array".to_string(),
        ));
    };
    let [csil_tag, csil_payload] = csil_arr.as_slice() else {
        return Err(CsilCborError(format!(
            "csil cbor: union array has {} elements, expected 2",
            csil_arr.len()
        )));
    };
    let csil_idx = cbor_as_u64(csil_tag)?;
    match csil_idx {
        0 => {
            let csil_decode = cbor_as_text;
            Ok(CheckValue::Variant0(csil_decode(csil_payload)?))
        }
        1 => {
            let csil_decode = cbor_as_i64;
            Ok(CheckValue::Variant1(csil_decode(csil_payload)?))
        }
        2 => {
            let csil_decode = cbor_as_f64;
            Ok(CheckValue::Variant2(csil_decode(csil_payload)?))
        }
        csil_other => Err(CsilCborError(format!(
            "csil cbor: unknown CheckValue variant {csil_other}"
        ))),
    }
}

/// Encode a CheckValue to canonical CSIL CBOR bytes.
pub fn encode_check_value(csil_v: &CheckValue) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_check_value(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a CheckValue.
pub fn decode_check_value(csil_data: &[u8]) -> Result<CheckValue, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_check_value(&csil_root)
}

/// Encode a KeyAlgorithm enum as its CBOR value.
fn csil_enc_key_algorithm(csil_v: &KeyAlgorithm) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_key_algorithm(csil_v: &CsilCborValue) -> Result<KeyAlgorithm, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    KeyAlgorithm::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown KeyAlgorithm value {number}")))
}

/// Encode a KeyAlgorithm to canonical CSIL CBOR bytes.
pub fn encode_key_algorithm(csil_v: &KeyAlgorithm) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_key_algorithm(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a KeyAlgorithm.
pub fn decode_key_algorithm(csil_data: &[u8]) -> Result<KeyAlgorithm, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_key_algorithm(&csil_root)
}

/// Encode a KeyUsage enum as its CBOR value.
fn csil_enc_key_usage(csil_v: &KeyUsage) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_key_usage(csil_v: &CsilCborValue) -> Result<KeyUsage, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    KeyUsage::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown KeyUsage value {number}")))
}

/// Encode a KeyUsage to canonical CSIL CBOR bytes.
pub fn encode_key_usage(csil_v: &KeyUsage) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_key_usage(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a KeyUsage.
pub fn decode_key_usage(csil_data: &[u8]) -> Result<KeyUsage, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_key_usage(&csil_root)
}

/// Encode a AeadSuite enum as its CBOR value.
fn csil_enc_aead_suite(csil_v: &AeadSuite) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_aead_suite(csil_v: &CsilCborValue) -> Result<AeadSuite, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    AeadSuite::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown AeadSuite value {number}")))
}

/// Encode a AeadSuite to canonical CSIL CBOR bytes.
pub fn encode_aead_suite(csil_v: &AeadSuite) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_aead_suite(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AeadSuite.
pub fn decode_aead_suite(csil_data: &[u8]) -> Result<AeadSuite, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_aead_suite(&csil_root)
}

/// Encode a ClaimValueType enum as its CBOR value.
fn csil_enc_claim_value_type(csil_v: &ClaimValueType) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_claim_value_type(csil_v: &CsilCborValue) -> Result<ClaimValueType, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    ClaimValueType::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown ClaimValueType value {number}")))
}

/// Encode a ClaimValueType to canonical CSIL CBOR bytes.
pub fn encode_claim_value_type(csil_v: &ClaimValueType) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim_value_type(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ClaimValueType.
pub fn decode_claim_value_type(csil_data: &[u8]) -> Result<ClaimValueType, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_value_type(&csil_root)
}

/// Encode a SetRule enum as its CBOR value.
fn csil_enc_set_rule(csil_v: &SetRule) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_set_rule(csil_v: &CsilCborValue) -> Result<SetRule, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    SetRule::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown SetRule value {number}")))
}

/// Encode a SetRule to canonical CSIL CBOR bytes.
pub fn encode_set_rule(csil_v: &SetRule) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_rule(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetRule.
pub fn decode_set_rule(csil_data: &[u8]) -> Result<SetRule, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_rule(&csil_root)
}

/// Encode a SigningRule enum as its CBOR value.
fn csil_enc_signing_rule(csil_v: &SigningRule) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_signing_rule(csil_v: &CsilCborValue) -> Result<SigningRule, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    SigningRule::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown SigningRule value {number}")))
}

/// Encode a SigningRule to canonical CSIL CBOR bytes.
pub fn encode_signing_rule(csil_v: &SigningRule) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_signing_rule(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SigningRule.
pub fn decode_signing_rule(csil_data: &[u8]) -> Result<SigningRule, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_signing_rule(&csil_root)
}

/// Encode a SetClaimOutcome enum as its CBOR value.
fn csil_enc_set_claim_outcome(csil_v: &SetClaimOutcome) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_set_claim_outcome(csil_v: &CsilCborValue) -> Result<SetClaimOutcome, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    SetClaimOutcome::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown SetClaimOutcome value {number}")))
}

/// Encode a SetClaimOutcome to canonical CSIL CBOR bytes.
pub fn encode_set_claim_outcome(csil_v: &SetClaimOutcome) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_set_claim_outcome(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a SetClaimOutcome.
pub fn decode_set_claim_outcome(csil_data: &[u8]) -> Result<SetClaimOutcome, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_set_claim_outcome(&csil_root)
}

/// Encode a ReleaseDisposition enum as its CBOR value.
fn csil_enc_release_disposition(
    csil_v: &ReleaseDisposition,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_release_disposition(
    csil_v: &CsilCborValue,
) -> Result<ReleaseDisposition, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    ReleaseDisposition::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown ReleaseDisposition value {number}"
        ))
    })
}

/// Encode a ReleaseDisposition to canonical CSIL CBOR bytes.
pub fn encode_release_disposition(csil_v: &ReleaseDisposition) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_release_disposition(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ReleaseDisposition.
pub fn decode_release_disposition(csil_data: &[u8]) -> Result<ReleaseDisposition, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_release_disposition(&csil_root)
}

/// Encode a ConsentRowPolicy enum as its CBOR value.
fn csil_enc_consent_row_policy(csil_v: &ConsentRowPolicy) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_consent_row_policy(csil_v: &CsilCborValue) -> Result<ConsentRowPolicy, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    ConsentRowPolicy::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown ConsentRowPolicy value {number}"
        ))
    })
}

/// Encode a ConsentRowPolicy to canonical CSIL CBOR bytes.
pub fn encode_consent_row_policy(csil_v: &ConsentRowPolicy) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_consent_row_policy(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ConsentRowPolicy.
pub fn decode_consent_row_policy(csil_data: &[u8]) -> Result<ConsentRowPolicy, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_consent_row_policy(&csil_root)
}

/// Encode a ClaimApprovalStatus enum as its CBOR value.
fn csil_enc_claim_approval_status(
    csil_v: &ClaimApprovalStatus,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_claim_approval_status(
    csil_v: &CsilCborValue,
) -> Result<ClaimApprovalStatus, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    ClaimApprovalStatus::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown ClaimApprovalStatus value {number}"
        ))
    })
}

/// Encode a ClaimApprovalStatus to canonical CSIL CBOR bytes.
pub fn encode_claim_approval_status(
    csil_v: &ClaimApprovalStatus,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim_approval_status(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ClaimApprovalStatus.
pub fn decode_claim_approval_status(
    csil_data: &[u8],
) -> Result<ClaimApprovalStatus, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_approval_status(&csil_root)
}

/// Encode a PinRecheckOutcome enum as its CBOR value.
fn csil_enc_pin_recheck_outcome(
    csil_v: &PinRecheckOutcome,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_pin_recheck_outcome(
    csil_v: &CsilCborValue,
) -> Result<PinRecheckOutcome, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    PinRecheckOutcome::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown PinRecheckOutcome value {number}"
        ))
    })
}

/// Encode a PinRecheckOutcome to canonical CSIL CBOR bytes.
pub fn encode_pin_recheck_outcome(csil_v: &PinRecheckOutcome) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_pin_recheck_outcome(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a PinRecheckOutcome.
pub fn decode_pin_recheck_outcome(csil_data: &[u8]) -> Result<PinRecheckOutcome, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_pin_recheck_outcome(&csil_root)
}

/// Encode a NotificationPurpose enum as its CBOR value.
fn csil_enc_notification_purpose(
    csil_v: &NotificationPurpose,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_notification_purpose(
    csil_v: &CsilCborValue,
) -> Result<NotificationPurpose, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    NotificationPurpose::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown NotificationPurpose value {number}"
        ))
    })
}

/// Encode a NotificationPurpose to canonical CSIL CBOR bytes.
pub fn encode_notification_purpose(csil_v: &NotificationPurpose) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_notification_purpose(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a NotificationPurpose.
pub fn decode_notification_purpose(csil_data: &[u8]) -> Result<NotificationPurpose, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_notification_purpose(&csil_root)
}

/// Encode a NotificationChannel enum as its CBOR value.
fn csil_enc_notification_channel(
    csil_v: &NotificationChannel,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_notification_channel(
    csil_v: &CsilCborValue,
) -> Result<NotificationChannel, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    NotificationChannel::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown NotificationChannel value {number}"
        ))
    })
}

/// Encode a NotificationChannel to canonical CSIL CBOR bytes.
pub fn encode_notification_channel(csil_v: &NotificationChannel) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_notification_channel(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a NotificationChannel.
pub fn decode_notification_channel(csil_data: &[u8]) -> Result<NotificationChannel, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_notification_channel(&csil_root)
}

/// Encode a DestinationKind enum as its CBOR value.
fn csil_enc_destination_kind(csil_v: &DestinationKind) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_destination_kind(csil_v: &CsilCborValue) -> Result<DestinationKind, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    DestinationKind::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown DestinationKind value {number}")))
}

/// Encode a DestinationKind to canonical CSIL CBOR bytes.
pub fn encode_destination_kind(csil_v: &DestinationKind) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_destination_kind(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a DestinationKind.
pub fn decode_destination_kind(csil_data: &[u8]) -> Result<DestinationKind, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_destination_kind(&csil_root)
}

/// Encode a LocalRpPolicy enum as its CBOR value.
fn csil_enc_local_rp_policy(csil_v: &LocalRpPolicy) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_local_rp_policy(csil_v: &CsilCborValue) -> Result<LocalRpPolicy, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    LocalRpPolicy::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown LocalRpPolicy value {number}")))
}

/// Encode a LocalRpPolicy to canonical CSIL CBOR bytes.
pub fn encode_local_rp_policy(csil_v: &LocalRpPolicy) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_local_rp_policy(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpPolicy.
pub fn decode_local_rp_policy(csil_data: &[u8]) -> Result<LocalRpPolicy, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_policy(&csil_root)
}

/// Encode a LocalRpStatus enum as its CBOR value.
fn csil_enc_local_rp_status(csil_v: &LocalRpStatus) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_local_rp_status(csil_v: &CsilCborValue) -> Result<LocalRpStatus, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    LocalRpStatus::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown LocalRpStatus value {number}")))
}

/// Encode a LocalRpStatus to canonical CSIL CBOR bytes.
pub fn encode_local_rp_status(csil_v: &LocalRpStatus) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_local_rp_status(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpStatus.
pub fn decode_local_rp_status(csil_data: &[u8]) -> Result<LocalRpStatus, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_status(&csil_root)
}

/// Encode a LocalRpAdmission enum as its CBOR value.
fn csil_enc_local_rp_admission(csil_v: &LocalRpAdmission) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_local_rp_admission(csil_v: &CsilCborValue) -> Result<LocalRpAdmission, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    LocalRpAdmission::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown LocalRpAdmission value {number}"
        ))
    })
}

/// Encode a LocalRpAdmission to canonical CSIL CBOR bytes.
pub fn encode_local_rp_admission(csil_v: &LocalRpAdmission) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_local_rp_admission(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a LocalRpAdmission.
pub fn decode_local_rp_admission(csil_data: &[u8]) -> Result<LocalRpAdmission, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_local_rp_admission(&csil_root)
}

/// Encode a AppAccessMode enum as its CBOR value.
fn csil_enc_app_access_mode(csil_v: &AppAccessMode) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_app_access_mode(csil_v: &CsilCborValue) -> Result<AppAccessMode, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    AppAccessMode::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown AppAccessMode value {number}")))
}

/// Encode a AppAccessMode to canonical CSIL CBOR bytes.
pub fn encode_app_access_mode(csil_v: &AppAccessMode) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_app_access_mode(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AppAccessMode.
pub fn decode_app_access_mode(csil_data: &[u8]) -> Result<AppAccessMode, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_app_access_mode(&csil_root)
}

/// Encode a AppAccessTargetKind enum as its CBOR value.
fn csil_enc_app_access_target_kind(
    csil_v: &AppAccessTargetKind,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_app_access_target_kind(
    csil_v: &CsilCborValue,
) -> Result<AppAccessTargetKind, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    AppAccessTargetKind::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown AppAccessTargetKind value {number}"
        ))
    })
}

/// Encode a AppAccessTargetKind to canonical CSIL CBOR bytes.
pub fn encode_app_access_target_kind(
    csil_v: &AppAccessTargetKind,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_app_access_target_kind(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AppAccessTargetKind.
pub fn decode_app_access_target_kind(
    csil_data: &[u8],
) -> Result<AppAccessTargetKind, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_app_access_target_kind(&csil_root)
}

/// Encode a ClaimOperator enum as its CBOR value.
fn csil_enc_claim_operator(csil_v: &ClaimOperator) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_claim_operator(csil_v: &CsilCborValue) -> Result<ClaimOperator, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    ClaimOperator::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown ClaimOperator value {number}")))
}

/// Encode a ClaimOperator to canonical CSIL CBOR bytes.
pub fn encode_claim_operator(csil_v: &ClaimOperator) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim_operator(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ClaimOperator.
pub fn decode_claim_operator(csil_data: &[u8]) -> Result<ClaimOperator, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_operator(&csil_root)
}

/// Encode a ApplicationKeyChallengePurpose enum as its CBOR value.
fn csil_enc_application_key_challenge_purpose(
    csil_v: &ApplicationKeyChallengePurpose,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_application_key_challenge_purpose(
    csil_v: &CsilCborValue,
) -> Result<ApplicationKeyChallengePurpose, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    ApplicationKeyChallengePurpose::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown ApplicationKeyChallengePurpose value {number}"
        ))
    })
}

/// Encode a ApplicationKeyChallengePurpose to canonical CSIL CBOR bytes.
pub fn encode_application_key_challenge_purpose(
    csil_v: &ApplicationKeyChallengePurpose,
) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_application_key_challenge_purpose(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApplicationKeyChallengePurpose.
pub fn decode_application_key_challenge_purpose(
    csil_data: &[u8],
) -> Result<ApplicationKeyChallengePurpose, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_application_key_challenge_purpose(&csil_root)
}

/// Encode a AuthFlow enum as its CBOR value.
fn csil_enc_auth_flow(csil_v: &AuthFlow) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_auth_flow(csil_v: &CsilCborValue) -> Result<AuthFlow, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    AuthFlow::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown AuthFlow value {number}")))
}

/// Encode a AuthFlow to canonical CSIL CBOR bytes.
pub fn encode_auth_flow(csil_v: &AuthFlow) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_auth_flow(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AuthFlow.
pub fn decode_auth_flow(csil_data: &[u8]) -> Result<AuthFlow, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_auth_flow(&csil_root)
}

/// Encode a RpCacheStatus enum as its CBOR value.
fn csil_enc_rp_cache_status(csil_v: &RpCacheStatus) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_rp_cache_status(csil_v: &CsilCborValue) -> Result<RpCacheStatus, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    RpCacheStatus::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown RpCacheStatus value {number}")))
}

/// Encode a RpCacheStatus to canonical CSIL CBOR bytes.
pub fn encode_rp_cache_status(csil_v: &RpCacheStatus) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_cache_status(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpCacheStatus.
pub fn decode_rp_cache_status(csil_data: &[u8]) -> Result<RpCacheStatus, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_cache_status(&csil_root)
}

/// Encode a AccountKind enum as its CBOR value.
fn csil_enc_account_kind(csil_v: &AccountKind) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_account_kind(csil_v: &CsilCborValue) -> Result<AccountKind, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    AccountKind::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown AccountKind value {number}")))
}

/// Encode a AccountKind to canonical CSIL CBOR bytes.
pub fn encode_account_kind(csil_v: &AccountKind) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_account_kind(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a AccountKind.
pub fn decode_account_kind(csil_data: &[u8]) -> Result<AccountKind, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_account_kind(&csil_root)
}

/// Encode a RpErrorCode enum as its CBOR value.
fn csil_enc_rp_error_code(csil_v: &RpErrorCode) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_rp_error_code(csil_v: &CsilCborValue) -> Result<RpErrorCode, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    RpErrorCode::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown RpErrorCode value {number}")))
}

/// Encode a RpErrorCode to canonical CSIL CBOR bytes.
pub fn encode_rp_error_code(csil_v: &RpErrorCode) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_rp_error_code(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a RpErrorCode.
pub fn decode_rp_error_code(csil_data: &[u8]) -> Result<RpErrorCode, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_rp_error_code(&csil_root)
}

/// Encode a IssuedClaimOutcome enum as its CBOR value.
fn csil_enc_issued_claim_outcome(
    csil_v: &IssuedClaimOutcome,
) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_issued_claim_outcome(
    csil_v: &CsilCborValue,
) -> Result<IssuedClaimOutcome, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    IssuedClaimOutcome::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown IssuedClaimOutcome value {number}"
        ))
    })
}

/// Encode a IssuedClaimOutcome to canonical CSIL CBOR bytes.
pub fn encode_issued_claim_outcome(csil_v: &IssuedClaimOutcome) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_issued_claim_outcome(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a IssuedClaimOutcome.
pub fn decode_issued_claim_outcome(csil_data: &[u8]) -> Result<IssuedClaimOutcome, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_issued_claim_outcome(&csil_root)
}

/// Encode a VerifyingParty enum as its CBOR value.
fn csil_enc_verifying_party(csil_v: &VerifyingParty) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_verifying_party(csil_v: &CsilCborValue) -> Result<VerifyingParty, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    VerifyingParty::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown VerifyingParty value {number}")))
}

/// Encode a VerifyingParty to canonical CSIL CBOR bytes.
pub fn encode_verifying_party(csil_v: &VerifyingParty) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_verifying_party(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a VerifyingParty.
pub fn decode_verifying_party(csil_data: &[u8]) -> Result<VerifyingParty, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_verifying_party(&csil_root)
}

/// Encode a ClaimCheckStatus enum as its CBOR value.
fn csil_enc_claim_check_status(csil_v: &ClaimCheckStatus) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_claim_check_status(csil_v: &CsilCborValue) -> Result<ClaimCheckStatus, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    ClaimCheckStatus::from_number(number).ok_or_else(|| {
        CsilCborError(format!(
            "csil cbor: unknown ClaimCheckStatus value {number}"
        ))
    })
}

/// Encode a ClaimCheckStatus to canonical CSIL CBOR bytes.
pub fn encode_claim_check_status(csil_v: &ClaimCheckStatus) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_claim_check_status(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ClaimCheckStatus.
pub fn decode_claim_check_status(csil_data: &[u8]) -> Result<ClaimCheckStatus, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_claim_check_status(&csil_root)
}

/// Encode a ApiErrorCode enum as its CBOR value.
fn csil_enc_api_error_code(csil_v: &ApiErrorCode) -> Result<CsilCborValue, CsilCborError> {
    Ok(cbor_int(csil_v.to_number()))
}

fn csil_dec_api_error_code(csil_v: &CsilCborValue) -> Result<ApiErrorCode, CsilCborError> {
    let number = cbor_as_i64(csil_v)?;
    ApiErrorCode::from_number(number)
        .ok_or_else(|| CsilCborError(format!("csil cbor: unknown ApiErrorCode value {number}")))
}

/// Encode a ApiErrorCode to canonical CSIL CBOR bytes.
pub fn encode_api_error_code(csil_v: &ApiErrorCode) -> Result<Vec<u8>, CsilCborError> {
    let csil_tree = csil_enc_api_error_code(csil_v)?;
    Ok(cbor_encode(&csil_tree))
}

/// Decode canonical CSIL CBOR bytes into a ApiErrorCode.
pub fn decode_api_error_code(csil_data: &[u8]) -> Result<ApiErrorCode, CsilCborError> {
    let csil_root = cbor_decode(csil_data)?;
    csil_dec_api_error_code(&csil_root)
}

pub fn encode_rp_sign_request_reply(
    reply: Result<RpSignResponse, RpError>,
) -> Result<(&'static str, Vec<u8>), CsilCborError> {
    Ok(match reply {
        Ok(value) => ("RpSignResponse", encode_rp_sign_response(&value)?),
        Err(value) => ("RpError", encode_rp_error(&value)?),
    })
}

pub fn encode_rp_decrypt_token_reply(
    reply: Result<RpDecryptResponse, RpError>,
) -> Result<(&'static str, Vec<u8>), CsilCborError> {
    Ok(match reply {
        Ok(value) => ("RpDecryptResponse", encode_rp_decrypt_response(&value)?),
        Err(value) => ("RpError", encode_rp_error(&value)?),
    })
}

pub fn encode_rp_verify_assertion_reply(
    reply: Result<RpVerifyResponse, RpError>,
) -> Result<(&'static str, Vec<u8>), CsilCborError> {
    Ok(match reply {
        Ok(value) => ("RpVerifyResponse", encode_rp_verify_response(&value)?),
        Err(value) => ("RpError", encode_rp_error(&value)?),
    })
}

pub fn encode_rp_userinfo_fetch_reply(
    reply: Result<UserInfo, RpError>,
) -> Result<(&'static str, Vec<u8>), CsilCborError> {
    Ok(match reply {
        Ok(value) => ("UserInfo", encode_user_info(&value)?),
        Err(value) => ("RpError", encode_rp_error(&value)?),
    })
}
