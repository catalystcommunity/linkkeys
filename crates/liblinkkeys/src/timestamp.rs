//! Timestamps: RFC 3339 text, and the form a signed payload carries.
//!
//! LINKKEYS-TRUST-CRITICAL: expiry, revocation, and freshness checks in the
//! signed-structure verifiers use these timestamps, and signed payloads carry
//! [`SignedTime`].
//!
//! On the wire, a timestamp is a CSIL `timestamp` (CBOR tag 0), which the
//! generated codec writes. A signed tuple payload carries [`SignedTime`]: whole
//! Unix seconds as a CBOR integer. Every language writes an integer the same
//! way, so a verifier rebuilds the exact signed bytes from decoded fields. A
//! signed timestamp must be whole seconds; [`whole_seconds`] makes one.
//!
//! The text below is for storage and logs. Its format is fixed. It is the format that `chrono` wrote before the
//! switch to `time`, so signed payloads, test vectors, and stored SQLite text
//! stay byte-identical, and SQLite text comparisons keep their order:
//!
//! - The default form ([`Rfc3339::to_rfc3339`]) is
//!   `YYYY-MM-DDTHH:MM:SS[.fff|.ffffff|.fffffffff]+00:00`. The fraction has 0,
//!   3, 6, or 9 digits, the fewest that hold the value. The offset is numeric,
//!   never `Z`.
//! - The whole-second form ([`Rfc3339::to_rfc3339_secs_z`]) is
//!   `YYYY-MM-DDTHH:MM:SSZ`.
//!
//! [`parse_rfc3339`] accepts what `chrono::DateTime::parse_from_rfc3339`
//! accepted: `T`, `t`, or a space between date and time; any number of
//! fraction digits (digits after the ninth are ignored); `Z`, `z`, or a
//! `±HH:MM` offset up to ±23:59; a leap second `:60`. The result is in UTC.

use std::fmt;

pub use time::{Date, Duration, Month, OffsetDateTime, UtcOffset};

/// Why a timestamp did not parse. The text names the failed rule only, never
/// the input, so it is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampError(&'static str);

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for TimestampError {}

const TOO_SHORT: TimestampError = TimestampError("timestamp is too short");
const TOO_LONG: TimestampError = TimestampError("timestamp has trailing characters");
const INVALID: TimestampError = TimestampError("timestamp is not RFC 3339");
const OUT_OF_RANGE: TimestampError = TimestampError("timestamp field is out of range");
const FRACTION: TimestampError =
    TimestampError("a signed timestamp must be a whole number of seconds");

/// A timestamp inside a signed payload: whole Unix seconds. Serializes as a
/// CBOR integer. Build it with [`SignedTime::new`], which refuses a fraction
/// of a second, so the signer and every verifier sign the same instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct SignedTime(i64);

impl SignedTime {
    /// The signed form of `t`. Fails when `t` has a fraction of a second.
    pub fn new(t: &OffsetDateTime) -> Result<Self, TimestampError> {
        if t.nanosecond() != 0 {
            return Err(FRACTION);
        }
        Ok(SignedTime(t.unix_timestamp()))
    }

    /// The Unix time in seconds.
    pub fn seconds(self) -> i64 {
        self.0
    }
}

/// `t` without its fraction of a second (rounded down), in UTC.
pub fn whole_seconds(t: OffsetDateTime) -> OffsetDateTime {
    t.to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .expect("zero is a valid nanosecond")
}

/// The current time in whole seconds, for a timestamp that will be signed.
pub fn now_whole_seconds() -> OffsetDateTime {
    whole_seconds(OffsetDateTime::now_utc())
}

/// `t` without its sub-millisecond part (rounded down), in UTC.
///
/// Every timestamp that LinkKeys stores or sends has millisecond precision or
/// coarser. A JavaScript `Date` holds milliseconds, and the generated
/// TypeScript codec rejects a finer timestamp instead of rounding it.
pub fn whole_milliseconds(t: OffsetDateTime) -> OffsetDateTime {
    let nanos = t.nanosecond();
    t.to_offset(UtcOffset::UTC)
        .replace_nanosecond(nanos - nanos % 1_000_000)
        .expect("a smaller nanosecond is valid")
}

/// The current time in whole milliseconds. Use it for every timestamp that is
/// not signed. A signed timestamp uses [`now_whole_seconds`].
pub fn now_whole_milliseconds() -> OffsetDateTime {
    whole_milliseconds(OffsetDateTime::now_utc())
}

/// The LinkKeys RFC 3339 text forms of an [`OffsetDateTime`].
pub trait Rfc3339 {
    /// The default form, with a numeric offset and an automatic fraction.
    fn to_rfc3339(&self) -> String;
    /// Whole seconds, with `Z` for UTC.
    fn to_rfc3339_secs_z(&self) -> String;
}

impl Rfc3339 for OffsetDateTime {
    fn to_rfc3339(&self) -> String {
        let mut out = String::with_capacity(35);
        write_date_time(&mut out, self);
        let nanos = self.nanosecond();
        if nanos != 0 {
            if nanos.is_multiple_of(1_000_000) {
                out.push_str(&format!(".{:03}", nanos / 1_000_000));
            } else if nanos.is_multiple_of(1_000) {
                out.push_str(&format!(".{:06}", nanos / 1_000));
            } else {
                out.push_str(&format!(".{:09}", nanos));
            }
        }
        write_offset(&mut out, self.offset(), false);
        out
    }

    fn to_rfc3339_secs_z(&self) -> String {
        let mut out = String::with_capacity(25);
        write_date_time(&mut out, self);
        write_offset(&mut out, self.offset(), true);
        out
    }
}

fn write_date_time(out: &mut String, t: &OffsetDateTime) {
    let year = t.year();
    if (0..10_000).contains(&year) {
        out.push_str(&format!("{year:04}"));
    } else {
        out.push_str(&format!("{year:+05}"));
    }
    out.push_str(&format!(
        "-{:02}-{:02}T{:02}:{:02}:{:02}",
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    ));
}

fn write_offset(out: &mut String, offset: UtcOffset, use_z: bool) {
    if use_z && offset.is_utc() {
        out.push('Z');
        return;
    }
    let total_minutes = offset.whole_minutes();
    let sign = if total_minutes < 0 { '-' } else { '+' };
    let minutes = total_minutes.unsigned_abs();
    out.push_str(&format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60));
}

/// Parse RFC 3339 text into a UTC [`OffsetDateTime`]. See the module
/// documentation for the accepted forms.
pub fn parse_rfc3339(s: &str) -> Result<OffsetDateTime, TimestampError> {
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return Err(TOO_SHORT);
    }
    let digit = |index: usize| -> Result<u8, TimestampError> {
        let byte = bytes[index];
        if byte.is_ascii_digit() {
            Ok(byte - b'0')
        } else {
            Err(INVALID)
        }
    };
    let pair =
        |index: usize| -> Result<u8, TimestampError> { Ok(digit(index)? * 10 + digit(index + 1)?) };
    let expect = |index: usize, byte: u8| -> Result<(), TimestampError> {
        if bytes[index] == byte {
            Ok(())
        } else {
            Err(INVALID)
        }
    };

    let year = i32::from(pair(0)?) * 100 + i32::from(pair(2)?);
    expect(4, b'-')?;
    let month = pair(5)?;
    expect(7, b'-')?;
    let day = pair(8)?;
    if !matches!(bytes[10], b'T' | b't' | b' ') {
        return Err(INVALID);
    }
    let hour = pair(11)?;
    expect(13, b':')?;
    let minute = pair(14)?;
    expect(16, b':')?;
    let second = pair(17)?;

    let month = Month::try_from(month).map_err(|_| OUT_OF_RANGE)?;
    let date = Date::from_calendar_date(year, month, day).map_err(|_| OUT_OF_RANGE)?;

    let mut rest = &s[19..];
    let mut nanos: u32 = 0;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(INVALID);
        }
        for (position, byte) in fraction.bytes().take(digits.min(9)).enumerate() {
            nanos += u32::from(byte - b'0') * 10u32.pow(8 - position as u32);
        }
        rest = &fraction[digits..];
    }

    // A leap second has no representation in `time`. Read it as the last
    // representable instant of that minute, so ordering stays correct.
    let (second, nanos) = match second {
        60 => (59, 999_999_999),
        _ => (second, nanos),
    };
    let date_time = date
        .with_hms_nano(hour, minute, second, nanos)
        .map_err(|_| OUT_OF_RANGE)?;

    let offset_seconds: i32 = match rest.as_bytes().first() {
        Some(b'Z' | b'z') => {
            rest = &rest[1..];
            0
        }
        Some(_) => {
            let (negative, after_sign) = if let Some(r) = rest.strip_prefix('+') {
                (false, r)
            } else if let Some(r) = rest.strip_prefix('-') {
                (true, r)
            } else if let Some(r) = rest.strip_prefix('\u{2212}') {
                (true, r)
            } else {
                return Err(INVALID);
            };
            let offset = after_sign.as_bytes();
            if offset.len() < 5 {
                return Err(TOO_SHORT);
            }
            if !offset[..2]
                .iter()
                .chain(&offset[3..5])
                .all(u8::is_ascii_digit)
                || offset[2] != b':'
            {
                return Err(INVALID);
            }
            let hours = i32::from((offset[0] - b'0') * 10 + (offset[1] - b'0'));
            let minutes = i32::from((offset[3] - b'0') * 10 + (offset[4] - b'0'));
            if hours > 23 || minutes > 59 {
                return Err(OUT_OF_RANGE);
            }
            rest = &after_sign[5..];
            let seconds = hours * 3600 + minutes * 60;
            if negative {
                -seconds
            } else {
                seconds
            }
        }
        None => return Err(TOO_SHORT),
    };
    if !rest.is_empty() {
        return Err(TOO_LONG);
    }

    let offset = UtcOffset::from_whole_seconds(offset_seconds).map_err(|_| OUT_OF_RANGE)?;
    Ok(date_time.assume_offset(offset).to_offset(UtcOffset::UTC))
}

/// Parse a calendar date written `YYYY-MM-DD`, as `chrono`'s `%Y-%m-%d` read
/// it: the month and day may have one or two digits, and the year may have a
/// sign.
pub fn parse_date_ymd(s: &str) -> Result<Date, TimestampError> {
    let mut parts = s.splitn(3, '-');
    let (year, month, day) = match (parts.next(), parts.next(), parts.next()) {
        (Some(y), Some(m), Some(d)) => (y, m, d),
        _ => return Err(INVALID),
    };
    // A leading '-' of a negative year makes the first part empty.
    let (year, month, day) = if year.is_empty() {
        let mut rest = s[1..].splitn(3, '-');
        match (rest.next(), rest.next(), rest.next()) {
            (Some(y), Some(m), Some(d)) => (format!("-{y}"), m, d),
            _ => return Err(INVALID),
        }
    } else {
        (year.to_string(), month, day)
    };
    let year_digits = year.trim_start_matches(['+', '-']);
    if year_digits.is_empty() || !year_digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(INVALID);
    }
    let small = |part: &str| -> Result<u8, TimestampError> {
        if (1..=2).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()) {
            part.parse().map_err(|_| INVALID)
        } else {
            Err(INVALID)
        }
    };
    let year: i32 = year.parse().map_err(|_| OUT_OF_RANGE)?;
    let month = Month::try_from(small(month)?).map_err(|_| OUT_OF_RANGE)?;
    Date::from_calendar_date(year, month, small(day)?).map_err(|_| OUT_OF_RANGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_milliseconds_drops_only_the_sub_millisecond_part() {
        let t = parse_rfc3339("2026-04-08T01:51:13.616455789+02:00").unwrap();
        let ms = whole_milliseconds(t);
        assert_eq!(ms.to_rfc3339(), "2026-04-07T23:51:13.616+00:00");
        assert_eq!(whole_milliseconds(ms), ms);
        let whole = parse_rfc3339("2026-04-08T01:51:13+00:00").unwrap();
        assert_eq!(whole_milliseconds(whole), whole);
        assert_eq!(now_whole_milliseconds().nanosecond() % 1_000_000, 0);
    }

    #[test]
    fn signed_time_is_whole_unix_seconds() {
        let t = parse_rfc3339("2026-11-22T10:00:00+00:00").unwrap();
        assert_eq!(SignedTime::new(&t).unwrap().seconds(), 1_795_341_600);
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&SignedTime::new(&t).unwrap(), &mut cbor).unwrap();
        assert_eq!(cbor, [0x1a, 0x6b, 0x02, 0xbd, 0x20]);

        let fractional = parse_rfc3339("2026-11-22T10:00:00.5+00:00").unwrap();
        assert_eq!(SignedTime::new(&fractional), Err(FRACTION));
        assert_eq!(
            SignedTime::new(&whole_seconds(fractional)).unwrap(),
            SignedTime::new(&t).unwrap()
        );
    }

    fn at(s: &str) -> OffsetDateTime {
        parse_rfc3339(s).unwrap()
    }

    #[test]
    fn default_form_uses_numeric_offset_and_automatic_fraction() {
        assert_eq!(
            at("2026-01-01T00:00:00Z").to_rfc3339(),
            "2026-01-01T00:00:00+00:00"
        );
        assert_eq!(
            at("2026-01-01T00:00:00.5Z").to_rfc3339(),
            "2026-01-01T00:00:00.500+00:00"
        );
        assert_eq!(
            at("2026-01-01T00:00:00.123456Z").to_rfc3339(),
            "2026-01-01T00:00:00.123456+00:00"
        );
        assert_eq!(
            at("2026-01-01T00:00:00.1234567Z").to_rfc3339(),
            "2026-01-01T00:00:00.123456700+00:00"
        );
        assert_eq!(
            at("2026-01-01T00:00:00.000001Z").to_rfc3339(),
            "2026-01-01T00:00:00.000001+00:00"
        );
    }

    #[test]
    fn secs_z_form_drops_the_fraction() {
        assert_eq!(
            at("2026-10-06T12:00:00.987+00:00").to_rfc3339_secs_z(),
            "2026-10-06T12:00:00Z"
        );
    }

    #[test]
    fn parse_normalizes_offsets_to_utc() {
        let t = at("2026-01-01T05:30:00+05:30");
        assert!(t.offset().is_utc());
        assert_eq!(t.to_rfc3339(), "2026-01-01T00:00:00+00:00");
        assert_eq!(at("2025-12-31T23:00:00-01:00"), at("2026-01-01T00:00:00Z"));
        assert_eq!(
            at("2025-12-31T23:00:00\u{2212}01:00"),
            at("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn parse_accepts_chrono_relaxations() {
        assert_eq!(at("2026-01-01t00:00:00z"), at("2026-01-01T00:00:00Z"));
        assert_eq!(at("2026-01-01 00:00:00Z"), at("2026-01-01T00:00:00Z"));
        assert_eq!(
            at("2026-01-01T00:00:00.1234567891234Z").nanosecond(),
            123_456_789
        );
        assert_eq!(at("2016-12-31T23:59:60Z").second(), 59);
    }

    #[test]
    fn parse_rejects_malformed_text() {
        for bad in [
            "",
            "2026-01-01",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00+0000",
            "2026-01-01T00:00:00+24:00",
            "2026-01-01T00:00:00.Z",
            "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:00:00Zjunk",
            "2026-01-01X00:00:00Z",
        ] {
            assert!(parse_rfc3339(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn round_trip_is_stable() {
        for s in [
            "2026-01-01T00:00:00+00:00",
            "2026-06-01T12:34:56.789+00:00",
            "2026-06-01T12:34:56.789012+00:00",
            "2026-06-01T12:34:56.789012345+00:00",
        ] {
            assert_eq!(at(s).to_rfc3339(), s);
        }
    }

    #[test]
    fn dates_parse_like_chrono_ymd() {
        assert_eq!(
            parse_date_ymd("2026-01-05").unwrap().to_string(),
            "2026-01-05"
        );
        assert_eq!(
            parse_date_ymd("2026-1-5").unwrap().to_string(),
            "2026-01-05"
        );
        for bad in [
            "2026-01",
            "2026-001-05",
            "2026-02-30",
            "x-01-01",
            "2026-01-05T",
        ] {
            assert!(parse_date_ymd(bad).is_err(), "{bad:?} parsed");
        }
    }
}
