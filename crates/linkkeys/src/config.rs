//! Shared parsing for server environment variables.

use std::env;

fn parse_nonzero_u16(name: &str, value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{name} must be an integer from 1 to 65535"))
}

fn parse_nonzero_u64(name: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{name} must be an integer greater than zero"))
}

pub fn nonzero_u16_env(name: &str, default: u16) -> Result<u16, String> {
    match env::var(name) {
        Ok(value) => parse_nonzero_u16(name, &value),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must contain text")),
    }
}

pub fn nonzero_u64_env(name: &str, default: u64) -> Result<u64, String> {
    match env::var(name) {
        Ok(value) => parse_nonzero_u64(name, &value),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must contain text")),
    }
}

fn parse_nonneg_i64(name: &str, value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .ok()
        .filter(|value| *value >= 0)
        .ok_or_else(|| format!("{name} must be an integer of zero or more"))
}

fn parse_positive_f64(name: &str, value: &str) -> Result<f64, String> {
    value
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or_else(|| format!("{name} must be a number greater than zero"))
}

fn parse_bool(name: &str, value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("{name} must be true or false")),
    }
}

/// A count that is allowed to be zero, so an operator can turn a bound off
/// deliberately rather than by writing a value the parser silently rejects.
pub fn nonneg_i64_env(name: &str, default: i64) -> Result<i64, String> {
    match env::var(name) {
        Ok(value) => parse_nonneg_i64(name, &value),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must contain text")),
    }
}

/// A rate, in units per second. Rates are fractional (100 requests per minute
/// is 1.667 per second), so they cannot be integers.
pub fn positive_f64_env(name: &str, default: f64) -> Result<f64, String> {
    match env::var(name) {
        Ok(value) => parse_positive_f64(name, &value),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must contain text")),
    }
}

pub fn bool_env(name: &str, default: bool) -> Result<bool, String> {
    match env::var(name) {
        Ok(value) => parse_bool(name, &value),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must contain text")),
    }
}

/// A non-empty string setting. An empty value is treated as absent, so an
/// operator who blanks a variable gets the default rather than an empty name.
pub fn string_env(name: &str, default: &str) -> String {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => default.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_bool, parse_nonneg_i64, parse_nonzero_u16, parse_nonzero_u64, parse_positive_f64,
    };

    #[test]
    fn parses_valid_values() {
        assert_eq!(parse_nonzero_u16("PORT", "443"), Ok(443));
        assert_eq!(parse_nonzero_u64("TIMEOUT", "60"), Ok(60));
    }

    #[test]
    fn rejects_zero_invalid_and_out_of_range_values() {
        for value in ["0", "invalid", "65536"] {
            assert!(parse_nonzero_u16("PORT", value).is_err());
        }
        for value in ["0", "invalid", "18446744073709551616"] {
            assert!(parse_nonzero_u64("TIMEOUT", value).is_err());
        }
    }

    #[test]
    fn parses_the_wider_value_shapes() {
        assert_eq!(parse_nonneg_i64("WINDOW", "0"), Ok(0));
        assert_eq!(parse_nonneg_i64("WINDOW", "94608000"), Ok(94_608_000));
        assert!(parse_nonneg_i64("WINDOW", "-1").is_err());
        assert_eq!(parse_positive_f64("RATE", "1.6667"), Ok(1.6667));
        for value in ["0", "-1", "nan", "inf"] {
            assert!(parse_positive_f64("RATE", value).is_err());
        }
        for (value, expected) in [("true", true), ("YES", true), ("0", false), ("off", false)] {
            assert_eq!(parse_bool("FLAG", value), Ok(expected));
        }
        assert!(parse_bool("FLAG", "maybe").is_err());
    }
}
