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

#[cfg(test)]
mod tests {
    use super::{parse_nonzero_u16, parse_nonzero_u64};

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
}
