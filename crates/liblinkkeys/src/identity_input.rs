//! Parsing for the identity value that a relying party collects before login.

use std::fmt;

/// A validated LinkKeys login destination and optional username hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityInput {
    pub username: Option<String>,
    pub domain: String,
}

/// The identity input is not a valid `username@domain` or bare domain value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidIdentityInput;

impl fmt::Display for InvalidIdentityInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("identity must be a username@domain or a domain")
    }
}

impl std::error::Error for InvalidIdentityInput {}

/// Parse a relying-party login field.
///
/// A bare domain selects the provider and does not create a username hint.
/// A `username@domain` value also creates the hint. A numeric port is allowed
/// for development destinations such as `localhost:8443`.
pub fn parse_identity_input(input: &str) -> Result<IdentityInput, InvalidIdentityInput> {
    let input = input.trim();
    if input.is_empty() || !input.is_ascii() {
        return Err(InvalidIdentityInput);
    }

    let mut parts = input.split('@');
    let first = parts.next().expect("split always has one item");
    let second = parts.next();
    if parts.next().is_some() {
        return Err(InvalidIdentityInput);
    }

    let (username, domain) = match second {
        Some(domain) if valid_username(first) => (Some(first.to_string()), domain),
        Some(_) => return Err(InvalidIdentityInput),
        None => (None, first),
    };
    if !valid_domain(domain) {
        return Err(InvalidIdentityInput);
    }

    Ok(IdentityInput {
        username,
        domain: domain.to_ascii_lowercase(),
    })
}

fn valid_username(username: &str) -> bool {
    if username.is_empty()
        || username.len() > 64
        || username.starts_with('.')
        || username.ends_with('.')
    {
        return false;
    }
    let mut previous_dot = false;
    for byte in username.bytes() {
        let valid = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'/'
                    | b'='
                    | b'?'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'{'
                    | b'|'
                    | b'}'
                    | b'~'
                    | b'.'
            );
        if !valid || (byte == b'.' && previous_dot) {
            return false;
        }
        previous_dot = byte == b'.';
    }
    true
}

fn valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 259 {
        return false;
    }
    let (host, has_port) = match domain.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return false;
            }
            let Ok(port) = port.parse::<u16>() else {
                return false;
            };
            if port == 0 {
                return false;
            }
            (host, true)
        }
        Some(_) => return false,
        None => (domain, false),
    };
    if host.is_empty() || host.len() > 253 || (!host.contains('.') && !has_port) {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_login_and_bare_destination() {
        assert_eq!(
            parse_identity_input(" Alice.Tag+work@ID.Example.COM ").unwrap(),
            IdentityInput {
                username: Some("Alice.Tag+work".to_string()),
                domain: "id.example.com".to_string(),
            }
        );
        assert_eq!(
            parse_identity_input("localhost:8443").unwrap(),
            IdentityInput {
                username: None,
                domain: "localhost:8443".to_string(),
            }
        );
        assert_eq!(
            parse_identity_input("example.com").unwrap(),
            IdentityInput {
                username: None,
                domain: "example.com".to_string(),
            }
        );
    }

    #[test]
    fn rejects_malformed_values() {
        for input in [
            "",
            "alice",
            "@example.com",
            "alice@",
            "alice@@example.com",
            "alice two@example.com",
            "alice..two@example.com",
            "https://example.com",
            "example.com/login",
            ".example.com",
            "example..com",
            "-example.com",
            "example.com:0",
            "example.com:65536",
            "example.com:+443",
            "example.com:https",
            "[::1]:8443",
        ] {
            assert!(parse_identity_input(input).is_err(), "accepted {input:?}");
        }
    }
}
