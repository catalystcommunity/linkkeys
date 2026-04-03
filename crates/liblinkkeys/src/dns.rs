use std::fmt;

/// Parsed LinkKeys DNS TXT record.
///
/// Expected format at `_linkkeys.{domain}`:
///   `v=lk1 api={base_url} fp={fingerprint1} fp={fingerprint2} ...`
///
/// The `v=lk1` tag identifies this as a LinkKeys v1 record.
/// The `api=` field is the base URL for the LinkKeys API (no trailing slash).
/// The `fp=` fields are SHA-256 hex fingerprints of domain public keys.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkKeysRecord {
    pub api_base: String,
    pub fingerprints: Vec<String>,
}

#[derive(Debug)]
pub enum DnsParseError {
    NoLinkKeysRecord,
    MissingVersion,
    UnsupportedVersion(String),
    MissingApiField,
    InvalidFormat(String),
}

impl fmt::Display for DnsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsParseError::NoLinkKeysRecord => write!(f, "no _linkkeys TXT record found"),
            DnsParseError::MissingVersion => write!(f, "missing v= tag in TXT record"),
            DnsParseError::UnsupportedVersion(v) => {
                write!(f, "unsupported linkkeys version: {}", v)
            }
            DnsParseError::MissingApiField => write!(f, "missing api= field in TXT record"),
            DnsParseError::InvalidFormat(msg) => write!(f, "invalid TXT record format: {}", msg),
        }
    }
}

impl std::error::Error for DnsParseError {}

/// The DNS name to query for a given domain.
pub fn linkkeys_dns_name(domain: &str) -> String {
    format!("_linkkeys.{}", domain)
}

/// Parse a single TXT record string into a LinkKeysRecord.
/// Returns None if this TXT record isn't a linkkeys record (no v=lk1 tag).
pub fn parse_linkkeys_txt(txt: &str) -> Result<LinkKeysRecord, DnsParseError> {
    let parts: Vec<&str> = txt.split_whitespace().collect();
    if parts.is_empty() {
        return Err(DnsParseError::MissingVersion);
    }

    // Find version tag
    let version = parts
        .iter()
        .find(|p| p.starts_with("v="))
        .map(|p| &p[2..])
        .ok_or(DnsParseError::MissingVersion)?;

    if version != "lk1" {
        return Err(DnsParseError::UnsupportedVersion(version.to_string()));
    }

    // Find api= field
    let api_base = parts
        .iter()
        .find(|p| p.starts_with("api="))
        .map(|p| p[4..].to_string())
        .ok_or(DnsParseError::MissingApiField)?;

    if api_base.is_empty() {
        return Err(DnsParseError::MissingApiField);
    }

    // Collect fingerprints
    let fingerprints: Vec<String> = parts
        .iter()
        .filter(|p| p.starts_with("fp="))
        .map(|p| p[3..].to_string())
        .collect();

    Ok(LinkKeysRecord {
        api_base,
        fingerprints,
    })
}

/// Build the expected TXT record string from components.
pub fn build_linkkeys_txt(api_base: &str, fingerprints: &[String]) -> String {
    let mut parts = vec![format!("v=lk1 api={}", api_base)];
    for fp in fingerprints {
        parts.push(format!("fp={}", fp));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_record() {
        let txt = "v=lk1 api=https://auth.example.com/linkkeys fp=abcdef123456 fp=789012345678";
        let record = parse_linkkeys_txt(txt).unwrap();
        assert_eq!(record.api_base, "https://auth.example.com/linkkeys");
        assert_eq!(record.fingerprints, vec!["abcdef123456", "789012345678"]);
    }

    #[test]
    fn test_parse_api_only() {
        let txt = "v=lk1 api=https://example.com";
        let record = parse_linkkeys_txt(txt).unwrap();
        assert_eq!(record.api_base, "https://example.com");
        assert!(record.fingerprints.is_empty());
    }

    #[test]
    fn test_parse_missing_version() {
        let txt = "api=https://example.com fp=abc";
        assert!(matches!(
            parse_linkkeys_txt(txt),
            Err(DnsParseError::MissingVersion)
        ));
    }

    #[test]
    fn test_parse_wrong_version() {
        let txt = "v=lk99 api=https://example.com";
        assert!(matches!(
            parse_linkkeys_txt(txt),
            Err(DnsParseError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn test_parse_missing_api() {
        let txt = "v=lk1 fp=abc";
        assert!(matches!(
            parse_linkkeys_txt(txt),
            Err(DnsParseError::MissingApiField)
        ));
    }

    #[test]
    fn test_dns_name() {
        assert_eq!(linkkeys_dns_name("example.com"), "_linkkeys.example.com");
        assert_eq!(
            linkkeys_dns_name("auth.example.com"),
            "_linkkeys.auth.example.com"
        );
    }

    #[test]
    fn test_build_and_parse_roundtrip() {
        let fps = vec!["abc123".to_string(), "def456".to_string()];
        let txt = build_linkkeys_txt("https://idp.example.com/api", &fps);
        let record = parse_linkkeys_txt(&txt).unwrap();
        assert_eq!(record.api_base, "https://idp.example.com/api");
        assert_eq!(record.fingerprints, fps);
    }

    #[test]
    fn test_order_independence() {
        let txt = "fp=aaa v=lk1 fp=bbb api=https://x.com fp=ccc";
        let record = parse_linkkeys_txt(txt).unwrap();
        assert_eq!(record.api_base, "https://x.com");
        assert_eq!(record.fingerprints, vec!["aaa", "bbb", "ccc"]);
    }
}
