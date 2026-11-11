//! Callback URLs of regular-RP login requests.
//!
//! The RP domain is the trust identity of a regular RP, and the calling
//! API-key account is the application principal in that domain. The RP
//! domain signs the callback URL, and that signature is the authorization:
//! the callback host does not have to be in the RP domain. The token at the
//! callback is sealed to the RP domain's key, so only the RP server can open
//! it.
//!
//! A callback URL must be `https`, have a host, and have no user information
//! (`https://a@b/` hides the real host from a person). The consent screen
//! shows the host when it is outside the RP domain.

/// Why a callback URL cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackUrlError {
    NotHttps,
    Unparseable,
}

/// Parse a callback URL and return its host.
pub fn callback_host(callback_url: &str) -> Result<String, CallbackUrlError> {
    if !callback_url.starts_with("https://") {
        return Err(CallbackUrlError::NotHttps);
    }
    let url = reqwest::Url::parse(callback_url).map_err(|_| CallbackUrlError::Unparseable)?;
    if url.scheme() != "https" {
        return Err(CallbackUrlError::NotHttps);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CallbackUrlError::Unparseable);
    }
    url.host_str()
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .ok_or(CallbackUrlError::Unparseable)
}

/// True when `host` is `domain` or a strict subdomain of it.
pub fn host_in_domain(host: &str, domain: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let domain = domain.to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_host_accepts_any_https_host() {
        assert_eq!(
            callback_host("https://HomeGrafana.catalystsquad.com:8443/cb?x=1"),
            Ok("homegrafana.catalystsquad.com".to_string())
        );
    }

    #[test]
    fn callback_host_rejects_http_userinfo_and_garbage() {
        assert_eq!(
            callback_host("http://todandlorna.com/cb"),
            Err(CallbackUrlError::NotHttps)
        );
        assert_eq!(
            callback_host("https://todandlorna.com@attacker.com/cb"),
            Err(CallbackUrlError::Unparseable)
        );
        assert_eq!(
            callback_host("https://"),
            Err(CallbackUrlError::Unparseable)
        );
    }

    #[test]
    fn host_in_domain_requires_dot_boundary() {
        assert!(host_in_domain("todandlorna.com", "todandlorna.com"));
        assert!(host_in_domain(
            "longhouse.todandlorna.com",
            "todandlorna.com"
        ));
        assert!(host_in_domain(
            "LongHouse.TodAndLorna.com",
            "todandlorna.com"
        ));
        assert!(!host_in_domain("evil-todandlorna.com", "todandlorna.com"));
        assert!(!host_in_domain("attacker.com", "todandlorna.com"));
    }
}
