//! Network seam. Production code reaches DNS and other domains' HTTPS endpoints
//! ONLY through a [`Net`], whose two trait objects (`DnsResolver`,
//! `DomainFetcher`) are real (hickory / reqwest) in production and in-process
//! fakes in tests. This is the architectural bypass that lets the full request
//! handlers run end-to-end in tests without touching a network socket.

use std::fmt;
use std::sync::Arc;

/// An opaque network error. `Send + Sync` so it can cross `.await` points and
/// live in trait objects.
#[derive(Debug)]
pub struct NetError(pub String);

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for NetError {}

/// A minimal HTTP response: whether the status was 2xx, and the raw body.
pub struct HttpResponse {
    pub success: bool,
    pub body: Vec<u8>,
}

#[rocket::async_trait]
pub trait DnsResolver: Send + Sync + std::fmt::Debug {
    /// Every TXT string published at `name`.
    async fn txt_lookup(&self, name: &str) -> Result<Vec<String>, NetError>;
}

#[rocket::async_trait]
pub trait DomainFetcher: Send + Sync + std::fmt::Debug {
    async fn get(&self, url: &str) -> Result<HttpResponse, NetError>;
    async fn post_cbor(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, NetError>;
}

/// The network capabilities a request handler may use. Cloning is cheap (Arc).
#[derive(Clone)]
pub struct Net {
    pub dns: Arc<dyn DnsResolver>,
    pub http: Arc<dyn DomainFetcher>,
}

impl Net {
    /// The real network: hickory for DNS, reqwest for HTTPS.
    pub fn production() -> Self {
        Net {
            dns: Arc::new(HickoryDnsResolver),
            http: Arc::new(ReqwestFetcher),
        }
    }
}

#[derive(Debug)]
struct HickoryDnsResolver;

#[rocket::async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn txt_lookup(&self, name: &str) -> Result<Vec<String>, NetError> {
        use hickory_resolver::TokioAsyncResolver;
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| NetError(format!("DNS resolver init failed: {}", e)))?;
        let response = resolver
            .txt_lookup(name)
            .await
            .map_err(|e| NetError(format!("no TXT record at {}: {}", name, e)))?;
        Ok(response.iter().map(|r| r.to_string()).collect())
    }
}

#[derive(Debug)]
struct ReqwestFetcher;

impl ReqwestFetcher {
    fn client() -> Result<reqwest::Client, NetError> {
        let accept_invalid = std::env::var("ALLOW_INVALID_CERTS").unwrap_or_default() == "true";
        reqwest::Client::builder()
            .danger_accept_invalid_certs(accept_invalid)
            .build()
            .map_err(|e| NetError(format!("HTTP client build failed: {}", e)))
    }
}

#[rocket::async_trait]
impl DomainFetcher for ReqwestFetcher {
    async fn get(&self, url: &str) -> Result<HttpResponse, NetError> {
        let resp = Self::client()?
            .get(url)
            .send()
            .await
            .map_err(|e| NetError(format!("GET {} failed: {}", url, e)))?;
        let success = resp.status().is_success();
        let body = resp
            .bytes()
            .await
            .map_err(|e| NetError(format!("reading {} body failed: {}", url, e)))?
            .to_vec();
        Ok(HttpResponse { success, body })
    }

    async fn post_cbor(&self, url: &str, body: Vec<u8>) -> Result<HttpResponse, NetError> {
        let resp = Self::client()?
            .post(url)
            .header("Content-Type", "application/cbor")
            .body(body)
            .send()
            .await
            .map_err(|e| NetError(format!("POST {} failed: {}", url, e)))?;
        let success = resp.status().is_success();
        let body = resp
            .bytes()
            .await
            .map_err(|e| NetError(format!("reading {} body failed: {}", url, e)))?
            .to_vec();
        Ok(HttpResponse { success, body })
    }
}
