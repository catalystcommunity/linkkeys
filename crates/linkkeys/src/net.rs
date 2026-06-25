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

/// Server-to-server CSIL-RPC over the LinkKeys TCP protocol. This is the
/// first-class transport for peer (IDP↔IDP / RP↔IDP) calls; HTTPS via
/// [`DomainFetcher`] is the browser-adjacent path. Real in production (the
/// blocking `linkkeys-rpc-client`, driven on a blocking thread), an in-process
/// dispatch fake in tests.
#[rocket::async_trait]
pub trait DomainRpc: Send + Sync + std::fmt::Debug {
    /// CSIL-RPC call to `addr` (`host:port`). `hostname` is the SNI / cert name
    /// pinned against `fingerprints`; `client_cert` (DER cert, DER key) is
    /// presented for mutual TLS when `Some`. `payload` is the CBOR-encoded
    /// request body, `auth` an optional API key. Returns the success-response
    /// payload bytes; any transport error or non-zero server status is a
    /// [`NetError`].
    #[allow(clippy::too_many_arguments)]
    async fn call(
        &self,
        addr: &str,
        hostname: &str,
        fingerprints: Vec<String>,
        client_cert: Option<(Vec<u8>, Vec<u8>)>,
        service: &str,
        op: &str,
        payload: Vec<u8>,
        auth: Option<String>,
    ) -> Result<Vec<u8>, NetError>;
}

/// The network capabilities a request handler may use. Cloning is cheap (Arc).
#[derive(Clone)]
pub struct Net {
    pub dns: Arc<dyn DnsResolver>,
    pub http: Arc<dyn DomainFetcher>,
    pub rpc: Arc<dyn DomainRpc>,
}

impl Net {
    /// The real network: hickory for DNS, reqwest for HTTPS, the blocking
    /// CSIL-RPC client for server-to-server TCP.
    pub fn production() -> Self {
        Net {
            dns: Arc::new(HickoryDnsResolver),
            http: Arc::new(ReqwestFetcher),
            rpc: Arc::new(TcpRpcClient),
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

/// Production [`DomainRpc`]: the blocking `linkkeys-rpc-client` transport, run on
/// a blocking thread so it doesn't stall the async runtime. Fingerprint
/// resolution and own-cert loading happen in the caller (which holds the DNS
/// seam and the DB); this just performs the TLS round-trip.
#[derive(Debug)]
struct TcpRpcClient;

#[rocket::async_trait]
impl DomainRpc for TcpRpcClient {
    async fn call(
        &self,
        addr: &str,
        hostname: &str,
        fingerprints: Vec<String>,
        client_cert: Option<(Vec<u8>, Vec<u8>)>,
        service: &str,
        op: &str,
        payload: Vec<u8>,
        auth: Option<String>,
    ) -> Result<Vec<u8>, NetError> {
        let addr = addr.to_string();
        let hostname = hostname.to_string();
        let service = service.to_string();
        let op = op.to_string();
        tokio::task::spawn_blocking(move || {
            let config = linkkeys_rpc_client::tls::client_config(fingerprints, client_cert)
                .map_err(|e| NetError(format!("TLS config: {}", e)))?;
            linkkeys_rpc_client::send_raw_with_config(
                &addr,
                config,
                &hostname,
                &service,
                &op,
                payload,
                auth.as_deref(),
            )
            .map_err(|e| NetError(e.to_string()))
        })
        .await
        .map_err(|e| NetError(format!("rpc task join failed: {}", e)))?
    }
}
