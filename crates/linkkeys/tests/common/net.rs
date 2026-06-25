//! Test fakes for the network seam (`linkkeys::net`). These let the full
//! request handlers run end-to-end with no network socket: DNS answers from a
//! fixed map, HTTP answers from a fixed url->body map.

#![allow(dead_code)]

use linkkeys::net::{DnsResolver, DomainFetcher, DomainRpc, HttpResponse, Net, NetError};
use std::collections::HashMap;
use std::sync::Arc;

/// DNS that answers only from a fixed map of `name -> TXT strings`. Any other
/// name errors (so an unexpected lookup fails loudly rather than hitting the
/// real resolver).
#[derive(Debug, Default)]
pub struct StaticDns {
    records: HashMap<String, Vec<String>>,
}

impl StaticDns {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, name: &str, txts: &[&str]) -> Self {
        self.records.insert(
            name.to_string(),
            txts.iter().map(|s| s.to_string()).collect(),
        );
        self
    }
}

#[rocket::async_trait]
impl DnsResolver for StaticDns {
    async fn txt_lookup(&self, name: &str) -> Result<Vec<String>, NetError> {
        self.records
            .get(name)
            .cloned()
            .ok_or_else(|| NetError(format!("no TXT record at {}", name)))
    }
}

/// HTTP that answers only from a fixed map of `url -> body bytes` (200 for known
/// URLs, error otherwise). Enough to serve another domain's `domain-keys.json`
/// or a userinfo response in a cross-domain test, with no socket.
#[derive(Debug, Default)]
pub struct CannedHttp {
    responses: HashMap<String, Vec<u8>>,
}

impl CannedHttp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, url: &str, body: Vec<u8>) -> Self {
        self.responses.insert(url.to_string(), body);
        self
    }
}

#[rocket::async_trait]
impl DomainFetcher for CannedHttp {
    async fn get(&self, url: &str) -> Result<HttpResponse, NetError> {
        match self.responses.get(url) {
            Some(body) => Ok(HttpResponse {
                success: true,
                body: body.clone(),
            }),
            None => Err(NetError(format!("no canned response for GET {}", url))),
        }
    }

    async fn post_cbor(&self, url: &str, _body: Vec<u8>) -> Result<HttpResponse, NetError> {
        match self.responses.get(url) {
            Some(body) => Ok(HttpResponse {
                success: true,
                body: body.clone(),
            }),
            None => Err(NetError(format!("no canned response for POST {}", url))),
        }
    }
}

/// CSIL-RPC fake: answers only from a fixed map keyed by
/// `"{hostname}|{service}|{op}"` -> success-response payload bytes. Any other
/// call errors (so an unexpected server-to-server call fails loudly rather than
/// touching a socket). The mirror of [`CannedHttp`] for the TCP seam.
#[derive(Debug, Default)]
pub struct CannedRpc {
    responses: HashMap<String, Vec<u8>>,
}

impl CannedRpc {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, hostname: &str, service: &str, op: &str, payload: Vec<u8>) -> Self {
        self.responses
            .insert(format!("{}|{}|{}", hostname, service, op), payload);
        self
    }
}

#[rocket::async_trait]
impl DomainRpc for CannedRpc {
    async fn call(
        &self,
        _addr: &str,
        hostname: &str,
        _fingerprints: Vec<String>,
        _client_cert: Option<(Vec<u8>, Vec<u8>)>,
        service: &str,
        op: &str,
        _payload: Vec<u8>,
        _auth: Option<String>,
    ) -> Result<Vec<u8>, NetError> {
        let key = format!("{}|{}|{}", hostname, service, op);
        self.responses
            .get(&key)
            .cloned()
            .ok_or_else(|| NetError(format!("no canned RPC response for {}", key)))
    }
}

/// A `Net` whose DNS, HTTP, and RPC all error on use: the safe default for tests
/// that stay on the self-RP (local-DB) path and must never touch the network. If
/// such a test accidentally goes off-domain, it fails loudly instead of doing I/O.
pub fn offline_net() -> Net {
    Net {
        dns: Arc::new(StaticDns::new()),
        http: Arc::new(CannedHttp::new()),
        rpc: Arc::new(CannedRpc::new()),
    }
}

/// A `Net` backed by the given static DNS + canned HTTP (RPC errors on use), for
/// cross-domain tests still exercising the HTTP path.
pub fn net_with(dns: StaticDns, http: CannedHttp) -> Net {
    Net {
        dns: Arc::new(dns),
        http: Arc::new(http),
        rpc: Arc::new(CannedRpc::new()),
    }
}

/// A `Net` backed by static DNS + canned RPC (HTTP errors on use), for
/// cross-domain tests exercising the server-to-server TCP path.
pub fn net_with_rpc(dns: StaticDns, rpc: CannedRpc) -> Net {
    Net {
        dns: Arc::new(dns),
        http: Arc::new(CannedHttp::new()),
        rpc: Arc::new(rpc),
    }
}
