//! Test fakes for the network seam (`linkkeys::net`). These let the full
//! request handlers run end-to-end with no network socket: DNS answers from a
//! fixed map, HTTP answers from a fixed url->body map.

#![allow(dead_code)]

use linkkeys::net::{DnsResolver, DomainFetcher, HttpResponse, Net, NetError};
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

/// A `Net` whose DNS and HTTP both error on use: the safe default for tests that
/// stay on the self-RP (local-DB) path and must never touch the network. If such
/// a test accidentally goes off-domain, it fails loudly instead of doing I/O.
pub fn offline_net() -> Net {
    Net {
        dns: Arc::new(StaticDns::new()),
        http: Arc::new(CannedHttp::new()),
    }
}

/// A `Net` backed by the given static DNS + canned HTTP, for cross-domain tests.
pub fn net_with(dns: StaticDns, http: CannedHttp) -> Net {
    Net {
        dns: Arc::new(dns),
        http: Arc::new(http),
    }
}
