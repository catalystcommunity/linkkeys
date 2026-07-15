//! CSIL-RPC over the injected [`Transport`], TLS-pinned to a domain's DNS
//! `fp=` records — the SDK's only network surface, per the design doc's
//! "Required Network Access": domain public keys, revocations, and
//! claim-ticket redemption, all unauthenticated-TLS TCP CSIL-RPC calls
//! pinned the same way `crates/linkkeys/src/tcp/tls.rs` pins the S2S path.
//!
//! This module deliberately reimplements the small (~30 line) length-prefixed
//! frame send/receive that `linkkeys-rpc-client` also has privately, rather
//! than calling that crate's `send_request`: that function's `connect_guarded`
//! bakes in the non-public-address SSRF refusal this SDK must not default to
//! (see `src/transport.rs`'s module docs). `linkkeys-rpc-client::tls` (the
//! `ClientConfig` builder + `FingerprintVerifier`) IS reused, because that
//! part has nothing to do with address policy and is fiddly to get right.

use crate::dns::DnsResolver;
use crate::transport::Transport;
use crate::Error;
use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use liblinkkeys::dns::{
    linkkeys_apis_dns_name, linkkeys_dns_name, parse_linkkeys_apis_txt, parse_linkkeys_txt,
};
use liblinkkeys::generated::types::{
    DomainPublicKey, EmptyRequest, GetDomainKeysResponse, GetRevocationsRequest,
    GetRevocationsResponse, LocalRpTicketRedemptionResponse, SignedLocalRpTicketRedemptionRequest,
};
use std::io::{Read, Write};
use std::sync::Arc;

/// Mirrors the server's own cap (`crates/linkkeys-rpc-client/src/lib.rs`) so a
/// malicious/compromised peer cannot drive this client to an unbounded
/// allocation via a forged length prefix.
const MAX_FRAME_SIZE: usize = 1024 * 1024;

fn send_frame(stream: &mut impl Write, data: &[u8]) -> Result<(), Error> {
    let len = (data.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|e| Error::Transport(e.to_string()))?;
    stream
        .write_all(data)
        .map_err(|e| Error::Transport(e.to_string()))?;
    stream.flush().map_err(|e| Error::Transport(e.to_string()))
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, Error> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| Error::Transport(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(Error::Protocol(format!(
            "peer frame too large ({len} bytes, max {MAX_FRAME_SIZE})"
        )));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| Error::Transport(e.to_string()))?;
    Ok(buf)
}

/// Discovered endpoint for a domain: its pinned trust-anchor fingerprints
/// (`_linkkeys`) and its CSIL-RPC TCP address (`_linkkeys_apis` `tcp=`).
pub struct DomainEndpoint {
    pub fingerprints: Vec<String>,
    pub tcp_addr: String,
}

/// Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails closed:
/// a missing/unparseable record, or a `_linkkeys` record with no `fp=`
/// entries, or a `_linkkeys_apis` record with no `tcp=` entry, is an error —
/// this SDK never proceeds without a fingerprint set to pin to.
pub fn discover_domain_endpoint(
    dns: &dyn DnsResolver,
    domain: &str,
) -> Result<DomainEndpoint, Error> {
    let anchor_name = linkkeys_dns_name(domain);
    let anchor_txts = dns.txt_lookup(&anchor_name)?;
    let fingerprints = anchor_txts
        .iter()
        .find_map(|txt| parse_linkkeys_txt(txt).ok())
        .map(|r| r.fingerprints)
        .filter(|fps| !fps.is_empty())
        .ok_or_else(|| {
            Error::Dns(format!(
                "no usable {anchor_name} TXT record with fp= entries"
            ))
        })?;

    let apis_name = linkkeys_apis_dns_name(domain);
    let apis_txts = dns.txt_lookup(&apis_name)?;
    let tcp_addr = apis_txts
        .iter()
        .find_map(|txt| parse_linkkeys_apis_txt(txt).ok())
        .and_then(|apis| apis.tcp)
        .ok_or_else(|| Error::Dns(format!("no usable {apis_name} TXT record with tcp= entry")))?;

    Ok(DomainEndpoint {
        fingerprints,
        tcp_addr,
    })
}

/// `Box<dyn ReadWrite>` does not itself implement `Read`/`Write` (trait
/// objects don't inherit their supertraits' impls automatically); this thin
/// newtype forwards both so `rustls::StreamOwned` can wrap it.
struct BoxedStream(Box<dyn crate::transport::ReadWrite>);

impl Read for BoxedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for BoxedStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// Open a TLS connection to `endpoint`, pinned to its fingerprints, using the
/// injected [`Transport`] to dial the raw TCP socket.
fn dial_tls(
    transport: &dyn Transport,
    endpoint: &DomainEndpoint,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, BoxedStream>, Error> {
    let raw = BoxedStream(transport.dial(&endpoint.tcp_addr)?);
    let hostname = linkkeys_rpc_client::extract_hostname(&endpoint.tcp_addr).to_string();
    let tls_config: Arc<rustls::ClientConfig> =
        linkkeys_rpc_client::tls::client_config(endpoint.fingerprints.clone(), None)
            .map_err(|e| Error::Tls(e.to_string()))?;
    let server_name = rustls::pki_types::ServerName::try_from(hostname)
        .map_err(|e| Error::Tls(format!("invalid server name: {e}")))?;
    let conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|e| Error::Tls(format!("TLS setup failed: {e}")))?;
    Ok(rustls::StreamOwned::new(conn, raw))
}

/// Send one CSIL-RPC request over a fresh TLS connection to `endpoint` and
/// return the decoded success payload. A non-Ok status becomes
/// [`Error::ServerError`].
fn call(
    transport: &dyn Transport,
    endpoint: &DomainEndpoint,
    service: &str,
    op: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let mut stream = dial_tls(transport, endpoint)?;

    let request = RpcRequest::new(service, op, payload);
    let encoded = request
        .encode()
        .map_err(|e| Error::Protocol(format!("encode request: {e:?}")))?;
    send_frame(&mut stream, &encoded)?;
    let resp_bytes = read_frame(&mut stream)?;
    let resp = RpcResponse::decode(&resp_bytes)
        .map_err(|e| Error::Protocol(format!("decode response: {e:?}")))?;

    if !resp.status.is_ok() {
        return Err(Error::ServerError {
            status: resp.status.code() as i32,
            message: resp.error.unwrap_or_else(|| "unknown error".to_string()),
        });
    }
    Ok(resp.payload)
}

/// Fetch `domain`'s currently-trusted public keys: `DomainKeys/get-domain-keys`
/// over TCP CSIL-RPC, pinned to the domain's DNS `fp=` set, with signing keys
/// pinned directly and encryption keys trusted only via a pinned signing
/// key's vouch (`liblinkkeys::dns::trust_keys`). Always also fetches
/// `DomainKeys/get-revocations` for the same domain — regardless of what the
/// `get-domain-keys` response's `recent_revocations_available` flag says —
/// and drops any key a quorum-verified sibling revocation certificate
/// targets. `recent_revocations_available` is an optional performance hint a
/// well-behaved IDP may use to signal "you don't even need to ask"; a
/// compromised/malicious or merely buggy IDP could otherwise use its absence
/// to suppress this SDK from ever learning about a revocation, which is
/// exactly the scenario revocation exists to guard against — so this SDK
/// never uses it to skip the check. A `get-revocations` RPC error
/// (connection failure or response decode failure) is FATAL: this SDK must
/// fail closed rather than silently proceed with a possibly-stale key set an
/// attacker could have engineered by making the endpoint fail. An empty
/// revocation list is normal success (nothing to apply). An empty trusted
/// result (after applying revocations) is [`Error::NoTrustedDomainKeys`] —
/// fail closed, matching the server's own `fetch_domain_keys` (`web/rp.rs`).
pub fn fetch_domain_keys(
    transport: &dyn Transport,
    dns: &dyn DnsResolver,
    domain: &str,
) -> Result<Vec<DomainPublicKey>, Error> {
    let endpoint = discover_domain_endpoint(dns, domain)?;

    let payload = liblinkkeys::generated::encode_empty_request(&EmptyRequest {});
    let resp_bytes = call(
        transport,
        &endpoint,
        "DomainKeys",
        "get-domain-keys",
        payload,
    )?;
    let resp: GetDomainKeysResponse =
        liblinkkeys::generated::decode_get_domain_keys_response(&resp_bytes)
            .map_err(|e| Error::Decode(format!("get-domain-keys response: {e}")))?;

    let mut trusted = liblinkkeys::dns::trust_keys(resp.keys, &endpoint.fingerprints);
    if trusted.is_empty() {
        return Err(Error::NoTrustedDomainKeys(domain.to_string()));
    }

    // Always fetch revocations — never gated on `recent_revocations_available`
    // (see this function's doc comment). A failure here is propagated with
    // `?`, i.e. FATAL: it must never be swallowed to "just proceed unfiltered".
    let since = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
    let req_payload =
        liblinkkeys::generated::encode_get_revocations_request(&GetRevocationsRequest {
            since: Some(since),
        });
    let resp_bytes = call(
        transport,
        &endpoint,
        "DomainKeys",
        "get-revocations",
        req_payload,
    )?;
    let revocations: Vec<_> = liblinkkeys::generated::decode_get_revocations_response(&resp_bytes)
        .map(|r: GetRevocationsResponse| r.revocations)
        .map_err(|e| Error::Decode(format!("get-revocations response: {e}")))?;
    for cert in &revocations {
        if liblinkkeys::revocation::verify_revocation_certificate(cert, &trusted, domain).is_ok() {
            trusted.retain(|k| k.key_id != cert.target_key_id);
        }
    }

    if trusted.is_empty() {
        return Err(Error::NoTrustedDomainKeys(domain.to_string()));
    }
    Ok(trusted)
}

/// Redeem a claim ticket with `domain`'s IDP: `LocalRp/redeem-claim-ticket`
/// over TCP CSIL-RPC, pinned via the domain's DNS `fp=` set. Unauthenticated
/// at the transport layer (no client cert) — the redemption request itself
/// is signed with the local RP's signing key, which is the possession proof
/// the server checks (`crates/linkkeys/src/tcp/mod.rs`,
/// `dispatch_local_rp_redeem_claim_ticket`).
pub fn redeem_claim_ticket(
    transport: &dyn Transport,
    dns: &dyn DnsResolver,
    domain: &str,
    signed_request: &SignedLocalRpTicketRedemptionRequest,
) -> Result<LocalRpTicketRedemptionResponse, Error> {
    let endpoint = discover_domain_endpoint(dns, domain)?;
    let payload =
        liblinkkeys::generated::encode_signed_local_rp_ticket_redemption_request(signed_request);
    let resp_bytes = call(
        transport,
        &endpoint,
        "LocalRp",
        "redeem-claim-ticket",
        payload,
    )?;
    liblinkkeys::generated::decode_local_rp_ticket_redemption_response(&resp_bytes)
        .map_err(|e| Error::Decode(format!("redeem-claim-ticket response: {e}")))
}
