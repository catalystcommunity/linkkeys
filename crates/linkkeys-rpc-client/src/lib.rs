//! LinkKeys CSIL-RPC client transport.
//!
//! A blocking, length-prefixed CBOR-over-TLS client for the LinkKeys protocol.
//! It frames a request envelope (`service`/`op`/`payload`/optional `auth`),
//! performs the TLS round-trip with fingerprint-pinned verification, and decodes
//! the response envelope. It owns no DNS resolution and no key storage: callers
//! resolve the peer's fingerprints (DNS or a pin) and optionally load their own
//! domain cert, then call [`send_request`] (or [`send_request_with_config`] with
//! a prebuilt config). This keeps the crate usable by the server's outbound
//! paths, the CLI, and the demo site without dragging in diesel or the net seam.

pub mod tls;

use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// Bound on the TCP connect so a slow/blackholed peer target can't tie up a
/// worker thread indefinitely (SEC-07).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// True if `ip` is an address the server must not be induced to dial when the
/// target comes from an untrusted source (a peer's DNS `tcp=` record). Blocks
/// loopback, private, link-local (incl. the 169.254.169.254 cloud-metadata
/// address), CGNAT, unspecified, and IPv6 ULA/link-local — the SSRF surface in
/// SEC-07. Operators running local/dev peers can opt out with
/// `LINKKEYS_ALLOW_PRIVATE_PEERS=true`.
fn is_disallowed_target(ip: IpAddr) -> bool {
    fn v4_disallowed(v4: std::net::Ipv4Addr) -> bool {
        let o = v4.octets();
        v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || v4.is_unspecified()
            || v4.is_broadcast()
            || v4.is_documentation()
            // CGNAT 100.64.0.0/10
            || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
    }
    match ip {
        IpAddr::V4(v4) => v4_disallowed(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || v6.to_ipv4_mapped().map(v4_disallowed).unwrap_or(false)
        }
    }
}

/// Resolve `server` (`host:port`) and connect to a vetted address with a
/// timeout. Resolving and connecting to the *same* `SocketAddr` (rather than
/// re-resolving the hostname) closes the DNS-rebinding window: we never connect
/// to an address we didn't just screen.
fn connect_guarded(server: &str) -> Result<TcpStream, ClientError> {
    let allow_private = std::env::var("LINKKEYS_ALLOW_PRIVATE_PEERS").unwrap_or_default() == "true";
    let addrs = server
        .to_socket_addrs()
        .map_err(|e| ClientError::Connection(format!("{}: resolve failed: {}", server, e)))?;
    let mut last_err: Option<ClientError> = None;
    for addr in addrs {
        if !allow_private && is_disallowed_target(addr.ip()) {
            last_err = Some(ClientError::Connection(format!(
                "{}: refusing to connect to non-public address {}",
                server,
                addr.ip()
            )));
            continue;
        }
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(ClientError::Connection(format!("{}: {}", server, e))),
        }
    }
    Err(last_err
        .unwrap_or_else(|| ClientError::Connection(format!("{}: no address resolved", server))))
}

#[derive(Debug)]
pub enum ClientError {
    Connection(String),
    Protocol(String),
    Tls(String),
    ServerError { status: i32, message: String },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Connection(msg) => write!(f, "connection error: {}", msg),
            ClientError::Protocol(msg) => write!(f, "protocol error: {}", msg),
            ClientError::Tls(msg) => write!(f, "TLS error: {}", msg),
            ClientError::ServerError { status, message } => {
                write!(f, "server error ({}): {}", status, message)
            }
        }
    }
}

impl std::error::Error for ClientError {}

/// Extract the hostname from a "host:port" server address string.
pub fn extract_hostname(server: &str) -> &str {
    // Handle [IPv6]:port format
    if server.starts_with('[') {
        if let Some(end) = server.find(']') {
            return &server[1..end];
        }
    }
    // Handle host:port
    match server.rfind(':') {
        Some(pos) => &server[..pos],
        None => server,
    }
}

/// Send a frame: 4-byte big-endian length prefix + payload.
fn send_frame(stream: &mut impl Write, data: &[u8]) -> Result<(), ClientError> {
    let len = (data.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    stream
        .write_all(data)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| ClientError::Connection(e.to_string()))
}

/// Maximum frame size the client will allocate for a server response. Mirrors
/// the server's cap so a malicious/compromised peer cannot drive the client to
/// an unbounded (multi-GiB) allocation via a forged length prefix (tcp-01).
const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Read a frame: 4-byte big-endian length prefix + payload.
fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, ClientError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > MAX_FRAME_SIZE {
        return Err(ClientError::Connection(format!(
            "server frame too large ({} bytes, max {})",
            resp_len, MAX_FRAME_SIZE
        )));
    }
    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    Ok(resp_buf)
}

/// Send a request envelope and receive the response over an established stream.
/// Uses the canonical CSIL-RPC envelope codec (tag-24 payload framing) so the
/// wire format matches the server exactly.
fn send_and_receive(
    stream: &mut (impl Read + Write),
    request: &RpcRequest,
) -> Result<RpcResponse, ClientError> {
    let envelope_bytes = request
        .encode()
        .map_err(|e| ClientError::Protocol(format!("encode RPC envelope: {}", e)))?;
    send_frame(stream, &envelope_bytes)?;

    let resp_buf = read_frame(stream)?;

    RpcResponse::decode(&resp_buf)
        .map_err(|e| ClientError::Protocol(format!("decode RPC response: {}", e)))
}

/// Send a pre-encoded CBOR `payload` to a LinkKeys server over a caller-provided
/// TLS config, returning the raw success-response payload bytes.
///
/// `hostname` is the SNI name presented in the handshake (and routed on by an
/// SNI-aware gateway / TLSRoute). The config's verifier pins the server's cert
/// to its DNS-published fingerprints; if the config carries a client cert the
/// server can verify us back (mutual TLS). A non-zero server status is returned
/// as [`ClientError::ServerError`].
pub fn send_raw_with_config(
    server: &str,
    tls_config: Arc<rustls::ClientConfig>,
    hostname: &str,
    service: &str,
    op: &str,
    payload: Vec<u8>,
    api_key: Option<&str>,
) -> Result<Vec<u8>, ClientError> {
    let mut request = RpcRequest::new(service, op, payload);
    if let Some(key) = api_key {
        request = request.with_auth(key);
    }

    let stream = connect_guarded(server)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| ClientError::Connection(e.to_string()))?;

    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|e| ClientError::Tls(format!("invalid server name: {}", e)))?;
    let tls_conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|e| ClientError::Tls(format!("TLS connection setup: {}", e)))?;
    let mut tls_stream = rustls::StreamOwned::new(tls_conn, stream);

    let resp = send_and_receive(&mut tls_stream, &request)?;

    if !resp.status.is_ok() {
        return Err(ClientError::ServerError {
            status: resp.status.code() as i32,
            message: resp.error.unwrap_or_else(|| "Unknown error".to_string()),
        });
    }

    Ok(resp.payload)
}

/// Send a pre-encoded CBOR `payload` to a LinkKeys server, pinning its
/// certificate to `fingerprints`, and return the raw success-response payload
/// bytes. When `client_cert` is `Some((cert_der, key_der))` the client presents
/// it for mutual TLS so the server can verify us back; otherwise it connects
/// without a client cert and relies on `api_key` for app-layer auth. SNI is
/// derived from `server` (the host portion of `host:port`). The caller encodes
/// the request and decodes the response with the CSIL codec.
#[allow(clippy::too_many_arguments)]
pub fn send_request(
    server: &str,
    fingerprints: Vec<String>,
    client_cert: Option<(Vec<u8>, Vec<u8>)>,
    service: &str,
    op: &str,
    payload: Vec<u8>,
    api_key: Option<&str>,
) -> Result<Vec<u8>, ClientError> {
    let hostname = extract_hostname(server).to_string();
    let tls_config = tls::client_config(fingerprints, client_cert)
        .map_err(|e| ClientError::Tls(format!("TLS config: {}", e)))?;
    send_raw_with_config(server, tls_config, &hostname, service, op, payload, api_key)
}

#[cfg(test)]
mod ssrf_tests {
    use super::is_disallowed_target;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_internal_and_metadata_targets() {
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.5",
            "172.16.9.9",
            "169.254.169.254", // cloud metadata
            "100.100.0.1",     // CGNAT
            "0.0.0.0",
            "::1",
            "fe80::1",          // link-local
            "fc00::1",          // ULA
            "fd12::34",         // ULA
            "::ffff:127.0.0.1", // v4-mapped loopback
            "::ffff:10.0.0.1",  // v4-mapped private
        ] {
            assert!(is_disallowed_target(ip(s)), "{s} should be disallowed");
        }
    }

    #[test]
    fn allows_public_targets() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(!is_disallowed_target(ip(s)), "{s} should be allowed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_hostname_with_port() {
        assert_eq!(extract_hostname("example.com:4987"), "example.com");
        assert_eq!(extract_hostname("localhost:4987"), "localhost");
        assert_eq!(
            extract_hostname("auth.example.com:8443"),
            "auth.example.com"
        );
    }

    #[test]
    fn test_extract_hostname_without_port() {
        assert_eq!(extract_hostname("example.com"), "example.com");
        assert_eq!(extract_hostname("localhost"), "localhost");
    }

    #[test]
    fn test_extract_hostname_ipv6() {
        assert_eq!(extract_hostname("[::1]:4987"), "::1");
        assert_eq!(extract_hostname("[2001:db8::1]:4987"), "2001:db8::1");
    }
}
