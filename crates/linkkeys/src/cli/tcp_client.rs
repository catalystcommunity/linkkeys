use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

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

#[derive(Serialize)]
struct RequestEnvelope {
    v: u32,
    service: String,
    op: String,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<String>,
}

#[derive(Deserialize)]
struct ResponseEnvelope {
    #[allow(dead_code)]
    v: u32,
    status: i32,
    error: Option<String>,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
}

mod serde_bytes {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        use serde::de::Visitor;

        struct BytesVisitor;
        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bytes or byte string")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Vec<u8>, A::Error> {
                let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(b) = seq.next_element()? {
                    bytes.push(b);
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_any(BytesVisitor)
    }
}

/// Extract the hostname from a "host:port" server address string.
fn extract_hostname(server: &str) -> &str {
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

/// Resolve the TLS client config for connecting to the given server.
/// Verifies the server's cert against its DNS-published fingerprints (or pinned).
/// If this process is also a domain server (has access to its own domain key),
/// it presents its own cert for mutual TLS — the server can verify us back.
/// Returns the config and the hostname for SNI.
fn resolve_tls_config(
    server: &str,
) -> Result<(Arc<rustls::ClientConfig>, String), ClientError> {
    let hostname = extract_hostname(server).to_string();

    // Check for pinned fingerprints (testing/bootstrap escape hatch)
    let fingerprints = match std::env::var("LINKKEYS_FINGERPRINTS") {
        Ok(pinned) => {
            let fps: Vec<String> = pinned.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            if fps.is_empty() {
                return Err(ClientError::Tls(
                    "LINKKEYS_FINGERPRINTS is set but empty".to_string(),
                ));
            }
            fps
        }
        Err(_) => {
            // Resolve from DNS — fail closed
            crate::dns::resolve_fingerprints(&hostname)
                .map_err(|e| ClientError::Tls(format!("DNS fingerprint resolution for {}: {}", hostname, e)))?
        }
    };

    // If we have access to our own domain key, present it for mutual TLS.
    // This is the case when we're a domain server connecting to another domain server.
    // If we don't have our own key (e.g., a lightweight client), the server
    // can still accept us — client auth is optional, app-layer auth via API key suffices.
    let config = match load_own_domain_cert() {
        Ok((cert_der, key_der)) => {
            crate::tcp::tls::build_client_config_with_cert(fingerprints, cert_der, key_der)
                .map_err(|e| ClientError::Tls(format!("TLS config: {}", e)))?
        }
        Err(_) => {
            crate::tcp::tls::build_client_config(fingerprints)
                .map_err(|e| ClientError::Tls(format!("TLS config: {}", e)))?
        }
    };

    Ok((config, hostname))
}

/// Load this domain's own certificate and private key for client cert presentation.
/// Only succeeds if we're running on a domain server with DATABASE_URL and
/// DOMAIN_KEY_PASSPHRASE available. These are our own keys — we never need
/// or access another domain's private keys.
fn load_own_domain_cert() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let passphrase = std::env::var("DOMAIN_KEY_PASSPHRASE")
        .map_err(|_| "DOMAIN_KEY_PASSPHRASE not set")?;

    let db_pool = linkkeys::db::create_pool();
    let domain_keys = db_pool
        .list_active_domain_keys()
        .map_err(|e| format!("Failed to list domain keys: {}", e))?;

    let dk = domain_keys
        .first()
        .ok_or("No active domain keys")?;

    let sk_bytes = liblinkkeys::crypto::decrypt_private_key(
        &dk.private_key_encrypted,
        passphrase.as_bytes(),
    )
    .map_err(|e| format!("Failed to decrypt domain key: {}", e))?;

    let seed: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| "Domain key is not 32 bytes")?;

    let domain_name = linkkeys::conversions::get_domain_name();
    crate::tcp::tls::generate_domain_tls_cert(&domain_name, &seed)
        .map_err(|e| e.into())
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

/// Read a frame: 4-byte big-endian length prefix + payload.
fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, ClientError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    Ok(resp_buf)
}

/// Send a request envelope and receive the response over an established stream.
fn send_and_receive(
    stream: &mut (impl Read + Write),
    envelope: &RequestEnvelope,
) -> Result<ResponseEnvelope, ClientError> {
    // Send frame
    let mut envelope_bytes = Vec::new();
    ciborium::ser::into_writer(envelope, &mut envelope_bytes)
        .map_err(|e| ClientError::Protocol(format!("CBOR encode envelope: {}", e)))?;
    send_frame(stream, &envelope_bytes)?;

    // Read response frame
    let resp_buf = read_frame(stream)?;

    ciborium::de::from_reader(resp_buf.as_slice())
        .map_err(|e| ClientError::Protocol(format!("CBOR decode response: {}", e)))
}

/// Send a request to a LinkKeys server and return the response payload.
/// All connections use TLS with fingerprint-based verification.
/// The server's certificate is verified against DNS-published fingerprints.
pub fn send_request<Req: Serialize, Resp: serde::de::DeserializeOwned>(
    server: &str,
    service: &str,
    op: &str,
    request: &Req,
    api_key: Option<&str>,
) -> Result<Resp, ClientError> {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(request, &mut payload)
        .map_err(|e| ClientError::Protocol(format!("CBOR encode: {}", e)))?;

    let envelope = RequestEnvelope {
        v: 1,
        service: service.to_string(),
        op: op.to_string(),
        payload,
        auth: api_key.map(|k| k.to_string()),
    };

    let (tls_config, hostname) = resolve_tls_config(server)?;

    let stream = TcpStream::connect(server)
        .map_err(|e| ClientError::Connection(format!("{}: {}", server, e)))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| ClientError::Connection(e.to_string()))?;

    let server_name = rustls::pki_types::ServerName::try_from(hostname)
        .map_err(|e| ClientError::Tls(format!("invalid server name: {}", e)))?;
    let tls_conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|e| ClientError::Tls(format!("TLS connection setup: {}", e)))?;
    let mut tls_stream = rustls::StreamOwned::new(tls_conn, stream);

    let resp_envelope = send_and_receive(&mut tls_stream, &envelope)?;

    if resp_envelope.status != 0 {
        return Err(ClientError::ServerError {
            status: resp_envelope.status,
            message: resp_envelope
                .error
                .unwrap_or_else(|| "Unknown error".to_string()),
        });
    }

    ciborium::de::from_reader(resp_envelope.payload.as_slice())
        .map_err(|e| ClientError::Protocol(format!("CBOR decode payload: {}", e)))
}

/// Get the API key from the LINKKEYS_API_KEY environment variable or exit.
pub fn get_api_key() -> String {
    std::env::var("LINKKEYS_API_KEY").unwrap_or_else(|_| {
        eprintln!("Error: LINKKEYS_API_KEY environment variable is required for remote commands");
        std::process::exit(1);
    })
}

/// Get the server address from an explicit flag, env vars, or default to localhost:4987.
pub fn get_server_addr(server: Option<&str>) -> String {
    server.map(|s| s.to_string()).unwrap_or_else(|| {
        let host = std::env::var("LINKKEYS_SERVER").unwrap_or_else(|_| "localhost".to_string());
        let port = std::env::var("TCP_PORT").unwrap_or_else(|_| "4987".to_string());
        format!("{}:{}", host, port)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_hostname_with_port() {
        assert_eq!(extract_hostname("example.com:4987"), "example.com");
        assert_eq!(extract_hostname("localhost:4987"), "localhost");
        assert_eq!(extract_hostname("auth.example.com:8443"), "auth.example.com");
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
