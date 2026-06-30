//! CLI-facing wrapper around the shared `linkkeys-rpc-client` transport.
//!
//! The transport itself (framing, CBOR envelope, TLS round-trip) lives in the
//! `linkkeys-rpc-client` crate. This module supplies the two things that crate
//! deliberately doesn't own: resolving the server's pinned fingerprints (DNS or
//! the `LINKKEYS_FINGERPRINTS` escape hatch) and loading this process's own
//! domain cert from the database for mutual TLS.

use std::sync::Arc;

pub use linkkeys_rpc_client::ClientError;

/// Resolve the TLS client config for connecting to the given server.
/// Verifies the server's cert against its DNS-published fingerprints (or pinned).
/// If this process is also a domain server (has access to its own domain key),
/// it presents its own cert for mutual TLS — the server can verify us back.
/// Returns the config and the hostname for SNI.
fn resolve_tls_config(server: &str) -> Result<(Arc<rustls::ClientConfig>, String), ClientError> {
    let hostname = linkkeys_rpc_client::extract_hostname(server).to_string();

    // Check for pinned fingerprints (testing/bootstrap escape hatch)
    let fingerprints = match std::env::var("LINKKEYS_FINGERPRINTS") {
        Ok(pinned) => {
            let fps: Vec<String> = pinned
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if fps.is_empty() {
                return Err(ClientError::Tls(
                    "LINKKEYS_FINGERPRINTS is set but empty".to_string(),
                ));
            }
            fps
        }
        Err(_) => {
            // Resolve from DNS — fail closed
            linkkeys::dns::resolve_fingerprints(&hostname).map_err(|e| {
                ClientError::Tls(format!(
                    "DNS fingerprint resolution for {}: {}",
                    hostname, e
                ))
            })?
        }
    };

    // If we have access to our own domain key, present it for mutual TLS.
    // This is the case when we're a domain server connecting to another domain server.
    // If we don't have our own key (e.g., a lightweight client), the server
    // can still accept us — client auth is optional, app-layer auth via API key suffices.
    let config = linkkeys_rpc_client::tls::client_config(fingerprints, load_own_domain_cert().ok())
        .map_err(|e| ClientError::Tls(format!("TLS config: {}", e)))?;

    Ok((config, hostname))
}

/// Load this domain's own certificate and private key for client cert presentation.
/// Only succeeds if we're running on a domain server with DATABASE_URL and
/// DOMAIN_KEY_PASSPHRASE available. These are our own keys — we never need
/// or access another domain's private keys.
fn load_own_domain_cert() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let passphrase =
        std::env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| "DOMAIN_KEY_PASSPHRASE not set")?;

    let db_pool = linkkeys::db::create_pool();
    let domain_keys = db_pool
        .list_active_domain_keys()
        .map_err(|e| format!("Failed to list domain keys: {}", e))?;

    let dk = domain_keys.first().ok_or("No active domain keys")?;

    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|e| format!("Failed to decrypt domain key: {}", e))?;

    let seed: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| "Domain key is not 32 bytes")?;

    let domain_name = linkkeys::conversions::get_domain_name();
    linkkeys::tcp::tls::generate_domain_tls_cert(&domain_name, &seed)
}

/// Send a pre-encoded CBOR `payload` to a LinkKeys server and return the raw
/// response payload bytes. All connections use TLS with fingerprint-based
/// verification; the server's certificate is verified against DNS-published
/// fingerprints. Callers encode the request and decode the response with the
/// CSIL codec.
pub fn send_request(
    server: &str,
    service: &str,
    op: &str,
    payload: Vec<u8>,
    api_key: Option<&str>,
) -> Result<Vec<u8>, ClientError> {
    let (tls_config, hostname) = resolve_tls_config(server)?;
    linkkeys_rpc_client::send_raw_with_config(
        server, tls_config, &hostname, service, op, payload, api_key,
    )
}

/// Get the API key from the LINKKEYS_API_KEY environment variable or exit.
pub fn get_api_key() -> String {
    std::env::var("LINKKEYS_API_KEY").unwrap_or_else(|_| {
        eprintln!("Error: LINKKEYS_API_KEY environment variable is required for remote commands");
        std::process::exit(1);
    })
}

/// Get the server address from an explicit flag, env vars, or default to
/// localhost on the spec default TCP port.
pub fn get_server_addr(server: Option<&str>) -> String {
    server.map(|s| s.to_string()).unwrap_or_else(|| {
        let host = std::env::var("LINKKEYS_SERVER").unwrap_or_else(|_| "localhost".to_string());
        let port = std::env::var("TCP_PORT")
            .unwrap_or_else(|_| liblinkkeys::dns::DEFAULT_TCP_PORT.to_string());
        format!("{}:{}", host, port)
    })
}
