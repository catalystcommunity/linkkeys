pub mod tls;

use std::collections::BTreeSet;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use threadpool::ThreadPool;

use crate::conversions::get_domain_name;
use crate::db::DbPool;
use crate::services::handshake::HandshakeHandler;
use crate::services::hello::HelloHandler;

use liblinkkeys::generated::types::{
    DepositClaimResponse, DomainPublicKey, GetDomainKeysResponse, GetUserKeysResponse, UserInfo,
};

// The RPC envelope is the canonical CSIL-RPC transport (`csilgen-transport`),
// not a bespoke struct — `RpcRequest` / `RpcResponse` carry the tag-24 payload,
// version, status registry, and `variant`. Framing on this TCP carrier is the
// length-prefixed frames in `read_frame`/`write_frame` (matches the spec's
// length-delimited stream carrier). `RpcRequest`'s fields (`service`, `op`,
// `payload`, `auth`) line up with what `dispatch` already reads.
use csilgen_transport::rpc::{RpcRequest, RpcResponse};
use csilgen_transport::Status;

#[derive(Serialize, Deserialize)]
struct HelloRequest {
    name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct HelloResponse {
    greeting: String,
}

#[derive(Serialize, Deserialize)]
struct CheckResultResponse {
    result: bool,
}

/// Capabilities the dispatch needs for ops that make an onward server-to-server
/// call (the `Rp` service's verify-assertion / userinfo-fetch reach the issuing
/// IDP). Only the TCP server provides this: its worker threads are plain blocking
/// threads, so they may `block_on` the runtime. The web `/csil/v1/rpc` carrier
/// and the test harness pass `None` — they already run inside tokio (cannot
/// `block_on`) and those ops have dedicated routes/tests elsewhere.
pub struct OutboundCtx<'a> {
    pub net: &'a crate::net::Net,
    pub rt: &'a tokio::runtime::Handle,
}

pub struct TcpServer {
    listener: TcpListener,
    thread_pool: ThreadPool,
    ready_flag: Arc<AtomicBool>,
    db_pool: DbPool,
    tls_config: Arc<rustls::ServerConfig>,
    net: crate::net::Net,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl TcpServer {
    pub fn new(
        ready_flag: Arc<AtomicBool>,
        db_pool: DbPool,
        net: crate::net::Net,
    ) -> std::io::Result<Self> {
        let port: u16 = env::var("TCP_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(liblinkkeys::dns::DEFAULT_TCP_PORT);

        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;

        let pool_size = num_cpus::get() * 2;
        let thread_pool = ThreadPool::new(pool_size);

        let tls_config = match build_tls_config(&db_pool, net.dns.clone()) {
            Ok(config) => {
                log::info!("TCP server listening on port {} (mutual TLS)", port);
                config
            }
            Err(e) => {
                log::error!("TCP TLS setup failed: {}. Ensure domain keys are initialized and DOMAIN_KEY_PASSPHRASE is set.", e);
                return Err(std::io::Error::other(e.to_string()));
            }
        };

        // A small multi-thread runtime backs the onward server-to-server calls
        // the `Rp` ops make. Worker threads `block_on` it; multi-thread lets
        // several connections do so concurrently without contending a single
        // current-thread scheduler.
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|e| std::io::Error::other(format!("TCP runtime build failed: {}", e)))?,
        );

        Ok(TcpServer {
            listener,
            thread_pool,
            ready_flag,
            db_pool,
            tls_config,
            net,
            runtime,
        })
    }

    pub fn run(self) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let ready_flag = self.ready_flag.clone();
                    let db_pool = self.db_pool.clone();
                    let tls_config = self.tls_config.clone();
                    let net = self.net.clone();
                    let rt = self.runtime.handle().clone();
                    self.thread_pool.execute(move || {
                        if let Err(e) =
                            handle_connection(stream, ready_flag, &db_pool, tls_config, &net, &rt)
                        {
                            log::debug!("Connection closed: {}", e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("Error accepting connection: {}", e);
                }
            }
        }
    }
}

/// Build TLS ServerConfig with mutual TLS from the first active domain key.
fn build_tls_config(
    db_pool: &DbPool,
    dns: Arc<dyn crate::net::DnsResolver>,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let passphrase =
        env::var("DOMAIN_KEY_PASSPHRASE").map_err(|_| "DOMAIN_KEY_PASSPHRASE not set")?;

    let domain_keys = db_pool
        .list_active_domain_keys()
        .map_err(|e| format!("Failed to list domain keys: {}", e))?;

    let dk = domain_keys
        .first()
        .ok_or("No active domain keys — run 'domain init' first")?;

    let sk_bytes =
        liblinkkeys::crypto::decrypt_private_key(&dk.private_key_encrypted, passphrase.as_bytes())
            .map_err(|e| format!("Failed to decrypt domain key: {}", e))?;

    let seed: [u8; 32] = sk_bytes
        .try_into()
        .map_err(|_| "Domain key is not 32 bytes")?;

    let domain_name = get_domain_name();
    let (cert_der, key_der) = tls::generate_domain_tls_cert(&domain_name, &seed)?;

    // Create a tokio runtime for the client cert verifier's DNS lookups
    let runtime = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to create runtime for TLS verifier: {}", e))?,
    );
    let client_verifier = Arc::new(tls::FingerprintClientCertVerifier::new(runtime, dns));

    tls::build_server_config(cert_der, key_der, client_verifier)
}

fn read_frame(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Frame too large ({} bytes, max {})", len, MAX_FRAME_SIZE),
        ));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_frame(stream: &mut impl Write, data: &[u8]) -> std::io::Result<()> {
    if data.len() > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Response frame too large",
        ));
    }
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(data)?;
    stream.flush()
}

const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Per-connection read/write timeout in seconds. Bounds slowloris-style hold
/// time. Configurable via TCP_IO_TIMEOUT_SECONDS; default 60s.
fn tcp_io_timeout_secs() -> u64 {
    env::var("TCP_IO_TIMEOUT_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(60)
}

fn handle_connection(
    stream: TcpStream,
    ready_flag: Arc<AtomicBool>,
    db_pool: &DbPool,
    tls_config: Arc<rustls::ServerConfig>,
    net: &crate::net::Net,
    rt: &tokio::runtime::Handle,
) -> std::io::Result<()> {
    log::debug!("New TCP connection from: {:?}", stream.peer_addr());
    // Bound how long a single connection can hold a worker thread. Both read
    // and write timeouts are set BEFORE the TLS handshake (which reads/writes
    // on this stream), so a slowloris that stalls mid-handshake or mid-frame is
    // dropped rather than pinning a thread (tcp-04). Configurable; safe default.
    let timeout = Duration::from_secs(tcp_io_timeout_secs());
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.set_nodelay(true)?;

    let conn = rustls::ServerConnection::new(tls_config).map_err(std::io::Error::other)?;
    let mut tls_stream = rustls::StreamOwned::new(conn, stream);

    // Drive the handshake to completion before serving frames so the verified
    // client certificate (if the caller is a domain) is available. mTLS client
    // auth is optional; a caller with no cert yields no client domain.
    tls_stream.conn.complete_io(&mut tls_stream.sock)?;
    let client_domain = tls_stream
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(tls::verified_client_domain);

    handle_message_loop(
        &mut tls_stream,
        &ready_flag,
        db_pool,
        client_domain.as_deref(),
        net,
        rt,
    )
}

/// Maximum CBOR nesting depth allowed. Prevents stack overflow from deeply
/// nested payloads while leaving room for real signed request envelopes, which
/// carry nested maps/arrays for request bodies and multiple signatures.
const MAX_CBOR_DEPTH: usize = 64;

/// Scan raw CBOR bytes and reject if nesting depth exceeds the limit.
/// CBOR major types 4 (array) and 5 (map) increase depth; their items decrease it
/// as they're consumed. This is a conservative linear scan, not a full parser.
fn check_cbor_depth(data: &[u8]) -> bool {
    let mut stack: Vec<Option<usize>> = Vec::new();
    let mut i = 0;
    while i < data.len() {
        while matches!(stack.last(), Some(Some(0))) {
            stack.pop();
        }
        if let Some(Some(remaining)) = stack.last_mut() {
            *remaining = remaining.saturating_sub(1);
        }

        let major = data[i] >> 5;
        let additional = data[i] & 0x1f;
        i += 1;

        let value = match additional {
            0..=23 => Some(additional as u64),
            24 => {
                if i >= data.len() {
                    return false;
                }
                let v = data[i] as u64;
                i += 1;
                Some(v)
            }
            25 => {
                if i + 2 > data.len() {
                    return false;
                }
                let v = u16::from_be_bytes([data[i], data[i + 1]]) as u64;
                i += 2;
                Some(v)
            }
            26 => {
                if i + 4 > data.len() {
                    return false;
                }
                let v = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as u64;
                i += 4;
                Some(v)
            }
            27 => {
                if i + 8 > data.len() {
                    return false;
                }
                let v = u64::from_be_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                i += 8;
                Some(v)
            }
            28..=30 => return false, // reserved, malformed
            31 => None,
            _ => unreachable!(),
        };

        match major {
            0 | 1 => {} // unsigned/negative int — no nesting
            2 | 3 => {
                let Some(len) = value else {
                    return false;
                };
                let Ok(len) = usize::try_from(len) else {
                    return false;
                };
                if i + len > data.len() {
                    return false;
                }
                i += len;
            }
            4 | 5 => {
                let entries = match value {
                    Some(len) if major == 4 => len,
                    Some(len) => len.saturating_mul(2),
                    None => return false,
                };
                let Ok(entries) = usize::try_from(entries) else {
                    return false;
                };
                stack.push(Some(entries));
                if stack.len() > MAX_CBOR_DEPTH {
                    return false;
                }
            }
            6 => {} // tag — next item is the tagged value
            7 => {
                if additional == 31 || value.is_none() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    stack.into_iter().all(|remaining| remaining == Some(0))
}

fn handle_message_loop(
    stream: &mut (impl Read + Write),
    ready_flag: &Arc<AtomicBool>,
    db_pool: &DbPool,
    client_domain: Option<&str>,
    net: &crate::net::Net,
    rt: &tokio::runtime::Handle,
) -> std::io::Result<()> {
    loop {
        let frame = read_frame(stream)?;

        // Defense against deeply nested CBOR causing stack overflow
        if !check_cbor_depth(&frame) {
            let resp = error_response(1, "Malformed request: excessive nesting depth");
            write_frame(stream, &resp)?;
            continue;
        }

        let envelope: RpcRequest = match std::panic::catch_unwind(|| RpcRequest::decode(&frame)) {
            Ok(Ok(env)) => env,
            Ok(Err(e)) => {
                let resp = error_response(1, &format!("Invalid request envelope: {}", e));
                write_frame(stream, &resp)?;
                continue;
            }
            Err(_) => {
                // Deserialization panicked (e.g. stack overflow) — don't crash the thread
                log::warn!(
                    "CBOR deserialization panicked on frame of {} bytes",
                    frame.len()
                );
                let resp = error_response(1, "Malformed request");
                write_frame(stream, &resp)?;
                continue;
            }
        };

        // The inner payload is decoded per-op inside dispatch; depth-check it
        // here too so a deeply-nested payload can't stack-overflow a handler
        // (tcp-05). It's already size-bounded by the 1 MiB frame cap.
        if !check_cbor_depth(&envelope.payload) {
            let resp = error_response(1, "Malformed request: excessive nesting depth");
            write_frame(stream, &resp)?;
            continue;
        }

        let outbound = OutboundCtx { net, rt };
        let response = dispatch(
            &envelope,
            ready_flag,
            db_pool,
            client_domain,
            Some(&outbound),
        );
        write_frame(stream, &response)?;
    }
}

/// Map an internal database error to a generic client message, logging the
/// detail server-side. Avoids leaking schema/SQL internals over the wire to
/// unauthenticated TCP callers (svc-02).
fn db_error_message(e: impl std::fmt::Display) -> String {
    log::warn!("TCP dispatch database error: {}", e);
    "internal database error".to_string()
}

fn cache_claim_signer_keys(
    db_pool: &DbPool,
    claim: &liblinkkeys::generated::types::Claim,
    outbound: Option<&OutboundCtx>,
) {
    let Some(ctx) = outbound else {
        return;
    };
    let our = get_domain_name();
    let domains: BTreeSet<String> = claim
        .signatures
        .iter()
        .map(|s| s.domain.clone())
        .filter(|d| d != &our)
        .collect();
    for domain in domains {
        let keys = match ctx
            .rt
            .block_on(crate::web::rp::fetch_domain_keys(db_pool, ctx.net, &domain))
        {
            Ok(keys) => keys,
            Err(e) => {
                log::warn!("Could not fetch signer keys for {}: {}", domain, e);
                continue;
            }
        };
        for key in keys {
            let peer = crate::db::models::PeerKey {
                domain: domain.clone(),
                key_id: key.key_id,
                public_key: key.public_key,
                algorithm: key.algorithm,
                fingerprint: key.fingerprint,
                key_usage: key.key_usage,
                expires_at: key.expires_at,
                revoked_at: key.revoked_at,
            };
            if let Err(e) = db_pool.cache_peer_key(&peer) {
                log::warn!(
                    "Could not cache signer key {} for {}: {}",
                    peer.key_id,
                    domain,
                    e
                );
            }
        }
    }
}

/// Test/diagnostic harness entry point: run the TCP service dispatch directly,
/// bypassing the socket, TLS, and framing entirely. `client_domain` is the
/// mTLS-proven caller domain the real server would have extracted from the
/// client certificate (`None` = unauthenticated peer). Returns the response
/// envelope's `(status, payload)` — status 0 is success. This is the
/// network-bypass seam for TCP end-to-end tests.
pub fn dispatch_for_test(
    service: &str,
    op: &str,
    payload: Vec<u8>,
    db_pool: &DbPool,
    client_domain: Option<&str>,
) -> (i32, Vec<u8>) {
    dispatch_for_test_authed(service, op, payload, None, db_pool, client_domain)
}

/// Like [`dispatch_for_test`] but carries an `auth` API key in the envelope, for
/// exercising the authenticated services (Admin/Account/Rp) through the dispatch.
/// Like the plain helper it provides no outbound context, so `Rp` ops that make
/// an onward server-to-server call return "unavailable on this carrier".
pub fn dispatch_for_test_authed(
    service: &str,
    op: &str,
    payload: Vec<u8>,
    auth: Option<&str>,
    db_pool: &DbPool,
    client_domain: Option<&str>,
) -> (i32, Vec<u8>) {
    let mut request = RpcRequest::new(service, op, payload);
    if let Some(a) = auth {
        request = request.with_auth(a);
    }
    let ready = Arc::new(AtomicBool::new(true));
    let bytes = dispatch(&request, &ready, db_pool, client_domain, None);
    let resp = RpcResponse::decode(&bytes).expect("response decodes");
    (resp.status.code() as i32, resp.payload)
}

/// Decode a CSIL-RPC request envelope and dispatch it, returning the response
/// envelope bytes. This is the single entry the generic CBOR-RPC carrier (the
/// web `POST /csil/v1/rpc`) shares with the TCP server, so the web carries the
/// same RPC surface without per-op routes. `client_domain` is the mTLS-proven
/// peer over TCP, `None` over the web.
pub fn dispatch_envelope(
    envelope_bytes: &[u8],
    ready_flag: &Arc<AtomicBool>,
    db_pool: &DbPool,
    client_domain: Option<&str>,
) -> Vec<u8> {
    let request = match RpcRequest::decode(envelope_bytes) {
        Ok(r) => r,
        Err(e) => return error_response(1, &format!("Invalid envelope: {}", e)),
    };
    // The web carrier runs inside tokio and cannot `block_on`, so it provides no
    // outbound context; the `Rp` helper ops (which need it) have dedicated HTTP
    // routes and are not served over `/csil/v1/rpc`.
    dispatch(&request, ready_flag, db_pool, client_domain, None)
}

fn dispatch(
    envelope: &RpcRequest,
    ready_flag: &Arc<AtomicBool>,
    db_pool: &DbPool,
    client_domain: Option<&str>,
    outbound: Option<&OutboundCtx>,
) -> Vec<u8> {
    match (envelope.service.as_str(), envelope.op.as_str()) {
        ("Ops", "healthcheck") => ok_response(cbor_response(&CheckResultResponse { result: true })),
        ("Ops", "readiness") => ok_response(cbor_response(&CheckResultResponse {
            result: ready_flag.load(Ordering::SeqCst),
        })),
        ("Hello", "hello") => {
            let request: HelloRequest = match ciborium::de::from_reader(&envelope.payload[..]) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let handler = HelloHandler;
            ok_response(cbor_response(&HelloResponse {
                greeting: handler.hello(request.name),
            }))
        }
        ("Handshake", "handshake") => {
            use liblinkkeys::generated::services::Handshake;
            let request = match liblinkkeys::generated::decode_handshake_request(&envelope.payload)
            {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match HandshakeHandler.handshake(&(), request) {
                Ok(resp) => ok_response(liblinkkeys::generated::encode_handshake_response(&resp)),
                Err(e) => error_response(4, &e.message),
            }
        }
        ("DomainKeys", "get-domain-keys") => match db_pool.list_active_domain_keys() {
            Ok(keys) => ok_response(liblinkkeys::generated::encode_get_domain_keys_response(
                &GetDomainKeysResponse {
                    domain: get_domain_name(),
                    keys: keys.iter().map(Into::into).collect(),
                    recent_revocations_available: Some(
                        crate::services::revocations::recent_revocations_available(db_pool),
                    ),
                },
            )),
            Err(e) => error_response(4, &db_error_message(e)),
        },
        ("DomainKeys", "get-revocations") => {
            let request =
                match liblinkkeys::generated::decode_get_revocations_request(&envelope.payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            let revocations =
                crate::services::revocations::serve(db_pool, request.since.as_deref());
            ok_response(liblinkkeys::generated::encode_get_revocations_response(
                &liblinkkeys::generated::types::GetRevocationsResponse { revocations },
            ))
        }
        // Unauthenticated, like DomainKeys/Ops: any CSIL-RPC client (browser
        // POST /csil/v1/rpc or native TCP) fetches the UI catalog before or
        // without authenticating. `get-translations` merges this domain's
        // per-locale claim-type labels (crate::db, Part C) into the pure
        // liblinkkeys::i18n catalog, so one call returns both UI chrome and
        // claim labels for the negotiated locale.
        ("I18n", "get-translations") => {
            let request =
                match liblinkkeys::generated::decode_translations_request(&envelope.payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            let locale = liblinkkeys::i18n::negotiate(
                request.accept_language.as_deref().unwrap_or(""),
                request.locale.as_deref(),
            );
            let mut messages = liblinkkeys::i18n::catalog_for(&locale);
            if let Ok(policies) = db_pool.list_claim_policies() {
                for policy in &policies {
                    if let Ok((label, description)) =
                        db_pool.resolved_label(&policy.claim_type, &locale)
                    {
                        messages.insert(format!("claim.{}.label", policy.claim_type), label);
                        if !description.is_empty() {
                            messages.insert(
                                format!("claim.{}.description", policy.claim_type),
                                description,
                            );
                        }
                    }
                }
            }
            ok_response(liblinkkeys::generated::encode_translations_response(
                &liblinkkeys::generated::types::TranslationsResponse {
                    locale,
                    available_locales: liblinkkeys::i18n::available_locales(),
                    messages: messages.into_iter().collect(),
                },
            ))
        }
        ("I18n", "list-locales") => {
            ok_response(liblinkkeys::generated::encode_list_locales_response(
                &liblinkkeys::generated::types::ListLocalesResponse {
                    available_locales: liblinkkeys::i18n::available_locales(),
                },
            ))
        }
        ("UserKeys", "get-user-keys") => {
            let request =
                match liblinkkeys::generated::decode_get_user_keys_request(&envelope.payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            match db_pool.list_active_user_keys(&request.user_id) {
                Ok(keys) => ok_response(liblinkkeys::generated::encode_get_user_keys_response(
                    &GetUserKeysResponse {
                        user_id: request.user_id,
                        domain: get_domain_name(),
                        keys: keys.iter().map(Into::into).collect(),
                    },
                )),
                Err(e) => error_response(4, &db_error_message(e)),
            }
        }
        ("Identity", "get-user-info") => {
            let request =
                match liblinkkeys::generated::decode_get_user_info_request(&envelope.payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            let token_str = match String::from_utf8(request.token) {
                Ok(s) => s,
                Err(_) => return error_response(2, "Invalid token encoding"),
            };
            let signed = match liblinkkeys::encoding::assertion_from_url_param(&token_str) {
                Ok(s) => s,
                Err(_) => return error_response(2, "Invalid token format"),
            };
            let domain_keys = match db_pool.list_active_domain_keys() {
                Ok(keys) => keys,
                Err(e) => return error_response(4, &db_error_message(e)),
            };
            let csil_keys: Vec<DomainPublicKey> = domain_keys.iter().map(Into::into).collect();
            let assertion = match liblinkkeys::assertions::verify_assertion(&signed, &csil_keys) {
                Ok(a) => a,
                Err(_) => return error_response(5, "Token verification failed"),
            };
            // Audience binding (crypto-06/tcp-02/tcp-03): the assertion may only
            // be redeemed by the relying party it was issued for. On TCP, the
            // caller's identity is the FP-pinned mTLS client cert domain proven
            // during the handshake; require it to equal the assertion audience.
            // No verified client cert => no proven caller => refuse.
            match client_domain {
                Some(domain) if domain == assertion.audience => {}
                _ => return error_response(5, "Caller is not the assertion audience"),
            }
            // Single-use redemption (parity with the web /userinfo path): an
            // assertion may be exchanged for user info at most once within its
            // TTL, so a leaked/observed token cannot be replayed. Namespaced
            // "userinfo:" to match the web burn and stay independent of login.
            match db_pool.record_nonce(
                &format!("userinfo:{}", assertion.nonce),
                std::time::Duration::from_secs(300),
            ) {
                Ok(true) => {}
                Ok(false) => return error_response(5, "Token already redeemed"),
                Err(e) => return error_response(4, &db_error_message(e)),
            }
            let user = match db_pool.find_user_by_id(&assertion.user_id) {
                Ok(u) => u,
                Err(_) => return error_response(4, "User not found"),
            };
            let claims = match db_pool.list_active_claims(&assertion.user_id) {
                Ok(c) => c,
                Err(e) => return error_response(4, &db_error_message(e)),
            };
            // Scope to exactly the claim types the user consented to for this
            // audience, recorded in the assertion. Parity with the web
            // /userinfo path; fail-closed (empty authorized_claims => nothing).
            let all_claims: Vec<liblinkkeys::generated::types::Claim> =
                claims.iter().map(Into::into).collect();
            let scoped =
                liblinkkeys::consent::scope_claims(&all_claims, &assertion.authorized_claims);
            ok_response(liblinkkeys::generated::encode_user_info(&UserInfo {
                user_id: user.id,
                domain: get_domain_name(),
                display_name: user.display_name,
                claims: scoped,
            }))
        }
        // DNS-less local RP claim-ticket redemption (dns-less-local-rp-design.md,
        // Phase 5). Unauthenticated at the transport layer like DomainKeys/Ops
        // and Attestation/deposit-claim — authentication is the application-
        // layer possession proof: the request is signed with the local RP's
        // own Ed25519 signing key, verified against the STORED key for the
        // claimed fingerprint (never a key supplied in the request).
        ("LocalRp", "redeem-claim-ticket") => {
            dispatch_local_rp_redeem_claim_ticket(&envelope.payload, db_pool)
        }
        ("Admin", op) => {
            let user = match authenticate_tcp_request(&envelope.auth, db_pool) {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            let domain = get_domain_name();
            if let Some(required) =
                crate::services::authorization::required_relation_for_op("Admin", op)
            {
                if !crate::services::authorization::user_has_permission(
                    db_pool, &user.id, required, "domain", &domain,
                ) {
                    return error_response(5, "Forbidden");
                }
            }
            // SEC-04: account-takeover-capable ops (reset-password, deactivate,
            // remove-credential) against a protected admin account require the
            // caller to hold full `admin`, not merely `manage_users`.
            if let Some(target) = admin_op_protected_target(op, &envelope.payload, db_pool) {
                if !crate::services::authorization::caller_may_manage_target(
                    db_pool, &user.id, &target,
                ) {
                    return error_response(5, "Forbidden: target is a protected admin account");
                }
            }
            // SEC-01: recheck-pins needs outbound DNS, so it runs on the TCP
            // carrier and is handled here (dispatch_admin has no net context).
            if op == "recheck-pins" {
                return dispatch_admin_recheck_pins(&envelope.payload, db_pool, outbound);
            }
            dispatch_admin(op, &envelope.payload, db_pool)
        }
        ("Account", op) => {
            let user = match authenticate_tcp_request(&envelope.auth, db_pool) {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            dispatch_account(op, &envelope.payload, db_pool, &user)
        }
        // Relying-party helpers a browser-facing RP (e.g. the demo site) delegates
        // to its RP server over TCP. API-key authenticated. verify-assertion and
        // userinfo-fetch make an onward server-to-server call to the issuing IDP,
        // so they require the outbound context (TCP carrier only).
        ("Rp", op) => {
            let user = match authenticate_tcp_request(&envelope.auth, db_pool) {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            // SEC-06: require the api_access relation, not just any valid API key.
            if let Some(required) =
                crate::services::authorization::required_relation_for_op("Rp", op)
            {
                if !crate::services::authorization::user_has_permission(
                    db_pool,
                    &user.id,
                    required,
                    "domain",
                    &get_domain_name(),
                ) {
                    return error_response(5, "Forbidden");
                }
            }
            dispatch_rp(op, &envelope.payload, db_pool, outbound)
        }
        // Server-to-server: an issuer deposits a claim it signed about one of our
        // accounts. The issuer's signature is the authority (verified against its
        // cached keys + our trusted-issuer policy), so no caller auth is required
        // beyond that — anyone may carry a valid trusted attestation to us.
        ("Attestation", "deposit-claim") => {
            let request =
                match liblinkkeys::generated::decode_deposit_claim_request(&envelope.payload) {
                    Ok(r) => r,
                    Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
                };
            let claim = request.claim;
            if db_pool.find_user_by_id(&claim.user_id).is_err() {
                return error_response(4, "Unknown subject");
            }
            cache_claim_signer_keys(db_pool, &claim, outbound);
            match crate::services::attestation::verify_and_store_attested(
                db_pool,
                &claim.user_id,
                &claim,
            ) {
                Ok(()) => ok_response(liblinkkeys::generated::encode_deposit_claim_response(
                    &DepositClaimResponse { stored: true },
                )),
                Err(e) => error_response(5, &e.message),
            }
        }
        _ => error_response(
            3,
            &format!(
                "Unknown service/operation: {}/{}",
                envelope.service, envelope.op
            ),
        ),
    }
}

/// For the account-takeover-capable Admin ops, decode the target user id from
/// the payload (resolving a credential id to its owning user for
/// remove-credential). Returns None for ops that don't manage an account, or
/// when the payload can't be decoded — the op's own handler surfaces the decode
/// error. Used only to gate SEC-04's protected-admin check.
fn admin_op_protected_target(op: &str, payload: &[u8], db_pool: &DbPool) -> Option<String> {
    use liblinkkeys::generated::codec;
    match op {
        "reset-password" => codec::decode_reset_password_request(payload)
            .ok()
            .map(|r| r.user_id),
        "deactivate-user" => codec::decode_deactivate_user_request(payload)
            .ok()
            .map(|r| r.user_id),
        "remove-credential" => {
            let req = codec::decode_remove_credential_request(payload).ok()?;
            db_pool
                .find_credential_by_id(&req.credential_id)
                .ok()
                .map(|c| c.user_id)
        }
        _ => None,
    }
}

/// SEC-01: admin-gated pin recheck. Runs on the TCP carrier because it makes
/// outbound DNS lookups. With no `domain` it rechecks every pinned domain.
fn dispatch_admin_recheck_pins(
    payload: &[u8],
    db_pool: &DbPool,
    outbound: Option<&OutboundCtx>,
) -> Vec<u8> {
    let Some(ctx) = outbound else {
        return error_response(
            6,
            "recheck-pins requires the TCP carrier (needs outbound DNS)",
        );
    };
    let request = match liblinkkeys::generated::decode_recheck_pins_request(payload) {
        Ok(r) => r,
        Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
    };
    let results = ctx.rt.block_on(async {
        match request.domain.as_deref() {
            Some(d) => vec![(
                d.to_string(),
                crate::services::pins::recheck_domain(db_pool, ctx.net, d).await,
            )],
            None => crate::services::pins::recheck_all(db_pool, ctx.net).await,
        }
    });
    let results = results
        .into_iter()
        .map(
            |(domain, r)| liblinkkeys::generated::types::PinRecheckResult {
                domain,
                outcome: match r {
                    Ok(o) => format!("{o:?}"),
                    Err(e) => format!("error: {e}"),
                },
            },
        )
        .collect();
    ok_response(liblinkkeys::generated::encode_recheck_pins_response(
        &liblinkkeys::generated::types::RecheckPinsResponse { results },
    ))
}

/// Whether a ticket-redemption request's `issued_at` is within the design's
/// bounded clock-skew tolerance of `now` (`liblinkkeys::local_rp::
/// DEFAULT_CLOCK_SKEW_SECONDS`, ±300s). `LocalRpTicketRedemptionRequest` has
/// no `expires_at` (unlike the login/callback structures) — freshness is a
/// single-sided window around `issued_at`, checked here rather than via
/// `liblinkkeys::local_rp::check_timestamps` (which expects an
/// issued/expires pair).
fn ticket_redemption_issued_at_fresh(issued_at: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    let Ok(issued) = chrono::DateTime::parse_from_rfc3339(issued_at) else {
        return false;
    };
    let issued = issued.with_timezone(&chrono::Utc);
    (now - issued).num_seconds().abs() <= liblinkkeys::local_rp::DEFAULT_CLOCK_SKEW_SECONDS
}

/// `LocalRp/redeem-claim-ticket` (dns-less-local-rp-design.md, Phase 5).
/// Order matters (Wire Precision, "Service and authorization placement" +
/// Phase 5 notes):
/// 1. decode (cheap CBOR, no crypto)
/// 2. peek at the unverified inner request only to learn which fingerprint
///    to look up
/// 3. look up the local RP row by that fingerprint; reject unless `approved`
/// 4. verify the envelope signature against the STORED signing key
///    (possession proof — never a key supplied in the request)
/// 5. rate-limit, keyed on the now-POSSESSION-PROVEN fingerprint. The debit
///    deliberately happens only after the signature verifies: the fingerprint
///    in the request is attacker-chosen, so metering before the proof would
///    let anyone who can reach the TCP port spam a *victim's* fingerprint
///    and exhaust the legitimate app's bucket — a cheap remote DoS of a
///    specific local RP. Placed here, only the actual key holder can ever
///    consume its own bucket. The unverified path's worst-case cost is one
///    indexed PK lookup plus one Ed25519 verify, matching the cost posture
///    of the other unauthenticated ops (get-domain-keys already does
///    unmetered DB reads).
/// 6. check `issued_at` freshness
/// 7. redeem the ticket via the Phase 4 path (hash, POSSESSION-PROVEN
///    fingerprint binding, expiry + approval re-check) — the fingerprint
///    check is what stops RP B from redeeming a ticket issued to RP A merely
///    by learning A's ticket bytes; only the RP the ticket was actually
///    issued to may ever redeem it
/// 8. reject a deactivated/purged ticket owner (Phase 4 finding: purge
///    minimizes rather than deletes the user row, so the ticket's FK never
///    cascades away on purge — this is the backstop)
/// 9. assemble the consent-frozen claim set at current values, with their
///    existing per-claim signatures, reusing the same
///    `list_active_claims` + `scope_claims` pattern `Identity/get-user-info`
///    and `Account/get-my-info` already use.
fn dispatch_local_rp_redeem_claim_ticket(payload: &[u8], db_pool: &DbPool) -> Vec<u8> {
    let signed =
        match liblinkkeys::generated::decode_signed_local_rp_ticket_redemption_request(payload) {
            Ok(s) => s,
            Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
        };

    // Cheap peek at the still-unverified inner request, only to learn which
    // fingerprint to look up. This is a plain CBOR decode, not a signature
    // check: a caller cannot gain anything by lying about the fingerprint
    // here, since the signature verified below must match the STORED key for
    // whatever fingerprint is actually looked up.
    let claimed =
        match liblinkkeys::generated::decode_local_rp_ticket_redemption_request(&signed.request) {
            Ok(r) => r,
            Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
        };

    let rp = match db_pool.find_local_rp(&claimed.fingerprint) {
        Ok(Some(rp)) => rp,
        Ok(None) => return error_response(5, "Unknown local RP"),
        Err(e) => return error_response(4, &db_error_message(e)),
    };
    if rp.status != crate::db::local_rp::STATUS_APPROVED {
        return error_response(5, "Local RP is not approved");
    }

    let request = match liblinkkeys::local_rp::verify_local_rp_ticket_redemption_request(
        &signed,
        &rp.signing_public_key,
        &rp.fingerprint,
    ) {
        Ok(r) => r,
        Err(_) => return error_response(5, "Ticket redemption signature verification failed"),
    };

    // Only a possession-proven request may consume the RP's bucket (see the
    // ordering rationale in the doc comment above).
    if !crate::services::ratelimit::TICKET_REDEMPTION.check(&rp.fingerprint) {
        return error_response(
            5,
            "Too many ticket redemption attempts. Please wait and try again.",
        );
    }

    let now = chrono::Utc::now();
    if !ticket_redemption_issued_at_fresh(&request.issued_at, now) {
        return error_response(5, "Ticket redemption request is not fresh");
    }

    // Never log the raw ticket bytes; only its hash ever leaves this scope.
    // `rp.fingerprint` is the caller's POSSESSION-PROVEN identity (the
    // signature above already verified against the STORED key for this
    // fingerprint) — passing it into `redeem_ticket` is what binds redemption
    // to the redeeming RP, not merely to whoever knows the ticket bytes.
    let ticket_hash = liblinkkeys::crypto::fingerprint(&request.claim_ticket);
    let ticket =
        match crate::services::local_rp::redeem_ticket(db_pool, &ticket_hash, &rp.fingerprint, now)
        {
            Ok(t) => t,
            Err(crate::services::local_rp::TicketRedeemError::NotFound) => {
                return error_response(5, "Claim ticket not found")
            }
            // Deliberately the SAME message/status as `NotFound`: a ticket bound
            // to a different RP must not be distinguishable from a ticket that
            // doesn't exist, or the error would be a fingerprint-guessing oracle.
            Err(crate::services::local_rp::TicketRedeemError::FingerprintMismatch) => {
                return error_response(5, "Claim ticket not found")
            }
            Err(crate::services::local_rp::TicketRedeemError::Expired) => {
                return error_response(5, "Claim ticket has expired")
            }
            Err(crate::services::local_rp::TicketRedeemError::RpNotApproved(_)) => {
                return error_response(5, "Local RP is not approved")
            }
            Err(crate::services::local_rp::TicketRedeemError::Db(e)) => {
                return error_response(4, &db_error_message(e))
            }
        };

    let user = match db_pool.find_user_by_id(&ticket.user_id) {
        Ok(u) => u,
        Err(_) => return error_response(4, "User not found"),
    };
    if !user.is_active || user.purged_at.is_some() {
        return error_response(5, "User is deactivated or purged");
    }

    let claims = match db_pool.list_active_claims(&ticket.user_id) {
        Ok(c) => c,
        Err(e) => return error_response(4, &db_error_message(e)),
    };
    let all_claims: Vec<liblinkkeys::generated::types::Claim> =
        claims.iter().map(Into::into).collect();
    let scoped = liblinkkeys::consent::scope_claims(&all_claims, &ticket.granted_claims);

    ok_response(
        liblinkkeys::generated::encode_local_rp_ticket_redemption_response(
            &liblinkkeys::generated::types::LocalRpTicketRedemptionResponse {
                user_id: ticket.user_id,
                user_domain: ticket.user_domain,
                claims: scoped,
                ticket_expires_at: ticket.expires_at,
            },
        ),
    )
}

fn dispatch_admin(op: &str, payload: &[u8], db_pool: &DbPool) -> Vec<u8> {
    use crate::services::admin;
    use liblinkkeys::generated::codec;

    macro_rules! admin_op {
        ($decode:path, $handler:expr, $encode:path) => {{
            let request = match $decode(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match $handler(db_pool, request) {
                Ok(resp) => ok_response($encode(&resp)),
                Err(e) => error_response(4, &e.message),
            }
        }};
    }

    match op {
        "list-users" => admin_op!(
            codec::decode_list_users_request,
            admin::list_users,
            codec::encode_list_users_response
        ),
        "get-user" => admin_op!(
            codec::decode_get_user_request,
            admin::get_user,
            codec::encode_get_user_response
        ),
        "create-user" => admin_op!(
            codec::decode_create_user_request,
            admin::create_user,
            codec::encode_create_user_response
        ),
        "authenticate" => admin_op!(
            codec::decode_authenticate_request,
            admin::authenticate,
            codec::encode_authenticate_response
        ),
        "update-user" => admin_op!(
            codec::decode_update_user_request,
            admin::update_user,
            codec::encode_update_user_response
        ),
        "deactivate-user" => admin_op!(
            codec::decode_deactivate_user_request,
            admin::deactivate_user,
            codec::encode_deactivate_user_response
        ),
        "reset-password" => admin_op!(
            codec::decode_reset_password_request,
            admin::reset_password,
            codec::encode_reset_password_response
        ),
        "remove-credential" => admin_op!(
            codec::decode_remove_credential_request,
            admin::remove_credential,
            codec::encode_remove_credential_response
        ),
        "set-claim" => admin_op!(
            codec::decode_set_claim_request,
            admin::set_claim,
            codec::encode_set_claim_response
        ),
        "remove-claim" => admin_op!(
            codec::decode_remove_claim_request,
            admin::remove_claim,
            codec::encode_remove_claim_response
        ),
        "list-user-claims" => admin_op!(
            codec::decode_list_user_claims_request,
            admin::list_user_claims,
            codec::encode_list_user_claims_response
        ),
        "set-user-claim" => admin_op!(
            codec::decode_set_user_claim_request,
            admin::set_user_claim,
            codec::encode_set_user_claim_response
        ),
        "list-settable-policies" => admin_op!(
            codec::decode_empty_request,
            admin::list_settable_policies,
            codec::encode_list_settable_policies_response
        ),
        "grant-relation" => admin_op!(
            codec::decode_grant_relation_request,
            admin::grant_relation,
            codec::encode_grant_relation_response
        ),
        "remove-relation" => admin_op!(
            codec::decode_remove_relation_request,
            admin::remove_relation,
            codec::encode_remove_relation_response
        ),
        "list-relations" => admin_op!(
            codec::decode_list_relations_request,
            admin::list_relations,
            codec::encode_list_relations_response
        ),
        "check-permission" => admin_op!(
            codec::decode_check_permission_request,
            admin::check_permission_handler,
            codec::encode_check_permission_response
        ),
        // DNS-less local RP admin surface (dns-less-local-rp-design.md, Phase 7).
        "list-local-rps" => admin_op!(
            codec::decode_list_local_rps_request,
            admin::list_local_rps,
            codec::encode_list_local_rps_response
        ),
        "get-local-rp" => admin_op!(
            codec::decode_get_local_rp_request,
            admin::get_local_rp,
            codec::encode_get_local_rp_response
        ),
        "approve-local-rp" => admin_op!(
            codec::decode_approve_local_rp_request,
            admin::approve_local_rp,
            codec::encode_approve_local_rp_response
        ),
        "deny-local-rp" => admin_op!(
            codec::decode_deny_local_rp_request,
            admin::deny_local_rp,
            codec::encode_deny_local_rp_response
        ),
        "revoke-local-rp" => admin_op!(
            codec::decode_revoke_local_rp_request,
            admin::revoke_local_rp,
            codec::encode_revoke_local_rp_response
        ),
        "get-local-rp-policy" => admin_op!(
            codec::decode_get_local_rp_policy_request,
            admin::get_local_rp_policy,
            codec::encode_get_local_rp_policy_response
        ),
        "set-local-rp-policy" => admin_op!(
            codec::decode_set_local_rp_policy_request,
            admin::set_local_rp_policy,
            codec::encode_set_local_rp_policy_response
        ),
        _ => error_response(3, &format!("Unknown Admin operation: {}", op)),
    }
}

fn dispatch_account(
    op: &str,
    payload: &[u8],
    db_pool: &DbPool,
    user: &crate::db::models::User,
) -> Vec<u8> {
    use crate::services::account;

    match op {
        "change-password" => {
            let request = match liblinkkeys::generated::decode_change_password_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match account::change_password(db_pool, &user.id, request) {
                Ok(resp) => ok_response(liblinkkeys::generated::encode_change_password_response(
                    &resp,
                )),
                Err(e) => error_response(4, &e.message),
            }
        }
        "get-my-info" => match account::get_my_info(db_pool, &user.id) {
            Ok(resp) => ok_response(liblinkkeys::generated::encode_get_my_info_response(&resp)),
            Err(e) => error_response(4, &e.message),
        },
        _ => error_response(3, &format!("Unknown Account operation: {}", op)),
    }
}

/// Map a web-layer `Status` (the Rp cores' error type) to a CSIL error response.
fn rp_status_to_error(status: rocket::http::Status) -> Vec<u8> {
    let code = match status.code {
        400 => 2,       // BadRequest -> invalid payload
        401 | 403 => 5, // Unauthorized / Forbidden -> auth/verification
        _ => 4,         // BadGateway / InternalServerError -> internal
    };
    error_response(code, status.reason().unwrap_or("error"))
}

/// Dispatch a `Rp` helper op, reusing the same core functions the web JSON routes
/// call. `sign-request` and `decrypt-token` are local; `verify-assertion` and
/// `userinfo-fetch` make an onward call to the issuing IDP and so require the
/// outbound context (present on the TCP carrier, absent on the web carrier and in
/// the test harness, where they return an error).
fn dispatch_rp(
    op: &str,
    payload: &[u8],
    db_pool: &DbPool,
    outbound: Option<&OutboundCtx>,
) -> Vec<u8> {
    use crate::web::rp;
    use liblinkkeys::generated::codec;

    match op {
        "sign-request" => {
            let req = match codec::decode_rp_sign_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let cfg = crate::rp_config::RpClaimsConfig::load_from_env();
            match rp::sign_request_core(
                db_pool,
                &cfg,
                &req.callback_url,
                &req.nonce,
                req.requested_claims,
                req.flow_context,
            ) {
                Ok(resp) => ok_response(codec::encode_rp_sign_response(&resp)),
                Err(s) => rp_status_to_error(s),
            }
        }
        "decrypt-token" => {
            let req = match codec::decode_rp_decrypt_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match rp::decrypt_token_core(db_pool, &req.encrypted_token) {
                Ok(resp) => ok_response(codec::encode_rp_decrypt_response(&resp)),
                Err(s) => rp_status_to_error(s),
            }
        }
        "verify-assertion" => {
            let req = match codec::decode_rp_verify_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let ctx = match outbound {
                Some(c) => c,
                None => return error_response(4, "operation unavailable on this carrier"),
            };
            match ctx.rt.block_on(rp::verify_assertion_core(
                db_pool,
                ctx.net,
                &req.signed_assertion,
                &req.expected_domain,
            )) {
                Ok(resp) => ok_response(codec::encode_rp_verify_response(&resp)),
                Err(s) => rp_status_to_error(s),
            }
        }
        "userinfo-fetch" => {
            let req = match codec::decode_rp_user_info_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let ctx = match outbound {
                Some(c) => c,
                None => return error_response(4, "operation unavailable on this carrier"),
            };
            match ctx.rt.block_on(rp::fetch_userinfo_core(
                db_pool,
                ctx.net,
                req.token,
                &req.api_base,
                &req.domain,
            )) {
                Ok(resp) => ok_response(codec::encode_user_info(&resp)),
                Err(s) => rp_status_to_error(s),
            }
        }
        "issue-attestation" => {
            let req = match codec::decode_rp_issue_attestation_request(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let ctx = match outbound {
                Some(c) => c,
                None => return error_response(4, "operation unavailable on this carrier"),
            };
            match ctx.rt.block_on(rp::issue_attestation_core(
                db_pool,
                ctx.net,
                req.signed_request,
                &req.claim_type,
                &req.claim_value,
            )) {
                Ok(resp) => ok_response(codec::encode_rp_issue_attestation_response(&resp)),
                Err(s) => rp_status_to_error(s),
            }
        }
        _ => error_response(3, &format!("Unknown Rp operation: {}", op)),
    }
}

/// A successful CSIL-RPC reply carrying a typed payload. Our operations declare a
/// single output type (no `/ ErrorType` arms yet), so `variant` is omitted; if we
/// later add typed error arms, set it to the chosen arm's CSIL type name.
fn ok_response(payload_bytes: Vec<u8>) -> Vec<u8> {
    RpcResponse {
        id: None,
        status: Status::Ok,
        variant: None,
        error: None,
        payload: payload_bytes,
    }
    .encode()
    .expect("encode RPC response")
}

/// CBOR-encode a hand-written (non-CSIL) response struct still carrying serde.
/// The generated CSIL types use the codec instead; this is only for the small
/// local structs (`HelloResponse`, `CheckResultResponse`) served on TCP.
fn cbor_response<T: Serialize>(payload: &T) -> Vec<u8> {
    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut payload_bytes)
        .expect("CBOR serialization of response payload");
    payload_bytes
}

/// Map our historical transport status ints onto the CSIL-RPC status registry and
/// build a transport-error response (no typed payload). These are *transport*
/// failures, never application errors (which would ride as a status-0 variant).
fn error_response(status: i32, message: &str) -> Vec<u8> {
    let status = match status {
        1 | 2 => Status::MalformedEnvelope,
        3 => Status::UnknownServiceOrOp,
        4 => Status::Internal,
        5 => Status::Forbidden,
        other => Status::Other(other as i64),
    };
    RpcResponse::transport_error(status, message)
        .encode()
        .expect("encode RPC error response")
}

/// Authenticate a TCP request using the auth field from the envelope.
/// Returns the authenticated user or an error response ready to send.
fn authenticate_tcp_request(
    auth: &Option<String>,
    db_pool: &DbPool,
) -> Result<crate::db::models::User, Vec<u8>> {
    let api_key = match auth {
        Some(key) => key,
        None => return Err(error_response(5, "Authentication required")),
    };

    let authenticator = crate::services::auth::ApiKeyAuthenticator::new(db_pool.clone());
    match authenticator.authenticate_key(api_key) {
        Ok(user) => {
            if !user.is_active {
                return Err(error_response(5, "Account deactivated"));
            }
            Ok(user)
        }
        Err(_) => Err(error_response(5, "Invalid credentials")),
    }
}

#[cfg(test)]
mod depth_tests {
    use super::check_cbor_depth;

    #[test]
    fn test_simple_cbor_passes() {
        // A simple CBOR map with string keys — typical request envelope
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&serde_json::json!({"hello": "world"}), &mut buf).unwrap();
        assert!(check_cbor_depth(&buf));
    }

    #[test]
    fn test_deeply_nested_array_rejected() {
        // Build CBOR with 100 nested arrays: each is major type 4, additional 1 (one-element array)
        let mut data = vec![0x81; 100];
        data.push(0x00); // integer 0 at the bottom
        assert!(!check_cbor_depth(&data));
    }

    #[test]
    fn test_moderate_nesting_passes() {
        // 10 levels of nesting — well under the limit
        let mut data = vec![0x81; 10];
        data.push(0x00);
        assert!(check_cbor_depth(&data));
    }

    #[test]
    fn test_empty_input_passes() {
        assert!(check_cbor_depth(&[]));
    }

    #[test]
    fn test_deeply_nested_maps_rejected() {
        // 100 nested maps: each is major type 5, additional 1 (one-entry map).
        // Must exceed MAX_CBOR_DEPTH (64) to be rejected — see the array test.
        let mut data = Vec::new();
        for _ in 0..100 {
            data.push(0xa1); // map of 1 entry
            data.push(0x61); // text string of length 1
            data.push(b'k'); // key "k"
        }
        data.push(0x00); // value 0
        assert!(!check_cbor_depth(&data));
    }
}
