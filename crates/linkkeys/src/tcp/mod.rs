pub mod tls;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::env;

use serde::{Deserialize, Serialize};
use threadpool::ThreadPool;

use linkkeys::conversions::get_domain_name;
use linkkeys::db::DbPool;
use linkkeys::services::handshake::HandshakeHandler;
use linkkeys::services::hello::HelloHandler;

use liblinkkeys::generated::types::{
    DomainPublicKey, GetDomainKeysResponse, GetUserInfoRequest, GetUserKeysRequest,
    GetUserKeysResponse, HandshakeRequest, UserInfo,
};

#[derive(Serialize, Deserialize)]
struct RequestEnvelope {
    v: u32,
    service: String,
    op: String,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    #[serde(default)]
    auth: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ResponseEnvelope {
    v: u32,
    status: i32,
    error: Option<String>,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
}

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

pub struct TcpServer {
    listener: TcpListener,
    thread_pool: ThreadPool,
    ready_flag: Arc<AtomicBool>,
    db_pool: DbPool,
    tls_config: Arc<rustls::ServerConfig>,
}

impl TcpServer {
    pub fn new(ready_flag: Arc<AtomicBool>, db_pool: DbPool) -> std::io::Result<Self> {
        let port: u16 = env::var("TCP_PORT")
            .unwrap_or_else(|_| "4987".to_string())
            .parse()
            .unwrap_or(4987);

        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;

        let pool_size = num_cpus::get() * 2;
        let thread_pool = ThreadPool::new(pool_size);

        let tls_config = match build_tls_config(&db_pool) {
            Ok(config) => {
                log::info!("TCP server listening on port {} (mutual TLS)", port);
                config
            }
            Err(e) => {
                log::error!("TCP TLS setup failed: {}. Ensure domain keys are initialized and DOMAIN_KEY_PASSPHRASE is set.", e);
                return Err(std::io::Error::other(e.to_string()));
            }
        };

        Ok(TcpServer { listener, thread_pool, ready_flag, db_pool, tls_config })
    }

    pub fn run(self) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let ready_flag = self.ready_flag.clone();
                    let db_pool = self.db_pool.clone();
                    let tls_config = self.tls_config.clone();
                    self.thread_pool.execute(move || {
                        if let Err(e) = handle_connection(stream, ready_flag, &db_pool, tls_config) {
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
fn build_tls_config(db_pool: &DbPool) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let passphrase = env::var("DOMAIN_KEY_PASSPHRASE")
        .map_err(|_| "DOMAIN_KEY_PASSPHRASE not set")?;

    let domain_keys = db_pool.list_active_domain_keys()
        .map_err(|e| format!("Failed to list domain keys: {}", e))?;

    let dk = domain_keys.first()
        .ok_or("No active domain keys — run 'domain init' first")?;

    let sk_bytes = liblinkkeys::crypto::decrypt_private_key(
        &dk.private_key_encrypted,
        passphrase.as_bytes(),
    ).map_err(|e| format!("Failed to decrypt domain key: {}", e))?;

    let seed: [u8; 32] = sk_bytes.try_into()
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
    let client_verifier = Arc::new(tls::FingerprintClientCertVerifier::new(runtime));

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

fn handle_connection(
    stream: TcpStream,
    ready_flag: Arc<AtomicBool>,
    db_pool: &DbPool,
    tls_config: Arc<rustls::ServerConfig>,
) -> std::io::Result<()> {
    log::debug!("New TCP connection from: {:?}", stream.peer_addr());
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;
    stream.set_nodelay(true)?;

    let conn = rustls::ServerConnection::new(tls_config)
        .map_err(std::io::Error::other)?;
    let mut tls_stream = rustls::StreamOwned::new(conn, stream);
    handle_message_loop(&mut tls_stream, &ready_flag, db_pool)
}

/// Maximum CBOR nesting depth allowed. Prevents stack overflow from deeply nested payloads.
const MAX_CBOR_DEPTH: usize = 32;

/// Scan raw CBOR bytes and reject if nesting depth exceeds the limit.
/// CBOR major types 4 (array) and 5 (map) increase depth; their items decrease it
/// as they're consumed. This is a conservative linear scan, not a full parser.
fn check_cbor_depth(data: &[u8]) -> bool {
    let mut depth: usize = 0;
    let mut i = 0;
    while i < data.len() {
        let major = data[i] >> 5;
        let additional = data[i] & 0x1f;
        i += 1;

        // Skip additional info bytes (determines the length/value encoding)
        match additional {
            0..=23 => {}       // value is in the additional bits
            24 => i += 1,      // 1-byte value follows
            25 => i += 2,      // 2-byte value
            26 => i += 4,      // 4-byte value
            27 => i += 8,      // 8-byte value
            28..=30 => return false, // reserved, malformed
            31 => {
                // Indefinite length — arrays and maps increase depth
                if major == 4 || major == 5 {
                    depth += 1;
                    if depth > MAX_CBOR_DEPTH {
                        return false;
                    }
                }
                continue;
            }
            _ => unreachable!(),
        }

        match major {
            0 | 1 => {}                          // unsigned/negative int — no nesting
            2 | 3 if additional <= 23 => {        // byte/text string with inline length
                i += additional as usize;
            }
            2 | 3 => {}                           // byte/text string — length already skipped above
            4 | 5 => {                            // array or map — increase depth
                depth += 1;
                if depth > MAX_CBOR_DEPTH {
                    return false;
                }
            }
            6 => {}                               // tag — next item is the tagged value
            7 => {                                // simple/float/break
                if additional == 31 {
                    // "break" — end of indefinite container
                    depth = depth.saturating_sub(1);
                }
            }
            _ => return false,
        }
    }
    true
}

fn handle_message_loop(
    stream: &mut (impl Read + Write),
    ready_flag: &Arc<AtomicBool>,
    db_pool: &DbPool,
) -> std::io::Result<()> {
    loop {
        let frame = read_frame(stream)?;

        // Defense against deeply nested CBOR causing stack overflow
        if !check_cbor_depth(&frame) {
            let resp = error_response(1, "Malformed request: excessive nesting depth");
            write_frame(stream, &resp)?;
            continue;
        }

        let envelope: RequestEnvelope = match std::panic::catch_unwind(|| {
            ciborium::de::from_reader::<RequestEnvelope, _>(&frame[..])
        }) {
            Ok(Ok(env)) => env,
            Ok(Err(e)) => {
                let resp = error_response(1, &format!("Invalid request envelope: {}", e));
                write_frame(stream, &resp)?;
                continue;
            }
            Err(_) => {
                // Deserialization panicked (e.g. stack overflow) — don't crash the thread
                log::warn!("CBOR deserialization panicked on frame of {} bytes", frame.len());
                let resp = error_response(1, "Malformed request");
                write_frame(stream, &resp)?;
                continue;
            }
        };

        let response = dispatch(&envelope, ready_flag, db_pool);
        write_frame(stream, &response)?;
    }
}

fn dispatch(envelope: &RequestEnvelope, ready_flag: &Arc<AtomicBool>, db_pool: &DbPool) -> Vec<u8> {
    match (envelope.service.as_str(), envelope.op.as_str()) {
        ("Ops", "healthcheck") => {
            ok_response(&CheckResultResponse { result: true })
        }
        ("Ops", "readiness") => {
            ok_response(&CheckResultResponse { result: ready_flag.load(Ordering::SeqCst) })
        }
        ("Hello", "hello") => {
            let request: HelloRequest = match ciborium::de::from_reader(&envelope.payload[..]) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            let handler = HelloHandler;
            ok_response(&HelloResponse { greeting: handler.hello(request.name) })
        }
        ("Handshake", "handshake") => {
            use liblinkkeys::generated::services::Handshake;
            let request: HandshakeRequest = match ciborium::de::from_reader(&envelope.payload[..]) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match HandshakeHandler.handshake(&(), request) {
                Ok(resp) => ok_response(&resp),
                Err(e) => error_response(4, &e.message),
            }
        }
        ("DomainKeys", "get-domain-keys") => {
            match db_pool.list_active_domain_keys() {
                Ok(keys) => ok_response(&GetDomainKeysResponse {
                    domain: get_domain_name(),
                    keys: keys.iter().map(Into::into).collect(),
                }),
                Err(e) => error_response(4, &format!("DB error: {}", e)),
            }
        }
        ("UserKeys", "get-user-keys") => {
            let request: GetUserKeysRequest = match ciborium::de::from_reader(&envelope.payload[..]) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match db_pool.list_active_user_keys(&request.user_id) {
                Ok(keys) => ok_response(&GetUserKeysResponse {
                    user_id: request.user_id,
                    domain: get_domain_name(),
                    keys: keys.iter().map(Into::into).collect(),
                }),
                Err(e) => error_response(4, &format!("DB error: {}", e)),
            }
        }
        ("Identity", "get-user-info") => {
            let request: GetUserInfoRequest = match ciborium::de::from_reader(&envelope.payload[..]) {
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
                Err(e) => return error_response(4, &format!("DB error: {}", e)),
            };
            let csil_keys: Vec<DomainPublicKey> = domain_keys.iter().map(Into::into).collect();
            let assertion = match liblinkkeys::assertions::verify_assertion(&signed, &csil_keys) {
                Ok(a) => a,
                Err(_) => return error_response(5, "Token verification failed"),
            };
            let user = match db_pool.find_user_by_id(&assertion.user_id) {
                Ok(u) => u,
                Err(_) => return error_response(4, "User not found"),
            };
            let claims = match db_pool.list_active_claims(&assertion.user_id) {
                Ok(c) => c,
                Err(e) => return error_response(4, &format!("DB error: {}", e)),
            };
            ok_response(&UserInfo {
                user_id: user.id,
                domain: get_domain_name(),
                display_name: user.display_name,
                claims: claims.iter().map(Into::into).collect(),
            })
        }
        ("Admin", op) => {
            let user = match authenticate_tcp_request(&envelope.auth, db_pool) {
                Ok(u) => u,
                Err(resp) => return resp,
            };
            let domain = get_domain_name();
            if let Some(required) = linkkeys::services::authorization::required_relation_for_op("Admin", op) {
                if !linkkeys::services::authorization::user_has_permission(db_pool, &user.id, required, "domain", &domain) {
                    return error_response(5, "Forbidden");
                }
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
        _ => error_response(
            3,
            &format!("Unknown service/operation: {}/{}", envelope.service, envelope.op),
        ),
    }
}

fn dispatch_admin(op: &str, payload: &[u8], db_pool: &DbPool) -> Vec<u8> {
    use linkkeys::services::admin;
    use liblinkkeys::generated::types::*;

    macro_rules! admin_op {
        ($req_type:ty, $handler:expr) => {{
            let request: $req_type = match ciborium::de::from_reader(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match $handler(db_pool, request) {
                Ok(resp) => ok_response(&resp),
                Err(e) => error_response(4, &e.message),
            }
        }};
    }

    match op {
        "list-users" => admin_op!(ListUsersRequest, admin::list_users),
        "get-user" => admin_op!(GetUserRequest, admin::get_user),
        "create-user" => admin_op!(CreateUserRequest, admin::create_user),
        "update-user" => admin_op!(UpdateUserRequest, admin::update_user),
        "deactivate-user" => admin_op!(DeactivateUserRequest, admin::deactivate_user),
        "reset-password" => admin_op!(ResetPasswordRequest, admin::reset_password),
        "remove-credential" => admin_op!(RemoveCredentialRequest, admin::remove_credential),
        "set-claim" => admin_op!(SetClaimRequest, admin::set_claim),
        "remove-claim" => admin_op!(RemoveClaimRequest, admin::remove_claim),
        "grant-relation" => admin_op!(GrantRelationRequest, admin::grant_relation),
        "remove-relation" => admin_op!(RemoveRelationRequest, admin::remove_relation),
        "list-relations" => admin_op!(ListRelationsRequest, admin::list_relations),
        "check-permission" => admin_op!(CheckPermissionRequest, admin::check_permission_handler),
        _ => error_response(3, &format!("Unknown Admin operation: {}", op)),
    }
}

fn dispatch_account(
    op: &str,
    payload: &[u8],
    db_pool: &DbPool,
    user: &linkkeys::db::models::User,
) -> Vec<u8> {
    use linkkeys::services::account;
    use liblinkkeys::generated::types::*;

    match op {
        "change-password" => {
            let request: ChangePasswordRequest = match ciborium::de::from_reader(payload) {
                Ok(r) => r,
                Err(e) => return error_response(2, &format!("Invalid payload: {}", e)),
            };
            match account::change_password(db_pool, &user.id, request) {
                Ok(resp) => ok_response(&resp),
                Err(e) => error_response(4, &e.message),
            }
        }
        "get-my-info" => match account::get_my_info(db_pool, &user.id) {
            Ok(resp) => ok_response(&resp),
            Err(e) => error_response(4, &e.message),
        },
        _ => error_response(3, &format!("Unknown Account operation: {}", op)),
    }
}

fn ok_response<T: Serialize>(payload: &T) -> Vec<u8> {
    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut payload_bytes)
        .expect("CBOR serialization of response payload");

    let envelope = ResponseEnvelope {
        v: 1,
        status: 0,
        error: None,
        payload: payload_bytes,
    };

    let mut out = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut out).expect("CBOR serialization of response envelope");
    out
}

fn error_response(status: i32, message: &str) -> Vec<u8> {
    let envelope = ResponseEnvelope {
        v: 1,
        status,
        error: Some(message.to_string()),
        payload: Vec::new(),
    };

    let mut out = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut out).expect("CBOR serialization of error envelope");
    out
}

/// Authenticate a TCP request using the auth field from the envelope.
/// Returns the authenticated user or an error response ready to send.
fn authenticate_tcp_request(
    auth: &Option<String>,
    db_pool: &DbPool,
) -> Result<linkkeys::db::models::User, Vec<u8>> {
    let api_key = match auth {
        Some(key) => key,
        None => return Err(error_response(5, "Authentication required")),
    };

    let authenticator = linkkeys::services::auth::ApiKeyAuthenticator::new(db_pool.clone());
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
        let mut data = Vec::new();
        for _ in 0..100 {
            data.push(0x81); // array of 1 element
        }
        data.push(0x00); // integer 0 at the bottom
        assert!(!check_cbor_depth(&data));
    }

    #[test]
    fn test_moderate_nesting_passes() {
        // 10 levels of nesting — well under the limit
        let mut data = Vec::new();
        for _ in 0..10 {
            data.push(0x81); // array of 1
        }
        data.push(0x00);
        assert!(check_cbor_depth(&data));
    }

    #[test]
    fn test_empty_input_passes() {
        assert!(check_cbor_depth(&[]));
    }

    #[test]
    fn test_deeply_nested_maps_rejected() {
        // 50 nested maps: each is major type 5, additional 1 (one-entry map)
        let mut data = Vec::new();
        for _ in 0..50 {
            data.push(0xa1); // map of 1 entry
            data.push(0x61); // text string of length 1
            data.push(b'k');  // key "k"
        }
        data.push(0x00); // value 0
        assert!(!check_cbor_depth(&data));
    }
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

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
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
