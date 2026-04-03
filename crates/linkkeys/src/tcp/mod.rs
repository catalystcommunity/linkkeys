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
}

impl TcpServer {
    pub fn new(ready_flag: Arc<AtomicBool>, db_pool: DbPool) -> std::io::Result<Self> {
        let port: u16 = env::var("TCP_PORT")
            .unwrap_or_else(|_| "4987".to_string())
            .parse()
            .unwrap_or(4987);

        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
        log::info!("TCP server listening on port {}", port);

        let pool_size = num_cpus::get() * 2;
        let thread_pool = ThreadPool::new(pool_size);

        Ok(TcpServer { listener, thread_pool, ready_flag, db_pool })
    }

    pub fn run(self) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let ready_flag = self.ready_flag.clone();
                    let db_pool = self.db_pool.clone();
                    self.thread_pool.execute(move || {
                        if let Err(e) = handle_connection(stream, ready_flag, &db_pool) {
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

fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
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

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
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
    mut stream: TcpStream,
    ready_flag: Arc<AtomicBool>,
    db_pool: &DbPool,
) -> std::io::Result<()> {
    log::debug!("New TCP connection from: {:?}", stream.peer_addr());
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;
    stream.set_nodelay(true)?;

    loop {
        let frame = read_frame(&mut stream)?;

        let envelope: RequestEnvelope = match ciborium::de::from_reader(&frame[..]) {
            Ok(env) => env,
            Err(e) => {
                let resp = error_response(1, &format!("Invalid request envelope: {}", e));
                write_frame(&mut stream, &resp)?;
                continue;
            }
        };

        let response = dispatch(&envelope, &ready_flag, db_pool);
        write_frame(&mut stream, &response)?;
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
        _ => error_response(
            3,
            &format!("Unknown service/operation: {}/{}", envelope.service, envelope.op),
        ),
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

mod serde_bytes {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
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
