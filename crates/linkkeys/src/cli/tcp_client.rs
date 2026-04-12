use std::io::{Read, Write};
use std::net::TcpStream;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum ClientError {
    Connection(String),
    Protocol(String),
    ServerError { status: i32, message: String },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Connection(msg) => write!(f, "connection error: {}", msg),
            ClientError::Protocol(msg) => write!(f, "protocol error: {}", msg),
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

/// Send a request to a LinkKeys server and return the response payload.
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

    let mut stream = TcpStream::connect(server)
        .map_err(|e| ClientError::Connection(format!("{}: {}", server, e)))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| ClientError::Connection(e.to_string()))?;

    // Send frame: 4-byte big-endian length prefix + CBOR bytes
    let mut envelope_bytes = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut envelope_bytes)
        .map_err(|e| ClientError::Protocol(format!("CBOR encode envelope: {}", e)))?;
    let len = (envelope_bytes.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    stream
        .write_all(&envelope_bytes)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| ClientError::Connection(e.to_string()))?;

    // Read response frame
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| ClientError::Connection(e.to_string()))?;

    let resp_envelope: ResponseEnvelope = ciborium::de::from_reader(resp_buf.as_slice())
        .map_err(|e| ClientError::Protocol(format!("CBOR decode response: {}", e)))?;

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
