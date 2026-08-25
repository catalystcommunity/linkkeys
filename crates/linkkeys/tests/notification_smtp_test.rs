use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use linkkeys::services::notification::{
    EmailTransport, PreparedEmail, SmtpConfig, SmtpEmailTransport, SmtpSecurity, SmtpTlsBackend,
};

const SMTP_ENV: &[&str] = &[
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_SECURITY",
    "SMTP_TLS_BACKEND",
    "SMTP_ALLOW_PLAINTEXT",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_FROM",
    "SMTP_TIMEOUT_SECONDS",
    "PUBLIC_ORIGIN",
    "OUTBOX_ENCRYPTION_KEY",
    "OUTBOX_MAX_ATTEMPTS",
    "OUTBOX_LEASE_SECONDS",
    "OUTBOX_POLL_MILLISECONDS",
];

struct EnvironmentGuard(Vec<(&'static str, Option<String>)>);

impl EnvironmentGuard {
    fn clear() -> Self {
        let saved = SMTP_ENV
            .iter()
            .map(|name| (*name, std::env::var(name).ok()))
            .collect();
        for name in SMTP_ENV {
            std::env::remove_var(name);
        }
        Self(saved)
    }
}

impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn set_required_smtp_environment() {
    std::env::set_var("SMTP_HOST", "localhost");
    std::env::set_var("SMTP_FROM", "LinkKeys <linkkeys@example.test>");
    std::env::set_var("PUBLIC_ORIGIN", "https://id.example.test");
    std::env::set_var(
        "OUTBOX_ENCRYPTION_KEY",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
}

#[test]
fn smtp_configuration_is_disabled_by_default_and_rejects_unsafe_modes() {
    let _guard = EnvironmentGuard::clear();
    assert!(SmtpConfig::from_env().unwrap().is_none());

    set_required_smtp_environment();
    let config = SmtpConfig::from_env().unwrap().unwrap();
    assert_eq!(config.security, SmtpSecurity::StartTls);
    assert_eq!(config.tls_backend, SmtpTlsBackend::Rustls);
    assert_eq!(config.port, 587);

    std::env::set_var("SMTP_SECURITY", "plaintext");
    assert!(SmtpConfig::from_env()
        .unwrap_err()
        .contains("SMTP_ALLOW_PLAINTEXT"));
    std::env::set_var("SMTP_ALLOW_PLAINTEXT", "true");
    std::env::set_var("SMTP_HOST", "smtp.example.test");
    assert!(SmtpConfig::from_env().unwrap_err().contains("loopback"));

    std::env::set_var("SMTP_HOST", "127.0.0.1");
    assert_eq!(SmtpConfig::from_env().unwrap().unwrap().port, 25);
    std::env::set_var("SMTP_PORT", "0");
    assert!(SmtpConfig::from_env().unwrap_err().contains("1 to 65535"));
    std::env::remove_var("SMTP_PORT");

    std::env::set_var("SMTP_USERNAME", "linkkeys");
    assert!(SmtpConfig::from_env()
        .unwrap_err()
        .contains("must be set together"));
    std::env::remove_var("SMTP_USERNAME");

    std::env::set_var("SMTP_SECURITY", "starttls");
    std::env::set_var("SMTP_TLS_BACKEND", "native");
    #[cfg(not(feature = "smtp-native-tls"))]
    assert!(SmtpConfig::from_env()
        .unwrap_err()
        .contains("smtp-native-tls feature"));
    #[cfg(feature = "smtp-native-tls")]
    assert_eq!(
        SmtpConfig::from_env().unwrap().unwrap().tls_backend,
        SmtpTlsBackend::Native
    );

    std::env::set_var("SMTP_TLS_BACKEND", "rustls");
    std::env::set_var("PUBLIC_ORIGIN", "http://id.example.test/path");
    assert!(SmtpConfig::from_env().unwrap_err().contains("HTTPS origin"));
}

fn write_reply(stream: &mut TcpStream, reply: &str) {
    stream.write_all(reply.as_bytes()).unwrap();
    stream.flush().unwrap();
}

fn run_test_smtp(listener: TcpListener, delivered: mpsc::Sender<String>) {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write_reply(&mut stream, "220 localhost test SMTP\r\n");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut data = String::new();
    let mut receiving_data = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if receiving_data {
            if line == ".\r\n" {
                write_reply(&mut stream, "250 queued\r\n");
                delivered.send(data).unwrap();
                break;
            }
            data.push_str(&line);
        } else if line.starts_with("EHLO ") {
            write_reply(&mut stream, "250-localhost\r\n250 8BITMIME\r\n");
        } else if line.starts_with("MAIL FROM:") || line.starts_with("RCPT TO:") {
            write_reply(&mut stream, "250 ok\r\n");
        } else if line == "DATA\r\n" {
            receiving_data = true;
            write_reply(&mut stream, "354 end with dot\r\n");
        } else {
            write_reply(&mut stream, "250 ok\r\n");
        }
    }
}

#[test]
fn smtp_transport_hands_a_complete_message_to_a_local_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (delivered_tx, delivered_rx) = mpsc::channel();
    let server = std::thread::spawn(move || run_test_smtp(listener, delivered_tx));

    let config = SmtpConfig {
        host: "127.0.0.1".to_string(),
        port,
        security: SmtpSecurity::Plaintext,
        tls_backend: SmtpTlsBackend::Rustls,
        username: None,
        password: None,
        from: "LinkKeys <linkkeys@example.test>".to_string(),
        timeout: Duration::from_secs(5),
        public_origin: "https://id.example.test".to_string(),
        outbox_key: [7; 32],
        max_attempts: 3,
        lease_seconds: 30,
        poll_interval: Duration::from_millis(10),
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let transport = runtime
        .block_on(async { SmtpEmailTransport::new(&config) })
        .unwrap();
    runtime
        .block_on(transport.send(PreparedEmail {
            from: config.from,
            to: "person@example.test".to_string(),
            subject: "LinkKeys SMTP test".to_string(),
            body: "A complete test message.".to_string(),
        }))
        .unwrap();

    let message = delivered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(message.contains("Subject: LinkKeys SMTP test"));
    assert!(message.contains("A complete test message."));
    server.join().unwrap();
    runtime.block_on(async move {
        drop(transport);
        tokio::task::yield_now().await;
    });
}
