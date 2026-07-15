//! The TCP dial seam.
//!
//! `dns-less-local-rp-design.md`'s "SDK API Shape" / "Required Network
//! Access" sections ask for a `Transport` seam the SDK embeds its CSIL-RPC
//! client over, with a default implementation and the whole thing injectable
//! for tests. Deliberately narrow: this trait only *connects a byte stream*
//! to `host:port`. TLS (certificate-pin verification against DNS `fp=`
//! records) is layered on top in `src/rpc.rs`, not here, so a test double can
//! swap out "how do I open a socket" without also having to fake a TLS
//! handshake.
//!
//! Wire Precision is explicit that this crate must NOT inherit
//! `linkkeys-rpc-client`'s non-public-address refusal as a *default*: that
//! refusal is a server-side SSRF guard, and "connecting from a LAN box to
//! wherever `_linkkeys_apis` points is the entire point of this mode." The
//! default policy here is [`AddressPolicy::Permissive`]. [`AddressPolicy::PublicOnly`]
//! is offered as an opt-in for integrators who specifically want that
//! stricter posture (e.g. a local app that itself runs multi-tenant and
//! wants to reduce its own SSRF surface), but nothing in this crate selects
//! it automatically.

use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// A dialed connection: anything that can be read from and written to. TLS
/// (`rustls::StreamOwned`) wraps this directly, so implementations need not
/// know anything about the LinkKeys protocol.
pub trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

#[derive(Debug)]
pub enum TransportError {
    /// The address was resolved but the connect attempt(s) failed.
    Connect(String),
    /// The address policy refused every candidate address before a connect
    /// was even attempted (see [`AddressPolicy::PublicOnly`]).
    Denied(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Connect(msg) => write!(f, "connect failed: {msg}"),
            TransportError::Denied(msg) => write!(f, "address policy denied connection: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Which destination addresses [`StdTransport`] is willing to dial.
/// **Default is [`AddressPolicy::Permissive`]** — see the module docs for why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressPolicy {
    /// Dial anything the OS resolver returns. Correct default for this mode:
    /// a LAN/loopback local RP talking to its LinkKeys domain's published
    /// `_linkkeys_apis` `tcp=` endpoint is routinely a private address.
    #[default]
    Permissive,
    /// Refuse loopback/private/link-local/CGNAT/ULA/documentation and
    /// unspecified addresses, mirroring (not reusing — see module docs)
    /// `linkkeys-rpc-client`'s server-side SSRF guard. Opt-in only.
    PublicOnly,
}

/// Dials `host:port` and returns a byte stream. Injectable so tests can hand
/// the RPC layer an in-memory duplex pipe instead of a real socket.
pub trait Transport: Send + Sync {
    fn dial(&self, host_port: &str) -> Result<Box<dyn ReadWrite>, TransportError>;
}

/// Default [`Transport`]: a plain blocking `std::net::TcpStream`, gated only
/// by `policy` (permissive unless the caller opts into [`AddressPolicy::PublicOnly`]).
#[derive(Debug, Clone)]
pub struct StdTransport {
    pub policy: AddressPolicy,
    pub connect_timeout: Duration,
    /// Applied to the connected socket as both the read and write timeout
    /// (`TcpStream::set_read_timeout`/`set_write_timeout`), so a
    /// slow/blackholed peer can't hang an RPC call indefinitely.
    pub io_timeout: Duration,
}

impl Default for StdTransport {
    fn default() -> Self {
        Self {
            policy: AddressPolicy::Permissive,
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
        }
    }
}

impl StdTransport {
    pub fn new(policy: AddressPolicy) -> Self {
        Self {
            policy,
            ..Default::default()
        }
    }
}

impl Transport for StdTransport {
    fn dial(&self, host_port: &str) -> Result<Box<dyn ReadWrite>, TransportError> {
        let addrs = host_port
            .to_socket_addrs()
            .map_err(|e| TransportError::Connect(format!("{host_port}: resolve failed: {e}")))?;

        let mut last_err: Option<TransportError> = None;
        for addr in addrs {
            if self.policy == AddressPolicy::PublicOnly && is_non_public(addr.ip()) {
                last_err = Some(TransportError::Denied(format!(
                    "{}: refusing non-public address under AddressPolicy::PublicOnly",
                    addr.ip()
                )));
                continue;
            }
            match TcpStream::connect_timeout(&addr, self.connect_timeout) {
                Ok(stream) => {
                    // Best-effort: these only fail on a platform that can't
                    // support socket timeouts at all, which would break the
                    // connection anyway.
                    let _ = stream.set_read_timeout(Some(self.io_timeout));
                    let _ = stream.set_write_timeout(Some(self.io_timeout));
                    return Ok(Box::new(stream));
                }
                Err(e) => last_err = Some(TransportError::Connect(format!("{host_port}: {e}"))),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            TransportError::Connect(format!("{host_port}: no address resolved"))
        }))
    }
}

/// True for loopback/private/link-local/CGNAT/documentation/unspecified
/// addresses. Only consulted under [`AddressPolicy::PublicOnly`], never by
/// default. Intentionally a small, self-contained check (not shared code
/// with `linkkeys-rpc-client`'s private equivalent) — see module docs for why
/// this crate does not depend on that crate's guard.
fn is_non_public(ip: IpAddr) -> bool {
    fn v4_non_public(v4: std::net::Ipv4Addr) -> bool {
        let o = v4.octets();
        v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || v4.is_unspecified()
            || v4.is_broadcast()
            || v4.is_documentation()
            || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // CGNAT 100.64.0.0/10
    }
    match ip {
        IpAddr::V4(v4) => v4_non_public(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || v6.to_ipv4_mapped().map(v4_non_public).unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_only_policy_flags_private_and_allows_public() {
        let priv_ips = [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.5",
            "169.254.169.254",
            "::1",
            "fe80::1",
        ];
        for s in priv_ips {
            assert!(
                is_non_public(s.parse().unwrap()),
                "{s} should be non-public"
            );
        }
        let pub_ips = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"];
        for s in pub_ips {
            assert!(!is_non_public(s.parse().unwrap()), "{s} should be public");
        }
    }

    #[test]
    fn default_policy_is_permissive() {
        assert_eq!(StdTransport::default().policy, AddressPolicy::Permissive);
    }
}
