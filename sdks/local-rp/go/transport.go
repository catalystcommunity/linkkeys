package localrp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// The TCP dial seam. Mirrors sdks/local-rp/rust/src/transport.rs.
//
// dns-less-local-rp-design.md's "SDK API Shape" / "Required Network Access"
// sections ask for a Transport seam the SDK embeds its CSIL-RPC calls over,
// with a default implementation and the whole thing injectable for tests.
// Deliberately narrow: Transport only *connects a byte stream* to
// `host:port`. TLS (certificate-pin verification against DNS `fp=` records)
// is layered on top in rpc.go, not here, so a test double can swap out "how
// do I open a socket" without also having to fake a TLS handshake.
//
// Wire Precision is explicit that this package must NOT inherit
// `linkkeys-rpc-client`'s non-public-address refusal as a *default*: that
// refusal is a server-side SSRF guard, and "connecting from a LAN box to
// wherever `_linkkeys_apis` points is the entire point of this mode." The
// default policy here is AddressPolicyPermissive. AddressPolicyPublicOnly is
// offered as an opt-in for integrators who specifically want that stricter
// posture, but nothing in this package selects it automatically.

// Transport dials host:port and returns a byte stream (a net.Conn is used
// directly since it already satisfies io.Reader/io.Writer/io.Closer —
// exactly what TLS wrapping needs). Injectable so tests can hand the RPC
// layer a loopback socket instead of relying on real DNS-driven addressing.
type Transport interface {
	Dial(hostPort string) (net.Conn, error)
}

// AddressPolicy controls which destination addresses StdTransport is
// willing to dial. Default is AddressPolicyPermissive — see the package
// docs for why.
type AddressPolicy int

const (
	// AddressPolicyPermissive dials anything the OS resolver returns.
	// Correct default for this mode: a LAN/loopback local RP talking to its
	// LinkKeys domain's published `_linkkeys_apis` `tcp=` endpoint is
	// routinely a private address.
	AddressPolicyPermissive AddressPolicy = iota
	// AddressPolicyPublicOnly refuses loopback/private/link-local/CGNAT/ULA/
	// documentation and unspecified addresses, mirroring (not sharing code
	// with) the server-side SSRF guard. Opt-in only.
	AddressPolicyPublicOnly
)

// StdTransport is the default Transport: a plain blocking net.Dialer, gated
// only by Policy (permissive unless the caller opts into
// AddressPolicyPublicOnly).
type StdTransport struct {
	Policy         AddressPolicy
	ConnectTimeout time.Duration
	// IOTimeout is applied as a fresh deadline before every subsequent
	// Read/Write on the dialed connection, so a slow/blackholed peer can't
	// hang an RPC call indefinitely.
	IOTimeout time.Duration
}

// NewStdTransport builds the default transport: permissive address policy,
// 10s connect timeout, 30s per-operation I/O timeout.
func NewStdTransport() *StdTransport {
	return &StdTransport{
		Policy:         AddressPolicyPermissive,
		ConnectTimeout: 10 * time.Second,
		IOTimeout:      30 * time.Second,
	}
}

func (t *StdTransport) Dial(hostPort string) (net.Conn, error) {
	if t.Policy == AddressPolicyPublicOnly {
		host, _, err := net.SplitHostPort(hostPort)
		if err != nil {
			return nil, &TransportError{Detail: fmt.Sprintf("%s: %s", hostPort, err.Error())}
		}
		ctx, cancel := context.WithTimeout(context.Background(), t.connectTimeoutOrDefault())
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		cancel()
		if err != nil {
			return nil, &TransportError{Detail: fmt.Sprintf("%s: resolve failed: %s", hostPort, err.Error())}
		}
		for _, addr := range addrs {
			if isNonPublicIP(addr.IP) {
				return nil, &TransportError{Detail: fmt.Sprintf("%s: refusing non-public address under AddressPolicyPublicOnly", addr.IP)}
			}
		}
	}

	d := net.Dialer{Timeout: t.connectTimeoutOrDefault()}
	conn, err := d.Dial("tcp", hostPort)
	if err != nil {
		return nil, &TransportError{Detail: fmt.Sprintf("%s: %s", hostPort, err.Error())}
	}
	return &timeoutConn{Conn: conn, timeout: t.ioTimeoutOrDefault()}, nil
}

func (t *StdTransport) connectTimeoutOrDefault() time.Duration {
	if t.ConnectTimeout > 0 {
		return t.ConnectTimeout
	}
	return 10 * time.Second
}

func (t *StdTransport) ioTimeoutOrDefault() time.Duration {
	if t.IOTimeout > 0 {
		return t.IOTimeout
	}
	return 30 * time.Second
}

// timeoutConn wraps a net.Conn so every Read/Write refreshes a deadline
// `timeout` in the future — matching the per-call semantics of
// TcpStream::set_read_timeout/set_write_timeout in the Rust SDK, rather than
// a single absolute deadline from connect time.
type timeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(b)
}

func (c *timeoutConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(b)
}

var nonPublicV4CIDRs, nonPublicV6CIDRs = mustParseCIDRs(
	[]string{
		"192.0.2.0/24",    // documentation (TEST-NET-1)
		"198.51.100.0/24", // documentation (TEST-NET-2)
		"203.0.113.0/24",  // documentation (TEST-NET-3)
		"100.64.0.0/10",   // CGNAT
	},
	[]string{
		"fc00::/7", // ULA
	},
)

func mustParseCIDRs(v4, v6 []string) ([]*net.IPNet, []*net.IPNet) {
	parse := func(cidrs []string) []*net.IPNet {
		out := make([]*net.IPNet, 0, len(cidrs))
		for _, c := range cidrs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				panic("localrp: invalid built-in CIDR " + c + ": " + err.Error())
			}
			out = append(out, n)
		}
		return out
	}
	return parse(v4), parse(v6)
}

// isNonPublicIP reports whether ip is loopback/private/link-local/CGNAT/
// documentation/ULA/unspecified/multicast — the same address classes the
// server-side SSRF guard rejects. Only consulted under
// AddressPolicyPublicOnly, never by default.
func isNonPublicIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		if v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalUnicast() || v4.IsUnspecified() {
			return true
		}
		if v4.Equal(net.IPv4bcast) {
			return true
		}
		for _, n := range nonPublicV4CIDRs {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, n := range nonPublicV6CIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

var (
	defaultTransportOnce sync.Once
	defaultTransportInst Transport
)

// DefaultTransport is the memoized default Transport for the process
// lifetime.
func DefaultTransport() Transport {
	defaultTransportOnce.Do(func() { defaultTransportInst = NewStdTransport() })
	return defaultTransportInst
}
