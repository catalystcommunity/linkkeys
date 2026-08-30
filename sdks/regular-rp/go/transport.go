package regularrp

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	rpctransport "github.com/catalystcommunity/csilgen/transports/go"
	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// CSIL-RPC over TCP, TLS-pinned to the application's own RP server, with the
// application API key carried in the RPC envelope's `auth` field — this
// package's only network surface. Mirrors
// sdks/regular-rp/typescript/src/rpc.ts's `PinnedRpcTransport` /
// sdks/local-rp/go/rpc.go's `dialTLS`/`call`, adapted to satisfy the
// go-client-generated `api.Transport` interface
// (`Call(ctx, service, op, payload) ([]byte, error)`) so this package can
// use api.NewRpClient(transport) directly rather than hand-rolling per-op
// request construction.
//
// Unlike sdks/local-rp/go (which discovers an arbitrary domain's endpoint
// over DNS), this transport talks to ONE pre-configured RP: the
// application's own, per docs/application-keys.md's Operations table
// ("Rp/resolve-application-keys ... The API key of the application"). There
// is no DNS discovery step and no permissive-vs-public-only address policy
// to choose — the application already knows how to reach its own RP.

// maxFrameSize mirrors the Rust and TypeScript SDKs' own cap, so a
// malicious/compromised peer cannot drive this client to an unbounded
// allocation via a forged length prefix.
const maxFrameSize = 1024 * 1024

const defaultRequestTimeout = 15 * time.Second

// PinnedRpcTransportOptions configures a PinnedRpcTransport for one
// configured RP server.
type PinnedRpcTransportOptions struct {
	// TCPAddress is the RP's CSIL-RPC TCP endpoint ("host:port").
	TCPAddress string
	// Fingerprints is the pinned set of acceptable SHA-256 hex
	// fingerprints of the RP's TLS certificate's raw Ed25519
	// SubjectPublicKeyInfo. LinkKeys domain certificates are self-signed
	// — there is no CA to validate against by design; this pin IS the
	// trust anchor, exactly as crates/linkkeys/src/tcp/tls.rs pins the
	// server-to-server path.
	Fingerprints []string
	// APIKey is the application's RP API key, carried in the RPC
	// envelope's `auth` field. Required.
	APIKey string
	// RequestTimeout bounds one complete RPC: TCP connect, TLS
	// negotiation, request write, and response read. Defaults to 15s.
	RequestTimeout time.Duration
	// Dial overrides how the raw TCP connection is opened (tests inject
	// a loopback dialer here). Defaults to (&net.Dialer{}).DialContext.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// PinnedRpcTransport is a generated-client api.Transport for one configured
// LinkKeys RP server.
type PinnedRpcTransport struct {
	opts PinnedRpcTransportOptions
}

// NewPinnedRpcTransport validates opts and builds a PinnedRpcTransport.
func NewPinnedRpcTransport(opts PinnedRpcTransportOptions) (*PinnedRpcTransport, error) {
	if opts.APIKey == "" {
		return nil, &ProtocolError{Detail: "the RP API key must not be empty"}
	}
	if opts.TCPAddress == "" {
		return nil, &ProtocolError{Detail: "the RP TCP address must not be empty"}
	}
	if len(opts.Fingerprints) == 0 {
		return nil, &ProtocolError{Detail: "the RP fingerprint set must not be empty"}
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = defaultRequestTimeout
	}
	if opts.Dial == nil {
		var d net.Dialer
		opts.Dial = d.DialContext
	}
	return &PinnedRpcTransport{opts: opts}, nil
}

var _ api.Transport = (*PinnedRpcTransport)(nil)

// Call implements api.Transport: one CSIL-RPC request over a fresh
// pinned-TLS connection. A non-Ok status becomes *ServerError.
func (t *PinnedRpcTransport) Call(ctx context.Context, service, op string, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, t.opts.RequestTimeout)
	defer cancel()

	conn, err := t.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	carrier := rpctransport.NewStreamCarrierWithMaxFrame(conn, maxFrameSize)

	req := rpctransport.NewRpcRequest(service, op, payload).WithAuth(t.opts.APIKey)
	encoded, err := req.Encode()
	if err != nil {
		return nil, &ProtocolError{Detail: fmt.Sprintf("encode request: %v", err)}
	}
	if err := carrier.SendFrame(encoded); err != nil {
		return nil, &TransportError{Detail: err.Error()}
	}

	respBytes, err := carrier.RecvFrame()
	if err != nil {
		return nil, &TransportError{Detail: err.Error()}
	}
	if respBytes == nil {
		return nil, &TransportError{Detail: "connection closed before response"}
	}

	resp, err := rpctransport.DecodeRpcResponse(respBytes)
	if err != nil {
		return nil, &ProtocolError{Detail: fmt.Sprintf("decode response: %v", err)}
	}
	if !resp.Status.IsOk() {
		msg := ""
		if resp.Error != nil {
			msg = *resp.Error
		}
		return nil, &ServerError{Status: resp.Status.Code(), Message: msg}
	}
	return resp.Payload, nil
}

func (t *PinnedRpcTransport) dialTLS(ctx context.Context) (*tls.Conn, error) {
	raw, err := t.opts.Dial(ctx, "tcp", t.opts.TCPAddress)
	if err != nil {
		return nil, &TransportError{Detail: err.Error()}
	}
	hostname := extractHostname(t.opts.TCPAddress)
	fingerprints := t.opts.Fingerprints

	cfg := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, // pinned verification below replaces WebPKI chain validation
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return &TLSError{Detail: "no peer certificate presented"}
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return &TLSError{Detail: "bad certificate encoding: " + err.Error()}
			}
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return &TLSError{Detail: "certificate is not within its validity period"}
			}
			fp, err := certFingerprint(cert)
			if err != nil {
				return err
			}
			for _, want := range fingerprints {
				if fp == want {
					return nil
				}
			}
			return &TLSError{Detail: fmt.Sprintf("certificate fingerprint %s does not match any pinned fingerprint for this RP", fp)}
		},
	}

	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, &TLSError{Detail: err.Error()}
	}
	return conn, nil
}

// extractHostname recovers the bare hostname from a `host:port` (or
// `[ipv6]:port`) string, for use as the TLS ServerName.
func extractHostname(hostPort string) string {
	if strings.HasPrefix(hostPort, "[") {
		if end := strings.Index(hostPort, "]"); end != -1 {
			return hostPort[1:end]
		}
	}
	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		return hostPort[:idx]
	}
	return hostPort
}

// certFingerprint computes the SHA-256 hex fingerprint of a certificate's
// SubjectPublicKeyInfo raw Ed25519 public key bytes — exactly the pin
// crates/linkkeys/src/tcp/tls.rs computes.
func certFingerprint(cert *x509.Certificate) (string, error) {
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", &TLSError{Detail: "peer certificate is not an Ed25519 key"}
	}
	return Fingerprint([]byte(pub)), nil
}
