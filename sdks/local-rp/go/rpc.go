package localrp

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	rpctransport "github.com/catalystcommunity/csilgen/transports/go"
	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// CSIL-RPC over the injected Transport, TLS-pinned to a domain's DNS `fp=`
// records — this SDK's only network surface, per the design doc's "Required
// Network Access": domain public keys, revocations, and claim-ticket
// redemption, all unauthenticated-TLS TCP CSIL-RPC calls pinned the same way
// crates/linkkeys/src/tcp/tls.rs pins the S2S path.
//
// This deliberately does NOT use the csilgen-generated `go-client` typed
// client for this CSIL file: when written, that generator emitted
// Transport.Call invocations with a lowercased/re-cased name pair rather
// than the verbatim CSIL names the linkkeys TCP dispatch matches on
// ("DomainKeys"/"get-domain-keys" — see crates/linkkeys/src/tcp/mod.rs).
// That csilgen defect has since been fixed upstream; adopting go-client is
// now possible but optional. This package builds the CSIL-RPC request
// directly against
// github.com/catalystcommunity/csilgen/transports/go's RpcRequest/
// RpcResponse/StreamCarrier (the same pattern the Rust reference SDK uses in
// sdks/local-rp/rust/src/rpc.rs, which reimplements the frame send/receive
// directly rather than going through a generated/shared client for a
// different reason — permissive address policy — but ends up in the same
// place: hand-written request construction with literal, correct
// service/op strings, using only the generated types + codec).

// maxFrameSize mirrors the Rust SDK's own cap (rpc.rs's MAX_FRAME_SIZE), so
// a malicious/compromised peer cannot drive this client to an unbounded
// allocation via a forged length prefix.
const maxFrameSize = 1024 * 1024

// DomainEndpoint is a discovered endpoint for a domain: its pinned
// trust-anchor fingerprints (`_linkkeys`) and its CSIL-RPC TCP address
// (`_linkkeys_apis` `tcp=`).
type DomainEndpoint struct {
	Fingerprints []string
	TCPAddr      string
}

// DiscoverDomainEndpoint looks up a domain's trust anchor + TCP endpoint
// over DNS TXT. Fails closed: a missing/unparseable record, or a
// `_linkkeys` record with no fp= entries, or a `_linkkeys_apis` record with
// no tcp= entry, is an error — this SDK never proceeds without a
// fingerprint set to pin to.
func DiscoverDomainEndpoint(dns DnsResolver, domain string) (*DomainEndpoint, error) {
	anchorName := LinkKeysDNSName(domain)
	anchorTxts, err := dns.TxtLookup(anchorName)
	if err != nil {
		return nil, err
	}
	var fingerprints []string
	for _, txt := range anchorTxts {
		if rec, err := ParseLinkKeysTXT(txt); err == nil && len(rec.Fingerprints) > 0 {
			fingerprints = rec.Fingerprints
			break
		}
	}
	if len(fingerprints) == 0 {
		return nil, &DNSError{Detail: fmt.Sprintf("no usable %s TXT record with fp= entries", anchorName)}
	}

	apisName := LinkKeysApisDNSName(domain)
	apisTxts, err := dns.TxtLookup(apisName)
	if err != nil {
		return nil, err
	}
	var tcpAddr string
	for _, txt := range apisTxts {
		if apis, err := ParseLinkKeysApisTXT(txt); err == nil && apis.TCP != nil {
			tcpAddr = *apis.TCP
			break
		}
	}
	if tcpAddr == "" {
		return nil, &DNSError{Detail: fmt.Sprintf("no usable %s TXT record with tcp= entry", apisName)}
	}

	return &DomainEndpoint{Fingerprints: fingerprints, TCPAddr: tcpAddr}, nil
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
// crates/linkkeys/src/tcp/tls.rs computes (`fingerprint(spki.subject_public_key.data)`).
// Go's x509 parser already exposes the raw 32-byte Ed25519 SPKI content
// (unwrapped from its BIT STRING and ASN.1 framing) directly as
// `ed25519.PublicKey`, so no manual ASN.1 handling is needed here.
func certFingerprint(cert *x509.Certificate) (string, error) {
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", &TLSError{Detail: "peer certificate is not an Ed25519 key"}
	}
	return Fingerprint([]byte(pub)), nil
}

// dialTLS opens a TLS connection to endpoint, pinned to its fingerprints,
// using the injected Transport to dial the raw TCP socket. Certificate
// validity is verified manually (Go's InsecureSkipVerify disables the
// standard chain/hostname verification, which does not apply here — there
// is no CA chain, DNS `fp=` pinning is the entire trust anchor, exactly as
// crates/linkkeys-rpc-client's FingerprintVerifier documents).
func dialTLS(tr Transport, endpoint *DomainEndpoint) (*tls.Conn, error) {
	raw, err := tr.Dial(endpoint.TCPAddr)
	if err != nil {
		return nil, &TransportError{Detail: err.Error()}
	}
	hostname := extractHostname(endpoint.TCPAddr)
	fingerprints := endpoint.Fingerprints

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
			return &TLSError{Detail: fmt.Sprintf("certificate fingerprint %s does not match any pinned fingerprint for this domain", fp)}
		},
	}

	conn := tls.Client(raw, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, &TLSError{Detail: err.Error()}
	}
	return conn, nil
}

// call sends one CSIL-RPC request over a fresh TLS connection to endpoint
// and returns the decoded success payload. A non-Ok status becomes
// *ServerError.
func call(tr Transport, endpoint *DomainEndpoint, service, op string, payload []byte) ([]byte, error) {
	conn, err := dialTLS(tr, endpoint)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	carrier := rpctransport.NewStreamCarrierWithMaxFrame(conn, maxFrameSize)

	req := rpctransport.NewRpcRequest(service, op, payload)
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

// FetchDomainKeys fetches domain's currently-trusted public keys:
// `DomainKeys/get-domain-keys` over TCP CSIL-RPC, pinned to the domain's DNS
// `fp=` set, with signing keys pinned directly and encryption keys trusted
// only via a pinned signing key's vouch (TrustKeys). ALWAYS also fetches
// `DomainKeys/get-revocations` — regardless of the response's
// recent_revocations_available flag, which is merely a server-side
// optimization hint, never a trust decision this client may rely on (a
// compromised/malicious IDP could otherwise simply omit or clear that flag
// to suppress delivery of a revocation targeting one of its own keys) — and
// drops any key a quorum-verified sibling revocation certificate targets. A
// get-revocations fetch or decode failure is FATAL (fails the whole call,
// fail closed): revocation delivery is exactly the mechanism that lets a
// verifier learn a key it would otherwise trust has been compromised, so
// silently proceeding without it on error would defeat revocation
// entirely — an empty *list* is a legitimate, successful "nothing revoked"
// answer, but a failure to even ask is not. An empty final trusted result is
// *NoTrustedDomainKeysError — fail closed, matching the server's own
// posture.
func FetchDomainKeys(tr Transport, dns DnsResolver, domain string) ([]api.DomainPublicKey, error) {
	endpoint, err := DiscoverDomainEndpoint(dns, domain)
	if err != nil {
		return nil, err
	}

	payload := api.EncodeEmptyRequest(api.EmptyRequest{})
	respBytes, err := call(tr, endpoint, "DomainKeys", "get-domain-keys", payload)
	if err != nil {
		return nil, err
	}
	resp, err := api.DecodeGetDomainKeysResponse(respBytes)
	if err != nil {
		return nil, &DecodeError{Detail: "get-domain-keys response: " + err.Error()}
	}

	trusted := TrustKeys(resp.Keys, endpoint.Fingerprints)
	if len(trusted) == 0 {
		return nil, &NoTrustedDomainKeysError{Domain: domain}
	}

	since := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	revReqPayload := api.EncodeGetRevocationsRequest(api.GetRevocationsRequest{Since: &since})
	revRespBytes, err := call(tr, endpoint, "DomainKeys", "get-revocations", revReqPayload)
	if err != nil {
		return nil, err
	}
	revResp, err := api.DecodeGetRevocationsResponse(revRespBytes)
	if err != nil {
		return nil, &DecodeError{Detail: "get-revocations response: " + err.Error()}
	}
	for _, cert := range revResp.Revocations {
		if VerifyRevocationCertificate(cert, trusted, domain) == nil {
			trusted = removeKeyByID(trusted, cert.TargetKeyId)
		}
	}

	if len(trusted) == 0 {
		return nil, &NoTrustedDomainKeysError{Domain: domain}
	}
	return trusted, nil
}

func removeKeyByID(keys []api.DomainPublicKey, keyID string) []api.DomainPublicKey {
	out := make([]api.DomainPublicKey, 0, len(keys))
	for _, k := range keys {
		if k.KeyId != keyID {
			out = append(out, k)
		}
	}
	return out
}

// RedeemClaimTicket redeems a claim ticket with domain's IDP:
// `LocalRp/redeem-claim-ticket` over TCP CSIL-RPC, pinned via the domain's
// DNS `fp=` set. Unauthenticated at the transport layer (no client cert) —
// the redemption request itself is signed with the local RP's signing key,
// which is the possession proof the server checks.
func RedeemClaimTicket(tr Transport, dns DnsResolver, domain string, signedRequest api.SignedLocalRpTicketRedemptionRequest) (*api.LocalRpTicketRedemptionResponse, error) {
	endpoint, err := DiscoverDomainEndpoint(dns, domain)
	if err != nil {
		return nil, err
	}
	payload := api.EncodeSignedLocalRpTicketRedemptionRequest(signedRequest)
	respBytes, err := call(tr, endpoint, "LocalRp", "redeem-claim-ticket", payload)
	if err != nil {
		return nil, err
	}
	resp, err := api.DecodeLocalRpTicketRedemptionResponse(respBytes)
	if err != nil {
		return nil, &DecodeError{Detail: "redeem-claim-ticket response: " + err.Error()}
	}
	return &resp, nil
}
