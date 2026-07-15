package localrp_test

// Flow tests: CompleteLocalLogin's full verification chain, end to end,
// against a real (but locally spun up, fake-identity) LinkKeys IDP —
// DNS-pinned TLS, CSIL-RPC framing, and all. Only two things are faked: the
// DNS TXT answers (fakeDNSResolver, so no real network/DNS is touched) and
// the IDP's identity itself (a throwaway domain signing key generated per
// test, not a real LinkKeys deployment). The Transport seam is also
// exercised via a small custom impl (testTransport) rather than the
// package's default, demonstrating the seam is genuinely injectable — the
// TLS handshake, certificate-pinning, and RPC wire format underneath it are
// all the SDK's real production code paths. Mirrors
// sdks/local-rp/rust/tests/flow.rs.
//
// Canned callback/ticket-redemption/domain-keys responses are built with
// this package directly (the same package app code uses), using the same
// fixed, publicly-known test key seeds as sdks/local-rp/conformance/keys.json
// (local_rp.signing = 0x01 repeated, local_rp.encryption = 0x02 repeated,
// domain_signing_key = 0x03 repeated) so this test suite and the
// conformance vectors describe the same identities.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	rpctransport "github.com/catalystcommunity/csilgen/transports/go"
	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// Same fixed seeds as sdks/local-rp/conformance/keys.json.
var (
	localRPSigningSeed        = [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	localRPEncryptionPrivate  = [32]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	domainSigningSeedFlowTest = [32]byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3}
	// domainSigningSeedSiblingB/C are two additional, distinct domain
	// signing keys used only by TestCertificateRevokedSigningKeyIsRejected
	// to build a quorum (RevocationQuorum = 2) of sibling signatures over a
	// revocation certificate targeting domainSigningSeedFlowTest's key —
	// not part of the fixed conformance-vector key set, since no
	// conformance vector needs a multi-signing-key domain.
	domainSigningSeedSiblingB = [32]byte{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4}
	domainSigningSeedSiblingC = [32]byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}
)

const (
	domainKeyIDFlowTest         = "test-domain-key-1"
	domainKeyIDSiblingBFlowTest = "test-domain-key-sibling-b"
	domainKeyIDSiblingCFlowTest = "test-domain-key-sibling-c"
	userDomainFlowTest          = "example.test"
	callbackURLFlowTest         = "http://localhost/callback"
)

// ---------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------

// testTransport is a Transport the test provides itself (rather than the
// package's default StdTransport), proving the seam is genuinely
// injectable. It still dials a real loopback socket — only the DNS answer
// steering it there is faked.
type testTransport struct{}

func (testTransport) Dial(hostPort string) (net.Conn, error) {
	return net.Dial("tcp", hostPort)
}

// fakeDNSResolver has canned DNS answers for exactly one domain.
type fakeDNSResolver struct {
	linkkeysTXT string
	apisTXT     string
}

func (f *fakeDNSResolver) TxtLookup(name string) ([]string, error) {
	switch name {
	case "_linkkeys." + userDomainFlowTest:
		return []string{f.linkkeysTXT}, nil
	case "_linkkeys_apis." + userDomainFlowTest:
		return []string{f.apisTXT}, nil
	default:
		return nil, fmt.Errorf("no fake record for %s", name)
	}
}

// ---------------------------------------------------------------------
// Fake IDP: a real TCP+TLS(fp-pinned)+CSIL-RPC server for exactly N requests
// ---------------------------------------------------------------------

// generateDomainTLSCert builds a self-signed TLS certificate whose subject
// key IS the Ed25519 key derived from seed, so its SPKI fingerprint is
// exactly what a test's DNS answer pins to (crypto/x509 exposes an Ed25519
// SPKI's raw public key bytes directly via Certificate.PublicKey, matching
// what crates/linkkeys/src/tcp/tls.rs / this package's certFingerprint
// compute).
func generateDomainTLSCert(domain string, seed [32]byte) (tls.Certificate, error) {
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: priv}, nil
}

const fakeIDPMaxFrame = 1024 * 1024

// spawnFakeIDP spawns a background goroutine that accepts expectedRequests
// TLS connections on a fresh loopback port, presenting a certificate
// derived from domainSeed (so its SPKI fingerprint is whatever the test's
// DNS answer pins to), and answers each with
// dispatch(service, op, payload). drop, when non-nil, is consulted after
// decoding each request: if it returns true, the connection is closed
// WITHOUT sending any response — a deterministic, non-racy way to simulate a
// hostile IDP that accepts a connection then drops it mid-conversation
// (distinct from simply under-provisioning expectedRequests, which races the
// listener's own close against the client's next dial). Returns the bound
// address. Any connection that never completes its TLS handshake (the "bad
// pin" test) simply causes that iteration to error out and move on — never
// a hang, since the loop only ever waits on Accept, not on a specific peer
// completing a handshake.
func spawnFakeIDP(t *testing.T, domainSeed [32]byte, expectedRequests int, drop func(service, op string) bool, dispatch func(service, op string, payload []byte) rpctransport.RpcResponse) string {
	t.Helper()
	cert, err := generateDomainTLSCert(userDomainFlowTest, domainSeed)
	if err != nil {
		t.Fatalf("generate fake IDP TLS cert: %v", err)
	}
	serverConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind fake IDP listener: %v", err)
	}

	go func() {
		defer ln.Close()
		for i := 0; i < expectedRequests; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func() {
				tlsConn := tls.Server(conn, serverConfig)
				defer tlsConn.Close()

				carrier := rpctransport.NewStreamCarrierWithMaxFrame(tlsConn, fakeIDPMaxFrame)
				frame, err := carrier.RecvFrame()
				if err != nil || frame == nil {
					return
				}
				req, err := rpctransport.DecodeRpcRequest(frame)
				if err != nil {
					return
				}
				if drop != nil && drop(req.Service, req.Op) {
					return // simulate a hostile IDP dropping the connection mid-conversation
				}
				resp := dispatch(req.Service, req.Op, req.Payload)
				encoded, err := resp.Encode()
				if err != nil {
					return
				}
				_ = carrier.SendFrame(encoded)
			}()
		}
	}()

	return ln.Addr().String()
}

// ---------------------------------------------------------------------
// Scenario construction
// ---------------------------------------------------------------------

func fixedKeyMaterial(t *testing.T, now time.Time) *localrp.LocalRpKeyMaterial {
	t.Helper()
	signingPriv := ed25519.NewKeyFromSeed(localRPSigningSeed[:])
	var signingPub [32]byte
	copy(signingPub[:], signingPriv.Public().(ed25519.PublicKey))

	x25519Priv, err := ecdh.X25519().NewPrivateKey(localRPEncryptionPrivate[:])
	if err != nil {
		t.Fatalf("x25519 private key: %v", err)
	}
	var encPub [32]byte
	copy(encPub[:], x25519Priv.PublicKey().Bytes())

	createdAt := now.Add(-24 * time.Hour).UTC().Format(time.RFC3339Nano)
	expiresAt := now.Add(3650 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)

	descriptor := localrp.BuildLocalRpDescriptor("Flow Test App", nil, signingPub, encPub, []string{"aes-256-gcm", "chacha20-poly1305"}, createdAt, expiresAt)
	fingerprint := descriptor.Fingerprint
	signedDescriptor := localrp.SignLocalRpDescriptor(descriptor, localRPSigningSeed)

	return &localrp.LocalRpKeyMaterial{
		SigningPrivateKey:    localRPSigningSeed,
		SigningPublicKey:     signingPub,
		EncryptionPrivateKey: localRPEncryptionPrivate,
		EncryptionPublicKey:  encPub,
		Descriptor:           signedDescriptor,
		Fingerprint:          fingerprint,
	}
}

// domainSigningKeyWithSeed builds a currently-valid api.DomainPublicKey for
// an arbitrary signing seed/key id — the general form
// domainPublicKeyFlowTest wraps for the scenario's primary domain key, and
// TestCertificateRevokedSigningKeyIsRejected uses directly to build sibling
// keys. created_at/expires_at are relative to the real wall clock (not a
// scenario's `now`) since signingKeyValidity always checks against
// time.Now(), never an injected time.
func domainSigningKeyWithSeed(seed [32]byte, keyID string) api.DomainPublicKey {
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return api.DomainPublicKey{
		KeyId:       keyID,
		PublicKey:   []byte(pub),
		Fingerprint: localrp.Fingerprint([]byte(pub)),
		Algorithm:   "ed25519",
		KeyUsage:    "sign",
		CreatedAt:   time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano),
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339Nano),
	}
}

func domainPublicKeyFlowTest() api.DomainPublicKey {
	return domainSigningKeyWithSeed(domainSigningSeedFlowTest, domainKeyIDFlowTest)
}

// scenario is every knob a failure-case test can turn, applied in this
// order: build the correct payload/domain key/claim/redemption, then apply
// these mutators, then sign + seal + serve. Defaults are all no-ops (the
// happy path).
type scenario struct {
	mutatePayload    func(*api.LocalRpCallbackPayload)
	mutateDomainKey  func(*api.DomainPublicKey)
	mutateClaim      func(*api.Claim)
	mutateRedemption func(*api.LocalRpTicketRedemptionResponse)
	// requiredClaims overrides begin_local_login's required_claims. nil
	// keeps the package default (DefaultRequiredClaims, i.e. ["handle"]).
	requiredClaims []string
	// extraDomainKeys are additional signing keys served alongside the
	// primary domain key in get-domain-keys, and pinned via additional DNS
	// fp= entries — used to build a sibling quorum for a revocation
	// certificate.
	extraDomainKeys []api.DomainPublicKey
	// revocations is served verbatim from get-revocations, unless
	// revocationsRPCFails or revocationsGarbage override it.
	revocations         []api.RevocationCertificate
	revocationsRPCFails bool
	revocationsGarbage  bool
	// dropOp, when non-nil, names a (service, op) pair whose connection the
	// fake IDP accepts, reads, and then drops without ever responding —
	// simulating a hostile IDP that cuts the connection mid-conversation.
	dropOp                 func(service, op string) bool
	dnsFingerprintOverride *string
	expectedRequests       int
}

func defaultScenario() scenario {
	noOpPayload := func(*api.LocalRpCallbackPayload) {}
	noOpKey := func(*api.DomainPublicKey) {}
	noOpClaim := func(*api.Claim) {}
	noOpRedemption := func(*api.LocalRpTicketRedemptionResponse) {}
	return scenario{
		mutatePayload:    noOpPayload,
		mutateDomainKey:  noOpKey,
		mutateClaim:      noOpClaim,
		mutateRedemption: noOpRedemption,
		// get-domain-keys + get-revocations (always fetched, FIX B) +
		// redeem-claim-ticket.
		expectedRequests: 3,
	}
}

func runScenario(t *testing.T, sc scenario) (*localrp.VerifiedLocalLogin, error) {
	t.Helper()
	now := time.Now()
	keyMaterial := fixedKeyMaterial(t, now)

	_, pending, err := localrp.BeginLocalLogin(localrp.BeginLocalLoginConfig{
		KeyMaterial:    keyMaterial,
		CallbackURL:    callbackURLFlowTest,
		UserDomain:     userDomainFlowTest,
		RequiredClaims: sc.requiredClaims,
		Now:            now,
	})
	if err != nil {
		t.Fatalf("begin_local_login: %v", err)
	}

	domainKey := domainPublicKeyFlowTest()
	sc.mutateDomainKey(&domainKey)

	claimTicket := bytes.Repeat([]byte{7}, 32)
	payload := localrp.BuildLocalRpCallbackPayload(
		"user-1", userDomainFlowTest, claimTicket, keyMaterial.Fingerprint, callbackURLFlowTest,
		pending.Nonce, pending.State,
		now.UTC().Format(time.RFC3339Nano), now.Add(5*time.Minute).UTC().Format(time.RFC3339Nano),
	)
	sc.mutatePayload(&payload)

	signedPayload := localrp.SignLocalRpCallbackPayload(payload, domainKeyIDFlowTest, domainSigningSeedFlowTest)

	encrypted, err := localrp.SealLocalRpCallback(
		signedPayload, localrp.AeadSuiteAES256GCM, keyMaterial.EncryptionPublicKey,
		payload.AudienceFingerprint, payload.Nonce, payload.State, payload.IssuedAt, payload.ExpiresAt,
	)
	if err != nil {
		t.Fatalf("seal callback: %v", err)
	}
	encryptedToken := localrp.LocalRpEncryptedCallbackToURLParam(encrypted)
	arrivedURL := fmt.Sprintf("%s?encrypted_token=%s", callbackURLFlowTest, encryptedToken)

	claim := localrp.SignClaim(localrp.ClaimSpec{
		ClaimID:       "claim-1",
		ClaimType:     "handle",
		ClaimValue:    []byte("flowtestuser"),
		UserID:        "user-1",
		SubjectDomain: userDomainFlowTest,
		AttestedAt:    now.UTC().Format(time.RFC3339Nano),
	}, []localrp.ClaimSigner{{Domain: userDomainFlowTest, KeyID: domainKeyIDFlowTest, PrivateKeySeed: domainSigningSeedFlowTest}})
	sc.mutateClaim(&claim)

	ticketExpiresAt := now.Add(1 * time.Hour).UTC().Format(time.RFC3339Nano)
	redemptionResponse := api.LocalRpTicketRedemptionResponse{
		UserId:          "user-1",
		UserDomain:      userDomainFlowTest,
		Claims:          []api.Claim{claim},
		TicketExpiresAt: ticketExpiresAt,
	}
	sc.mutateRedemption(&redemptionResponse)

	domainKeysForWire := append([]api.DomainPublicKey{domainKey}, sc.extraDomainKeys...)
	revocationsForWire := sc.revocations
	redemptionForWire := redemptionResponse
	addr := spawnFakeIDP(t, domainSigningSeedFlowTest, sc.expectedRequests, sc.dropOp, func(service, op string, _ []byte) rpctransport.RpcResponse {
		switch {
		case service == "DomainKeys" && op == "get-domain-keys":
			resp := api.GetDomainKeysResponse{Domain: userDomainFlowTest, Keys: domainKeysForWire}
			return rpctransport.NewRpcResponseOk("GetDomainKeysResponse", api.EncodeGetDomainKeysResponse(resp))
		case service == "DomainKeys" && op == "get-revocations":
			if sc.revocationsRPCFails {
				return rpctransport.NewRpcResponseTransportError(rpctransport.StatusInternal, "fake IDP: revocations fetch intentionally failing")
			}
			if sc.revocationsGarbage {
				return rpctransport.NewRpcResponseOk("GetRevocationsResponse", []byte{0xFF, 0xFF, 0xFF})
			}
			resp := api.GetRevocationsResponse{Revocations: revocationsForWire}
			return rpctransport.NewRpcResponseOk("GetRevocationsResponse", api.EncodeGetRevocationsResponse(resp))
		case service == "LocalRp" && op == "redeem-claim-ticket":
			return rpctransport.NewRpcResponseOk("LocalRpTicketRedemptionResponse", api.EncodeLocalRpTicketRedemptionResponse(redemptionForWire))
		default:
			return rpctransport.NewRpcResponseTransportError(rpctransport.StatusUnknownServiceOrOp, fmt.Sprintf("fake IDP has no handler for %s/%s", service, op))
		}
	})

	realFingerprint := localrp.Fingerprint(domainKey.PublicKey)
	fingerprints := []string{realFingerprint}
	for _, k := range sc.extraDomainKeys {
		fingerprints = append(fingerprints, localrp.Fingerprint(k.PublicKey))
	}
	if sc.dnsFingerprintOverride != nil {
		fingerprints[0] = *sc.dnsFingerprintOverride
	}
	linkkeysTXT := "v=lk1"
	for _, fp := range fingerprints {
		linkkeysTXT += " fp=" + fp
	}
	dns := &fakeDNSResolver{
		linkkeysTXT: linkkeysTXT,
		apisTXT:     "v=lk1 tcp=" + addr,
	}

	return localrp.CompleteLocalLogin(localrp.CompleteLocalLoginConfig{
		KeyMaterial:    keyMaterial,
		Pending:        pending,
		EncryptedToken: encryptedToken,
		ArrivedURL:     arrivedURL,
		Now:            now,
		Transport:      testTransport{},
		DNS:            dns,
	})
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

func TestHappyPathReturnsVerifiedLogin(t *testing.T) {
	verified, err := runScenario(t, defaultScenario())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if verified.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", verified.UserID)
	}
	if verified.UserDomain != userDomainFlowTest {
		t.Errorf("UserDomain = %q, want %q", verified.UserDomain, userDomainFlowTest)
	}
	if len(verified.Claims) != 1 || verified.Claims[0].ClaimType != "handle" {
		t.Errorf("unexpected claims: %+v", verified.Claims)
	}
	if len(verified.LocalRpFingerprint) != 64 {
		t.Errorf("LocalRpFingerprint length = %d, want 64", len(verified.LocalRpFingerprint))
	}
	if len(verified.DomainPublicKeys) != 1 {
		t.Errorf("DomainPublicKeys count = %d, want 1", len(verified.DomainPublicKeys))
	}
}

func expectLocalRpError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var lrpErr *localrp.LocalRpError
	if !errors.As(err, &lrpErr) {
		t.Fatalf("expected *localrp.LocalRpError, got %T: %v", err, err)
	}
}

func expectLocalRpErrorKind(t *testing.T, err error, kind localrp.LocalRpErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var lrpErr *localrp.LocalRpError
	if !errors.As(err, &lrpErr) {
		t.Fatalf("expected *localrp.LocalRpError, got %T: %v", err, err)
	}
	if lrpErr.Kind != kind {
		t.Fatalf("error kind = %q, want %q (%v)", lrpErr.Kind, kind, err)
	}
}

func expectClaimErrorKind(t *testing.T, err error, kind localrp.ClaimErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var claimErr *localrp.ClaimError
	if !errors.As(err, &claimErr) {
		t.Fatalf("expected *localrp.ClaimError, got %T: %v", err, err)
	}
	if claimErr.Kind != kind {
		t.Fatalf("error kind = %q, want %q (%v)", claimErr.Kind, kind, err)
	}
}

// requestsForOneKeyFetch is the wire-request count a single FetchDomainKeys
// call now costs (FIX B: get-domain-keys + get-revocations, always both).
const requestsForOneKeyFetch = 2

func TestWrongAudienceFingerprintIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.mutatePayload = func(p *api.LocalRpCallbackPayload) {
		p.AudienceFingerprint = repeatChar('b', 64)
	}
	sc.expectedRequests = requestsForOneKeyFetch
	_, err := runScenario(t, sc)
	expectLocalRpError(t, err)
}

func TestWrongIssuerDomainIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.mutatePayload = func(p *api.LocalRpCallbackPayload) {
		p.UserDomain = "attacker.test"
	}
	sc.expectedRequests = requestsForOneKeyFetch
	_, err := runScenario(t, sc)
	expectLocalRpError(t, err)
}

func TestNonceMismatchIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.mutatePayload = func(p *api.LocalRpCallbackPayload) {
		p.Nonce = bytes.Repeat([]byte{0xEE}, 32)
	}
	sc.expectedRequests = requestsForOneKeyFetch
	_, err := runScenario(t, sc)
	expectLocalRpError(t, err)
}

func TestExpiredCallbackPayloadIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.mutatePayload = func(p *api.LocalRpCallbackPayload) {
		n := time.Now()
		p.IssuedAt = n.Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
		p.ExpiresAt = n.Add(-1 * time.Hour).UTC().Format(time.RFC3339Nano)
	}
	sc.expectedRequests = requestsForOneKeyFetch
	_, err := runScenario(t, sc)
	expectLocalRpError(t, err)
}

func TestDNSFingerprintPinMismatchIsRejected(t *testing.T) {
	sc := defaultScenario()
	bad := repeatChar('c', 64)
	sc.dnsFingerprintOverride = &bad
	sc.expectedRequests = 1
	// Fails during the TLS handshake (the fake IDP's real cert fingerprint
	// no longer matches the pinned set) or, if it somehow connects, during
	// TrustKeys — either way it must never reach a verified result.
	if _, err := runScenario(t, sc); err == nil {
		t.Fatal("expected an error for a DNS fingerprint pin mismatch")
	}
}

func TestRevokedSigningKeyIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.mutateDomainKey = func(k *api.DomainPublicKey) {
		revokedAt := time.Now().UTC().Format(time.RFC3339Nano)
		k.RevokedAt = &revokedAt
	}
	sc.expectedRequests = requestsForOneKeyFetch
	_, err := runScenario(t, sc)
	expectLocalRpError(t, err)
}

func TestTamperedClaimSignatureIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.mutateClaim = func(c *api.Claim) {
		if len(c.Signatures) > 0 && len(c.Signatures[0].Signature) > 0 {
			c.Signatures[0].Signature[0] ^= 0xff
		}
	}
	sc.expectedRequests = requestsForOneKeyFetch + 1 // + redeem-claim-ticket
	_, err := runScenario(t, sc)
	if err == nil {
		t.Fatal("expected an error for a tampered claim signature")
	}
	var claimErr *localrp.ClaimError
	if !errors.As(err, &claimErr) {
		t.Fatalf("expected *localrp.ClaimError, got %T: %v", err, err)
	}
}

func repeatChar(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// ---------------------------------------------------------------------
// Hostile-IDP tests (security review fixes: identity binding, required
// claims, revocation fail-open). Each proves CompleteLocalLogin fails
// closed against a fake IDP that answers with a subtly, maliciously wrong
// response — never merely a wire-level parse failure.
// ---------------------------------------------------------------------

// (1) Redemption identity != signed payload: a compromised/malicious IDP
// answers the (unauthenticated) ticket redemption for a different user (or
// domain) than the one the domain-signature-verified callback payload
// actually named. Both fields are checked independently.

func TestRedemptionUserIDMismatchIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.mutateRedemption = func(r *api.LocalRpTicketRedemptionResponse) {
		r.UserId = "attacker-user"
	}
	sc.expectedRequests = requestsForOneKeyFetch + 1 // + redeem-claim-ticket
	_, err := runScenario(t, sc)
	expectLocalRpErrorKind(t, err, localrp.ErrKindRedemptionIdentityMismatch)
}

func TestRedemptionUserDomainMismatchIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.mutateRedemption = func(r *api.LocalRpTicketRedemptionResponse) {
		r.UserDomain = "attacker.test"
	}
	sc.expectedRequests = requestsForOneKeyFetch + 1 // + redeem-claim-ticket
	_, err := runScenario(t, sc)
	expectLocalRpErrorKind(t, err, localrp.ErrKindRedemptionIdentityMismatch)
}

// (2) claim.user_id != payload.user_id: a claim in the redemption response
// names a different subject than the verified payload, even though the
// claim's own signature (over that different user_id) is perfectly valid.
// Must be rejected on the cross-check, not merely accepted because its
// signature checks out.

func TestClaimUserIDMismatchIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.mutateClaim = func(c *api.Claim) {
		c.UserId = "attacker-user"
	}
	sc.expectedRequests = requestsForOneKeyFetch + 1 // + redeem-claim-ticket
	_, err := runScenario(t, sc)
	expectClaimErrorKind(t, err, localrp.ClaimErrKindUserIDMismatch)
}

// (3) required_claims non-empty but empty/insufficient claims returned: the
// IDP simply omits a claim the login demanded (or returns none at all).

func TestMissingRequiredClaimIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.requiredClaims = []string{"handle", "email"}  // "email" is never returned
	sc.expectedRequests = requestsForOneKeyFetch + 1 // + redeem-claim-ticket
	_, err := runScenario(t, sc)
	expectClaimErrorKind(t, err, localrp.ClaimErrKindRequiredClaimMissing)
}

func TestEmptyClaimsWithRequiredClaimsIsRejected(t *testing.T) {
	sc := defaultScenario()
	sc.mutateRedemption = func(r *api.LocalRpTicketRedemptionResponse) {
		r.Claims = nil
	}
	sc.expectedRequests = requestsForOneKeyFetch + 1 // + redeem-claim-ticket
	_, err := runScenario(t, sc)
	expectClaimErrorKind(t, err, localrp.ClaimErrKindRequiredClaimMissing)
}

// (4) get-revocations errors/drops: revocation delivery must never be
// best-effort. A server-error status, an undecodable payload, and a
// mid-conversation connection drop must all fail the whole login closed —
// none may be silently treated as "nothing revoked".

func TestRevocationsServerErrorFailsClosed(t *testing.T) {
	sc := defaultScenario()
	sc.revocationsRPCFails = true
	sc.expectedRequests = requestsForOneKeyFetch // never reaches redeem-claim-ticket
	_, err := runScenario(t, sc)
	if err == nil {
		t.Fatal("expected an error when get-revocations returns a server error")
	}
	var srvErr *localrp.ServerError
	if !errors.As(err, &srvErr) {
		t.Fatalf("expected *localrp.ServerError, got %T: %v", err, err)
	}
}

func TestRevocationsGarbagePayloadFailsClosed(t *testing.T) {
	sc := defaultScenario()
	sc.revocationsGarbage = true
	sc.expectedRequests = requestsForOneKeyFetch // never reaches redeem-claim-ticket
	_, err := runScenario(t, sc)
	if err == nil {
		t.Fatal("expected an error when get-revocations returns an undecodable payload")
	}
	var decErr *localrp.DecodeError
	if !errors.As(err, &decErr) {
		t.Fatalf("expected *localrp.DecodeError, got %T: %v", err, err)
	}
}

func TestRevocationsConnectionDropFailsClosed(t *testing.T) {
	sc := defaultScenario()
	sc.dropOp = func(service, op string) bool {
		return service == "DomainKeys" && op == "get-revocations"
	}
	sc.expectedRequests = requestsForOneKeyFetch // accepted, then dropped; never reaches redeem-claim-ticket
	_, err := runScenario(t, sc)
	if err == nil {
		t.Fatal("expected an error when get-revocations connection is dropped")
	}
	var transErr *localrp.TransportError
	if !errors.As(err, &transErr) {
		t.Fatalf("expected *localrp.TransportError, got %T: %v", err, err)
	}
}

// (5) certificate-revoked signing key: unlike TestRevokedSigningKeyIsRejected
// (which sets revoked_at directly on the key record itself), this proves the
// FIX B path — a key that is otherwise unmarked, but targeted by a
// quorum-verified sibling revocation certificate delivered via
// get-revocations — is dropped from the trusted set BEFORE it is used to
// verify the callback envelope. Requires two sibling signing keys (a
// key can never authorize its own revocation; RevocationQuorum is 2).

func TestCertificateRevokedSigningKeyIsRejected(t *testing.T) {
	targetPriv := ed25519.NewKeyFromSeed(domainSigningSeedFlowTest[:])
	targetPub := targetPriv.Public().(ed25519.PublicKey)
	targetFingerprint := localrp.Fingerprint([]byte(targetPub))

	siblingB := domainSigningKeyWithSeed(domainSigningSeedSiblingB, domainKeyIDSiblingBFlowTest)
	siblingC := domainSigningKeyWithSeed(domainSigningSeedSiblingC, domainKeyIDSiblingCFlowTest)

	cert := localrp.SignRevocationCertificate(domainKeyIDFlowTest, targetFingerprint, "2020-01-01T00:00:00Z", []localrp.RevocationSigner{
		{Domain: userDomainFlowTest, KeyID: domainKeyIDSiblingBFlowTest, PrivateKeySeed: domainSigningSeedSiblingB},
		{Domain: userDomainFlowTest, KeyID: domainKeyIDSiblingCFlowTest, PrivateKeySeed: domainSigningSeedSiblingC},
	})

	sc := defaultScenario()
	sc.extraDomainKeys = []api.DomainPublicKey{siblingB, siblingC}
	sc.revocations = []api.RevocationCertificate{cert}
	sc.expectedRequests = requestsForOneKeyFetch // fails during envelope verification; never reaches redemption
	_, err := runScenario(t, sc)
	expectLocalRpErrorKind(t, err, localrp.ErrKindKeyNotFound)
}
