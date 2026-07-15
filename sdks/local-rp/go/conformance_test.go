package localrp_test

// Conformance-vector tests for the Go local-RP SDK.
//
// Consumes every file under sdks/local-rp/conformance/ (see that
// directory's README for the schema) — the same fixed, checked-in vectors
// crates/liblinkkeys/tests/conformance.rs and
// sdks/local-rp/rust/tests/conformance.rs use. This package's public API is
// exercised directly (black-box, package localrp_test) since, unlike the
// Rust SDK (a thin wrapper over the separate liblinkkeys crate), this Go
// package IS the local-RP protocol implementation — there is no separate
// "liblinkkeys-go" to depend on.
//
// Covers: keys.json, envelopes.json, callback_box.json, url_params.json,
// dns.json, tickets.json, expirations.json — every file in the conformance
// directory, positive and negative cases.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

func conformanceDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "conformance")
}

func loadJSON(t *testing.T, name string, out interface{}) {
	t.Helper()
	path := filepath.Join(conformanceDir(t), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run the generator? see conformance/README.md)", path, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b := mustHex(t, s)
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d for %q", len(b), s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func parseRFC3339(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("bad RFC3339 timestamp %q: %v", s, err)
	}
	return tm.UTC()
}

// ---------------------------------------------------------------------
// keys.json
// ---------------------------------------------------------------------

type keyEntry struct {
	Algorithm      string  `json:"algorithm"`
	PrivateKeyHex  string  `json:"private_key_hex"`
	PublicKeyHex   string  `json:"public_key_hex"`
	SeedHex        *string `json:"seed_hex"`
	FingerprintHex *string `json:"fingerprint_hex"`
	KeyID          *string `json:"key_id"`
}

type keysFile struct {
	LocalRp struct {
		Signing    keyEntry `json:"signing"`
		Encryption keyEntry `json:"encryption"`
	} `json:"local_rp"`
	DomainSigningKey keyEntry `json:"domain_signing_key"`
}

func TestKeysFingerprintsRoundTripThroughSDKHelpers(t *testing.T) {
	var d keysFile
	loadJSON(t, "keys.json", &d)

	for _, entry := range []keyEntry{d.LocalRp.Signing, d.DomainSigningKey} {
		seed := mustHex32(t, *entry.SeedHex)
		public := mustHex(t, entry.PublicKeyHex)
		expectedFp := *entry.FingerprintHex

		priv := ed25519.NewKeyFromSeed(seed[:])
		if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != hex.EncodeToString(public) {
			t.Fatalf("derived public key from seed does not match vector public_key_hex")
		}

		computed := localrp.Fingerprint(public)
		if computed != expectedFp {
			t.Fatalf("Fingerprint mismatch: got %s want %s", computed, expectedFp)
		}

		s := localrp.FingerprintToString(computed)
		roundTripped, err := localrp.FingerprintFromString(s)
		if err != nil || roundTripped != expectedFp {
			t.Fatalf("fingerprint string round trip failed: %v", err)
		}
	}

	if _, err := localrp.FingerprintFromString("deadbeef"); err == nil {
		t.Fatalf("FingerprintFromString must reject non-fingerprint strings")
	}
}

// ---------------------------------------------------------------------
// envelopes.json
// ---------------------------------------------------------------------

type envelopeCase struct {
	Structure             string  `json:"structure"`
	Context               string  `json:"context"`
	PayloadCborHex        string  `json:"payload_cbor_hex"`
	SignatureInputCborHex string  `json:"signature_input_cbor_hex"`
	SignatureHex          string  `json:"signature_hex"`
	VerifyKeyHex          string  `json:"verify_key_hex"`
	ExpectedValid         bool    `json:"expected_valid"`
	Name                  *string `json:"name"`
}

type envelopesFile struct {
	Cases         []envelopeCase `json:"cases"`
	NegativeCases []envelopeCase `json:"negative_cases"`
}

func caseLabel(c envelopeCase) string {
	if c.Name != nil {
		return *c.Name
	}
	return c.Structure
}

func checkEnvelopeCase(t *testing.T, c envelopeCase) {
	t.Helper()
	payload := mustHex(t, c.PayloadCborHex)
	expectedSigInput := mustHex(t, c.SignatureInputCborHex)
	signature := mustHex(t, c.SignatureHex)
	verifyKey := mustHex(t, c.VerifyKeyHex)

	computedSigInput := localrp.EnvelopeSignatureInput(c.Context, payload)
	if hex.EncodeToString(computedSigInput) != hex.EncodeToString(expectedSigInput) {
		t.Fatalf("signature_input_cbor_hex mismatch for %s", caseLabel(c))
	}

	valid := len(verifyKey) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(verifyKey), computedSigInput, signature)
	if valid != c.ExpectedValid {
		t.Fatalf("verify result mismatch for %s: got valid=%v want %v", caseLabel(c), valid, c.ExpectedValid)
	}
}

func TestEnvelopesPositiveCasesVerify(t *testing.T) {
	var d envelopesFile
	loadJSON(t, "envelopes.json", &d)
	if len(d.Cases) != 4 {
		t.Fatalf("expected 4 positive envelope cases, got %d", len(d.Cases))
	}
	for _, c := range d.Cases {
		if !c.ExpectedValid {
			t.Fatalf("case %s should be expected_valid=true", caseLabel(c))
		}
		checkEnvelopeCase(t, c)
	}
}

func TestEnvelopesNegativeCasesFail(t *testing.T) {
	var d envelopesFile
	loadJSON(t, "envelopes.json", &d)
	if len(d.NegativeCases) != 20 {
		t.Fatalf("expected 20 negative envelope cases, got %d", len(d.NegativeCases))
	}
	for _, c := range d.NegativeCases {
		if c.ExpectedValid {
			t.Fatalf("negative case %s should be expected_valid=false", caseLabel(c))
		}
		checkEnvelopeCase(t, c)
	}
}

// ---------------------------------------------------------------------
// callback_box.json
// ---------------------------------------------------------------------

type callbackBoxCase struct {
	Suite                *string  `json:"suite"`
	DecryptPrivateKeyHex string   `json:"decrypt_private_key_hex"`
	Fingerprint          *string  `json:"fingerprint"`
	NonceHex             *string  `json:"nonce_hex"`
	StateHex             *string  `json:"state_hex"`
	IssuedAt             *string  `json:"issued_at"`
	ExpiresAt            *string  `json:"expires_at"`
	HeaderCborHex        string   `json:"header_cbor_hex"`
	PlaintextCborHex     *string  `json:"plaintext_cbor_hex"`
	CiphertextHex        string   `json:"ciphertext_hex"`
	AllowedSuites        []string `json:"allowed_suites"`
	ExpectedValid        bool     `json:"expected_valid"`
	Name                 *string  `json:"name"`
}

type callbackBoxFile struct {
	PositiveCases []callbackBoxCase `json:"positive_cases"`
	NegativeCases []callbackBoxCase `json:"negative_cases"`
}

func parseAllowedSuites(t *testing.T, ids []string) []localrp.AeadSuite {
	t.Helper()
	out := make([]localrp.AeadSuite, 0, len(ids))
	for _, id := range ids {
		suite, ok := localrp.ParseAeadSuite(id)
		if !ok {
			t.Fatalf("unregistered suite id in allowed_suites: %q", id)
		}
		out = append(out, suite)
	}
	return out
}

func TestCallbackBoxPositiveCasesOpen(t *testing.T) {
	var d callbackBoxFile
	loadJSON(t, "callback_box.json", &d)
	if len(d.PositiveCases) != 2 {
		t.Fatalf("expected 2 positive callback_box cases, got %d", len(d.PositiveCases))
	}

	for _, c := range d.PositiveCases {
		headerBytes := mustHex(t, c.HeaderCborHex)
		ciphertext := mustHex(t, c.CiphertextHex)
		decryptKey := mustHex32(t, c.DecryptPrivateKeyHex)
		allowed := parseAllowedSuites(t, c.AllowedSuites)

		encrypted := api.LocalRpEncryptedCallback{Header: headerBytes, Ciphertext: ciphertext}
		header, signedPayload, err := localrp.OpenLocalRpCallback(encrypted, decryptKey, allowed)
		if err != nil {
			t.Fatalf("positive case suite=%v failed to open: %v", c.Suite, err)
		}

		if string(header.Suite) != *c.Suite {
			t.Errorf("suite mismatch: got %s want %s", header.Suite, *c.Suite)
		}
		if header.Fingerprint != *c.Fingerprint {
			t.Errorf("fingerprint mismatch")
		}
		if hex.EncodeToString(header.Nonce) != *c.NonceHex {
			t.Errorf("nonce mismatch")
		}
		if hex.EncodeToString(header.State) != *c.StateHex {
			t.Errorf("state mismatch")
		}
		if header.IssuedAt != *c.IssuedAt {
			t.Errorf("issued_at mismatch")
		}
		if header.ExpiresAt != *c.ExpiresAt {
			t.Errorf("expires_at mismatch")
		}

		plaintext := api.EncodeSignedLocalRpCallbackPayload(*signedPayload)
		if hex.EncodeToString(plaintext) != *c.PlaintextCborHex {
			t.Errorf("re-encoded plaintext does not match plaintext_cbor_hex")
		}
	}
}

func TestCallbackBoxNegativeCasesFail(t *testing.T) {
	var d callbackBoxFile
	loadJSON(t, "callback_box.json", &d)
	if len(d.NegativeCases) != 13 {
		t.Fatalf("expected 13 negative callback_box cases, got %d", len(d.NegativeCases))
	}

	for _, c := range d.NegativeCases {
		headerBytes := mustHex(t, c.HeaderCborHex)
		ciphertext := mustHex(t, c.CiphertextHex)
		decryptKey := mustHex32(t, c.DecryptPrivateKeyHex)
		allowed := parseAllowedSuites(t, c.AllowedSuites)

		encrypted := api.LocalRpEncryptedCallback{Header: headerBytes, Ciphertext: ciphertext}
		if _, _, err := localrp.OpenLocalRpCallback(encrypted, decryptKey, allowed); err == nil {
			name := ""
			if c.Name != nil {
				name = *c.Name
			}
			t.Fatalf("negative case %s unexpectedly opened", name)
		}
	}
}

// ---------------------------------------------------------------------
// url_params.json
// ---------------------------------------------------------------------

type urlParamCase struct {
	Name              string `json:"name"`
	CborHex           string `json:"cbor_hex"`
	Base64URLUnpadded string `json:"base64url_unpadded"`
}

type urlParamNegativeCase struct {
	Input         string `json:"input"`
	ExpectedValid bool   `json:"expected_valid"`
}

type urlParamsFile struct {
	Cases         []urlParamCase         `json:"cases"`
	NegativeCases []urlParamNegativeCase `json:"negative_cases"`
}

func TestURLParamsCasesRoundTripBothDirections(t *testing.T) {
	var d urlParamsFile
	loadJSON(t, "url_params.json", &d)

	for _, c := range d.Cases {
		cbor := mustHex(t, c.CborHex)

		switch c.Name {
		case "signed_local_rp_login_request":
			typed, err := api.DecodeSignedLocalRpLoginRequest(cbor)
			if err != nil {
				t.Fatalf("decode signed login request: %v", err)
			}
			if got := localrp.SignedLocalRpLoginRequestToURLParam(typed); got != c.Base64URLUnpadded {
				t.Errorf("encode mismatch for %s", c.Name)
			}
			roundTripped, err := localrp.SignedLocalRpLoginRequestFromURLParam(c.Base64URLUnpadded)
			if err != nil {
				t.Fatalf("decode url param: %v", err)
			}
			if hex.EncodeToString(roundTripped.Request) != hex.EncodeToString(typed.Request) ||
				hex.EncodeToString(roundTripped.Signature) != hex.EncodeToString(typed.Signature) {
				t.Errorf("round trip mismatch for %s", c.Name)
			}
		case "local_rp_encrypted_callback":
			typed, err := api.DecodeLocalRpEncryptedCallback(cbor)
			if err != nil {
				t.Fatalf("decode encrypted callback: %v", err)
			}
			if got := localrp.LocalRpEncryptedCallbackToURLParam(typed); got != c.Base64URLUnpadded {
				t.Errorf("encode mismatch for %s", c.Name)
			}
			roundTripped, err := localrp.LocalRpEncryptedCallbackFromURLParam(c.Base64URLUnpadded)
			if err != nil {
				t.Fatalf("decode url param: %v", err)
			}
			if hex.EncodeToString(roundTripped.Header) != hex.EncodeToString(typed.Header) ||
				hex.EncodeToString(roundTripped.Ciphertext) != hex.EncodeToString(typed.Ciphertext) {
				t.Errorf("round trip mismatch for %s", c.Name)
			}
		default:
			t.Fatalf("unrecognized url_params.json case name: %s", c.Name)
		}
	}
}

func TestURLParamsNegativeCasesRejected(t *testing.T) {
	var d urlParamsFile
	loadJSON(t, "url_params.json", &d)
	if len(d.NegativeCases) != 2 {
		t.Fatalf("expected 2 negative url_params cases, got %d", len(d.NegativeCases))
	}
	for _, c := range d.NegativeCases {
		if _, err := localrp.LocalRpEncryptedCallbackFromURLParam(c.Input); err == nil {
			t.Errorf("expected rejection for input %q", c.Input)
		}
	}
}

// ---------------------------------------------------------------------
// dns.json
// ---------------------------------------------------------------------

type dnsValidCase struct {
	Txt                  string   `json:"txt"`
	ExpectedFingerprints []string `json:"expected_fingerprints"`
	ExpectedTCP          *string  `json:"expected_tcp"`
	ExpectedHTTPSBase    *string  `json:"expected_https_base"`
}

type dnsInvalidCase struct {
	Txt           string `json:"txt"`
	ExpectedError string `json:"expected_error"`
}

type dnsFile struct {
	DefaultTCPPort int `json:"default_tcp_port"`
	LinkKeysTXT    struct {
		ValidCases   []dnsValidCase   `json:"valid_cases"`
		InvalidCases []dnsInvalidCase `json:"invalid_cases"`
	} `json:"linkkeys_txt"`
	LinkKeysApisTXT struct {
		ValidCases   []dnsValidCase   `json:"valid_cases"`
		InvalidCases []dnsInvalidCase `json:"invalid_cases"`
	} `json:"linkkeys_apis_txt"`
}

func TestDNSLinkKeysTXTCases(t *testing.T) {
	var d dnsFile
	loadJSON(t, "dns.json", &d)

	for _, c := range d.LinkKeysTXT.ValidCases {
		rec, err := localrp.ParseLinkKeysTXT(c.Txt)
		if err != nil {
			t.Fatalf("parse %q: %v", c.Txt, err)
		}
		if len(rec.Fingerprints) != len(c.ExpectedFingerprints) {
			t.Fatalf("fingerprint count mismatch for %q", c.Txt)
		}
		for i, fp := range c.ExpectedFingerprints {
			if rec.Fingerprints[i] != fp {
				t.Errorf("fingerprint[%d] mismatch for %q", i, c.Txt)
			}
		}
	}

	for _, c := range d.LinkKeysTXT.InvalidCases {
		_, err := localrp.ParseLinkKeysTXT(c.Txt)
		if err == nil {
			t.Fatalf("expected parse error for %q", c.Txt)
		}
		var perr *localrp.DnsParseError
		if !asDnsParseError(err, &perr) {
			t.Fatalf("expected *DnsParseError, got %T", err)
		}
		if string(perr.Kind) != c.ExpectedError {
			t.Errorf("error kind mismatch for %q: got %s want %s", c.Txt, perr.Kind, c.ExpectedError)
		}
	}

	if localrp.DefaultTCPPort != uint16(d.DefaultTCPPort) {
		t.Errorf("DefaultTCPPort mismatch: got %d want %d", localrp.DefaultTCPPort, d.DefaultTCPPort)
	}
}

func TestDNSLinkKeysApisTXTCases(t *testing.T) {
	var d dnsFile
	loadJSON(t, "dns.json", &d)

	for _, c := range d.LinkKeysApisTXT.ValidCases {
		apis, err := localrp.ParseLinkKeysApisTXT(c.Txt)
		if err != nil {
			t.Fatalf("parse %q: %v", c.Txt, err)
		}
		gotTCP := (*string)(nil)
		if apis.TCP != nil {
			gotTCP = apis.TCP
		}
		if !strPtrEqual(gotTCP, c.ExpectedTCP) {
			t.Errorf("tcp mismatch for %q", c.Txt)
		}
		if !strPtrEqual(apis.HTTPSBase, c.ExpectedHTTPSBase) {
			t.Errorf("https_base mismatch for %q", c.Txt)
		}
	}

	for _, c := range d.LinkKeysApisTXT.InvalidCases {
		_, err := localrp.ParseLinkKeysApisTXT(c.Txt)
		if err == nil {
			t.Fatalf("expected parse error for %q", c.Txt)
		}
		var perr *localrp.DnsParseError
		if !asDnsParseError(err, &perr) {
			t.Fatalf("expected *DnsParseError, got %T", err)
		}
		if string(perr.Kind) != c.ExpectedError {
			t.Errorf("error kind mismatch for %q: got %s want %s", c.Txt, perr.Kind, c.ExpectedError)
		}
	}
}

func strPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func asDnsParseError(err error, target **localrp.DnsParseError) bool {
	if e, ok := err.(*localrp.DnsParseError); ok {
		*target = e
		return true
	}
	return false
}

// ---------------------------------------------------------------------
// tickets.json
// ---------------------------------------------------------------------

type ticketCase struct {
	Name      string `json:"name"`
	TicketHex string `json:"ticket_hex"`
	Sha256Hex string `json:"sha256_hex"`
}

type ticketsFile struct {
	Cases []ticketCase `json:"cases"`
}

func TestTicketsHashPairsMatchFingerprintRoutine(t *testing.T) {
	var d ticketsFile
	loadJSON(t, "tickets.json", &d)
	if len(d.Cases) == 0 {
		t.Fatal("expected at least one ticket case")
	}
	for _, c := range d.Cases {
		ticket := mustHex(t, c.TicketHex)
		if len(ticket) != 32 {
			t.Fatalf("ticket %s: expected 32 bytes, got %d", c.Name, len(ticket))
		}
		if got := localrp.Fingerprint(ticket); got != c.Sha256Hex {
			t.Errorf("ticket %s: fingerprint mismatch: got %s want %s", c.Name, got, c.Sha256Hex)
		}
	}
}

// ---------------------------------------------------------------------
// expirations.json
// ---------------------------------------------------------------------

type expirationCase struct {
	Now           string `json:"now"`
	ExpectedLevel string `json:"expected_level"`
}

type timestampCase struct {
	Now           string `json:"now"`
	ExpectedValid bool   `json:"expected_valid"`
	Description   string `json:"description"`
}

type expirationsFile struct {
	CheckExpirations struct {
		ExpiresAt string           `json:"expires_at"`
		Cases     []expirationCase `json:"cases"`
	} `json:"check_expirations"`
	CheckTimestamps struct {
		IssuedAt    string          `json:"issued_at"`
		ExpiresAt   string          `json:"expires_at"`
		SkewSeconds int64           `json:"skew_seconds"`
		Cases       []timestampCase `json:"cases"`
	} `json:"check_timestamps"`
}

func TestExpirationsCheckExpirationsThresholdsViaSDKWrapper(t *testing.T) {
	var d expirationsFile
	loadJSON(t, "expirations.json", &d)
	if len(d.CheckExpirations.Cases) != 11 {
		t.Fatalf("expected 11 check_expirations cases, got %d", len(d.CheckExpirations.Cases))
	}

	expiresAt := parseRFC3339(t, d.CheckExpirations.ExpiresAt)
	createdAt := expiresAt.Add(-3650 * 24 * time.Hour)

	identity, err := localrp.GenerateLocalRpIdentity(localrp.GenerateLocalRpIdentityConfig{
		AppName:  "Conformance Test App",
		Lifetime: expiresAt.Sub(createdAt),
		Now:      createdAt,
	})
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	for _, c := range d.CheckExpirations.Cases {
		now := parseRFC3339(t, c.Now)
		status, err := localrp.CheckExpirations(identity, now)
		if err != nil {
			t.Fatalf("check_expirations(now=%s): %v", now, err)
		}
		if string(status.Level) != c.ExpectedLevel {
			t.Errorf("now=%s: got level %s want %s", now, status.Level, c.ExpectedLevel)
		}
	}
}

func TestExpirationsCheckTimestampsSkewBoundariesAreExact(t *testing.T) {
	var d expirationsFile
	loadJSON(t, "expirations.json", &d)
	if len(d.CheckTimestamps.Cases) != 4 {
		t.Fatalf("expected 4 check_timestamps cases, got %d", len(d.CheckTimestamps.Cases))
	}

	for _, c := range d.CheckTimestamps.Cases {
		now := parseRFC3339(t, c.Now)
		err := localrp.CheckTimestamps(d.CheckTimestamps.IssuedAt, d.CheckTimestamps.ExpiresAt, now, d.CheckTimestamps.SkewSeconds)
		valid := err == nil
		if valid != c.ExpectedValid {
			t.Errorf("%s (now=%s): got valid=%v want %v", c.Description, now, valid, c.ExpectedValid)
		}
	}
}
