package localrp

import (
	"bytes"
	"crypto/subtle"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// DNS-less local RP identity: pure protocol helpers. Mirrors
// crates/liblinkkeys/src/local_rp.rs byte-for-byte per
// dns-less-local-rp-design.md's "Wire Precision (Normative)" section — read
// that first. Summary of the shape:
//
//   - Every signed structure uses the envelope pattern: the payload is
//     CBOR-encoded once, and the signature covers
//     CBOR([context: tstr, payload: bstr]) — a two-element CBOR array, never
//     a bare context||payload concatenation.
//   - Four mandatory, structure-specific context strings stop a signature
//     over one structure from ever verifying as another.
//   - The descriptor, login request, and ticket-redemption envelopes verify
//     against the local RP's own signing key (self-asserted identity,
//     SSH-host style). The callback payload envelope verifies against
//     DOMAIN public keys, keyed by signing_key_id.
//   - The callback ciphertext is a variant of a sealed-box construction,
//     extended with negotiated-suite selection and cleartext-header AAD
//     binding.
//
// This file performs no I/O: every "current time" is an explicit `now`
// parameter, never the system clock (with one narrow, deliberate exception —
// signingKeyValidity — that mirrors liblinkkeys::crypto::signing_key_validity
// exactly, wall clock and all).

// Signature contexts for the four local-RP signed structures.
const (
	CtxLocalRpDescriptor       = "linkkeys-local-rp-descriptor"
	CtxLocalRpLoginRequest     = "linkkeys-local-rp-login-request"
	CtxLocalRpCallback         = "linkkeys-local-rp-callback"
	CtxLocalRpTicketRedemption = "linkkeys-local-rp-ticket-redemption"
)

// DefaultClockSkewSeconds is the default bounded clock-skew tolerance for
// timestamp checks (design doc: "±300 seconds").
const DefaultClockSkewSeconds int64 = 300

// EnvelopeSignatureInput is the signature input for every local-RP signed
// structure: CBOR([context, payload_bytes]) — a two-element array with the
// domain-separation context string first and the exact payload bytes second
// (encoded as a CBOR byte string, never re-serialized). Deliberately NOT a
// bare `context || payload` concatenation — see the design doc's "Signature
// input bytes".
func EnvelopeSignatureInput(context string, payloadBytes []byte) []byte {
	return cborTuple(cborText(context), cborBytesVal(payloadBytes))
}

func parseTimestamp(field, s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, &LocalRpError{Kind: ErrKindBadTimestamp, Detail: field + ": " + err.Error()}
	}
	return t.UTC(), nil
}

// CheckTimestamps checks an (issued_at, expires_at) pair against now,
// tolerant of skewSeconds of clock skew in either direction. Boundaries are
// inclusive: exactly `now - skew == expires_at` still passes, and exactly
// one second past either boundary fails.
func CheckTimestamps(issuedAt, expiresAt string, now time.Time, skewSeconds int64) error {
	issued, err := parseTimestamp("issued_at", issuedAt)
	if err != nil {
		return err
	}
	expires, err := parseTimestamp("expires_at", expiresAt)
	if err != nil {
		return err
	}
	skew := time.Duration(skewSeconds) * time.Second
	if now.Add(skew).Before(issued) {
		return &LocalRpError{Kind: ErrKindNotYetValid}
	}
	if now.Add(-skew).After(expires) {
		return &LocalRpError{Kind: ErrKindExpired}
	}
	return nil
}

// ExpirationLevel is the warning level returned by CheckExpirations
// (design doc, "Expiration Helper"): notice at 180 days remaining, warning
// at 90, critical at 30, expired once now >= expires_at.
type ExpirationLevel string

const (
	ExpirationOk       ExpirationLevel = "ok"
	ExpirationNotice   ExpirationLevel = "notice"
	ExpirationWarning  ExpirationLevel = "warning"
	ExpirationCritical ExpirationLevel = "critical"
	ExpirationExpired  ExpirationLevel = "expired"
)

// ExpirationStatus carries facts about a local RP identity's expiry as of
// now. The SDK reports facts; the app decides whether to warn admins, warn
// users, block login, renew, or ignore.
type ExpirationStatus struct {
	Level     ExpirationLevel
	ExpiresAt time.Time
	Now       time.Time
}

// CheckExpirationsAt is the pure per-timestamp expiry check (mirrors
// `liblinkkeys::local_rp::check_expirations`). This does NOT apply
// clock-skew tolerance (unlike CheckTimestamps): expiry warnings are
// advisory, day-scale facts, not a replay/freshness security boundary. See
// [CheckExpirations] for the identity-based SDK-shape wrapper.
func CheckExpirationsAt(expiresAt string, now time.Time) (*ExpirationStatus, error) {
	expires, err := parseTimestamp("expires_at", expiresAt)
	if err != nil {
		return nil, err
	}
	remaining := expires.Sub(now)
	var level ExpirationLevel
	switch {
	case !now.Before(expires):
		level = ExpirationExpired
	case remaining <= 30*24*time.Hour:
		level = ExpirationCritical
	case remaining <= 90*24*time.Hour:
		level = ExpirationWarning
	case remaining <= 180*24*time.Hour:
		level = ExpirationNotice
	default:
		level = ExpirationOk
	}
	return &ExpirationStatus{Level: level, ExpiresAt: expires, Now: now}, nil
}

// VerifyNonceState verifies a nonce/state pair against the caller-supplied
// expected values (typically the pending-login state persisted from
// begin_local_login). Constant-time comparison (crypto/subtle) — these
// values gate a security-relevant decision (is this callback the one THIS
// login began), so comparing them must not leak timing information about
// how much of a guessed value matched, even though both are also bound
// inside a signed/encrypted envelope elsewhere in the chain; defense in
// depth costs nothing here. Replay protection at the app boundary (treating
// PendingLogin as single-use) is the caller's job.
func VerifyNonceState(expectedNonce, expectedState, actualNonce, actualState []byte) error {
	if subtle.ConstantTimeCompare(expectedNonce, actualNonce) != 1 {
		return &LocalRpError{Kind: ErrKindNonceMismatch}
	}
	if subtle.ConstantTimeCompare(expectedState, actualState) != 1 {
		return &LocalRpError{Kind: ErrKindStateMismatch}
	}
	return nil
}

// VerifyAudience verifies the callback's audience (fingerprint) equals the
// local RP's own fingerprint.
func VerifyAudience(payloadAudienceFingerprint, localRpFingerprint string) error {
	if payloadAudienceFingerprint != localRpFingerprint {
		return &LocalRpError{Kind: ErrKindAudienceMismatch}
	}
	return nil
}

// VerifyIssuer verifies issuer binding: the callback payload's user_domain
// must equal the domain the login was begun with.
func VerifyIssuer(payloadUserDomain, expectedDomain string) error {
	if payloadUserDomain != expectedDomain {
		return &LocalRpError{Kind: ErrKindIssuerMismatch}
	}
	return nil
}

// VerifyCallbackURL verifies the callback payload's callback_url equals the
// URL the callback actually arrived at (not merely the URL originally
// requested).
func VerifyCallbackURL(payloadCallbackURL, arrivedURL string) error {
	if payloadCallbackURL != arrivedURL {
		return &LocalRpError{Kind: ErrKindCallbackURLMismatch}
	}
	return nil
}

// ---------------------------------------------------------------------
// Signing-key validity (mirrors liblinkkeys::crypto::signing_key_validity /
// check_signing_key_valid exactly, including its use of the real wall clock
// rather than an explicit `now` parameter).
// ---------------------------------------------------------------------

type keyValidity int

const (
	keyValidityValid keyValidity = iota
	keyValidityRevoked
	keyValidityExpired
	keyValidityBadExpiry
)

func signingKeyValidity(expiresAt string, revokedAt *string) keyValidity {
	if revokedAt != nil {
		return keyValidityRevoked
	}
	t, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return keyValidityBadExpiry
	}
	if time.Now().UTC().After(t.UTC()) {
		return keyValidityExpired
	}
	return keyValidityValid
}

// checkSigningKeyValid rejects a signing key that is not usable as a
// signer: wrong key_usage, revoked, or expired. Shared by every verify path
// that resolves a key by id.
func checkSigningKeyValid(key api.DomainPublicKey) error {
	if key.KeyUsage != "sign" {
		return &LocalRpError{Kind: ErrKindSignatureInvalid}
	}
	switch signingKeyValidity(key.ExpiresAt, key.RevokedAt) {
	case keyValidityValid:
		return nil
	case keyValidityRevoked:
		return &LocalRpError{Kind: ErrKindKeyRevoked, Detail: key.KeyId}
	default:
		return &LocalRpError{Kind: ErrKindKeyExpired, Detail: key.KeyId}
	}
}

// ---------------------------------------------------------------------
// Descriptor
// ---------------------------------------------------------------------

// toAeadSuites converts wire suite-id strings to the generated api.AeadSuite
// named-string type.
func toAeadSuites(suites []string) []api.AeadSuite {
	out := make([]api.AeadSuite, len(suites))
	for i, s := range suites {
		out[i] = api.AeadSuite(s)
	}
	return out
}

// BuildLocalRpDescriptor builds an unsigned LocalRpDescriptor. Fingerprint is
// always derived from signingPublicKey via Fingerprint — callers cannot set
// it directly, so it can never drift from the key it names.
func BuildLocalRpDescriptor(appName string, localDomainHint *string, signingPublicKey, encryptionPublicKey [32]byte, supportedSuites []string, createdAt, expiresAt string) api.LocalRpDescriptor {
	return api.LocalRpDescriptor{
		AppName:             appName,
		LocalDomainHint:     localDomainHint,
		SigningPublicKey:    append([]byte{}, signingPublicKey[:]...),
		EncryptionPublicKey: append([]byte{}, encryptionPublicKey[:]...),
		Fingerprint:         Fingerprint(signingPublicKey[:]),
		SupportedSuites:     toAeadSuites(supportedSuites),
		CreatedAt:           createdAt,
		ExpiresAt:           expiresAt,
	}
}

// SignLocalRpDescriptor signs a LocalRpDescriptor with the local RP's own
// signing key.
func SignLocalRpDescriptor(descriptor api.LocalRpDescriptor, signingPrivateKeySeed [32]byte) api.SignedLocalRpDescriptor {
	descriptorBytes := api.EncodeLocalRpDescriptor(descriptor)
	sigInput := EnvelopeSignatureInput(CtxLocalRpDescriptor, descriptorBytes)
	sig := signEd25519(signingPrivateKeySeed, sigInput)
	return api.SignedLocalRpDescriptor{Descriptor: descriptorBytes, Signature: sig}
}

// VerifyLocalRpDescriptor verifies a signed local RP descriptor: decode it,
// check its fingerprint field truly is Fingerprint(signing_public_key),
// verify the envelope signature against its own embedded signing key (a
// local RP descriptor is self-asserted identity, SSH-host style), and check
// created_at/expires_at bounds.
func VerifyLocalRpDescriptor(signed api.SignedLocalRpDescriptor, now time.Time, skewSeconds int64) (*api.LocalRpDescriptor, error) {
	descriptor, err := api.DecodeLocalRpDescriptor(signed.Descriptor)
	if err != nil {
		return nil, &LocalRpError{Kind: ErrKindDecode, Detail: err.Error()}
	}

	if len(descriptor.SigningPublicKey) != 32 {
		return nil, &LocalRpError{Kind: ErrKindInvalidKeyLength}
	}

	expectedFingerprint := Fingerprint(descriptor.SigningPublicKey)
	if descriptor.Fingerprint != expectedFingerprint {
		return nil, &LocalRpError{Kind: ErrKindFingerprintMismatch}
	}

	sigInput := EnvelopeSignatureInput(CtxLocalRpDescriptor, signed.Descriptor)
	if err := resolveAndVerify("ed25519", sigInput, signed.Signature, descriptor.SigningPublicKey); err != nil {
		return nil, err
	}

	if err := CheckTimestamps(descriptor.CreatedAt, descriptor.ExpiresAt, now, skewSeconds); err != nil {
		return nil, err
	}

	return &descriptor, nil
}

// ---------------------------------------------------------------------
// Login request
// ---------------------------------------------------------------------

// BuildLocalRpLoginRequest builds an unsigned LocalRpLoginRequest around an
// already-signed descriptor.
func BuildLocalRpLoginRequest(descriptor api.SignedLocalRpDescriptor, callbackURL string, nonce, state []byte, requestedClaims, requiredClaims []string, issuedAt, expiresAt string) api.LocalRpLoginRequest {
	return api.LocalRpLoginRequest{
		Descriptor:      descriptor,
		CallbackUrl:     callbackURL,
		Nonce:           nonce,
		State:           state,
		RequestedClaims: requestedClaims,
		RequiredClaims:  requiredClaims,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
	}
}

// SignLocalRpLoginRequest signs a LocalRpLoginRequest with the local RP's
// signing key (the same key embedded in the request's own descriptor).
func SignLocalRpLoginRequest(request api.LocalRpLoginRequest, signingPrivateKeySeed [32]byte) api.SignedLocalRpLoginRequest {
	requestBytes := api.EncodeLocalRpLoginRequest(request)
	sigInput := EnvelopeSignatureInput(CtxLocalRpLoginRequest, requestBytes)
	sig := signEd25519(signingPrivateKeySeed, sigInput)
	return api.SignedLocalRpLoginRequest{Request: requestBytes, Signature: sig}
}

// VerifyLocalRpLoginRequest verifies a signed local RP login request end to
// end: decode it, fully verify the nested descriptor (envelope signature,
// fingerprint binding, timestamp bounds), then verify the outer envelope
// signature against the descriptor's signing key, then check the request's
// own issued_at/expires_at bounds.
func VerifyLocalRpLoginRequest(signed api.SignedLocalRpLoginRequest, now time.Time, skewSeconds int64) (*api.LocalRpLoginRequest, error) {
	request, err := api.DecodeLocalRpLoginRequest(signed.Request)
	if err != nil {
		return nil, &LocalRpError{Kind: ErrKindDecode, Detail: err.Error()}
	}

	descriptor, err := VerifyLocalRpDescriptor(request.Descriptor, now, skewSeconds)
	if err != nil {
		return nil, err
	}

	sigInput := EnvelopeSignatureInput(CtxLocalRpLoginRequest, signed.Request)
	if err := resolveAndVerify("ed25519", sigInput, signed.Signature, descriptor.SigningPublicKey); err != nil {
		return nil, err
	}

	if err := CheckTimestamps(request.IssuedAt, request.ExpiresAt, now, skewSeconds); err != nil {
		return nil, err
	}

	return &request, nil
}

// ---------------------------------------------------------------------
// Ticket redemption
// ---------------------------------------------------------------------

// BuildLocalRpTicketRedemptionRequest builds an unsigned
// LocalRpTicketRedemptionRequest.
func BuildLocalRpTicketRedemptionRequest(claimTicket []byte, fingerprint string, issuedAt string) api.LocalRpTicketRedemptionRequest {
	return api.LocalRpTicketRedemptionRequest{
		ClaimTicket: claimTicket,
		Fingerprint: fingerprint,
		IssuedAt:    issuedAt,
	}
}

// SignLocalRpTicketRedemptionRequest signs a ticket redemption request with
// the local RP's signing key, so a stolen ticket is useless without the
// matching private key.
func SignLocalRpTicketRedemptionRequest(request api.LocalRpTicketRedemptionRequest, signingPrivateKeySeed [32]byte) api.SignedLocalRpTicketRedemptionRequest {
	requestBytes := api.EncodeLocalRpTicketRedemptionRequest(request)
	sigInput := EnvelopeSignatureInput(CtxLocalRpTicketRedemption, requestBytes)
	sig := signEd25519(signingPrivateKeySeed, sigInput)
	return api.SignedLocalRpTicketRedemptionRequest{Request: requestBytes, Signature: sig}
}

// VerifyLocalRpTicketRedemptionRequest verifies a ticket-redemption
// request's possession proof: signingPublicKey is the key the caller
// resolved for expectedFingerprint — the signature must verify against it,
// AND that key's own fingerprint plus the request's embedded fingerprint
// field must both equal expectedFingerprint.
func VerifyLocalRpTicketRedemptionRequest(signed api.SignedLocalRpTicketRedemptionRequest, signingPublicKey []byte, expectedFingerprint string) (*api.LocalRpTicketRedemptionRequest, error) {
	sigInput := EnvelopeSignatureInput(CtxLocalRpTicketRedemption, signed.Request)
	if err := resolveAndVerify("ed25519", sigInput, signed.Signature, signingPublicKey); err != nil {
		return nil, err
	}

	request, err := api.DecodeLocalRpTicketRedemptionRequest(signed.Request)
	if err != nil {
		return nil, &LocalRpError{Kind: ErrKindDecode, Detail: err.Error()}
	}

	keyFingerprint := Fingerprint(signingPublicKey)
	if keyFingerprint != expectedFingerprint || request.Fingerprint != expectedFingerprint {
		return nil, &LocalRpError{Kind: ErrKindFingerprintMismatch}
	}

	return &request, nil
}

// ---------------------------------------------------------------------
// Callback payload (domain-signed envelope)
// ---------------------------------------------------------------------

// BuildLocalRpCallbackPayload builds an unsigned LocalRpCallbackPayload.
func BuildLocalRpCallbackPayload(userID, userDomain string, claimTicket []byte, audienceFingerprint, callbackURL string, nonce, state []byte, issuedAt, expiresAt string) api.LocalRpCallbackPayload {
	return api.LocalRpCallbackPayload{
		UserId:              userID,
		UserDomain:          userDomain,
		ClaimTicket:         claimTicket,
		AudienceFingerprint: audienceFingerprint,
		CallbackUrl:         callbackURL,
		Nonce:               nonce,
		State:               state,
		IssuedAt:            issuedAt,
		ExpiresAt:           expiresAt,
	}
}

// SignLocalRpCallbackPayload signs a LocalRpCallbackPayload with one of the
// issuing domain's signing keys (keyID identifies which one — a domain holds
// several signing keys). This is a server-side (IDP) operation exposed here
// only because it is a pure protocol helper, mirroring
// liblinkkeys::local_rp; the local-RP SDK itself never calls it in
// production — only test fixtures (fake IDPs) do.
func SignLocalRpCallbackPayload(payload api.LocalRpCallbackPayload, keyID string, signingPrivateKeySeed [32]byte) api.SignedLocalRpCallbackPayload {
	payloadBytes := api.EncodeLocalRpCallbackPayload(payload)
	sigInput := EnvelopeSignatureInput(CtxLocalRpCallback, payloadBytes)
	sig := signEd25519(signingPrivateKeySeed, sigInput)
	return api.SignedLocalRpCallbackPayload{Payload: payloadBytes, SigningKeyId: keyID, Signature: sig}
}

// VerifyLocalRpCallbackPayload verifies a domain-signed callback payload
// envelope against a set of domain public keys: resolve signing_key_id,
// reject a revoked/expired/non-signing key, verify the envelope signature,
// decode, then check issued_at/expires_at bounds.
func VerifyLocalRpCallbackPayload(signed api.SignedLocalRpCallbackPayload, domainPublicKeys []api.DomainPublicKey, now time.Time, skewSeconds int64) (*api.LocalRpCallbackPayload, error) {
	var key *api.DomainPublicKey
	for i := range domainPublicKeys {
		if domainPublicKeys[i].KeyId == signed.SigningKeyId {
			key = &domainPublicKeys[i]
			break
		}
	}
	if key == nil {
		return nil, &LocalRpError{Kind: ErrKindKeyNotFound, Detail: signed.SigningKeyId}
	}

	if err := checkSigningKeyValid(*key); err != nil {
		return nil, err
	}

	sigInput := EnvelopeSignatureInput(CtxLocalRpCallback, signed.Payload)
	if err := resolveAndVerify(key.Algorithm, sigInput, signed.Signature, key.PublicKey); err != nil {
		return nil, err
	}

	payload, err := api.DecodeLocalRpCallbackPayload(signed.Payload)
	if err != nil {
		return nil, &LocalRpError{Kind: ErrKindDecode, Detail: err.Error()}
	}

	if err := CheckTimestamps(payload.IssuedAt, payload.ExpiresAt, now, skewSeconds); err != nil {
		return nil, err
	}

	return &payload, nil
}

// CheckCallbackHeaderMatchesPayload cross-checks the cleartext callback
// header's routing fields against the authoritative copies inside the
// decrypted, domain-signature-verified payload. The header is already bound
// as AEAD associated data (so it cannot be tampered independently of the
// ciphertext it accompanies), but a verifier must still consult the signed
// copies rather than trusting the header alone.
func CheckCallbackHeaderMatchesPayload(header api.LocalRpCallbackHeader, payload api.LocalRpCallbackPayload) error {
	if header.Fingerprint != payload.AudienceFingerprint {
		return &LocalRpError{Kind: ErrKindHeaderPayloadMismatch, Detail: "fingerprint"}
	}
	if !bytes.Equal(header.Nonce, payload.Nonce) {
		return &LocalRpError{Kind: ErrKindHeaderPayloadMismatch, Detail: "nonce"}
	}
	if !bytes.Equal(header.State, payload.State) {
		return &LocalRpError{Kind: ErrKindHeaderPayloadMismatch, Detail: "state"}
	}
	if header.IssuedAt != payload.IssuedAt {
		return &LocalRpError{Kind: ErrKindHeaderPayloadMismatch, Detail: "issued_at"}
	}
	if header.ExpiresAt != payload.ExpiresAt {
		return &LocalRpError{Kind: ErrKindHeaderPayloadMismatch, Detail: "expires_at"}
	}
	return nil
}

// ---------------------------------------------------------------------
// Callback sealed box (Wire Precision: "Callback sealed box")
// ---------------------------------------------------------------------

// SealLocalRpCallback seals a SignedLocalRpCallbackPayload into a
// LocalRpEncryptedCallback for recipientEncryptionPublicKey, using suite.
// This is a server-side (IDP) operation exposed here as a pure protocol
// helper (mirroring liblinkkeys::local_rp::seal_local_rp_callback); the
// local-RP SDK itself never calls it in production, only test fixtures.
func SealLocalRpCallback(signedPayload api.SignedLocalRpCallbackPayload, suite AeadSuite, recipientEncryptionPublicKey [32]byte, fingerprint string, nonce, state []byte, issuedAt, expiresAt string) (api.LocalRpEncryptedCallback, error) {
	ephemeralPriv, ephemeralPub, err := generateX25519Keypair()
	if err != nil {
		return api.LocalRpEncryptedCallback{}, &LocalRpError{Kind: ErrKindCrypto, Detail: err.Error()}
	}
	var aeadNonce [12]byte
	if err := randomBytes(aeadNonce[:]); err != nil {
		return api.LocalRpEncryptedCallback{}, &LocalRpError{Kind: ErrKindCrypto, Detail: err.Error()}
	}
	return sealLocalRpCallbackInner(signedPayload, suite, recipientEncryptionPublicKey, fingerprint, nonce, state, issuedAt, expiresAt, ephemeralPriv, ephemeralPub, aeadNonce)
}

func sealLocalRpCallbackInner(signedPayload api.SignedLocalRpCallbackPayload, suite AeadSuite, recipientPub [32]byte, fingerprint string, nonce, state []byte, issuedAt, expiresAt string, ephemeralPriv, ephemeralPub [32]byte, aeadNonce [12]byte) (api.LocalRpEncryptedCallback, error) {
	plaintext := api.EncodeSignedLocalRpCallbackPayload(signedPayload)

	sharedSecret, err := x25519ECDH(ephemeralPriv, recipientPub)
	if err != nil {
		return api.LocalRpEncryptedCallback{}, &LocalRpError{Kind: ErrKindCrypto, Detail: "non-contributory recipient key"}
	}

	header := api.LocalRpCallbackHeader{
		Fingerprint:        fingerprint,
		Nonce:              nonce,
		State:              state,
		Suite:              api.AeadSuite(suite),
		EphemeralPublicKey: append([]byte{}, ephemeralPub[:]...),
		AeadNonce:          append([]byte{}, aeadNonce[:]...),
		IssuedAt:           issuedAt,
		ExpiresAt:          expiresAt,
	}
	headerBytes := api.EncodeLocalRpCallbackHeader(header)

	aeadKey, kdfContext, err := localRpCallbackKDF(suite, ephemeralPub, recipientPub, sharedSecret)
	if err != nil {
		return api.LocalRpEncryptedCallback{}, &LocalRpError{Kind: ErrKindCrypto, Detail: err.Error()}
	}

	aad := append(append([]byte{}, kdfContext...), headerBytes...)
	ciphertext, err := aeadEncrypt(suite, aeadKey, aeadNonce, aad, plaintext)
	if err != nil {
		return api.LocalRpEncryptedCallback{}, &LocalRpError{Kind: ErrKindCrypto, Detail: err.Error()}
	}

	return api.LocalRpEncryptedCallback{Header: headerBytes, Ciphertext: ciphertext}, nil
}

// OpenLocalRpCallback opens a LocalRpEncryptedCallback with the local RP's
// encryption private key. allowedSuites is the local RP's own
// supported-suite list (from its descriptor): a header advertising a suite
// NOT in that list is rejected even if it is otherwise a valid registry id.
//
// Returns the decoded header (cleartext routing metadata) and the still
// domain-signature-unverified SignedLocalRpCallbackPayload — callers must
// still call VerifyLocalRpCallbackPayload against fetched domain keys, and
// then CheckCallbackHeaderMatchesPayload, before trusting the result.
func OpenLocalRpCallback(encrypted api.LocalRpEncryptedCallback, recipientEncryptionPrivateKey [32]byte, allowedSuites []AeadSuite) (*api.LocalRpCallbackHeader, *api.SignedLocalRpCallbackPayload, error) {
	header, err := api.DecodeLocalRpCallbackHeader(encrypted.Header)
	if err != nil {
		return nil, nil, &LocalRpError{Kind: ErrKindDecode, Detail: err.Error()}
	}

	suite, ok := ParseAeadSuite(string(header.Suite))
	if !ok {
		return nil, nil, &LocalRpError{Kind: ErrKindUnsupportedSuite, Detail: string(header.Suite)}
	}
	if !containsSuite(allowedSuites, suite) {
		return nil, nil, &LocalRpError{Kind: ErrKindSuiteNotAdvertised, Detail: string(header.Suite)}
	}

	if len(header.EphemeralPublicKey) != 32 {
		return nil, nil, &LocalRpError{Kind: ErrKindInvalidKeyLength}
	}
	var ephemeralPub [32]byte
	copy(ephemeralPub[:], header.EphemeralPublicKey)

	if len(header.AeadNonce) != 12 {
		return nil, nil, &LocalRpError{Kind: ErrKindInvalidKeyLength}
	}
	var aeadNonce [12]byte
	copy(aeadNonce[:], header.AeadNonce)

	recipientPub, err := x25519PublicFromPrivate(recipientEncryptionPrivateKey)
	if err != nil {
		return nil, nil, &LocalRpError{Kind: ErrKindInvalidKeyLength, Detail: err.Error()}
	}

	sharedSecret, err := x25519ECDH(recipientEncryptionPrivateKey, ephemeralPub)
	if err != nil {
		return nil, nil, &LocalRpError{Kind: ErrKindCrypto, Detail: "non-contributory ephemeral key"}
	}

	aeadKey, kdfContext, err := localRpCallbackKDF(suite, ephemeralPub, recipientPub, sharedSecret)
	if err != nil {
		return nil, nil, &LocalRpError{Kind: ErrKindCrypto, Detail: err.Error()}
	}

	aad := append(append([]byte{}, kdfContext...), encrypted.Header...)
	plaintext, err := aeadDecrypt(suite, aeadKey, aeadNonce, aad, encrypted.Ciphertext)
	if err != nil {
		return nil, nil, &LocalRpError{Kind: ErrKindCrypto, Detail: "decrypt failed"}
	}

	signedPayload, err := api.DecodeSignedLocalRpCallbackPayload(plaintext)
	if err != nil {
		return nil, nil, &LocalRpError{Kind: ErrKindDecode, Detail: err.Error()}
	}

	return &header, &signedPayload, nil
}
