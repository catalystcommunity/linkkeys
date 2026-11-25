package localrp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// Crypto primitives this SDK needs, per the design doc's Language Crypto
// Matrix Go row: stdlib-only for the mandatory baseline
// (crypto/ed25519, crypto/ecdh X25519, AES-256-GCM via crypto/aes+cipher,
// crypto/hkdf), plus golang.org/x/crypto/chacha20poly1305 for the optional
// second AEAD suite (see go.mod for the dependency justification).
//
// This mirrors crates/liblinkkeys/src/crypto.rs's fingerprint/keypair/AEAD
// helpers and crates/liblinkkeys/src/local_rp.rs's callback-box KDF —
// deliberately only the subset the local-RP protocol needs (this SDK does not
// need the generic sealed_box_encrypt/decrypt, password hashing, or
// private-key-at-rest encryption liblinkkeys also has, since those aren't
// part of the local-RP wire protocol).

// randomBytes fills b with cryptographically secure random bytes.
func randomBytes(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// Fingerprint is `sha256(public_key_bytes)`, lowercase hex — the canonical
// LinkKeys fingerprint format used everywhere (DNS `fp=` records, TLS SPKI
// pinning, local RP identity). Matches `liblinkkeys::crypto::fingerprint`
// exactly.
func Fingerprint(publicKeyBytes []byte) string {
	sum := sha256.Sum256(publicKeyBytes)
	return hex.EncodeToString(sum[:])
}

// generateEd25519Keypair generates a fresh Ed25519 keypair, returning the
// 32-byte public key and 32-byte seed (Ed25519's "private key" IS its
// 32-byte seed — see keys.json's convention note).
func generateEd25519Keypair() (pub [32]byte, seed [32]byte, err error) {
	p, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return pub, seed, err
	}
	copy(pub[:], p)
	copy(seed[:], priv.Seed())
	return pub, seed, nil
}

// signEd25519 signs message with the Ed25519 key derived from seed.
func signEd25519(seed [32]byte, message []byte) []byte {
	priv := ed25519.NewKeyFromSeed(seed[:])
	return ed25519.Sign(priv, message)
}

// verifyEd25519 verifies an Ed25519 signature. Returns false (never panics)
// for a malformed public key.
func verifyEd25519(pub []byte, message, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}

// keyAlgorithmLabel is a key algorithm's label for error details; an
// unknown number is shown as its decimal value.
func keyAlgorithmLabel(algorithm api.KeyAlgorithm) string {
	if text, err := algorithm.MarshalText(); err == nil {
		return string(text)
	}
	return fmt.Sprintf("%d", int64(algorithm))
}

// resolveAndVerify resolves a wire algorithm and verifies a signature,
// returning a *LocalRpError classifying the failure. Only "ed25519" is
// supported today (liblinkkeys::crypto::SigningAlgorithm has exactly one
// variant); a new signing algorithm would be a new protocol mode with new
// context strings per the design doc, never a version bump of this one.
func resolveAndVerify(algorithm api.KeyAlgorithm, message, sig, pubKey []byte) error {
	if algorithm != api.KeyAlgorithmEd25519 {
		return &LocalRpError{Kind: ErrKindUnsupportedAlgorithm, Detail: keyAlgorithmLabel(algorithm)}
	}
	if !verifyEd25519(pubKey, message, sig) {
		return &LocalRpError{Kind: ErrKindSignatureInvalid}
	}
	return nil
}

// generateX25519Keypair generates a fresh X25519 encryption keypair — a
// *separate* key from any signing key, never algebraically derived (design
// doc: "Encryption Key Is Separate, Not Derived").
func generateX25519Keypair() (priv [32]byte, pub [32]byte, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return priv, pub, err
	}
	copy(priv[:], key.Bytes())
	copy(pub[:], key.PublicKey().Bytes())
	return priv, pub, nil
}

// x25519ECDH performs the X25519 Diffie-Hellman exchange. Go's crypto/ecdh
// already rejects an all-zero (low-order/non-contributory) result with an
// error (see crypto/ecdh.PrivateKey.ECDH docs: "If the result is the
// all-zero value, ECDH returns an error"), matching Wire Precision's
// requirement to reject a non-contributory ephemeral/recipient key.
func x25519ECDH(privBytes, pubBytes [32]byte) ([]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privBytes[:])
	if err != nil {
		return nil, err
	}
	pub, err := curve.NewPublicKey(pubBytes[:])
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// x25519PublicFromPrivate derives the X25519 public key for a private scalar
// — needed on the decrypting side to reconstruct the recipient's own public
// key for the KDF context (Wire Precision's `recipient_public(32)`).
func x25519PublicFromPrivate(privBytes [32]byte) ([32]byte, error) {
	var out [32]byte
	priv, err := ecdh.X25519().NewPrivateKey(privBytes[:])
	if err != nil {
		return out, err
	}
	copy(out[:], priv.PublicKey().Bytes())
	return out, nil
}

// AeadSuite is the negotiated AEAD suite registry (design doc, Wire
// Precision "AEAD suite registry"). It is the generated api.AeadSuite
// named-number enum: on the wire a suite is a CBOR unsigned integer
// (aes-256-gcm=1, chacha20-poly1305=2). The callback-box KDF context still
// binds the suite's text id (see AeadSuiteKDFLabel). Mirrors
// `liblinkkeys::crypto::AeadSuite`.
type AeadSuite = api.AeadSuite

const (
	// AeadSuiteAES256GCM is the mandatory-to-implement baseline.
	AeadSuiteAES256GCM = api.AeadSuiteAes256Gcm
	// AeadSuiteChaCha20Poly1305 is the optional second suite.
	AeadSuiteChaCha20Poly1305 = api.AeadSuiteChacha20Poly1305
)

// AeadSuiteKDFLabel returns the exact, case-sensitive text id the
// callback-box KDF context binds for suite ("aes-256-gcm",
// "chacha20-poly1305"). Returns false for a value outside the registry.
func AeadSuiteKDFLabel(suite AeadSuite) (string, bool) {
	switch suite {
	case AeadSuiteAES256GCM:
		return "aes-256-gcm", true
	case AeadSuiteChaCha20Poly1305:
		return "chacha20-poly1305", true
	default:
		return "", false
	}
}

// ParseAeadSuite parses a suite text id ("aes-256-gcm",
// "chacha20-poly1305"). Exact match only, never case-folded. Returns false
// for an id outside the registry.
func ParseAeadSuite(s string) (AeadSuite, bool) {
	switch s {
	case "aes-256-gcm":
		return AeadSuiteAES256GCM, true
	case "chacha20-poly1305":
		return AeadSuiteChaCha20Poly1305, true
	default:
		return 0, false
	}
}

// AllSupportedSuites returns every registry suite, in preference order
// (baseline first).
func AllSupportedSuites() []AeadSuite {
	return []AeadSuite{AeadSuiteAES256GCM, AeadSuiteChaCha20Poly1305}
}

// SelectSupportedSuite picks the first suite in advertised (preference
// order) that this implementation supports. Never returns a suite outside
// advertised, even if this implementation also supports it.
func SelectSupportedSuite(advertised []AeadSuite) (AeadSuite, bool) {
	for _, s := range advertised {
		if _, ok := AeadSuiteKDFLabel(s); ok {
			return s, true
		}
	}
	return 0, false
}

func containsSuite(suites []AeadSuite, target AeadSuite) bool {
	for _, s := range suites {
		if s == target {
			return true
		}
	}
	return false
}

func newAEAD(suite AeadSuite, key [32]byte) (cipher.AEAD, error) {
	switch suite {
	case AeadSuiteAES256GCM:
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case AeadSuiteChaCha20Poly1305:
		return chacha20poly1305.New(key[:])
	default:
		return nil, fmt.Errorf("unsupported AEAD suite: %d", suite)
	}
}

// aeadEncrypt encrypts under suite, dispatching to the concrete AEAD
// implementation. Shared dispatch point for both suites, mirroring
// `liblinkkeys::crypto::aead_encrypt`.
func aeadEncrypt(suite AeadSuite, key [32]byte, nonce [12]byte, aad, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

// aeadDecrypt decrypts under suite. See aeadEncrypt.
func aeadDecrypt(suite AeadSuite, key [32]byte, nonce [12]byte, aad, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce[:], ciphertext, aad)
}

// localRpCallbackBoxTag is the domain-separation tag for the local-RP
// callback sealed box (Wire Precision), distinct from liblinkkeys' generic
// sealed-box tag: this construction additionally binds the negotiated suite
// id into the KDF context, and binds the cleartext header into the AEAD
// associated data.
const localRpCallbackBoxTag = "linkkeys-local-rp-callback-box-v1alpha"

// localRpCallbackKDF derives the AEAD key for the local-RP callback sealed
// box via HKDF-SHA256, and returns the context bytes that double as the AEAD
// associated-data prefix. Layout (Wire Precision, "Callback sealed box"):
// `tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)`.
func localRpCallbackKDF(suite AeadSuite, ephemeralPublic, recipientPublic [32]byte, sharedSecret []byte) (key [32]byte, context []byte, err error) {
	suiteID, ok := AeadSuiteKDFLabel(suite)
	if !ok {
		return key, nil, fmt.Errorf("unsupported AEAD suite: %d", suite)
	}
	context = make([]byte, 0, len(localRpCallbackBoxTag)+len(suiteID)+64)
	context = append(context, []byte(localRpCallbackBoxTag)...)
	context = append(context, []byte(suiteID)...)
	context = append(context, ephemeralPublic[:]...)
	context = append(context, recipientPublic[:]...)

	// HKDF-SHA256(salt=none, ikm=shared_secret).expand(info=context, 32
	// bytes) — crypto/hkdf.Key with a nil salt performs Extract with the
	// RFC 5869 default (zero-filled) salt then Expand, matching Rust's
	// `Hkdf::<Sha256>::new(None, shared_secret)` + `expand`.
	derived, err := hkdf.Key(sha256.New, sharedSecret, nil, string(context), 32)
	if err != nil {
		return key, nil, err
	}
	copy(key[:], derived)
	return key, context, nil
}
