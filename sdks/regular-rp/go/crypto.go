package regularrp

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Crypto primitives this SDK needs, mirroring
// crates/liblinkkeys/src/crypto.rs's fingerprint/keypair/sign/verify helpers
// and the sealed-box construction application_keys::seal_challenge /
// open_challenge builds on top of it. Deliberately only the subset the
// application-key protocol needs: Ed25519 signing, X25519 key agreement, and
// the ChaCha20-Poly1305 sealed box (CHALLENGE_SEAL_SUITE is fixed, not
// negotiated — see doc.go and go.mod's dependency note).

const algorithmEd25519 = "ed25519"
const algorithmX25519 = "x25519"

// Fingerprint is `sha256(public_key_bytes)`, lowercase hex — the canonical
// LinkKeys fingerprint format. Matches `liblinkkeys::crypto::fingerprint`
// exactly.
func Fingerprint(publicKeyBytes []byte) string {
	sum := sha256.Sum256(publicKeyBytes)
	return hex.EncodeToString(sum[:])
}

// GenerateEd25519KeyPair generates a fresh Ed25519 signing keypair. The
// private key is returned as its 32-byte seed (Ed25519's "private key" IS
// its 32-byte seed).
func GenerateEd25519KeyPair() (publicKey [32]byte, seed [32]byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return publicKey, seed, err
	}
	copy(publicKey[:], pub)
	copy(seed[:], priv.Seed())
	return publicKey, seed, nil
}

// GenerateX25519KeyPair generates a fresh X25519 key-agreement keypair — a
// dedicated encryption key, never derived from a signing key (mirrors
// `liblinkkeys::crypto::generate_x25519_keypair`).
func GenerateX25519KeyPair() (publicKey [32]byte, privateKey [32]byte, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return publicKey, privateKey, err
	}
	copy(privateKey[:], key.Bytes())
	copy(publicKey[:], key.PublicKey().Bytes())
	return publicKey, privateKey, nil
}

func signEd25519(seed [32]byte, message []byte) []byte {
	priv := ed25519.NewKeyFromSeed(seed[:])
	return ed25519.Sign(priv, message)
}

func verifyEd25519(pub []byte, message, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}

// signWithAlgorithm signs message with privateKeyBytes under algorithm.
// Mirrors `liblinkkeys::crypto::sign_with_algorithm` — only "ed25519" is a
// signing algorithm (x25519 keys cannot sign).
func signWithAlgorithm(algorithm string, message []byte, privateKeyBytes []byte) ([]byte, error) {
	if algorithm != algorithmEd25519 {
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: fmt.Sprintf("unsupported signing algorithm: %s", algorithm)}
	}
	if len(privateKeyBytes) != ed25519.SeedSize {
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: "invalid ed25519 private key length"}
	}
	var seed [32]byte
	copy(seed[:], privateKeyBytes)
	return signEd25519(seed, message), nil
}

// resolveAndVerify resolves a wire algorithm string and verifies a
// signature. Mirrors `liblinkkeys::crypto::resolve_and_verify` — only
// "ed25519" is a supported/verifiable signing algorithm.
func resolveAndVerify(algorithm string, message, sig, pubKey []byte) error {
	if algorithm != algorithmEd25519 {
		return &ApplicationKeyError{Kind: ErrCrypto, Detail: fmt.Sprintf("unsupported signing algorithm: %s", algorithm)}
	}
	if !verifyEd25519(pubKey, message, sig) {
		return &ApplicationKeyError{Kind: ErrCrypto, Detail: "signature verification failed"}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The sealed challenge (X25519 proof of possession) — recipient side
// ---------------------------------------------------------------------------

// challengeSealSuite is CHALLENGE_SEAL_SUITE from
// crates/liblinkkeys/src/application_keys.rs: fixed, not negotiated — there
// is no handshake in which to agree a suite for a one-shot box from the home
// domain to the application.
const challengeSealSuite = "chacha20-poly1305"

// sealedBoxTag is SEALED_BOX_TAG from crates/liblinkkeys/src/crypto.rs.
const sealedBoxTag = "linkkeys-sealed-box-v1alpha"

// sealedBoxKDF derives the AEAD key for a sealed box via HKDF-SHA256, and
// returns the context bytes that double as AEAD associated data (AAD).
// Layout: `tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)`
// — mirrors `liblinkkeys::crypto::sealed_box_kdf` exactly.
func sealedBoxKDF(suite string, ephemeralPublic, recipientPublic [32]byte, sharedSecret []byte) (key [32]byte, context []byte, err error) {
	context = make([]byte, 0, len(sealedBoxTag)+len(suite)+64)
	context = append(context, []byte(sealedBoxTag)...)
	context = append(context, []byte(suite)...)
	context = append(context, ephemeralPublic[:]...)
	context = append(context, recipientPublic[:]...)

	derived, err := hkdf.Key(sha256.New, sharedSecret, nil, string(context), 32)
	if err != nil {
		return key, nil, err
	}
	copy(key[:], derived)
	return key, context, nil
}

// rejectLowOrder rejects a non-contributory / low-order ECDH result (an
// all-zero shared secret), which a malicious peer can force by supplying a
// low-order point. Mirrors `liblinkkeys::crypto::reject_low_order`.
func rejectLowOrder(sharedSecret []byte) error {
	allZero := true
	for _, b := range sharedSecret {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return &ApplicationKeyError{Kind: ErrCrypto, Detail: "non-contributory (low-order) public key rejected"}
	}
	return nil
}

// sealedBoxDecrypt decrypts a sealed box addressed to recipientPrivate.
// Mirrors `liblinkkeys::crypto::sealed_box_decrypt`, fixed to the
// ChaCha20-Poly1305 suite (the only suite this SDK's callers — the X25519
// application-key challenge — ever use).
func sealedBoxDecrypt(ephemeralPublic, nonce, ciphertext []byte, recipientPrivate [32]byte, suite string) ([]byte, error) {
	if suite != challengeSealSuite {
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: fmt.Sprintf("unsupported sealed challenge suite: %s", suite)}
	}
	if len(ephemeralPublic) != 32 {
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: "invalid ephemeral key length"}
	}
	if len(nonce) != 12 {
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: "invalid nonce length"}
	}

	curve := ecdh.X25519()
	recipientKey, err := curve.NewPrivateKey(recipientPrivate[:])
	if err != nil {
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: "invalid recipient private key: " + err.Error()}
	}
	ephemeralKey, err := curve.NewPublicKey(ephemeralPublic)
	if err != nil {
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: "invalid ephemeral public key: " + err.Error()}
	}
	sharedSecret, err := recipientKey.ECDH(ephemeralKey)
	if err != nil {
		// crypto/ecdh already rejects an all-zero (non-contributory) result.
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: "ECDH failed: " + err.Error()}
	}
	if err := rejectLowOrder(sharedSecret); err != nil {
		return nil, err
	}

	var recipientPublicArr, ephemeralPublicArr [32]byte
	copy(recipientPublicArr[:], recipientKey.PublicKey().Bytes())
	copy(ephemeralPublicArr[:], ephemeralPublic)

	aeadKey, aad, err := sealedBoxKDF(suite, ephemeralPublicArr, recipientPublicArr, sharedSecret)
	if err != nil {
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: "HKDF derivation failed: " + err.Error()}
	}

	aead, err := chacha20poly1305.New(aeadKey[:])
	if err != nil {
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: err.Error()}
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, &ApplicationKeyError{Kind: ErrCrypto, Detail: "decryption failed: " + err.Error()}
	}
	return plaintext, nil
}
