package localrp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// GenerateLocalRpIdentity and the raw-byte storage helpers (design doc:
// "SDK API Shape", "Byte Storage Helpers"). Mirrors
// sdks/local-rp/rust/src/identity.rs.
//
// A local RP identity is exactly one Ed25519 signing keypair, one X25519
// encryption keypair, and a self-signed SignedLocalRpDescriptor binding them
// together. There is no continuity story across rotation — generating a new
// identity means a new fingerprint, full stop.
//
// Security note (design doc, "Byte Storage Helpers"): the private key
// fields in LocalRpKeyMaterial do not directly identify a user, but they
// control this app's entire local RP identity — anyone holding them can
// sign login requests and redeem claim tickets as this app. Store them with
// ordinary application-secret care (the same care as a database credential
// or API key), not merely as configuration.

// DefaultLifetime is the default local RP key lifetime: 10 years (design
// doc, "One Signing Key and One Encryption Key" — "Default lifetime: 10
// years. Rotation is a deliberate operator event.").
const DefaultLifetime = 3650 * 24 * time.Hour

// GenerateLocalRpIdentityConfig is the input to GenerateLocalRpIdentity.
// Big-config, single struct, per the design doc's "SDK API Shape".
type GenerateLocalRpIdentityConfig struct {
	// AppName is the display name shown on the IDP's consent screen. NOT
	// identity — the design doc is explicit that approval keys on the
	// fingerprint alone; this is audit/display metadata only.
	AppName string
	// LocalDomainHint is an optional local domain/origin hint (e.g.
	// "jukebox.lan"), also display/audit metadata, never an identity input.
	LocalDomainHint *string
	// SupportedSuites are the AEAD suites this app can decrypt callbacks
	// with, in preference order. Defaults to both registry suites
	// (aes-256-gcm first, mandatory baseline; chacha20-poly1305 second,
	// optional) when nil.
	SupportedSuites []string
	// Lifetime is the key/descriptor lifetime from Now. Defaults to
	// DefaultLifetime (10 years) when zero.
	Lifetime time.Duration
	// Now is the current time — never read from the system clock inside
	// this package's pure logic, so callers control determinism.
	Now time.Time
}

// LocalRpKeyMaterial is a local RP's full key material: signing keypair,
// encryption keypair, the self-signed descriptor binding them (which also
// carries app_name, local_domain_hint, supported_suites, and the
// created/expires timestamps), and the identity fingerprint.
type LocalRpKeyMaterial struct {
	SigningPrivateKey    [32]byte // Ed25519 seed
	SigningPublicKey     [32]byte
	EncryptionPrivateKey [32]byte
	EncryptionPublicKey  [32]byte
	// Descriptor is the self-signed envelope, reused as-is in every
	// BeginLocalLogin call rather than re-signed per login, so the
	// identity's descriptor stays a single stable object for the key's
	// whole lifetime.
	Descriptor api.SignedLocalRpDescriptor
	// Fingerprint is sha256(signing_public_key) hex — the canonical
	// identity anchor.
	Fingerprint string
}

// GenerateLocalRpIdentity implements `generate_local_rp_identity(config) ->
// LocalRpKeyMaterial` (design doc, "SDK API Shape"). Generates a fresh
// Ed25519 signing keypair and a *separate* X25519 encryption keypair (never
// algebraically derived), builds and self-signs the SignedLocalRpDescriptor
// binding them, and returns everything the app needs to persist.
func GenerateLocalRpIdentity(config GenerateLocalRpIdentityConfig) (*LocalRpKeyMaterial, error) {
	if strings.TrimSpace(config.AppName) == "" {
		return nil, &InvalidInputError{Detail: "app_name must not be empty"}
	}

	signingPublicKey, signingPrivateKey, err := generateEd25519Keypair()
	if err != nil {
		return nil, err
	}
	encryptionPrivateKey, encryptionPublicKey, err := generateX25519Keypair()
	if err != nil {
		return nil, err
	}

	suites := config.SupportedSuites
	if suites == nil {
		suites = AllSupportedSuites()
	}
	if len(suites) == 0 {
		return nil, &InvalidInputError{Detail: "supported_suites must not be empty"}
	}

	lifetime := config.Lifetime
	if lifetime == 0 {
		lifetime = DefaultLifetime
	}
	createdAt := config.Now.UTC().Format(time.RFC3339Nano)
	expiresAt := config.Now.Add(lifetime).UTC().Format(time.RFC3339Nano)

	descriptor := BuildLocalRpDescriptor(config.AppName, config.LocalDomainHint, signingPublicKey, encryptionPublicKey, suites, createdAt, expiresAt)
	fingerprint := descriptor.Fingerprint
	signedDescriptor := SignLocalRpDescriptor(descriptor, signingPrivateKey)

	return &LocalRpKeyMaterial{
		SigningPrivateKey:    signingPrivateKey,
		SigningPublicKey:     signingPublicKey,
		EncryptionPrivateKey: encryptionPrivateKey,
		EncryptionPublicKey:  encryptionPublicKey,
		Descriptor:           signedDescriptor,
		Fingerprint:          fingerprint,
	}, nil
}

// ---------------------------------------------------------------------
// Byte storage helpers (design doc: "Byte Storage Helpers")
// ---------------------------------------------------------------------

// SigningKeyToBytes returns the raw 32-byte signing key (public or private)
// bytes.
func SigningKeyToBytes(key [32]byte) []byte { return append([]byte{}, key[:]...) }

// SigningKeyFromBytes parses a raw 32-byte signing key. Errors if the input
// is not exactly 32 bytes.
func SigningKeyFromBytes(b []byte) ([32]byte, error) {
	var out [32]byte
	if len(b) != 32 {
		return out, &InvalidInputError{Detail: fmt.Sprintf("signing key must be 32 bytes, got %d", len(b))}
	}
	copy(out[:], b)
	return out, nil
}

// EncryptionKeyToBytes returns the raw 32-byte encryption key (public or
// private) bytes.
func EncryptionKeyToBytes(key [32]byte) []byte { return append([]byte{}, key[:]...) }

// EncryptionKeyFromBytes parses a raw 32-byte encryption key. Errors if the
// input is not exactly 32 bytes.
func EncryptionKeyFromBytes(b []byte) ([32]byte, error) {
	var out [32]byte
	if len(b) != 32 {
		return out, &InvalidInputError{Detail: fmt.Sprintf("encryption key must be 32 bytes, got %d", len(b))}
	}
	copy(out[:], b)
	return out, nil
}

// FingerprintToString is the canonical fingerprint string form — a
// pass-through, since in this SDK the fingerprint IS a hex string (design
// doc: "fingerprint: hex string ... the existing LinkKeys fingerprint
// format, everywhere, with no bytes variant").
func FingerprintToString(fingerprint string) string { return fingerprint }

// FingerprintFromString parses/validates a fingerprint string: exactly 64
// lowercase-normalized hex characters (a SHA-256 digest). Rejects anything
// else so a malformed value can never silently pass as a pin or an
// identity.
func FingerprintFromString(s string) (string, error) {
	if !IsValidFingerprint(s) {
		return "", &InvalidInputError{Detail: fmt.Sprintf("not a valid fingerprint (want 64 hex chars): %q", s)}
	}
	return strings.ToLower(s), nil
}

// identityBundleMagic is the magic prefix for the identity-bundle byte
// format below. This is an SDK-local storage convenience, NOT a protocol
// wire format — nothing in dns-less-local-rp-design.md's Wire Precision
// governs it, and no conformance vector covers it. Versioned so a future
// incompatible layout change fails loudly instead of silently misparsing.
var identityBundleMagic = []byte("LKI1")

// LocalRpIdentityToBytes implements `local_rp_identity_to_bytes(identity) ->
// bytes` (design doc, "SDK API Shape" + "Byte Storage Helpers": "identity
// bundle"). Packs both private keys and the signed descriptor (which
// already carries both public keys, app_name, local_domain_hint,
// supported_suites, and the created/expires timestamps) into one opaque
// blob an app can store as a single secret/config value. Layout:
// `MAGIC(4) || signing_private_key(32) || encryption_private_key(32) ||
// descriptor_len(4, BE) || descriptor_cbor`.
func LocalRpIdentityToBytes(identity *LocalRpKeyMaterial) []byte {
	descriptorBytes := api.EncodeSignedLocalRpDescriptor(identity.Descriptor)
	out := make([]byte, 0, 4+32+32+4+len(descriptorBytes))
	out = append(out, identityBundleMagic...)
	out = append(out, identity.SigningPrivateKey[:]...)
	out = append(out, identity.EncryptionPrivateKey[:]...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(descriptorBytes)))
	out = append(out, lenBuf[:]...)
	out = append(out, descriptorBytes...)
	return out
}

// LocalRpIdentityFromBytes is the inverse of LocalRpIdentityToBytes. Public
// keys and the fingerprint are read back out of the embedded descriptor
// rather than re-derived from the private keys, exactly mirroring what was
// stored; this function does no signature/expiry verification (that is
// CheckExpirations's and the protocol verification chain's job).
func LocalRpIdentityFromBytes(b []byte) (*LocalRpKeyMaterial, error) {
	const headerLen = 4 + 32 + 32 + 4
	if len(b) < headerLen {
		return nil, &InvalidInputError{Detail: "identity bundle too short"}
	}
	if !bytes.Equal(b[0:4], identityBundleMagic) {
		return nil, &InvalidInputError{Detail: "identity bundle has an unrecognized magic prefix"}
	}

	var signingPriv, encPriv [32]byte
	copy(signingPriv[:], b[4:36])
	copy(encPriv[:], b[36:68])
	descLen := binary.BigEndian.Uint32(b[68:72])

	if uint64(headerLen)+uint64(descLen) > uint64(len(b)) {
		return nil, &InvalidInputError{Detail: "identity bundle descriptor length exceeds available bytes"}
	}
	descriptorBytes := b[headerLen : uint64(headerLen)+uint64(descLen)]

	signedDescriptor, err := api.DecodeSignedLocalRpDescriptor(descriptorBytes)
	if err != nil {
		return nil, &DecodeError{Detail: "identity bundle descriptor: " + err.Error()}
	}
	descriptor, err := api.DecodeLocalRpDescriptor(signedDescriptor.Descriptor)
	if err != nil {
		return nil, &DecodeError{Detail: "identity bundle descriptor payload: " + err.Error()}
	}

	if len(descriptor.SigningPublicKey) != 32 {
		return nil, &InvalidInputError{Detail: "descriptor signing_public_key was not 32 bytes"}
	}
	if len(descriptor.EncryptionPublicKey) != 32 {
		return nil, &InvalidInputError{Detail: "descriptor encryption_public_key was not 32 bytes"}
	}
	var signingPub, encPub [32]byte
	copy(signingPub[:], descriptor.SigningPublicKey)
	copy(encPub[:], descriptor.EncryptionPublicKey)

	return &LocalRpKeyMaterial{
		SigningPrivateKey:    signingPriv,
		SigningPublicKey:     signingPub,
		EncryptionPrivateKey: encPriv,
		EncryptionPublicKey:  encPub,
		Descriptor:           signedDescriptor,
		Fingerprint:          descriptor.Fingerprint,
	}, nil
}

// CheckExpirations implements `check_expirations(identity, now) ->
// ExpirationStatus` (design doc, "SDK API Shape" / "Expiration Helper").
// Thin wrapper over CheckExpirationsAt, taking the identity's descriptor
// expires_at directly. The SDK reports facts; the app decides whether to
// warn admins, warn users, block login, renew, or ignore.
func CheckExpirations(identity *LocalRpKeyMaterial, now time.Time) (*ExpirationStatus, error) {
	descriptor, err := api.DecodeLocalRpDescriptor(identity.Descriptor.Descriptor)
	if err != nil {
		return nil, &DecodeError{Detail: "identity descriptor: " + err.Error()}
	}
	return CheckExpirationsAt(descriptor.ExpiresAt, now)
}
