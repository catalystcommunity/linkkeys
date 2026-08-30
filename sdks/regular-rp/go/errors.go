package regularrp

import "fmt"

// This file defines the SDK's typed error taxonomy. Every fallible
// operation in this package returns a plain `error`, concretely one of the
// types below. Callers that need to distinguish failure classes should use
// `errors.As` against the concrete type.
//
// Per AGENTS.md's error-handling rule ("Never log sensitive information"):
// none of these types carry key material, nonces, challenges, or claim
// values — only enough context (key ids, field names, short messages) to
// explain what failed.

// ApplicationKeyErrorKind mirrors
// `liblinkkeys::application_keys::ApplicationKeyError`'s variants (the
// subset this SDK's read/build side can produce — this package never
// verifies an addition/renewal/enrollment request, that is a home-domain
// server operation, so the variants unique to that path are not
// represented here).
type ApplicationKeyErrorKind string

const (
	// ErrDecode: a CBOR payload (attestation, sealed challenge) did not
	// decode.
	ErrDecode ApplicationKeyErrorKind = "decode"
	// ErrBadTimestamp: a timestamp field was not RFC3339.
	ErrBadTimestamp ApplicationKeyErrorKind = "bad_timestamp"
	// ErrIdentityMismatch: a signed payload names a different subject,
	// domain, application, or instance than the one being operated on.
	ErrIdentityMismatch ApplicationKeyErrorKind = "identity_mismatch"
	// ErrRequestExpired: the request's own validity window does not
	// contain `now`.
	ErrRequestExpired ApplicationKeyErrorKind = "request_expired"
	// ErrInsufficientSignatures: fewer than the required number of
	// DISTINCT valid signatures verified.
	ErrInsufficientSignatures ApplicationKeyErrorKind = "insufficient_signatures"
	// ErrMissingPossessionProof: the new or target key proved nothing
	// about its private key.
	ErrMissingPossessionProof ApplicationKeyErrorKind = "missing_possession_proof"
	// ErrBadPossessionProof: a possession proof was supplied where none
	// is possible, or it did not verify.
	ErrBadPossessionProof ApplicationKeyErrorKind = "bad_possession_proof"
	// ErrUsageMismatch: key_usage and algorithm do not agree, or do not
	// match the operation.
	ErrUsageMismatch ApplicationKeyErrorKind = "usage_mismatch"
	// ErrFingerprintMismatch: the stated fingerprint is not the
	// fingerprint of the stated public key.
	ErrFingerprintMismatch ApplicationKeyErrorKind = "fingerprint_mismatch"
	// ErrUnknownKey: the named key is not a key of this instance.
	ErrUnknownKey ApplicationKeyErrorKind = "unknown_key"
	// ErrKeyRevoked: the key is revoked, and revocation is permanent.
	ErrKeyRevoked ApplicationKeyErrorKind = "key_revoked"
	// ErrKeyExpired: the key's own validity window has passed.
	ErrKeyExpired ApplicationKeyErrorKind = "key_expired"
	// ErrAttestationExpired: the attestation's validity window has
	// passed. This is NOT a revocation — a renewed attestation can make
	// the same unrevoked key acceptable again.
	ErrAttestationExpired ApplicationKeyErrorKind = "attestation_expired"
	// ErrUntrustedAttestation: no signature from a currently valid domain
	// signing key verified.
	ErrUntrustedAttestation ApplicationKeyErrorKind = "untrusted_attestation"
	// ErrDuplicateKey: the same key id appeared twice where distinct keys
	// are required.
	ErrDuplicateKey ApplicationKeyErrorKind = "duplicate_key"
	// ErrBadConfiguration: a configured value is self-defeating (e.g. a
	// non-positive requested key lifetime).
	ErrBadConfiguration ApplicationKeyErrorKind = "bad_configuration"
	// ErrCrypto: a low-level cryptographic operation failed (bad key
	// length, unsupported algorithm, AEAD failure, ...).
	ErrCrypto ApplicationKeyErrorKind = "crypto"
)

// ApplicationKeyError is an application-key protocol verification or
// construction failure.
type ApplicationKeyError struct {
	Kind ApplicationKeyErrorKind
	// Field is set for ErrIdentityMismatch / ErrUsageMismatch.
	Field string
	// Detail is a short, non-sensitive explanation.
	Detail string
	// Got/Need are set for ErrInsufficientSignatures.
	Got, Need int
}

func (e *ApplicationKeyError) Error() string {
	switch e.Kind {
	case ErrIdentityMismatch:
		return fmt.Sprintf("application key request is bound to a different %s", e.Field)
	case ErrInsufficientSignatures:
		return fmt.Sprintf("%d distinct valid application key signatures; %d required", e.Got, e.Need)
	case ErrUsageMismatch:
		return fmt.Sprintf("key use mismatch: %s", e.Detail)
	default:
		if e.Detail != "" {
			return fmt.Sprintf("application key: %s: %s", e.Kind, e.Detail)
		}
		return fmt.Sprintf("application key: %s", e.Kind)
	}
}

// TransportError: the TCP transport could not reach the configured RP.
type TransportError struct{ Detail string }

func (e *TransportError) Error() string { return "transport error: " + e.Detail }

// TLSError: TLS handshake or certificate fingerprint pinning failed.
type TLSError struct{ Detail string }

func (e *TLSError) Error() string { return "TLS error: " + e.Detail }

// ProtocolError: the CSIL-RPC envelope could not be encoded/decoded, or the
// wire framing was malformed.
type ProtocolError struct{ Detail string }

func (e *ProtocolError) Error() string { return "protocol error: " + e.Detail }

// ServerError: the RP returned a non-Ok RPC transport status.
type ServerError struct {
	Status  int64
	Message string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("server error (%d): %s", e.Status, e.Message)
}

// DecodeError: CBOR decoding of a stored or wire structure failed.
type DecodeError struct{ Detail string }

func (e *DecodeError) Error() string { return "decode error: " + e.Detail }

// NoCachedResultError: the resolver could not reach the RP and has nothing
// previously verified for this instance to fall back to.
type NoCachedResultError struct{ Detail string }

func (e *NoCachedResultError) Error() string {
	return "no cached application keys available: " + e.Detail
}

// RevocationError: a sibling-signed domain-key revocation certificate did
// not meet quorum. Mirrors `liblinkkeys::revocation::RevocationError`.
type RevocationError struct {
	Got  int
	Need int
}

func (e *RevocationError) Error() string {
	return fmt.Sprintf("domain key revocation certificate has %d valid sibling signatures; %d required", e.Got, e.Need)
}
