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

// ActAsErrorKind mirrors `liblinkkeys::act_as::ActAsError`'s variants.
type ActAsErrorKind string

const (
	// ErrActAsDecode: an embedded CBOR payload did not decode.
	ErrActAsDecode ActAsErrorKind = "decode"
	// ErrActAsBadTimestamp: a timestamp field was not RFC3339.
	ErrActAsBadTimestamp ActAsErrorKind = "bad_timestamp"
	// ErrActAsMalformedGrantee: a GranteeRef or GranteeProof did not carry
	// exactly one form.
	ErrActAsMalformedGrantee ActAsErrorKind = "malformed_grantee"
	// ErrActAsProofDoesNotMatchGrantee: the proof's form does not match the
	// grantee's form.
	ErrActAsProofDoesNotMatchGrantee ActAsErrorKind = "proof_does_not_match_grantee"
	// ErrActAsUntrustedSigner: the signing key is not a valid key of the
	// expected party.
	ErrActAsUntrustedSigner ActAsErrorKind = "untrusted_signer"
	// ErrActAsBadSignature: a signature did not verify.
	ErrActAsBadSignature ActAsErrorKind = "bad_signature"
	// ErrActAsNoValidSignature: no signature on a multi-signed structure came
	// from an acceptable key. Detail names each signing key and why it was
	// refused.
	ErrActAsNoValidSignature ActAsErrorKind = "no_valid_signature"
	// ErrActAsBadHandleClaim: a handle claim is malformed, about another
	// account, or did not verify.
	ErrActAsBadHandleClaim ActAsErrorKind = "bad_handle_claim"
	// ErrActAsMismatch: a field did not equal the value the verifier
	// expected. Field names the field.
	ErrActAsMismatch ActAsErrorKind = "mismatch"
	// ErrActAsBadScopeSet: a scope set is empty, too large, or repeats a
	// scope.
	ErrActAsBadScopeSet ActAsErrorKind = "bad_scope_set"
	// ErrActAsBadApprovedScope: the approved scope is empty, repeats a
	// scope, or names a scope outside the scope set.
	ErrActAsBadApprovedScope ActAsErrorKind = "bad_approved_scope"
	// ErrActAsRequestExpired: a request or presentation is outside its time
	// window.
	ErrActAsRequestExpired ActAsErrorKind = "request_expired"
	// ErrActAsScopeSetExpired: the scope set has expired. Applies only at
	// approval.
	ErrActAsScopeSetExpired ActAsErrorKind = "scope_set_expired"
	// ErrActAsGrantExpired: the grant has expired.
	ErrActAsGrantExpired ActAsErrorKind = "grant_expired"
	// ErrActAsGrantRevoked: the grant is revoked.
	ErrActAsGrantRevoked ActAsErrorKind = "grant_revoked"
	// ErrActAsBadTerms: a lifetime or renewal window is not positive, or
	// exceeds a bound.
	ErrActAsBadTerms ActAsErrorKind = "bad_terms"
	// ErrActAsDeviceBindingUnsupported: the grant carries a device binding.
	// Device keys are Reserved, so no verifier can check one yet.
	ErrActAsDeviceBindingUnsupported ActAsErrorKind = "device_binding_unsupported"
	// ErrActAsCrypto: a cryptographic primitive failed.
	ErrActAsCrypto ActAsErrorKind = "crypto"
)

// ActAsError is an act-as grant verification or construction failure. Like
// every error in this package, it carries no key material, nonce, or scope
// value: only the kind, a field name, and a short detail.
type ActAsError struct {
	Kind ActAsErrorKind
	// Field is set for ErrActAsMismatch.
	Field string
	// Detail is a short, non-sensitive explanation.
	Detail string
}

func (e *ActAsError) Error() string {
	switch {
	case e.Kind == ErrActAsMismatch:
		return fmt.Sprintf("act-as: %s does not match the expected value", e.Field)
	case e.Detail != "":
		return fmt.Sprintf("act-as: %s: %s", e.Kind, e.Detail)
	default:
		return fmt.Sprintf("act-as: %s", e.Kind)
	}
}
