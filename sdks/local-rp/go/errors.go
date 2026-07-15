package localrp

import "fmt"

// This file defines the SDK's typed error taxonomy. Every fallible operation
// in this package returns a plain `error`, concretely one of the types below
// (or occasionally a wrapped stdlib error for a boundary failure like DNS
// resolution or a socket error). Callers that need to distinguish failure
// classes (as the flow tests do, mirroring the Rust SDK's
// `matches!(err, Error::Verification(_))` style assertions) should use
// `errors.As` against the concrete type.
//
// Per AGENTS.md's error-handling rule ("Never log sensitive information"):
// none of these types carry key material, nonces, tokens, tickets, or claim
// values — only enough context (domain names, field names, short messages)
// to explain what failed.

// InvalidInputError: a field the caller supplied was structurally invalid
// (bad key length, malformed fingerprint string, empty required list, etc).
type InvalidInputError struct{ Detail string }

func (e *InvalidInputError) Error() string { return "invalid input: " + e.Detail }

// DecodeError: CBOR decoding of a stored or wire structure failed.
type DecodeError struct{ Detail string }

func (e *DecodeError) Error() string { return "decode error: " + e.Detail }

// DNSError: a DNS TXT lookup failed (network/resolver failure, not a parse
// failure — see DnsParseError for record-format problems).
type DNSError struct{ Detail string }

func (e *DNSError) Error() string { return "DNS error: " + e.Detail }

// TransportError: the TCP transport could not reach a domain's endpoint.
type TransportError struct{ Detail string }

func (e *TransportError) Error() string { return "transport error: " + e.Detail }

// TLSError: TLS handshake or certificate fingerprint pinning failed.
type TLSError struct{ Detail string }

func (e *TLSError) Error() string { return "TLS error: " + e.Detail }

// ProtocolError: the CSIL-RPC envelope could not be encoded/decoded, or the
// wire framing was malformed.
type ProtocolError struct{ Detail string }

func (e *ProtocolError) Error() string { return "protocol error: " + e.Detail }

// ServerError: the peer returned a non-Ok RPC transport status.
type ServerError struct {
	Status  int64
	Message string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("server error (%d): %s", e.Status, e.Message)
}

// NoTrustedDomainKeysError: no trustworthy domain keys were established for a
// domain (DNS pin matched nothing, or vouch verification failed for every
// candidate).
type NoTrustedDomainKeysError struct{ Domain string }

func (e *NoTrustedDomainKeysError) Error() string {
	return "no trusted public keys could be established for domain: " + e.Domain
}

// RevocationError: a sibling-signed revocation certificate did not meet
// quorum.
type RevocationError struct {
	Got  int
	Need int
}

func (e *RevocationError) Error() string {
	return fmt.Sprintf("revocation certificate has %d valid sibling signatures; %d required", e.Got, e.Need)
}

// LocalRpErrorKind mirrors liblinkkeys::local_rp::LocalRpError's variants —
// see crates/liblinkkeys/src/local_rp.rs. Go doesn't have sum-typed enums, so
// this package uses the common "tagged struct" idiom instead: a fixed set of
// exported Kind constants plus a Detail string for context.
type LocalRpErrorKind string

const (
	ErrKindDecode                LocalRpErrorKind = "decode"
	ErrKindInvalidKeyLength      LocalRpErrorKind = "invalid_key_length"
	ErrKindFingerprintMismatch   LocalRpErrorKind = "fingerprint_mismatch"
	ErrKindNotYetValid           LocalRpErrorKind = "not_yet_valid"
	ErrKindExpired               LocalRpErrorKind = "expired"
	ErrKindBadTimestamp          LocalRpErrorKind = "bad_timestamp"
	ErrKindNonceMismatch         LocalRpErrorKind = "nonce_mismatch"
	ErrKindStateMismatch         LocalRpErrorKind = "state_mismatch"
	ErrKindAudienceMismatch      LocalRpErrorKind = "audience_mismatch"
	ErrKindIssuerMismatch        LocalRpErrorKind = "issuer_mismatch"
	ErrKindCallbackURLMismatch   LocalRpErrorKind = "callback_url_mismatch"
	ErrKindUnsupportedSuite      LocalRpErrorKind = "unsupported_suite"
	ErrKindSuiteNotAdvertised    LocalRpErrorKind = "suite_not_advertised"
	ErrKindHeaderPayloadMismatch LocalRpErrorKind = "header_payload_mismatch"
	ErrKindSignatureInvalid      LocalRpErrorKind = "signature_invalid"
	ErrKindKeyNotFound           LocalRpErrorKind = "key_not_found"
	ErrKindKeyRevoked            LocalRpErrorKind = "key_revoked"
	ErrKindKeyExpired            LocalRpErrorKind = "key_expired"
	ErrKindUnsupportedAlgorithm  LocalRpErrorKind = "unsupported_algorithm"
	ErrKindCrypto                LocalRpErrorKind = "crypto"
	// ErrKindRedemptionIdentityMismatch: the ticket-redemption response's
	// user_id/user_domain did not match the domain-signature-verified
	// callback payload's user_id/user_domain. A stolen/substituted ticket,
	// or a compromised/malicious IDP answering a redemption for a different
	// user than the one who authenticated, must never be attributed to this
	// login.
	ErrKindRedemptionIdentityMismatch LocalRpErrorKind = "redemption_identity_mismatch"
)

// LocalRpError is a local-RP protocol verification failure (signature,
// envelope, timestamp, nonce/state, audience, issuer, callback URL, suite
// negotiation).
type LocalRpError struct {
	Kind   LocalRpErrorKind
	Detail string
}

func (e *LocalRpError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("local-rp: %s: %s", e.Kind, e.Detail)
	}
	return fmt.Sprintf("local-rp: %s", e.Kind)
}

// ClaimErrorKind mirrors liblinkkeys::claims::ClaimError's variants.
type ClaimErrorKind string

const (
	ClaimErrKindSignatureInvalid      ClaimErrorKind = "signature_invalid"
	ClaimErrKindUnsupportedAlgorithm  ClaimErrorKind = "unsupported_algorithm"
	ClaimErrKindKeyNotFound           ClaimErrorKind = "key_not_found"
	ClaimErrKindKeyRevoked            ClaimErrorKind = "key_revoked"
	ClaimErrKindKeyExpired            ClaimErrorKind = "key_expired"
	ClaimErrKindRevoked               ClaimErrorKind = "revoked"
	ClaimErrKindExpired               ClaimErrorKind = "expired"
	ClaimErrKindBadExpiry             ClaimErrorKind = "bad_expiry"
	ClaimErrKindUnsigned              ClaimErrorKind = "unsigned"
	ClaimErrKindDomainKeysUnavailable ClaimErrorKind = "domain_keys_unavailable"
	ClaimErrKindDomainUnverified      ClaimErrorKind = "domain_unverified"
	// ClaimErrKindUserIDMismatch: a claim's user_id did not match the
	// domain-signature-verified callback payload's user_id — a claim about a
	// different user must never be attributed to this login, regardless of
	// whether its own signature checks out.
	ClaimErrKindUserIDMismatch ClaimErrorKind = "user_id_mismatch"
	// ClaimErrKindRequiredClaimMissing: a claim type named in the pending
	// login's required_claims did not appear among the claims that passed
	// full verification (signature quorum + not revoked + not expired) —
	// enforced here since generated CSIL traits are pure/infallible and the
	// server-side ticket redemption does not itself re-check the original
	// requirement.
	ClaimErrKindRequiredClaimMissing ClaimErrorKind = "required_claim_missing"
)

// ClaimError is a claim signature/revocation/expiry verification failure.
type ClaimError struct {
	Kind   ClaimErrorKind
	Detail string
}

func (e *ClaimError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("claim: %s: %s", e.Kind, e.Detail)
	}
	return fmt.Sprintf("claim: %s", e.Kind)
}

// DnsErrorKind mirrors liblinkkeys::dns::DnsParseError's variants. The string
// values are chosen to match the conformance vectors' `expected_error`
// symbolic strings exactly (see sdks/local-rp/conformance/dns.json), so
// tests can compare directly.
type DnsErrorKind string

const (
	DnsErrMissingVersion      DnsErrorKind = "missing_version"
	DnsErrUnsupportedVersion  DnsErrorKind = "unsupported_version"
	DnsErrMissingApisEndpoint DnsErrorKind = "missing_apis_endpoint"
	DnsErrNoLinkKeysRecord    DnsErrorKind = "no_linkkeys_record"
	DnsErrInvalidFormat       DnsErrorKind = "invalid_format"
)

// DnsParseError is a `_linkkeys`/`_linkkeys_apis` TXT record parse failure.
type DnsParseError struct {
	Kind   DnsErrorKind
	Detail string
}

func (e *DnsParseError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("DNS record parse error: %s: %s", e.Kind, e.Detail)
	}
	return fmt.Sprintf("DNS record parse error: %s", e.Kind)
}
