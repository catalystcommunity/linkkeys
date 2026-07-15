// The SDK's error taxonomy. Mirrors the Rust/Go/Java SDKs' own error types
// (`liblinkkeys::local_rp::LocalRpError`, `liblinkkeys::claims::ClaimError`,
// `liblinkkeys::revocation::RevocationError`, plus a network/IO-layer
// [SdkException]). None of these ever carry key material, nonces, tokens,
// tickets, or claim values in their message (AGENTS.md: "Never log sensitive
// information") -- only enough context (a field name, an algorithm id, a key
// id) to explain what failed.
library;

/// The SDK's network/IO-layer error -- everything that isn't a pure protocol
/// verification failure ([LocalRpError]/[ClaimError]/[RevocationError]).
/// Every fallible network operation in this SDK throws one of these.
enum SdkExceptionKind {
  /// A field the caller supplied was structurally invalid.
  invalidInput,

  /// DNS TXT lookup or record parsing failed for a domain.
  dns,

  /// The TCP transport could not reach a domain's endpoint.
  transport,

  /// TLS handshake / certificate pinning failed.
  tls,

  /// The CSIL-RPC envelope could not be encoded/decoded, or wire framing was
  /// malformed.
  protocol,

  /// The peer returned a non-Ok RPC transport status.
  server,

  /// No trustworthy domain keys were established for a domain.
  noTrustedDomainKeys,
}

class SdkException implements Exception {
  final SdkExceptionKind kind;
  final String message;
  final int serverStatus;
  final Object? cause;

  SdkException(this.kind, this.message, {this.cause}) : serverStatus = 0;

  SdkException.server(this.serverStatus, this.message)
      : kind = SdkExceptionKind.server,
        cause = null;

  @override
  String toString() => kind == SdkExceptionKind.server
      ? 'SdkException: server error ($serverStatus): $message'
      : 'SdkException(${kind.name}): $message';
}

/// A local-RP protocol verification failure: signature, envelope, timestamp,
/// nonce/state, audience, issuer, callback URL, or suite-negotiation check.
enum LocalRpErrorKind {
  decode,
  invalidKeyLength,
  fingerprintMismatch,
  notYetValid,
  expired,
  badTimestamp,
  nonceMismatch,
  stateMismatch,
  audienceMismatch,
  issuerMismatch,
  callbackUrlMismatch,
  unsupportedSuite,
  suiteNotAdvertised,
  headerPayloadMismatch,
  keyNotFound,
  keyRevoked,
  keyExpired,
  signatureInvalid,
  unsupportedAlgorithm,
  crypto,

  /// The ticket-redemption response's `user_id`/`user_domain` did not match
  /// the domain-signature-verified callback payload's `user_id`/
  /// `user_domain`. A stolen/substituted ticket, or a compromised/malicious
  /// IDP answering a redemption for a different user than the one who
  /// authenticated, must never be attributed to this login.
  redemptionIdentityMismatch,
}

class LocalRpError implements Exception {
  final LocalRpErrorKind kind;
  final String? detail;
  final Object? cause;

  LocalRpError(this.kind, this.detail, {this.cause});

  @override
  String toString() => detail == null
      ? 'LocalRpError(${kind.name})'
      : 'LocalRpError(${kind.name}): $detail';
}

/// A claim signature/revocation/expiry verification failure.
enum ClaimErrorKind {
  unsigned,
  keyNotFound,
  keyRevoked,
  keyExpired,
  unsupportedAlgorithm,
  signatureInvalid,
  domainKeysUnavailable,
  domainUnverified,
  revoked,
  badExpiry,
  expired,

  /// A claim's `user_id` did not match the domain-signature-verified
  /// callback payload's `user_id` -- a claim about a different user must
  /// never be attributed to this login, regardless of whether its own
  /// signature checks out.
  userIdMismatch,

  /// A claim type named in the pending login's `required_claims` did not
  /// appear among the claims that passed full verification (signature
  /// quorum + not revoked + not expired) -- enforced here since generated
  /// CSIL traits are pure/infallible and ticket redemption does not itself
  /// re-check the original requirement.
  requiredClaimMissing,
}

class ClaimError implements Exception {
  final ClaimErrorKind kind;
  final String? detail;

  ClaimError(this.kind, this.detail);

  @override
  String toString() => detail == null
      ? 'ClaimError(${kind.name})'
      : 'ClaimError(${kind.name}): $detail';
}

/// A sibling-signed revocation certificate failed to meet quorum.
class RevocationError implements Exception {
  final int got;
  final int need;

  RevocationError(this.got, this.need);

  @override
  String toString() =>
      'RevocationError: revocation certificate has $got valid distinct signer(s), needs $need';
}

/// Thrown for any cryptographic failure: signature verification failure, AEAD
/// authentication failure, a non-contributory (low-order) X25519 key, a
/// malformed key length, or an unexpected backend error. Never carries key
/// material, shared secrets, or plaintext in its message.
class CryptoException implements Exception {
  final String message;
  final Object? cause;

  CryptoException(this.message, {this.cause});

  @override
  String toString() => 'CryptoException: $message';
}

/// A `_linkkeys`/`_linkkeys_apis` TXT record failed to parse.
enum DnsParseErrorKind {
  noLinkkeysRecord,
  missingVersion,
  unsupportedVersion,
  missingApisEndpoint,
  invalidFormat,
}

class DnsParseError implements Exception {
  final DnsParseErrorKind kind;
  final String? detail;

  DnsParseError(this.kind, this.detail);

  /// The symbolic string `dns.json`'s `expected_error` field uses.
  String get symbol => switch (kind) {
        DnsParseErrorKind.noLinkkeysRecord => 'no_linkkeys_record',
        DnsParseErrorKind.missingVersion => 'missing_version',
        DnsParseErrorKind.unsupportedVersion => 'unsupported_version',
        DnsParseErrorKind.missingApisEndpoint => 'missing_apis_endpoint',
        DnsParseErrorKind.invalidFormat => 'invalid_format',
      };

  @override
  String toString() => detail == null
      ? 'DnsParseError(${kind.name})'
      : 'DnsParseError(${kind.name}): $detail';
}
