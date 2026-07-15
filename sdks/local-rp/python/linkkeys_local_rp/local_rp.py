"""DNS-less local RP identity: pure protocol helpers.

Mirrors `crates/liblinkkeys/src/local_rp.rs` (read that file's module docs
and `dns-less-local-rp-design.md`'s "Wire Precision (Normative)" section
first — this module implements it byte-for-byte). Summary of the shape:

- Every signed structure uses the envelope pattern: the payload is
  CBOR-encoded once, and the signature covers
  `CBOR([context: tstr, payload: bstr])` — a two-element CBOR array, never a
  bare `context || payload` concatenation (see `envelope_signature_input`).
- Four mandatory, structure-specific context strings stop a signature over
  one structure from ever verifying as another.
- The descriptor, login request, and ticket-redemption envelopes are
  self-asserted (verified against the local RP's own embedded signing key,
  SSH-host style). The callback payload envelope is domain-signed (verified
  against fetched domain public keys, keyed by `signing_key_id`).
- The callback ciphertext is a variant of the sealed-box construction,
  extended with negotiated-suite selection and cleartext-header AAD
  binding — see `seal_local_rp_callback` / `open_local_rp_callback`.

This module performs no I/O and never reads the system clock — every
"current time" is an explicit `now` parameter, so verification stays
deterministic and testable against fixed conformance vectors.

Only the subset actually used by an RP (build+sign the descriptor/login
request/ticket-redemption; verify+open the callback) is exercised at
runtime by this SDK. `build_local_rp_callback_payload` /
`sign_local_rp_callback_payload` / `seal_local_rp_callback` are IDP-side
operations — included here (mirroring `liblinkkeys::local_rp`, which serves
both sides) purely so this package's own test suite can act as a
self-contained fake IDP in the flow tests, exactly like
`sdks/local-rp/rust/tests/flow.rs` does by calling straight into
`liblinkkeys::local_rp`.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Tuple

from . import crypto
from .generated import codec as _codec  # noqa: F401  (side effect: attaches to_cbor/from_cbor)
from .generated.types import (
    DomainPublicKey,
    LocalRpCallbackHeader,
    LocalRpCallbackPayload,
    LocalRpDescriptor,
    LocalRpEncryptedCallback,
    LocalRpLoginRequest,
    LocalRpTicketRedemptionRequest,
    SignedLocalRpCallbackPayload,
    SignedLocalRpDescriptor,
    SignedLocalRpLoginRequest,
    SignedLocalRpTicketRedemptionRequest,
)
from .generated.codec import cbor_encode
from .timeutil import parse_rfc3339

CTX_LOCAL_RP_DESCRIPTOR = "linkkeys-local-rp-descriptor"
CTX_LOCAL_RP_LOGIN_REQUEST = "linkkeys-local-rp-login-request"
CTX_LOCAL_RP_CALLBACK = "linkkeys-local-rp-callback"
CTX_LOCAL_RP_TICKET_REDEMPTION = "linkkeys-local-rp-ticket-redemption"

DEFAULT_CLOCK_SKEW_SECONDS = 300

_LOCAL_RP_CALLBACK_BOX_TAG = b"linkkeys-local-rp-callback-box"


# ---------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------


class LocalRpError(Exception):
    """Base class for every local-RP protocol verification failure. Per the
    conformance suite's own README: "Exact error *types* are intentionally
    not part of the contract ... only pass/fail is portable" — so callers
    that only need pass/fail can catch this one base class; the subclasses
    below exist for the flow tests and for apps that want richer diagnostics
    without ever seeing key material, nonces, tokens, tickets, or claim
    values in a message (AGENTS.md's error-handling rule)."""


class DecodeFailed(LocalRpError):
    pass


class InvalidKeyLength(LocalRpError):
    pass


class FingerprintMismatch(LocalRpError):
    pass


class NotYetValid(LocalRpError):
    pass


class Expired(LocalRpError):
    pass


class BadTimestamp(LocalRpError):
    pass


class NonceMismatch(LocalRpError):
    pass


class StateMismatch(LocalRpError):
    pass


class AudienceMismatch(LocalRpError):
    pass


class IssuerMismatch(LocalRpError):
    pass


class CallbackUrlMismatch(LocalRpError):
    pass


class UnsupportedSuite(LocalRpError):
    def __init__(self, suite_id: str):
        super().__init__(f"unsupported AEAD suite: {suite_id}")
        self.suite_id = suite_id


class SuiteNotAdvertised(LocalRpError):
    def __init__(self, suite_id: str):
        super().__init__(f"AEAD suite was not advertised/allowed: {suite_id}")
        self.suite_id = suite_id


class HeaderPayloadMismatch(LocalRpError):
    def __init__(self, field: str):
        super().__init__(f"callback header does not match signed payload field: {field}")
        self.field = field


class KeyNotFound(LocalRpError):
    def __init__(self, key_id: str):
        super().__init__(f"signing key not found: {key_id}")
        self.key_id = key_id


class KeyRevoked(LocalRpError):
    def __init__(self, key_id: str):
        super().__init__(f"signing key has been revoked: {key_id}")
        self.key_id = key_id


class KeyExpired(LocalRpError):
    def __init__(self, key_id: str):
        super().__init__(f"signing key has expired: {key_id}")
        self.key_id = key_id


class SignatureInvalid(LocalRpError):
    pass


class UnsupportedSigningAlgorithm(LocalRpError):
    def __init__(self, algorithm: str):
        super().__init__(f"unsupported signing algorithm: {algorithm}")
        self.algorithm = algorithm


# ---------------------------------------------------------------------
# Envelope signature input (Wire Precision: "Signature input bytes")
# ---------------------------------------------------------------------


def envelope_signature_input(context: str, payload_bytes: bytes) -> bytes:
    """`CBOR([context, payload_bytes])` — a two-element CBOR array, context
    string first (CBOR text string), then the exact payload bytes (CBOR byte
    string). Deliberately NOT a bare `context || payload` concatenation; see
    module docs. `cbor_encode([context, payload_bytes])` produces exactly
    this because the generated codec's encoder renders a Python `list` as a
    CBOR array (major type 4) and dispatches `str`/`bytes` to CBOR text/byte
    strings respectively — the same shape `ciborium`'s tuple serialization
    produces on the Rust side."""
    return cbor_encode([context, payload_bytes])


# ---------------------------------------------------------------------
# Timestamps / expirations
# ---------------------------------------------------------------------


def check_timestamps(issued_at: str, expires_at: str, now: datetime, skew_seconds: int) -> None:
    """Check an `(issued_at, expires_at)` pair against `now`, tolerant of
    `skew_seconds` of clock skew in either direction. Boundaries are
    inclusive: exactly `now - skew == expires_at` still passes, and exactly
    one second past either boundary fails. Raises on failure."""
    try:
        issued = parse_rfc3339(issued_at)
        expires = parse_rfc3339(expires_at)
    except ValueError as e:
        raise BadTimestamp(str(e)) from e

    skew = timedelta(seconds=skew_seconds)
    if now + skew < issued:
        raise NotYetValid("timestamp is not yet valid")
    if now - skew > expires:
        raise Expired("timestamp has expired")


class ExpirationLevel(str, Enum):
    OK = "ok"
    NOTICE = "notice"
    WARNING = "warning"
    CRITICAL = "critical"
    EXPIRED = "expired"

    def as_str(self) -> str:
        return self.value


@dataclass
class ExpirationStatus:
    level: ExpirationLevel
    expires_at: datetime
    now: datetime


def check_expirations(expires_at: str, now: datetime) -> ExpirationStatus:
    """`check_expirations(identity, now) -> ExpirationStatus` (design doc,
    "Expiration Helper"): `notice` at 180 days remaining, `warning` at 90,
    `critical` at 30, `expired` once `now >= expires_at`. No clock-skew
    tolerance (unlike `check_timestamps`) — expiry warnings are advisory,
    day-granularity facts, not a replay/freshness security boundary."""
    try:
        expires = parse_rfc3339(expires_at)
    except ValueError as e:
        raise BadTimestamp(str(e)) from e

    remaining = expires - now
    if now >= expires:
        level = ExpirationLevel.EXPIRED
    elif remaining <= timedelta(days=30):
        level = ExpirationLevel.CRITICAL
    elif remaining <= timedelta(days=90):
        level = ExpirationLevel.WARNING
    elif remaining <= timedelta(days=180):
        level = ExpirationLevel.NOTICE
    else:
        level = ExpirationLevel.OK
    return ExpirationStatus(level=level, expires_at=expires, now=now)


# ---------------------------------------------------------------------
# Nonce/state/audience/issuer/callback-url checks
# ---------------------------------------------------------------------


def verify_nonce_state(
    expected_nonce: bytes, expected_state: bytes, actual_nonce: bytes, actual_state: bytes
) -> None:
    """Constant-time comparison (`hmac.compare_digest`, not `!=`): nonce and
    state are unpredictable-to-the-attacker secrets the app committed to at
    `begin_local_login` time, so a timing side channel on the comparison
    must not leak how many leading bytes an attacker-supplied value got
    right."""
    if not hmac.compare_digest(expected_nonce, actual_nonce):
        raise NonceMismatch("nonce does not match")
    if not hmac.compare_digest(expected_state, actual_state):
        raise StateMismatch("state does not match")


def verify_audience(payload_audience_fingerprint: str, local_rp_fingerprint: str) -> None:
    if payload_audience_fingerprint != local_rp_fingerprint:
        raise AudienceMismatch("audience fingerprint does not match")


def verify_issuer(payload_user_domain: str, expected_domain: str) -> None:
    if payload_user_domain != expected_domain:
        raise IssuerMismatch("issuing domain does not match")


def verify_callback_url(payload_callback_url: str, arrived_url: str) -> None:
    if payload_callback_url != arrived_url:
        raise CallbackUrlMismatch("callback URL does not match")


# ---------------------------------------------------------------------
# Descriptor (build + sign only — verification is the IDP's job)
# ---------------------------------------------------------------------


def build_local_rp_descriptor(
    app_name: str,
    local_domain_hint: Optional[str],
    signing_public_key: bytes,
    encryption_public_key: bytes,
    supported_suites: List[str],
    created_at: str,
    expires_at: str,
) -> LocalRpDescriptor:
    """`fingerprint` is always derived from `signing_public_key` — callers
    cannot set it directly, so it can never drift from the key it names."""
    return LocalRpDescriptor(
        app_name=app_name,
        local_domain_hint=local_domain_hint,
        signing_public_key=signing_public_key,
        encryption_public_key=encryption_public_key,
        fingerprint=crypto.fingerprint(signing_public_key),
        supported_suites=list(supported_suites),
        created_at=created_at,
        expires_at=expires_at,
    )


def sign_local_rp_descriptor(descriptor: LocalRpDescriptor, private_key_bytes: bytes) -> SignedLocalRpDescriptor:
    descriptor_bytes = descriptor.to_cbor()
    signature_input = envelope_signature_input(CTX_LOCAL_RP_DESCRIPTOR, descriptor_bytes)
    signature = crypto.sign_with_algorithm(crypto.SigningAlgorithm.ED25519, signature_input, private_key_bytes)
    return SignedLocalRpDescriptor(descriptor=descriptor_bytes, signature=signature)


# ---------------------------------------------------------------------
# Login request (build + sign only)
# ---------------------------------------------------------------------


def build_local_rp_login_request(
    descriptor: SignedLocalRpDescriptor,
    callback_url: str,
    nonce: bytes,
    state: bytes,
    requested_claims: List[str],
    required_claims: List[str],
    issued_at: str,
    expires_at: str,
) -> LocalRpLoginRequest:
    return LocalRpLoginRequest(
        descriptor=descriptor,
        callback_url=callback_url,
        nonce=nonce,
        state=state,
        requested_claims=list(requested_claims),
        required_claims=list(required_claims),
        issued_at=issued_at,
        expires_at=expires_at,
    )


def sign_local_rp_login_request(
    request: LocalRpLoginRequest, private_key_bytes: bytes
) -> SignedLocalRpLoginRequest:
    request_bytes = request.to_cbor()
    signature_input = envelope_signature_input(CTX_LOCAL_RP_LOGIN_REQUEST, request_bytes)
    signature = crypto.sign_with_algorithm(crypto.SigningAlgorithm.ED25519, signature_input, private_key_bytes)
    return SignedLocalRpLoginRequest(request=request_bytes, signature=signature)


# ---------------------------------------------------------------------
# Ticket redemption (build + sign — the RP's possession proof)
# ---------------------------------------------------------------------


def build_local_rp_ticket_redemption_request(
    claim_ticket: bytes, fingerprint: str, issued_at: str
) -> LocalRpTicketRedemptionRequest:
    return LocalRpTicketRedemptionRequest(claim_ticket=claim_ticket, fingerprint=fingerprint, issued_at=issued_at)


def sign_local_rp_ticket_redemption_request(
    request: LocalRpTicketRedemptionRequest, private_key_bytes: bytes
) -> SignedLocalRpTicketRedemptionRequest:
    request_bytes = request.to_cbor()
    signature_input = envelope_signature_input(CTX_LOCAL_RP_TICKET_REDEMPTION, request_bytes)
    signature = crypto.sign_with_algorithm(crypto.SigningAlgorithm.ED25519, signature_input, private_key_bytes)
    return SignedLocalRpTicketRedemptionRequest(request=request_bytes, signature=signature)


# ---------------------------------------------------------------------
# Callback payload (build + sign — IDP-side, used only by this package's
# own fake-IDP flow tests) / verify (RP-side, used by `complete_local_login`)
# ---------------------------------------------------------------------


def build_local_rp_callback_payload(
    user_id: str,
    user_domain: str,
    claim_ticket: bytes,
    audience_fingerprint: str,
    callback_url: str,
    nonce: bytes,
    state: bytes,
    issued_at: str,
    expires_at: str,
) -> LocalRpCallbackPayload:
    return LocalRpCallbackPayload(
        user_id=user_id,
        user_domain=user_domain,
        claim_ticket=claim_ticket,
        audience_fingerprint=audience_fingerprint,
        callback_url=callback_url,
        nonce=nonce,
        state=state,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def sign_local_rp_callback_payload(
    payload: LocalRpCallbackPayload,
    key_id: str,
    algorithm: crypto.SigningAlgorithm,
    private_key_bytes: bytes,
) -> SignedLocalRpCallbackPayload:
    payload_bytes = payload.to_cbor()
    signature_input = envelope_signature_input(CTX_LOCAL_RP_CALLBACK, payload_bytes)
    signature = crypto.sign_with_algorithm(algorithm, signature_input, private_key_bytes)
    return SignedLocalRpCallbackPayload(payload=payload_bytes, signing_key_id=key_id, signature=signature)


def _check_signing_key_valid(key: DomainPublicKey, now: datetime) -> None:
    """Reject a signing key that is not currently a signing key, or is
    revoked/expired — shared by every verify path that resolves a key by
    id."""
    if key.key_usage != "sign":
        raise SignatureInvalid("key is not a signing key")
    validity = crypto.signing_key_validity(key.expires_at, key.revoked_at, now)
    if validity == crypto.KeyValidity.REVOKED:
        raise KeyRevoked(key.key_id)
    if validity in (crypto.KeyValidity.EXPIRED, crypto.KeyValidity.BAD_EXPIRY):
        raise KeyExpired(key.key_id)


def verify_local_rp_callback_payload(
    signed: SignedLocalRpCallbackPayload,
    domain_public_keys: List[DomainPublicKey],
    now: datetime,
    skew_seconds: int,
) -> LocalRpCallbackPayload:
    """Verify a domain-signed callback payload envelope against a set of
    domain public keys: resolve `signing_key_id`, reject a
    revoked/expired/non-signing key, verify the envelope signature, decode,
    then check `issued_at`/`expires_at` bounds. Nothing inside the payload is
    trusted before this succeeds."""
    key = next((k for k in domain_public_keys if k.key_id == signed.signing_key_id), None)
    if key is None:
        raise KeyNotFound(signed.signing_key_id)

    _check_signing_key_valid(key, now)

    signature_input = envelope_signature_input(CTX_LOCAL_RP_CALLBACK, signed.payload)
    try:
        crypto.resolve_and_verify(key.algorithm, signature_input, signed.signature, key.public_key)
    except crypto.UnsupportedAlgorithm as e:
        raise UnsupportedSigningAlgorithm(key.algorithm) from e
    except crypto.CryptoError as e:
        raise SignatureInvalid("callback payload signature verification failed") from e

    payload = LocalRpCallbackPayload.from_cbor(signed.payload)
    check_timestamps(payload.issued_at, payload.expires_at, now, skew_seconds)
    return payload


def check_callback_header_matches_payload(header: LocalRpCallbackHeader, payload: LocalRpCallbackPayload) -> None:
    """Cross-check the cleartext callback header's routing fields against
    the authoritative copies inside the decrypted, signature-verified
    payload. The header is already bound as AEAD associated data, but a
    verifier must still consult the signed copies rather than trusting the
    header alone."""
    if header.fingerprint != payload.audience_fingerprint:
        raise HeaderPayloadMismatch("fingerprint")
    if header.nonce != payload.nonce:
        raise HeaderPayloadMismatch("nonce")
    if header.state != payload.state:
        raise HeaderPayloadMismatch("state")
    if header.issued_at != payload.issued_at:
        raise HeaderPayloadMismatch("issued_at")
    if header.expires_at != payload.expires_at:
        raise HeaderPayloadMismatch("expires_at")


# ---------------------------------------------------------------------
# Callback sealed box (Wire Precision: "Callback sealed box")
# ---------------------------------------------------------------------


def _local_rp_callback_kdf(
    suite: crypto.AeadSuite, ephemeral_public: bytes, recipient_public: bytes, shared_secret: bytes
) -> Tuple[bytes, bytes]:
    """Derive the AEAD key and construct the KDF `info`/AAD-prefix context:
    `tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)`,
    raw concatenation. Returns `(aead_key, context)`."""
    suite_id = suite.as_str().encode("utf-8")
    context = _LOCAL_RP_CALLBACK_BOX_TAG + suite_id + ephemeral_public + recipient_public
    key = crypto.hkdf_sha256_expand(shared_secret, context, 32)
    return key, context


def seal_local_rp_callback(
    signed_payload: SignedLocalRpCallbackPayload,
    suite: crypto.AeadSuite,
    recipient_encryption_public_key: bytes,
    fingerprint: str,
    nonce: bytes,
    state: bytes,
    issued_at: str,
    expires_at: str,
    *,
    ephemeral_private_key: Optional[bytes] = None,
    aead_nonce: Optional[bytes] = None,
) -> LocalRpEncryptedCallback:
    """Seal a `SignedLocalRpCallbackPayload` into a `LocalRpEncryptedCallback`
    for `recipient_encryption_public_key`, under `suite`. IDP-side operation
    — included here purely so this package's own tests can build a
    self-contained fake IDP (see module docs).

    `ephemeral_private_key` / `aead_nonce` are deterministic-testing hooks
    (mirroring `seal_local_rp_callback_with_randomness` in the Rust
    reference): production callers must leave both `None` so real OS
    randomness is used.
    """
    ephemeral_private = ephemeral_private_key if ephemeral_private_key is not None else os.urandom(32)
    nonce_bytes = aead_nonce if aead_nonce is not None else os.urandom(12)

    ephemeral_public = crypto.x25519_public_from_private(ephemeral_private)
    shared_secret = crypto.x25519_diffie_hellman(ephemeral_private, recipient_encryption_public_key)
    crypto.reject_low_order(shared_secret)

    plaintext = signed_payload.to_cbor()

    header = LocalRpCallbackHeader(
        fingerprint=fingerprint,
        nonce=nonce,
        state=state,
        suite=suite.as_str(),
        ephemeral_public_key=ephemeral_public,
        aead_nonce=nonce_bytes,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    header_bytes = header.to_cbor()

    aead_key, kdf_context = _local_rp_callback_kdf(
        suite, ephemeral_public, recipient_encryption_public_key, shared_secret
    )
    aad = kdf_context + header_bytes
    ciphertext = crypto.aead_encrypt(suite, aead_key, nonce_bytes, aad, plaintext)

    return LocalRpEncryptedCallback(header=header_bytes, ciphertext=ciphertext)


def open_local_rp_callback(
    encrypted: LocalRpEncryptedCallback,
    recipient_encryption_private_key: bytes,
    allowed_suites: List[crypto.AeadSuite],
) -> Tuple[LocalRpCallbackHeader, SignedLocalRpCallbackPayload]:
    """Open a `LocalRpEncryptedCallback` with the local RP's encryption
    private key. `allowed_suites` is the local RP's own supported-suite list
    (from its descriptor): a header advertising a suite NOT in that list is
    rejected even if it is otherwise a valid registry id (Wire Precision:
    "The SDK must decrypt only with a suite listed in its own descriptor").

    Returns the decoded header and the still-domain-signature-unverified
    payload envelope — callers must still call
    `verify_local_rp_callback_payload` against fetched domain keys, and then
    `check_callback_header_matches_payload`, before trusting the result.
    """
    try:
        header = LocalRpCallbackHeader.from_cbor(encrypted.header)
    except Exception as e:  # noqa: BLE001 - re-raise as our own decode error
        raise DecodeFailed(f"callback header: {e}") from e

    suite = crypto.AeadSuite.parse_str(header.suite)
    if suite is None:
        raise UnsupportedSuite(header.suite)
    if suite not in allowed_suites:
        raise SuiteNotAdvertised(header.suite)

    if len(header.ephemeral_public_key) != 32:
        raise InvalidKeyLength("ephemeral_public_key must be 32 bytes")
    if len(header.aead_nonce) != 12:
        raise InvalidKeyLength("aead_nonce must be 12 bytes")

    recipient_public = crypto.x25519_public_from_private(recipient_encryption_private_key)
    shared_secret = crypto.x25519_diffie_hellman(recipient_encryption_private_key, header.ephemeral_public_key)
    crypto.reject_low_order(shared_secret)

    aead_key, kdf_context = _local_rp_callback_kdf(
        suite, header.ephemeral_public_key, recipient_public, shared_secret
    )
    aad = kdf_context + encrypted.header

    try:
        plaintext = crypto.aead_decrypt(suite, aead_key, header.aead_nonce, aad, encrypted.ciphertext)
    except crypto.CryptoError as e:
        raise DecodeFailed(f"callback decryption failed: {e}") from e

    try:
        signed_payload = SignedLocalRpCallbackPayload.from_cbor(plaintext)
    except Exception as e:  # noqa: BLE001
        raise DecodeFailed(f"callback payload: {e}") from e

    return header, signed_payload
