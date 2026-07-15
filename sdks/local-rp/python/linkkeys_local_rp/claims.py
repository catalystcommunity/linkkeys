"""Claim signature/revocation/expiry verification.

Mirrors `crates/liblinkkeys/src/claims.rs` for exactly the pieces
`complete_local_login` needs: per-signer-domain signature quorum, revocation,
and expiry. `sign_claim` is included only so this package's own flow tests
can build fake claims exactly like `sdks/local-rp/rust/tests/flow.rs` does
(IDP-side operation; the SDK itself only ever verifies claims returned from
a ticket redemption, never signs them).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from . import crypto
from .generated import codec as _codec  # noqa: F401  (side effect: attaches to_cbor/from_cbor)
from .generated.codec import cbor_encode
from .generated.types import Claim, ClaimSignature, LocalRpTicketRedemptionResponse
from .timeutil import parse_rfc3339

CLAIM_PAYLOAD_TAG = "linkkeys-claim-v2"


class ClaimError(Exception):
    """Base class for every claim verification failure. Per the conformance
    suite's contract, only pass/fail is portable across languages — these
    subclasses exist for richer app-side diagnostics only."""


class SignatureInvalid(ClaimError):
    pass


class UnsupportedAlgorithm(ClaimError):
    def __init__(self, algorithm: str):
        super().__init__(f"unsupported signing algorithm: {algorithm}")
        self.algorithm = algorithm


class KeyNotFound(ClaimError):
    def __init__(self, key_id: str):
        super().__init__(f"signing key not found: {key_id}")
        self.key_id = key_id


class KeyRevoked(ClaimError):
    def __init__(self, key_id: str):
        super().__init__(f"signing key has been revoked: {key_id}")
        self.key_id = key_id


class KeyExpired(ClaimError):
    def __init__(self, key_id: str):
        super().__init__(f"signing key has expired: {key_id}")
        self.key_id = key_id


class Revoked(ClaimError):
    pass


class Expired(ClaimError):
    pass


class BadExpiry(ClaimError):
    pass


class Unsigned(ClaimError):
    pass


class DomainKeysUnavailable(ClaimError):
    def __init__(self, domain: str):
        super().__init__(f"no public keys available for signing domain: {domain}")
        self.domain = domain


class DomainUnverified(ClaimError):
    def __init__(self, domain: str):
        super().__init__(f"no valid signature for signing domain: {domain}")
        self.domain = domain


@dataclass
class DomainKeySet:
    domain: str
    keys: list


@dataclass
class ClaimSpec:
    claim_id: str
    claim_type: str
    claim_value: bytes
    user_id: str
    subject_domain: str
    attested_at: str
    expires_at: Optional[str] = None


@dataclass
class ClaimSigner:
    domain: str
    key_id: str
    algorithm: "crypto.SigningAlgorithm"
    private_key_bytes: bytes


def claim_sign_payload(
    claim_id: str,
    claim_type: str,
    claim_value: bytes,
    user_id: str,
    subject_domain: str,
    signing_domain: str,
    expires_at: Optional[str],
    attested_at: str,
) -> bytes:
    """The subject is bound as the single full identity
    `user_id@subject_domain` (not the bare user_id), so a claim about a
    user_id at one domain can't be replayed as the same user_id at another.
    `signing_domain` — the attestor for *this* signature — is bound
    per-signature."""
    subject = f"{user_id}@{subject_domain}"
    payload = [
        CLAIM_PAYLOAD_TAG,
        claim_id,
        claim_type,
        claim_value,
        subject,
        signing_domain,
        expires_at,
        attested_at,
    ]
    return cbor_encode(payload)


def sign_claim(spec: ClaimSpec, signers: List[ClaimSigner]) -> Claim:
    """Sign a claim with one or more keys, producing a `Claim` carrying one
    `ClaimSignature` per signer. IDP-side operation; see module docs."""
    signatures = []
    for signer in signers:
        payload = claim_sign_payload(
            spec.claim_id,
            spec.claim_type,
            spec.claim_value,
            spec.user_id,
            spec.subject_domain,
            signer.domain,
            spec.expires_at,
            spec.attested_at,
        )
        signature = crypto.sign_with_algorithm(signer.algorithm, payload, signer.private_key_bytes)
        signatures.append(
            ClaimSignature(domain=signer.domain, signed_by_key_id=signer.key_id, signature=signature)
        )

    return Claim(
        claim_id=spec.claim_id,
        user_id=spec.user_id,
        claim_type=spec.claim_type,
        claim_value=spec.claim_value,
        signatures=signatures,
        attested_at=spec.attested_at,
        created_at=spec.attested_at,
        expires_at=spec.expires_at,
        revoked_at=None,
    )


def _verify_one_signature(sig: ClaimSignature, payload: bytes, keys: list, now: datetime) -> None:
    key = next((k for k in keys if k.key_id == sig.signed_by_key_id), None)
    if key is None:
        raise KeyNotFound(sig.signed_by_key_id)
    if key.key_usage != "sign":
        raise SignatureInvalid("key is not a signing key")

    # This gates the SIGNING KEY's own revocation/expiry (not the claim's,
    # which `verify_claim` checks separately). `liblinkkeys`'s equivalent
    # reads `Utc::now()` directly at this exact point rather than taking an
    # explicit parameter (a documented exception to its own "explicit now"
    # discipline, since key revocation must be checked live); this port
    # instead threads the caller's `now` through, which is strictly more
    # testable/deterministic and produces the same result for any real
    # (non-backdated) `now`.
    validity = crypto.signing_key_validity(key.expires_at, key.revoked_at, now)
    if validity == crypto.KeyValidity.REVOKED:
        raise KeyRevoked(key.key_id)
    if validity in (crypto.KeyValidity.EXPIRED, crypto.KeyValidity.BAD_EXPIRY):
        raise KeyExpired(key.key_id)

    try:
        crypto.resolve_and_verify(key.algorithm, payload, sig.signature, key.public_key)
    except crypto.UnsupportedAlgorithm as e:
        raise UnsupportedAlgorithm(key.algorithm) from e
    except crypto.CryptoError as e:
        raise SignatureInvalid("claim signature verification failed") from e


def verify_claim_signatures(claim: Claim, subject_domain: str, domain_keys: List[DomainKeySet], now: datetime) -> None:
    """Every distinct domain that signed must contribute at least one
    signature from a currently-valid key of that domain."""
    if not claim.signatures:
        raise Unsigned("claim has no signatures")

    domains = sorted({sig.domain for sig in claim.signatures})
    for signing_domain in domains:
        key_set = next((s for s in domain_keys if s.domain == signing_domain), None)
        if key_set is None:
            raise DomainKeysUnavailable(signing_domain)

        payload = claim_sign_payload(
            claim.claim_id,
            claim.claim_type,
            claim.claim_value,
            claim.user_id,
            subject_domain,
            signing_domain,
            claim.expires_at,
            claim.attested_at,
        )

        last_err: ClaimError = DomainUnverified(signing_domain)
        satisfied = False
        for sig in claim.signatures:
            if sig.domain != signing_domain:
                continue
            try:
                _verify_one_signature(sig, payload, key_set.keys, now)
                satisfied = True
                break
            except ClaimError as e:
                last_err = e
        if not satisfied:
            raise last_err


def verify_claim(claim: Claim, subject_domain: str, domain_keys: List[DomainKeySet], now: datetime) -> None:
    """Full claim verification: the cryptographic per-domain quorum plus the
    claim's own revocation and expiry. All must pass."""
    verify_claim_signatures(claim, subject_domain, domain_keys, now)

    if claim.revoked_at is not None:
        raise Revoked("claim has been revoked")
    if claim.expires_at is not None:
        try:
            expires = parse_rfc3339(claim.expires_at)
        except ValueError as e:
            raise BadExpiry("claim has an invalid expires_at") from e
        if now > expires:
            raise Expired("claim has expired")


def decode_claim(data: bytes) -> Claim:
    """Decode a single `Claim` from its CBOR wire bytes via the generated
    codec. The generated decoder validates every field against its declared
    CSIL type -- a CBOR-text-encoded `claim_value` raises
    `generated.codec.CsilDecodeError` (see conformance `claims.json`'s
    `claim_value_as_cbor_text_rejected` case) -- so no additional wire-type
    check is needed here. Kept as the SDK's stable decode seam."""
    return Claim.from_cbor(data)


def decode_ticket_redemption_response(data: bytes) -> LocalRpTicketRedemptionResponse:
    """Decode a `LocalRpTicketRedemptionResponse` -- the wire message
    `complete_local_login` actually consumes `Claim`s from (via
    `redeem_claim_ticket`). Strict declared-type validation, including of
    every embedded `Claim`, happens inside the generated codec."""
    return LocalRpTicketRedemptionResponse.from_cbor(data)
