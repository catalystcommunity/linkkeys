"""Sibling-signed key revocation certificate verification.

Mirrors `crates/liblinkkeys/src/revocation.rs` (compact reference:
`sdks/local-rp/go/revocation.go`). Only verification is ported here —
building/signing a revocation certificate is a domain-admin/server-side
operation, out of scope for a local-RP SDK. This SDK verifies revocation
certificates fetched alongside domain keys (`rpc.fetch_domain_keys`) so it
can drop a key a quorum-verified sibling revocation targets *before* any
envelope or claim verification consults the key set.

Wire-precision gotchas, per `sdks/local-rp/conformance/README.md`'s
`revocations.json` section (these are exactly what the vectors punish):

- The signed payload is `CBOR([tag, target_key_id, target_fingerprint,
  revoked_at, signing_domain])` — a **five-element** CBOR array with the
  domain-separation tag `linkkeys-key-revocation-v1` first. This is the
  older house tuple pattern, NOT the local-RP envelopes' two-element
  `CBOR([context, payload])` framing.
- The verifier recomputes each signature's payload from that signature's
  **wire** `domain` field; the `domain` parameter only *filters* which
  signatures are eligible. (This is what defeats cross-domain signature
  reuse: a signature whose wire `domain` lies about its binding recomputes
  to different bytes and fails.)
- Sibling-key validity (expiry/revocation) is a **wall-clock** check in the
  Rust implementation (`check_signing_key_valid` takes no `now`); this port
  defaults `now` to the wall clock and only accepts an override for tests.
- Invalid signatures are silently skipped; distinctness is by signer key
  id; the only failure mode is an insufficient count of valid signers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from . import crypto
from .generated import codec as _codec  # noqa: F401  (side effect: attaches to_cbor/from_cbor)
from .generated.codec import cbor_encode
from .generated.types import DomainPublicKey, RevocationCertificate

# Minimum number of distinct sibling signatures required to revoke a key.
REVOCATION_QUORUM = 2

_REVOCATION_TAG = "linkkeys-key-revocation-v1"


class RevocationError(Exception):
    """The certificate did not reach the sibling-signature quorum."""

    def __init__(self, got: int, need: int):
        super().__init__(f"revocation certificate has {got} valid sibling signature(s), need {need}")
        self.got = got
        self.need = need


def revocation_payload(target_key_id: str, target_fingerprint: str, revoked_at: str, signing_domain: str) -> bytes:
    """The canonical signed bytes: `CBOR([tag, target_key_id,
    target_fingerprint, revoked_at, signing_domain])` — the signing
    sibling's domain is bound per-signature to stop cross-domain reuse."""
    return cbor_encode([_REVOCATION_TAG, target_key_id, target_fingerprint, revoked_at, signing_domain])


def count_valid_signers(
    cert: RevocationCertificate,
    domain_keys: List[DomainPublicKey],
    domain: str,
    now: Optional[datetime] = None,
) -> int:
    """Count the DISTINCT signer key ids whose signature survives every
    filtering rule (not the target, wire domain equals `domain`, signer key
    present + currently-valid signing key) and cryptographically verifies
    over the recomputed payload. `now` defaults to the wall clock (see
    module docs) — the override exists for deterministic tests only."""
    if now is None:
        now = datetime.now(timezone.utc)

    valid_signers = set()
    for sig in cert.signatures:
        # A key can never authorize its own revocation.
        if sig.signed_by_key_id == cert.target_key_id:
            continue
        # The signature must be bound to this domain (filter only; the
        # payload below is recomputed from the signature's own wire field).
        if sig.domain != domain:
            continue
        key = next((k for k in domain_keys if k.key_id == sig.signed_by_key_id), None)
        if key is None:
            continue
        # Only a currently-valid signing key counts toward the quorum.
        if key.key_usage != "sign":
            continue
        if crypto.signing_key_validity(key.expires_at, key.revoked_at, now) != crypto.KeyValidity.VALID:
            continue

        payload = revocation_payload(cert.target_key_id, cert.target_fingerprint, cert.revoked_at, sig.domain)
        try:
            crypto.resolve_and_verify(key.algorithm, payload, sig.signature, key.public_key)
        except crypto.CryptoError:
            continue
        valid_signers.add(sig.signed_by_key_id)

    return len(valid_signers)


def verify_revocation_certificate(
    cert: RevocationCertificate,
    domain_keys: List[DomainPublicKey],
    domain: str,
    now: Optional[datetime] = None,
) -> None:
    """Verify a revocation certificate against a domain's public key set.
    Requires at least `REVOCATION_QUORUM` DISTINCT signing keys of `domain`,
    each currently valid and NOT the target key, to have signed the
    canonical payload. Raises `RevocationError` on insufficient quorum."""
    got = count_valid_signers(cert, domain_keys, domain, now)
    if got < REVOCATION_QUORUM:
        raise RevocationError(got=got, need=REVOCATION_QUORUM)


def apply_revocations(
    trusted: List[DomainPublicKey],
    revocations: List[RevocationCertificate],
    domain: str,
    now: Optional[datetime] = None,
) -> List[DomainPublicKey]:
    """Apply quorum-verified revocation certificates to a trusted key set:
    any key a valid certificate targets is dropped, no matter what the
    fetched key entry itself says (its own `revoked_at` may well be unset —
    that is the whole point of the sibling-certificate channel). Certificates
    that fail verification are ignored. Returns the filtered list."""
    result = list(trusted)
    for cert in revocations:
        try:
            verify_revocation_certificate(cert, result, domain, now)
        except RevocationError:
            continue
        result = [k for k in result if k.key_id != cert.target_key_id]
    return result
