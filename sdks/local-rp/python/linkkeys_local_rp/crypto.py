"""Crypto primitives for the local-RP SDK.

Mirrors `crates/liblinkkeys/src/crypto.rs` for exactly the pieces this SDK
needs (design doc's Python language-matrix row: the `cryptography` package
covers Ed25519, X25519, AEAD, HKDF, and raw byte key import/export; the
Python standard library has none of these). Every function here is pure —
no I/O, no network, no filesystem — matching liblinkkeys' own discipline so
this module stays easy to reason about and test against the conformance
vectors.

Dependency justification (AGENTS.md "every dependency is a liability"):
`cryptography` is the de facto standard, actively maintained, audited Python
crypto library (used by pip, requests, etc.) and is the *only* reasonable way
to get Ed25519/X25519/AES-256-GCM/ChaCha20-Poly1305/HKDF in Python — the
standard library has none of them. There is no lighter-weight alternative
that covers this whole set.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .generated.types import AeadSuite as _GeneratedAeadSuite
from .generated.types import KeyAlgorithm, KeyUsage

ALGORITHM_ED25519 = "ed25519"

AEAD_SUITE_AES_256_GCM = "aes-256-gcm"
AEAD_SUITE_CHACHA20_POLY1305 = "chacha20-poly1305"


class CryptoError(Exception):
    """Base class for every crypto-layer failure in this module."""


class SigningFailed(CryptoError):
    pass


class VerificationFailed(CryptoError):
    pass


class UnsupportedAlgorithm(CryptoError):
    def __init__(self, algorithm: str):
        super().__init__(f"unsupported algorithm: {algorithm}")
        self.algorithm = algorithm


class EncryptionFailed(CryptoError):
    pass


class DecryptionFailed(CryptoError):
    pass


class InvalidKeyLength(CryptoError):
    pass


class SigningAlgorithm(str, Enum):
    """Supported signing algorithms — currently Ed25519 only, mirroring
    `liblinkkeys::crypto::SigningAlgorithm`. New algorithms are added as new
    enum members and a new dispatch arm below; per the design doc there is
    no signature *versioning* story, only new algorithms / new modes.
    """

    ED25519 = ALGORITHM_ED25519

    @staticmethod
    def parse_str(s: str) -> Optional["SigningAlgorithm"]:
        try:
            return SigningAlgorithm(s)
        except ValueError:
            return None

    def as_str(self) -> str:
        return self.value

    @staticmethod
    def all_supported() -> List[str]:
        return [ALGORITHM_ED25519]


# The negotiated AEAD suite registry (design doc, "AEAD suite registry") is
# the CSIL `AeadSuite` enum: on the wire it is a CBOR unsigned integer
# (1 = aes-256-gcm, 2 = chacha20-poly1305). `aes-256-gcm` is
# mandatory-to-implement; `chacha20-poly1305` is optional.
AeadSuite = _GeneratedAeadSuite

_AEAD_KDF_LABELS = {
    _GeneratedAeadSuite.AES_256_GCM: AEAD_SUITE_AES_256_GCM,
    _GeneratedAeadSuite.CHACHA_20_POLY_1305: AEAD_SUITE_CHACHA20_POLY1305,
}
_AEAD_BY_KDF_LABEL = {label: suite for suite, label in _AEAD_KDF_LABELS.items()}


def aead_suite_kdf_label(suite: AeadSuite) -> str:
    """The suite's text id (`aes-256-gcm`, `chacha20-poly1305`). The local-RP
    callback box binds this text into its KDF context, so it never changes,
    even though the wire header carries the suite as a number
    (`AeadSuite::kdf_label` in liblinkkeys)."""
    return _AEAD_KDF_LABELS[suite]


def aead_suite_from_kdf_label(label: str) -> Optional[AeadSuite]:
    """The suite whose text id is `label`, or None when the text names no
    supported suite."""
    return _AEAD_BY_KDF_LABEL.get(label)


def all_supported_aead_suites() -> List[AeadSuite]:
    """Every AEAD suite this implementation supports, in preference order."""
    return [_GeneratedAeadSuite.AES_256_GCM, _GeneratedAeadSuite.CHACHA_20_POLY_1305]


def select_supported_aead_suite(advertised: List[AeadSuite]) -> Optional[AeadSuite]:
    """Pick the first suite in `advertised` (preference order) this
    implementation supports, so a suite outside the advertised list can
    never be selected."""
    for suite in advertised:
        if suite in _AEAD_KDF_LABELS:
            return suite
    return None


def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """Returns (public_key_bytes, private_key_bytes) — private is the raw
    32-byte seed, matching `ed25519_dalek::SigningKey::to_bytes()`."""
    sk = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

    private_bytes = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return public_bytes, private_bytes


def generate_x25519_keypair() -> Tuple[bytes, bytes]:
    """Returns (public_key_bytes, private_key_bytes), both 32 bytes. A
    dedicated encryption keypair — NEVER derived from an Ed25519 signing key
    (design doc: "Encryption Key Is Separate, Not Derived")."""
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

    sk = X25519PrivateKey.generate()
    private_bytes = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return public_bytes, private_bytes


def sign_with_algorithm(algorithm: SigningAlgorithm, message: bytes, private_key_bytes: bytes) -> bytes:
    if algorithm != SigningAlgorithm.ED25519:
        raise UnsupportedAlgorithm(str(algorithm))
    if len(private_key_bytes) != 32:
        raise InvalidKeyLength("Ed25519 private key must be 32 bytes")
    sk = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return sk.sign(message)


def verify_with_algorithm(
    algorithm: SigningAlgorithm, message: bytes, signature: bytes, public_key_bytes: bytes
) -> None:
    """Raises `VerificationFailed` (or `InvalidKeyLength`) on failure;
    returns None on success."""
    if algorithm != SigningAlgorithm.ED25519:
        raise UnsupportedAlgorithm(str(algorithm))
    if len(public_key_bytes) != 32:
        raise InvalidKeyLength("Ed25519 public key must be 32 bytes")
    try:
        vk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        vk.verify(signature, message)
    except (InvalidSignature, ValueError) as e:
        raise VerificationFailed("signature verification failed") from e


def resolve_and_verify(
    algorithm: KeyAlgorithm, message: bytes, signature: bytes, public_key_bytes: bytes
) -> None:
    """Map a wire `KeyAlgorithm` to a signing algorithm before verifying —
    the entry point for assertion/claim verification paths. A key algorithm
    that is not a signing algorithm (for example `x25519`) is rejected."""
    alg = SigningAlgorithm.parse_str(str(algorithm))
    if alg is None:
        raise UnsupportedAlgorithm(str(algorithm))
    verify_with_algorithm(alg, message, signature, public_key_bytes)


def fingerprint(public_key_bytes: bytes) -> str:
    """`sha256(public_key_bytes)` lowercase hex — the canonical LinkKeys
    fingerprint format used everywhere (DNS `fp=`, TLS SPKI pinning, local RP
    identity)."""
    return hashlib.sha256(public_key_bytes).hexdigest()


class KeyValidity(str, Enum):
    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"
    BAD_EXPIRY = "bad_expiry"


def signing_key_validity(expires_at: datetime, revoked_at: Optional[datetime], now: datetime) -> KeyValidity:
    """`now` is an explicit `datetime` (never read from the system clock in
    this module, mirroring liblinkkeys's WASM-viable discipline). A naive
    `expires_at` has no defined instant, so it is a bad expiry."""
    if revoked_at is not None:
        return KeyValidity.REVOKED
    if not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
        return KeyValidity.BAD_EXPIRY
    return KeyValidity.EXPIRED if now > expires_at else KeyValidity.VALID


def is_signing_key(key_usage: KeyUsage) -> bool:
    """True when a wire `key_usage` marks a signing key."""
    return key_usage == KeyUsage.SIGN


def is_encryption_key(key_usage: KeyUsage) -> bool:
    """True when a wire `key_usage` marks an encryption key."""
    return key_usage == KeyUsage.ENCRYPT


def reject_low_order(shared_secret: bytes) -> None:
    """Reject an all-zero ECDH output — the signal a low-order/non-
    contributory X25519 public key forces regardless of the other party's
    private key."""
    if shared_secret == b"\x00" * 32:
        raise EncryptionFailed("non-contributory (low-order) public key rejected")


def aead_encrypt(suite: AeadSuite, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """Dispatches to the concrete AEAD implementation. Ciphertext carries the
    16-byte auth tag appended, matching the RustCrypto `aes-gcm` /
    `chacha20poly1305` crates' `Aead::encrypt` output shape exactly."""
    if suite == AeadSuite.AES_256_GCM:
        return AESGCM(key).encrypt(nonce, plaintext, aad)
    if suite == AeadSuite.CHACHA_20_POLY_1305:
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    raise UnsupportedAlgorithm(str(suite))


def aead_decrypt(suite: AeadSuite, key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    try:
        if suite == AeadSuite.AES_256_GCM:
            return AESGCM(key).decrypt(nonce, ciphertext, aad)
        if suite == AeadSuite.CHACHA_20_POLY_1305:
            return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as e:
        raise DecryptionFailed("AEAD authentication failed") from e
    raise UnsupportedAlgorithm(str(suite))


def hkdf_sha256_expand(shared_secret: bytes, info: bytes, length: int = 32) -> bytes:
    """Full HKDF-SHA256 (extract-then-expand), salt=None. `cryptography`'s
    `HKDF` defaults an absent salt to a zero-filled block per RFC 5869,
    exactly matching the Rust `hkdf` crate's `Hkdf::new(None, ikm)` — so this
    reproduces `liblinkkeys::crypto::sealed_box_kdf` /
    `local_rp::local_rp_callback_kdf` byte-for-byte."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(shared_secret)


@dataclass
class X25519KeyPair:
    public_key: bytes
    private_key: bytes


def x25519_diffie_hellman(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(private_key_bytes)
    pk = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    return sk.exchange(pk)


def x25519_public_from_private(private_key_bytes: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    sk = X25519PrivateKey.from_private_bytes(private_key_bytes)
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
