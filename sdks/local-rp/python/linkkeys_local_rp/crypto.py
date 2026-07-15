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


class AeadSuite(str, Enum):
    """Registry of negotiated AEAD suites (design doc, "AEAD suite
    registry"): `aes-256-gcm` is mandatory-to-implement; `chacha20-poly1305`
    is optional. Mirrors `liblinkkeys::crypto::AeadSuite` exactly — same
    parse_str/as_str/all_supported shape.
    """

    AES_256_GCM = AEAD_SUITE_AES_256_GCM
    CHACHA20_POLY1305 = AEAD_SUITE_CHACHA20_POLY1305

    @staticmethod
    def parse_str(s: str) -> Optional["AeadSuite"]:
        try:
            return AeadSuite(s)
        except ValueError:
            return None

    def as_str(self) -> str:
        return self.value

    @staticmethod
    def all_supported() -> List[str]:
        return [AEAD_SUITE_AES_256_GCM, AEAD_SUITE_CHACHA20_POLY1305]

    @staticmethod
    def select_supported(advertised: List[str]) -> Optional["AeadSuite"]:
        """Pick the first suite in `advertised` (preference order) this
        implementation supports. Used by whichever side chooses among an
        advertised list, so a suite outside the advertised list can never be
        selected."""
        for s in advertised:
            suite = AeadSuite.parse_str(s)
            if suite is not None:
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


def resolve_and_verify(algorithm: str, message: bytes, signature: bytes, public_key_bytes: bytes) -> None:
    """Parse a wire-format algorithm string before verifying — the entry
    point for assertion/claim verification paths."""
    alg = SigningAlgorithm.parse_str(algorithm)
    if alg is None:
        raise UnsupportedAlgorithm(algorithm)
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


def signing_key_validity(expires_at: str, revoked_at: Optional[str], now) -> KeyValidity:
    """`now` is an explicit `datetime` (never read from the system clock in
    this module, mirroring liblinkkeys's WASM-viable discipline)."""
    if revoked_at is not None:
        return KeyValidity.REVOKED
    from .timeutil import parse_rfc3339

    try:
        expires = parse_rfc3339(expires_at)
    except ValueError:
        return KeyValidity.BAD_EXPIRY
    return KeyValidity.EXPIRED if now > expires else KeyValidity.VALID


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
    if suite == AeadSuite.CHACHA20_POLY1305:
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    raise UnsupportedAlgorithm(str(suite))


def aead_decrypt(suite: AeadSuite, key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    try:
        if suite == AeadSuite.AES_256_GCM:
            return AESGCM(key).decrypt(nonce, ciphertext, aad)
        if suite == AeadSuite.CHACHA20_POLY1305:
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
