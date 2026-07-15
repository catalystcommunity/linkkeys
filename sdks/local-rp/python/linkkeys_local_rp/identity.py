"""`generate_local_rp_identity` and the raw-byte storage helpers (design doc:
"SDK API Shape", "Byte Storage Helpers").

A local RP identity is exactly one Ed25519 signing keypair, one X25519
encryption keypair, and a self-signed `SignedLocalRpDescriptor` binding them
together. There is no continuity story across rotation — generating a new
identity means a new fingerprint, full stop.

Security note (design doc, "Byte Storage Helpers"): the private key fields
in `LocalRpKeyMaterial` do not directly identify a user, but they control
this app's entire local RP identity — anyone holding them can sign login
requests and redeem claim tickets as this app. Store them with ordinary
application-secret care (the same care as a database credential or API
key), not merely as configuration.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from . import crypto, local_rp
from .generated import codec as _codec  # noqa: F401  (side effect: attaches to_cbor/from_cbor)
from .generated.types import SignedLocalRpDescriptor
from .timeutil import to_rfc3339

# Default local RP key lifetime: 10 years (design doc, "One Signing Key and
# One Encryption Key" — "Default lifetime: 10 years. Rotation is a
# deliberate operator event.").
DEFAULT_LIFETIME = timedelta(days=3650)


class IdentityError(Exception):
    pass


@dataclass
class GenerateLocalRpIdentityConfig:
    """Input to `generate_local_rp_identity`. Big-config, single struct, per
    the design doc's "SDK API Shape" ("Every SDK should have big-config,
    single-function APIs first")."""

    app_name: str
    now: datetime
    local_domain_hint: Optional[str] = None
    # AEAD suites this app can decrypt callbacks with, in preference order.
    # Defaults to both registry suites when None.
    supported_suites: Optional[List[str]] = None
    # Key/descriptor lifetime from `now`. Defaults to DEFAULT_LIFETIME (10
    # years) when None.
    lifetime: Optional[timedelta] = None


@dataclass
class LocalRpKeyMaterial:
    """A local RP's full key material: signing keypair, encryption keypair,
    the self-signed descriptor binding them (which also carries `app_name`,
    `local_domain_hint`, `supported_suites`, and the created/expires
    timestamps), and the identity fingerprint.

    Private key fields are raw 32-byte values — see the module docs'
    security note before persisting them."""

    signing_private_key: bytes
    signing_public_key: bytes
    encryption_private_key: bytes
    encryption_public_key: bytes
    descriptor: SignedLocalRpDescriptor
    fingerprint: str


def generate_local_rp_identity(config: GenerateLocalRpIdentityConfig) -> LocalRpKeyMaterial:
    """`generate_local_rp_identity(config) -> LocalRpKeyMaterial` (design
    doc, "SDK API Shape"). Generates a fresh Ed25519 signing keypair and a
    *separate* X25519 encryption keypair (never algebraically derived — see
    the design doc's "Encryption Key Is Separate, Not Derived"), builds and
    self-signs the `SignedLocalRpDescriptor` binding them, and returns
    everything the app needs to persist."""
    if not config.app_name.strip():
        raise IdentityError("app_name must not be empty")

    signing_public_key, signing_private_key = crypto.generate_ed25519_keypair()
    encryption_public_key, encryption_private_key = crypto.generate_x25519_keypair()

    suites = config.supported_suites if config.supported_suites is not None else crypto.AeadSuite.all_supported()
    if not suites:
        raise IdentityError("supported_suites must not be empty")

    lifetime = config.lifetime if config.lifetime is not None else DEFAULT_LIFETIME
    created_at = to_rfc3339(config.now)
    expires_at = to_rfc3339(config.now + lifetime)

    descriptor = local_rp.build_local_rp_descriptor(
        config.app_name,
        config.local_domain_hint,
        signing_public_key,
        encryption_public_key,
        list(suites),
        created_at,
        expires_at,
    )
    fingerprint = descriptor.fingerprint
    signed_descriptor = local_rp.sign_local_rp_descriptor(descriptor, signing_private_key)

    return LocalRpKeyMaterial(
        signing_private_key=signing_private_key,
        signing_public_key=signing_public_key,
        encryption_private_key=encryption_private_key,
        encryption_public_key=encryption_public_key,
        descriptor=signed_descriptor,
        fingerprint=fingerprint,
    )


# ---------------------------------------------------------------------
# Byte storage helpers (design doc: "Byte Storage Helpers")
# ---------------------------------------------------------------------


def signing_key_to_bytes(key: bytes) -> bytes:
    """Raw 32-byte signing key (public or private) -> bytes. Trivial, but
    provided so callers never invent their own encoding."""
    return bytes(key)


def signing_key_from_bytes(data: bytes) -> bytes:
    if len(data) != 32:
        raise IdentityError(f"signing key must be 32 bytes, got {len(data)}")
    return bytes(data)


def encryption_key_to_bytes(key: bytes) -> bytes:
    return bytes(key)


def encryption_key_from_bytes(data: bytes) -> bytes:
    if len(data) != 32:
        raise IdentityError(f"encryption key must be 32 bytes, got {len(data)}")
    return bytes(data)


def fingerprint_to_string(fp: str) -> str:
    """The canonical fingerprint string form — a pass-through, since in this
    SDK the fingerprint IS a hex string already (design doc: "fingerprint:
    hex string ... the existing LinkKeys fingerprint format, everywhere,
    with no bytes variant")."""
    return fp


def fingerprint_from_string(s: str) -> str:
    """Parse/validate a fingerprint string: exactly 64 lowercase-normalized
    hex characters (a SHA-256 digest). Rejects anything else so a malformed
    value can never silently pass as a pin or an identity."""
    from . import dns as dns_mod

    if dns_mod.is_valid_fingerprint(s):
        return s.lower()
    raise IdentityError(f"not a valid fingerprint (want 64 hex chars): {s!r}")


# Magic prefix for the identity-bundle byte format below. This is an
# SDK-local storage convenience, NOT a protocol wire format — nothing in
# the design doc's Wire Precision governs it, and no conformance vector
# covers it. Versioned so a future incompatible layout change fails loudly
# instead of silently misparsing.
_IDENTITY_BUNDLE_MAGIC = b"LKI1"


def local_rp_identity_to_bytes(identity: LocalRpKeyMaterial) -> bytes:
    """`local_rp_identity_to_bytes(identity) -> bytes` (design doc, "SDK API
    Shape" + "Byte Storage Helpers": "identity bundle"). Packs both private
    keys and the signed descriptor (which already carries both public keys,
    `app_name`, `local_domain_hint`, `supported_suites`, and the
    created/expires timestamps) into one opaque blob an app can store as a
    single secret/config value. Layout: `MAGIC(4) ||
    signing_private_key(32) || encryption_private_key(32) ||
    descriptor_len(4, BE) || descriptor_cbor`."""
    descriptor_bytes = identity.descriptor.to_cbor()
    out = bytearray()
    out += _IDENTITY_BUNDLE_MAGIC
    out += identity.signing_private_key
    out += identity.encryption_private_key
    out += struct.pack(">I", len(descriptor_bytes))
    out += descriptor_bytes
    return bytes(out)


def local_rp_identity_from_bytes(data: bytes) -> LocalRpKeyMaterial:
    """The inverse of `local_rp_identity_to_bytes`. Public keys and the
    fingerprint are read back out of the embedded descriptor rather than
    re-derived from the private keys, exactly mirroring what was stored;
    this function does no signature/expiry verification (that is
    `check_expirations`'s and the protocol verification chain's job)."""
    header_len = 4 + 32 + 32 + 4
    if len(data) < header_len:
        raise IdentityError("identity bundle too short")
    if data[0:4] != _IDENTITY_BUNDLE_MAGIC:
        raise IdentityError("identity bundle has an unrecognized magic prefix")

    signing_private_key = data[4:36]
    encryption_private_key = data[36:68]
    (descriptor_len,) = struct.unpack(">I", data[68:72])
    descriptor_bytes = data[header_len : header_len + descriptor_len]
    if len(descriptor_bytes) != descriptor_len:
        raise IdentityError("identity bundle descriptor length exceeds available bytes")

    try:
        signed_descriptor = SignedLocalRpDescriptor.from_cbor(descriptor_bytes)
    except Exception as e:  # noqa: BLE001
        raise IdentityError(f"identity bundle descriptor: {e}") from e

    from .generated.types import LocalRpDescriptor

    try:
        descriptor = LocalRpDescriptor.from_cbor(signed_descriptor.descriptor)
    except Exception as e:  # noqa: BLE001
        raise IdentityError(f"identity bundle descriptor payload: {e}") from e

    if len(descriptor.signing_public_key) != 32:
        raise IdentityError("descriptor signing_public_key was not 32 bytes")
    if len(descriptor.encryption_public_key) != 32:
        raise IdentityError("descriptor encryption_public_key was not 32 bytes")

    return LocalRpKeyMaterial(
        signing_private_key=bytes(signing_private_key),
        signing_public_key=bytes(descriptor.signing_public_key),
        encryption_private_key=bytes(encryption_private_key),
        encryption_public_key=bytes(descriptor.encryption_public_key),
        descriptor=signed_descriptor,
        fingerprint=descriptor.fingerprint,
    )
