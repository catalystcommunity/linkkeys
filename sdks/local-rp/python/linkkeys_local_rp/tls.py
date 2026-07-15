"""Client-side TLS pinning: verify a peer's certificate by its SPKI public
key fingerprint against a DNS-published `fp=` set — no CA chain, matching
the trust model `crates/linkkeys/src/tcp/tls.rs` uses for every LinkKeys
TCP peer.

`crates/linkkeys/src/tcp/tls.rs` / `crates/linkkeys-rpc-client/src/tls.rs`
pin `sha256(spki.subject_public_key.data)` — the raw bytes of the
SubjectPublicKeyInfo's `subjectPublicKey` BIT STRING — and generate every
LinkKeys domain TLS certificate from an **Ed25519** domain signing key
(`generate_domain_tls_cert`, via a hand-built PKCS8 DER wrapper). Per
RFC 8410, an Ed25519 SPKI's `subjectPublicKey` BIT STRING contents ARE
exactly the 32 raw public key bytes (no ASN.1 padding/framing inside the bit
string), so `cert.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)`
reproduces the identical bytes the Rust side hashes. This SDK therefore only
ever needs to handle Ed25519 leaf certificates — there is no other key type
in the LinkKeys TLS trust model to support.

Python's `ssl` module cannot express "verify only by SPKI pin, ignore
WebPKI/hostname" as a built-in verification mode, so this module uses
`ssl.CERT_NONE` (skip the built-in chain/hostname checks entirely) and
performs the pin check itself, manually, as a **mandatory** post-handshake
step — the socket is closed and an error raised before a single
application byte is trusted if the pin doesn't match.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import crypto


class TlsError(Exception):
    pass


class PinMismatch(TlsError):
    pass


class UnsupportedCertificateKeyType(TlsError):
    pass


class CertificateExpired(TlsError):
    pass


def extract_hostname(host_port: str) -> str:
    host, _, _port = host_port.rpartition(":")
    return host or host_port


def _leaf_public_key_fingerprint(der_bytes: bytes) -> str:
    """Extract the SPKI raw public-key bytes from a DER certificate and
    return their SHA-256 hex fingerprint — the same value
    `crates/linkkeys/src/tcp/tls.rs` computes from `spki.subject_public_key.data`."""
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except ValueError as e:
        raise TlsError(f"peer certificate could not be parsed: {e}") from e

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    if now < not_before or now > not_after:
        raise CertificateExpired("peer certificate is not within its validity period")

    public_key = cert.public_key()
    if not isinstance(public_key, Ed25519PublicKey):
        raise UnsupportedCertificateKeyType(
            f"expected an Ed25519 certificate public key, got {type(public_key).__name__}"
        )
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return crypto.fingerprint(raw)


def dial_tls_pinned(raw_sock: socket.socket, server_hostname: str, expected_fingerprints: List[str]) -> ssl.SSLSocket:
    """Wrap `raw_sock` in a TLS client connection pinned to
    `expected_fingerprints`, presenting no client certificate (public
    domain-key/revocation fetch and ticket redemption must not require
    mutual TLS — design doc, "Required Network Access"). Raises `TlsError`
    and closes the socket if the peer's certificate does not pin to any of
    `expected_fingerprints`.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        tls_sock = context.wrap_socket(raw_sock, server_hostname=server_hostname)
    except Exception:
        # The handshake itself failed (network error, protocol mismatch,
        # etc, as opposed to our own pin check below) -- close the raw
        # socket ourselves since wrap_socket never handed back an object
        # that owns it.
        raw_sock.close()
        raise
    try:
        der_bytes = tls_sock.getpeercert(binary_form=True)
        if der_bytes is None:
            raise TlsError("peer presented no certificate")
        fp = _leaf_public_key_fingerprint(der_bytes)
        expected_lower = {f.lower() for f in expected_fingerprints}
        if fp.lower() not in expected_lower:
            raise PinMismatch(
                f"certificate fingerprint {fp} does not match any expected fingerprint"
            )
    except Exception:
        tls_sock.close()
        raise
    return tls_sock
