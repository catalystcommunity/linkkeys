"""DNS TXT lookup seam + `_linkkeys`/`_linkkeys_apis` record parsing and key
pinning.

Mirrors `crates/liblinkkeys/src/dns.rs` (record parsing, pinning, vouch
verification, `trust_keys`) plus the DNS *lookup* seam itself
(`sdks/local-rp/rust/src/dns.rs`'s `DnsResolver` trait). Per the design
doc's "Required Network Access" / "SDK endpoint discovery and pinning": the
resolver is configurable, defaulting to the system resolver — LAN resolver
spoofing is an accepted, documented tradeoff for this mode.

Dependency justification: the Python standard library has no DNS TXT
lookup capability at all (`socket` only does address resolution). `dnspython`
is the de facto standard, actively maintained pure-Python DNS library and
the design doc's matrix explicitly sanctions it for this purpose.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Protocol

from . import crypto
from .generated.types import DomainPublicKey

DEFAULT_TCP_PORT = 4987

# A DNS TXT character-string is capped at 255 bytes (RFC 1035); records
# longer than this need splitting across multiple strings, which many
# resolvers/zone tools handle poorly.
MAX_TXT_STRING_LEN = 255


class DnsParseError(Exception):
    pass


class NoLinkKeysRecord(DnsParseError):
    pass


class MissingVersion(DnsParseError):
    pass


class UnsupportedVersion(DnsParseError):
    def __init__(self, version: str):
        super().__init__(f"unsupported linkkeys version: {version}")
        self.version = version


class MissingApisEndpoint(DnsParseError):
    pass


class InvalidFormat(DnsParseError):
    pass


@dataclass
class LinkKeysRecord:
    fingerprints: List[str]


@dataclass
class LinkKeysApis:
    tcp: Optional[str]
    https_base: Optional[str]


def linkkeys_dns_name(domain: str) -> str:
    return f"_linkkeys.{domain}"


def linkkeys_apis_dns_name(domain: str) -> str:
    return f"_linkkeys_apis.{domain}"


def _require_lk1_version(parts: List[str]) -> None:
    version = next((p[2:] for p in parts if p.startswith("v=")), None)
    if version is None:
        raise MissingVersion("missing v= tag in TXT record")
    if version != "lk1":
        raise UnsupportedVersion(version)


def parse_linkkeys_txt(txt: str) -> LinkKeysRecord:
    parts = txt.split()
    _require_lk1_version(parts)
    fingerprints = [p[3:] for p in parts if p.startswith("fp=")]
    return LinkKeysRecord(fingerprints=fingerprints)


def _normalize_tcp_endpoint(value: str) -> str:
    if value == "" or ":" in value:
        return value
    return f"{value}:{DEFAULT_TCP_PORT}"


def parse_linkkeys_apis_txt(txt: str) -> LinkKeysApis:
    parts = txt.split()
    _require_lk1_version(parts)

    tcp_raw = next((p[4:] for p in parts if p.startswith("tcp=")), None)
    tcp = _normalize_tcp_endpoint(tcp_raw) if tcp_raw else None

    https_raw = next((p[6:] for p in parts if p.startswith("https=")), None)
    https_base = f"https://{https_raw}" if https_raw else None

    if tcp is None and https_base is None:
        raise MissingApisEndpoint("_linkkeys_apis record has neither tcp= nor https=")

    return LinkKeysApis(tcp=tcp, https_base=https_base)


def is_valid_fingerprint(fp: str) -> bool:
    return len(fp) == 64 and all(c in "0123456789abcdefABCDEF" for c in fp)


def pin_keys_to_fingerprints(keys: List[DomainPublicKey], pinned: List[str]) -> List[DomainPublicKey]:
    """Recompute each candidate key's fingerprint (never trust the wire
    `fingerprint` field) and keep only keys whose recomputed fingerprint is
    a member of `pinned`."""
    pinned_lower = {f.lower() for f in pinned if is_valid_fingerprint(f)}
    return [k for k in keys if crypto.fingerprint(k.public_key).lower() in pinned_lower]


_KEY_VOUCH_TAG = "linkkeys-key-vouch-v1"


def key_vouch_payload(enc_fingerprint: str, enc_expires_at: str) -> bytes:
    from .generated.codec import cbor_encode

    return cbor_encode([_KEY_VOUCH_TAG, enc_fingerprint, enc_expires_at])


def verify_key_vouch(enc_key: DomainPublicKey, signing_key: DomainPublicKey, now) -> bool:
    """Verify that `signing_key` vouches for `enc_key` (encryption keys are
    not published in DNS; they are trusted only via a DNS-pinned signing
    key's vouch)."""
    if enc_key.signed_by_key_id != signing_key.key_id:
        return False
    if crypto.signing_key_validity(signing_key.expires_at, signing_key.revoked_at, now) != crypto.KeyValidity.VALID:
        return False
    if enc_key.key_signature is None:
        return False
    recomputed_fp = crypto.fingerprint(enc_key.public_key)
    payload = key_vouch_payload(recomputed_fp, enc_key.expires_at)
    try:
        crypto.resolve_and_verify(signing_key.algorithm, payload, enc_key.key_signature, signing_key.public_key)
        return True
    except crypto.CryptoError:
        return False


def trust_keys(keys: List[DomainPublicKey], pinned: List[str], now) -> List[DomainPublicKey]:
    """Establish the trusted key set from a fetched key list and the
    DNS-pinned fingerprint set. Signing keys are pinned directly; encryption
    keys are trusted only when a pinned signing key vouches for them.
    Callers MUST treat an empty result as "no trustworthy keys" and fail
    closed."""
    signing = [k for k in keys if k.key_usage == "sign"]
    pinned_signing = pin_keys_to_fingerprints(signing, pinned)

    trusted = list(pinned_signing)
    for k in keys:
        if k.key_usage != "encrypt":
            continue
        if any(verify_key_vouch(k, sk, now) for sk in pinned_signing):
            trusted.append(k)
    return trusted


class DnsResolver(Protocol):
    """Caller-injected DNS TXT lookup seam. Each returned string is one TXT
    record's content (the concatenation of its character-strings)."""

    def txt_lookup(self, name: str) -> List[str]:
        ...


class SystemDnsResolver:
    """Default `DnsResolver`: the OS-configured resolver via `dnspython`.
    Per the design doc's "Decided" section, resolver spoofing on a LAN is an
    accepted, documented tradeoff for this mode; operators wanting hardening
    can inject their own `DnsResolver` (e.g. a DoH client) instead."""

    def txt_lookup(self, name: str) -> List[str]:
        import dns.resolver as _resolver

        try:
            answer = _resolver.resolve(name, "TXT")
        except Exception as e:  # noqa: BLE001 - surfaced uniformly to callers
            raise RuntimeError(f"DNS TXT lookup failed for {name}: {e}") from e

        results = []
        for rdata in answer:
            # Each rdata carries a tuple of character-strings (bytes);
            # concatenate them, matching the Rust resolver seam's
            # `TXT::to_string()` behavior.
            joined = b"".join(rdata.strings)
            results.append(joined.decode("utf-8", errors="replace"))
        return results
