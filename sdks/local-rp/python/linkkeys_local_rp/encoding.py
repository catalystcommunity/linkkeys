"""Base64url (unpadded) URL-parameter helpers.

Mirrors `crates/liblinkkeys/src/encoding.rs`'s `Base64UrlUnpadded` helpers,
used for the begin route's `?signed_request=` parameter and the callback
redirect's `&encrypted_token=` parameter (Wire Precision: "URL and parameter
conventions"). Strict: standard-alphabet input (`+`/`/`) and padded input
(`=`) are both rejected, matching `base64ct::Base64UrlUnpadded`'s decoder
exactly (see `sdks/local-rp/conformance/url_params.json`'s negative cases).
"""

from __future__ import annotations

import base64
import re

from .generated import codec as _codec  # noqa: F401  (side effect: attaches to_cbor/from_cbor)
from .generated.types import LocalRpEncryptedCallback, SignedLocalRpLoginRequest

_B64URL_UNPADDED_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class DecodeError(Exception):
    pass


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    """Strict base64url decode: rejects the standard alphabet (`+`/`/`) and
    any padding (`=`) present in the input string itself."""
    if not _B64URL_UNPADDED_RE.match(s):
        raise DecodeError(f"not valid unpadded base64url: {s!r}")
    remainder = len(s) % 4
    if remainder == 1:
        raise DecodeError(f"invalid base64url length: {s!r}")
    padded = s + "=" * ((4 - remainder) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as e:  # noqa: BLE001
        raise DecodeError(f"base64url decode failed: {e}") from e


def signed_local_rp_login_request_to_url_param(signed: SignedLocalRpLoginRequest) -> str:
    return b64url_encode(signed.to_cbor())


def signed_local_rp_login_request_from_url_param(param: str) -> SignedLocalRpLoginRequest:
    cbor_bytes = b64url_decode(param)
    try:
        return SignedLocalRpLoginRequest.from_cbor(cbor_bytes)
    except DecodeError:
        raise
    except Exception as e:  # noqa: BLE001
        raise DecodeError(f"CBOR decode failed: {e}") from e


def local_rp_encrypted_callback_to_url_param(callback: LocalRpEncryptedCallback) -> str:
    return b64url_encode(callback.to_cbor())


def local_rp_encrypted_callback_from_url_param(param: str) -> LocalRpEncryptedCallback:
    cbor_bytes = b64url_decode(param)
    try:
        return LocalRpEncryptedCallback.from_cbor(cbor_bytes)
    except DecodeError:
        raise
    except Exception as e:  # noqa: BLE001
        raise DecodeError(f"CBOR decode failed: {e}") from e
