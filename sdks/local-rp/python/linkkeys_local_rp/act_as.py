"""Act-as grants, grantee side only (docs/spec/reserved/act-as-grants.md).

Mirrors `crates/liblinkkeys/src/act_as.rs` (`GranteeSigner::LocalRp`,
`sign_grant_request`, `sign_refresh_request`, `present`).

A local RP can be the GRANTEE of an act-as grant: a user lets this app act as
the user at an enrolled application (the audience). A local RP can never be
an audience, because a peer cannot resolve its keys through DNS. The home
domain accepts a local-RP grantee only after it approved that local RP.

Every signature covers `CBOR([tag, payload_bytes])` and is made with the
descriptor signing key. The proof carries the signed descriptor, and its
`signed_by_key_id` is the descriptor fingerprint.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Protocol, Tuple, Union
from urllib.parse import parse_qs, urlsplit

from . import crypto
from . import dns as dns_mod
from . import rpc
from .begin import BeginLoginError, _parse_identity_input, _validate_callback_scheme
from .browser import BROWSER_ROUTE_ACT_AS, resolve_browser_endpoint
from .generated import codec as _codec  # noqa: F401  (side effect: attaches to_cbor/from_cbor)
from .generated.types import (
    ActAsCredential,
    ActAsGrant,
    ActAsGrantRequest,
    ActAsPresentation,
    ActAsRefreshRequest,
    ApplicationKeySignature,
    ApplicationRef,
    GranteeProof,
    GranteeRef,
    SignedActAsGrant,
    SignedActAsGrantRequest,
    SignedActAsPresentation,
    SignedActAsRefreshRequest,
    SignedActAsScopeSet,
    SignedLocalRpDescriptor,
)
from .local_rp import DecodeFailed, NonceMismatch, envelope_signature_input
from .transport import StdTransport, Transport

ACT_AS_GRANT_REQUEST_TAG = "linkkeys-act-as-grant-request-v1alpha"
ACT_AS_REFRESH_REQUEST_TAG = "linkkeys-act-as-refresh-request-v1alpha"
ACT_AS_PRESENTATION_TAG = "linkkeys-act-as-presentation-v1alpha"

# Default request window of a grant request, in seconds.
DEFAULT_ACT_AS_REQUEST_WINDOW_SECONDS = 300
# Largest request window the reference home domain accepts, in seconds.
MAX_ACT_AS_REQUEST_WINDOW_SECONDS = 900
# Request window of a refresh request, in seconds.
ACT_AS_REFRESH_WINDOW_SECONDS = 300


class ActAsError(Exception):
    """Invalid input to an act-as call, or a callback without its parameters."""


class ActAsSigningMaterial(Protocol):
    """The part of `LocalRpKeyMaterial` that a grantee signature needs."""

    descriptor: SignedLocalRpDescriptor
    fingerprint: str
    signing_private_key: bytes


def format_act_as_time(t: datetime) -> str:
    """Whole-second RFC3339 in UTC, ending in `Z` (`act_as::format_time`)."""
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def act_as_grant_hash(grant_bytes: bytes) -> bytes:
    """SHA-256 of `SignedActAsGrant.grant`. A presentation binds this value."""
    return hashlib.sha256(grant_bytes).digest()


def local_rp_grantee(key_material: ActAsSigningMaterial) -> GranteeRef:
    """The local-RP form of `GranteeRef`."""
    return GranteeRef(local_rp_descriptor_fingerprint=key_material.fingerprint)


def _prove(key_material: ActAsSigningMaterial, tag: str, payload: bytes) -> GranteeProof:
    signature = crypto.sign_with_algorithm(
        crypto.SigningAlgorithm.ED25519,
        envelope_signature_input(tag, payload),
        key_material.signing_private_key,
    )
    return GranteeProof(
        local_rp_descriptor=key_material.descriptor,
        signature=ApplicationKeySignature(signed_by_key_id=key_material.fingerprint, signature=signature),
    )


def _fresh_nonce() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def sign_act_as_grant_request(
    request: ActAsGrantRequest, key_material: ActAsSigningMaterial
) -> SignedActAsGrantRequest:
    """Sign an `ActAsGrantRequest` with the descriptor signing key. Pure."""
    request_bytes = request.to_cbor()
    return SignedActAsGrantRequest(
        request=request_bytes, proof=_prove(key_material, ACT_AS_GRANT_REQUEST_TAG, request_bytes)
    )


def sign_act_as_refresh_request(
    request: ActAsRefreshRequest, key_material: ActAsSigningMaterial
) -> SignedActAsRefreshRequest:
    """Sign an `ActAsRefreshRequest` with the descriptor signing key. Pure."""
    request_bytes = request.to_cbor()
    return SignedActAsRefreshRequest(
        request=request_bytes, proof=_prove(key_material, ACT_AS_REFRESH_REQUEST_TAG, request_bytes)
    )


def signed_act_as_grant_request_to_url_param(signed: SignedActAsGrantRequest) -> str:
    """`base64url-no-pad(CBOR(SignedActAsGrantRequest))`, the `signed_request` value."""
    return base64.urlsafe_b64encode(signed.to_cbor()).rstrip(b"=").decode("ascii")


def _check_optional_seconds(name: str, value: Optional[int], minimum: int) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ActAsError(f"{name} must be a whole number >= {minimum}")


# ---------------------------------------------------------------------
# Begin
# ---------------------------------------------------------------------


@dataclass
class BeginActAsConfig:
    """Input to `begin_act_as`.

    `user_domain` is the user's login or domain. Only the domain is used.
    `scope_set` is the audience's `SignedActAsScopeSet` as CBOR bytes, exactly
    as the audience sent it. `request_window_seconds` defaults to 300 and
    must not be more than 900. `dns` defaults to the system resolver.
    """

    key_material: ActAsSigningMaterial
    user_domain: str
    scope_set: bytes
    callback_url: str
    now: datetime
    requested_lifetime_seconds: Optional[int] = None
    requested_renewal_window_seconds: Optional[int] = None
    dns: Optional[dns_mod.DnsResolver] = None
    request_window_seconds: int = DEFAULT_ACT_AS_REQUEST_WINDOW_SECONDS


@dataclass
class ActAsRedirect:
    redirect_url: str


@dataclass
class PendingActAs:
    """State to keep between `begin_act_as` and `complete_act_as_callback`.
    Single-use."""

    nonce: str
    user_domain: str
    callback_url: str

    def to_dict(self) -> dict:
        return {"nonce": self.nonce, "user_domain": self.user_domain, "callback_url": self.callback_url}

    @classmethod
    def from_dict(cls, data: dict) -> "PendingActAs":
        return cls(nonce=data["nonce"], user_domain=data["user_domain"], callback_url=data["callback_url"])


def begin_act_as(config: BeginActAsConfig) -> Tuple[ActAsRedirect, PendingActAs]:
    """Sign an `ActAsGrantRequest` and return the URL that sends the browser
    to the user's home domain (`/auth/act-as`), plus the pending state.
    Browser endpoint discovery and fallback are the same as
    `begin_local_login`."""
    try:
        _validate_callback_scheme(config.callback_url)
        _username, domain = _parse_identity_input(config.user_domain)
    except BeginLoginError as e:
        raise ActAsError(str(e)) from e
    _check_optional_seconds("requested_lifetime_seconds", config.requested_lifetime_seconds, 1)
    _check_optional_seconds("requested_renewal_window_seconds", config.requested_renewal_window_seconds, 0)
    window = config.request_window_seconds
    if isinstance(window, bool) or not isinstance(window, int) or not 1 <= window <= MAX_ACT_AS_REQUEST_WINDOW_SECONDS:
        raise ActAsError(f"request_window_seconds must be 1..{MAX_ACT_AS_REQUEST_WINDOW_SECONDS}")

    try:
        scope_set = SignedActAsScopeSet.from_cbor(config.scope_set)
    except Exception as e:
        raise DecodeFailed(f"scope set: {e}") from e

    nonce = _fresh_nonce()
    request = ActAsGrantRequest(
        grantee=local_rp_grantee(config.key_material),
        scope_set=scope_set,
        requested_lifetime_seconds=config.requested_lifetime_seconds,
        requested_renewal_window_seconds=config.requested_renewal_window_seconds,
        # A local RP has no enrolling account, so it never sends a handle claim.
        grantee_handle_claim=None,
        callback_url=config.callback_url,
        nonce=nonce,
        requested_at=format_act_as_time(config.now),
        expires_at=format_act_as_time(config.now + timedelta(seconds=window)),
    )
    signed = sign_act_as_grant_request(request, config.key_material)
    dns = config.dns if config.dns is not None else dns_mod.SystemDnsResolver()
    redirect_url = resolve_browser_endpoint(
        dns, domain, BROWSER_ROUTE_ACT_AS, signed_act_as_grant_request_to_url_param(signed)
    )
    return (
        ActAsRedirect(redirect_url=redirect_url),
        PendingActAs(nonce=nonce, user_domain=domain, callback_url=config.callback_url),
    )


# ---------------------------------------------------------------------
# Callback
# ---------------------------------------------------------------------


def complete_act_as_callback(pending: PendingActAs, arrived: Union[str, dict]) -> str:
    """Read `act_as_grant_id` and `nonce` from the callback and return the
    grant id. `arrived` is the full callback URL, its query string, or a dict
    of query parameters. The nonce must equal the pending nonce
    (constant-time compare)."""
    if isinstance(arrived, dict):
        values = {k: [v] if isinstance(v, str) else list(v) for k, v in arrived.items()}
    else:
        query = urlsplit(arrived).query if "://" in arrived else arrived.lstrip("?")
        values = parse_qs(query, keep_blank_values=True)
    # A repeated parameter is ambiguous: refuse it rather than pick one.
    if len(values.get("act_as_grant_id", [])) > 1 or len(values.get("nonce", [])) > 1:
        raise ActAsError("callback repeats an act-as parameter")
    params = {k: v[0] for k, v in values.items() if v}
    grant_id = params.get("act_as_grant_id")
    nonce = params.get("nonce")
    if not grant_id or nonce is None:
        raise ActAsError("callback needs act_as_grant_id and nonce")
    if not hmac.compare_digest(pending.nonce.encode("utf-8"), nonce.encode("utf-8")):
        raise NonceMismatch("nonce does not match")
    return grant_id


# ---------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------


@dataclass
class ActAsRefreshResult:
    grant: SignedActAsGrant
    # True when the home domain made a new signature for this call.
    signed: bool


def refresh_act_as_grant(
    key_material: ActAsSigningMaterial,
    user_domain: str,
    grant_id: str,
    now: datetime,
    transport: Optional[Transport] = None,
    dns: Optional[dns_mod.DnsResolver] = None,
) -> ActAsRefreshResult:
    """Fetch the grant, or a renewed grant, with `ActAs/refresh-grant` on the
    user's home domain (`PendingActAs.user_domain`). Uses the same discovery
    and pinned TCP path as claim-ticket redemption."""
    if not grant_id:
        raise ActAsError("grant_id must not be empty")
    request = ActAsRefreshRequest(
        grant_id=grant_id,
        grantee=local_rp_grantee(key_material),
        requested_at=format_act_as_time(now),
        expires_at=format_act_as_time(now + timedelta(seconds=ACT_AS_REFRESH_WINDOW_SECONDS)),
        nonce=_fresh_nonce(),
    )
    signed = sign_act_as_refresh_request(request, key_material)
    response = rpc.refresh_act_as_grant(
        transport if transport is not None else StdTransport(),
        dns if dns is not None else dns_mod.SystemDnsResolver(),
        user_domain,
        signed,
    )
    # The audience checks the grant signature. This only checks that the home
    # domain returned the grant this call asked for, so a confused or hostile
    # server cannot hand this grantee another grant.
    try:
        grant = ActAsGrant.from_cbor(response.grant.grant)
    except Exception as e:  # noqa: BLE001 - re-raise as our own decode error
        raise DecodeFailed(f"refresh-grant grant: {e}") from e
    if grant.grant_id != grant_id:
        raise ActAsError("refresh-grant returned another grant id")
    if grant.grantee.application is not None or grant.grantee.local_rp_descriptor_fingerprint != key_material.fingerprint:
        raise ActAsError("refresh-grant returned a grant for another grantee")
    if not _ascii_casefold_equal(grant.subject_domain, user_domain):
        raise ActAsError("refresh-grant returned a grant from another subject domain")
    return ActAsRefreshResult(grant=response.grant, signed=response.signed)


def _ascii_casefold_equal(a: str, b: str) -> bool:
    """Domain comparison with ASCII-only case folding."""
    table = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    return a.translate(table) == b.translate(table)


# ---------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------


@dataclass
class ActAsPresentationResult:
    credential: ActAsCredential
    credential_cbor: bytes


def present_act_as(
    grant: SignedActAsGrant,
    audience: ApplicationRef,
    request_digest: bytes,
    now: datetime,
    nonce: bytes,
    key_material: ActAsSigningMaterial,
) -> ActAsPresentationResult:
    """Build and sign the `ActAsCredential` for one call to the audience.
    `request_digest` is defined by the audience's protocol. Use a fresh
    `nonce` per call. Pure."""
    presentation = ActAsPresentation(
        grant_hash=act_as_grant_hash(grant.grant),
        audience=audience,
        request_digest=request_digest,
        presented_at=format_act_as_time(now),
        nonce=nonce,
    )
    presentation_bytes = presentation.to_cbor()
    credential = ActAsCredential(
        grant=grant,
        presentation=SignedActAsPresentation(
            presentation=presentation_bytes,
            proof=_prove(key_material, ACT_AS_PRESENTATION_TAG, presentation_bytes),
        ),
    )
    return ActAsPresentationResult(credential=credential, credential_cbor=credential.to_cbor())
