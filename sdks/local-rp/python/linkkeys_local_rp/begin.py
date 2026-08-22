"""`begin_local_login` (design doc: "SDK API Shape", "Flow" steps 4-6).

Pure/offline: no network access happens here. It generates a fresh
nonce/state, builds and signs a `LocalRpLoginRequest` around the identity's
already-signed descriptor, and returns a redirect URL plus the
pending-login state the app must persist and treat as single-use.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional
from urllib.parse import urlencode

from . import encoding, local_rp
from .identity import LocalRpKeyMaterial
from .timeutil import to_rfc3339

# Default requested claims when the caller doesn't specify any (design doc,
# "Default Claim Set"): a usable "identity" out of the box with zero claim
# configuration.
DEFAULT_REQUESTED_CLAIMS = ["display_name", "email", "handle"]
# Default required claims (design doc, "Default Claim Set").
DEFAULT_REQUIRED_CLAIMS = ["handle"]
# Default login-request lifetime: short-lived, matching the callback's own
# short default lifetime (design doc: "callback lifetime is short, default
# 5 minutes").
DEFAULT_LOGIN_REQUEST_LIFETIME = timedelta(minutes=5)


class BeginLoginError(Exception):
    pass


@dataclass
class BeginLocalLoginConfig:
    """Input to `begin_local_login`.

    `user_domain` accepts a full login or a bare domain. A full login adds a
    username hint. A bare domain selects only the IDP.
    """

    key_material: LocalRpKeyMaterial
    callback_url: str
    user_domain: str
    now: datetime
    requested_claims: Optional[List[str]] = None
    required_claims: Optional[List[str]] = None
    request_lifetime: Optional[timedelta] = None


@dataclass
class LocalLoginRedirect:
    """The redirect URL the app should send the user's browser to. The SDK
    never performs the redirect itself (design doc: "Browser-only Flow")."""

    redirect_url: str


@dataclass
class PendingLogin:
    """The state `begin_local_login` returns for the app to persist (e.g.
    in a server-side session tied to the browser) and pass unchanged to
    `complete_local_login`. **Single-use**: the app must discard it after
    one completion attempt — this package owns no storage and cannot
    enforce that itself.

    `required_claims` is retained (not just `nonce`/`state`/`user_domain`/
    `callback_url`) so `complete_local_login` can enforce, against the
    REDEEMED claims, exactly the claim types this login actually demanded —
    an IDP that omits a required claim (or returns none at all) must not be
    able to complete the login just because the caller forgot to re-check."""

    nonce: bytes
    state: bytes
    user_domain: str
    callback_url: str
    required_claims: List[str]

    def to_dict(self) -> dict:
        """JSON-safe serialization helper (bytes -> hex) so apps can persist
        this in an ordinary JSON session store without inventing their own
        encoding."""
        return {
            "nonce": self.nonce.hex(),
            "state": self.state.hex(),
            "user_domain": self.user_domain,
            "callback_url": self.callback_url,
            "required_claims": list(self.required_claims),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PendingLogin":
        return cls(
            nonce=bytes.fromhex(data["nonce"]),
            state=bytes.fromhex(data["state"]),
            user_domain=data["user_domain"],
            callback_url=data["callback_url"],
            required_claims=list(data.get("required_claims", [])),
        )


def _validate_callback_scheme(url: str) -> None:
    if not (url.startswith("http://") or url.startswith("https://")):
        raise BeginLoginError(f"callback_url must be http:// or https://, got: {url!r}")


def _parse_identity_input(value: str) -> "tuple[Optional[str], str]":
    identity = value.strip()
    if not identity.isascii() or identity.count("@") > 1:
        raise BeginLoginError("identity must be a username@domain or a domain")
    username, separator, domain = identity.partition("@")
    if not separator:
        domain, username = username, None
    elif not re.fullmatch(r"(?!\.)(?!.*\.\.)[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.]{1,64}(?<!\.)", username):
        raise BeginLoginError("identity must be a username@domain or a domain")
    match = re.fullmatch(r"([^:]+)(?::([0-9]+))?", domain)
    host = match.group(1) if match else ""
    port = int(match.group(2)) if match and match.group(2) else None
    labels = host.split(".")
    valid_host = len(host) <= 253 and ("." in host or port is not None) and all(
        1 <= len(label) <= 63 and re.fullmatch(r"(?!-)[A-Za-z0-9-]+(?<!-)", label)
        for label in labels
    )
    if not valid_host or len(domain) > 259 or (port is not None and not 1 <= port <= 65535):
        raise BeginLoginError("identity must be a username@domain or a domain")
    return username, domain.lower()


def begin_local_login(config: BeginLocalLoginConfig) -> "tuple[LocalLoginRedirect, PendingLogin]":
    """`begin_local_login(config) -> (LocalLoginRedirect, PendingLogin)`
    (design doc, "SDK API Shape"). Generates a fresh nonce/state, builds and
    signs a `LocalRpLoginRequest` (envelope + `linkkeys-local-rp-login-request-v1alpha`
    context) around the identity's descriptor, and returns the full redirect
    URL for the user's LinkKeys domain plus the pending-login state."""
    _validate_callback_scheme(config.callback_url)
    username, domain = _parse_identity_input(config.user_domain)

    nonce = os.urandom(32)
    state = os.urandom(32)

    requested_claims = config.requested_claims if config.requested_claims is not None else list(
        DEFAULT_REQUESTED_CLAIMS
    )
    required_claims = config.required_claims if config.required_claims is not None else list(DEFAULT_REQUIRED_CLAIMS)
    lifetime = config.request_lifetime if config.request_lifetime is not None else DEFAULT_LOGIN_REQUEST_LIFETIME
    issued_at = to_rfc3339(config.now)
    expires_at = to_rfc3339(config.now + lifetime)

    request = local_rp.build_local_rp_login_request(
        config.key_material.descriptor,
        config.callback_url,
        nonce,
        state,
        requested_claims,
        required_claims,
        issued_at,
        expires_at,
    )
    signed = local_rp.sign_local_rp_login_request(request, config.key_material.signing_private_key)

    encoded = encoding.signed_local_rp_login_request_to_url_param(signed)

    # Wire Precision: "Begin route: GET /auth/local-rp?signed_request=<...>"
    # — mirrors the existing GET /auth/authorize?signed_request=... shape.
    query = {"signed_request": encoded}
    if username is not None:
        query["username"] = username
    redirect_url = f"https://{domain}/auth/local-rp?{urlencode(query)}"

    return (
        LocalLoginRedirect(redirect_url=redirect_url),
        PendingLogin(
            nonce=nonce,
            state=state,
            user_domain=domain,
            callback_url=config.callback_url,
            required_claims=required_claims,
        ),
    )
