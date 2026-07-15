"""linkkeys_local_rp — Python SDK for LinkKeys' DNS-less local RP identity
mode (`dns-less-local-rp-design.md` at the repo root — read it first; this
package implements its "SDK API Shape" section, Python-idiomatically
adapted).

This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
self-hosted service with no public DNS) use LinkKeys for login without
running its own DNS-pinned relying party. The app's identity is the
fingerprint of a locally-generated signing key (SSH-host-key style), not a
domain.

Quickstart
----------

```python
from datetime import datetime, timezone
from linkkeys_local_rp import (
    generate_local_rp_identity, begin_local_login, complete_local_login,
    GenerateLocalRpIdentityConfig, BeginLocalLoginConfig,
    local_rp_identity_to_bytes, local_rp_identity_from_bytes,
)

# Once, at install/setup time -- persist the returned bytes with ordinary
# application-secret care.
identity = generate_local_rp_identity(
    GenerateLocalRpIdentityConfig(app_name="My LAN Jukebox", now=datetime.now(timezone.utc))
)
stored_bytes = local_rp_identity_to_bytes(identity)

# Later, per login attempt:
identity = local_rp_identity_from_bytes(stored_bytes)
redirect, pending = begin_local_login(BeginLocalLoginConfig(
    key_material=identity,
    callback_url="http://jukebox.lan:8080/auth/callback",
    user_domain="example.com",
    now=datetime.now(timezone.utc),
))
# App: persist `pending` (e.g. pending.to_dict() into a session), then
# redirect the browser to redirect.redirect_url.

# On callback (app's HTTP handler received `arrived_url` with an
# `encrypted_token=` query parameter):
verified = complete_local_login(
    identity, pending, encrypted_token, arrived_url, datetime.now(timezone.utc)
)
# verified.user_id, verified.user_domain, verified.claims, ... -- session
# creation, local user records, and authorization are all the app's own
# responsibility.
```

Storage and single-use responsibilities this SDK assigns to the app
---------------------------------------------------------------------

- **Key material**: persist the bytes from `local_rp_identity_to_bytes` with
  ordinary application-secret care (same tier as a database credential or
  API key) — see `identity` module docs.
- **`PendingLogin`**: persist it (e.g. via `.to_dict()`/`.from_dict()`)
  between `begin_local_login` and `complete_local_login`, and discard it
  after one completion attempt. This package owns no storage and cannot
  enforce single-use itself.
- **Sessions, local user records, authorization**: entirely the app's. This
  package returns verified protocol facts; it never creates a session or
  writes to an app database.

Security notes
--------------

- Revoking this local RP identity at the IDP kills future logins AND any
  outstanding claim tickets immediately — but it does **not** reach into
  sessions the app already minted from a prior successful login.
- Key rotation is not supported as a continuity operation: generating a new
  identity means a new fingerprint and re-approval at every LinkKeys domain.
- Domain keys fetched over the network are only ever trusted after DNS
  `fp=` pinning (`rpc.py`) — an unpinned/unauthenticated key can never reach
  the verification chain.
- The default DNS resolver is the OS-configured system resolver via
  `dnspython`; LAN resolver spoofing is an accepted, documented tradeoff for
  this mode. Inject a hardened `DnsResolver` if your deployment needs more.
"""

from .begin import (
    DEFAULT_LOGIN_REQUEST_LIFETIME,
    DEFAULT_REQUESTED_CLAIMS,
    DEFAULT_REQUIRED_CLAIMS,
    BeginLocalLoginConfig,
    BeginLoginError,
    LocalLoginRedirect,
    PendingLogin,
    begin_local_login,
)
from .complete import (
    CompleteLoginError,
    IdentityMismatch,
    RequiredClaimsNotSatisfied,
    VerifiedLocalLogin,
    complete_local_login,
)
from .crypto import AeadSuite, SigningAlgorithm
from .dns import DnsResolver, SystemDnsResolver
from .identity import (
    DEFAULT_LIFETIME,
    GenerateLocalRpIdentityConfig,
    IdentityError,
    LocalRpKeyMaterial,
    encryption_key_from_bytes,
    encryption_key_to_bytes,
    fingerprint_from_string,
    fingerprint_to_string,
    generate_local_rp_identity,
    local_rp_identity_from_bytes,
    local_rp_identity_to_bytes,
    signing_key_from_bytes,
    signing_key_to_bytes,
)
from .local_rp import DEFAULT_CLOCK_SKEW_SECONDS, ExpirationLevel, ExpirationStatus, LocalRpError
from .local_rp import check_expirations as _check_expirations
from .revocation import REVOCATION_QUORUM, RevocationError, verify_revocation_certificate
from .transport import AddressPolicy, StdTransport, Transport

# Re-exported so app code doesn't need to import the generated package
# directly just to name these types.
from .generated.types import Claim, ClaimSignature, DomainPublicKey  # noqa: E402

__all__ = [
    "generate_local_rp_identity",
    "GenerateLocalRpIdentityConfig",
    "LocalRpKeyMaterial",
    "DEFAULT_LIFETIME",
    "local_rp_identity_to_bytes",
    "local_rp_identity_from_bytes",
    "signing_key_to_bytes",
    "signing_key_from_bytes",
    "encryption_key_to_bytes",
    "encryption_key_from_bytes",
    "fingerprint_to_string",
    "fingerprint_from_string",
    "begin_local_login",
    "BeginLocalLoginConfig",
    "LocalLoginRedirect",
    "PendingLogin",
    "DEFAULT_REQUESTED_CLAIMS",
    "DEFAULT_REQUIRED_CLAIMS",
    "DEFAULT_LOGIN_REQUEST_LIFETIME",
    "complete_local_login",
    "VerifiedLocalLogin",
    "check_expirations",
    "ExpirationStatus",
    "ExpirationLevel",
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "Transport",
    "StdTransport",
    "AddressPolicy",
    "DnsResolver",
    "SystemDnsResolver",
    "AeadSuite",
    "SigningAlgorithm",
    "Claim",
    "ClaimSignature",
    "DomainPublicKey",
    "LocalRpError",
    "IdentityError",
    "BeginLoginError",
    "CompleteLoginError",
    "IdentityMismatch",
    "RequiredClaimsNotSatisfied",
    "verify_revocation_certificate",
    "RevocationError",
    "REVOCATION_QUORUM",
]


def check_expirations(identity: LocalRpKeyMaterial, now) -> ExpirationStatus:
    """`check_expirations(identity, now) -> ExpirationStatus` (design doc,
    "SDK API Shape" / "Expiration Helper"). Thin wrapper taking the
    identity's descriptor `expires_at` directly. The SDK reports facts; the
    app decides whether to warn admins, warn users, block login, renew, or
    ignore."""
    from .generated.types import LocalRpDescriptor

    descriptor = LocalRpDescriptor.from_cbor(identity.descriptor.descriptor)
    return _check_expirations(descriptor.expires_at, now)
