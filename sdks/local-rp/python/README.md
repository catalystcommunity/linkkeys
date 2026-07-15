# linkkeys-local-rp (Python)

Python SDK for LinkKeys' **DNS-less local RP identity** mode — see
`dns-less-local-rp-design.md` at the repo root for the full design; this
package implements its "SDK API Shape" section. It lets a locally installed
app (a LAN jukebox, a desktop tool, a self-hosted service with no public
DNS) use LinkKeys for login without running its own DNS-pinned relying
party. The app's identity is the fingerprint of a locally-generated signing
key (SSH-host-key style), not a domain.

Mirrors the Rust reference SDK (`sdks/local-rp/rust/`) module-for-module —
read that crate's README first if you want the fullest picture; this one
notes only where Python differs.

## Package layout

```
sdks/local-rp/python/
  pyproject.toml
  linkkeys_local_rp/
    __init__.py       # public API surface (re-exports)
    identity.py        # generate_local_rp_identity + byte storage helpers
    begin.py           # begin_local_login
    complete.py         # complete_local_login (the full verification chain)
    local_rp.py         # pure protocol helpers (envelope sign/verify, callback
                        # seal/open, timestamp/expiration checks) -- mirrors
                        # crates/liblinkkeys/src/local_rp.rs
    claims.py            # claim signature/revocation/expiry verification --
                        # mirrors crates/liblinkkeys/src/claims.rs
    revocation.py         # sibling-signed key revocation certificate
                        # verification + application to the trusted key set
                        # -- mirrors crates/liblinkkeys/src/revocation.rs
    crypto.py            # Ed25519/X25519/AEAD/HKDF/fingerprint wrappers over
                        # the `cryptography` package
    dns.py                # _linkkeys/_linkkeys_apis TXT parsing, key pinning,
                        # the DnsResolver seam + SystemDnsResolver (dnspython)
    tls.py                 # SPKI-fingerprint TLS pinning (the trust anchor for
                        # every TCP peer this SDK talks to)
    transport.py            # the TCP dial seam + AddressPolicy
    rpc.py                   # CSIL-RPC framing + fetch_domain_keys /
                        # redeem_claim_ticket
    encoding.py               # base64url-unpadded URL-parameter helpers
    timeutil.py                # RFC3339 parse/format shared by every module
    generated/                   # csilgen-generated CSIL types + CSIL-RPC
                        # client (checked in, never hand-edited -- see
                        # "Code generation" below)
  tests/
    conftest.py
    test_conformance_*.py    # one file per conformance vector JSON file
    test_flow.py               # fake-IDP end-to-end flow tests
```

## Environment setup

System Python 3.10+ is fine; there is no repo-wide Python toolchain
precedent to follow beyond `csilgen/transports/python/` (a plain,
dependency-free package tested via `python3 -m unittest discover`) — this
SDK needs real third-party dependencies (`cryptography`, `dnspython`), so it
adds a `pyproject.toml` and uses a venv, per this task's own instructions.

```sh
cd sdks/local-rp/python
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Running the tests

```sh
cd sdks/local-rp/python
source .venv/bin/activate
pytest
```

(Equivalently: `python -m pytest`, or `pytest sdks/local-rp/python` from the
repo root once the venv is active.) This is the command to wire into
`tools.sh test-local-rp-python` — this task's instructions say not to edit
`tools.sh` directly; see "Wiring into tools.sh" below.

## Code generation

Types + a CSIL-RPC-facing client are generated via:

```sh
csilgen generate --input csil/linkkeys.csil --target python-client \
  --output sdks/local-rp/python/linkkeys_local_rp/generated/
```

`python-client` was the right sub-target (over bare `python`, which also
emits a server surface this SDK never needs, or `python-typesonly`, which
would have meant hand-rolling the entire CBOR codec for ~15 local-RP
record types by hand). The generated `types.py` (dataclasses) +
`codec.py` (`to_cbor()`/`from_cbor()` methods, monkey-patched onto each
dataclass) turned out to produce **byte-identical canonical CBOR field
ordering** to the Rust `liblinkkeys` codec this whole protocol is specified
against — verified field-by-field against
`crates/liblinkkeys/src/generated/codec.gen.rs` before trusting it, and
confirmed by every conformance test in this package passing. `client.py` /
`client_async.py` are also generated and checked in (per "generate CSIL
types + client"), but this SDK's own `rpc.py` does not call through their
`DomainKeysClient`/`LocalRpClient` wrapper classes — historically because
their `Transport.call()` seam passed a lowercased service name (a csilgen
defect since fixed upstream; the regenerated client now passes verbatim CSIL
wire names, so switching to the wrappers is possible but optional).
`rpc.py` instead builds the two real `CsilRpcRequest`s directly, reusing
`generated/codec.py`'s `to_cbor()`/`from_cbor()` for the typed payloads —
mirroring exactly what the Rust reference SDK's own `rpc.rs` does, for an
analogous reason documented in its module doc.

Regenerate with the same command above; the output is fully reproducible
(re-running produces byte-identical files) and must never be hand-edited —
fix the generator or file a request instead.

## Dependency justification (AGENTS.md: "every dependency is a liability")

- **`cryptography`**: the Python standard library has no Ed25519, X25519,
  AES-256-GCM, ChaCha20-Poly1305, or HKDF at all. `cryptography` is the de
  facto standard, actively maintained, audited library that covers this
  entire set (and raw key import/export) — there is no lighter alternative
  that covers it. The design doc's own language matrix names it explicitly.
- **`dnspython`**: the standard library's `socket` module cannot perform DNS
  TXT queries (only address resolution). `dnspython` is the de facto
  standard pure-Python DNS library and is explicitly sanctioned by the
  design doc's matrix for this purpose.
- **`pytest`** (dev-only): this task's own instructions specify pytest as
  the test runner.

Nothing else. TLS pinning uses only the standard library's `ssl` module
(manual post-handshake verification — see `tls.py`); CBOR encode/decode
reuses the generated `codec.py`'s hand-rolled canonical encoder (no CBOR
library dependency at all).

## App developer responsibilities

Same division of labor as every other LinkKeys SDK — this package returns
verified protocol facts; it never creates a session, writes to an app
database, or manages local user authorization:

- **Key material** (`LocalRpKeyMaterial` / the bytes from
  `local_rp_identity_to_bytes`): persist wherever your app stores its own
  secrets/configuration, with the same care as a database credential or API
  key — anyone holding these bytes can sign login requests and redeem claim
  tickets as your app.
- **`PendingLogin`**: persist it between `begin_local_login` and
  `complete_local_login` (`.to_dict()`/`.from_dict()` give you a JSON-safe
  round trip for an ordinary session store), and **discard it after one
  completion attempt**. This package owns no storage and cannot enforce
  single-use itself — replay protection at the app boundary is your job.
- **Sessions, local user records, authorization decisions**: entirely
  yours, using the verified facts `complete_local_login` returns.
- **The redirect itself**: `begin_local_login` returns a URL; this package
  never issues an HTTP redirect or opens a browser (a UX decision outside
  its scope — see the design doc's "Browser-only Flow").

### Quickstart

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
# ... write stored_bytes to your app's secret/config store ...

# Later, per login attempt:
identity = local_rp_identity_from_bytes(stored_bytes)
redirect, pending = begin_local_login(BeginLocalLoginConfig(
    key_material=identity,
    callback_url="http://jukebox.lan:8080/auth/callback",
    user_domain="example.com",   # the LinkKeys domain the user selected/entered
    now=datetime.now(timezone.utc),
))
# Persist pending.to_dict() (e.g. in a server-side session tied to the
# browser), then redirect the user's browser to redirect.redirect_url.

# On callback, your app's HTTP handler receives a request whose query
# string carries `encrypted_token=<...>`. Pass the request's full URL and
# that parameter's raw value to complete_local_login:
verified = complete_local_login(
    identity, pending, encrypted_token, arrived_url, datetime.now(timezone.utc)
)
# verified.user_id, verified.user_domain, verified.claims, ... -- session
# creation, local user records, and authorization are all your app's job.
```

## Security notes

- **Key storage**: see "App developer responsibilities" above.
- **Revocation semantics**: revoking this local RP identity at a LinkKeys
  domain stops future logins there and kills that RP's outstanding claim
  tickets immediately (redemption re-checks approval status on every call).
  It does **not** reach into sessions the app already minted from a prior
  successful login — session lifecycle is the app's to manage.
- **No key continuity / rotation**: generating a new identity means a new
  fingerprint and re-approval at every LinkKeys domain that should allow the
  app. There is no "same app, new key" continuity story in this protocol
  version.
- **Network trust anchor**: domain public keys fetched over the network
  (`linkkeys_local_rp.rpc`) are only ever trusted after DNS `fp=` pinning —
  an unpinned/unauthenticated key can never reach the verification chain.
  TLS pinning (`tls.py`) verifies the peer certificate's SPKI public-key
  SHA-256 fingerprint against that pinned set — **not** WebPKI validity —
  exactly mirroring `crates/linkkeys/src/tcp/tls.rs`. Every LinkKeys domain
  TLS certificate is generated from an Ed25519 domain signing key (see
  `crates/linkkeys-rpc-client/src/tls.rs::generate_domain_tls_cert`), so this
  SDK only ever needs to accept Ed25519 leaf certificates; an unexpected key
  type is rejected outright (`tls.UnsupportedCertificateKeyType`) rather than
  silently trusted.
- **No client TLS certificate**: this SDK never presents a client
  certificate — public domain-key fetch and ticket redemption must not
  require mutual TLS (the redemption request's own signature is the
  possession proof instead).
- **Default DNS resolver**: the OS-configured system resolver via
  `dnspython`. LAN resolver spoofing is an accepted, documented tradeoff for
  this mode (the design doc's "Decided" section). Inject a hardened
  `DnsResolver` (e.g. a DoH client) if your deployment needs more.
- **Address policy**: the default `Transport` (`StdTransport`) dials
  whatever address DNS returns, including private/loopback/LAN addresses —
  that is the entire point of this mode. Pass
  `StdTransport(policy=AddressPolicy.PUBLIC_ONLY)` to opt into a stricter
  SSRF-guard posture; nothing in this package applies that restriction by
  default.
- **Expiration**: `check_expirations(identity, now)` reports `notice` (180
  days remaining), `warning` (90 days), `critical` (30 days), and `expired`
  thresholds as facts — this package never blocks a login or forces
  rotation on its own; that decision is the app's.

## Testing

- `tests/test_conformance_*.py` consume every file under
  `sdks/local-rp/conformance/` (`keys`, `envelopes`, `callback_box`,
  `url_params`, `dns`, `tickets`, `expirations`, `revocations`), positive
  and negative cases, exercising this SDK's own wrappers directly. The
  revocation suite covers all nine certificate cases with their exact
  counted-signer expectations, plus the application case proving
  certificates are applied to the key set, not merely verified.
- `tests/test_flow.py` runs `complete_local_login`'s full verification chain
  end-to-end against a real (but locally spun up) TLS+TCP+CSIL-RPC fake IDP,
  with a fake `DnsResolver` injected (no real DNS/network touched) — a happy
  path plus one test per verification-chain failure (wrong audience, wrong
  issuer, nonce mismatch, expired callback, DNS pin mismatch, revoked
  signing key, certificate-revoked signing key, tampered claim signature),
  using the same fixed, publicly-known test key seeds as
  `sdks/local-rp/conformance/keys.json`.

Test counts as of this writing: **31 passed** (22 conformance-vector
tests spanning all eight vector files' positive/negative cases + 9 flow
tests: happy path + 8 failure modes) — no skips, no xfails.

## Wiring into `tools.sh`

Per this task's instructions, `tools.sh` itself was not edited. The exact
command to wire in as `test-local-rp-python`:

```sh
cd sdks/local-rp/python && source .venv/bin/activate && pytest
```

(or, without assuming a pre-existing venv: `cd sdks/local-rp/python &&
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]' && .venv/bin/pytest`).

## Revocation certificates

Sibling-signed key revocation certificates
(`crates/liblinkkeys/src/revocation.rs`; conformance authority:
`sdks/local-rp/conformance/revocations.json` + its README section) are fully
supported: when `get-domain-keys` signals `recent_revocations_available`,
`rpc.fetch_domain_keys` also fetches `DomainKeys/get-revocations` and
**applies** every quorum-verified certificate to the trusted key set — the
target key is dropped no matter what its own fetched entry says (its
`revoked_at` may well be unset; that is the whole point of the sibling
channel). Verification semantics (`revocation.py`): quorum of 2 distinct,
currently-valid sibling signing keys; the target's self-signature never
counts; each signature covers the five-element
`CBOR([tag, target_key_id, target_fingerprint, revoked_at, signing_domain])`
tuple (the older house tuple pattern — NOT the local-RP two-element envelope
framing) recomputed from that signature's own wire `domain` field; sibling
validity is a wall-clock check. Delivery stays best-effort (a failed
revocation *fetch* never fails a login — matching the server's and the
Go/Rust reference SDKs' posture), but a certificate that arrives and
verifies is always applied.

## Known scope limits / follow-ups

- **Suite negotiation** only supports what the conformance vectors and Rust
  reference SDK exercise (`aes-256-gcm`, `chacha20-poly1305`); no other
  registry entries exist to add.
- Generator ambiguity encountered and resolved: see "Code generation" above
  for the `python-client` sub-target choice and the filed csilgen request
  about the generated `Transport` seam's service-name casing.
