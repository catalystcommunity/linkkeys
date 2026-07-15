# Accepting regular (DNS-pinned) LinkKeys logins from Python

This document is for a Python app developer who wants to let users log in
with **any** LinkKeys identity provider on the internet — the normal,
DNS-pinned protocol flow. That is **not** what the `linkkeys_local_rp`
package in this directory implements. See "local-RP vs regular-RP" near the
end before you start copying code from here.

## Architecture: your app never touches a private key

A regular LinkKeys login needs a relying-party (RP) server that holds a
LinkKeys **domain key** — it signs outbound auth requests and decrypts the
tokens that come back. Your Python app is not supposed to hold that key
itself. Instead you run a second, small deployment: the same `linkkeys`
server binary as any identity provider, just configured in RP mode (no login
UI, no human user accounts, `rp.enabled: true`). Your app talks to *that*
server over the network, authenticated with a plain API key, and never sees
a private key. See `docs/DEPLOYING-RP.md` for the full deployment
(Helm chart, values, gateway TLS passthrough) — this document picks up once
that RP server is running and focuses on the Python side.

```
 Browser                Your Python App          Your RP server           Identity Provider
    |                         |                         |                         |
    |--- log in with -------->|                         |                         |
    |    you@idp.example      |-- Rp/sign-request ----->|                         |
    |                         |<--- signed_request ------|                         |
    |<--- redirect to ------- |                         |                         |
    |     idp /auth/authorize |                         |                         |
    |------------------------------------- user authenticates at the IDP -------->|
    |<--------------------------------------------- redirect to your /callback ---|
    |    ?encrypted_token=...                            |                         |
    |--- GET /callback ------>|                         |                         |
    |                         |-- Rp/decrypt-token ----->|                         |
    |                         |<--- signed_assertion ----|                         |
    |                         |-- Rp/verify-assertion -->|-- verifies vs IDP's --->|
    |                         |<--- verified assertion --|    published keys       |
    |                         |-- Rp/userinfo-fetch ---->|-- redeems claims ------>|
    |                         |<--- UserInfo -------------|                         |
    |<--- session cookie -----|                         |                         |
```

Your RP server is itself a full participant in the DNS-pinned trust model
(it has its own `_linkkeys`/`_linkkeys_apis` TXT records), and your app's
connection *to* it is pinned the same way every other LinkKeys TCP peer
connection is: by the RP server's own DNS-published key fingerprints, not by
a certificate authority.

## Prerequisites

1. **Deploy your RP server.** Follow `docs/DEPLOYING-RP.md`. You need its
   TCP endpoint (`tcpPort`, default `4987`) reachable from your app.

2. **Initialize domain keys and create a service account for your app**,
   inside the RP server:

   ```sh
   linkkeys domain init
   linkkeys user create my-webapp "My Web Application" --api-key --relation api_access
   # Save the printed API key -- it will not be shown again.
   ```

   `--relation api_access` grants the `api_access` relation at creation
   time. If you forgot it, or need to grant it to an already-existing
   service account, use the standalone grant command instead (DB-direct,
   idempotent, run where the RP server's database lives):

   ```sh
   linkkeys relation grant-local my-webapp api_access
   ```

   This is not optional and not automatic. The `Rp` CSIL service (every
   operation your app calls below) requires the caller's API key to carry
   the dedicated `api_access` relation on the RP's domain — a valid API key
   alone is rejected with `Forbidden`. This is enforced in
   `crates/linkkeys/src/tcp/mod.rs`'s dispatch (`required_relation_for_op`
   in `crates/linkkeys/src/services/authorization.rs` maps every `Rp`
   operation to `RELATION_API_ACCESS`) specifically so a leaked ordinary
   user API key can't be used to drive the sign/decrypt oracles. The
   constant and the CLI subcommand: `RELATION_API_ACCESS` /
   `RelationCommands::GrantLocal` in
   `crates/linkkeys/src/services/authorization.rs` and
   `crates/linkkeys/src/cli/mod.rs`. `deploy/live.sh` uses the same
   `relation grant-local` command for live deployments.

3. **Check DNS** for your RP server's own domain:

   ```sh
   linkkeys domain dns-check
   ```

   This prints the `_linkkeys` TXT record (`fp=` fingerprints — pin these
   in your app's config below) and the `_linkkeys_apis` TXT record
   (`tcp=`/`https=`) it expects to find published. Publish them. Your app
   pins to the `fp=` values directly (as a small fixed list in
   configuration, the same way you'd pin a certificate's public key) —
   it does not need to re-resolve DNS on every call, though it's free to.

4. **Your app needs no DNS entries of its own** for this flow beyond a
   reachable `callback_url` the identity provider's browser redirect can
   reach.

## The login flow, wire-level

Everything below is TCP CSIL-RPC (`csil/linkkeys.csil`'s `Rp` service),
never HTTP. See "A note on the HTTP routes" at the end — the HTTP JSON
routes older docs described were removed from the server when S2S moved to
TCP (`docs/DEPLOYING-RP.md` now documents the TCP integration correctly).

```
service Rp {
    sign-request:      RpSignRequest      -> RpSignResponse,
    decrypt-token:      RpDecryptRequest   -> RpDecryptResponse,
    verify-assertion:   RpVerifyRequest    -> RpVerifyResponse,
    userinfo-fetch:     RpUserInfoRequest  -> UserInfo,
    issue-attestation:  RpIssueAttestationRequest -> RpIssueAttestationResponse
}
```

1. **`Rp/sign-request`** `{callback_url, nonce, requested_claims?}` →
   `{signed_request}`. Your app generates a fresh `nonce` and calls this
   before ever redirecting the browser.
2. **Redirect the browser** to
   `https://<user's chosen domain>/auth/authorize?...&signed_request=<...>`
   (`user_hint=` is optional — a login-form-prefill hint, not a trust
   input).
3. The identity provider authenticates the user and redirects the browser
   back to your `callback_url` with `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** `{encrypted_token}` → `{signed_assertion}`.
5. **`Rp/verify-assertion`** `{signed_assertion, expected_domain}` →
   `{assertion, verified}`. `expected_domain` is the domain your app
   expected to authenticate against — the one you asked the user for at
   step 1 — checked against the assertion's own `domain` field on the
   server side. **Nonce single-use is your app's job**, not the server's:
   compare `assertion.nonce` against the nonce you generated at step 1 and
   make sure you can't do that comparison twice (see "App responsibilities"
   below).
6. **`Rp/userinfo-fetch`** (optional) `{token, api_base, domain}` → claims.
   `token` is the `signed_assertion` string from step 4; `api_base` and
   `domain` identify the issuing IDP (the RP server redeems the claims from
   there — it holds the domain key needed to prove it's the assertion's
   audience, your app does not).

Every `Rp` call's envelope carries your API key in the CSIL-RPC envelope's
`auth` field (`crates/csilgen-transport/src/rpc.rs`'s `RpcRequest.auth`) —
this is how `authenticate_tcp_request` in `crates/linkkeys/src/tcp/mod.rs`
identifies your service account; there is no separate header or cookie.

## Complete Python walkthrough

There's no packaged regular-RP client for Python — the `linkkeys_local_rp`
package in this directory implements the *different*, DNS-less local-RP
mode. What follows builds a small RP client directly, reusing this
package's TLS-pinning, transport, and generated CSIL types/codec (all of
which are protocol-mode-agnostic), and inlining only the handful of lines
that are specific to this package's own private `rpc.py` module (its
CSIL-RPC envelope framing has no `auth` field, because the local-RP protocol
never needs one).

Everything below that doesn't require a live RP server + IDP (construction,
CBOR envelope encode/decode, DNS TXT parsing) was actually executed against
`sdks/local-rp/python/.venv` while writing this document — see the note at
the end of this section.

### `rp_client.py` — the reusable glue

```python
"""A minimal regular-RP client: talks TCP CSIL-RPC to your own RP server,
authenticated with an API key. Not part of the linkkeys_local_rp package --
that package implements the DNS-less local-RP mode instead. Everything
imported below (transport.StdTransport, tls.dial_tls_pinned/extract_hostname,
dns.*, rpc.MAX_FRAME_SIZE, generated.codec, generated.types) is genuine
package plumbing this reuses; only the envelope framing with an `auth` field
is inlined, because linkkeys_local_rp.rpc's own framing is private
(underscore-prefixed) and has no `auth` field -- the local-RP protocol it
serves never authenticates with an API key.
"""

from __future__ import annotations

import socket
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

from linkkeys_local_rp.transport import StdTransport
from linkkeys_local_rp import tls as lk_tls
from linkkeys_local_rp import dns as lk_dns
from linkkeys_local_rp.dns import SystemDnsResolver, DnsParseError
from linkkeys_local_rp.rpc import MAX_FRAME_SIZE
from linkkeys_local_rp.generated.codec import CborTag, cbor_encode, cbor_decode
from linkkeys_local_rp.generated.types import (
    RpSignRequest, RpSignResponse,
    RpDecryptRequest, RpDecryptResponse,
    RpVerifyRequest, RpVerifyResponse,
    RpUserInfoRequest, UserInfo,
    ClaimRequest, RequestedClaim,
)

_CSIL_RPC_VERSION = 1
_TAG_ENCODED_CBOR = 24


class RpCallError(Exception):
    """Raised for both transport-level and CSIL-RPC status failures."""


@dataclass
class RpConfig:
    tcp_addr: str                 # e.g. "127.0.0.1:4987" -- your RP server
    fingerprints: List[str]       # fp= values from `linkkeys domain dns-check`
    api_key: str                  # the service account's API key (api_access granted)
    domain: str                   # your RP's own domain, sent as relying_party=
    required_claims: List[str] = field(default_factory=list)


def _build_request_envelope(op: str, req, api_key: str) -> bytes:
    envelope = {
        "v": _CSIL_RPC_VERSION,
        "service": "Rp",
        "op": op,
        "payload": CborTag(_TAG_ENCODED_CBOR, req.to_cbor()),
        "auth": api_key,
    }
    return cbor_encode(envelope)


def _parse_response_envelope(response_bytes: bytes, decode_response):
    envelope = cbor_decode(response_bytes)
    status = envelope.get("status")
    if status != 0:
        raise RpCallError(f"server error (status={status}): {envelope.get('error')}")
    payload_tag = envelope.get("payload")
    payload = payload_tag.value if isinstance(payload_tag, CborTag) else b""
    return decode_response(payload)


def _send_frame(sock, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(4, "big"))
    sock.sendall(data)


def _recv_exact(sock, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RpCallError("connection closed before expected bytes were received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(sock) -> bytes:
    length = int.from_bytes(_recv_exact(sock, 4), "big")
    if length > MAX_FRAME_SIZE:
        raise RpCallError(f"peer frame too large ({length} bytes, max {MAX_FRAME_SIZE})")
    return _recv_exact(sock, length)


def rp_call(rp_config: RpConfig, op: str, req, decode_response):
    """Call one `Rp/<op>` on your RP server: TLS-pinned to its published
    fingerprints, authenticated with your app's API key. No client
    certificate is presented -- your app holds no domain key."""
    request_bytes = _build_request_envelope(op, req, rp_config.api_key)

    transport = StdTransport()
    raw_sock = transport.dial(rp_config.tcp_addr)
    hostname = lk_tls.extract_hostname(rp_config.tcp_addr)
    tls_sock = lk_tls.dial_tls_pinned(raw_sock, hostname, rp_config.fingerprints)
    try:
        _send_frame(tls_sock, request_bytes)
        response_bytes = _recv_frame(tls_sock)
    finally:
        tls_sock.close()

    return _parse_response_envelope(response_bytes, decode_response)


def default_claim_request() -> ClaimRequest:
    """Adjust to whatever claims your app actually needs."""
    return ClaimRequest(
        required=[RequestedClaim(claim_type="display_name", datatype="text")],
        optional=[RequestedClaim(claim_type="email", datatype="email")],
    )


def resolve_api_base(domain: str, resolver=None) -> str:
    """Look up the IDP's own `_linkkeys_apis` TXT record for its `https=`
    base URL; fall back to `https://<domain>` if there is none (matching
    the Rust reference RP client, `demoappsite/src/main.rs`'s
    `resolve_api_base`)."""
    resolver = resolver or SystemDnsResolver()
    name = lk_dns.linkkeys_apis_dns_name(domain)
    try:
        for txt in resolver.txt_lookup(name):
            try:
                apis = lk_dns.parse_linkkeys_apis_txt(txt)
            except DnsParseError:
                continue
            if apis.https_base:
                return apis.https_base
    except Exception:
        pass
    return f"https://{domain}"


def build_authorize_redirect(rp_config: RpConfig, api_base: str, callback_url: str,
                              nonce: str, signed_request: str, user_hint: Optional[str]) -> str:
    params = {
        "callback_url": callback_url,
        "nonce": nonce,
        "user_hint": user_hint or "",
        "relying_party": rp_config.domain,
        "signed_request": signed_request,
    }
    return f"{api_base}/auth/authorize?{urllib.parse.urlencode(params)}"


def begin_login(rp_config: RpConfig, callback_url: str, user_domain: str,
                 user_hint: Optional[str] = None) -> tuple[str, dict]:
    """Returns (redirect_url, pending) -- `pending` must be persisted by the
    caller between this call and `complete_login`, tied to the browser
    session, and used at most once (see "App responsibilities")."""
    nonce = str(uuid.uuid4())
    sign_resp: RpSignResponse = rp_call(
        rp_config, "sign-request",
        RpSignRequest(
            callback_url=callback_url,
            nonce=nonce,
            requested_claims=default_claim_request(),
        ),
        RpSignResponse.from_cbor,
    )
    api_base = resolve_api_base(user_domain)
    redirect_url = build_authorize_redirect(
        rp_config, api_base, callback_url, nonce, sign_resp.signed_request, user_hint,
    )
    pending = {"nonce": nonce, "domain": user_domain, "api_base": api_base}
    return redirect_url, pending


def complete_login(rp_config: RpConfig, pending: dict, encrypted_token: str) -> UserInfo:
    """`pending` is whatever `begin_login` returned; the caller is
    responsible for having retrieved-and-discarded it exactly once before
    calling this (single-use)."""
    decrypt_resp: RpDecryptResponse = rp_call(
        rp_config, "decrypt-token",
        RpDecryptRequest(encrypted_token=encrypted_token),
        RpDecryptResponse.from_cbor,
    )
    verify_resp: RpVerifyResponse = rp_call(
        rp_config, "verify-assertion",
        RpVerifyRequest(
            signed_assertion=decrypt_resp.signed_assertion,
            expected_domain=pending["domain"],
        ),
        RpVerifyResponse.from_cbor,
    )
    if not verify_resp.verified:
        raise RpCallError("assertion did not verify")
    assertion = verify_resp.assertion
    if assertion.nonce != pending["nonce"]:
        raise RpCallError("nonce mismatch -- possible replay")
    if assertion.domain != pending["domain"]:
        raise RpCallError("domain mismatch")

    return rp_call(
        rp_config, "userinfo-fetch",
        RpUserInfoRequest(
            token=decrypt_resp.signed_assertion,
            api_base=pending["api_base"],
            domain=pending["domain"],
        ),
        UserInfo.from_cbor,
    )
```

### What actually ran

The socket/TLS parts of `rp_call` need a live RP server to exercise (there
is no fake-carrier seam exposed for this mode the way `dispatch_for_test` is
for the Rust server-side tests, and standing one up is outside a docs task).
Everything else in the module above — construction, the CBOR envelope
encode and decode, the CSIL type round-trips, DNS TXT parsing, and the
redirect URL builder — is plain code with no network dependency, and was
run for real against `sdks/local-rp/python/.venv`:

```pycon
>>> cfg = RpConfig(tcp_addr="127.0.0.1:4987", fingerprints=["a"*64, "b"*64],
...                 api_key="lk_test_key", domain="myapp.example.com")
>>> req = RpSignRequest(callback_url="https://myapp.example.com/auth/callback",
...                      nonce=str(uuid.uuid4()), requested_claims=default_claim_request())
>>> wire_bytes = _build_request_envelope("sign-request", req, cfg.api_key)
>>> envelope = cbor_decode(wire_bytes)
>>> (envelope["service"], envelope["op"], envelope["auth"] == cfg.api_key)
('Rp', 'sign-request', True)
>>> RpSignRequest.from_cbor(envelope["payload"].value).nonce == req.nonce
True
```

plus: an `RpSignResponse`/`RpDecryptRequest`/`RpDecryptResponse`/
`RpVerifyRequest`/`RpVerifyResponse`/`RpUserInfoRequest` CBOR round-trip
for every type used above (`X.from_cbor(x.to_cbor()) == x`); a synthetic
success-status response envelope parsed back through
`_parse_response_envelope`; a synthetic error-status envelope confirmed to
raise `RpCallError`; `resolve_api_base` against a fake `DnsResolver`
returning a canned `_linkkeys_apis` TXT string (confirms the `https=`
parse) and against one returning nothing (confirms the `https://<domain>`
fallback); and `build_authorize_redirect` confirmed to produce a
well-formed `.../auth/authorize?...` URL with the expected query
parameters. All of it passed, importing only the installed
`linkkeys-local-rp` package (`pip show linkkeys-local-rp` in that venv
shows it installed editable from this directory) — no SDK code was
modified to make this work.

### The HTTP handler pair

Your web framework is your own choice; this uses the standard library's
`http.server` so the example needs no extra dependency beyond what's already
in the SDK's venv. A Flask app looks structurally identical — two routes,
same calls into `rp_client`.

```python
"""app.py -- the web app side. Run your RP server separately (see
docs/DEPLOYING-RP.md) and set RP_TCP_ADDR / RP_FINGERPRINTS / RP_API_KEY /
RP_DOMAIN before starting this.
"""

import os
import secrets
import urllib.parse
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from rp_client import RpConfig, RpCallError, begin_login, complete_login

RP_CONFIG = RpConfig(
    tcp_addr=os.environ["RP_TCP_ADDR"],
    fingerprints=[fp.strip() for fp in os.environ["RP_FINGERPRINTS"].split(",") if fp.strip()],
    api_key=os.environ["RP_API_KEY"],
    domain=os.environ["RP_DOMAIN"],
)
CALLBACK_URL = os.environ.get("CALLBACK_URL", "http://localhost:8080/callback")

# Demo-only storage. A real deployment needs a server-side store shared
# across worker processes (Redis, a DB table with an expiry) -- see "App
# responsibilities" below. Sessions here are likewise in-memory and are lost
# on restart; use a real session store for anything beyond a demo.
PENDING_LOGINS: dict[str, dict] = {}
SESSIONS: dict[str, dict] = {}


class Handler(BaseHTTPRequestHandler):
    def _cookie(self, name: str) -> str | None:
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return jar[name].value if name in jar else None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/login":
            return self._start_login(urllib.parse.parse_qs(parsed.query))
        if parsed.path == "/callback":
            return self._callback(urllib.parse.parse_qs(parsed.query))
        self.send_response(404)
        self.end_headers()

    def _start_login(self, query: dict):
        user_domain = query.get("domain", [""])[0].strip()
        if not user_domain:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"?domain=<the identity provider domain> is required")
            return

        redirect_url, pending = begin_login(RP_CONFIG, CALLBACK_URL, user_domain)

        # Single-use handle for `pending`: a random id, stored server-side,
        # handed to the browser only as an opaque cookie value. The
        # callback consumes (pops) this entry -- see _callback below.
        pending_id = secrets.token_urlsafe(32)
        PENDING_LOGINS[pending_id] = pending

        self.send_response(302)
        self.send_header("Location", redirect_url)
        cookie = cookies.SimpleCookie()
        cookie["pending_id"] = pending_id
        cookie["pending_id"]["path"] = "/"
        cookie["pending_id"]["httponly"] = True
        cookie["pending_id"]["samesite"] = "Lax"
        # cookie["pending_id"]["secure"] = True  # enable once served over HTTPS
        self.send_header("Set-Cookie", cookie["pending_id"].OutputString())
        self.end_headers()

    def _callback(self, query: dict):
        pending_id = self._cookie("pending_id")
        # Pop, not peek: this is what makes the pending login single-use.
        # Whether or not verification below succeeds, this id can never be
        # replayed -- there is nothing left in PENDING_LOGINS to redeem.
        pending = PENDING_LOGINS.pop(pending_id, None) if pending_id else None
        if pending is None:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"No pending login found -- it may have expired or already been used")
            return

        encrypted_token = query.get("encrypted_token", [""])[0]
        if not encrypted_token:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing encrypted_token")
            return

        try:
            user_info = complete_login(RP_CONFIG, pending, encrypted_token)
        except RpCallError as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"Login failed: {e}".encode())
            return

        session_id = secrets.token_urlsafe(32)
        SESSIONS[session_id] = {
            "user_id": user_info.user_id,
            "domain": user_info.domain,
            "display_name": user_info.display_name,
            "claims": {c.claim_type: c.claim_value for c in user_info.claims},
        }

        self.send_response(302)
        self.send_header("Location", "/")
        cookie = cookies.SimpleCookie()
        cookie["session_id"] = session_id
        cookie["session_id"]["path"] = "/"
        cookie["session_id"]["httponly"] = True
        cookie["session_id"]["samesite"] = "Lax"
        self.send_header("Set-Cookie", cookie["session_id"].OutputString())
        self.end_headers()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
```

## App responsibilities

This mirrors what every other LinkKeys SDK in this repo hands back to the
app (see this package's own `README.md`, "App developer responsibilities"):

- **Nonce single-use.** The server does not track your nonces for you —
  `assertion.nonce == pending["nonce"]` only proves the callback matches
  *a* login you started; it does not by itself stop the same callback URL
  from being replayed. The mechanism above is deletion: `pending` (which
  carries the nonce) is looked up by a one-time, unguessable id and
  `.pop()`-ed out of storage the instant the callback handler runs, before
  verification. A second request with the same `pending_id` cookie finds
  nothing and is rejected outright. If you use signed cookies instead of a
  server-side store, you need some other single-use mechanism (a
  once-column in a DB row, a short-TTL cache keyed by nonce) since a signed
  cookie can be replayed as many times as an attacker can resubmit it.
- **Sessions.** `complete_login` returns verified protocol facts
  (`UserInfo`: `user_id`, `domain`, `display_name`, `claims`) and nothing
  else — it does not create a session, set a cookie, or touch a database.
  Building a local session/user record from those facts, and deciding how
  long it lives, is entirely your app's call.
- **API key storage.** `RP_CONFIG.api_key` is a bearer credential for your
  RP server's `Rp` service — anyone holding it can mint sign/decrypt/verify
  calls as your app (though not forge assertions outright; the RP server's
  own domain key is what actually signs/decrypts). Store it the same way
  you'd store a database credential: environment/secret manager, never
  committed, never logged. Never log the API key, `encrypted_token`,
  `signed_assertion`, or claim values (AGENTS.md's "Error Handling": never
  log keys, claim values, session tokens, or credentials).
- **Fingerprint pinning.** `RP_FINGERPRINTS` is your trust anchor for the
  connection to your own RP server. Rotate it whenever the RP server's
  signing keys rotate (re-run `linkkeys domain dns-check` and update your
  app's config) — an out-of-date fingerprint list means `dial_tls_pinned`
  starts refusing the connection outright (fails closed, not open).

## local-RP vs regular-RP

This document covers the **regular** flow: your app runs its own
DNS-pinned RP server, and users log in with identities on any LinkKeys
domain that publishes standard `_linkkeys`/`_linkkeys_apis` DNS records.
That's almost certainly what you want for a normal web app.

The `linkkeys_local_rp` package that actually lives in this directory
(`sdks/local-rp/python/linkkeys_local_rp/`) implements something different:
**DNS-less local-RP identity** (see `dns-less-local-rp-design.md` at the
repo root, and `docs/local-rp-app-developer-guide.md`,
`docs/local-rp-operator-guide.md`, `docs/local-rp-security-tradeoffs.md`,
`docs/local-rp-key-lifecycle.md`). That mode is for apps with **no public
DNS at all** — a LAN jukebox, a desktop tool, a self-hosted service on a
home network — where the app's identity is a locally-generated signing key
fingerprint (SSH-host-key style) rather than a domain, and it must be
individually approved per LinkKeys IDP before it can redeem claim tickets.
It needs no RP server of its own and never touches a domain key, but every
IDP has to explicitly trust its fingerprint first, and revoking that trust
kills the app's access to that IDP outright. Use it if you genuinely have
no DNS name to hang an RP server off of; otherwise use the flow in this
document.

## A note on the HTTP routes in `docs/DEPLOYING-RP.md`

That document's "Web App Integration" section lists
`POST /v1alpha/sign-request.json`, `/v1alpha/decrypt-token.json`, and
`/v1alpha/verify-assertion.json` as bearer-token HTTP routes. As of the
current server code, **these routes are not registered** — searching
`crates/linkkeys/src/web/` for their handlers turns up nothing, and the only
callers of the shared `sign_request_core` / `decrypt_token_core` /
`verify_assertion_core` functions in `crates/linkkeys/src/web/rp.rs` are
`crates/linkkeys/src/tcp/mod.rs`'s `dispatch_rp` and the test suite. The
`Rp` service is served exclusively over TCP CSIL-RPC now, matching the
TCP-first migration elsewhere in this codebase (the S2S HTTP routes in
`crates/linkkeys/src/web/mod.rs` carry the same
`// TODO: deprecated, remove later` markers). `demoappsite/src/main.rs` —
the Rust reference RP web app checked into this repo — bears this out: its
`rp_call` helper drives everything through
`linkkeys_rpc_client::send_request(..., "Rp", op, payload, Some(&api_key))`
and contains no HTTP calls to its RP server at all. This document (and the
`rp_client.py` above) follow the code; `docs/DEPLOYING-RP.md`'s "Web App
Integration" section has since been corrected to document the same TCP
integration.
