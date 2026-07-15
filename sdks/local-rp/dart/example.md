# Accepting regular (DNS-pinned) LinkKeys logins from Dart

This document is for a Dart app developer who wants to let users log in with
**any** LinkKeys identity provider on the internet — the normal, DNS-pinned
protocol flow ("Sign in with LinkKeys" for `alice@example.com`). That is
**not** what the `linkkeys_local_rp` package in this directory implements —
see "Local-RP vs regular-RP" near the end before you start copying code from
here.

**Read this whole document before wiring anything into a real app**,
especially "The Dart TLS caveat" below. It is the reason this example looks
different in shape from its Go/Python/Java/TypeScript siblings
(`sdks/local-rp/<language>/example.md`): a plain "dial the RP server
directly" client, which is what those documents show, **does not work from
Dart today**, for a specific, verified reason.

## Architecture: your app never touches a private key

A regular LinkKeys login needs a relying-party (RP) server that holds a
LinkKeys **domain key** — it signs outbound auth requests and decrypts the
tokens that come back. Your Dart app is not supposed to hold that key
itself. Instead you run a second, small deployment: the same `linkkeys`
server binary as any identity provider, just configured in RP mode (no login
UI, no human user accounts, `rp.enabled: true`). Your app talks to *that*
server over the network, authenticated with a plain API key, and never sees
a private key. See `docs/DEPLOYING-RP.md` for the full deployment (Helm
chart, values, gateway TLS passthrough) — this document picks up once that
RP server is running and focuses on the Dart side, including the TLS
complication below.

```
 Browser              Your Dart App          Local sidecar proxy         Your RP server            Identity Provider
    |                       |                  (stunnel/socat -- see       |                          |
    |                       |                  "The Dart TLS caveat")      |                          |
    |-- log in with ------->|                       |                      |                          |
    |   you@idp.example     |-- Rp/sign-request -+-->|--- pinned TLS ------>|                          |
    |                       |   (plain TCP,      |   |                     |                          |
    |                       |    loopback only)  |   |<-- signed_request --|                          |
    |                       |<--------------------+---|                    |                          |
    |<-- redirect to ------ |                       |                      |                          |
    |    idp /auth/authorize|                       |                      |                          |
    |------------------------------------------- user authenticates at the IDP ------------------------>|
    |<-------------------------------------------------------------- redirect to your /callback --------|
    |   ?encrypted_token=...                        |                      |                          |
    |-- GET /callback ----->|                       |                      |                          |
    |                       |-- Rp/decrypt-token -->|--- pinned TLS ------>|                          |
    |                       |<-- signed_assertion --|                      |                          |
    |                       |-- Rp/verify-assertion>|--- pinned TLS ------>|-- verifies vs IDP's ----->|
    |                       |<-- verified assertion-|                      |    published keys        |
    |                       |-- Rp/userinfo-fetch ->|--- pinned TLS ------>|-- redeems claims -------->|
    |                       |<-- UserInfo -----------|                     |                          |
    |<-- session cookie ----|                       |                      |                          |
```

Your RP server is itself a full participant in the DNS-pinned trust model
(it has its own `_linkkeys`/`_linkkeys_apis` TXT records), and the
connection to it is pinned the same way every other LinkKeys TCP peer
connection is: by the RP server's own DNS-published key fingerprints, not by
a certificate authority. In every other reference SDK in this repo, *your
app* performs that pinned TLS handshake directly. In Dart, as built today,
it cannot — read on.

## The Dart TLS caveat (read this first)

This SDK's own `README.md` ("Known limitations") documents a `dart:io`
platform gap, verified empirically before any flow-test code in this SDK was
written:

> `dart:io`'s TLS stack (BoringSSL) refuses the handshake outright when the
> server presents an Ed25519 certificate —
> `HandshakeException: Handshake error in server (OS Error:
> NO_COMMON_SIGNATURE_ALGORITHMS(extensions.cc:4823))` — for both serving
> and, by construction, any client connecting to it.

This protocol's TLS pinning is defined in terms of a domain's **Ed25519**
signing key (`crates/linkkeys/src/tcp/tls.rs`'s trust model): the pinned
fingerprint is `sha256(spki_raw_ed25519_public_key)`, and the peer
certificate presented on the RP server's TCP CSIL-RPC port carries exactly
that key. Every reference SDK's pinned-TLS dial — including this Dart SDK's
own `lib/src/rpc/tls_pinning.dart`, whose `connectPinned` function is
written exactly like the Rust/Go/Java equivalents — depends on completing a
TLS handshake against that certificate. `dart:io`'s bundled BoringSSL cannot
do that, full stop. This is not a bug in this SDK to work around with
cleverer code; it is a missing signature-algorithm negotiation in the
platform TLS stack itself, and it blocks a Dart app from driving the `Rp`
service **directly** over TCP CSIL-RPC in the same shape the Go/Python/Java
examples use.

Two consequences worth being explicit about:

- **The `connectPinned`/pin-checking logic in this SDK is not exported**
  from the public barrel (`lib/linkkeys_local_rp.dart`) in the first place —
  it's package-private plumbing for this SDK's own `DomainKeys`/`LocalRp`
  calls, not a general client. Even if `dart:io` could complete the
  handshake, this example would still need to hand-write an equivalent
  pinning routine rather than reuse the SDK's (the same "inline what isn't
  exported" situation the CBOR codec below is in). It is `dart:io` itself,
  not this SDK's API surface, that is the actual blocker.
- This SDK's own flow tests (`test/flow_test.dart`) cannot exercise a real
  in-process TLS handshake either, for the identical reason — they use an
  internal, unexported test seam that skips only the TLS step. That is a
  deliberate, documented tradeoff for *testing* the SDK; it is not something
  an app is meant to ship. This document does not use that seam (it isn't
  exported, and shipping a "skip TLS" client would be a real
  vulnerability, not a docs convenience) — it uses a different, legitimate
  way to skip the TLS step from Dart's side, below.

### The realistic deployment: a loopback TLS-terminating sidecar

The fix that works **today**, without waiting on a `dart:io`/BoringSSL
upstream fix, is to not ask Dart to speak TLS to the RP server at all. Put a
small, purpose-built TLS client in front of it instead — a sidecar process
in the same pod/host as your Dart app, listening on loopback, doing the
pinned TLS handshake to the RP server on your app's behalf, and forwarding
plaintext CSIL-RPC bytes to your Dart process over loopback TCP:

```
 Dart app  --plaintext TCP, loopback only-->  sidecar proxy  --pinned TLS-->  RP server
```

This works because the blocker is specifically `dart:io`'s bundled
BoringSSL, not TLS-with-Ed25519-certificates in general: OpenSSL (which
`stunnel` and `socat`'s `OPENSSL:` address type both link against) has
negotiated Ed25519 TLS certificates since OpenSSL 1.1.1 (2018), years before
this gap in Dart's bundled stack. The sidecar is doing nothing exotic — it's
using a TLS stack that already supports what `dart:io`'s does not.

**Step 1 — pin the sidecar's trust anchor to the RP's DNS-published key**,
the same way any LinkKeys peer pins a domain. Fetch the RP server's live
leaf certificate once and verify its SPKI fingerprint against
`linkkeys domain dns-check`'s `fp=` output *before* trusting it — don't
skip this, or the sidecar's pin degrades to bare trust-on-first-use:

```sh
openssl s_client -connect rp.example.com:4987 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > rp-server-cert.pem

# Must match one of the fp= values `linkkeys domain dns-check` prints for the RP.
openssl x509 -in rp-server-cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256
```

**Step 2 — run the sidecar.** `stunnel` example (a long-running daemon,
easy to wire into a systemd unit or a second container in the same pod):

```ini
; stunnel-client.conf -- terminates the Ed25519-pinned TLS hop dart:io
; cannot perform itself. Runs alongside the Dart app, same pod/host.
pid = /tmp/stunnel-rp-client.pid
foreground = yes

[rp]
client = yes
accept = 127.0.0.1:4988          ; the Dart app dials THIS port, in plaintext
connect = rp.example.com:4987    ; the RP server's real TCP CSIL-RPC port
verifyPeer = yes
CAfile = /etc/stunnel/rp-server-cert.pem   ; pinned to the fingerprint checked above
```

A `socat` one-liner does the same thing without a long-running config file,
if that fits your deployment better:

```sh
socat TCP-LISTEN:4988,bind=127.0.0.1,fork,reuseaddr \
  OPENSSL:rp.example.com:4987,verify=1,cafile=/etc/stunnel/rp-server-cert.pem
```

**Step 3 — point your Dart app at the sidecar, not the RP server.** In the
code below, `RP_TCP_ADDR=127.0.0.1:4988` (the sidecar), never
`rp.example.com:4987` (the RP server) directly.

### The tradeoff, stated plainly

This is a workaround, not a fix, and it has real costs against the
"your app never touches private key material, and the SDK enforces the pin
for you" posture the other reference SDKs get natively:

- **One more moving part.** The sidecar is a separate process your
  deployment must start, restart on crash, and monitor — exactly like any
  other dependency, but one this architecture wouldn't otherwise need.
- **The pin now lives in two places conceptually** (the sidecar's `CAfile`/
  `cafile` and whatever tracks your RP's current fingerprints), and rotates
  on the same schedule your RP's domain-key rotation already requires you to
  track (`linkkeys domain dns-check`) — this is the same operational
  obligation an in-process pinned client would have, just executed by a
  config file instead of code.
- **Misconfiguration fails open, silently.** If `verifyPeer`/`verify=1` is
  ever accidentally dropped from the sidecar config, it silently accepts any
  certificate — there is no compiler, type system, or SDK-level required
  parameter forcing the check the way `connectPinned`'s mandatory
  post-handshake fingerprint comparison does in the other reference SDKs.
  Treat this config file as security-critical: code-review changes to it,
  and consider a startup smoke test that confirms the sidecar actually
  rejects a wrong-fingerprint certificate.
- **The plaintext hop must never leave loopback.** `127.0.0.1:4988` above is
  only safe because it's local — the app and the sidecar share a trust
  boundary (same pod, same host). If they don't, this whole approach is
  unsafe; don't bind the plaintext side to any non-loopback interface.
- **This is not a substitute for a real fix.** The actual fix is upstream:
  `dart:io`/BoringSSL negotiating Ed25519 TLS certificates. Until that
  lands, every Dart app doing this needs its own sidecar; there's no way to
  centralize this workaround inside the SDK, because the SDK's own
  `connectPinned` has exactly the same problem the sidecar exists to route
  around.

Everything below is written **assuming this sidecar is in place** —
`RpConfig.tcpAddr` is the sidecar's loopback address, and the Dart code
never performs a TLS handshake itself. That absence is not an oversight; it
is the direct, visible consequence of the caveat above, and the code is
structured so that fact is obvious at the call site (see `rp_client.dart`'s
`rpCall`, which dials `Transport.dial` and goes straight to CSIL-RPC framing
— no TLS step in between).

## Prerequisites

1. **Deploy your RP server.** Follow `docs/DEPLOYING-RP.md` end to end
   (Helm chart with `rp.enabled: true`, `linkkeys domain init` inside the
   pod, and publish the `_linkkeys`/`_linkkeys_apis` DNS TXT records
   `linkkeys domain dns-check` prints).

2. **Create a service account (API key) for your app and grant it
   `api_access`.** Every `Rp` CSIL-RPC operation (`sign-request`,
   `decrypt-token`, `verify-assertion`, `userinfo-fetch`) requires the
   caller's key to hold the dedicated `api_access` relation on the RP's
   domain (SEC-06) — a bare valid API key is **not** enough, and nothing
   provisions this automatically. One command does both:

   ```sh
   kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- \
     linkkeys user create my-webapp "My Web Application" --api-key --relation api_access
   # Save the printed API key -- it is shown exactly once.
   ```

   If you already minted a key without `--relation`, grant it separately
   (DB-direct, idempotent):

   ```sh
   kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- \
     linkkeys relation grant-local my-webapp api_access
   ```

   This repo's own cluster wrappers do the same two things:
   `./deploy/live.sh api-key <user> <relation...>` and
   `./deploy/live.sh grant <user> <relation>`.

3. **Set up the TLS sidecar** described above, and confirm it forwards a
   connection (a bare `nc -z 127.0.0.1 4988` or `openssl s_client -connect
   rp.example.com:4987` compared against the sidecar's own pinned cert is
   enough at this stage — the full CSIL-RPC round trip is exercised once the
   app is running).

4. **Know your RP server's fingerprints.** `linkkeys domain dns-check` on
   the RP prints the `fp=` values to pin — feed the same values into both
   the sidecar's `CAfile`/`cafile` verification (step above) and this app's
   own `RP_FINGERPRINTS` (validated at startup, see `RpConfig` below, even
   though this Dart client never uses them for a TLS handshake itself).

## The login flow, wire-level

Everything below is TCP CSIL-RPC (`csil/linkkeys.csil`'s `Rp` service, sent
to the sidecar, never HTTP — the old `POST /v1alpha/*.json` HTTP routes were
removed when S2S moved to TCP, and the generic HTTP RPC carrier cannot
complete `verify-assertion`/`userinfo-fetch` at all, per
`docs/DEPLOYING-RP.md`'s "Web App Integration"):

```
service Rp {
    sign-request:      RpSignRequest      -> RpSignResponse,
    decrypt-token:      RpDecryptRequest   -> RpDecryptResponse,
    verify-assertion:   RpVerifyRequest    -> RpVerifyResponse,
    userinfo-fetch:     RpUserInfoRequest  -> UserInfo,
    issue-attestation:  RpIssueAttestationRequest -> RpIssueAttestationResponse
}
```

1. **`Rp/sign-request`** `{callback_url, nonce, ?requested_claims}` →
   `{signed_request}`. Your app mints a fresh single-use `nonce` before ever
   redirecting the browser.
2. **Redirect the browser** to
   `https://<user's chosen domain>/auth/authorize?signed_request=<...>`
   (`user_hint=` is optional). Only `signed_request` and `user_hint` are
   read by `GET /auth/authorize` — no other query parameter matters.
3. The identity provider authenticates the user and redirects the browser
   back to your `callback_url` with `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** `{encrypted_token}` → `{signed_assertion}`. Only
   your RP server (holder of your domain's private key) can do this.
5. **`Rp/verify-assertion`** `{signed_assertion, expected_domain}` →
   `{assertion, verified}`. **Check `verified` explicitly** — a call that
   doesn't throw only means the round trip succeeded, not that the assertion
   is trustworthy. Nonce single-use is your app's job, not the server's.
6. **`Rp/userinfo-fetch`** (optional) `{token, api_base, domain}` → claims.
   `token` here is the `signed_assertion` string from step 4 (per the CSIL
   doc comment: "URL-param-encoded SignedIdentityAssertion (the
   decrypt-token result)") — not the original `encrypted_token` from the
   callback query string.

## API-key envelope auth, and why it's TCP-only

All five `Rp` operations are authenticated the same way: the API key rides
the CSIL-RPC envelope's `auth` field as a **raw key with no `Bearer `
prefix** (that convention belongs to the separate, browser-facing HTTP
surfaces) — `crates/linkkeys/src/tcp/mod.rs`'s `authenticate_tcp_request`
reads exactly `envelope.auth`. There is no client certificate on this leg;
your app presents no domain key of its own (the RP server holds one), which
is why API-key auth is used instead of mutual TLS.

The `Rp` service is TCP CSIL-RPC only: the old `POST /v1alpha/*.json` HTTP
routes were removed when server-to-server traffic moved to TCP, and the
generic HTTP RPC carrier cannot complete `verify-assertion` or
`userinfo-fetch` at all (both need the outbound S2S context only the TCP
carrier has). `docs/DEPLOYING-RP.md`'s "Web App Integration" section is
current and accurate on this point — there is no HTTP fallback to reach for
if the TLS caveat above feels like a reason to look for one.

## Why there's no packaged Dart client, and what this reuses

There is no packaged regular-RP client for Dart — the `linkkeys_local_rp`
package in this directory implements the *different* DNS-less local-RP
mode. What follows hand-builds a small RP client, reusing what this SDK's
public barrel (`lib/linkkeys_local_rp.dart`) actually exports, and inlining
only what it doesn't:

**Reused, genuinely exported, protocol-mode-agnostic:**

- **`Transport` / `StdTransport`** (`lib/src/rpc/transport.dart`,
  `std_transport.dart`) — the byte-stream dial seam. This app's `rpCall`
  takes a `Transport` parameter and dials through it exactly the way this
  SDK's own `DomainKeys`/`LocalRp` calls do; only the address it dials
  differs (the sidecar, not a domain resolved from DNS).
- **`DnsResolver` / `SystemDnsResolver`** and `dns/dns.dart`'s
  `linkkeysApisDnsName`/`parseLinkKeysApisTxt`/`isValidFingerprint` — used
  below to resolve the *issuing IDP's* `_linkkeys_apis` HTTPS base for the
  `userinfo-fetch` step, and to sanity-check `RP_FINGERPRINTS` at startup.
  None of this is local-RP-specific.
- **`Claim` / `ClaimSignature`** (`lib/src/wire/types.dart`, exported by the
  barrel without restriction) — `UserInfo.claims` below decodes directly
  into the SDK's own `Claim` type rather than redefining an equivalent one.
- **`encodeUrlParam`/`decodeUrlParam`** exist for base64url work, though
  this particular flow doesn't need them directly — the `signed_request`/
  `encrypted_token` strings the RP server hands back are already
  URL-param-encoded by the server per the CSIL doc comments, so this app
  passes them through unchanged rather than re-encoding.

**NOT exported — inlined below, and why:**

- **The CBOR codec** (`lib/src/wire/cbor.dart`) is not part of the public
  barrel. `cbor_lite.dart` below hand-writes an independent minimal CBOR
  encoder/decoder covering exactly what the `Rp` service's shapes need
  (definite-length maps/arrays, text, bytes, bool, tag 24) — mirroring the
  *shape* of the SDK's own hand-written codec (canonical map-key ordering,
  same tag-24 envelope convention) without reaching into `lib/src/`.
- **The CSIL-RPC envelope and frame codec**
  (`lib/src/rpc/rpc_envelope.dart`, `stream_framing.dart`) are also
  unexported — `rp_client.dart` reimplements the same 4-byte-big-endian
  length-prefixed CBOR-envelope framing this SDK's own (private) copy uses.
- **The `Rp` service's request/response shapes** (`RpSignRequest`,
  `IdentityAssertion`, `UserInfo`, etc.) don't exist anywhere in this SDK —
  they're specific to the browser-RP-delegation flow this package doesn't
  implement. `rp_client.dart` defines them by hand from
  `csil/linkkeys.csil`.
- **TLS pinning** (`lib/src/rpc/tls_pinning.dart`) is neither exported nor
  usable from Dart at all right now — see the caveat section above. This
  example does not attempt to reuse or reimplement it; the sidecar replaces
  it entirely.

## The code

Everything below was `dart analyze`-checked and `dart compile exe`-compiled
as a real package (path-dependent on a local checkout of this SDK) — see
"What was verified" at the end.

### `pubspec.yaml`

```yaml
name: regular_rp_example
description: Example Dart web app accepting regular (DNS-pinned) LinkKeys logins via an RP server.
publish_to: none
version: 0.0.1

environment:
  sdk: ^3.5.0

dependencies:
  # This SDK is publish_to: none (see sdks/local-rp/dart/pubspec.yaml) --
  # it is not on pub.dev. A real external app depends on it via git:
  #
  #   linkkeys_local_rp:
  #     git:
  #       url: https://github.com/catalystcommunity/linkkeys.git
  #       path: sdks/local-rp/dart
  #       ref: main
  #
  # This doc's own compile verification instead used a `path:` dependency
  # against a local checkout -- delete this comment and use the `git:` form
  # above in a real app.
  linkkeys_local_rp:
    path: /path/to/local/checkout/sdks/local-rp/dart

dev_dependencies:
  lints: ^5.0.0
```

### `lib/cbor_lite.dart` — the hand-written CBOR codec

```dart
// A minimal canonical CBOR (RFC 8949) encoder/decoder for exactly the
// `Rp` CSIL-RPC service's request/response shapes.
//
// linkkeys_local_rp's own `lib/src/wire/cbor.dart` is NOT part of this
// package's public API (the barrel `linkkeys_local_rp.dart` does not export
// it), so this app cannot import it -- and per AGENTS.md/this SDK's own
// precedent, hand-writing the small subset of CBOR a client needs is the
// established pattern here rather than reaching into `lib/src/` internals
// or taking on a full third-party CBOR package for ~10 field types. This
// mirrors the *shape* of `wire/cbor.dart` (definite-length-only, canonical
// map key ordering, tag 24 for the CSIL-RPC envelope's inner payload) but is
// independently written for this app.
//
// Supported subset: unsigned/negative integers, byte strings, UTF-8 text
// strings, booleans, null, definite-length arrays and maps (text-string keys
// only, RFC 8949 4.2.1 canonical key ordering on encode), and tag 24
// ("encoded CBOR data item", used only for the RPC envelope's `payload`
// field). Indefinite-length items are not supported -- the CSIL-RPC
// transport and this protocol never emit them.
library;

import 'dart:convert';
import 'dart:typed_data';

/// Wraps the bytes of a nested CBOR-encoded item, i.e. CBOR tag 24. Used
/// only for the RPC envelope's `payload` field, whose value is itself the
/// CBOR encoding of a request/response struct.
class CborTag24 {
  final Uint8List bytes;
  const CborTag24(this.bytes);
}

/// Encode [value] as canonical CBOR. Accepted Dart types: `null`, `bool`,
/// `int`, `String` (-> CBOR text), `Uint8List` (-> CBOR byte string),
/// `List<Object?>` (-> CBOR array, non-`Uint8List` only), `Map<String,
/// Object?>` (-> CBOR map, keys sorted by their own encoded bytes), and
/// [CborTag24].
Uint8List cborEncode(Object? value) {
  final out = BytesBuilder(copy: false);
  _writeValue(value, out);
  return out.toBytes();
}

void _writeHead(BytesBuilder out, int major, int arg) {
  final mt = (major & 0x7) << 5;
  if (arg < 24) {
    out.addByte(mt | arg);
  } else if (arg <= 0xff) {
    out.addByte(mt | 24);
    out.addByte(arg);
  } else if (arg <= 0xffff) {
    out.addByte(mt | 25);
    out.addByte((arg >> 8) & 0xff);
    out.addByte(arg & 0xff);
  } else {
    out.addByte(mt | 26);
    out.addByte((arg >> 24) & 0xff);
    out.addByte((arg >> 16) & 0xff);
    out.addByte((arg >> 8) & 0xff);
    out.addByte(arg & 0xff);
  }
}

int _compareBytes(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    final diff = a[i] - b[i];
    if (diff != 0) return diff;
  }
  return a.length - b.length;
}

void _writeValue(Object? value, BytesBuilder out) {
  switch (value) {
    case null:
      out.addByte(0xf6);
    case bool b:
      out.addByte(b ? 0xf5 : 0xf4);
    case CborTag24 t:
      _writeHead(out, 6, 24);
      _writeValue(t.bytes, out);
    case Uint8List bytes:
      _writeHead(out, 2, bytes.length);
      out.add(bytes);
    case int i:
      if (i >= 0) {
        _writeHead(out, 0, i);
      } else {
        _writeHead(out, 1, -1 - i);
      }
    case String s:
      final utf8Bytes = utf8.encode(s);
      _writeHead(out, 3, utf8Bytes.length);
      out.add(utf8Bytes);
    case List<Object?> list:
      _writeHead(out, 4, list.length);
      for (final item in list) {
        _writeValue(item, out);
      }
    case Map<String, Object?> map:
      final keys = map.keys.toList();
      final encodedKeys = <String, Uint8List>{
        for (final k in keys) k: cborEncode(k),
      };
      keys.sort((a, b) => _compareBytes(encodedKeys[a]!, encodedKeys[b]!));
      _writeHead(out, 5, keys.length);
      for (final k in keys) {
        out.add(encodedKeys[k]!);
        _writeValue(map[k], out);
      }
    default:
      throw ArgumentError('cannot CBOR-encode ${value.runtimeType}');
  }
}

/// Thrown when [cborDecode] or one of the `cborRequire*` accessors below
/// hits malformed or unexpected-shape input.
class CborLiteDecodeException implements Exception {
  final String message;
  CborLiteDecodeException(this.message);

  @override
  String toString() => 'CborLiteDecodeException: $message';
}

/// Decode a single top-level CBOR data item. Returns `null`, `bool`, `int`,
/// `String`, `Uint8List`, `List<Object?>`, `Map<String, Object?>`, or
/// [CborTag24] (for a tag-24-wrapped byte string). Trailing bytes after the
/// item are rejected -- every wire message this app decodes is exactly one
/// CBOR item.
Object? cborDecode(Uint8List data) {
  final r = _Reader(data);
  final v = r.readValue();
  if (r.pos != data.length) {
    throw CborLiteDecodeException(
        'trailing bytes after CBOR item: ${data.length - r.pos} byte(s)');
  }
  return v;
}

class _Reader {
  final Uint8List data;
  int pos = 0;
  _Reader(this.data);

  int _byte() {
    if (pos >= data.length) {
      throw CborLiteDecodeException('unexpected end of CBOR input');
    }
    return data[pos++];
  }

  Uint8List _take(int n) {
    if (pos + n > data.length) {
      throw CborLiteDecodeException('unexpected end of CBOR input');
    }
    final out = Uint8List.sublistView(data, pos, pos + n);
    pos += n;
    return out;
  }

  int _arg(int ai) {
    if (ai < 24) return ai;
    switch (ai) {
      case 24:
        return _byte();
      case 25:
        return (_byte() << 8) | _byte();
      case 26:
        var v = 0;
        for (var i = 0; i < 4; i++) {
          v = (v << 8) | _byte();
        }
        return v;
      default:
        throw CborLiteDecodeException(
            'unsupported CBOR additional info $ai (indefinite lengths are not supported)');
    }
  }

  Object? readValue() {
    final head = _byte();
    final major = head >> 5;
    final ai = head & 0x1f;
    switch (major) {
      case 0:
        return _arg(ai);
      case 1:
        return -1 - _arg(ai);
      case 2:
        return _take(_arg(ai));
      case 3:
        return utf8.decode(_take(_arg(ai)));
      case 4:
        final n = _arg(ai);
        return <Object?>[for (var i = 0; i < n; i++) readValue()];
      case 5:
        final n = _arg(ai);
        final out = <String, Object?>{};
        for (var i = 0; i < n; i++) {
          final k = readValue();
          final v = readValue();
          if (k is! String) {
            throw CborLiteDecodeException('map key is not a CBOR text string');
          }
          out[k] = v;
        }
        return out;
      case 6:
        final tag = _arg(ai);
        final inner = readValue();
        if (tag == 24) {
          if (inner is! Uint8List) {
            throw CborLiteDecodeException(
                'tag 24 payload is not a byte string');
          }
          return CborTag24(inner);
        }
        throw CborLiteDecodeException('unsupported CBOR tag $tag');
      case 7:
        if (ai == 20) return false;
        if (ai == 21) return true;
        if (ai == 22) return null;
        throw CborLiteDecodeException('unsupported CBOR simple value ai=$ai');
      default:
        throw CborLiteDecodeException('unsupported CBOR major type $major');
    }
  }
}

// -----------------------------------------------------------------
// Small typed accessors over a decoded `Map<String, Object?>`, mirroring
// the shape of linkkeys_local_rp's own (unexported) `Cbor.require*`
// helpers closely enough to keep the call sites in rp_client.dart readable.
// -----------------------------------------------------------------

Object? cborMapGet(Object? map, String key) {
  if (map is! Map<String, Object?>) return null;
  return map[key];
}

Object? cborRequire(Object? map, String key) {
  final v = cborMapGet(map, key);
  if (v == null) {
    throw CborLiteDecodeException("missing required field '$key'");
  }
  return v;
}

String cborAsText(Object? v) {
  if (v is String) return v;
  throw CborLiteDecodeException('expected a CBOR text string, got $v');
}

bool cborAsBool(Object? v) {
  if (v is bool) return v;
  throw CborLiteDecodeException('expected a CBOR bool, got $v');
}

Uint8List cborAsBytes(Object? v) {
  if (v is Uint8List) return v;
  throw CborLiteDecodeException('expected a CBOR byte string, got $v');
}

List<Object?> cborAsArray(Object? v) {
  if (v is List<Object?>) return v;
  throw CborLiteDecodeException('expected a CBOR array, got $v');
}

Map<String, Object?> cborAsMap(Object? v) {
  if (v is Map<String, Object?>) return v;
  throw CborLiteDecodeException('expected a CBOR map, got $v');
}

String cborRequireText(Object? map, String key) =>
    cborAsText(cborRequire(map, key));

bool cborRequireBool(Object? map, String key) =>
    cborAsBool(cborRequire(map, key));

Map<String, Object?> cborRequireMap(Object? map, String key) =>
    cborAsMap(cborRequire(map, key));

List<Object?> cborRequireArray(Object? map, String key) =>
    cborAsArray(cborRequire(map, key));

String? cborOptText(Object? map, String key) {
  final v = cborMapGet(map, key);
  return v == null ? null : cborAsText(v);
}
```

### `lib/rp_client.dart` — the RP-call glue

```dart
// A minimal regular-RP client: talks the `Rp` CSIL-RPC service on this
// app's own RP server, authenticated with an API key (envelope `auth`
// field, raw key, no "Bearer " prefix). NOT part of linkkeys_local_rp --
// that package implements the different, DNS-less local-RP mode. See
// example.md's "Why there's no packaged Dart client" for exactly which
// SDK pieces this file reuses (`Transport`, DNS TXT parsing, `Claim`/
// `ClaimSignature`, base64url helpers, `SdkException`-style error
// handling) versus which it hand-writes (the CBOR envelope in
// `cbor_lite.dart`, the CSIL-RPC frame codec, and the `Rp` service's own
// request/response shapes -- none of that is exported from the SDK's
// public barrel).
//
// IMPORTANT -- read example.md's TLS caveat section before wiring this up
// for real: `rp.tcpAddr` below is dialed with NO TLS at all. That is only
// safe when it points at a local, trusted sidecar (see the caveat section)
// that has already TLS-pinned the hop to the real RP server on this app's
// behalf. dart:io cannot perform that pinned TLS handshake itself against
// this protocol's Ed25519 server certificate -- see the SDK's own
// README.md, "Known limitations".
library;

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';

import 'cbor_lite.dart';

/// Mirrors the SDK's own frame cap (`lib/src/rpc/stream_framing.dart`'s
/// `maxFrameSize`) so a malicious/misbehaving peer can't drive this client
/// to an unbounded allocation via a forged length prefix.
const int maxFrameSize = 1024 * 1024;

const int _rpcVersion = 1;

/// Raised for both transport-level failures and non-OK CSIL-RPC statuses.
class RpCallError implements Exception {
  final String message;
  RpCallError(this.message);

  @override
  String toString() => 'RpCallError: $message';
}

/// This app's connection to its own co-located RP server (see
/// `docs/DEPLOYING-RP.md`). In the deployment this example recommends (see
/// the TLS caveat section), [tcpAddr] is a *loopback sidecar proxy*
/// address, not the RP server's own TCP address -- the proxy is what
/// actually dials the RP server over pinned TLS.
class RpConfig {
  /// `host:port` this app dials directly -- a loopback TLS-terminating
  /// sidecar in the recommended deployment (see example.md).
  final String tcpAddr;

  /// The RP server's DNS-pinned fingerprints (`linkkeys domain dns-check`
  /// on the RP). This Dart client never uses these for TLS verification
  /// itself -- that responsibility lives in the sidecar proxy's own config
  /// (see the TLS caveat section) -- but they are validated here so a
  /// misconfigured deployment fails fast instead of silently trusting an
  /// unpinned proxy.
  final List<String> fingerprints;

  final String apiKey;

  /// This app's own RP domain. Informational only in this client (used for
  /// logging/diagnostics), never sent on the wire -- the API key is the
  /// authentication credential.
  final String domain;

  RpConfig({
    required this.tcpAddr,
    required this.fingerprints,
    required this.apiKey,
    required this.domain,
  }) {
    if (fingerprints.isEmpty) {
      throw ArgumentError('RpConfig.fingerprints must not be empty');
    }
    for (final fp in fingerprints) {
      if (!isValidFingerprint(fp)) {
        throw ArgumentError(
            'RpConfig.fingerprints: not a valid fingerprint: $fp');
      }
    }
  }

  factory RpConfig.fromEnv() {
    final tcpAddr = Platform.environment['RP_TCP_ADDR'];
    final fpList = Platform.environment['RP_FINGERPRINTS'];
    final apiKey = Platform.environment['RP_API_KEY'];
    final domain = Platform.environment['RP_DOMAIN'];
    if (tcpAddr == null || fpList == null || apiKey == null || domain == null) {
      throw StateError(
          'RP_TCP_ADDR, RP_FINGERPRINTS, RP_API_KEY, and RP_DOMAIN must all be set');
    }
    final fingerprints = fpList
        .split(',')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    return RpConfig(
        tcpAddr: tcpAddr,
        fingerprints: fingerprints,
        apiKey: apiKey,
        domain: domain);
  }
}

// -----------------------------------------------------------------
// CSIL-RPC envelope + frame codec (hand-written -- see the file doc
// comment for why this can't just import the SDK's own copies).
// -----------------------------------------------------------------

Uint8List _encodeRpcRequest({
  required String service,
  required String op,
  required Uint8List payload,
  required String auth,
}) {
  return cborEncode(<String, Object?>{
    'v': _rpcVersion,
    'service': service,
    'op': op,
    'payload': CborTag24(payload),
    'auth': auth,
  });
}

class _RpcResponse {
  final int status;
  final Uint8List payload;
  final String? error;
  const _RpcResponse({required this.status, required this.payload, this.error});
}

_RpcResponse _decodeRpcResponse(Uint8List bytes) {
  final env = cborDecode(bytes);
  final v = cborRequire(env, 'v');
  if (v != _rpcVersion) {
    throw RpCallError('unsupported CSIL-RPC transport version: $v');
  }
  final status = cborRequire(env, 'status');
  if (status is! int) {
    throw RpCallError('malformed response: status is not an integer');
  }
  final payloadField = cborMapGet(env, 'payload');
  final payload = payloadField is CborTag24 ? payloadField.bytes : Uint8List(0);
  return _RpcResponse(
      status: status, payload: payload, error: cborOptText(env, 'error'));
}

Future<void> _sendFrame(Socket sock, Uint8List data) async {
  final header = ByteData(4)..setUint32(0, data.length, Endian.big);
  sock.add(header.buffer.asUint8List());
  sock.add(data);
  await sock.flush();
}

class _FrameReader {
  final Stream<List<int>> _stream;
  StreamIterator<List<int>>? _iter;
  Uint8List _buffer = Uint8List(0);

  _FrameReader(this._stream);

  Future<Uint8List> _readExact(int n) async {
    _iter ??= StreamIterator(_stream);
    while (_buffer.length < n) {
      if (!await _iter!.moveNext()) {
        throw RpCallError('connection closed before expected bytes arrived');
      }
      final chunk = Uint8List.fromList(_iter!.current);
      final combined = Uint8List(_buffer.length + chunk.length)
        ..setAll(0, _buffer)
        ..setAll(_buffer.length, chunk);
      _buffer = combined;
    }
    final out = Uint8List.sublistView(_buffer, 0, n);
    _buffer = Uint8List.sublistView(_buffer, n);
    return out;
  }

  Future<Uint8List> readFrame() async {
    final lenBytes = await _readExact(4);
    final len = ByteData.sublistView(lenBytes).getUint32(0, Endian.big);
    if (len > maxFrameSize) {
      throw RpCallError('peer frame too large ($len bytes, max $maxFrameSize)');
    }
    return _readExact(len);
  }
}

/// Make one API-key-authenticated `Rp/<op>` call. [transport] is the SDK's
/// own [Transport] seam (typically [StdTransport]) -- see the file doc
/// comment for why there is deliberately no TLS step here.
Future<Uint8List> rpCall(
    Transport transport, RpConfig rp, String op, Uint8List payload) async {
  final sock = await transport.dial(rp.tcpAddr);
  try {
    final reqBytes = _encodeRpcRequest(
        service: 'Rp', op: op, payload: payload, auth: rp.apiKey);
    await _sendFrame(sock, reqBytes);
    final resp = _decodeRpcResponse(await _FrameReader(sock).readFrame());
    if (resp.status != 0) {
      final detail = resp.error == null ? '' : ': ${resp.error}';
      throw RpCallError('Rp/$op: server status ${resp.status}$detail');
    }
    return resp.payload;
  } finally {
    sock.destroy();
  }
}

// -----------------------------------------------------------------
// `Rp` service request/response shapes (csil/linkkeys.csil) -- hand-written
// for the same reason as the envelope codec above.
// -----------------------------------------------------------------

Map<String, Object?> _requestedClaim(String claimType, String datatype) =>
    {'claim_type': claimType, 'datatype': datatype};

/// Adjust to whatever claims your app actually needs. Matches the shape of
/// `csil/linkkeys.csil`'s `ClaimRequest`/`RequestedClaim`.
Map<String, Object?> defaultClaimRequest() => {
      'required': [_requestedClaim('display_name', 'text')],
      'optional': [_requestedClaim('email', 'email')],
    };

/// Step 1: sign an auth request addressed to the user's chosen LinkKeys
/// domain, naming this app's callback URL and a fresh single-use nonce.
Future<String> signRequest(
  Transport transport,
  RpConfig rp, {
  required String callbackUrl,
  required String nonce,
  Map<String, Object?>? requestedClaims,
}) async {
  final payload = cborEncode(<String, Object?>{
    'callback_url': callbackUrl,
    'nonce': nonce,
    'requested_claims': requestedClaims ?? defaultClaimRequest(),
  });
  final respBytes = await rpCall(transport, rp, 'sign-request', payload);
  return cborRequireText(cborDecode(respBytes), 'signed_request');
}

/// Step 4: exchange the callback's `encrypted_token` for the signed
/// identity assertion inside it. Only the RP server (holder of this app's
/// domain private key) can do this.
Future<String> decryptToken(
    Transport transport, RpConfig rp, String encryptedToken) async {
  final payload =
      cborEncode(<String, Object?>{'encrypted_token': encryptedToken});
  final respBytes = await rpCall(transport, rp, 'decrypt-token', payload);
  return cborRequireText(cborDecode(respBytes), 'signed_assertion');
}

/// `csil/linkkeys.csil`'s `IdentityAssertion`.
class IdentityAssertion {
  final String userId;
  final String domain;
  final String audience;
  final String nonce;
  final String issuedAt;
  final String expiresAt;
  final List<String> authorizedClaims;
  final String? displayName;

  const IdentityAssertion({
    required this.userId,
    required this.domain,
    required this.audience,
    required this.nonce,
    required this.issuedAt,
    required this.expiresAt,
    required this.authorizedClaims,
    this.displayName,
  });

  static IdentityAssertion _fromCbor(Object? v) {
    final claims = cborRequireArray(v, 'authorized_claims');
    return IdentityAssertion(
      userId: cborRequireText(v, 'user_id'),
      domain: cborRequireText(v, 'domain'),
      audience: cborRequireText(v, 'audience'),
      nonce: cborRequireText(v, 'nonce'),
      issuedAt: cborRequireText(v, 'issued_at'),
      expiresAt: cborRequireText(v, 'expires_at'),
      authorizedClaims: [for (final c in claims) cborAsText(c)],
      displayName: cborOptText(v, 'display_name'),
    );
  }
}

class VerifyResult {
  final IdentityAssertion assertion;
  final bool verified;
  const VerifyResult(this.assertion, this.verified);
}

/// Step 5: verify the decrypted assertion against the issuing domain's
/// published keys. Callers MUST check [VerifyResult.verified] -- a call
/// that doesn't throw only means the round trip succeeded, not that the
/// assertion is trustworthy.
Future<VerifyResult> verifyAssertion(
  Transport transport,
  RpConfig rp, {
  required String signedAssertion,
  required String expectedDomain,
}) async {
  final payload = cborEncode(<String, Object?>{
    'signed_assertion': signedAssertion,
    'expected_domain': expectedDomain,
  });
  final respBytes = await rpCall(transport, rp, 'verify-assertion', payload);
  final resp = cborDecode(respBytes);
  return VerifyResult(
    IdentityAssertion._fromCbor(cborRequireMap(resp, 'assertion')),
    cborRequireBool(resp, 'verified'),
  );
}

Claim _decodeClaim(Object? v) {
  final sigs = cborRequireArray(v, 'signatures');
  return Claim(
    claimId: cborRequireText(v, 'claim_id'),
    userId: cborRequireText(v, 'user_id'),
    claimType: cborRequireText(v, 'claim_type'),
    claimValue: cborAsBytes(cborRequire(v, 'claim_value')),
    signatures: [for (final s in sigs) _decodeClaimSignature(s)],
    attestedAt: cborRequireText(v, 'attested_at'),
    createdAt: cborRequireText(v, 'created_at'),
    expiresAt: cborOptText(v, 'expires_at'),
    revokedAt: cborOptText(v, 'revoked_at'),
  );
}

ClaimSignature _decodeClaimSignature(Object? v) => ClaimSignature(
      domain: cborRequireText(v, 'domain'),
      signedByKeyId: cborRequireText(v, 'signed_by_key_id'),
      signature: cborAsBytes(cborRequire(v, 'signature')),
    );

/// `csil/linkkeys.csil`'s `UserInfo`. [claims] reuses linkkeys_local_rp's
/// own exported `Claim`/`ClaimSignature` types (`wire/types.dart`, exported
/// by the barrel) -- these ARE part of the SDK's public API, unlike the
/// `Rp`-specific shapes above.
class UserInfo {
  final String userId;
  final String domain;
  final String displayName;
  final List<Claim> claims;

  const UserInfo({
    required this.userId,
    required this.domain,
    required this.displayName,
    required this.claims,
  });
}

/// Step 6 (optional): fetch the user's consented claims from the issuing
/// IDP, via this app's RP server. [token] is the `signed_assertion` string
/// [decryptToken] returned (per `csil/linkkeys.csil`'s `RpUserInfoRequest`
/// doc comment) -- not the original `encrypted_token` from the callback
/// query string.
Future<UserInfo> userInfoFetch(
  Transport transport,
  RpConfig rp, {
  required String token,
  required String apiBase,
  required String domain,
}) async {
  final payload = cborEncode(<String, Object?>{
    'token': token,
    'api_base': apiBase,
    'domain': domain,
  });
  final respBytes = await rpCall(transport, rp, 'userinfo-fetch', payload);
  final resp = cborDecode(respBytes);
  final claims = cborRequireArray(resp, 'claims');
  return UserInfo(
    userId: cborRequireText(resp, 'user_id'),
    domain: cborRequireText(resp, 'domain'),
    displayName: cborRequireText(resp, 'display_name'),
    claims: [for (final c in claims) _decodeClaim(c)],
  );
}

// -----------------------------------------------------------------
// DNS: resolve the issuing IDP's browser-facing HTTPS API base, reusing
// the SDK's own exported `_linkkeys_apis` TXT parsing (`dns/dns.dart`) --
// not local-RP-specific, so it's a legitimate reuse for this flow too.
// -----------------------------------------------------------------

Future<String> resolveApiBase(DnsResolver dns, String domain) async {
  final fallback = 'https://$domain';
  try {
    final txts = await dns.txtLookup(linkkeysApisDnsName(domain));
    for (final txt in txts) {
      try {
        final apis = parseLinkKeysApisTxt(txt);
        if (apis.httpsBase != null) return apis.httpsBase!;
      } on DnsParseError {
        continue; // try the next TXT record
      }
    }
  } catch (_) {
    // best-effort, matching the Rust/Go/Python reference clients' fallback
  }
  return fallback;
}

// -----------------------------------------------------------------
// Login flow glue: begin / handle-callback
// -----------------------------------------------------------------

/// What the app persists between [beginLogin] and [handleCallback] --
/// tied to the browser session that initiated the login, and used at most
/// once (see example.md's "App responsibilities").
class RegularRpPendingLogin {
  final String nonce;
  final String userDomain;
  final String apiBase;
  const RegularRpPendingLogin(
      {required this.nonce, required this.userDomain, required this.apiBase});
}

/// Generates an unguessable random hex token -- used both as the
/// single-use login `nonce` sent to the RP server and (by `bin/main.dart`)
/// as opaque session/pending-login handles.
String newRandomHexToken({int bytes = 16}) {
  final rnd = Random.secure();
  final buf = Uint8List(bytes);
  for (var i = 0; i < bytes; i++) {
    buf[i] = rnd.nextInt(256);
  }
  return buf.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Steps 1-2: sign an auth request via the RP server and build the
/// browser-redirect URL to the user's chosen LinkKeys domain. Only
/// `signed_request` (and, optionally, `user_hint`) are read by
/// `GET /auth/authorize` (`docs/DEPLOYING-RP.md`, "Web App Integration").
Future<(String redirectUrl, RegularRpPendingLogin pending)> beginLogin(
  Transport transport,
  DnsResolver dns,
  RpConfig rp, {
  required String userDomain,
  required String callbackUrl,
  String? userHint,
}) async {
  final nonce = newRandomHexToken();
  final signedRequest =
      await signRequest(transport, rp, callbackUrl: callbackUrl, nonce: nonce);
  final apiBase = await resolveApiBase(dns, userDomain);

  final redirectUri =
      Uri.parse('$apiBase/auth/authorize').replace(queryParameters: {
    'signed_request': signedRequest,
    if (userHint != null && userHint.isNotEmpty) 'user_hint': userHint,
  });

  return (
    redirectUri.toString(),
    RegularRpPendingLogin(
        nonce: nonce, userDomain: userDomain, apiBase: apiBase),
  );
}

class LoginResult {
  final IdentityAssertion assertion;
  final UserInfo? userInfo;
  const LoginResult(this.assertion, this.userInfo);
}

/// Steps 3-5 (plus the optional step 6): decrypt the callback's token,
/// verify the assertion, and enforce domain/nonce checks before trusting
/// the result. Nonce single-use itself is enforced by the caller (see
/// `bin/main.dart`'s pending-login store) -- this function only checks that
/// the nonce in the assertion matches the one this login attempt minted.
Future<LoginResult> handleCallback(
  Transport transport,
  RpConfig rp,
  RegularRpPendingLogin pending,
  String encryptedToken,
) async {
  final signedAssertion = await decryptToken(transport, rp, encryptedToken);

  final result = await verifyAssertion(
    transport,
    rp,
    signedAssertion: signedAssertion,
    expectedDomain: pending.userDomain,
  );
  if (!result.verified) {
    throw RpCallError(
        "assertion did not verify against ${pending.userDomain}'s published keys");
  }
  if (result.assertion.domain != pending.userDomain) {
    throw RpCallError(
        'domain mismatch: expected ${pending.userDomain}, got ${result.assertion.domain}');
  }
  if (result.assertion.nonce != pending.nonce) {
    throw RpCallError('nonce mismatch -- possible replay');
  }

  UserInfo? userInfo;
  try {
    userInfo = await userInfoFetch(
      transport,
      rp,
      token: signedAssertion,
      apiBase: pending.apiBase,
      domain: pending.userDomain,
    );
  } catch (_) {
    userInfo = null; // optional step: proceed with proof of identity only
  }

  return LoginResult(result.assertion, userInfo);
}
```

## Callback handling

`bin/main.dart` below wires two HTTP routes: `/auth/login` (starts a login,
calls `beginLogin`) and `/auth/callback` — the route named in
`callbackUrl` — which the IDP's browser redirect lands on with
`?encrypted_token=<...>`. The callback handler is the security-sensitive
half of this flow; three things about it matter beyond just "call
`handleCallback`":

1. **Look up and *remove* the pending-login record before doing anything
   else with it.** `pendingLogins.remove(pendingCookie.value)` (not a plain
   lookup) is what makes a given login attempt single-use — whether or not
   verification below succeeds, a second request bearing the same
   `lk_pending` cookie value finds nothing left to redeem. This is the same
   property `demoappsite/src/main.rs`'s `cookies.remove_private("auth_state")`
   achieves via a signed cookie instead of a server-side store; either
   mechanism satisfies "App responsibilities" below, and this example uses
   the server-side-store form (matching the sibling Go/Python examples) to
   avoid pulling in a cookie-signing dependency for a Dart web app that
   might not otherwise need one.
2. **`handleCallback` throwing `RpCallError` means "reject the login," not
   "retry."** A thrown error already covers "did not verify," "domain
   mismatch," and "nonce mismatch" — the callback handler's job is just to
   turn that into an HTTP 403 without leaking which check failed (don't
   echo assertion contents or the encrypted token back into an error page).
3. **`userinfo-fetch` failing is not fatal.** `handleCallback` already
   treats it as optional (`catch (_) { userInfo = null; }`) — the callback
   handler must not treat a `null` `userInfo` as a login failure; it means
   "proof of identity only, no claims," which is a valid outcome your app
   should handle explicitly (e.g. by prompting the user to grant claim
   consent later) rather than crashing on a null claims map.

### `bin/main.dart` — wiring it into HTTP handlers

```dart
// The web app side: two HTTP routes wired to rp_client.dart's login flow.
// Run your RP server (or, per the TLS caveat section, its local sidecar
// proxy) separately -- see docs/DEPLOYING-RP.md -- and set RP_TCP_ADDR /
// RP_FINGERPRINTS / RP_API_KEY / RP_DOMAIN before starting this.
//
// dart:io's HttpServer is used directly (no web framework dependency) to
// keep this example's dependency footprint to exactly one package: the SDK
// itself, path-referenced. A real app can wire the same two handlers into
// shelf, package:conduit, or whatever framework it already uses.
library;

import 'dart:convert';
import 'dart:io';

import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';

import 'package:regular_rp_example/rp_client.dart';

/// Demo-only storage. A real deployment needs a server-side store shared
/// across worker processes/replicas (Redis, a DB table with an expiry) --
/// see example.md's "App responsibilities". Both maps are lost on restart
/// here, which is fine for a walkthrough, not for production.
final Map<String, RegularRpPendingLogin> pendingLogins = {};
final Map<String, Map<String, Object?>> sessions = {};

Cookie? _findCookie(HttpRequest request, String name) {
  for (final c in request.cookies) {
    if (c.name == name) return c;
  }
  return null;
}

Future<void> _respond(HttpRequest request, int status, String body) async {
  request.response.statusCode = status;
  request.response.write(body);
  await request.response.close();
}

Future<void> handleLogin(
  HttpRequest request,
  Transport transport,
  DnsResolver dns,
  RpConfig rp,
  String callbackUrl,
) async {
  final userDomain = request.uri.queryParameters['domain'];
  if (userDomain == null || userDomain.isEmpty) {
    await _respond(request, HttpStatus.badRequest,
        '?domain=<the identity provider domain> is required');
    return;
  }
  final userHint = request.uri.queryParameters['user_hint'];

  final (String, RegularRpPendingLogin) beginResult;
  try {
    beginResult = await beginLogin(
      transport,
      dns,
      rp,
      userDomain: userDomain,
      callbackUrl: callbackUrl,
      userHint: userHint,
    );
  } on RpCallError catch (e) {
    stderr.writeln('begin login failed: $e');
    await _respond(request, HttpStatus.badGateway, 'could not start login');
    return;
  }
  final (redirectUrl, pending) = beginResult;

  final pendingId = newRandomHexToken();
  pendingLogins[pendingId] = pending;

  request.response
    ..statusCode = HttpStatus.found
    ..headers.set(HttpHeaders.locationHeader, redirectUrl)
    ..cookies.add(Cookie('lk_pending', pendingId)
      ..path = '/'
      ..httpOnly = true
      ..secure = true
      ..sameSite = SameSite.lax
      ..maxAge = 600); // the round trip should complete within 10 minutes
  await request.response.close();
}

Future<void> handleAuthCallback(
    HttpRequest request, Transport transport, RpConfig rp) async {
  final encryptedToken = request.uri.queryParameters['encrypted_token'];
  if (encryptedToken == null || encryptedToken.isEmpty) {
    await _respond(request, HttpStatus.badRequest, 'missing encrypted_token');
    return;
  }

  final pendingCookie = _findCookie(request, 'lk_pending');
  // Pop, not peek: this is what makes the pending login single-use. Whether
  // or not verification below succeeds, this id can never be replayed --
  // there is nothing left in `pendingLogins` to redeem a second time.
  final pending =
      pendingCookie == null ? null : pendingLogins.remove(pendingCookie.value);
  if (pending == null) {
    await _respond(request, HttpStatus.badRequest,
        'no pending login found -- it may have expired or already been used');
    return;
  }

  final LoginResult result;
  try {
    result = await handleCallback(transport, rp, pending, encryptedToken);
  } on RpCallError catch (e) {
    stderr.writeln('callback verification failed: $e');
    await _respond(
        request, HttpStatus.forbidden, 'login could not be verified');
    return;
  }

  final claims = <String, String>{
    for (final c in result.userInfo?.claims ?? const <Claim>[])
      c.claimType: utf8.decode(c.claimValue, allowMalformed: true),
  };

  final sessionId = newRandomHexToken();
  sessions[sessionId] = {
    'user_id': result.assertion.userId,
    'domain': result.assertion.domain,
    'display_name': result.assertion.displayName ?? result.assertion.userId,
    'claims': claims,
  };

  request.response
    ..statusCode = HttpStatus.found
    ..headers.set(HttpHeaders.locationHeader, '/')
    ..cookies.add(Cookie('lk_session', sessionId)
      ..path = '/'
      ..httpOnly = true
      ..secure = true
      ..sameSite = SameSite.lax
      ..maxAge = 86400)
    ..cookies.add(Cookie('lk_pending', '')
      ..path = '/'
      ..maxAge = 0); // clear the now-consumed pending cookie
  await request.response.close();
}

Future<void> main() async {
  final rp = RpConfig.fromEnv();
  final callbackUrl = Platform.environment['CALLBACK_URL'] ??
      'http://localhost:8080/auth/callback';

  // Structured behind the SDK's own seams: StdTransport for the byte-stream
  // dial, SystemDnsResolver for `_linkkeys_apis` TXT lookups. Neither is
  // local-RP-specific -- both are protocol-mode-agnostic plumbing this app
  // reuses rather than reimplements. See example.md's TLS caveat section
  // for why `rp.tcpAddr` must point at a local sidecar, not the RP server
  // directly.
  final transport = StdTransport();
  final dns = SystemDnsResolver();

  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 8080);
  stdout.writeln('listening on :8080');

  await for (final request in server) {
    try {
      switch (request.uri.path) {
        case '/auth/login':
          await handleLogin(request, transport, dns, rp, callbackUrl);
        case '/auth/callback':
          await handleAuthCallback(request, transport, rp);
        default:
          await _respond(request, HttpStatus.notFound, 'not found');
      }
    } catch (e, st) {
      stderr.writeln('unhandled error: $e\n$st');
      try {
        await _respond(
            request, HttpStatus.internalServerError, 'internal error');
      } catch (_) {
        // response may already be closed/detached; nothing more to do
      }
    }
  }
}
```

## App responsibilities

Mirrors what every other LinkKeys SDK in this repo hands back to the app
(see this package's own `README.md`, "App responsibilities"):

- **Nonce single-use.** `handleAuthCallback` above pops (`.remove`, not a
  lookup) the pending-login record keyed by an unguessable `lk_pending`
  cookie value before doing anything else with it — that's what stops the
  same callback URL from being replayed against this app. `pendingLogins`
  and `sessions` are process-local `Map`s here for clarity; a real
  deployment needs a store shared across worker processes/replicas (Redis,
  a DB table with an expiry), or the single-use property breaks the moment
  you run more than one instance.
- **Sessions.** `handleCallback` returns verified protocol facts
  (`LoginResult`: an `IdentityAssertion` plus an optional `UserInfo`) and
  nothing else — it does not create a session, set a cookie, or touch a
  database. Building a local session/user record from those facts is
  entirely your app's call, same as every other reference SDK in this repo.
- **API key storage.** `RpConfig.apiKey` authorizes signing/decrypting on
  your domain's behalf via the sidecar-fronted RP server — store it with
  the same care as a database credential (environment/secret manager, never
  logged, never committed). It is shown once at creation time; if it leaks,
  mint a new one and re-grant `api_access` rather than trying to recover the
  old value.
- **Fingerprint pinning, on both sides now.** `RP_FINGERPRINTS` is validated
  by `RpConfig`'s constructor at startup, but — per the TLS caveat section —
  the fingerprint that actually matters for the TLS hop lives in the
  sidecar's own config (`CAfile`/`cafile`). Rotate **both** whenever the RP
  server's signing keys rotate; they are two copies of the same fact, and
  letting them drift apart defeats the pin on whichever side is stale.
- **Never log sensitive fields.** Per `AGENTS.md`'s "Error Handling": never
  log the API key, `encrypted_token`, `signed_assertion`, or claim values.
  The error paths above intentionally log only the exception's own message
  (which this SDK's/this example's error types keep free of that content),
  never raw request/response payloads.

## Local-RP vs regular-RP

| | Local RP (`linkkeys_local_rp`, this directory) | Regular RP (this document) |
|---|---|---|
| App identity | A locally-generated Ed25519 key fingerprint (SSH-host-key style) | A DNS domain your RP server owns |
| DNS required | No | Yes — `_linkkeys` + `_linkkeys_apis` TXT records |
| Where keys live | In the app itself (`localRpIdentityToBytes`) | In a separate RP server process your app talks to over TCP |
| Admission | Explicit per-domain approval (`linkkeys local-rp approve <fingerprint>`) — pending until an admin approves | Ordinary DNS-pinned trust, same as any LinkKeys peer |
| Dart TLS story | Also blocked by the same `dart:io`/Ed25519 gap (`README.md`, "Known limitations") — this SDK covers it with an internal, unexported test seam that is **not** meant for app use | Blocked the same way; this document's sidecar-proxy workaround is what an app actually ships |
| Dart SDK | This package (`beginLocalLogin`/`completeLocalLogin`) | None packaged — hand-write the glue this document shows |
| Best for | LAN tools, self-hosted apps with no public DNS, desktop apps | Any app that already has (or can get) a domain |

If your app has a domain, this document's approach is almost certainly what
you want. If it doesn't (a LAN jukebox, a local dev tool), see this
package's own `README.md`/`lib/linkkeys_local_rp.dart` doc comments instead
— and note that mode hits the identical Dart TLS gap for its own
`DomainKeys`/`LocalRp` network calls, which is why *that* SDK's own flow
tests use an internal test seam rather than a real handshake either.

## What was verified

Everything under "The code" above is copied verbatim from a real package
built in a scratch directory outside this repo, with a `path:` dependency
on this checkout's `sdks/local-rp/dart`:

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"   # dart 3.12.2
dart pub get
dart analyze          # "No issues found!" -- strict-casts/strict-inference
                       # enabled, matching this SDK's own analysis_options.yaml
dart format --output=none --set-exit-if-changed .   # clean after `dart format .`
dart compile exe bin/main.dart -o main_exe           # compiles to a native executable
```

Beyond static checking, the CBOR envelope, frame codec, and every `Rp`
operation's request/response shape were also exercised **at runtime**, over
a real loopback TCP socket, against a fake in-process RP-server double
(bind a `ServerSocket` on `127.0.0.1`, read one real length-prefixed CBOR
frame, canned-reply with a real CBOR-encoded response) — the same technique
this SDK's own `test/flow_test.dart` uses to cover everything except the TLS
handshake step. That run exercised: `signRequest`/`decryptToken`/
`verifyAssertion`/`userInfoFetch` round-tripping real CBOR bytes across a
real socket; `IdentityAssertion` and `UserInfo` (including the SDK's own
`Claim`/`ClaimSignature` types) decoding correctly from nested CBOR maps;
the raw-API-key-no-`Bearer`-prefix envelope field arriving intact;
`beginLogin`'s redirect-URL construction against a fake `DnsResolver`
serving a canned `_linkkeys_apis` TXT record; and `RegularRpPendingLogin`
round-tripping through the nonce/domain checks in `handleCallback`. All
checks passed.

**What was not, and could not be, verified here: the TLS hop itself.**
Nothing in this document exercises a real pinned TLS handshake from Dart to
either an RP server or a sidecar proxy — that would require standing up a
real `linkkeys` server (or a real `stunnel`/`socat` process pointed at one)
with genuine DNS-published Ed25519 keys, which is outside what a docs task
can respect the honesty of claiming to have done. The TLS caveat section's
central claim — that `dart:io` cannot complete this handshake at all — is
not asserted from this session; it is this SDK's own `README.md`, already
verified empirically by the SDK's authors before any flow-test code was
written (their words: "Verified empirically before writing any flow-test
code"), and is cited here rather than re-verified. Treat the sidecar-proxy
recommendation as architecturally sound and the wire-level code as
functionally verified; treat the TLS hop specifically as unverified by this
document and worth a real smoke test against your actual RP server before
you ship.
