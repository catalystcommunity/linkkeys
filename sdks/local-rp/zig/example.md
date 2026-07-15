# Regular (DNS-pinned) LinkKeys login in Zig

This directory's `linkkeys_local_rp` module implements LinkKeys' **DNS-less
local-RP identity** mode (`dns-less-local-rp-design.md` at the repo root): a
locally installed app with no public DNS, identified by the fingerprint of
its own signing key. If that's what you want — a LAN jukebox, a desktop
tool, a self-hosted service with no domain — stop here and read this
directory's own `README.md` instead.

This document is for the *other*, far more common case: your app has (or is
willing to run) a domain, and wants "Sign in with LinkKeys" for **any**
user's LinkKeys identity — `alice@example.com`, on `example.com`'s own
DNS-pinned LinkKeys domain. That's **regular RP mode**, the protocol's
primary mode. There is no packaged Zig SDK for it — you run a small LinkKeys
server next to your app in RP mode (`docs/DEPLOYING-RP.md`) and talk to it
over TCP CSIL-RPC. This walkthrough shows the glue, reusing what this
directory's local-RP SDK already exports and hand-writing the rest, the same
way `sdks/local-rp/go/example.md` and `sdks/local-rp/rust/example.md` do for
their languages.

**A head-on caveat before anything else**: this SDK's own README documents
that Zig 0.14.1's `std.crypto.tls.Client` cannot expose the peer certificate
after a handshake, so it cannot implement the protocol's mandatory SPKI pin
check and fails closed (`error.PinnedTlsUnavailable`). That limitation is
not local-RP-specific — it applies here too. See "The TLS caveat" below for
what this means and the two realistic ways around it; one of them is
compiled and tested in this document, the other is not.

Everything below was verified against this repo's own code as of this
writing: `docs/DEPLOYING-RP.md`, `csil/linkkeys.csil`, `demoappsite/src/main.rs`
(the reference Rust integration), `sdks/local-rp/go/example.md` and
`sdks/local-rp/rust/example.md` (the same walkthrough for languages with more
mature TLS/codec tooling), `sdks/local-rp/c/src/rpc.c` (the sibling C SDK's
own OpenSSL pinning code, which the TLS caveat section's Option A mirrors),
and this SDK's own `src/{cbor,types,transport,rpc,tls_pin}.zig`. See "What was
compiled" at the end for exactly what ran.

## Architecture

```
+----------------------------------------------------------+
|               Your Application Stack                     |
|                                                            |
|  +--------------+    TCP CSIL-RPC   +--------------------+ |
|  |   Your App   |   (API-key auth, |  LinkKeys RP Server | |
|  |  (this doc,  |--- pinned TLS -->|  (same linkkeys     | |
|  |   Zig)       |                  |   image, RP config) | |
|  |              |                  |  Holds domain keys  | |
|  +------+-------+                  +----------+-----------+ |
|         | HTTP redirect                        | TCP CSIL-RPC
+---------|---------------------------------------|-----------+
          v                                       v
    user's browser                     the *user's* LinkKeys domain
  (goes to their IDP's                (verify-assertion / userinfo-fetch
   /auth/authorize)                    make an onward S2S call here)
```

Your Zig app is **not** the relying party in the protocol sense — the RP
server is. It holds the domain key pair, signs the outgoing auth request,
and decrypts the token the IDP sends back. Your app is a thin client of that
server: it never touches a domain private key, only an API key that
authorizes it to call `Rp` service operations over TCP.

## Prerequisites

### 1. Deploy your own RP server

Follow `docs/DEPLOYING-RP.md` end to end: the same LinkKeys Docker
image/Helm chart as a full IDP, with `rp.enabled: true` (no login UI, no
human user accounts, service accounts only).

```sh
kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- linkkeys domain init
```

### 2. Create a service account for your app, with `api_access`

Every `Rp` operation (`sign-request`, `decrypt-token`, `verify-assertion`,
`userinfo-fetch`, `issue-attestation`) requires the caller's API key to hold
the dedicated `api_access` relation (SEC-06) — a bare valid key is not
enough. `user create --relation` does both in one step:

```sh
kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- \
  linkkeys user create my-webapp "My Web Application" --api-key --relation api_access
# Save the printed API key -- it is shown exactly once.
```

If you already minted a key without `--relation` (as `docs/DEPLOYING-RP.md`'s
own "Initial Setup" example does), grant it after the fact — idempotent,
safe to re-run:

```sh
kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- \
  linkkeys relation grant-local my-webapp api_access
```

`api_access` is one of five relations `user create --relation`/`relation
grant-local` validate against (`admin`, `manage_users`, `manage_claims`,
`api_access`, `issue_claims`) — grant only `api_access` for a pure RP
delegate.

### 3. Publish DNS for the RP server's own domain, and collect its fingerprints

```sh
kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- linkkeys domain dns-check
```

prints the `_linkkeys`/`_linkkeys_apis` TXT records to publish for the RP
server's domain, including its signing-key fingerprints. Publish those
records, and keep the fingerprint list — that's `RP_FINGERPRINTS` below. This
is a **different** domain from whatever the end user types into your login
form; you don't publish anything for the user's own domain, your app just
resolves it at request time.

### Environment variables your app needs

Matching `demoappsite/src/main.rs`'s `RpConfig` and `sdks/local-rp/go/example.md`'s
`rpConfig` verbatim, so the same Helm/env-var deployment config works across
languages:

| Variable | Where it comes from |
|---|---|
| `RP_TCP_ADDR` | `host:port` of your RP server's TCP listener (default port `4987`) |
| `RP_FINGERPRINTS` | Comma-separated fingerprints from step 3 |
| `RP_API_KEY` | The API key from step 2 — store it with the same care as a database credential, never log it |

## The login flow — TCP CSIL-RPC only

`docs/DEPLOYING-RP.md` is explicit: the old `POST /v1alpha/*.json` HTTP
routes for these operations **were removed** when server-to-server traffic
moved to TCP CSIL-RPC, and the generic HTTP RPC carrier cannot complete this
flow at all (`verify-assertion` and `userinfo-fetch` need the outbound S2S
context only the TCP carrier has). The `Rp` service over TCP CSIL-RPC is the
**only** way to drive these operations today — this document's approach.

Six steps (`csil/linkkeys.csil`'s `Rp` service, lines ~719-786):

1. **`Rp/sign-request`** — `{callback_url, nonce, ?requested_claims}` →
   `{signed_request}`. Your app picks a fresh single-use `nonce` and its own
   `callback_url`; the RP server signs an auth request with your domain key.
2. **Redirect the browser** to
   `https://<user_domain>/auth/authorize?signed_request=<signed_request>`.
   `user_domain` is whatever LinkKeys domain the *user* chose (from an
   `alice@example.com`-shaped identity string) — **not** your RP's own
   domain.
3. The user authenticates and consents at their own IDP, which redirects the
   browser back to your `callback_url` with `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** — `{encrypted_token}` → `{signed_assertion}`. Only
   your RP server (holder of your domain's private key) can decrypt this.
5. **`Rp/verify-assertion`** — `{signed_assertion, expected_domain}` →
   `{assertion, verified}`. Your RP server checks the assertion's signature
   against the *issuing* domain's published keys. **Check `verified`** — a
   successful call only means the bytes round-tripped and decoded, not that
   the assertion is trustworthy. Reject unless `verified == true`. Nonce
   single-use and domain equality are your app's job (nothing in this call
   enforces them) — see `handleCallback` below.
6. **Optional: `Rp/userinfo-fetch`** — `{token, api_base, domain}` →
   `UserInfo{user_id, domain, display_name, claims}`. Skip it if you only
   need proof of identity.

**Envelope auth**: all `Rp` operations are authenticated by the CSIL-RPC
request envelope's optional `auth` field (`csil-rpc-transport.md` §1.1)
carrying this app's **raw API key — no `Bearer ` prefix** (that convention
belongs to the remaining HTTP surfaces, per `docs/DEPLOYING-RP.md`'s "Web App
Integration"). There is no client certificate on this leg: your app presents
no domain key of its own; only the RP server has one.

## The TLS caveat — read this before writing any network code

### The stdlib limitation, stated plainly

This SDK's own README (`sdks/local-rp/zig/README.md`, "TLS evaluation
outcome") and `src/tls_pin.zig`'s module docs establish, for Zig 0.14.1:

- `std.crypto.tls.Client` **can** complete a TLS 1.3 handshake with
  certificate verification relaxed (`Options.ca = .self_signed`,
  `Options.host = .no_verification`), including against Ed25519 leaf
  certificates.
- It **cannot** expose the parsed peer certificate afterward.
  `Client.init()` verifies and discards the leaf certificate transiently
  during the handshake; nothing on the `Client` struct retains it, and there
  is no verification-callback hook (unlike a `rustls::ClientConfig` or a Go
  `tls.Config.VerifyPeerCertificate`) to intercept it first.

The protocol's trust model is **pin-based, not WebPKI-based**: connecting to
your RP server (or the SDK's own local-RP calls to a domain's IDP) must
verify the server certificate's SPKI Ed25519 public-key fingerprint is a
member of the DNS-published `fp=` set — that is the entire anchor, not CA
validity. Without a way to see the peer certificate, `std.crypto.tls.Client`
alone cannot implement that check. This is exactly why this SDK's own
`rpc.defaultSecureDial` always returns `error.PinnedTlsUnavailable` rather
than silently connecting unpinned, and why this document's app-level
`SecureDial` (below) does the same by default.

There are two realistic ways to actually get pinned TLS bytes on the wire in
Zig today. This document implements and compile-verifies the first; it
describes, but does not compile, the second.

### Option A (implemented here): OpenSSL via Zig's C interop

Link a real TLS library that DOES expose the peer certificate, through
Zig's `@cImport`/C interop — the same approach the sibling **C** SDK
(`sdks/local-rp/c/src/rpc.c`) already takes, since C has no stdlib TLS at
all. The extern boundary is small:

- `@cImport({ @cInclude("openssl/ssl.h"); ... })` gets you `SSL_CTX`, `SSL`,
  `BIO`, and `X509` as Zig types generated by `translate-c` directly from the
  system's real OpenSSL headers — no hand-maintained binding layer.
- A custom source/sink `BIO` (`BIO_meth_new(BIO_TYPE_SOURCE_SINK, ...)`)
  hands OpenSSL an already-connected socket instead of letting it `connect()`
  one itself, via read/write callback functions with `callconv(.C)`.
- `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL)` disables WebPKI chain
  validation — the manual pin check is the trust anchor, not the CA chain.
- After `SSL_connect` succeeds, `SSL_get1_peer_certificate` +
  `X509_get0_pubkey` + `EVP_PKEY_get_raw_public_key` extract the peer's raw
  32-byte Ed25519 public key — the fact `std.crypto.tls.Client` cannot give
  you — and this SDK's own `fingerprintHex`/`fp=` comparison does the rest.

**Tradeoffs**: real, unsafe-adjacent C interop lives in your Zig binary (an
`@cImport`'d C library, manual `BIO`/`SSL_CTX`/`SSL` lifetime management, raw
pointer casts in the callback glue) — every memory-safety property Zig
otherwise buys you at that boundary is back on you and OpenSSL's own
correctness. It does link and run cleanly against this environment's system
OpenSSL (3.6.3) with no vendoring required, and it's the only one of the two
options this document actually compiled and exercised — see "What was
compiled" below and `tls_pin_openssl.zig`'s full listing further down.

### Option B (described, not compiled): a local TLS-terminating sidecar proxy

Run a small process on `localhost` — in whatever language/tool most
comfortably does pinned TLS (a tiny Go proxy using
`tls.Config.VerifyPeerCertificate`, exactly the ~15-line callback
`sdks/local-rp/go/example.md`'s `dialPinnedTLS` already shows; or `stunnel`/
nginx's stream module configured to trust only the RP server's exact
certificate file, which achieves the same "don't trust WebPKI, trust this
one specific key" property as SPKI pinning even though the *mechanism* is
exact-certificate matching rather than a raw SPKI hash set) — that
terminates the pinned TLS connection to your RP server and forwards
plaintext to your Zig app over a loopback socket. Your Zig app then talks to
`127.0.0.1:<local-port>` using nothing more than `std.net` — no TLS, no C
interop, in the Zig binary at all.

**Tradeoffs**:
- **For**: zero unsafe/C-interop code in the Zig binary; the pinning logic
  lives in a tool that already has mature, audited certificate handling; easy
  to swap the sidecar implementation (Go, stunnel, nginx, …) without
  touching Zig code at all.
- **Against**: an extra moving part to build, deploy, and supervise
  alongside your app (its own process lifecycle, its own failure mode if it
  crashes or isn't restarted); the pin configuration now lives outside the
  Zig binary, in whatever config format the sidecar uses — a second place
  fingerprints/certs can drift out of sync with what your app expects; the
  loopback socket between app and sidecar must itself be access-controlled
  (bind it to `127.0.0.1` only, or use a Unix domain socket with restrictive
  permissions) so nothing else on the box can inject traffic between them.
  Latency overhead is negligible (an extra loopback hop), but it is a genuine
  extra hop to reason about.

Both options plug into the exact same seam: this document's `SecureDial`
function type (`rp_client.zig`, below) takes an allocator and this app's
`RpConfig` and returns an established `Conn` — Option A implements it with
`tlsOpenSslDial`; Option B would implement it by dialing the sidecar's
loopback port in plain `std.net`, no TLS calls of its own at all.

## The code

Built and tested as a real, standalone Zig package in a scratch directory
outside this repo, importing this SDK as an ordinary module dependency (see
"What was compiled" at the end). Layout:

```text
regularrp-zig-example/
  build.zig, build.zig.zon
  src/
    conn.zig               a Conn seam independent of std.net.Stream
    rp_types.zig            hand-written CBOR codecs for the Rp service
    rpc_envelope.zig         envelope-with-auth + framing over Conn
    tls_pin_openssl.zig      Option A: real pinned-TLS dial via OpenSSL
    rp_client.zig            RpConfig, beginLogin, handleCallback
    main.zig                 module root
```

### `build.zig.zon` / `build.zig`

A real external app depends on this SDK the normal way (a module
path/URL/git dependency); the relative `.path` here exists only because this
scratch package was built and compiled inside a checkout of the linkkeys
repo, against an unpublished local copy of `sdks/local-rp/zig` — delete or
repoint it in a real app, the same way `sdks/local-rp/go/example.md`'s
`replace` directive is checkout-only.

```zig
// build.zig.zon
.{
    .name = .regularrp_zig_example,
    .version = "0.1.0",
    .fingerprint = 0xd34c90a7b33817e7,
    .minimum_zig_version = "0.14.1",
    .dependencies = .{
        .linkkeys_local_rp = .{
            .path = "../path/to/checkout/sdks/local-rp/zig",
        },
    },
    .paths = .{ "build.zig", "build.zig.zon", "src" },
}
```

```zig
// build.zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lrp_dep = b.dependency("linkkeys_local_rp", .{ .target = target, .optimize = optimize });
    const lrp_mod = lrp_dep.module("linkkeys_local_rp");

    // One module for the whole example: CBOR/RPC glue (pure Zig) plus the
    // OpenSSL-backed pinned-TLS dial (real C interop), because a real app
    // links them into one binary. `link_libc` + `-lssl -lcrypto` are only
    // needed for the OpenSSL half; the pure half compiles and runs fine
    // without ever touching the network.
    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addImport("linkkeys_local_rp", lrp_mod);
    mod.linkSystemLibrary("ssl", .{});
    mod.linkSystemLibrary("crypto", .{});

    const test_step = b.step("test", "Run example tests (CBOR/RPC round trips + OpenSSL smoke tests, no live network)");
    const tests = b.addTest(.{ .root_module = mod });
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
```

`zig build test` runs everything below in one binary: pure CBOR/envelope/flow
tests over real loopback sockets, and real (non-network) OpenSSL calls —
`SSL_CTX_new`, a real X.509 parse — proving the C interop actually links and
runs, not just type-checks.

### `conn.zig` — a byte-stream seam independent of `std.net.Stream`

This SDK's own `rpc.zig` framing helpers
(`writeLengthPrefixed`/`readLengthPrefixed`) are typed concretely to
`std.net.Stream`, because that SDK's default transport only ever hands back
a raw TCP stream (pinned TLS is out of scope there, per its README). This
app's transport to its own RP server is *always* TLS, and an OpenSSL `SSL*`
is not a `std.net.Stream` — there's no way to make `SSL_read`/`SSL_write`
satisfy that concrete type. So this app defines its own tiny vtable seam
(the same pattern this SDK's own `Transport` uses for its dial seam) and
writes framing/envelope helpers against it instead:

```zig
const std = @import("std");

pub const Conn = struct {
    ptr: *anyopaque,
    readFn: *const fn (ptr: *anyopaque, buf: []u8) anyerror!usize,
    writeFn: *const fn (ptr: *anyopaque, buf: []const u8) anyerror!usize,
    closeFn: *const fn (ptr: *anyopaque) void,

    pub fn readAll(self: Conn, buf: []u8) !usize {
        var total: usize = 0;
        while (total < buf.len) {
            const n = try self.readFn(self.ptr, buf[total..]);
            if (n == 0) break; // clean EOF
            total += n;
        }
        return total;
    }

    pub fn writeAll(self: Conn, buf: []const u8) !void {
        var sent: usize = 0;
        while (sent < buf.len) {
            const n = try self.writeFn(self.ptr, buf[sent..]);
            if (n == 0) return error.ConnectionClosed;
            sent += n;
        }
    }

    pub fn close(self: Conn) void {
        self.closeFn(self.ptr);
    }
};

/// Adapts a std.net.Stream (a plain, UNENCRYPTED TCP socket) to Conn. Used
/// to wrap a fresh TCP dial before TLS is layered on top, and by this
/// example's own tests against a fake loopback server. Never used against a
/// real RP server on its own — the real dial path attaches pinned TLS via
/// tls_pin_openssl.attachPinnedTls first.
pub const StreamConn = struct {
    stream: std.net.Stream,

    pub fn conn(self: *StreamConn) Conn {
        return .{ .ptr = self, .readFn = readImpl, .writeFn = writeImpl, .closeFn = closeImpl };
    }

    fn readImpl(ptr: *anyopaque, buf: []u8) anyerror!usize {
        const self: *StreamConn = @ptrCast(@alignCast(ptr));
        return self.stream.read(buf);
    }
    fn writeImpl(ptr: *anyopaque, buf: []const u8) anyerror!usize {
        const self: *StreamConn = @ptrCast(@alignCast(ptr));
        return self.stream.write(buf);
    }
    fn closeImpl(ptr: *anyopaque) void {
        const self: *StreamConn = @ptrCast(@alignCast(ptr));
        self.stream.close();
    }
};
```

### `rp_types.zig` — hand-written CBOR codecs for the `Rp` service

No csilgen Zig target exists yet (this SDK's own README documents the filed
request), so these follow the exact hand-written, value-tree-over-`cbor.zig`
style `sdks/local-rp/zig/src/types.zig` already uses — field-for-field
against `csil/linkkeys.csil`'s `RpSignRequest`, `RpSignResponse`,
`RpDecryptRequest`, `RpDecryptResponse`, `RpVerifyRequest`,
`RpVerifyResponse`, `RpUserInfoRequest`, `IdentityAssertion`, and `UserInfo`
CDDL (lines ~243-258, ~377-390, ~719-786, ~425-430). Where the SDK already
exports a reusable piece — `Claim`, and `claimArrayFromValue` — this file
reuses it rather than redefining it:

```zig
const std = @import("std");
const lrp = @import("linkkeys_local_rp");
const cbor = lrp.cbor;

fn textArrayToValue(allocator: std.mem.Allocator, items: []const []const u8) !cbor.Value {
    const vals = try allocator.alloc(cbor.Value, items.len);
    for (items, 0..) |it, i| vals[i] = cbor.text(it);
    return cbor.arrayVal(vals);
}

fn textArrayFromValue(allocator: std.mem.Allocator, v: cbor.Value) ![][]const u8 {
    const arr = try cbor.asArray(v);
    const out = try allocator.alloc([]const u8, arr.len);
    for (arr, 0..) |it, i| out[i] = try cbor.asText(it);
    return out;
}

// RequestedClaim / ClaimRequest (csil/linkkeys.csil lines ~243-258)

pub const RequestedClaim = struct {
    claim_type: []const u8,
    datatype: []const u8,
};

fn requestedClaimToValue(allocator: std.mem.Allocator, v: RequestedClaim) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 2);
    entries[0] = .{ .key = cbor.text("claim_type"), .value = cbor.text(v.claim_type) };
    entries[1] = .{ .key = cbor.text("datatype"), .value = cbor.text(v.datatype) };
    return cbor.mapVal(entries);
}

fn requestedClaimArrayToValue(allocator: std.mem.Allocator, items: []const RequestedClaim) !cbor.Value {
    const vals = try allocator.alloc(cbor.Value, items.len);
    for (items, 0..) |it, i| vals[i] = try requestedClaimToValue(allocator, it);
    return cbor.arrayVal(vals);
}

pub const ClaimRequest = struct {
    required: []const RequestedClaim,
    optional: []const RequestedClaim,
};

fn claimRequestToValue(allocator: std.mem.Allocator, v: ClaimRequest) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 2);
    entries[0] = .{ .key = cbor.text("required"), .value = try requestedClaimArrayToValue(allocator, v.required) };
    entries[1] = .{ .key = cbor.text("optional"), .value = try requestedClaimArrayToValue(allocator, v.optional) };
    return cbor.mapVal(entries);
}

// RpSignRequest / RpSignResponse
//
// `flow_context` (AuthFlowContext) is deliberately not implemented here --
// it's only used for the "claims_update" re-consent flow
// (demoappsite/src/main.rs's request_age_checks), which this walkthrough
// doesn't cover. Add a `flowContextToValue` alongside `claimRequestToValue`
// above, the same way, if your app needs it.

pub const RpSignRequest = struct {
    callback_url: []const u8,
    nonce: []const u8,
    requested_claims: ?ClaimRequest = null,
};

pub fn encodeRpSignRequest(allocator: std.mem.Allocator, v: RpSignRequest) ![]u8 {
    var entries = std.ArrayList(cbor.Entry).init(allocator);
    try entries.append(.{ .key = cbor.text("callback_url"), .value = cbor.text(v.callback_url) });
    try entries.append(.{ .key = cbor.text("nonce"), .value = cbor.text(v.nonce) });
    if (v.requested_claims) |rc| {
        try entries.append(.{ .key = cbor.text("requested_claims"), .value = try claimRequestToValue(allocator, rc) });
    }
    return cbor.encodeAlloc(allocator, cbor.mapVal(try entries.toOwnedSlice()));
}

pub const RpSignResponse = struct {
    signed_request: []const u8,
};

pub fn decodeRpSignResponse(allocator: std.mem.Allocator, bytes: []const u8) !RpSignResponse {
    const root = try cbor.decode(allocator, bytes);
    return .{ .signed_request = try cbor.asText(try cbor.require(root, "signed_request")) };
}
```

`RpDecryptRequest`/`RpDecryptResponse` and `RpUserInfoRequest` follow the
identical trivial shape (one or three plain text fields; the full source has
them). `IdentityAssertion` and `RpVerifyResponse` are the more interesting
ones — a nested struct and a required text-array field:

```zig
// IdentityAssertion (csil/linkkeys.csil lines ~377-390)

pub const IdentityAssertion = struct {
    user_id: []const u8,
    domain: []const u8,
    audience: []const u8,
    nonce: []const u8,
    issued_at: []const u8,
    expires_at: []const u8,
    authorized_claims: []const []const u8,
    display_name: ?[]const u8 = null,
};

fn identityAssertionFromValue(allocator: std.mem.Allocator, v: cbor.Value) !IdentityAssertion {
    return .{
        .user_id = try cbor.asText(try cbor.require(v, "user_id")),
        .domain = try cbor.asText(try cbor.require(v, "domain")),
        .audience = try cbor.asText(try cbor.require(v, "audience")),
        .nonce = try cbor.asText(try cbor.require(v, "nonce")),
        .issued_at = try cbor.asText(try cbor.require(v, "issued_at")),
        .expires_at = try cbor.asText(try cbor.require(v, "expires_at")),
        .authorized_claims = try textArrayFromValue(allocator, try cbor.require(v, "authorized_claims")),
        .display_name = if (cbor.mapGet(v, "display_name")) |x| try cbor.asText(x) else null,
    };
}

// RpVerifyRequest / RpVerifyResponse

pub const RpVerifyRequest = struct {
    signed_assertion: []const u8,
    expected_domain: []const u8,
};

pub fn encodeRpVerifyRequest(allocator: std.mem.Allocator, v: RpVerifyRequest) ![]u8 {
    const entries = try allocator.alloc(cbor.Entry, 2);
    entries[0] = .{ .key = cbor.text("signed_assertion"), .value = cbor.text(v.signed_assertion) };
    entries[1] = .{ .key = cbor.text("expected_domain"), .value = cbor.text(v.expected_domain) };
    return cbor.encodeAlloc(allocator, cbor.mapVal(entries));
}

pub const RpVerifyResponse = struct {
    assertion: IdentityAssertion,
    verified: bool,
};

pub fn decodeRpVerifyResponse(allocator: std.mem.Allocator, bytes: []const u8) !RpVerifyResponse {
    const root = try cbor.decode(allocator, bytes);
    return .{
        .assertion = try identityAssertionFromValue(allocator, try cbor.require(root, "assertion")),
        .verified = try cbor.asBool(try cbor.require(root, "verified")),
    };
}

// RpUserInfoRequest / UserInfo (csil/linkkeys.csil lines ~764-771, 425-430)
//
// UserInfo.claims reuses the SDK's own exported Claim type and
// claimArrayFromValue decoder -- no need to redefine Claim/ClaimSignature.

pub const RpUserInfoRequest = struct {
    token: []const u8,
    api_base: []const u8,
    domain: []const u8,
};

pub fn encodeRpUserInfoRequest(allocator: std.mem.Allocator, v: RpUserInfoRequest) ![]u8 {
    const entries = try allocator.alloc(cbor.Entry, 3);
    entries[0] = .{ .key = cbor.text("token"), .value = cbor.text(v.token) };
    entries[1] = .{ .key = cbor.text("api_base"), .value = cbor.text(v.api_base) };
    entries[2] = .{ .key = cbor.text("domain"), .value = cbor.text(v.domain) };
    return cbor.encodeAlloc(allocator, cbor.mapVal(entries));
}

pub const UserInfo = struct {
    user_id: []const u8,
    domain: []const u8,
    display_name: []const u8,
    claims: []lrp.types.Claim,
};

pub fn decodeUserInfo(allocator: std.mem.Allocator, bytes: []const u8) !UserInfo {
    const root = try cbor.decode(allocator, bytes);
    return .{
        .user_id = try cbor.asText(try cbor.require(root, "user_id")),
        .domain = try cbor.asText(try cbor.require(root, "domain")),
        .display_name = try cbor.asText(try cbor.require(root, "display_name")),
        .claims = try lrp.types.claimArrayFromValue(allocator, try cbor.require(root, "claims")),
    };
}
```

The full file also has encode-direction counterparts for `RpDecryptResponse`,
`RpVerifyResponse`, and `RpSignResponse` (`encodeRpDecryptResponse`, etc.) —
these exist **only** for this example's own fake-RP-server tests, the same
way this SDK's own `rpc.zig` marks its `encodeRpcResponseOk` "only used by
this SDK's own test fixtures." A real app never encodes an
`IdentityAssertion`/`UserInfo`/sign-response itself; only the IDP/RP server
does.

### `rpc_envelope.zig` — envelope-with-auth + framing over `Conn`

Reuses what this SDK already exports and is transport-agnostic
(`lrp.cbor`, and `lrp.rpc.decodeRpcResponse` — which only parses a
`[]const u8` frame body, not a stream, so it works unchanged here) but does
**not** reuse `lrp.rpc.encodeRpcRequest` (never emits an `auth` field — the
SDK's own local-RP calls are unauthenticated at the envelope level by
design) or `lrp.rpc.writeLengthPrefixed`/`readLengthPrefixed` (typed
concretely to `std.net.Stream`, per `conn.zig`'s docs above):

```zig
const std = @import("std");
const lrp = @import("linkkeys_local_rp");
const cbor = lrp.cbor;
const connmod = @import("conn.zig");

pub const rpc_version: u64 = 1;

/// Matches the local-RP SDK's own cap (lrp.rpc.max_frame_size) so a
/// malicious/compromised RP server can't drive this client to an unbounded
/// allocation via a forged length prefix.
pub const max_frame_size: usize = 1024 * 1024;

pub fn encodeRpcRequestAuth(allocator: std.mem.Allocator, service: []const u8, op: []const u8, payload: []const u8, auth: ?[]const u8) ![]u8 {
    var payload_bytes_val = cbor.bytesVal(payload);
    var entries = std.ArrayList(cbor.Entry).init(allocator);
    try entries.append(.{ .key = cbor.text("v"), .value = cbor.uint(rpc_version) });
    try entries.append(.{ .key = cbor.text("service"), .value = cbor.text(service) });
    try entries.append(.{ .key = cbor.text("op"), .value = cbor.text(op) });
    try entries.append(.{ .key = cbor.text("payload"), .value = cbor.tagVal(24, &payload_bytes_val) });
    if (auth) |a| try entries.append(.{ .key = cbor.text("auth"), .value = cbor.text(a) });
    return cbor.encodeAlloc(allocator, cbor.mapVal(try entries.toOwnedSlice()));
}

pub fn writeFramed(conn: connmod.Conn, bytes: []const u8) !void {
    if (bytes.len > max_frame_size) return error.FrameTooLarge;
    var prefix: [4]u8 = undefined;
    std.mem.writeInt(u32, &prefix, @intCast(bytes.len), .big);
    try conn.writeAll(&prefix);
    try conn.writeAll(bytes);
}

pub fn readFramed(allocator: std.mem.Allocator, conn: connmod.Conn, max_frame: usize) !?[]u8 {
    var prefix: [4]u8 = undefined;
    const n = try conn.readAll(&prefix);
    if (n == 0) return null;
    if (n != 4) return error.ConnectionClosed;
    const len = std.mem.readInt(u32, &prefix, .big);
    if (len > max_frame) return error.FrameTooLarge;
    const buf = try allocator.alloc(u8, len);
    const got = try conn.readAll(buf);
    if (got != len) return error.ConnectionClosed;
    return buf;
}

/// Transport status registry (csil-transport-conventions.md section 4) --
/// derived independently from the public spec doc rather than reaching into
/// the SDK's own (unexported) statusToError.
pub fn rpcStatusError(code: i64) anyerror {
    return switch (code) {
        0 => unreachable, // Ok is not an error
        1 => error.RpcMalformedEnvelope,
        2 => error.RpcUnknownServiceOrOp,
        3 => error.RpcUnauthenticated,
        4 => error.RpcForbidden,
        5 => error.RpcVersionUnsupported,
        6 => error.RpcInternal,
        7 => error.RpcUnavailable,
        8 => error.RpcDeadlineExceeded,
        else => error.RpcServerError,
    };
}

/// One API-key-authenticated CSIL-RPC call to the Rp service over an
/// already-established (pinned-TLS, in production) Conn.
pub fn call(allocator: std.mem.Allocator, conn: connmod.Conn, api_key: []const u8, op: []const u8, payload: []const u8) ![]const u8 {
    const req_bytes = try encodeRpcRequestAuth(allocator, "Rp", op, payload, api_key);
    try writeFramed(conn, req_bytes);

    const resp_bytes = try readFramed(allocator, conn, max_frame_size) orelse return error.ConnectionClosed;
    const resp = try lrp.rpc.decodeRpcResponse(allocator, resp_bytes);
    if (resp.status != 0) return rpcStatusError(resp.status);
    return resp.payload;
}
```

This file's own tests (real, run — not shown here for space) exercise
`encodeRpcRequestAuth` (asserting the API key rides `auth` with no `Bearer `
prefix, and is omitted entirely when `null`) and `writeFramed`/`readFramed`
over a real loopback TCP pair, including the too-large-frame rejection path.

### `tls_pin_openssl.zig` — Option A, in full

This is the file the TLS caveat section above describes. Full listing,
because the extern boundary is exactly the part worth seeing in full rather
than summarized:

```zig
const std = @import("std");
const lrp = @import("linkkeys_local_rp");
const connmod = @import("conn.zig");

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/evp.h");
});

pub const PinError = error{
    NotAnEd25519Key,
    UnexpectedKeyLength,
};

/// Extracts the raw 32-byte Ed25519 public key from a parsed OpenSSL
/// certificate -- the same fact lrp.tls_pin.extractEd25519PublicKeyFromCertificateDer
/// extracts by scanning DER bytes for the fixed SPKI prefix; this version
/// asks OpenSSL's own X.509/EVP_PKEY API for it directly, since a real
/// pinned-TLS callback has a parsed X509*, not raw DER, in hand.
pub fn extractEd25519PublicKeyFromX509(cert: ?*c.X509) (PinError || error{OpenSslPublicKeyExtractionFailed})![32]u8 {
    const pkey = c.X509_get0_pubkey(cert) orelse return error.OpenSslPublicKeyExtractionFailed;
    if (c.EVP_PKEY_id(pkey) != c.EVP_PKEY_ED25519) return error.NotAnEd25519Key;

    var raw: [32]u8 = undefined;
    var raw_len: usize = raw.len;
    if (c.EVP_PKEY_get_raw_public_key(pkey, &raw, &raw_len) != 1) return error.OpenSslPublicKeyExtractionFailed;
    if (raw_len != 32) return error.UnexpectedKeyLength;
    return raw;
}

/// Verifies public_key's fingerprint is a member of pinned_fingerprints_hex,
/// via the SDK's own exported fingerprint function so this file computes
/// the pin the identical way the rest of the SDK does.
pub fn verifyPin(public_key: [32]u8, pinned_fingerprints_hex: []const []const u8) bool {
    const fp = lrp.crypto.fingerprintHex(&public_key);
    for (pinned_fingerprints_hex) |pinned| {
        if (std.ascii.eqlIgnoreCase(&fp, pinned)) return true;
    }
    return false;
}

// Conn -> OpenSSL BIO adapter (custom source/sink BIO, mirrors the C SDK's
// bio_conn_read/write/ctrl/create/destroy in sdks/local-rp/c/src/rpc.c)

fn bioConnWrite(bio: ?*c.BIO, buf: [*c]const u8, len: c_int) callconv(.C) c_int {
    const conn: *connmod.Conn = @ptrCast(@alignCast(c.BIO_get_data(bio)));
    const n = conn.writeFn(conn.ptr, buf[0..@intCast(len)]) catch {
        c.BIO_clear_retry_flags(bio);
        return -1;
    };
    c.BIO_clear_retry_flags(bio);
    return @intCast(n);
}

fn bioConnRead(bio: ?*c.BIO, buf: [*c]u8, len: c_int) callconv(.C) c_int {
    const conn: *connmod.Conn = @ptrCast(@alignCast(c.BIO_get_data(bio)));
    const n = conn.readFn(conn.ptr, buf[0..@intCast(len)]) catch {
        c.BIO_clear_retry_flags(bio);
        return -1;
    };
    c.BIO_clear_retry_flags(bio);
    return @intCast(n); // 0 == clean EOF, matches the C SDK
}

fn bioConnCtrl(bio: ?*c.BIO, cmd: c_int, num: c_long, ptr: ?*anyopaque) callconv(.C) c_long {
    _ = bio;
    _ = num;
    _ = ptr;
    if (cmd == c.BIO_CTRL_FLUSH) return 1;
    return 0;
}

fn bioConnCreate(bio: ?*c.BIO) callconv(.C) c_int {
    c.BIO_set_init(bio, 1);
    return 1;
}

fn bioConnDestroy(bio: ?*c.BIO) callconv(.C) c_int {
    if (bio == null) return 0;
    c.BIO_set_data(bio, null);
    c.BIO_set_init(bio, 0);
    return 1;
}

var bio_conn_method: ?*c.BIO_METHOD = null;

fn connBioMethod() !*c.BIO_METHOD {
    if (bio_conn_method) |m| return m;
    const m = c.BIO_meth_new(c.BIO_TYPE_SOURCE_SINK, "lrp_conn") orelse return error.OpenSslBioMethNewFailed;
    _ = c.BIO_meth_set_write(m, bioConnWrite);
    _ = c.BIO_meth_set_read(m, bioConnRead);
    _ = c.BIO_meth_set_ctrl(m, bioConnCtrl);
    _ = c.BIO_meth_set_create(m, bioConnCreate);
    _ = c.BIO_meth_set_destroy(m, bioConnDestroy);
    bio_conn_method = m;
    return m;
}

pub const TlsConn = struct {
    ssl_ctx: ?*c.SSL_CTX = null,
    ssl: ?*c.SSL = null,
    raw: connmod.Conn = undefined,

    pub fn conn(self: *TlsConn) connmod.Conn {
        return .{ .ptr = self, .readFn = readImpl, .writeFn = writeImpl, .closeFn = closeImpl };
    }

    fn readImpl(ptr: *anyopaque, buf: []u8) anyerror!usize {
        const self: *TlsConn = @ptrCast(@alignCast(ptr));
        const n = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (n <= 0) return error.TlsReadFailed;
        return @intCast(n);
    }
    fn writeImpl(ptr: *anyopaque, buf: []const u8) anyerror!usize {
        const self: *TlsConn = @ptrCast(@alignCast(ptr));
        const n = c.SSL_write(self.ssl, buf.ptr, @intCast(buf.len));
        if (n <= 0) return error.TlsWriteFailed;
        return @intCast(n);
    }
    fn closeImpl(ptr: *anyopaque) void {
        const self: *TlsConn = @ptrCast(@alignCast(ptr));
        if (self.ssl) |s| {
            _ = c.SSL_shutdown(s);
            c.SSL_free(s); // also frees the attached BIO
        }
        if (self.ssl_ctx) |ctx| c.SSL_CTX_free(ctx);
        self.raw.close();
    }
};

/// Dials raw (already an open, plain-TCP Conn -- e.g. from
/// lrp.transport.StdTransport, whose dial-only seam this app reuses
/// unmodified), completes a TLS handshake with WebPKI chain validation OFF,
/// then MANDATORILY verifies the peer certificate's Ed25519 SPKI
/// fingerprint is a member of pinned_fingerprints_hex. Fails closed on any
/// mismatch or non-Ed25519 key.
pub fn attachPinnedTls(raw: connmod.Conn, pinned_fingerprints_hex: []const []const u8, out: *TlsConn) !void {
    out.raw = raw;

    out.ssl_ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.OpenSslCtxNewFailed;
    errdefer if (out.ssl_ctx) |ctx| c.SSL_CTX_free(ctx);

    // WebPKI validity is NOT the trust anchor here -- the manual pin check
    // below is.
    c.SSL_CTX_set_verify(out.ssl_ctx, c.SSL_VERIFY_NONE, null);

    out.ssl = c.SSL_new(out.ssl_ctx) orelse return error.OpenSslNewFailed;
    errdefer if (out.ssl) |s| c.SSL_free(s);

    const method = try connBioMethod();
    const bio = c.BIO_new(method) orelse return error.OpenSslBioNewFailed;
    // &out.raw is stable for the lifetime of out (the caller-owned TlsConn),
    // which must outlive the connection -- the same lifetime contract
    // SSL_set_bio already imposes.
    c.BIO_set_data(bio, &out.raw);
    c.SSL_set_bio(out.ssl, bio, bio); // SSL now owns bio

    if (c.SSL_connect(out.ssl) != 1) return error.TlsHandshakeFailed;

    const cert = c.SSL_get1_peer_certificate(out.ssl) orelse return error.NoPeerCertificate;
    defer c.X509_free(cert);

    const pub_key = try extractEd25519PublicKeyFromX509(cert);
    if (!verifyPin(pub_key, pinned_fingerprints_hex)) return error.CertificateFingerprintNotPinned;
}
```

This file's own tests (real, and they run without any network access) are
worth calling out specifically, since they're the proof this isn't just
code that type-checks:

```zig
test "SSL_CTX_new/SSL_CTX_free smoke test -- proves the C interop actually links and runs" {
    const ctx = c.SSL_CTX_new(c.TLS_client_method());
    try std.testing.expect(ctx != null);
    c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
    c.SSL_CTX_free(ctx);
}

test "extractEd25519PublicKeyFromX509 matches the SDK's own DER-scanning extraction on the same openssl-minted fixture" {
    // The identical fixture certificate as sdks/local-rp/zig/src/tls_pin.zig's
    // own test (same openssl-CLI generation command, documented there).
    const fixture_cert_der_hex = "3082013e...4e4bd3d01"; // see tls_pin.zig for the full hex
    const fixture_raw_pubkey_hex = "76126b9a...016cd2";

    var der: [fixture_cert_der_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&der, fixture_cert_der_hex);
    var der_ptr: [*c]const u8 = &der;
    const cert = c.d2i_X509(null, &der_ptr, @intCast(der.len));
    defer c.X509_free(cert);

    const extracted = try extractEd25519PublicKeyFromX509(cert);
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, fixture_raw_pubkey_hex);
    try std.testing.expectEqualSlices(u8, &expected, &extracted);

    // Cross-check against the SDK's own pure-Zig DER-scanning extraction --
    // both must agree on the identical fixture bytes.
    const sdk_extracted = try lrp.tls_pin.extractEd25519PublicKeyFromCertificateDer(&der);
    try std.testing.expectEqualSlices(u8, &sdk_extracted, &extracted);
}
```

(The full hex constants are in the actual file — elided here for length.)
That second test is the strongest evidence this document can offer that
Option A is correct, not merely "compiles": OpenSSL's own X.509 parser and
this SDK's independent DER-scanning parser are handed the exact same
openssl-minted certificate bytes, and their extracted 32-byte public keys
are asserted equal.

### `rp_client.zig` — the login flow

`RpConfig` and the env var names match `demoappsite/src/main.rs`'s
`RpConfig` and `sdks/local-rp/go/example.md`'s `rpConfig` verbatim:

```zig
const std = @import("std");
const lrp = @import("linkkeys_local_rp");
const connmod = @import("conn.zig");
const envelope = @import("rpc_envelope.zig");
const rp_types = @import("rp_types.zig");
const tls_openssl = @import("tls_pin_openssl.zig");

pub const RpConfig = struct {
    tcp_addr: []const u8,
    fingerprints: []const []const u8,
    api_key: []const u8,
};

/// The dial seam rpCall uses to obtain an authenticated, pinned-TLS-verified
/// Conn to the RP server. The default (defaultSecureDial, below) fails
/// closed -- see the TLS caveat section above.
pub const SecureDial = *const fn (allocator: std.mem.Allocator, cfg: RpConfig, out: *tls_openssl.TlsConn) anyerror!connmod.Conn;

/// Always fails closed -- there is no safe unpinned fallback for this
/// protocol's mandatory SPKI pin check.
pub fn defaultSecureDial(allocator: std.mem.Allocator, cfg: RpConfig, out: *tls_openssl.TlsConn) anyerror!connmod.Conn {
    _ = allocator;
    _ = cfg;
    _ = out;
    return error.PinnedTlsUnavailable;
}

/// The real dial path: lrp.transport.StdTransport (the SDK's own dial-only
/// seam, reused unmodified -- opening a TCP socket has nothing
/// local-RP-specific about it) for the raw connect, then
/// tls_pin_openssl.attachPinnedTls for the pinned TLS handshake.
pub fn tlsOpenSslDial(allocator: std.mem.Allocator, cfg: RpConfig, out: *tls_openssl.TlsConn) anyerror!connmod.Conn {
    _ = allocator;
    var std_transport = lrp.transport.StdTransport{};
    const stream = try std_transport.transport().dial(cfg.tcp_addr);
    var stream_conn = connmod.StreamConn{ .stream = stream };
    try tls_openssl.attachPinnedTls(stream_conn.conn(), cfg.fingerprints, out);
    return out.conn();
}

pub fn rpCall(allocator: std.mem.Allocator, cfg: RpConfig, secure_dial: SecureDial, op: []const u8, payload: []const u8) ![]const u8 {
    var tls_conn: tls_openssl.TlsConn = .{};
    const conn = try secure_dial(allocator, cfg, &tls_conn);
    defer conn.close();
    return envelope.call(allocator, conn, cfg.api_key, op, payload);
}

pub fn signRequest(allocator: std.mem.Allocator, cfg: RpConfig, secure_dial: SecureDial, callback_url: []const u8, nonce: []const u8) ![]const u8 {
    const payload = try rp_types.encodeRpSignRequest(allocator, .{ .callback_url = callback_url, .nonce = nonce });
    const resp_bytes = try rpCall(allocator, cfg, secure_dial, "sign-request", payload);
    const resp = try rp_types.decodeRpSignResponse(allocator, resp_bytes);
    return resp.signed_request;
}

pub fn decryptToken(allocator: std.mem.Allocator, cfg: RpConfig, secure_dial: SecureDial, encrypted_token: []const u8) ![]const u8 {
    const payload = try rp_types.encodeRpDecryptRequest(allocator, .{ .encrypted_token = encrypted_token });
    const resp_bytes = try rpCall(allocator, cfg, secure_dial, "decrypt-token", payload);
    const resp = try rp_types.decodeRpDecryptResponse(allocator, resp_bytes);
    return resp.signed_assertion;
}

/// Callers MUST check the returned `verified` flag -- a successful return
/// only means the call round-tripped and decoded, not that the assertion is
/// trustworthy.
pub fn verifyAssertion(allocator: std.mem.Allocator, cfg: RpConfig, secure_dial: SecureDial, signed_assertion: []const u8, expected_domain: []const u8) !rp_types.RpVerifyResponse {
    const payload = try rp_types.encodeRpVerifyRequest(allocator, .{ .signed_assertion = signed_assertion, .expected_domain = expected_domain });
    const resp_bytes = try rpCall(allocator, cfg, secure_dial, "verify-assertion", payload);
    return rp_types.decodeRpVerifyResponse(allocator, resp_bytes);
}

pub fn userInfoFetch(allocator: std.mem.Allocator, cfg: RpConfig, secure_dial: SecureDial, token: []const u8, api_base: []const u8, domain: []const u8) !rp_types.UserInfo {
    const payload = try rp_types.encodeRpUserInfoRequest(allocator, .{ .token = token, .api_base = api_base, .domain = domain });
    const resp_bytes = try rpCall(allocator, cfg, secure_dial, "userinfo-fetch", payload);
    return rp_types.decodeUserInfo(allocator, resp_bytes);
}

/// What this app persists between beginLogin and the callback arriving --
/// a server-side session tied to the browser (a signed cookie, a DB row).
/// Single-use: discard it after one handleCallback attempt.
pub const PendingLogin = struct {
    nonce: []const u8,
    user_domain: []const u8,
};

/// Steps 1-2: sign an auth request via this app's RP server and build the
/// browser-redirect URL to the user's chosen LinkKeys domain (user_domain --
/// NOT this app's own RP domain).
pub fn beginLogin(allocator: std.mem.Allocator, cfg: RpConfig, secure_dial: SecureDial, user_domain: []const u8, callback_url: []const u8, nonce: []const u8) !struct { redirect_url: []const u8, pending: PendingLogin } {
    const signed_request = try signRequest(allocator, cfg, secure_dial, callback_url, nonce);
    const redirect_url = try std.fmt.allocPrint(
        allocator,
        "https://{s}/auth/authorize?signed_request={s}",
        .{ user_domain, signed_request },
    );
    return .{ .redirect_url = redirect_url, .pending = .{ .nonce = nonce, .user_domain = user_domain } };
}

pub const CallbackError = error{
    AssertionNotVerified,
    DomainMismatch,
    NonceMismatch,
    TokenAlreadyRedeemed,
};

/// Steps 3-5 (decrypt, verify, and the app's OWN nonce/domain/single-use
/// checks -- none of which the RP service enforces for you).
///
/// Two allocators, deliberately: `allocator` is per-call scratch (a real
/// app typically passes a request-scoped arena -- everything it produces is
/// only valid until that arena is freed). `nonce_store_allocator` is
/// whatever backs `used_nonces` for the long haul. These must NOT be the
/// same short-lived arena, or the nonce this function records would dangle
/// the moment the caller's per-request arena is freed.
pub fn handleCallback(
    allocator: std.mem.Allocator,
    nonce_store_allocator: std.mem.Allocator,
    cfg: RpConfig,
    secure_dial: SecureDial,
    pending: PendingLogin,
    encrypted_token: []const u8,
    used_nonces: *std.StringHashMap(void),
) !rp_types.IdentityAssertion {
    const signed_assertion = try decryptToken(allocator, cfg, secure_dial, encrypted_token);

    const verify_result = try verifyAssertion(allocator, cfg, secure_dial, signed_assertion, pending.user_domain);
    if (!verify_result.verified) return error.AssertionNotVerified;

    const assertion = verify_result.assertion;
    if (!std.mem.eql(u8, assertion.domain, pending.user_domain)) return error.DomainMismatch;
    if (!std.mem.eql(u8, assertion.nonce, pending.nonce)) return error.NonceMismatch;
    if (used_nonces.contains(assertion.nonce)) return error.TokenAlreadyRedeemed;
    try used_nonces.put(try nonce_store_allocator.dupe(u8, assertion.nonce), {});

    return assertion;
}
```

This file's own tests (a real fake-RP-server pattern — a loopback
`std.net.Server` accepting real connections on a background thread, plaintext
at the `Conn` seam, the same sanctioned non-TLS fallback this SDK's own
`tests/flow.zig` uses for everything but the TLS layer itself) exercise:

- `beginLogin` against a fake server, asserting the `auth` field carried the
  raw API key with no `Bearer ` prefix, and that the redirect URL is built
  against the *user's* domain.
- `handleCallback`'s full decrypt+verify round trip, asserting the returned
  assertion's fields and that the nonce gets recorded.
- `handleCallback` rejecting a replayed nonce on a **second** full round
  trip (the fake server serves two complete decrypt+verify pairs; the RP
  service itself has no idea this app already redeemed the nonce once — it
  happily verifies the assertion again, and it's `handleCallback`'s own
  `used_nonces` check that catches the replay).
- `defaultSecureDial` always failing closed.

## Wiring into an HTTP handler

This example deliberately stops at `beginLogin`/`handleCallback` — Zig has
no single blessed HTTP framework the way Rust has Rocket or Go has
`net/http`, so wiring depends heavily on what your app already uses
(`std.http.Server`, a third-party router, or an existing non-Zig frontend
calling into a Zig backend service). The shape, regardless of framework, is
exactly `sdks/local-rp/go/example.md`'s `handleLogin`/`handleAuthCallback`:

```zig
// Illustrative only -- NOT compiled as part of this walkthrough (it depends
// on whatever HTTP framework/router your app uses). Shape only.
fn handleLoginRoute(app: *App, req: *Request, res: *Response) !void {
    const user_domain = req.query("domain") orelse return res.badRequest("missing domain");
    const nonce = generateNonce(); // random, single-use -- see identity.zig's randomBytes for a pattern
    const callback_url = try std.fmt.allocPrint(req.arena, "{s}/auth/callback", .{app.base_url});

    const result = rp_client.beginLogin(req.arena, app.rp_cfg, rp_client.tlsOpenSslDial, user_domain, callback_url, nonce) catch |err| {
        return res.badGateway("could not start login: {}", .{err});
    };

    try req.session.put("pending_nonce", result.pending.nonce);
    try req.session.put("pending_domain", result.pending.user_domain);
    res.redirect(result.redirect_url);
}

fn handleCallbackRoute(app: *App, req: *Request, res: *Response) !void {
    const encrypted_token = req.query("encrypted_token") orelse return res.badRequest("missing encrypted_token");
    const pending = rp_client.PendingLogin{
        .nonce = req.session.get("pending_nonce") orelse return res.badRequest("no pending login"),
        .user_domain = req.session.get("pending_domain") orelse return res.badRequest("no pending login"),
    };
    req.session.remove("pending_nonce"); // single-use: consume before use

    const assertion = rp_client.handleCallback(
        req.arena,
        app.durable_allocator,
        app.rp_cfg,
        rp_client.tlsOpenSslDial,
        pending,
        encrypted_token,
        &app.used_nonces,
    ) catch |err| return res.forbidden("login could not be verified: {}", .{err});

    try req.session.put("user_id", assertion.user_id);
    try req.session.put("user_domain", assertion.domain);
    res.redirect("/");
}
```

## App responsibilities (this walkthrough owns none of these)

Exactly parallel to what this SDK's own README documents for local-RP mode:

- **Nonce single-use.** `handleCallback` checks `used_nonces` and marks it,
  but a real app's `used_nonces` must be a durable store (a DB unique
  constraint, a cache entry with a TTL past `expires_at`) — an in-process
  `std.StringHashMap` doesn't survive a restart or work across replicas.
- **Sessions.** `PendingLogin` (in-flight) and the logged-in session are
  separate concerns; keep `PendingLogin` single-use and short-lived.
- **The pinned-TLS `SecureDial`.** See the TLS caveat section — Option A
  (`tlsOpenSslDial`) or your own equivalent must be supplied; the default
  fails closed.
- **API key storage.** Treat `RP_API_KEY` the same tier as a database
  credential — it's shown once and cannot be retrieved again.
- **Local user records / authorization.** This walkthrough returns
  `IdentityAssertion`/`UserInfo` — protocol facts. Mapping `user_id`+`domain`
  to a local account, first-login provisioning, and any app-level
  authorization decisions are entirely your app's to make.
- **Memory.** Every function here takes an explicit allocator; a real app
  typically scopes an arena per request the same way this SDK's own
  `beginLocalLogin`/`completeLocalLogin` recommend — see `handleCallback`'s
  doc comment above for the one place (the nonce store) that must NOT share
  that arena.

## Local-RP vs regular-RP

| | Local RP (`linkkeys_local_rp`, this directory) | Regular RP (this document) |
|---|---|---|
| App identity | A locally-generated Ed25519 key fingerprint (SSH-host-key style) | A DNS domain your RP server owns |
| DNS required | No | Yes — `_linkkeys` + `_linkkeys_apis` TXT records |
| Where keys live | In the app itself (`localRpIdentityToBytes`) | In a separate RP server process your app talks to over TCP |
| Admission | Explicit per-domain approval (pending until an admin approves) | Ordinary DNS-pinned trust, same as any LinkKeys peer |
| Zig SDK | This package (`beginLocalLogin`/`completeLocalLogin`) | None packaged — hand-write the glue this document shows |
| Pinned TLS | Not implemented in this SDK either (`error.PinnedTlsUnavailable`) — same stdlib gap | Same gap; this document's `tlsOpenSslDial` (Option A) or a sidecar (Option B) |
| Best for | LAN tools, self-hosted apps with no public DNS | Any app that already has (or can get) a domain |

## TCP-only and raw-key callouts, gathered in one place

- **TCP CSIL-RPC only.** The `POST /v1alpha/*.json` HTTP routes this
  operation set once had were removed; the generic HTTP RPC carrier cannot
  complete `verify-assertion`/`userinfo-fetch` at all. `Rp/sign-request`,
  `Rp/decrypt-token`, `Rp/verify-assertion`, `Rp/userinfo-fetch` (and
  `Rp/issue-attestation`, not covered by this walkthrough's flow) over TCP
  CSIL-RPC are the only way to drive these operations today.
- **Raw API key, no `Bearer` prefix.** The CSIL-RPC envelope's `auth` field
  carries the key exactly as printed by `user create --api-key`. `Bearer `
  is an HTTP-surface convention this transport does not use.
- **`api_access` relation required.** A syntactically valid API key is not
  enough — every `Rp` op additionally requires the caller to hold the
  `api_access` relation (SEC-06); see "Prerequisites" step 2.
- **Pinned TLS is mandatory, and this SDK's stdlib path can't do it.** See
  "The TLS caveat" section — this is the one piece of the flow this
  walkthrough cannot hand you a drop-in stdlib-only answer for.

## What was compiled

`conn.zig`, `rp_types.zig`, `rpc_envelope.zig`, `tls_pin_openssl.zig`, and
`rp_client.zig` above are copied from a real package built and tested in a
scratch directory outside this repo, with a `path` dependency pointing at
this checkout's `sdks/local-rp/zig`:

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"   # Zig 0.14.1
zig build test --summary all
zig fmt --check src build.zig
```

Result: **17/17 tests pass**, ~3s, and `zig fmt --check` reports no files
needing formatting. What that run actually exercised:

- **Pure CBOR/RPC logic** (`rp_types.zig`, `rpc_envelope.zig`): every
  `Rp*Request`/`Rp*Response`/`IdentityAssertion`/`UserInfo` encode/decode
  pair, round-tripped through this SDK's own `cbor.zig`; the
  envelope-with-`auth` encoder; and the 4-byte length-prefix framing over a
  **real loopback TCP socket pair** (not an in-memory fake — actual
  `std.net.Server`/`std.net.Stream` I/O), including the oversized-frame
  rejection path.
- **The full flow** (`rp_client.zig`): `beginLogin` and `handleCallback`
  against a **real fake RP server** — a background-thread `std.net.Server`
  accepting real TCP connections and speaking real CSIL-RPC frames — proving
  the auth-carrying envelope, the framing, the codecs, and the
  nonce/domain/single-use checks all correctly compose end to end, including
  a same-nonce replay actually being rejected on a second live round trip.
- **Real OpenSSL calls, no network** (`tls_pin_openssl.zig`): `SSL_CTX_new`/
  `SSL_CTX_free` (proving the `@cImport`/`-lssl -lcrypto` linkage actually
  works, not just type-checks), a real `d2i_X509` parse of an
  openssl-CLI-minted Ed25519 certificate fixture (the same fixture this
  SDK's own `tls_pin.zig` test uses), and a cross-check that OpenSSL's
  extraction and this SDK's independent pure-Zig DER-scanning extraction
  agree byte-for-byte on the same input.

**What this run does NOT prove**: no code here dialed a real, live LinkKeys
RP server over the network — there is no live deployment in this
environment to dial. `tlsOpenSslDial`'s handshake-and-pin-check path
(`attachPinnedTls`'s `SSL_connect`/`SSL_get1_peer_certificate` call) is
exercised only up to the point real OpenSSL structures are correctly built
and freed; the actual network handshake against a real RP server, and
Option B (a sidecar proxy) in its entirety, are described but not run here.
That is the honest boundary of what a sandboxed, network-isolated compile
check can verify — wire up `RP_TCP_ADDR`/`RP_FINGERPRINTS`/`RP_API_KEY`
against a real deployed RP server (per "Prerequisites") to exercise the rest.
