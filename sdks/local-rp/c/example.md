# Worked example: accepting regular (DNS-pinned) LinkKeys logins in C

This document is **not** about the `liblinkkeys_local_rp` library this
directory implements. That library (`include/linkkeys_local_rp.h`,
`src/*.c`) is for the *DNS-less local RP* mode
(`dns-less-local-rp-design.md` at the repo root) — apps with no public DNS,
identified by a locally-generated key fingerprint instead of a domain.

This document is for the far more common case: a C app that has (or is
willing to run) its own domain, and wants to accept logins from any LinkKeys
identity — "Sign in with LinkKeys" for `alice@example.com`. That's **regular
RP mode**. There is no packaged C SDK for it (see "Why there's no packaged
client" below); this document shows you the glue you write yourself, reusing
the pieces of this local-RP SDK that are already public and reusable, and
hand-writing the small amount of CBOR/CSIL-RPC code the SDK can't export
because it's internal plumbing scoped to the local-RP flow.

Everything below was compiled with `gcc -std=c11 -Wall -Wextra` against this
SDK's built `liblinkkeys_local_rp.a`, and the non-network parts were run
(including under ASan/UBSan) — see "What was compiled and run" at the end.

## Architecture

Per `docs/DEPLOYING-RP.md`: your app runs alongside its **own** LinkKeys
server deployed in RP mode (the same Docker image/binary as a full identity
provider, different configuration — `ENABLE_RP_ENDPOINTS`/`rp.enabled` Helm
values). The RP server holds your domain's private keys, signs auth
requests, and decrypts callback tokens on your behalf. **Your app never
touches private keys** — it authenticates to its own RP server with a plain
API key over TCP CSIL-RPC and asks it to do the crypto.

```
+------------------------------------------------------------+
|                   Your Application Stack                    |
|                                                              |
|   +--------------+  TCP CSIL-RPC   +----------------------+ |
|   |    C App     |  (API-key auth, |  LinkKeys RP Server  | |
|   |              |  TLS pinned to  |  (same linkkeys      | |
|   |  This doc's  |--DNS `fp=`----->|   image, RP config)  | |
|   |  glue code   |                 |  Holds domain keys   | |
|   +------+-------+                 +-----------+----------+ |
|          | HTTP redirect                       | TCP CSIL-RPC
+----------+-------------------------------------+-------------+
           v                                     v
     user's browser                    the *user's* LinkKeys domain
   (goes to their IDP's                (verify-assertion / userinfo-fetch
    /auth/authorize)                    make an onward S2S call here)
```

## Prerequisites

1. **Deploy your RP server.** Follow `docs/DEPLOYING-RP.md` end to end
   (Helm chart with `rp.enabled: true`, `linkkeys domain init` inside the
   pod, and publish the `_linkkeys`/`_linkkeys_apis` DNS TXT records it
   prints via `linkkeys domain dns-check`). You need a real domain you
   control — this is what makes it "regular" (DNS-pinned) RP mode as
   opposed to this directory's local-RP mode.

2. **Create a service account (API key) for your app and grant it
   `api_access`.** This is not optional: every `Rp` CSIL-RPC operation
   (`sign-request`, `decrypt-token`, `verify-assertion`, `userinfo-fetch`,
   `issue-attestation`) requires the caller's key to hold the dedicated
   `api_access` relation on the RP's domain (SEC-06,
   `crates/linkkeys/src/services/authorization.rs:102`, gated in
   `crates/linkkeys/src/tcp/mod.rs` around line 797). A bare valid API key
   is **not** enough — you'll get a `server error (4): ...` response until
   it's granted, and nothing provisions it automatically.

   One command does both (mint the key and grant the relation together):

   ```sh
   kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- \
     linkkeys user create my-webapp "My Web Application" --api-key --relation api_access
   # Save the printed API key -- it is shown exactly once.
   ```

   If you already minted a key without `--relation` (as `DEPLOYING-RP.md`'s
   own example does) or need to repair an under-provisioned key, grant it
   separately:

   ```sh
   kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- \
     linkkeys relation grant-local my-webapp api_access
   ```

   This repo's own cluster wrappers do the same two things:
   `./deploy/live.sh api-key <user> <relation...>` (mint + grant) and
   `./deploy/live.sh grant <user> <relation>` (grant to an existing user).

   `api_access` is one of five relations `user create --relation` /
   `relation grant-local` validate against (`GRANTABLE_RELATIONS` in
   `services/authorization.rs`): `admin`, `manage_users`, `manage_claims`,
   `api_access`, `issue_claims`. Grant only `api_access` — least privilege
   for a pure RP delegate.

3. **Know your RP server's TCP address and pinned fingerprints.** Your app
   pins its TLS connection to the RP server the same way any LinkKeys peer
   pins a domain: to the SHA-256 fingerprints in that domain's `_linkkeys`
   DNS TXT record (`linkkeys domain dns-check` on the RP prints the exact
   value to publish, and you can read it back the same way). Configure your
   app with:
   - `RP_TCP_ADDR` — `host:port` for the RP server's CSIL-RPC listener
     (default TCP port is `4987`, `liblinkkeys::dns::DEFAULT_TCP_PORT`).
   - `RP_FINGERPRINTS` — comma-separated fingerprint set, pinned to the RP's
     own `_linkkeys` record.
   - `RP_API_KEY` — the key from step 2.

   These three env var names match the reference Rust integration
   (`demoappsite/src/main.rs`'s `RpConfig`) — reuse them verbatim if you're
   deploying alongside this repo's Helm chart, or rename to taste.

## The login flow

Six steps, all but the browser redirect happening over **TCP CSIL-RPC
only** to your own RP server (**not** the user's IDP — your RP server makes
any onward server-to-server calls to the IDP on your behalf). The old
`POST /v1alpha/*.json` HTTP routes were removed when S2S moved to TCP, and
the generic HTTP RPC carrier cannot complete this flow (`verify-assertion`
and `userinfo-fetch` need the outbound S2S context only the TCP carrier
has) — see "The deprecated HTTP path" below.

1. **`Rp/sign-request`** `{callback_url, nonce, ?requested_claims}` ->
   `{signed_request}`. Your app picks a fresh single-use `nonce` and its own
   callback URL; the RP server signs an auth request with your domain key.
   This example omits `requested_claims` to fall back to the RP server's
   own `RP_CLAIMS_CONFIG`-configured defaults.
2. **Redirect the browser** to
   `https://<user_domain>/auth/authorize?signed_request=<signed_request>`
   (optionally `&user_hint=<hint>`). `user_domain` is whatever LinkKeys
   domain the *user* chose to log in with (e.g. from an
   `alice@example.com`-shaped identity string) — this is **not** your RP's
   own domain. The IDP's `GET /auth/authorize` route only reads
   `signed_request` and `user_hint`
   (`crates/linkkeys/src/web/mod.rs:1418`); no other query parameters
   matter.
3. The user authenticates and consents at their IDP, which redirects back
   to your `callback_url` with `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** `{encrypted_token}` -> `{signed_assertion}`. Only
   your RP server (holder of your domain's private key) can decrypt this.
5. **`Rp/verify-assertion`** `{signed_assertion, expected_domain}` ->
   `{assertion, verified}`. Your RP server checks the assertion's signature
   against the *issuing* domain's published keys. **Check `verified` — a
   0 return code only means the call round-tripped, not that the assertion
   is trustworthy.** Reject unless `verified == true`. Nonce single-use is
   your app's job (see below) — this call does not enforce it.
6. **Optional: `Rp/userinfo-fetch`** `{token, api_base, domain}` ->
   `UserInfo{user_id, domain, display_name, claims}`. Fetches the user's
   consented claims. Skip it if you only need proof of identity (no
   claims).

## API-key envelope auth (the raw-key trap)

All five `Rp` operations are authenticated the same way: the API key rides
the CSIL-RPC envelope's `auth` field, not an application-level parameter.
Server-side, `crates/linkkeys/src/tcp/mod.rs`'s `authenticate_tcp_request`
reads exactly `envelope.auth` (an `Option<String>`).

**The trap:** the envelope's `auth` field carries the **raw API key** —
`"sk_live_abc123..."`, no `"Bearer "` prefix. That HTTP convention belongs
to the remaining browser-facing HTTP surfaces, not the CSIL-RPC envelope.
`rc_encode_rpc_request` below writes `auth` as a plain CBOR text string of
exactly the key the caller passed in — do not prepend `"Bearer "` to
`cfg->api_key` before calling it.

## Why there's no packaged client — and what this example reuses vs. inlines

`sdks/local-rp/c/src/rpc.h`'s own top-of-file comment explains why this SDK
hand-writes CSIL-RPC calls instead of using a generated codec: **no csilgen
`c` target exists at all** (a request for one has been filed — see
`~/repos/catalystcommunity/csilgen/docs/csilgen-requests/`). That's a
stronger gap than the Go SDK example hits (Go at least has a generated,
if mis-cased, client to work around); for C there is nothing generated to
reuse. This example is therefore split cleanly into what's genuinely
public/reusable from `include/linkkeys_local_rp.h` and what it must
hand-write:

**Reused as-is, unmodified, from `include/linkkeys_local_rp.h` (this SDK's
only public header):**

- **`lrp_default_transport(LRP_ADDRESS_PERMISSIVE)`** — the plain blocking
  TCP dialer (`src/transport.c`), including its connect/IO timeouts and
  `LRP_ADDRESS_PUBLIC_ONLY` opt-in. This example never reimplements socket
  dialing.
- **`lrp_error`/`lrp_error_code`/`lrp_error_code_name`** — this example's
  own error-reporting shape reuses the SDK's public error type end to end
  (see `lrp_fail_ext` below) rather than inventing a parallel one.
- **`lrp_bytes`/`lrp_str`** and their `_free` functions — ordinary buffer
  ownership, reused for every borrowed/owned byte and string this example
  produces.
- **`lrp_bytes_to_hex`** — reused twice: once to hex-encode a fresh login
  nonce (`rrp_new_nonce`), and once to compute a peer certificate's pinned
  fingerprint (`rc_cert_fingerprint_hex`) after this example does its own
  `EVP_Digest(..., EVP_sha256(), ...)`. Neither hand-rolls hex encoding.
- **`lrp_dns_resolver`/`lrp_default_dns_resolver`/`lrp_txt_records`** — the
  DNS TXT lookup seam, reused by `rrp_resolve_api_base` to find the issuing
  domain's `_linkkeys_apis` `https=` field (needed for `userinfo-fetch`).
  Because it's an injectable seam (a struct of function pointers, not a
  hard-coded resolver call), `test_roundtrip.c` exercises it with a fake
  resolver and no real network — see "What was compiled and run".
- **`LRP_FINGERPRINT_HEX_LEN`** — the fingerprint hex-string length
  constant, reused for buffer sizing instead of a second magic number.

**Necessarily hand-written (nothing to reuse — these live in internal
headers `src/cbor.h`, `src/rpc.h`, `src/types.h` that
`include/linkkeys_local_rp.h` deliberately does not expose, per this SDK's
own README: "Only `include/linkkeys_local_rp.h` is the public surface"):**

- **CBOR writer + generic decoder** (`regularrp_internal.h`'s `rc_*`
  functions) — modeled on `src/cbor.c`'s shape (a growable-buffer writer,
  a value-tree decoder, the same `RFC 8949` canonical-map key ordering) but
  a fresh, much smaller implementation: no bignum, indefinite-length, or
  float support, and no negative-integer decoding, because nothing this
  example's five `Rp` types needs requires them.
- **CSIL-RPC v1 envelope encode/decode** (`rc_encode_rpc_request`,
  `rc_decode_rpc_response`) — the `{v, service, op, payload, ?auth}`
  canonical map and 4-byte-big-endian frame length prefix, matching
  `csil-rpc-transport.md` / `crates/csilgen-transport/src/{rpc,conventions,carrier}.rs`,
  the same wire format `src/rpc.c`'s (internal, unexported)
  `encode_rpc_request`/`decode_rpc_response` implement.
- **TLS pin-and-connect** (`rc_tls_connect_pinned` + its `BIO_meth_new`
  adapter bridging `lrp_conn` to OpenSSL) — mirrors `src/rpc.c`'s
  `tls_connect_pinned`/BIO adapter byte-for-byte in approach
  (`SSL_VERIFY_NONE` plus a *mandatory* manual
  `SSL_get1_peer_certificate` -> `X509_get0_pubkey` ->
  `EVP_PKEY_get_raw_public_key` -> sha256 -> pinned-fingerprint-set
  membership check), rebuilt fresh because `src/rpc.h` is internal. One
  deliberate simplification: this example builds a fresh `BIO_METHOD` per
  connection rather than the SDK's `pthread_once`-cached global — simpler
  to read, and correct at the call frequency of a login flow (a handful of
  RPCs per login, not a hot loop).
- **Rp-service type encode/decode** (`rc_encode_rp_sign_request`,
  `rc_decode_rp_verify_response`, `rc_decode_user_info`, etc.) — hand-written
  directly from `csil/linkkeys.csil`'s `RpSignRequest`/`RpSignResponse`/
  `RpDecryptRequest`/`RpDecryptResponse`/`RpVerifyRequest`/`RpVerifyResponse`/
  `IdentityAssertion`/`RpUserInfoRequest`/`UserInfo`/`Claim`/`ClaimSignature`
  definitions, the same way `src/types.c` hand-writes the local-RP flow's
  types — except `types.c` only covers *that* flow (`LocalRpDescriptor`,
  `LocalRpLoginRequest`, ticket redemption, ...), never the `Rp` service, so
  none of it is reusable here either.

## The code

### Layout

```
regularrp.h            public surface: rrp_config, rrp_pending_login,
                        rrp_identity, rrp_begin_login, rrp_handle_callback,
                        rrp_resolve_api_base
regularrp_internal.h    CBOR writer/decoder, CSIL-RPC envelope, Rp type
                        encode/decode -- internal, but exposed via a header
                        (not kept `static`) the same way sdks/local-rp/c's
                        own src/*.h internals are reachable from its tests
                        via -Isrc
regularrp.c             implementation of both headers above
test_roundtrip.c        CBOR/envelope/DNS-seam round-trip tests, no network
Makefile                builds regularrp.o and the round-trip test binary
                        against this SDK's built liblinkkeys_local_rp.a
```

A real app only ever `#include "regularrp.h"` — `regularrp_internal.h` is
this example's own internal header, included only from `regularrp.c` and
`test_roundtrip.c`, mirroring exactly the public/internal split
`include/linkkeys_local_rp.h` vs. `src/*.h` draws for this SDK itself.

### `regularrp.h` — the public surface

```c
/* regularrp.h -- worked example: accepting REGULAR (DNS-pinned) LinkKeys
 * logins from a C app, via the app's own LinkKeys RP server (docs/DEPLOYING-RP.md).
 * This is NOT the local-RP mode sdks/local-rp/c implements -- see example.md's
 * "Local-RP vs regular-RP" section. Public surface of this tiny example
 * library; regularrp_internal.h holds the CBOR/RPC/TLS plumbing, exactly the
 * public/internal split sdks/local-rp/c itself uses.
 */
#ifndef REGULARRP_H
#define REGULARRP_H

#include <stddef.h>

#include <linkkeys_local_rp.h> /* lrp_error, lrp_bytes, lrp_str, lrp_transport */

#ifdef __cplusplus
extern "C" {
#endif

/* Connection facts for this app's own RP server: a TCP CSIL-RPC address, the
 * RP server's DNS-pinned TLS fingerprints (from its `_linkkeys` fp= set),
 * and the api_access-relation API key minted for this app (example.md's
 * "Prerequisites"). All fields borrowed for the duration of a call -- this
 * struct owns nothing. */
typedef struct rrp_config {
    const char *tcp_addr;             /* "host:port", default port 4987 */
    const char *const *fingerprints;
    size_t fingerprints_count;
    const char *api_key;              /* raw key; rides the envelope `auth`
                                        * field -- no "Bearer " prefix */
} rrp_config;

/* State to persist between rrp_begin_login and rrp_handle_callback (e.g. in
 * a server-side session tied to the browser). Single-use: this library owns
 * no storage and cannot enforce that itself -- discard it after one
 * completion attempt, same rule as the local-RP SDK's lrp_pending_login. */
typedef struct rrp_pending_login {
    char *nonce;       /* owned, NUL-terminated */
    char *user_domain; /* owned, NUL-terminated */
} rrp_pending_login;

void rrp_pending_login_free(rrp_pending_login *p);

/* One claim the user released, narrowed to what a typical app session needs
 * (claim_type/value plus the distinct domains that signed it -- the
 * trust-relevant attribution), mirroring demoappsite/src/main.rs's
 * SessionClaim rather than exposing the full wire Claim/ClaimSignature
 * shape. claim_value is opaque protocol bytes; UTF-8 for this example's text
 * claims. */
typedef struct rrp_claim {
    char *claim_type;
    lrp_bytes claim_value;
    char **signing_domains;
    size_t signing_domains_count;
} rrp_claim;

typedef struct rrp_identity {
    char *user_id;
    char *domain;
    char *display_name; /* NULL if absent */
    rrp_claim *claims;   /* NULL/0 if userinfo was not fetched */
    size_t claims_count;
} rrp_identity;

void rrp_identity_free(rrp_identity *v);

/* Steps 1-2 of the login flow (example.md): sign an auth request via this
 * app's RP server (Rp/sign-request) and build the browser-redirect URL to
 * the user's chosen LinkKeys domain. `user_domain` is whatever domain the
 * USER picked (e.g. parsed out of an "alice@example.com"-shaped identity
 * string) -- it is NOT this app's own domain. `user_hint` may be NULL.
 *
 * On success (0): *out_redirect_url is a malloc'd NUL-terminated URL (free()
 * it) and *out_pending is populated for the caller to persist and pass
 * unchanged to rrp_handle_callback. On failure (-1): both are left zeroed
 * and *err (if non-NULL) explains why. */
int rrp_begin_login(const rrp_config *cfg, const char *user_domain, const char *user_hint,
                     const char *callback_url, char **out_redirect_url,
                     rrp_pending_login *out_pending, lrp_error *err);

/* Steps 3-6: decrypt the callback's encrypted_token (Rp/decrypt-token),
 * verify the assertion against the issuing domain's published keys
 * (Rp/verify-assertion), and enforce nonce/domain equality against
 * `pending`. If `fetch_userinfo` is non-zero, also calls Rp/userinfo-fetch
 * (needs `api_base`, the issuing domain's browser-facing HTTPS API base --
 * see example.md's resolve_api_base) to populate out->claims.
 *
 * Nonce SINGLE-USE enforcement (rejecting a replayed encrypted_token) is the
 * caller's job -- this call only checks the nonce MATCHES `pending`, not
 * that it hasn't been redeemed before. See example.md's "App
 * responsibilities". */
int rrp_handle_callback(const rrp_config *cfg, const rrp_pending_login *pending,
                         const char *encrypted_token, int fetch_userinfo, const char *api_base,
                         rrp_identity *out, lrp_error *err);

/* Resolves `domain`'s `_linkkeys_apis` DNS TXT record for its published
 * `https=` API base (the value rrp_handle_callback's `api_base` parameter
 * needs), falling back to "https://<domain>" if the record or field is
 * absent/unreachable -- same DNS name and field the local-RP SDK's own
 * sdks/local-rp/c/src/dns.c parses for a different purpose, and the same
 * fallback demoappsite/src/main.rs's resolve_api_base uses. Takes an
 * explicit `lrp_dns_resolver` (the public header's exported seam, e.g.
 * a `lrp_default_dns_resolver()`) rather than hard-coding one, so tests can
 * inject a fake without a network -- see example.md's test_roundtrip.c.
 * Returns a malloc'd NUL-terminated string (free() it); NULL only on
 * allocation failure. */
char *rrp_resolve_api_base(lrp_dns_resolver *dns, const char *domain);

#ifdef __cplusplus
}
#endif

#endif /* REGULARRP_H */
```

### `regularrp_internal.h` — CBOR/envelope/Rp-type plumbing

```c
/* regularrp_internal.h -- CBOR writer/decoder, the CSIL-RPC v1 envelope, and
 * the Rp-service type encode/decode this example hand-writes because no
 * generated C codec exists for the CSIL (sdks/local-rp/c/src/rpc.h's own
 * top-of-file comment: "No csilgen `c` target exists ... a request for one
 * has been filed"). Modeled on sdks/local-rp/c/src/cbor.{h,c}'s shape and
 * conventions -- NOT a copy: cbor.h is an internal SDK header, not part of
 * include/linkkeys_local_rp.h's public surface, so an external app cannot
 * `#include "cbor.h"` from the SDK; this is a fresh, much smaller
 * implementation scoped to exactly the five Rp types below (no bignum,
 * indefinite-length, or float support -- CSIL never needs them here).
 *
 * Exposed via a header (rather than kept static in regularrp.c) the same
 * way sdks/local-rp/c's own internal src headers are reachable from its
 * tests via -Isrc: test_roundtrip.c includes this directly to exercise
 * CBOR/envelope round trips without a network. A real app only needs
 * regularrp.h.
 */
#ifndef REGULARRP_INTERNAL_H
#define REGULARRP_INTERNAL_H

#include <stdint.h>

#include "regularrp.h"

/* This example has no error.c of its own (that's internal to the SDK too),
 * so it reimplements the SDK's tiny printf-into-lrp_error helper
 * (sdks/local-rp/c/src/error.h's lrp_fail) under a distinct name to avoid
 * any symbol collision if ever linked alongside sdks/local-rp/c object
 * files in the same program. Always returns -1, so call sites can
 * `return lrp_fail_ext(err, CODE, "...");`. */
int lrp_fail_ext(lrp_error *err, lrp_error_code code, const char *fmt, ...);

/* --------------------------------------------------------------------- */
/* Minimal CBOR writer (growable buffer)                                 */
/* --------------------------------------------------------------------- */

typedef struct rc_buf {
    uint8_t *data;
    size_t len;
    size_t cap;
} rc_buf;

void rc_buf_init(rc_buf *b);
void rc_buf_free(rc_buf *b);
lrp_bytes rc_buf_release(rc_buf *b);

/* Appends raw already-encoded bytes verbatim. Exposed (like
 * sdks/local-rp/c/src/cbor.h's own cbor_write_raw) so test_roundtrip.c can
 * hand-assemble array items -- this example's writer otherwise never emits
 * an array (see rc_write_array_header's doc comment). */
int rc_write_raw(rc_buf *b, const uint8_t *data, size_t len);
int rc_write_uint(rc_buf *b, uint64_t v);
int rc_write_text_cstr(rc_buf *b, const char *s);
int rc_write_bytes(rc_buf *b, const uint8_t *data, size_t len);
int rc_write_bool(rc_buf *b, int v);
int rc_write_tag24(rc_buf *b, const uint8_t *payload, size_t len);
/* No Rp request this example encodes has an array-valued field, so
 * regularrp.c itself never calls this -- it exists for test_roundtrip.c to
 * hand-build the `claims`/`signatures` arrays UserInfo decoding is tested
 * against. */
int rc_write_array_header(rc_buf *b, size_t n);

/* One entry for rc_write_canon_map: `key` plus the ALREADY-ENCODED CBOR
 * bytes of the value. */
typedef struct rc_map_entry {
    const char *key;
    const uint8_t *value_data;
    size_t value_len;
} rc_map_entry;

/* Writes a definite-length map with entries sorted by the bytewise order of
 * their encoded keys (RFC 8949 core deterministic encoding) -- the
 * CSIL-RPC envelope's required canonical form. */
int rc_write_canon_map(rc_buf *out, rc_map_entry *entries, size_t n);

/* --------------------------------------------------------------------- */
/* Minimal CBOR decoder (generic value tree)                             */
/* --------------------------------------------------------------------- */

typedef enum rc_type {
    RC_T_UINT,
    RC_T_BYTES,
    RC_T_TEXT,
    RC_T_ARRAY,
    RC_T_MAP,
    RC_T_BOOL,
    RC_T_NULL,
    RC_T_TAG,
} rc_type;

typedef struct rc_value rc_value;
struct rc_value {
    rc_type type;
    uint64_t uint_val;
    uint8_t *bytes; /* BYTES/TEXT; NUL-terminated when TEXT */
    size_t bytes_len;
    rc_value *items; /* ARRAY */
    size_t items_len;
    rc_value *map_keys; /* MAP, parallel to map_vals */
    rc_value *map_vals;
    size_t map_len;
    int bool_val;
    uint64_t tag;
    rc_value *tag_inner; /* TAG */
};

int rc_decode(const uint8_t *data, size_t len, rc_value **out, lrp_error *err);
void rc_value_free(rc_value *v);

const rc_value *rc_map_get(const rc_value *map, const char *key);
int rc_as_text(const rc_value *v, lrp_str *out, lrp_error *err);
int rc_as_bytes(const rc_value *v, lrp_bytes *out, lrp_error *err);

int rc_get_text(const rc_value *map, const char *key, lrp_str *out, lrp_error *err);
int rc_get_bytes(const rc_value *map, const char *key, lrp_bytes *out, lrp_error *err);
int rc_get_uint(const rc_value *map, const char *key, uint64_t *out, lrp_error *err);
int rc_get_array(const rc_value *map, const char *key, const rc_value **out, lrp_error *err);
/* Optional-field accessors: leave *out unset and return without failing
 * when the key is absent or the wrong type. */
void rc_get_text_opt(const rc_value *map, const char *key, lrp_str *out);
void rc_get_bool_opt(const rc_value *map, const char *key, int *present, int *value);

/* --------------------------------------------------------------------- */
/* CSIL-RPC v1 envelope (csil-rpc-transport.md)                          */
/* --------------------------------------------------------------------- */

/* Mirrors sdks/local-rp/c/src/rpc.h's own cap so a malicious/compromised RP
 * server can't drive this client to an unbounded allocation via a forged
 * length prefix. */
#define RC_MAX_RPC_FRAME_SIZE (1024 * 1024)

/* `auth` may be NULL -- omitted from the envelope entirely (not sent as
 * CBOR null) when the op needs no API key. */
int rc_encode_rpc_request(const char *service, const char *op, const char *auth,
                           const uint8_t *payload, size_t payload_len, lrp_bytes *out,
                           lrp_error *err);

typedef struct rc_rpc_response {
    int64_t status;
    lrp_str variant;
    lrp_str error_msg;
    lrp_bytes payload;
} rc_rpc_response;
void rc_rpc_response_free(rc_rpc_response *r);
int rc_decode_rpc_response(const uint8_t *data, size_t len, rc_rpc_response *out, lrp_error *err);

/* One CSIL-RPC call over a fresh TLS connection pinned to `fingerprints`:
 * dial -> TLS-connect-and-pin -> send request frame -> read response frame
 * -> decode. Returns the decoded response's payload bytes on transport
 * status 0 (Ok); a non-zero status becomes LRP_ERR_SERVER. */
int rc_rpc_call(lrp_transport *transport, const char *tcp_addr, const char *const *fingerprints,
                 size_t fingerprints_count, const char *service, const char *op, const char *auth,
                 const uint8_t *payload, size_t payload_len, lrp_bytes *out_payload,
                 lrp_error *err);

/* --------------------------------------------------------------------- */
/* Rp-service type encode/decode (csil/linkkeys.csil's Rp section)       */
/* --------------------------------------------------------------------- */

int rc_encode_rp_sign_request(const char *callback_url, const char *nonce, lrp_bytes *out,
                               lrp_error *err);
int rc_decode_rp_sign_response(const uint8_t *data, size_t len, lrp_str *out_signed_request,
                                lrp_error *err);

int rc_encode_rp_decrypt_request(const char *encrypted_token, lrp_bytes *out, lrp_error *err);
int rc_decode_rp_decrypt_response(const uint8_t *data, size_t len, lrp_str *out_signed_assertion,
                                   lrp_error *err);

int rc_encode_rp_verify_request(const char *signed_assertion, const char *expected_domain,
                                 lrp_bytes *out, lrp_error *err);

typedef struct rc_identity_assertion {
    lrp_str user_id;
    lrp_str domain;
    lrp_str audience;
    lrp_str nonce;
    lrp_str issued_at;
    lrp_str expires_at;
    lrp_str display_name; /* .data == NULL if absent */
} rc_identity_assertion;
void rc_identity_assertion_free(rc_identity_assertion *a);

typedef struct rc_rp_verify_response {
    rc_identity_assertion assertion;
    int verified;
} rc_rp_verify_response;
void rc_rp_verify_response_free(rc_rp_verify_response *v);
int rc_decode_rp_verify_response(const uint8_t *data, size_t len, rc_rp_verify_response *out,
                                  lrp_error *err);

int rc_encode_rp_userinfo_request(const char *token, const char *api_base, const char *domain,
                                   lrp_bytes *out, lrp_error *err);
/* Decodes straight into rrp_identity (regularrp.h's public claim shape) --
 * this example never needs a standalone UserInfo/Claim/ClaimSignature
 * struct beyond that, so it narrows during decode (see regularrp.c's
 * rc_claim_signing_domains) rather than building and then converting a
 * fuller wire type. */
int rc_decode_user_info(const uint8_t *data, size_t len, rrp_identity *out, lrp_error *err);

#endif /* REGULARRP_INTERNAL_H */
```

### `regularrp.c` — the implementation

```c
/* regularrp.c -- see regularrp.h and example.md. */
#include "regularrp_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp */

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* --------------------------------------------------------------------- */
/* Minimal CBOR writer                                                   */
/* --------------------------------------------------------------------- */

void rc_buf_init(rc_buf *b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void rc_buf_free(rc_buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

lrp_bytes rc_buf_release(rc_buf *b) {
    lrp_bytes out;
    out.data = b->data;
    out.len = b->len;
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    return out;
}

static int rc_buf_reserve(rc_buf *b, size_t extra) {
    if (b->len + extra <= b->cap) return 0;
    size_t new_cap = b->cap == 0 ? 64 : b->cap * 2;
    while (new_cap < b->len + extra) new_cap *= 2;
    uint8_t *n = (uint8_t *)realloc(b->data, new_cap);
    if (n == NULL) return -1;
    b->data = n;
    b->cap = new_cap;
    return 0;
}

int rc_write_raw(rc_buf *b, const uint8_t *data, size_t len) {
    if (rc_buf_reserve(b, len) != 0) return -1;
    if (len > 0) memcpy(b->data + b->len, data, len);
    b->len += len;
    return 0;
}

static int rc_write_head(rc_buf *b, uint8_t major, uint64_t n) {
    uint8_t m = (uint8_t)(major << 5);
    if (n < 24) {
        uint8_t byte = (uint8_t)(m | (uint8_t)n);
        return rc_write_raw(b, &byte, 1);
    } else if (n <= 0xffULL) {
        uint8_t tmp[2] = {(uint8_t)(m | 24), (uint8_t)n};
        return rc_write_raw(b, tmp, 2);
    } else if (n <= 0xffffULL) {
        uint8_t tmp[3] = {(uint8_t)(m | 25), (uint8_t)(n >> 8), (uint8_t)n};
        return rc_write_raw(b, tmp, 3);
    } else if (n <= 0xffffffffULL) {
        uint8_t tmp[5];
        tmp[0] = (uint8_t)(m | 26);
        tmp[1] = (uint8_t)(n >> 24);
        tmp[2] = (uint8_t)(n >> 16);
        tmp[3] = (uint8_t)(n >> 8);
        tmp[4] = (uint8_t)n;
        return rc_write_raw(b, tmp, 5);
    }
    uint8_t tmp[9];
    tmp[0] = (uint8_t)(m | 27);
    for (int i = 0; i < 8; i++) tmp[1 + i] = (uint8_t)(n >> (56 - 8 * i));
    return rc_write_raw(b, tmp, 9);
}

int rc_write_uint(rc_buf *b, uint64_t v) { return rc_write_head(b, 0, v); }

static int rc_write_text(rc_buf *b, const char *s, size_t len) {
    if (rc_write_head(b, 3, len) != 0) return -1;
    return rc_write_raw(b, (const uint8_t *)s, len);
}

int rc_write_text_cstr(rc_buf *b, const char *s) { return rc_write_text(b, s, strlen(s)); }

int rc_write_bytes(rc_buf *b, const uint8_t *data, size_t len) {
    if (rc_write_head(b, 2, len) != 0) return -1;
    return rc_write_raw(b, data, len);
}

int rc_write_bool(rc_buf *b, int v) {
    uint8_t byte = v ? 0xf5 : 0xf4;
    return rc_write_raw(b, &byte, 1);
}

/* No Rp request type this example encodes has an array-valued field
 * (ClaimRequest/AuthFlowContext's optional array fields are simply omitted
 * from RpSignRequest -- see rc_encode_rp_sign_request), so regularrp.c
 * itself never calls this; it's exposed for test_roundtrip.c. */
int rc_write_array_header(rc_buf *b, size_t n) { return rc_write_head(b, 4, n); }
static int rc_write_map_header(rc_buf *b, size_t n) { return rc_write_head(b, 5, n); }
static int rc_write_tag_head(rc_buf *b, uint64_t tag) { return rc_write_head(b, 6, tag); }

int rc_write_tag24(rc_buf *b, const uint8_t *payload, size_t len) {
    if (rc_write_tag_head(b, 24) != 0) return -1;
    return rc_write_bytes(b, payload, len);
}

static int rc_compare_encoded_keys(const void *pa, const void *pb) {
    const rc_map_entry *const *a = (const rc_map_entry *const *)pa;
    const rc_map_entry *const *b = (const rc_map_entry *const *)pb;
    rc_buf ka, kb;
    rc_buf_init(&ka);
    rc_buf_init(&kb);
    rc_write_text_cstr(&ka, (*a)->key);
    rc_write_text_cstr(&kb, (*b)->key);
    size_t min_len = ka.len < kb.len ? ka.len : kb.len;
    int cmp = memcmp(ka.data, kb.data, min_len);
    if (cmp == 0) {
        if (ka.len < kb.len) cmp = -1;
        else if (ka.len > kb.len) cmp = 1;
    }
    rc_buf_free(&ka);
    rc_buf_free(&kb);
    return cmp;
}

int rc_write_canon_map(rc_buf *out, rc_map_entry *entries, size_t n) {
    if (n == 0) return rc_write_map_header(out, 0);
    const rc_map_entry **order = (const rc_map_entry **)malloc(n * sizeof(*order));
    if (order == NULL) return -1;
    for (size_t i = 0; i < n; i++) order[i] = &entries[i];
    qsort(order, n, sizeof(*order), rc_compare_encoded_keys);

    int rc = rc_write_map_header(out, n);
    for (size_t i = 0; rc == 0 && i < n; i++) {
        rc = rc_write_text_cstr(out, order[i]->key);
        if (rc == 0) rc = rc_write_raw(out, order[i]->value_data, order[i]->value_len);
    }
    free(order);
    return rc;
}

/* --------------------------------------------------------------------- */
/* Minimal CBOR decoder                                                  */
/* --------------------------------------------------------------------- */

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} rc_cursor;

static int rc_cur_need(rc_cursor *c, size_t n, lrp_error *err) {
    if ((size_t)(c->end - c->p) < n) {
        return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: unexpected end of input");
    }
    return 0;
}

static int rc_read_arg(rc_cursor *c, uint8_t info, uint64_t *out, lrp_error *err) {
    if (info < 24) {
        *out = info;
        return 0;
    }
    switch (info) {
        case 24:
            if (rc_cur_need(c, 1, err) != 0) return -1;
            *out = c->p[0];
            c->p += 1;
            return 0;
        case 25:
            if (rc_cur_need(c, 2, err) != 0) return -1;
            *out = ((uint64_t)c->p[0] << 8) | c->p[1];
            c->p += 2;
            return 0;
        case 26:
            if (rc_cur_need(c, 4, err) != 0) return -1;
            *out = ((uint64_t)c->p[0] << 24) | ((uint64_t)c->p[1] << 16) | ((uint64_t)c->p[2] << 8) |
                   c->p[3];
            c->p += 4;
            return 0;
        case 27: {
            if (rc_cur_need(c, 8, err) != 0) return -1;
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | c->p[i];
            c->p += 8;
            *out = v;
            return 0;
        }
        default:
            return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: indefinite-length or reserved item unsupported");
    }
}

static int rc_decode_item(rc_cursor *c, rc_value *out, lrp_error *err, int depth);

static void rc_value_zero(rc_value *v) { memset(v, 0, sizeof(*v)); }

static int rc_decode_array_items(rc_cursor *c, size_t n, rc_value **items, lrp_error *err, int depth) {
    if (n == 0) {
        *items = NULL;
        return 0;
    }
    rc_value *arr = (rc_value *)calloc(n, sizeof(rc_value));
    if (arr == NULL) return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
    for (size_t i = 0; i < n; i++) {
        if (rc_decode_item(c, &arr[i], err, depth + 1) != 0) {
            rc_value tmp;
            tmp.type = RC_T_ARRAY;
            tmp.items = arr;
            tmp.items_len = i;
            rc_value_free(&tmp);
            return -1;
        }
    }
    *items = arr;
    return 0;
}

static int rc_decode_item(rc_cursor *c, rc_value *out, lrp_error *err, int depth) {
    if (depth > 64) return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: nesting too deep");
    if (rc_cur_need(c, 1, err) != 0) return -1;
    uint8_t first = c->p[0];
    c->p += 1;
    uint8_t major = (uint8_t)(first >> 5);
    uint8_t info = (uint8_t)(first & 0x1f);
    rc_value_zero(out);

    uint64_t n;
    switch (major) {
        case 0:
            if (rc_read_arg(c, info, &n, err) != 0) return -1;
            out->type = RC_T_UINT;
            out->uint_val = n;
            return 0;
        case 2:
            if (rc_read_arg(c, info, &n, err) != 0) return -1;
            if (rc_cur_need(c, (size_t)n, err) != 0) return -1;
            out->type = RC_T_BYTES;
            out->bytes_len = (size_t)n;
            out->bytes = (uint8_t *)malloc(n > 0 ? (size_t)n : 1);
            if (out->bytes == NULL) return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
            if (n > 0) memcpy(out->bytes, c->p, (size_t)n);
            c->p += n;
            return 0;
        case 3:
            if (rc_read_arg(c, info, &n, err) != 0) return -1;
            if (rc_cur_need(c, (size_t)n, err) != 0) return -1;
            out->type = RC_T_TEXT;
            out->bytes_len = (size_t)n;
            out->bytes = (uint8_t *)malloc((size_t)n + 1);
            if (out->bytes == NULL) return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
            if (n > 0) memcpy(out->bytes, c->p, (size_t)n);
            out->bytes[n] = '\0';
            c->p += n;
            return 0;
        case 4:
            if (rc_read_arg(c, info, &n, err) != 0) return -1;
            out->type = RC_T_ARRAY;
            out->items_len = (size_t)n;
            return rc_decode_array_items(c, (size_t)n, &out->items, err, depth);
        case 5: {
            if (rc_read_arg(c, info, &n, err) != 0) return -1;
            out->type = RC_T_MAP;
            out->map_len = (size_t)n;
            if (n == 0) return 0;
            out->map_keys = (rc_value *)calloc((size_t)n, sizeof(rc_value));
            out->map_vals = (rc_value *)calloc((size_t)n, sizeof(rc_value));
            if (out->map_keys == NULL || out->map_vals == NULL) {
                return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
            }
            for (size_t i = 0; i < n; i++) {
                if (rc_decode_item(c, &out->map_keys[i], err, depth + 1) != 0) {
                    out->map_len = i;
                    rc_value_free(out);
                    rc_value_zero(out);
                    return -1;
                }
                if (rc_decode_item(c, &out->map_vals[i], err, depth + 1) != 0) {
                    rc_value_free(&out->map_keys[i]);
                    out->map_len = i;
                    rc_value_free(out);
                    rc_value_zero(out);
                    return -1;
                }
            }
            return 0;
        }
        case 6: {
            if (rc_read_arg(c, info, &n, err) != 0) return -1;
            out->type = RC_T_TAG;
            out->tag = n;
            out->tag_inner = (rc_value *)calloc(1, sizeof(rc_value));
            if (out->tag_inner == NULL) return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
            if (rc_decode_item(c, out->tag_inner, err, depth + 1) != 0) {
                free(out->tag_inner);
                out->tag_inner = NULL;
                return -1;
            }
            return 0;
        }
        case 7:
            switch (info) {
                case 20:
                    out->type = RC_T_BOOL;
                    out->bool_val = 0;
                    return 0;
                case 21:
                    out->type = RC_T_BOOL;
                    out->bool_val = 1;
                    return 0;
                case 22:
                case 23:
                    out->type = RC_T_NULL;
                    return 0;
                default:
                    return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: unsupported simple value (info=%u)", info);
            }
        default:
            return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: negative integers unsupported by this example");
    }
}

int rc_decode(const uint8_t *data, size_t len, rc_value **out, lrp_error *err) {
    rc_cursor c = {data, data + len};
    rc_value *root = (rc_value *)calloc(1, sizeof(rc_value));
    if (root == NULL) return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
    if (rc_decode_item(&c, root, err, 0) != 0) {
        free(root);
        return -1;
    }
    if (c.p != c.end) {
        rc_value_free(root);
        free(root);
        return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: trailing bytes after item");
    }
    *out = root;
    return 0;
}

void rc_value_free(rc_value *v) {
    if (v == NULL) return;
    switch (v->type) {
        case RC_T_BYTES:
        case RC_T_TEXT:
            free(v->bytes);
            v->bytes = NULL;
            break;
        case RC_T_ARRAY:
            for (size_t i = 0; i < v->items_len; i++) rc_value_free(&v->items[i]);
            free(v->items);
            v->items = NULL;
            break;
        case RC_T_MAP:
            for (size_t i = 0; i < v->map_len; i++) {
                rc_value_free(&v->map_keys[i]);
                rc_value_free(&v->map_vals[i]);
            }
            free(v->map_keys);
            free(v->map_vals);
            v->map_keys = NULL;
            v->map_vals = NULL;
            break;
        case RC_T_TAG:
            rc_value_free(v->tag_inner);
            free(v->tag_inner);
            v->tag_inner = NULL;
            break;
        default:
            break;
    }
}

const rc_value *rc_map_get(const rc_value *map, const char *key) {
    if (map == NULL || map->type != RC_T_MAP) return NULL;
    size_t klen = strlen(key);
    for (size_t i = 0; i < map->map_len; i++) {
        const rc_value *k = &map->map_keys[i];
        if (k->type == RC_T_TEXT && k->bytes_len == klen && memcmp(k->bytes, key, klen) == 0) {
            return &map->map_vals[i];
        }
    }
    return NULL;
}

int rc_as_text(const rc_value *v, lrp_str *out, lrp_error *err) {
    if (v == NULL || v->type != RC_T_TEXT) return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: expected text string");
    out->data = (char *)malloc(v->bytes_len + 1);
    if (out->data == NULL) return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
    memcpy(out->data, v->bytes, v->bytes_len);
    out->data[v->bytes_len] = '\0';
    return 0;
}

int rc_as_bytes(const rc_value *v, lrp_bytes *out, lrp_error *err) {
    if (v == NULL || v->type != RC_T_BYTES) return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: expected byte string");
    if (v->bytes_len == 0) {
        out->data = NULL;
        out->len = 0;
        return 0;
    }
    out->data = (uint8_t *)malloc(v->bytes_len);
    if (out->data == NULL) return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
    memcpy(out->data, v->bytes, v->bytes_len);
    out->len = v->bytes_len;
    return 0;
}

int rc_get_text(const rc_value *map, const char *key, lrp_str *out, lrp_error *err) {
    const rc_value *v = rc_map_get(map, key);
    if (v == NULL) return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: missing required field '%s'", key);
    return rc_as_text(v, out, err);
}

int rc_get_bytes(const rc_value *map, const char *key, lrp_bytes *out, lrp_error *err) {
    const rc_value *v = rc_map_get(map, key);
    if (v == NULL) return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: missing required field '%s'", key);
    return rc_as_bytes(v, out, err);
}

int rc_get_uint(const rc_value *map, const char *key, uint64_t *out, lrp_error *err) {
    const rc_value *v = rc_map_get(map, key);
    if (v == NULL || v->type != RC_T_UINT) {
        return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: missing or non-integer field '%s'", key);
    }
    *out = v->uint_val;
    return 0;
}

int rc_get_array(const rc_value *map, const char *key, const rc_value **out, lrp_error *err) {
    const rc_value *v = rc_map_get(map, key);
    if (v == NULL || v->type != RC_T_ARRAY) {
        return lrp_fail_ext(err, LRP_ERR_DECODE, "CBOR: missing or non-array field '%s'", key);
    }
    *out = v;
    return 0;
}

void rc_get_text_opt(const rc_value *map, const char *key, lrp_str *out) {
    out->data = NULL;
    const rc_value *v = rc_map_get(map, key);
    if (v == NULL || v->type != RC_T_TEXT) return;
    lrp_error tmp = {0};
    (void)rc_as_text(v, out, &tmp);
}

void rc_get_bool_opt(const rc_value *map, const char *key, int *present, int *value) {
    *present = 0;
    const rc_value *v = rc_map_get(map, key);
    if (v == NULL || v->type != RC_T_BOOL) return;
    *present = 1;
    *value = v->bool_val;
}

/* --------------------------------------------------------------------- */
/* lrp_fail_ext -- declared in regularrp_internal.h                      */
/* --------------------------------------------------------------------- */

int lrp_fail_ext(lrp_error *err, lrp_error_code code, const char *fmt, ...) {
    if (err != NULL) {
        err->code = code;
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err->message, sizeof(err->message), fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* --------------------------------------------------------------------- */
/* CSIL-RPC v1 envelope                                                  */
/* --------------------------------------------------------------------- */

int rc_encode_rpc_request(const char *service, const char *op, const char *auth,
                           const uint8_t *payload, size_t payload_len, lrp_bytes *out,
                           lrp_error *err) {
    rc_buf vbuf, sbuf, obuf, pbuf, abuf, outbuf;
    rc_buf_init(&vbuf);
    rc_buf_init(&sbuf);
    rc_buf_init(&obuf);
    rc_buf_init(&pbuf);
    rc_buf_init(&abuf);
    rc_buf_init(&outbuf);
    int rc = 0;
    rc |= rc_write_uint(&vbuf, 1);
    rc |= rc_write_text_cstr(&sbuf, service);
    rc |= rc_write_text_cstr(&obuf, op);
    rc |= rc_write_tag24(&pbuf, payload, payload_len);
    if (auth != NULL) rc |= rc_write_text_cstr(&abuf, auth);

    rc_map_entry entries[5];
    size_t n = 0;
    entries[n++] = (rc_map_entry){"v", vbuf.data, vbuf.len};
    entries[n++] = (rc_map_entry){"service", sbuf.data, sbuf.len};
    entries[n++] = (rc_map_entry){"op", obuf.data, obuf.len};
    entries[n++] = (rc_map_entry){"payload", pbuf.data, pbuf.len};
    if (auth != NULL) entries[n++] = (rc_map_entry){"auth", abuf.data, abuf.len};

    if (rc == 0) rc = rc_write_canon_map(&outbuf, entries, n);
    rc_buf_free(&vbuf);
    rc_buf_free(&sbuf);
    rc_buf_free(&obuf);
    rc_buf_free(&pbuf);
    rc_buf_free(&abuf);
    if (rc != 0) {
        rc_buf_free(&outbuf);
        return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "encode RPC request: out of memory");
    }
    *out = rc_buf_release(&outbuf);
    return 0;
}

void rc_rpc_response_free(rc_rpc_response *r) {
    lrp_str_free(&r->variant);
    lrp_str_free(&r->error_msg);
    lrp_bytes_free(&r->payload);
}

int rc_decode_rpc_response(const uint8_t *data, size_t len, rc_rpc_response *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    rc_value *root = NULL;
    if (rc_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;
    uint64_t v = 0, status = 0;
    if (rc_get_uint(root, "v", &v, err) != 0) goto done;
    if (v != 1) {
        lrp_fail_ext(err, LRP_ERR_PROTOCOL, "unsupported CSIL-RPC transport version %llu",
                     (unsigned long long)v);
        goto done;
    }
    if (rc_get_uint(root, "status", &status, err) != 0) goto done;
    out->status = (int64_t)status;
    rc_get_text_opt(root, "variant", &out->variant);
    rc_get_text_opt(root, "error", &out->error_msg);
    {
        const rc_value *pv = rc_map_get(root, "payload");
        if (pv != NULL && pv->type == RC_T_TAG && pv->tag == 24 && pv->tag_inner != NULL &&
            pv->tag_inner->type == RC_T_BYTES) {
            if (rc_as_bytes(pv->tag_inner, &out->payload, err) != 0) goto done;
        }
    }
    rc = 0;
done:
    rc_value_free(root);
    free(root);
    if (rc != 0) {
        rc_rpc_response_free(out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

/* --------------------------------------------------------------------- */
/* TLS pin extraction + connect (mirrors sdks/local-rp/c/src/rpc.c's       */
/* tls_connect_pinned/BIO adapter, built fresh against only the exported   */
/* lrp_transport/lrp_conn seam and lrp_bytes_to_hex -- see example.md).    */
/* --------------------------------------------------------------------- */

static int rc_bio_write(BIO *b, const char *buf, int len) {
    lrp_conn *conn = (lrp_conn *)BIO_get_data(b);
    long n = conn->write(conn, (const uint8_t *)buf, (size_t)len);
    BIO_clear_retry_flags(b);
    if (n <= 0) {
        BIO_set_retry_write(b);
        return -1;
    }
    return (int)n;
}

static int rc_bio_read(BIO *b, char *buf, int len) {
    lrp_conn *conn = (lrp_conn *)BIO_get_data(b);
    long n = conn->read(conn, (uint8_t *)buf, (size_t)len);
    BIO_clear_retry_flags(b);
    if (n < 0) {
        BIO_set_retry_read(b);
        return -1;
    }
    return (int)n; /* 0 == clean EOF */
}

static long rc_bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
    (void)b;
    (void)num;
    (void)ptr;
    if (cmd == BIO_CTRL_FLUSH) return 1;
    return 0;
}

static int rc_bio_create(BIO *b) {
    BIO_set_init(b, 1);
    return 1;
}

static int rc_bio_destroy(BIO *b) {
    if (b == NULL) return 0;
    BIO_set_data(b, NULL);
    BIO_set_init(b, 0);
    return 1;
}

typedef struct rc_tls_conn {
    BIO_METHOD *bio_method;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    lrp_conn raw;
} rc_tls_conn;

static void rc_tls_close(rc_tls_conn *t) {
    if (t == NULL) return;
    if (t->ssl != NULL) {
        SSL_shutdown(t->ssl);
        SSL_free(t->ssl); /* also frees the attached BIO */
    }
    if (t->ssl_ctx != NULL) SSL_CTX_free(t->ssl_ctx);
    /* This example builds a fresh BIO_METHOD per connection (simpler than
     * the SDK's pthread_once-cached global, and correct at the call
     * frequency of a login flow); free it after the SSL object above,
     * which is the last thing referencing it. */
    if (t->bio_method != NULL) BIO_meth_free(t->bio_method);
    if (t->raw.close != NULL) t->raw.close(&t->raw);
}

static int rc_cert_fingerprint_hex(X509 *cert, char out_fp[LRP_FINGERPRINT_HEX_LEN + 1],
                                    lrp_error *err) {
    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    if (pkey == NULL || EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        return lrp_fail_ext(err, LRP_ERR_TLS, "peer certificate is not an Ed25519 key");
    }
    uint8_t raw[32];
    size_t raw_len = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) != 1 || raw_len != 32) {
        return lrp_fail_ext(err, LRP_ERR_TLS, "failed to extract Ed25519 SPKI bytes");
    }
    uint8_t digest[32];
    unsigned int digest_len = 0;
    if (EVP_Digest(raw, sizeof(raw), digest, &digest_len, EVP_sha256(), NULL) != 1 ||
        digest_len != 32) {
        return lrp_fail_ext(err, LRP_ERR_TLS, "sha256 of peer SPKI failed");
    }
    /* lrp_bytes_to_hex is the SDK's own exported hex helper (public header)
     * -- reused here rather than hand-rolling hex encoding again. */
    lrp_str hex = {0};
    if (lrp_bytes_to_hex(digest, sizeof(digest), &hex, err) != 0) return -1;
    snprintf(out_fp, LRP_FINGERPRINT_HEX_LEN + 1, "%s", hex.data);
    lrp_str_free(&hex);
    return 0;
}

static int rc_tls_connect_pinned(lrp_transport *transport, const char *tcp_addr,
                                  const char *const *fingerprints, size_t fingerprints_count,
                                  rc_tls_conn *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (transport->dial(transport, tcp_addr, &out->raw, err) != 0) return -1;

    out->bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "rrp_conn");
    if (out->bio_method == NULL) {
        lrp_fail_ext(err, LRP_ERR_TLS, "BIO_meth_new failed");
        goto fail;
    }
    BIO_meth_set_write(out->bio_method, rc_bio_write);
    BIO_meth_set_read(out->bio_method, rc_bio_read);
    BIO_meth_set_ctrl(out->bio_method, rc_bio_ctrl);
    BIO_meth_set_create(out->bio_method, rc_bio_create);
    BIO_meth_set_destroy(out->bio_method, rc_bio_destroy);

    out->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (out->ssl_ctx == NULL) {
        lrp_fail_ext(err, LRP_ERR_TLS, "SSL_CTX_new failed");
        goto fail;
    }
    SSL_CTX_set_min_proto_version(out->ssl_ctx, TLS1_2_VERSION);
    /* WebPKI chain validity is NOT the trust anchor here -- the DNS fp= pin
     * checked below is. Matches sdks/local-rp/c/src/rpc.c and
     * crates/linkkeys/src/tcp/tls.rs's server-side posture. */
    SSL_CTX_set_verify(out->ssl_ctx, SSL_VERIFY_NONE, NULL);

    out->ssl = SSL_new(out->ssl_ctx);
    if (out->ssl == NULL) {
        lrp_fail_ext(err, LRP_ERR_TLS, "SSL_new failed");
        goto fail;
    }
    BIO *bio = BIO_new(out->bio_method);
    if (bio == NULL) {
        lrp_fail_ext(err, LRP_ERR_TLS, "BIO_new failed");
        goto fail;
    }
    BIO_set_data(bio, &out->raw);
    SSL_set_bio(out->ssl, bio, bio); /* SSL now owns `bio` */

    if (SSL_connect(out->ssl) != 1) {
        lrp_fail_ext(err, LRP_ERR_TLS, "TLS handshake failed");
        goto fail;
    }

    X509 *cert = SSL_get1_peer_certificate(out->ssl);
    if (cert == NULL) {
        lrp_fail_ext(err, LRP_ERR_TLS, "no peer certificate presented");
        goto fail;
    }
    char fp[LRP_FINGERPRINT_HEX_LEN + 1];
    int frc = rc_cert_fingerprint_hex(cert, fp, err);
    X509_free(cert);
    if (frc != 0) goto fail;

    int matched = 0;
    for (size_t i = 0; i < fingerprints_count; i++) {
        if (strcasecmp(fp, fingerprints[i]) == 0) {
            matched = 1;
            break;
        }
    }
    if (!matched) {
        lrp_fail_ext(err, LRP_ERR_TLS,
                     "certificate fingerprint does not match any pinned RP fingerprint");
        goto fail;
    }
    return 0;

fail:
    rc_tls_close(out);
    memset(out, 0, sizeof(*out));
    return -1;
}

static int rc_ssl_write_all(SSL *ssl, const uint8_t *data, size_t len, lrp_error *err) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, data + off, (int)(len - off));
        if (n <= 0) return lrp_fail_ext(err, LRP_ERR_TRANSPORT, "TLS write failed");
        off += (size_t)n;
    }
    return 0;
}

static int rc_ssl_read_all(SSL *ssl, uint8_t *data, size_t len, lrp_error *err) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_read(ssl, data + off, (int)(len - off));
        if (n <= 0) return lrp_fail_ext(err, LRP_ERR_TRANSPORT, "TLS read failed or connection closed");
        off += (size_t)n;
    }
    return 0;
}

static int rc_send_frame(SSL *ssl, const uint8_t *data, size_t len, lrp_error *err) {
    uint8_t lenbuf[4] = {(uint8_t)(len >> 24), (uint8_t)(len >> 16), (uint8_t)(len >> 8),
                          (uint8_t)len};
    if (rc_ssl_write_all(ssl, lenbuf, 4, err) != 0) return -1;
    if (len == 0) return 0;
    return rc_ssl_write_all(ssl, data, len, err);
}

static int rc_read_frame(SSL *ssl, lrp_bytes *out, lrp_error *err) {
    uint8_t lenbuf[4];
    if (rc_ssl_read_all(ssl, lenbuf, 4, err) != 0) return -1;
    uint32_t len = ((uint32_t)lenbuf[0] << 24) | ((uint32_t)lenbuf[1] << 16) |
                   ((uint32_t)lenbuf[2] << 8) | lenbuf[3];
    if (len > RC_MAX_RPC_FRAME_SIZE) {
        return lrp_fail_ext(err, LRP_ERR_PROTOCOL, "peer frame too large (%u bytes, max %d)", len,
                             RC_MAX_RPC_FRAME_SIZE);
    }
    uint8_t *buf = (uint8_t *)malloc(len > 0 ? len : 1);
    if (buf == NULL) return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    if (len > 0 && rc_ssl_read_all(ssl, buf, len, err) != 0) {
        free(buf);
        return -1;
    }
    out->data = buf;
    out->len = len;
    return 0;
}

int rc_rpc_call(lrp_transport *transport, const char *tcp_addr, const char *const *fingerprints,
                 size_t fingerprints_count, const char *service, const char *op, const char *auth,
                 const uint8_t *payload, size_t payload_len, lrp_bytes *out_payload,
                 lrp_error *err) {
    rc_tls_conn conn;
    if (rc_tls_connect_pinned(transport, tcp_addr, fingerprints, fingerprints_count, &conn, err) !=
        0) {
        return -1;
    }

    lrp_bytes req = {0};
    int rc = rc_encode_rpc_request(service, op, auth, payload, payload_len, &req, err);
    if (rc == 0) rc = rc_send_frame(conn.ssl, req.data, req.len, err);
    lrp_bytes_free(&req);
    if (rc != 0) {
        rc_tls_close(&conn);
        return -1;
    }

    lrp_bytes resp_bytes = {0};
    if (rc_read_frame(conn.ssl, &resp_bytes, err) != 0) {
        rc_tls_close(&conn);
        return -1;
    }
    rc_tls_close(&conn);

    rc_rpc_response resp;
    rc = rc_decode_rpc_response(resp_bytes.data, resp_bytes.len, &resp, err);
    lrp_bytes_free(&resp_bytes);
    if (rc != 0) return -1;

    if (resp.status != 0) {
        if (err != NULL) {
            err->code = LRP_ERR_SERVER;
            snprintf(err->message, sizeof(err->message), "server error (%lld): %s",
                     (long long)resp.status,
                     resp.error_msg.data != NULL ? resp.error_msg.data : "unknown error");
        }
        rc_rpc_response_free(&resp);
        return -1;
    }

    *out_payload = resp.payload;
    resp.payload.data = NULL;
    resp.payload.len = 0;
    rc_rpc_response_free(&resp);
    return 0;
}

/* --------------------------------------------------------------------- */
/* Rp-service type encode/decode                                        */
/* --------------------------------------------------------------------- */

int rc_encode_rp_sign_request(const char *callback_url, const char *nonce, lrp_bytes *out,
                               lrp_error *err) {
    rc_buf cbuf, nbuf, outbuf;
    rc_buf_init(&cbuf);
    rc_buf_init(&nbuf);
    rc_buf_init(&outbuf);
    int rc = 0;
    rc |= rc_write_text_cstr(&cbuf, callback_url);
    rc |= rc_write_text_cstr(&nbuf, nonce);
    rc_map_entry entries[2] = {
        {"callback_url", cbuf.data, cbuf.len},
        {"nonce", nbuf.data, nbuf.len},
    };
    if (rc == 0) rc = rc_write_canon_map(&outbuf, entries, 2);
    rc_buf_free(&cbuf);
    rc_buf_free(&nbuf);
    if (rc != 0) {
        rc_buf_free(&outbuf);
        return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "encode RpSignRequest: out of memory");
    }
    *out = rc_buf_release(&outbuf);
    return 0;
}

int rc_decode_rp_sign_response(const uint8_t *data, size_t len, lrp_str *out_signed_request,
                                lrp_error *err) {
    rc_value *root = NULL;
    if (rc_decode(data, len, &root, err) != 0) return -1;
    int rc = rc_get_text(root, "signed_request", out_signed_request, err);
    rc_value_free(root);
    free(root);
    return rc;
}

int rc_encode_rp_decrypt_request(const char *encrypted_token, lrp_bytes *out, lrp_error *err) {
    rc_buf tbuf, outbuf;
    rc_buf_init(&tbuf);
    rc_buf_init(&outbuf);
    int rc = rc_write_text_cstr(&tbuf, encrypted_token);
    rc_map_entry entries[1] = {{"encrypted_token", tbuf.data, tbuf.len}};
    if (rc == 0) rc = rc_write_canon_map(&outbuf, entries, 1);
    rc_buf_free(&tbuf);
    if (rc != 0) {
        rc_buf_free(&outbuf);
        return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "encode RpDecryptRequest: out of memory");
    }
    *out = rc_buf_release(&outbuf);
    return 0;
}

int rc_decode_rp_decrypt_response(const uint8_t *data, size_t len, lrp_str *out_signed_assertion,
                                   lrp_error *err) {
    rc_value *root = NULL;
    if (rc_decode(data, len, &root, err) != 0) return -1;
    int rc = rc_get_text(root, "signed_assertion", out_signed_assertion, err);
    rc_value_free(root);
    free(root);
    return rc;
}

int rc_encode_rp_verify_request(const char *signed_assertion, const char *expected_domain,
                                 lrp_bytes *out, lrp_error *err) {
    rc_buf sbuf, dbuf, outbuf;
    rc_buf_init(&sbuf);
    rc_buf_init(&dbuf);
    rc_buf_init(&outbuf);
    int rc = 0;
    rc |= rc_write_text_cstr(&sbuf, signed_assertion);
    rc |= rc_write_text_cstr(&dbuf, expected_domain);
    rc_map_entry entries[2] = {
        {"signed_assertion", sbuf.data, sbuf.len},
        {"expected_domain", dbuf.data, dbuf.len},
    };
    if (rc == 0) rc = rc_write_canon_map(&outbuf, entries, 2);
    rc_buf_free(&sbuf);
    rc_buf_free(&dbuf);
    if (rc != 0) {
        rc_buf_free(&outbuf);
        return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "encode RpVerifyRequest: out of memory");
    }
    *out = rc_buf_release(&outbuf);
    return 0;
}

void rc_identity_assertion_free(rc_identity_assertion *a) {
    lrp_str_free(&a->user_id);
    lrp_str_free(&a->domain);
    lrp_str_free(&a->audience);
    lrp_str_free(&a->nonce);
    lrp_str_free(&a->issued_at);
    lrp_str_free(&a->expires_at);
    lrp_str_free(&a->display_name);
}

void rc_rp_verify_response_free(rc_rp_verify_response *v) { rc_identity_assertion_free(&v->assertion); }

static int rc_decode_identity_assertion(const rc_value *map, rc_identity_assertion *out,
                                         lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (rc_get_text(map, "user_id", &out->user_id, err) != 0) goto fail;
    if (rc_get_text(map, "domain", &out->domain, err) != 0) goto fail;
    if (rc_get_text(map, "audience", &out->audience, err) != 0) goto fail;
    if (rc_get_text(map, "nonce", &out->nonce, err) != 0) goto fail;
    if (rc_get_text(map, "issued_at", &out->issued_at, err) != 0) goto fail;
    if (rc_get_text(map, "expires_at", &out->expires_at, err) != 0) goto fail;
    rc_get_text_opt(map, "display_name", &out->display_name); /* optional */
    return 0;
fail:
    rc_identity_assertion_free(out);
    memset(out, 0, sizeof(*out));
    return -1;
}

int rc_decode_rp_verify_response(const uint8_t *data, size_t len, rc_rp_verify_response *out,
                                  lrp_error *err) {
    memset(out, 0, sizeof(*out));
    rc_value *root = NULL;
    if (rc_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;
    const rc_value *assertion_map = rc_map_get(root, "assertion");
    if (assertion_map == NULL || assertion_map->type != RC_T_MAP) {
        lrp_fail_ext(err, LRP_ERR_DECODE, "RpVerifyResponse: missing 'assertion' map");
        goto done;
    }
    if (rc_decode_identity_assertion(assertion_map, &out->assertion, err) != 0) goto done;
    {
        int present = 0, value = 0;
        rc_get_bool_opt(root, "verified", &present, &value);
        if (!present) {
            lrp_fail_ext(err, LRP_ERR_DECODE, "RpVerifyResponse: missing 'verified'");
            rc_identity_assertion_free(&out->assertion);
            goto done;
        }
        out->verified = value;
    }
    rc = 0;
done:
    rc_value_free(root);
    free(root);
    if (rc != 0) memset(out, 0, sizeof(*out));
    return rc;
}

int rc_encode_rp_userinfo_request(const char *token, const char *api_base, const char *domain,
                                   lrp_bytes *out, lrp_error *err) {
    rc_buf tbuf, abuf, dbuf, outbuf;
    rc_buf_init(&tbuf);
    rc_buf_init(&abuf);
    rc_buf_init(&dbuf);
    rc_buf_init(&outbuf);
    int rc = 0;
    rc |= rc_write_text_cstr(&tbuf, token);
    rc |= rc_write_text_cstr(&abuf, api_base);
    rc |= rc_write_text_cstr(&dbuf, domain);
    rc_map_entry entries[3] = {
        {"token", tbuf.data, tbuf.len},
        {"api_base", abuf.data, abuf.len},
        {"domain", dbuf.data, dbuf.len},
    };
    if (rc == 0) rc = rc_write_canon_map(&outbuf, entries, 3);
    rc_buf_free(&tbuf);
    rc_buf_free(&abuf);
    rc_buf_free(&dbuf);
    if (rc != 0) {
        rc_buf_free(&outbuf);
        return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "encode RpUserInfoRequest: out of memory");
    }
    *out = rc_buf_release(&outbuf);
    return 0;
}

static void rrp_claims_free(rrp_claim *claims, size_t count) {
    if (claims == NULL) return;
    for (size_t i = 0; i < count; i++) {
        free(claims[i].claim_type);
        lrp_bytes_free(&claims[i].claim_value);
        for (size_t j = 0; j < claims[i].signing_domains_count; j++) free(claims[i].signing_domains[j]);
        free(claims[i].signing_domains);
    }
    free(claims);
}

/* Decodes one Claim's `signatures` array down to the distinct signing
 * domains, first-seen order -- the trust-relevant attribution a session
 * needs (demoappsite/src/main.rs's callback handler does the same
 * dedup). */
static int rc_claim_signing_domains(const rc_value *claim_map, char ***out_domains,
                                     size_t *out_count, lrp_error *err) {
    *out_domains = NULL;
    *out_count = 0;
    const rc_value *sigs = rc_map_get(claim_map, "signatures");
    if (sigs == NULL || sigs->type != RC_T_ARRAY || sigs->items_len == 0) return 0;

    char **domains = (char **)calloc(sigs->items_len, sizeof(char *));
    if (domains == NULL) return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    size_t n = 0;
    for (size_t i = 0; i < sigs->items_len; i++) {
        const rc_value *sig = &sigs->items[i];
        lrp_str domain = {0};
        if (rc_get_text(sig, "domain", &domain, err) != 0) {
            for (size_t j = 0; j < n; j++) free(domains[j]);
            free(domains);
            return -1;
        }
        int dup = 0;
        for (size_t j = 0; j < n; j++) {
            if (strcmp(domains[j], domain.data) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup) {
            lrp_str_free(&domain);
        } else {
            domains[n++] = domain.data; /* transfer ownership */
        }
    }
    *out_domains = domains;
    *out_count = n;
    return 0;
}

int rc_decode_user_info(const uint8_t *data, size_t len, rrp_identity *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    rc_value *root = NULL;
    if (rc_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;

    lrp_str user_id = {0}, domain = {0}, display_name = {0};
    if (rc_get_text(root, "user_id", &user_id, err) != 0) goto done;
    if (rc_get_text(root, "domain", &domain, err) != 0) goto done;
    if (rc_get_text(root, "display_name", &display_name, err) != 0) {
        lrp_str_free(&user_id);
        lrp_str_free(&domain);
        goto done;
    }

    const rc_value *claims_arr = NULL;
    if (rc_get_array(root, "claims", &claims_arr, err) != 0) {
        lrp_str_free(&user_id);
        lrp_str_free(&domain);
        lrp_str_free(&display_name);
        goto done;
    }

    rrp_claim *claims = NULL;
    if (claims_arr->items_len > 0) {
        claims = (rrp_claim *)calloc(claims_arr->items_len, sizeof(rrp_claim));
        if (claims == NULL) {
            lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
            lrp_str_free(&user_id);
            lrp_str_free(&domain);
            lrp_str_free(&display_name);
            goto done;
        }
    }
    size_t claims_count = 0;
    for (size_t i = 0; i < claims_arr->items_len; i++) {
        const rc_value *cm = &claims_arr->items[i];
        lrp_str claim_type = {0};
        lrp_bytes claim_value = {0};
        if (rc_get_text(cm, "claim_type", &claim_type, err) != 0 ||
            rc_get_bytes(cm, "claim_value", &claim_value, err) != 0) {
            lrp_str_free(&claim_type);
            lrp_bytes_free(&claim_value);
            rrp_claims_free(claims, claims_count);
            lrp_str_free(&user_id);
            lrp_str_free(&domain);
            lrp_str_free(&display_name);
            goto done;
        }
        char **sd = NULL;
        size_t sd_count = 0;
        if (rc_claim_signing_domains(cm, &sd, &sd_count, err) != 0) {
            lrp_str_free(&claim_type);
            lrp_bytes_free(&claim_value);
            rrp_claims_free(claims, claims_count);
            lrp_str_free(&user_id);
            lrp_str_free(&domain);
            lrp_str_free(&display_name);
            goto done;
        }
        claims[claims_count].claim_type = claim_type.data;
        claims[claims_count].claim_value = claim_value;
        claims[claims_count].signing_domains = sd;
        claims[claims_count].signing_domains_count = sd_count;
        claims_count++;
    }

    out->user_id = user_id.data;
    out->domain = domain.data;
    out->display_name = display_name.data;
    out->claims = claims;
    out->claims_count = claims_count;
    rc = 0;
done:
    rc_value_free(root);
    free(root);
    return rc;
}

/* --------------------------------------------------------------------- */
/* rrp_pending_login / rrp_identity ownership                            */
/* --------------------------------------------------------------------- */

void rrp_pending_login_free(rrp_pending_login *p) {
    if (p == NULL) return;
    free(p->nonce);
    free(p->user_domain);
    p->nonce = NULL;
    p->user_domain = NULL;
}

void rrp_identity_free(rrp_identity *v) {
    if (v == NULL) return;
    free(v->user_id);
    free(v->domain);
    free(v->display_name);
    rrp_claims_free(v->claims, v->claims_count);
    v->user_id = NULL;
    v->domain = NULL;
    v->display_name = NULL;
    v->claims = NULL;
    v->claims_count = 0;
}

/* --------------------------------------------------------------------- */
/* Small helpers: nonce, percent-encoding                                */
/* --------------------------------------------------------------------- */

/* 16 random bytes, hex-encoded via the SDK's own exported lrp_bytes_to_hex
 * -- reused rather than hand-rolled a second time (see
 * rc_cert_fingerprint_hex above). */
static int rrp_new_nonce(char **out, lrp_error *err) {
    uint8_t raw[16];
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        return lrp_fail_ext(err, LRP_ERR_CRYPTO, "RAND_bytes failed");
    }
    lrp_str hex = {0};
    if (lrp_bytes_to_hex(raw, sizeof(raw), &hex, err) != 0) return -1;
    *out = hex.data; /* transfer ownership (lrp_str.data is malloc'd) */
    return 0;
}

/* Appends a literal C string's bytes verbatim (no percent-encoding) --
 * strlen-driven rather than a hand-counted length constant, so a typo in a
 * literal can't silently truncate or corrupt the built URL. */
static int rc_write_cstr_raw(rc_buf *b, const char *s) { return rc_write_raw(b, (const uint8_t *)s, strlen(s)); }

static int rrp_url_encode_append(rc_buf *b, const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
        int is_unreserved = (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                             (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.' ||
                             *p == '~';
        if (is_unreserved) {
            if (rc_write_raw(b, p, 1) != 0) return -1;
        } else {
            char tmp[3];
            snprintf(tmp, sizeof(tmp), "%02X", *p);
            uint8_t enc[3] = {'%', (uint8_t)tmp[0], (uint8_t)tmp[1]};
            if (rc_write_raw(b, enc, 3) != 0) return -1;
        }
    }
    return 0;
}

char *rrp_resolve_api_base(lrp_dns_resolver *dns, const char *domain) {
    char name[512];
    int name_len = snprintf(name, sizeof(name), "_linkkeys_apis.%s", domain);
    char *result = NULL;

    if (name_len > 0 && (size_t)name_len < sizeof(name)) {
        lrp_txt_records recs = {0};
        lrp_error ignore = {0};
        if (dns->txt_lookup(dns, name, &recs, &ignore) == 0) {
            for (size_t i = 0; i < recs.count && result == NULL; i++) {
                const char *txt = recs.entries[i];
                if (strncmp(txt, "v=lk1 ", 6) != 0) continue;
                const char *p = strstr(txt, "https=");
                if (p == NULL || (p != txt && p[-1] != ' ')) continue;
                p += 6;
                const char *end = p;
                while (*end != '\0' && *end != ' ') end++;
                size_t host_len = (size_t)(end - p);
                if (host_len == 0) continue;
                size_t buflen = host_len + 9; /* "https://" + host + NUL */
                result = (char *)malloc(buflen);
                if (result != NULL) snprintf(result, buflen, "https://%.*s", (int)host_len, p);
            }
        }
        lrp_txt_records_free(&recs);
    }

    if (result == NULL) {
        size_t buflen = strlen(domain) + 9;
        result = (char *)malloc(buflen);
        if (result != NULL) snprintf(result, buflen, "https://%s", domain);
    }
    return result;
}

/* --------------------------------------------------------------------- */
/* Public API: rrp_begin_login / rrp_handle_callback                     */
/* --------------------------------------------------------------------- */

int rrp_begin_login(const rrp_config *cfg, const char *user_domain, const char *user_hint,
                     const char *callback_url, char **out_redirect_url,
                     rrp_pending_login *out_pending, lrp_error *err) {
    *out_redirect_url = NULL;
    memset(out_pending, 0, sizeof(*out_pending));

    char *nonce = NULL;
    if (rrp_new_nonce(&nonce, err) != 0) return -1;

    lrp_transport transport = lrp_default_transport(LRP_ADDRESS_PERMISSIVE);
    lrp_bytes req = {0};
    if (rc_encode_rp_sign_request(callback_url, nonce, &req, err) != 0) {
        free(nonce);
        return -1;
    }
    lrp_bytes resp_bytes = {0};
    int rc = rc_rpc_call(&transport, cfg->tcp_addr, cfg->fingerprints, cfg->fingerprints_count,
                          "Rp", "sign-request", cfg->api_key, req.data, req.len, &resp_bytes, err);
    lrp_bytes_free(&req);
    if (rc != 0) {
        free(nonce);
        return -1;
    }

    lrp_str signed_request = {0};
    rc = rc_decode_rp_sign_response(resp_bytes.data, resp_bytes.len, &signed_request, err);
    lrp_bytes_free(&resp_bytes);
    if (rc != 0) {
        free(nonce);
        return -1;
    }

    /* Only signed_request (and, optionally, user_hint) are read by
     * GET /auth/authorize -- crates/linkkeys/src/web/mod.rs's route
     * signature (#[rocket::get("/auth/authorize?<user_hint>&<signed_request>")]). */
    rc_buf url;
    rc_buf_init(&url);
    rc |= rc_write_cstr_raw(&url, "https://");
    rc |= rc_write_cstr_raw(&url, user_domain);
    rc |= rc_write_cstr_raw(&url, "/auth/authorize?signed_request=");
    rc |= rrp_url_encode_append(&url, signed_request.data);
    if (user_hint != NULL && user_hint[0] != '\0') {
        rc |= rc_write_cstr_raw(&url, "&user_hint=");
        rc |= rrp_url_encode_append(&url, user_hint);
    }
    lrp_str_free(&signed_request);
    if (rc != 0) {
        rc_buf_free(&url);
        free(nonce);
        return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "build redirect URL: out of memory");
    }
    {
        uint8_t nul = 0;
        if (rc_write_raw(&url, &nul, 1) != 0) { /* NUL terminator */
            rc_buf_free(&url);
            free(nonce);
            return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "build redirect URL: out of memory");
        }
    }

    *out_redirect_url = (char *)url.data; /* rc_buf's malloc'd bytes; caller free()s */
    url.data = NULL;
    url.len = 0;
    url.cap = 0;

    out_pending->nonce = nonce;
    out_pending->user_domain = strdup(user_domain);
    if (out_pending->user_domain == NULL) {
        free(*out_redirect_url);
        *out_redirect_url = NULL;
        free(out_pending->nonce);
        memset(out_pending, 0, sizeof(*out_pending));
        return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    }
    return 0;
}

int rrp_handle_callback(const rrp_config *cfg, const rrp_pending_login *pending,
                         const char *encrypted_token, int fetch_userinfo, const char *api_base,
                         rrp_identity *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    lrp_transport transport = lrp_default_transport(LRP_ADDRESS_PERMISSIVE);

    /* Step 4: Rp/decrypt-token. */
    lrp_bytes dreq = {0};
    if (rc_encode_rp_decrypt_request(encrypted_token, &dreq, err) != 0) return -1;
    lrp_bytes dresp = {0};
    int rc = rc_rpc_call(&transport, cfg->tcp_addr, cfg->fingerprints, cfg->fingerprints_count,
                          "Rp", "decrypt-token", cfg->api_key, dreq.data, dreq.len, &dresp, err);
    lrp_bytes_free(&dreq);
    if (rc != 0) return -1;
    lrp_str signed_assertion = {0};
    rc = rc_decode_rp_decrypt_response(dresp.data, dresp.len, &signed_assertion, err);
    lrp_bytes_free(&dresp);
    if (rc != 0) return -1;

    /* Step 5: Rp/verify-assertion. */
    lrp_bytes vreq = {0};
    rc = rc_encode_rp_verify_request(signed_assertion.data, pending->user_domain, &vreq, err);
    if (rc != 0) {
        lrp_str_free(&signed_assertion);
        return -1;
    }
    lrp_bytes vresp_bytes = {0};
    rc = rc_rpc_call(&transport, cfg->tcp_addr, cfg->fingerprints, cfg->fingerprints_count, "Rp",
                      "verify-assertion", cfg->api_key, vreq.data, vreq.len, &vresp_bytes, err);
    lrp_bytes_free(&vreq);
    if (rc != 0) {
        lrp_str_free(&signed_assertion);
        return -1;
    }
    rc_rp_verify_response vresp;
    rc = rc_decode_rp_verify_response(vresp_bytes.data, vresp_bytes.len, &vresp, err);
    lrp_bytes_free(&vresp_bytes);
    if (rc != 0) {
        lrp_str_free(&signed_assertion);
        return -1;
    }

    /* A non-error return from rc_rpc_call only means the call round-tripped
     * -- callers MUST also check `verified`. */
    if (!vresp.verified) {
        lrp_fail_ext(err, LRP_ERR_VERIFICATION, "assertion did not verify against %s's published keys",
                     pending->user_domain);
        rc_rp_verify_response_free(&vresp);
        lrp_str_free(&signed_assertion);
        return -1;
    }
    if (strcmp(vresp.assertion.domain.data, pending->user_domain) != 0) {
        lrp_fail_ext(err, LRP_ERR_VERIFICATION, "domain mismatch: expected %s, got %s",
                     pending->user_domain, vresp.assertion.domain.data);
        rc_rp_verify_response_free(&vresp);
        lrp_str_free(&signed_assertion);
        return -1;
    }
    if (strcmp(vresp.assertion.nonce.data, pending->nonce) != 0) {
        /* Nonce MATCH is checked here; nonce SINGLE-USE (rejecting replay of
         * a previously-redeemed encrypted_token) is the caller's job -- see
         * example.md's "App responsibilities". */
        lrp_fail_ext(err, LRP_ERR_VERIFICATION, "nonce mismatch -- possible replay attack");
        rc_rp_verify_response_free(&vresp);
        lrp_str_free(&signed_assertion);
        return -1;
    }

    if (!fetch_userinfo) {
        out->user_id = strdup(vresp.assertion.user_id.data);
        out->domain = strdup(vresp.assertion.domain.data);
        out->display_name =
            vresp.assertion.display_name.data != NULL ? strdup(vresp.assertion.display_name.data) : NULL;
        rc_rp_verify_response_free(&vresp);
        lrp_str_free(&signed_assertion);
        if (out->user_id == NULL || out->domain == NULL) {
            rrp_identity_free(out);
            return lrp_fail_ext(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
        }
        return 0;
    }
    rc_rp_verify_response_free(&vresp);

    /* Step 6 (optional): Rp/userinfo-fetch. */
    lrp_bytes ureq = {0};
    rc = rc_encode_rp_userinfo_request(signed_assertion.data, api_base, pending->user_domain, &ureq,
                                        err);
    lrp_str_free(&signed_assertion);
    if (rc != 0) return -1;
    lrp_bytes uresp = {0};
    rc = rc_rpc_call(&transport, cfg->tcp_addr, cfg->fingerprints, cfg->fingerprints_count, "Rp",
                      "userinfo-fetch", cfg->api_key, ureq.data, ureq.len, &uresp, err);
    lrp_bytes_free(&ureq);
    if (rc != 0) return -1;
    rc = rc_decode_user_info(uresp.data, uresp.len, out, err);
    lrp_bytes_free(&uresp);
    return rc;
}
```

### `Makefile`

```makefile
SDK ?= sdks/local-rp/c
CC ?= gcc
PKG_CONFIG ?= pkg-config

OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl)
CFLAGS := -std=c11 -Wall -Wextra -Wno-unused-parameter -g -O0 -D_GNU_SOURCE \
          -I$(SDK)/include $(OPENSSL_CFLAGS)
LDLIBS := $(OPENSSL_LIBS) -lresolv -lpthread

SDK_LIB := $(SDK)/build/liblinkkeys_local_rp.a

.PHONY: all test clean

all: regularrp.o

$(SDK_LIB):
	$(MAKE) -C $(SDK) lib

regularrp.o: regularrp.c regularrp.h regularrp_internal.h
	$(CC) $(CFLAGS) -c regularrp.c -o regularrp.o

test_roundtrip: $(SDK_LIB) regularrp.o test_roundtrip.c regularrp_internal.h
	$(CC) $(CFLAGS) -c test_roundtrip.c -o test_roundtrip.o
	$(CC) $(CFLAGS) regularrp.o test_roundtrip.o $(SDK_LIB) $(LDLIBS) -o test_roundtrip

test: test_roundtrip
	./test_roundtrip

clean:
	rm -f *.o test_roundtrip
```

`SDK` defaults to `sdks/local-rp/c` (a relative path), matching a real app
that checks out this repo (or vendors just this SDK directory) alongside
its own source and points `SDK` at it; override with `make SDK=/path/to/checkout`.

## Wiring it into HTTP handlers

`rrp_begin_login`/`rrp_handle_callback` are deliberately framework-agnostic
— they take plain config/pointers and return plain structs, so they drop
into whatever HTTP server your app already embeds (libmicrohttpd, a CGI
shim, a hand-rolled listener, ...). This example does not implement one;
here is the shape your login-start and callback routes would take (compiled
and smoke-tested — see below — but not wired to a real HTTP server):

```c
#include <stdio.h>
#include "regularrp.h"

/* Your app's login-start route handler calls this with the RP config, the
 * LinkKeys domain the user typed (parsed from "alice@example.com" or a bare
 * domain), and its own callback URL. On success, HTTP-redirect the browser
 * to *out_redirect_url and persist *out_pending (e.g. in a signed,
 * short-lived session cookie) for the callback route to retrieve. */
int handle_login_route(const rrp_config *cfg, const char *user_domain,
                        const char *user_hint, const char *callback_url,
                        char **out_redirect_url, rrp_pending_login *out_pending) {
    lrp_error err = {0};
    if (rrp_begin_login(cfg, user_domain, user_hint, callback_url, out_redirect_url, out_pending,
                         &err) != 0) {
        fprintf(stderr, "begin login failed: [%s] %s\n", lrp_error_code_name(err.code), err.message);
        return -1;
    }
    return 0;
}

/* Your app's callback route handler calls this with the `pending` it
 * retrieved from the session and the `encrypted_token` query parameter the
 * IDP redirected back with. On success, out->user_id/domain/claims are
 * verified protocol facts -- mint your own application session from them;
 * this call never creates one itself. */
int handle_callback_route(const rrp_config *cfg, const rrp_pending_login *pending,
                           const char *encrypted_token, const char *api_base,
                           rrp_identity *out) {
    lrp_error err = {0};
    if (rrp_handle_callback(cfg, pending, encrypted_token, 1 /* fetch_userinfo */, api_base, out,
                             &err) != 0) {
        fprintf(stderr, "callback verification failed: [%s] %s\n", lrp_error_code_name(err.code),
                err.message);
        return -1;
    }
    return 0;
}
```

Delete the pending-login's session record as soon as you retrieve it in the
callback handler (before calling `rrp_handle_callback`) — one `beginLogin`
should only ever be completable once, independent of the nonce check inside
`rrp_handle_callback` itself (see "App responsibilities" below).

## Memory and ownership notes (this example's own conventions)

Following the SDK's own documented style (`include/linkkeys_local_rp.h`'s
top-of-file comment):

- Every `rrp_*_free` function releases exactly what the matching allocating
  call returned, and is safe to call on a zero-initialized (`= {0}`),
  never-populated struct — `rrp_pending_login_free`/`rrp_identity_free` both
  check every heap-owned field for `NULL` before freeing it.
- Output parameters of `rrp_begin_login`/`rrp_handle_callback` are populated
  **only** on success (return `0`); on failure they are left zeroed (or, for
  `rrp_begin_login`'s `*out_redirect_url`, left `NULL`) and owe the caller
  nothing.
- `rrp_pending_login` is **single-use**, exactly like the local-RP SDK's own
  `lrp_pending_login`: this example owns no storage and cannot enforce
  that itself. Persist it in your app's session mechanism, pass it unchanged
  to `rrp_handle_callback`, and discard it after one completion attempt.
- `rrp_resolve_api_base`'s and `rrp_begin_login`'s `*out_redirect_url`
  returns are plain `malloc`'d C strings (`free()` them), not `lrp_str` —
  this example's public surface stays plain-C-idiomatic rather than pulling
  every return value through the SDK's ownership types, since those types'
  contract (`lrp_str_free`) is no different from `free()` for a
  `malloc`'d buffer anyway.
- **No private key material ever touches this app's process** — that's the
  entire point of regular-RP mode (`docs/DEPLOYING-RP.md`'s "Web App
  Integration": "Web app NEVER touches private keys"). Unlike
  `lrp_identity` in this SDK's local-RP mode (which holds an Ed25519 seed
  and an X25519 private key, and whose `lrp_identity_free` zeroizes both
  with `OPENSSL_cleanse` before releasing them), this example's own most
  sensitive value is `cfg->api_key` — a bearer-style credential, not a
  private key, and it is only ever **borrowed** (a `const char *` your app
  supplies and continues to own), never copied into a heap allocation this
  example would need to zeroize.
- The two ephemeral secrets this example *does* allocate and own —
  `pending->nonce` and the decrypted `signed_assertion` string inside
  `rrp_handle_callback` — are released with ordinary `free()`/`lrp_str_free`
  (not zeroized). That mirrors the SDK's own distinction between
  `lrp_bytes_free` (ordinary) and `lrp_bytes_free_sensitive`
  (`OPENSSL_cleanse`-then-free, reserved for private key material): a login
  nonce or a short-lived bearer assertion is sensitive in the sense of "keep
  it out of logs" (see below), but it is not key material, so this example
  does not claim a zeroization guarantee it would be misleading to make. If
  your threat model wants defense-in-depth here (e.g. hardening against a
  heap-scraping attacker on a shared host), wrap those two frees in
  `OPENSSL_cleanse` yourself — nothing about this example's design prevents
  it.
- This example performs no logging of its own, matching AGENTS.md's rule
  never to log keys, claim values, session tokens, or credentials. The
  `wiring_demo.c` snippet above does log `err.message` on failure to
  `stderr` — that's fine because, exactly like the SDK's own `lrp_error`,
  the messages this example's `lrp_fail_ext` writes are deliberately built
  from static format strings and hostnames/status codes, never key
  material, tokens, nonces, or claim values. Your app's own logging of
  request parameters, claims, etc. is your responsibility to keep equally
  careful.

## App responsibilities

Exactly parallel to what this SDK's own README documents for the local-RP
mode — this glue code hands back verified protocol facts, and these
responsibilities are entirely yours, whether you write this glue by hand (as
here) or eventually use a packaged regular-RP SDK:

- **Nonce single-use.** `rrp_handle_callback` compares the assertion's nonce
  against `pending->nonce` and rejects a mismatch, but it enforces MATCH,
  not SINGLE USE — nothing in the `Rp` service or this example stops a
  second `rrp_handle_callback` call with the same still-valid
  `encrypted_token` from succeeding again. Persist a durable single-use
  record (a unique DB constraint, or a cache entry with a TTL past the
  assertion's `expires_at`) keyed on the nonce, and check it before trusting
  a callback. (The IDP itself separately burns the assertion once, but only
  at the point your RP server calls `userinfo-fetch` — replay of the earlier
  steps is still on you.)
- **Sessions.** Nothing in this example creates an application session.
  `rrp_identity` is a bag of verified protocol facts
  (`user_id`/`domain`/`display_name`/`claims`) — mint your own session
  (signed cookie, server-side session store, whatever your app already
  uses) from it in your callback handler, and make sure the pending-login
  record (state tying a browser to its in-flight login) and the logged-in
  session are separate, with the pending-login record single-use and
  short-lived.
- **API key storage.** `cfg->api_key` (from "Prerequisites" step 2)
  authorizes signing and decrypting on your domain's behalf via your RP
  server — treat it with the same care as a database credential, not as
  ordinary configuration (an environment variable read once at startup and
  never logged is the usual pattern). It's shown once at creation time and
  cannot be retrieved again — mint a new one and re-grant `api_access` if it
  leaks.
- **Local user records / authorization.** This glue returns `rrp_identity`
  — protocol facts. Mapping `user_id`+`domain` to a local account,
  first-login provisioning, and any app-level authorization decisions are
  entirely your app's to make.
- **Zeroization**, if your threat model wants it beyond what's described
  above — see "Memory and ownership notes".

## Local-RP vs regular-RP

| | Local RP (`liblinkkeys_local_rp`, this directory) | Regular RP (this document) |
|---|---|---|
| App identity | A locally-generated Ed25519 key fingerprint (SSH-host-key style) | A DNS domain your app owns |
| DNS required | No | Yes -- `_linkkeys` + `_linkkeys_apis` TXT records |
| Where keys live | In the app itself (`lrp_local_rp_identity_to_bytes`) | In a separate RP server process your app talks to over TCP |
| Admission | Explicit per-domain approval (`linkkeys local-rp approve <fingerprint>`) -- pending until an admin approves | Ordinary DNS-pinned trust, same as any LinkKeys peer |
| C library/example | `liblinkkeys_local_rp.a` (`lrp_begin_local_login`/`lrp_complete_local_login`) | None packaged -- hand-write the glue this document shows, reusing this SDK's public header where it applies |
| Best for | LAN tools, self-hosted apps with no public DNS, desktop apps | Any app that already has (or can get) a domain |

If your app has a domain, use this document's approach. If it doesn't (a LAN
jukebox, a local dev tool), see this directory's own `README.md` and
`include/linkkeys_local_rp.h` instead.

## TCP-only + raw-key recap

Two traps worth restating, since they're the two things most likely to bite
a first integration:

1. **TCP CSIL-RPC only.** There is no HTTP JSON path for `Rp` operations —
   `POST /v1alpha/sign-request.json` and friends were never wired up as
   Rocket routes (`crates/linkkeys/src/web/rp.rs` only contains the core
   logic functions the TCP dispatch calls, not an HTTP route), and the
   generic HTTP RPC carrier structurally cannot complete `verify-assertion`
   or `userinfo-fetch` (they need the outbound S2S context only the TCP
   carrier has). `rc_rpc_call` above is TCP-and-TLS-pinned end to end; there
   is no shortcut through an HTTP client library here.
2. **Raw API key, no `"Bearer "` prefix.** The CSIL-RPC envelope's `auth`
   field is a plain CBOR text string of the key itself
   (`rc_encode_rpc_request`'s `if (auth != NULL) rc |= rc_write_text_cstr(&abuf, auth);`).
   Prepending `"Bearer "` (an HTTP-auth-header convention that does not
   apply to this envelope field) will authenticate as a garbage key and
   fail every `Rp` call with an authorization error.

## What was compiled and run

All code blocks above are copied verbatim from files built and exercised in
a scratch directory outside this repo, against this checkout's
`sdks/local-rp/c` (`make lib` first, to produce
`build/liblinkkeys_local_rp.a`):

```sh
cd sdks/local-rp/c && make lib   # build/liblinkkeys_local_rp.a

cd /scratch/regularrp-c
gcc -std=c11 -Wall -Wextra -Wno-unused-parameter -g -O0 -D_GNU_SOURCE \
    -I/path/to/sdks/local-rp/c/include $(pkg-config --cflags openssl) \
    -c regularrp.c -o regularrp.o                      # clean: no warnings

gcc -std=c11 -Wall -Wextra -Wno-unused-parameter -g -O0 -D_GNU_SOURCE \
    -I/path/to/sdks/local-rp/c/include $(pkg-config --cflags openssl) \
    -c test_roundtrip.c -o test_roundtrip.o             # clean: no warnings

gcc -std=c11 -Wall -Wextra -Wno-unused-parameter -g -O0 -D_GNU_SOURCE \
    regularrp.o test_roundtrip.o \
    /path/to/sdks/local-rp/c/build/liblinkkeys_local_rp.a \
    $(pkg-config --libs openssl) -lresolv -lpthread \
    -o test_roundtrip
./test_roundtrip
```

Output:

```
ok  envelope round trip (canonical key order + tag24 payload)
ok  envelope with no auth field omits 'auth' entirely
ok  RPC response envelope round trip (status + tag24 payload)
ok  RpSignRequest/RpSignResponse round trip
ok  RpVerifyResponse round trip (nested IdentityAssertion, optional display_name)
ok  UserInfo decode (nested claims + signature-domain dedup)
ok  rrp_resolve_api_base (fake DNS seam, present + fallback)
all round-trip tests passed
```

The same build was repeated with
`-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all`
(the same flags `sdks/local-rp/c`'s own `make test` uses) — clean, no
ASan/UBSan findings, same output. Every CBOR/envelope/DNS-seam code path
above ran under both a plain build and an instrumented one.

Additionally, the "Wiring it into HTTP handlers" snippet (`wiring_demo.c` in
the scratch directory, not reproduced in full here since it adds nothing
code-wise beyond what's already shown) was compiled with the same flags and
run against a **closed local port** (`127.0.0.1:1`) to prove the dial/TLS
path in `rc_rpc_call` fails cleanly — a real `lrp_error` with no crash —
rather than only ever being compile-checked:

```
begin login failed: [transport] 127.0.0.1:1: connect failed
ok  rrp_begin_login against a closed port failed cleanly (no crash)
```

Toolchain: system GCC 16.1.1, OpenSSL 3.6.3 (via `pkg-config`), the exact
versions this environment ships — no `catalyst-tools` toolchain override was
needed since this document only builds C against the system compiler and
OpenSSL, matching `sdks/local-rp/c/README.md`'s own stated requirements.

**Exports sufficed vs. inlined — summary:** `lrp_default_transport`,
`lrp_error`/`lrp_error_code_name`, `lrp_bytes`/`lrp_str` and their `_free`
functions, `lrp_bytes_to_hex`, and
`lrp_dns_resolver`/`lrp_default_dns_resolver`/`lrp_txt_records` from
`include/linkkeys_local_rp.h` sufficed unmodified. Everything CSIL-RPC- and
CBOR-shaped (the envelope codec, TLS pin-and-connect, and all five `Rp`
type encoders/decoders) had to be inlined/hand-written, because this SDK's
public header is scoped to the local-RP flow only and no csilgen `c` target
exists to generate a codec from `csil/linkkeys.csil` directly. No mismatch
between the documented flow (`docs/DEPLOYING-RP.md`) and the server's actual
routes was found for the TCP CSIL-RPC path used here — only the already-known,
separately-documented HTTP-JSON-routes-don't-exist gap (see "TCP-only +
raw-key recap" above).
