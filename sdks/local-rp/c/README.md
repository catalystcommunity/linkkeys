# liblinkkeys_local_rp (C)

C SDK for LinkKeys' **DNS-less local RP identity** mode — see
`dns-less-local-rp-design.md` at the repo root for the full design; this
library implements its "SDK API Shape" section, C-idiomatically adapted
(big-config input structs, explicit out-parameters, explicit ownership
documented in `include/linkkeys_local_rp.h`). It lets a locally installed
app (a LAN jukebox, a desktop tool, a self-hosted service with no public
DNS) use LinkKeys for login without running its own DNS-pinned relying
party. The app's identity is the fingerprint of a locally-generated Ed25519
signing key (SSH-host-key style), not a domain.

## Layout

```
sdks/local-rp/c/
  include/linkkeys_local_rp.h   public API — read this first
  src/
    error.c/.h                  lrp_error / lrp_fail
    bytes.c                     lrp_bytes/lrp_str/lrp_txt_records ownership
    time_util.c/.h               RFC3339 <-> unix seconds (internal)
    cbor.c/.h                    hand-written CBOR writer + decoder (internal)
    encoding.c/.h                 base64url (unpadded) (internal)
    crypto.c/.h                   OpenSSL EVP wrappers (internal)
    types.c/.h                    CSIL type encode/decode (internal)
    local_rp.c/.h                 envelope sign/verify, callback sealed box,
                                   timestamp/expiration checks (internal)
    dns.c/.h                      _linkkeys[_apis] TXT parsing, key pinning,
                                   default libresolv resolver (internal)
    revocation.c/.h                sibling-signed revocation certs (internal)
    claims.c/.h                    claim signature/revocation/expiry (internal)
    transport.c                    default TCP Transport (public API type)
    rpc.c/.h                       CSIL-RPC v1 codec/framing + TLS pinning +
                                    fetch-domain-keys / redeem-claim-ticket
    identity.c                     generate_local_rp_identity, byte helpers,
                                    check_expirations
    begin.c                        begin_local_login, PendingLogin bytes
    complete.c                     complete_local_login (the full chain)
  tests/
    json.c/.h                      minimal JSON parser — TEST HARNESS ONLY
    test_util.c/.h                  assertion macros + fixture hex helpers
    test_conformance.c              runs every sdks/local-rp/conformance/*.json
    test_flow.c                     real loopback TLS "fake IDP" + happy path
                                     + sibling failure modes
    test_main.c
  Makefile
```

Only `include/linkkeys_local_rp.h` is the public surface. Every `src/*.h`
is an internal header (still reachable from `tests/` via `-Isrc`, which is
how the test suite reaches CBOR/crypto/protocol internals directly — e.g.
to recompute an envelope signature input and compare it byte-for-byte
against a conformance vector).

## Build

Requires system GCC (C11) and OpenSSL 3.x with `pkg-config` able to find it
(`pkg-config --cflags --libs openssl`). No cmake/autotools — a plain
Makefile, per the design doc's "SDK Layout and Tooling".

```sh
cd sdks/local-rp/c
make           # build build/liblinkkeys_local_rp.a
make test      # build + run the ASan/UBSan-instrumented test suite
make clean
```

**Test command for CI/automation:** `cd sdks/local-rp/c && make test`

The test binary must be run from `sdks/local-rp/c/` (it loads fixtures via
paths relative to that directory, `../conformance/*.json`); `make test`
already does this.

`make test` compiles every `src/*.c` file a SECOND time (not against the
plain `.a`) with `-fsanitize=address,undefined
-fno-sanitize-recover=all`, so every line of the library — not just the
test harness — runs instrumented. A C SDK claim of correctness without
ASan is not credible; this repo does not make that claim without evidence.

### Linking against the library from your own app

```sh
cc your_app.c $(pkg-config --cflags openssl) \
   -Isdks/local-rp/c/include \
   sdks/local-rp/c/build/liblinkkeys_local_rp.a \
   $(pkg-config --libs openssl) -lresolv -lpthread -o your_app
```

(`-lpthread` is only required if *your* app or test harness spawns threads
that touch this library concurrently from more than one thread at a time —
see "Thread safety" below; the library itself does not spawn threads.)

## Quickstart

```c
#include <time.h>
#include <linkkeys_local_rp.h>

lrp_error err = {0};

/* Once, at install/setup time. */
lrp_generate_identity_config gen_cfg = {0};
gen_cfg.app_name = "My LAN Jukebox";
gen_cfg.now_unix = time(NULL);
lrp_identity identity = {0};
if (lrp_generate_local_rp_identity(&gen_cfg, &identity, &err) != LRP_OK) { /* ... */ }

lrp_bytes stored = {0};
lrp_local_rp_identity_to_bytes(&identity, &stored, &err);
/* persist stored.data/stored.len with application-secret care, then: */
lrp_bytes_free(&stored);

/* Per login attempt: */
lrp_begin_login_config begin_cfg = {0};
begin_cfg.identity = &identity;
begin_cfg.callback_url = "http://jukebox.lan:8080/auth/callback";
begin_cfg.user_domain = "example.com";
begin_cfg.now_unix = time(NULL);

lrp_login_redirect redirect = {0};
lrp_pending_login pending = {0};
if (lrp_begin_local_login(&begin_cfg, &redirect, &pending, &err) != LRP_OK) { /* ... */ }
/* app: persist `pending` (e.g. in a server-side session), then redirect the
 * browser to redirect.redirect_url. */

/* On callback (your HTTP handler received `arrived_url`, whose query
 * string carries `encrypted_token=...`): */
lrp_complete_login_config complete_cfg = {0};
complete_cfg.identity = &identity;
complete_cfg.pending = &pending;
complete_cfg.encrypted_token = encrypted_token_from_query_string;
complete_cfg.arrived_url = full_request_url;
complete_cfg.now_unix = time(NULL);
/* complete_cfg.transport / .dns left NULL -> library defaults (real TCP +
 * system resolver via libresolv). */

lrp_verified_login verified = {0};
if (lrp_complete_local_login(&complete_cfg, &verified, &err) != LRP_OK) { /* ... */ }
/* verified.user_id / .user_domain / .claims / .domain_public_keys /
 * .local_rp_fingerprint / expirations. Session creation, local user
 * records, and authorization are entirely your app's responsibility. */

lrp_verified_login_free(&verified);
lrp_pending_login_free(&pending);
lrp_login_redirect_free(&redirect);
lrp_identity_free(&identity); /* zeroizes both private keys before freeing */
```

## Ownership and lifetime rules

Read `include/linkkeys_local_rp.h`'s top-of-file comment in full before
calling anything; the summary:

- Every `lrp_*_free` function releases exactly what the matching allocating
  call returned, and is safe to call on a zero-initialized (`= {0}`),
  never-populated struct.
- `lrp_identity` (`lrp_generate_local_rp_identity`,
  `lrp_local_rp_identity_from_bytes`) holds both private keys; `lrp_identity_free`
  zeroizes them (`OPENSSL_cleanse`) before releasing the struct's heap
  fields. Treat the bytes from `lrp_local_rp_identity_to_bytes` with the
  same care as a database credential or API key (they control this app's
  entire local-RP identity), not merely as configuration.
- Output parameters of every allocating function are populated **only** on
  success (return `LRP_OK`); on failure they are left zeroed.
- `lrp_pending_login` (from `lrp_begin_local_login`) is **single-use**: this
  library owns no storage and cannot enforce that itself. Persist it (e.g.
  `lrp_pending_login_to_bytes`/`_from_bytes` into a server-side session),
  supply it unchanged to `lrp_complete_local_login`, and discard it after
  one completion attempt.

## App responsibilities

Per the design doc's "SDKs must not own application storage, sessions,
database writes, or local user authorization":

- **Sessions, local user records, authorization** are entirely the app's.
  This library returns verified protocol facts (`lrp_verified_login`) and
  never creates a session or writes to an app database.
- **Single-use enforcement** for `lrp_pending_login` (see above) is the
  app's job.
- **Key storage** for `lrp_identity`'s bytes is the app's job (this library
  only zeroizes its own in-memory copy on free).
- **Opening the redirect URL**: `lrp_begin_local_login` never performs an
  HTTP redirect or opens a browser itself — it returns
  `lrp_login_redirect.redirect_url` and leaves the UX decision (HTTP
  redirect, displayed link, embedded webview) to the app, per the design
  doc's "Browser-only Flow".

## Security notes

- Revoking this local RP identity at the IDP kills future logins **and**
  any outstanding claim tickets immediately (redemption re-checks approval
  status every time) — but does **not** reach into sessions the app already
  minted from a prior successful login. Session lifecycle is the app's.
- Key rotation is not a continuity operation: generating a new identity
  means a new fingerprint and re-approval at every LinkKeys domain. There
  is no "same app, new key" story in this protocol version.
- Domain keys and revocations fetched over the network are only ever
  trusted after DNS `fp=` pinning (`src/dns.c`, `src/rpc.c`) — an
  unpinned/unauthenticated key can never reach the verification chain.
  `lrp_fetch_domain_keys` fails closed (`LRP_ERR_NO_TRUSTED_KEYS`) when
  pinning yields nothing trustworthy.
- The default DNS resolver (`lrp_default_dns_resolver`, libresolv
  `res_query`) is the OS-configured system resolver; LAN resolver spoofing
  is an accepted, documented tradeoff for this mode (design doc,
  "Decided"). Inject a hardened `lrp_dns_resolver` (e.g. a DoH client) for
  deployments that need more.
- The default `lrp_transport` (`lrp_default_transport`) defaults to
  `LRP_ADDRESS_PERMISSIVE` — it will dial loopback/private/LAN addresses,
  which is the entire point of this mode (a local RP's `_linkkeys_apis`
  endpoint is routinely a private address). `LRP_ADDRESS_PUBLIC_ONLY` is
  available as an opt-in for integrators that specifically want the
  stricter, server-side-SSRF-guard-style posture.
- TLS to the pinned TCP endpoint disables WebPKI chain validation
  (`SSL_VERIFY_NONE`) — the DNS `fp=` pin is the trust anchor, not a CA
  chain — and **mandatorily** verifies the peer certificate's Ed25519 SPKI
  fingerprint against that pin after the handshake
  (`src/rpc.c`'s `tls_connect_pinned`). A handshake that succeeds but whose
  certificate doesn't match a pinned fingerprint is rejected.
- Signature verification uses distinct, mandatory-per-structure context
  strings (`LRP_CTX_DESCRIPTOR`, `LRP_CTX_LOGIN_REQUEST`, `LRP_CTX_CALLBACK`,
  `LRP_CTX_TICKET_REDEMPTION`) so a signature over one structure can never
  verify as another. Ed25519 only; no signature versioning.
- The number of distinct claim-signer domains `lrp_complete_local_login`
  will fetch keys for per completion is capped
  (`MAX_CLAIM_SIGNER_DOMAINS`, 8, in `src/complete.c`) — an unbounded claim
  set naming attacker-chosen "signer domains" would otherwise be an
  SSRF/DoS amplification vector against the app's own process.
- This library performs no logging of its own. If your app logs
  `lrp_error`, note that `lrp_error.message` is written to deliberately
  avoid including key material, nonces, tokens, tickets, or claim values
  (AGENTS.md's error-handling rule) — but your app's own logging of request
  parameters, claims, etc. is your responsibility to keep equally careful.

## Crypto (OpenSSL EVP) API choices

See `src/crypto.h`'s module doc for the full rationale; summary:

- **Ed25519 / X25519**: `EVP_PKEY_new_raw_private_key`/`raw_public_key` +
  `EVP_DigestSign`/`EVP_DigestVerify` with a `NULL` message digest
  (Ed25519 is PureEdDSA — one-shot, no prehash) for signing; `EVP_PKEY_derive`
  for X25519 ECDH, with an explicit all-zero-shared-secret rejection
  (`lrp_x25519_ecdh`) matching the sealed-box construction's
  low-order-point defense.
- **HKDF-SHA256**: `EVP_PKEY_CTX` with `EVP_PKEY_HKDF` (`<openssl/kdf.h>`),
  default `EXTRACT_AND_EXPAND` mode, empty (not NULL-length-mismatched)
  salt. This matches `Hkdf::<Sha256>::new(None, ikm).expand(info, 32)`
  byte-for-byte — HMAC treats a 0-length key identically to a
  hash-block-length all-zero key (both zero-pad to the same 64-byte HMAC
  block) — verified directly against `callback_box.json`'s
  `kdf_context_hex` in `tests/test_conformance.c`.
- **AES-256-GCM / ChaCha20-Poly1305**: `EVP_{En,De}cryptInit_ex` +
  `EVP_CIPHER_CTX_ctrl` for the IV length and 16-byte tag, through one
  `cipher_for(suite)` dispatch point shared by encrypt/decrypt (mirrors
  `liblinkkeys::crypto::aead_encrypt`/`aead_decrypt`'s single dispatch
  point, so a future suite is added in exactly one place). Ciphertext
  output is `ciphertext || 16-byte tag`, matching the conformance vectors'
  RustCrypto `Aead`-trait convention.
- **TLS pin extraction**: `SSL_get1_peer_certificate` ->
  `X509_get0_pubkey` -> `EVP_PKEY_get_raw_public_key` to recover the raw
  32-byte Ed25519 SPKI content directly — no manual ASN.1/DER unwrapping
  needed, since OpenSSL's EVP layer already does it.

## DNS TXT lookups

The default resolver (`lrp_default_dns_resolver`) uses glibc's libresolv
(`res_query` + `ns_initparse`/`ns_parserr`, `<resolv.h>`/`<arpa/nameser.h>`,
linked via `-lresolv`). Known limitation: the legacy resolver API's global
`_res` state is not fully reentrant across concurrent lookups from multiple
threads on all glibc versions; if your app performs `lrp_complete_local_login`
calls from multiple threads simultaneously with the default resolver,
either serialize DNS lookups yourself or inject an `lrp_dns_resolver` built
on a thread-safe resolver library instead.

## Thread safety

No global mutable state is shared across calls except:

- OpenSSL's own global state, which OpenSSL 3.x initializes and manages
  safely for concurrent use without extra locking from this library.
- The libresolv-based default DNS resolver's caveat above.

Otherwise, every `lrp_identity`/`lrp_pending_login`/`lrp_verified_login`/etc.
is a plain caller-owned value with no hidden shared state; concurrent calls
operating on distinct instances are safe.

## Vendored test-only dependency

`tests/json.c`/`tests/json.h` is a small, hand-written JSON parser scoped
exactly to what `sdks/local-rp/conformance/*.json` needs (objects, arrays,
strings with `\uXXXX`/surrogate-pair escapes, numbers, booleans, null). It
is compiled only into the test binary — `include/linkkeys_local_rp.h` and
every `src/*.c` file have no JSON dependency, per the design doc's
constraint that "the library itself must not need JSON."

## Conformance coverage

`make test` runs `tests/test_conformance.c` against all eight
`sdks/local-rp/conformance/*.json` files (`keys.json`, `envelopes.json`
— 4 positive + 20 negative cases, `callback_box.json` — 2 positive + 13
negative cases, `tickets.json`, `url_params.json`, `dns.json`,
`expirations.json`, `revocations.json` — 9 certificate cases plus the
application case) and `tests/test_flow.c`, a real loopback TCP+TLS "fake
IDP" server written with the same OpenSSL libcrypto/libssl this SDK uses
(never a forked `openssl s_server`) exercising the full
`begin_local_login`/`complete_local_login` chain end to end, plus the
sibling failure modes: non-http(s) callback scheme rejection, DNS `fp=`
pin mismatch, wrong decryption key, and nonce/state mismatch.
