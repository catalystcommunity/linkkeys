# linkkeys_local_rp (OCaml)

OCaml SDK for LinkKeys' DNS-less local RP identity mode. Read
`dns-less-local-rp-design.md` at the repo root first — this package implements its
"SDK API Shape" section, OCaml-idiomatic: big-config records with optional-labelled
arguments, one closed `Error.t` variant returned via `('a, Error.t) result` from every
public entry point, and duck-typed `Transport.t` / `Dns.resolver` seams (one-function
records rather than module types, so a test fake is a one-line value).

This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a self-hosted
service with no public DNS) use LinkKeys for login without running its own DNS-pinned
relying party. The app's identity is the fingerprint of a locally-generated signing key
(SSH-host-key style), not a domain.

## Quickstart

```ocaml
(* Once, at install/setup time -- persist the returned bytes with ordinary
   application-secret care. *)
let identity =
  Linkkeys_local_rp.generate_local_rp_identity
    (Linkkeys_local_rp.Identity.make_config ~app_name:"My LAN Jukebox"
       ~now:(Unix.gettimeofday ()) ())
  |> Result.get_ok
in
let stored_bytes = Linkkeys_local_rp.local_rp_identity_to_bytes identity in

(* Later, per login attempt: *)
let identity = Linkkeys_local_rp.local_rp_identity_from_bytes stored_bytes |> Result.get_ok in
let redirect, pending =
  Linkkeys_local_rp.begin_local_login
    (Linkkeys_local_rp.Begin_login.make_config ~key_material:identity
       ~callback_url:"http://jukebox.lan:8080/auth/callback" ~user_domain:"example.com"
       ~now:(Unix.gettimeofday ()) ())
  |> Result.get_ok
in
(* App: persist `pending` (e.g. via Begin_login.pending_login_to_fields into a
   session), then redirect the browser to redirect.redirect_url. *)

(* On callback (app's HTTP handler received `arrived_url` with an
   `encrypted_token=` query parameter): *)
let verified =
  Linkkeys_local_rp.complete_local_login
    (Linkkeys_local_rp.Complete_login.make_config ~key_material:identity ~pending
       ~encrypted_token ~arrived_url ~now:(Unix.gettimeofday ()) ())
  |> Result.get_ok
in
(* verified.user_id, verified.user_domain, verified.claims, ... -- session creation,
   local user records, and authorization are all the app's own responsibility. *)
```

`check_expirations identity now` reports facts (`ok` / `notice` / `warning` / `critical`
/ `expired`); the app decides what to do with them.

## Layout

```text
sdks/local-rp/ocaml/
  dune-project
  lib/
    cbor.ml            hand-rolled canonical/deterministic CBOR (no csilgen OCaml target)
    hex.ml              minimal hex codec
    timeutil.ml          RFC3339 <-> Unix epoch seconds, TZ-independent (Howard Hinnant's
                         days_from_civil/civil_from_days algorithm)
    crypto.ml            Ed25519, X25519, AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA256,
                         fingerprint, suite/algorithm registries, RNG bootstrap
    types.ml              hand-written CBOR struct codecs for the 19 CSIL types this SDK
                         touches (field order verified against every *_cbor_hex fixture)
    local_rp.ml           envelope sign/verify, sealed-box seal/open, timestamp/expiry/
                         nonce/audience/issuer checks -- the pure protocol core
    claims.ml             claim signature/revocation/expiry verification
    revocation.ml          sibling-signed key revocation certificate verification
    dns.ml                 _linkkeys/_linkkeys_apis TXT record parsing + pinning, plus a
                         hand-rolled bounded UDP DNS TXT query (no ocaml-dns dependency)
    transport.ml            the TCP dial seam (permissive by default, matching this mode's
                         "connect to a LAN box" intent, not the server's SSRF-guarded default)
    tls_client.ml           SPKI Ed25519 pin-check authenticator + a hand-driven blocking
                         Tls.Engine client (see "TLS evaluation" below)
    rpc.ml                 CSIL-RPC envelope + stream framing (hand-rolled; see the filed
                         csilgen request) + the two operations this SDK calls
    url_params.ml           base64url-unpadded encode/decode for the two URL parameters
    identity.ml             generate_local_rp_identity + byte storage helpers
    begin_login.ml           begin_local_login
    complete_login.ml         complete_local_login
    error.ml                one closed error variant for this SDK's own result-returning API
    linkkeys_local_rp.ml      top-level facade (re-exports + quickstart docs)
  test/
    test_helper.ml           JSON-vector loading helpers (Yojson)
    run_tests.ml              conformance tests over all 8 vector files + TLS pin-extraction
                            + RPC-framing + flow tests
    fixtures/ed25519_cert.der  openssl-CLI-minted Ed25519 cert, used only by the TLS
                            pin-extraction test
  README.md (this file)
```

## Toolchain and opam packages

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
eval "$(opam env --root "$CATALYST_TOOLS/opam" --switch catalyst)"
```

OCaml 5.2.1, dune 3.23.1 (both from the catalyst-tools switch). Installed into the
existing `catalyst` opam switch (no new switch created, per the toolchain's caveat about
opam switches not being relocatable):

| Package | Version | Why |
|---|---|---|
| `mirage-crypto` | 0.11.3 | AES-256-GCM (`Cipher_block.AES.GCM`) and ChaCha20-Poly1305 (`Chacha20`), both real AEAD constructions, not libsodium (whose AES-256-GCM is AES-NI-hardware-gated and not portable). |
| `mirage-crypto-ec` | 0.11.3 | Ed25519 (`Mirage_crypto_ec.Ed25519`) and X25519 (`Mirage_crypto_ec.X25519`), Fiat-Crypto-derived, constant-time. |
| `mirage-crypto-rng` | 0.11.3 | CSPRNG (Fortuna) for key/nonce/state generation. |
| `mirage-crypto-rng.unix` | 0.11.3 (sub-library) | Seeds the default generator from `getrandom(2)`/CPU RNG for production key generation. |
| `hkdf` | 1.0.4 (upstream-deprecated, still the right package -- see note below) | RFC 5869 HKDF-SHA256 for the callback sealed-box KDF. |
| `digestif` | 1.3.0 | SHA-256 for the `fingerprint` function (string-native API with built-in hex encoding, used at the hottest call site in the SDK). |
| `cstruct` | 6.2.0 | Transitive requirement of the three packages above; this SDK's own public API is plain `string`, converting to/from `Cstruct.t` only at crypto call sites. |
| `tls` | 0.17.5 | TLS 1.2/1.3 client engine (`Tls.Engine`), used for the pinned CSIL-RPC transport. |
| `x509` | 0.16.5 | Certificate parsing, including native Ed25519 `SubjectPublicKeyInfo` support. |
| `ptime` | 1.2.0 | POSIX time type `tls`/`x509`'s APIs require for certificate-validity checks. |
| `domain-name` | 0.5.0 | `[`host] Domain_name.t` type `Tls.Config.client`'s `peer_name` wants. |
| `yojson` | 3.0.0 (test only) | Parses the JSON conformance vectors. |
| `alcotest` | 1.9.1 (test only) | Test runner/assertions. |

`hkdf`'s opam metadata carries a `deprecated` flag but the package is still published,
still installs cleanly, and there is no successor package that does the same job with a
smaller footprint (the deprecation appears to be about maintenance status, not a
replacement) — kept because `mirage-crypto`/`mirage-crypto-ec` don't ship HKDF
themselves, so a hand-rolled HMAC-based HKDF would just be re-implementing this exact
~40-line package. Flag it for review on future updates.

No vendored-C route, no libsodium. Every crypto primitive is pure OCaml (Fiat-Crypto
constant-time field arithmetic for the elliptic-curve work).

## TLS evaluation (design doc / task instructions required this)

The evaluation looked at whether `tls` (ocaml-tls) supports Ed25519 server certificates
and exposes the peer certificate for the mandatory manual SPKI pin check:

- **`x509` (0.16.5) supports Ed25519 certificates directly** — `X509.Public_key.t` has an
  `` `ED25519 of Mirage_crypto_ec.Ed25519.pub`` constructor, and
  `X509.Certificate.public_key` exposes it. Not a fallback path; a first-class case.
- **`tls` (0.17.5) exposes exactly the pin-check hook needed**: `Tls.Config.client
  ~authenticator ...` takes an `X509.Authenticator.t = ?ip:_ -> host:_ ->
  Certificate.t list -> Validation.r`, invoked *with* the peer's certificate chain
  during the handshake itself. This is cleaner than the Ruby reference SDK's approach
  (which has to set `OpenSSL::SSL::VERIFY_NONE` and pin manually post-handshake, because
  Ruby's OpenSSL binding can't express "verify only by SPKI pin"): here the pin check
  *is* the authenticator, enforced natively, and a mismatch fails the handshake before
  any application byte is exchanged.
- **Gotcha found during the evaluation**: `X509.Public_key.fingerprint` (and the
  ready-made `X509.Authenticator.server_key_fingerprint`) hash the ASN.1-encoded
  SubjectPublicKeyInfo DER structure (confirmed by reading `x509`'s own
  `public_key.ml`: `Mirage_crypto.Hash.digest hash (Asn.pub_info_to_cstruct pub)`), which
  is **not** the LinkKeys fingerprint convention (sha256 of the raw 32-byte Ed25519
  public key only, matching DNS `fp=` records and `crates/linkkeys/src/tcp/tls.rs`).
  Using the ready-made fingerprint authenticator would have silently pinned against the
  wrong hash. `tls_client.ml` instead extracts the raw Ed25519 public key via
  `X509.Certificate.public_key` → `` `ED25519 pub`` → `Mirage_crypto_ec.Ed25519.pub_to_cstruct`
  and computes this SDK's own `Crypto.fingerprint` over exactly those 32 bytes.
- **Remaining gap**: the standalone `tls` package is a *pure state machine*
  (`Tls.Engine`) with no bundled blocking I/O driver — only Lwt/Async/Eio/Miou driver
  packages exist (`tls-lwt`, `tls-async`, `tls-eio`, `tls-miou-unix`). Pulling in an
  entire async runtime (e.g. Lwt) purely to get TLS I/O, when every other module in this
  SDK is deliberately synchronous/blocking (matching the Go/Ruby/C# siblings' style and
  this project's "every dependency is a liability" rule), was judged not worth it for
  one I/O driver. `tls_client.ml` instead hand-drives `Tls.Engine` directly over a
  blocking `Unix.file_descr` (the handshake loop and application-data read/write) — real,
  working TLS 1.2/1.3 client code (Ed25519 leaf certs and all), not a stub, but it has
  never been exercised against a live LinkKeys server in this environment (none is
  reachable here). Treat the handshake loop as reviewed-but-field-untested.

**What is actually tested** (`dune runtest`, no live server needed):

- `tls_client.ml`'s pin-extraction logic (`leaf_fingerprint_of_der`,
  `pin_authenticator`) against a real **openssl-CLI-minted Ed25519 certificate
  fixture's DER bytes** (`test/fixtures/ed25519_cert.der`), with the expected
  fingerprint computed independently via the openssl CLI:

  ```sh
  openssl genpkey -algorithm ed25519 -out key.pem
  openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/CN=fixture"
  openssl x509 -in cert.pem -outform DER -out cert.der
  openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform DER -out pub.der
  python3 -c "import hashlib; print(hashlib.sha256(open('pub.der','rb').read()[-32:]).hexdigest())"
  ```

- `rpc.ml`'s length-prefix framing and CSIL-RPC envelope encode/decode, in-memory (no
  socket, no TLS).
- The full cryptographic verification chain `complete_local_login` runs internally
  (envelope verify, sealed-box open, header/payload cross-check, audience/issuer/
  callback-URL/nonce-state checks, ticket-redemption possession proof, claim signature
  verification) via flow tests that call the same `Local_rp`/`Claims`/`Revocation`
  functions `complete_local_login` calls, in the same order, with a directly-supplied
  "fetched" domain-key set standing in for what `Rpc.fetch_domain_keys` would have
  returned over the (untestable-here) TLS transport. This is "whatever seam is honest"
  for this environment — see `test/run_tests.ml`'s flow-test module docs for the full
  rationale.

## DNS decision

No `ocaml-dns` dependency: `dns.ml` hand-rolls a small (~100 line), bounded UDP DNS TXT
query directly over a `Unix.SOCK_DGRAM` socket, reading the resolver address from
`/etc/resolv.conf` (falling back to `127.0.0.1`) — the same approach the sibling
C#/Dart/Zig SDKs take, and a smaller, more auditable footprint than a general DNS stack
for a package that only ever needs TXT lookups of two fixed record names. The resolver
is injectable (`Dns.resolver = { txt_lookup : string -> string list }`); a caller wanting
DoH or another hardened resolver supplies their own value.

## App responsibilities

- Persist the bytes from `local_rp_identity_to_bytes` with ordinary application-secret
  care (same tier as a database credential or API key).
- Persist `pending_login` between `begin_local_login` and `complete_local_login` (e.g.
  via `Begin_login.pending_login_to_fields`/`_of_fields` into a session store), and
  discard it after one completion attempt — this package owns no storage and cannot
  enforce single-use itself.
- Sessions, local user records, authorization: entirely the app's. This package returns
  verified protocol facts; it never creates a session or writes to an app database.

## Security notes

- Revoking a local RP identity at the IDP kills future logins **and** any outstanding
  claim tickets immediately, but does **not** reach into sessions the app already
  minted from a prior successful login.
- Key rotation is not a continuity operation: generating a new identity means a new
  fingerprint and re-approval at every LinkKeys domain.
- Domain keys fetched over the network are only ever trusted after DNS `fp=` pinning
  (`Dns.trust_keys`, consulted by `Rpc.fetch_domain_keys`) — an unpinned/unauthenticated
  key can never reach the verification chain.
- The default DNS resolver is this package's own UDP TXT query against the system's
  configured nameserver; LAN resolver spoofing is an accepted, documented tradeoff for
  this mode (per the design doc). Inject a hardened resolver if your deployment needs
  more.
- Private key material (`signing_private_key`, `encryption_private_key`) is never
  logged by this package. `Error.t` messages never include key material, nonces,
  tokens, tickets, or claim values.
- The `Transport.t` default (`Transport.default_transport`) is deliberately
  *permissive* (connects to loopback/private/LAN addresses) — this mode's entire point
  is a LAN app talking to a LinkKeys domain that may itself be LAN/loopback-only.
  `Transport.Std_transport.create ~policy:Transport.Public_only ()` is available for
  integrators who want the stricter, server-style SSRF posture instead.

## Test command

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
eval "$(opam env --root "$CATALYST_TOOLS/opam" --switch catalyst)"
cd sdks/local-rp/ocaml && dune runtest
```

17 test cases, all green: `keys.json`, `envelopes.json` (cases + all 20 negative
cases), `callback_box.json` (both suites' positive cases + all 13 negative cases),
`url_params.json` (both cases + both negative cases), `dns.json` (all valid/invalid
`_linkkeys`/`_linkkeys_apis` cases), `tickets.json`, `expirations.json`
(`check_expirations` + `check_timestamps`), `revocations.json` (all 9 certificate cases
+ the before/after-revocation application case), TLS pin extraction, RPC framing, and 7
flow tests (happy path, wrong-signer-key rejection, unadvertised-suite rejection,
wrong-identity ticket-redemption-signature rejection, `check_expirations` facade,
identity byte round-trip, and a `Claim.claim_value` wire-type regression test).
Every conformance-vector test iterates the JSON arrays directly (no hardcoded
subset), so case counts always match the vector files exactly.

Note on the `claim_value` regression test: no shared conformance vector contains a
`Claim` struct at all (none of the eight files carries a `Claim` or a
`LocalRpTicketRedemptionResponse`), so the vectors cannot catch a Claim-codec wire-type
error -- an earlier revision of this SDK encoded `claim_value` as CBOR text instead of
bytes and passed the full vector suite anyway. The local regression test pins the
correct wire type (CSIL `claim_value: bytes`, matching the generated Rust codec's
`cbor_bytes`) until the shared vectors grow a Claim case.

## Unresolved / known limitations

- The `tls_client.ml` blocking handshake driver has not been exercised against a live
  LinkKeys server in this environment (none is reachable here) — see "TLS evaluation"
  above. It is real, reviewed code, not a stub, built on `tls`'s pure `Engine` module,
  but should be treated as field-untested until run against a real domain's TCP CSIL-RPC
  endpoint.
- No csilgen OCaml target exists yet; `cbor.ml`, `types.ml`, and the envelope/framing
  half of `rpc.ml` are hand-written pending one. Request filed:
  `~/repos/catalystcommunity/csilgen/docs/csilgen-requests/ocaml-target-does-not-exist.md`
  (`Status: open`).
