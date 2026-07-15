# Building an app on DNS-less local RP identity

This is the app-developer guide for LinkKeys' DNS-less local RP mode: how a
locally installed app (a LAN jukebox, a desktop tool, a self-hosted service
with no public DNS) uses a LinkKeys domain for login without running its own
DNS-pinned relying party. The app's identity is the fingerprint of a
locally-generated Ed25519 signing key — SSH-host-key style — not a domain.

This guide covers the generic flow and the responsibilities every SDK
deliberately leaves to your app. It does not duplicate any SDK's quickstart
or API reference: read your language's SDK README for exact function
signatures, types, and idioms — see "Pick your SDK" below.

For the full protocol design, see
[`dns-less-local-rp-design.md`](../dns-less-local-rp-design.md) at the repo
root. For what your domain admin will see and decide, see
[`local-rp-admin-guide.md`](local-rp-admin-guide.md).

## The generic flow

1. **Generate an identity once**, at install/setup time — one signing
   keypair, one encryption keypair, bundled with a self-signed descriptor.
   Every SDK calls this `generate_local_rp_identity` (language-cased, e.g.
   `generateLocalRpIdentity` in Dart/TypeScript).
2. **Store the raw key bytes** wherever your app already stores its own
   secrets/configuration. Every SDK exposes byte import/export helpers
   (`local_rp_identity_to_bytes` / `local_rp_identity_from_bytes`, plus
   narrower per-key variants) so you never have to invent an encoding.
   Treat these bytes with the same care as a database credential or API
   key — see "What the SDK deliberately does not own" below.
3. **Begin a login** (`begin_local_login`) when a user wants to log in and
   has told your app which LinkKeys domain to use. This builds and signs a
   login request and returns two things: a redirect URL, and a
   `PendingLogin` state object your app must persist (see below).
4. **Redirect the user's browser** to that URL. What "redirect" means is
   entirely up to your app — an HTTP 302, a link, an embedded webview, a
   desktop app opening the system browser. The SDK never opens a browser
   itself; it only builds the URL (design doc: "Opening a browser is a UX
   decision outside the LinkKeys SDK").
5. **Complete the login** (`complete_local_login`) when the browser arrives
   back at your callback URL carrying an `encrypted_token=` query
   parameter. Pass the SDK: your key material, the `PendingLogin` from step
   3, the raw callback data, the full URL the request actually arrived at,
   and the current time. The SDK verifies everything (signatures, issuer
   binding, audience, expiry, nonce/state, revocations) and, as part of
   completion, redeems the embedded claim ticket directly with the user's
   IDP over TCP CSIL-RPC to fetch the actual claim values. You get back
   verified user id/domain, claims, the domain keys used, and metadata.

The callback carries a **claim-get ticket**, not the claims themselves — the
browser round-trip stays small (fits in a GET redirect query parameter), and
claims move over a direct RP↔IDP channel your SDK opens itself, over TCP.
Ticket redemption is TCP-only; there is no HTTP fallback.

## What your app owns that the SDK deliberately does not

Every local-RP SDK returns verified protocol facts and stops there. Per the
design doc's "SDK API Shape": *"SDKs must not own application storage,
sessions, database writes, or local user authorization."* Concretely:

- **`PendingLogin` is single-use.** Persist it between `begin_local_login`
  and `complete_local_login` (a server-side session tied to the browser is
  the natural place), and **discard it after one completion attempt**. The
  SDK owns no storage and cannot enforce single-use itself — replay
  protection at the app boundary is your job. If your app lets
  `complete_local_login` be called twice with the same pending state, that
  is a replay hole the SDK cannot close for you.
- **Session creation.** The SDK never mints a session, cookie, or token for
  your app. You take the verified `user_id`/`user_domain`/claims and decide
  what a "logged in" session means in your app.
- **Key material storage.** The private signing and encryption keys in your
  identity bundle don't directly identify an end user, but they control
  your app's entire local RP identity — anyone holding them can sign login
  requests and redeem claim tickets as your app. Store them with ordinary
  application-secret care, not merely as configuration.
- **Local user records and authorization decisions.** Whether a verified
  LinkKeys identity maps to an existing local account, a new one, or is
  denied outright is entirely your app's business logic.

## Pick your SDK

Fourteen languages have a shipped, conformance-tested SDK under
`sdks/local-rp/`. Each one's README is the primary reference for that
language's exact API, dependencies, and quickstart:

| Language | README |
|---|---|
| Rust | [`sdks/local-rp/rust/README.md`](../sdks/local-rp/rust/README.md) |
| Go | [`sdks/local-rp/go/README.md`](../sdks/local-rp/go/README.md) |
| TypeScript / Node | [`sdks/local-rp/typescript/README.md`](../sdks/local-rp/typescript/README.md) |
| Python | [`sdks/local-rp/python/README.md`](../sdks/local-rp/python/README.md) |
| PHP | [`sdks/local-rp/php/README.md`](../sdks/local-rp/php/README.md) |
| Java | [`sdks/local-rp/java/README.md`](../sdks/local-rp/java/README.md) |
| Kotlin | [`sdks/local-rp/kotlin/README.md`](../sdks/local-rp/kotlin/README.md) |
| C#/.NET | [`sdks/local-rp/csharp/README.md`](../sdks/local-rp/csharp/README.md) |
| Dart | [`sdks/local-rp/dart/README.md`](../sdks/local-rp/dart/README.md) |
| Ruby | [`sdks/local-rp/ruby/README.md`](../sdks/local-rp/ruby/README.md) |
| Elixir | [`sdks/local-rp/elixir/README.md`](../sdks/local-rp/elixir/README.md) |
| C | [`sdks/local-rp/c/README.md`](../sdks/local-rp/c/README.md) |
| Zig | [`sdks/local-rp/zig/README.md`](../sdks/local-rp/zig/README.md) |
| OCaml | [`sdks/local-rp/ocaml/README.md`](../sdks/local-rp/ocaml/README.md) |

Swift is deliberately unimplemented for now — no Swift toolchain was
available when the SDKs were built; the shared conformance vectors
(`sdks/local-rp/conformance/`) make a future implementation well-bounded.

Rust's SDK joins the main Cargo workspace (it's a thin wrapper over
`liblinkkeys`); every other SDK stands alone with its own toolchain, mirroring
the csilgen transport-library pattern. Run `./tools.sh test-local-rp-<lang>`
(e.g. `test-local-rp-go`, `test-local-rp-python`) to run any one SDK's test
suite locally, or `./tools.sh test-local-rp-all` for all of them; see
`./tools.sh` with no arguments for the full command list.

## The default claim set

If you don't specify claims when calling `begin_local_login`, every SDK
requests:

- **Requested:** `display_name`, `email`, `handle`
- **Required:** `handle`

This gives a usable "identity" out of the box with zero claim configuration.
You can pass any other requested/required claim set explicitly — these are
just the defaults.

## Platform caveats

Read the language matrix in the design doc's "Language Crypto Matrix"
section for the full research; the two production-relevant blockers and one
explicit non-target are:

| Platform | Status | Why |
|---|---|---|
| **Dart** | Client TLS blocked | `dart:io`'s BoringSSL-backed TLS client refuses to negotiate a handshake against a server presenting an Ed25519 certificate (`NO_COMMON_SIGNATURE_ALGORITHMS`) — and LinkKeys domain TLS certs are Ed25519. The Dart SDK is fully implemented and vector-conformant, but cannot reach a real IDP over the pinned TCP path until Dart's TLS stack supports Ed25519 certs, or LinkKeys offers an alternate-key certificate. See the Dart README's "Known limitations" for the empirical error and detail. |
| **Zig** | Supply your own pinned dial | `std.crypto.tls.Client` (as of the pinned toolchain version) exposes no peer-certificate hook, so SPKI pin verification is impossible with stdlib TLS alone. The Zig SDK fails closed (`error.PinnedTlsUnavailable`) rather than connecting unpinned; you must inject a pinning-capable `SecureDial` (e.g. shelling out to a system TLS library) before this SDK can reach a real network peer. The pin-extraction logic itself is implemented and tested, ready to slot into a real implementation once one exists. |
| **TypeScript / browser** | Never a target, by design | The TypeScript SDK is Node-only. A browser-resident local RP identity would mean the RP's private signing key lives in browser storage — the design doc calls this out directly as something to never do. If you need a local RP identity compiled to WASM, compile `liblinkkeys` itself and own the consequences; this is explicitly out of scope for the TypeScript SDK. |

## Network access your app needs

Your app does not need any inbound network access. It needs outbound access
to:

- The user's LinkKeys domain, over TCP CSIL-RPC: public keys, revocations,
  claim-ticket redemption.
- Any claim-signer domains referenced by the claims you requested, over TCP
  CSIL-RPC: public keys and revocations, to verify claim signatures.
- DNS TXT lookups for `_linkkeys.{domain}` (`fp=` pins) and
  `_linkkeys_apis.{domain}` (`tcp=` endpoint) records.

Every SDK's transport and DNS-resolver seams are injectable — the default
DNS resolver is the OS-configured system resolver (the easiest path); supply
a hardened resolver (e.g. DoH) if your deployment wants that. See your SDK's
README, "Security notes" section, for the exact seam names.
