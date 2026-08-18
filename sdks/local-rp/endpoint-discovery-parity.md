# Follow-up: browser endpoint discovery parity across local-RP SDKs

Status: Open
Date: 2026-08-17

## Background

The begin step of the local-RP flow must not send the browser to the
identity domain itself. The identity domain (for example `todandlorna.com`)
is a trust and discovery domain. The `_linkkeys_apis.<identity-domain>` TXT
record's `https=` value names the browser-facing host (see
`docs/spec/trust-and-anchors.md`). A begin implementation that builds
`https://<identity-domain>/auth/local-rp` sends the user to the wrong host
whenever the two differ, and forces each consumer to rediscover and rewrite
the URL (Reactorcide did exactly that).

The Go SDK now performs this discovery itself (`sdks/local-rp/go/browser.go`):

- `ResolveBrowserBase(dns, identityDomain)` reads
  `_linkkeys_apis.<identityDomain>` and selects the first valid LinkKeys v1
  record with an `https=` endpoint. It validates the base (https only, host
  present, optional path prefix, no userinfo/query/fragment).
- `BuildBrowserEndpoint(base, route, signedRequest)` joins the base, the
  route (`/auth/local-rp` or `/auth/authorize`), and the `signed_request`
  query parameter with real URL handling — a path prefix in `https=` is
  preserved.
- `BeginLocalLogin` composes the two, takes an injectable resolver
  (`BeginLocalLoginConfig.DNS`, default system resolver), and falls back to
  `https://<identityDomain>` when DNS lookup fails, no valid record carries
  `https=`, or the discovered base is invalid.
- `PendingLogin.UserDomain` stays the identity domain. Verification stays
  bound to the identity domain, never to the discovered service host.

Go tests cover: discovered host used, path prefix preserved, tcp-only
fallback, DNS-error fallback, invalid records ignored, first-valid-record
selection, `signed_request` round-trip, identity-domain retention, and
resolver-omitted compatibility (`sdks/local-rp/go/browser_test.go`).

## Affected SDKs

Every other maintained SDK still hard-codes
`https://<user-domain>/auth/local-rp?signed_request=...` in its begin step.
Each already has a DNS TXT resolver seam and the `_linkkeys_apis` parser
(used by its complete step), so the parity work reuses existing pieces —
do not add a second TXT parser.

| SDK | Begin construction to replace |
| --- | --- |
| rust | `sdks/local-rp/rust/src/begin.rs` (`format!("https://{}/auth/local-rp...")`) |
| typescript | `sdks/local-rp/typescript/src/begin.ts` (template literal) |
| python | `sdks/local-rp/python/linkkeys_local_rp/begin.py` (f-string) |
| ruby | `sdks/local-rp/ruby/lib/linkkeys_local_rp/begin.rb` |
| elixir | `sdks/local-rp/elixir/lib/linkkeys_local_rp/begin.ex` |
| java | `sdks/local-rp/java/src/main/java/community/catalyst/linkkeys/localrp/Begin.java` |
| kotlin | wraps the Java SDK (`Login.kt`); fixed transitively by the Java change |
| csharp | `sdks/local-rp/csharp/src/LinkKeys.LocalRp/Begin.cs` |
| dart | `sdks/local-rp/dart/lib/src/begin.dart` |
| zig | `sdks/local-rp/zig/src/begin.zig` |
| c | `sdks/local-rp/c/src/begin.c` |
| ocaml | `sdks/local-rp/ocaml/lib/begin_login.ml` |
| php | `sdks/local-rp/php/src/Begin.php` |

## Required work per SDK

1. Add an exported browser-base resolver and endpoint builder equivalent to
   the Go helpers, reusing the SDK's existing DNS seam and
   `_linkkeys_apis` parser.
2. Make the begin step call them, with an injectable resolver and the same
   fallback rules (fall back to `https://<identity-domain>` on lookup
   failure, no valid `https=`, or an invalid base).
3. Keep the pending-login identity domain unchanged.
4. Build the URL with the language's URL library, not string concatenation;
   preserve an `https=` path prefix; never allow a non-HTTPS scheme.
5. Port the nine Go test cases with a fake resolver (no live DNS in unit
   tests).
6. Update the SDK's README/package docs.

The begin step stops being fully offline in every SDK: it gains one DNS TXT
lookup with a defined fallback. Mirror the Go doc comments when porting.

## Consumers

After parity lands in an SDK, its consumers redirect to the returned URL
without parsing or rewriting it. The Reactorcide Go consumer
(`coordinator_api/internal/auth/backend_localrp.go`) can drop its own
discovery-and-rewrite once it adopts the updated Go SDK.
