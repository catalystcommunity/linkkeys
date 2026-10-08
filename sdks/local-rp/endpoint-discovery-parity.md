# Browser endpoint discovery parity across local-RP SDKs

Status: Done
Date: 2026-08-17 (opened), 2026-09-16 (all SDKs complete)

## Background

The begin step of the local-RP flow must not send the browser to the
identity domain itself. The identity domain (for example `todandlorna.com`)
is a trust and discovery domain. The `_linkkeys_apis.<identity-domain>` TXT
record's `https=` value names the browser-facing host (see
`docs/spec/trust-and-anchors.md`). A begin implementation that builds
`https://<identity-domain>/auth/local-rp` sends the user to the wrong host
whenever the two differ, and forces each consumer to rediscover and rewrite
the URL (Reactorcide did exactly that).

## The contract every SDK now implements

The Go SDK (`sdks/local-rp/go/browser.go`) is the reference. Every SDK
below implements the same behavior:

- An exported browser-base resolver reads `_linkkeys_apis.<identityDomain>`
  through the SDK's existing DNS seam and existing `_linkkeys_apis` parser.
  It selects the first valid LinkKeys v1 record with an `https=` endpoint.
  It validates the base: https only, host present, optional path prefix,
  no userinfo, query, or fragment. It returns an error when the lookup
  fails or no record yields a valid base.
- An exported browser-endpoint builder joins the base, a route
  (`/auth/local-rp` or `/auth/authorize`, exported constants), and the
  `signed_request` query parameter with the language's URL facilities. A
  path prefix in `https=` is preserved. The `signed_request` value passes
  through byte-identically.
- The begin step calls both with an injectable resolver. An omitted
  resolver selects the SDK's default system resolver. The begin step falls
  back to `https://<identityDomain>` when the DNS lookup fails, no valid
  record carries `https=`, or the discovered base is invalid.
- The pending-login user domain stays the identity domain. Verification is
  bound to the identity domain, never to the discovered service host.
- Nine test cases with a fake resolver (no live DNS): discovered host used,
  path prefix preserved, tcp-only fallback, DNS-error fallback, invalid
  record ignored, first valid record selected, `signed_request` round-trip,
  identity domain retained, resolver-omitted caller still works. Plus
  direct tests of the exported helpers.
- README and package docs describe discovery, resolver injection, and the
  fallback rule.

The begin step is no longer fully offline in any SDK. It performs one DNS
TXT lookup with a defined fallback.

## Per-SDK status

| SDK | Module | Notes |
| --- | --- | --- |
| go | `go/browser.go` | Reference implementation. |
| rust | `rust/src/browser.rs` | `dns: Option<&dyn DnsResolver>` on the begin config. Direct `url` dependency added; the crate was already in the tree. |
| typescript | `typescript/src/browser.ts` | **`beginLocalLogin` is now `async`.** Callers must `await` it. |
| python | `python/linkkeys_local_rp/browser.py` | `dns=None` on `BeginLocalLoginConfig`. |
| ruby | `ruby/lib/linkkeys_local_rp/browser.rb` | `:dns` struct member on the begin config. |
| elixir | `elixir/lib/linkkeys_local_rp/browser.ex` | `:dns` key on the begin config. `example.md` regular-RP glue still has its own `resolve_api_base`; it can delegate to `Browser` in a later change. |
| java | `java/.../Browser.java` | `BeginLocalLoginConfig.dns` (null = default). |
| kotlin | wraps Java | `beginLocalLogin(..., dns = defaultDnsResolver())` plus Kotlin wrappers and `BrowserRoutes`. |
| csharp | `csharp/src/LinkKeys.LocalRp/Browser.cs` | Trailing optional `IDnsResolver? Dns = null` record parameter. |
| dart | `dart/lib/src/browser.dart` | `BeginLocalLoginConfig.dns`. `beginLocalLogin` was already a `Future`. |
| zig | `zig/src/browser.zig` | `dns: ?DnsResolver = null` on the begin config. |
| c | `c/src/browser.c`, `c/src/browser.h` | New `dns` pointer at the end of `lrp_begin_login_config`. Hand-written strict `https://host[:port][/path]` grammar; C has no URL library. |
| ocaml | `ocaml/lib/browser.ml` | `make_config ?dns`. A caller that builds the `Begin_login.config` record literally must add the `dns` field. Hand-written validator; `uri` is not a dependency. |

## Consumers

Consumers redirect to the returned URL without parsing or rewriting it.
The Reactorcide Go consumer already injects its own resolver into
`BeginLocalLogin` and no longer rewrites the URL.

## Verification

Run `./tools.sh test-local-rp-all` from the repository root. It runs every
local-RP SDK test suite in sequence.
