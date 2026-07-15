# Worked example: accepting regular (DNS-pinned) LinkKeys logins in Go

This document is **not** about the `localrp` package this directory implements.
That package is for the *DNS-less local RP* mode (`dns-less-local-rp-design.md`
at the repo root) — apps with no public DNS, identified by a locally-generated
key fingerprint instead of a domain.

This document is for the far more common case: a Go web app that has (or is
willing to run) its own domain, and wants to accept logins from any LinkKeys
identity — "Sign in with LinkKeys" for `alice@example.com`. That's **regular
RP mode**. There is no packaged Go SDK for it (see "Why there's no packaged
client" below); this document shows you the ~150 lines of glue you write
yourself, reusing the pieces of this local-RP SDK that are already exported
and reusable.

Everything below was compiled and `go vet`-checked as a real module before
being pasted into this document — see "What was compiled" at the end.

## Architecture

Per `docs/DEPLOYING-RP.md`: your app runs alongside its **own** LinkKeys
server deployed in RP mode (the same Docker image/binary as a full identity
provider, different configuration — `ENABLE_RP_ENDPOINTS`/`rp.enabled` Helm
values). The RP server holds your domain's private keys, signs auth requests,
and decrypts callback tokens on your behalf. **Your app never touches private
keys** — it authenticates to its own RP server with a plain API key over TCP
CSIL-RPC and asks it to do the crypto.

```
┌──────────────────────────────────────────────────────────┐
│                   Your Application Stack                  │
│                                                            │
│   ┌──────────────┐  TCP CSIL-RPC   ┌────────────────────┐ │
│   │   Go Web App │  (API-key auth, │  LinkKeys RP Server │ │
│   │              │  TLS pinned to  │  (same linkkeys     │ │
│   │  This doc's  │──DNS `fp=`────►│   image, RP config)  │ │
│   │  glue code   │                 │  Holds domain keys  │ │
│   └──────┬───────┘                 └──────────┬──────────┘ │
│          │ HTTP redirect                       │ TCP CSIL-RPC
└──────────┼──────────────────────────────────────┼──────────┘
           ▼                                       ▼
     user's browser                    the *user's* LinkKeys domain
   (goes to their IDP's                (verify-assertion / userinfo-fetch
    /auth/authorize)                    make an onward S2S call here)
```

## Prerequisites

1. **Deploy your RP server.** Follow `docs/DEPLOYING-RP.md` end to end
   (Helm chart with `rp.enabled: true`, `linkkeys domain init` inside the pod,
   and publish the `_linkkeys`/`_linkkeys_apis` DNS TXT records it prints via
   `linkkeys domain dns-check`). You need a real domain you control — this is
   what makes it "regular" (DNS-pinned) RP mode as opposed to local-RP mode.

2. **Create a service account (API key) for your app and grant it
   `api_access`.** This is not optional: every `Rp` CSIL-RPC operation
   (`sign-request`, `decrypt-token`, `verify-assertion`, `userinfo-fetch`,
   `issue-attestation`) requires the caller's key to hold the dedicated
   `api_access` relation on the RP's domain (SEC-06,
   `crates/linkkeys/src/services/authorization.rs:102`, gated in
   `crates/linkkeys/src/tcp/mod.rs` around line 795). A bare valid API key is
   **not** enough — you'll see `server error (4): Forbidden` from
   `resp.AsTransportError()` until it's granted, and nothing provisions it
   automatically (no startup/Helm bootstrap step does this for you).

   One command does both (mint the key and grant the relation together):

   ```sh
   kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- \
     linkkeys user create my-webapp "My Web Application" --api-key --relation api_access
   # Save the printed API key — it is shown exactly once.
   ```

   If you already minted a key without `--relation` or need to repair an
   under-provisioned key, grant it
   separately — this is DB-direct and idempotent, so it's also how you
   bootstrap the very first key (`relation grant` over TCP needs an admin key
   to already exist; this doesn't):

   ```sh
   kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- \
     linkkeys relation grant-local my-webapp api_access
   ```

   This repo's own cluster wrappers do the same two things:
   `./deploy/live.sh api-key <user> <relation...>` (mint + grant) and
   `./deploy/live.sh grant <user> <relation>` (grant to an existing user).

   `api_access` is one of five relations `user create --relation` /
   `relation grant-local` validate against
   (`GRANTABLE_RELATIONS` in `services/authorization.rs`): `admin`,
   `manage_users`, `manage_claims`, `api_access`, `issue_claims`. Grant only
   `api_access` — least privilege for a pure RP delegate.

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

Six steps, all but the browser redirect happening over TCP CSIL-RPC to your
own RP server (**not** the user's IDP — your RP server makes any onward
server-to-server calls to the IDP on your behalf):

1. **`Rp/sign-request`** `{callback_url, nonce, ?requested_claims}` →
   `{signed_request}`. Your app picks a fresh single-use `nonce` and its own
   callback URL; the RP server signs an auth request with your domain key.
   Omit `requested_claims` to fall back to the RP server's own
   `RP_CLAIMS_CONFIG`-configured defaults.
2. **Redirect the browser** to
   `https://<user_domain>/auth/authorize?signed_request=<signed_request>`
   (optionally `&user_hint=<hint>`). `user_domain` is whatever LinkKeys
   domain the *user* chose to log in with (e.g. from an
   `alice@example.com`-shaped identity string) — this is **not** your RP's
   own domain. The IDP's `GET /auth/authorize` route only reads
   `signed_request` and `user_hint`
   (`crates/linkkeys/src/web/mod.rs:1418`); no other query parameters matter.
3. The user authenticates and consents at their IDP, which redirects back to
   your `callback_url` with `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** `{encrypted_token}` → `{signed_assertion}`. Only
   your RP server (holder of your domain's private key) can decrypt this.
5. **`Rp/verify-assertion`** `{signed_assertion, expected_domain}` →
   `{assertion, verified}`. Your RP server checks the assertion's signature
   against the *issuing* domain's published keys. **Check `verified` — a
   `nil` Go error only means the call round-tripped, not that the assertion
   is trustworthy.** Reject unless `verified == true`. Nonce single-use is
   your app's job (see below) — this call does not enforce it.
6. **Optional: `Rp/userinfo-fetch`** `{token, api_base, domain}` →
   `UserInfo{user_id, domain, display_name, claims}`. Fetches the user's
   consented claims. `token` is the **`signed_assertion` string from step 4's
   decrypt-token result** — not the raw `encrypted_token` from the callback.
   The CSIL doc comment on `RpUserInfoRequest.token` says exactly this
   ("URL-param-encoded SignedIdentityAssertion (the decrypt-token result)"),
   and the IDP end of the chain parses it as one
   (`Identity/get-user-info` in `crates/linkkeys/src/tcp/mod.rs` runs it
   through `assertion_from_url_param`). Skip this step if you only need proof
   of identity (no claims).

## API-key envelope auth

All five `Rp` operations are authenticated the same way: the API key rides
the CSIL-RPC envelope's `auth` field, not an application-level parameter.
Server-side, `crates/linkkeys/src/tcp/mod.rs`'s `authenticate_tcp_request`
reads exactly `envelope.auth` (an `Option<String>`); the Go transport
library's request builder exposes this as
`RpcRequest.WithAuth(apiKey string)` (`csilgen/transports/go/rpc.go`). There
is no client certificate involved on this leg — your app presents no domain
key of its own; it's the RP server that holds one, which is why the app
authenticates with a bearer-style API key instead.

## Why there's no packaged client — and what this example reuses

`sdks/local-rp/go`'s `rpc.go` doc comment explains why this SDK hand-builds
CSIL-RPC calls instead of using csilgen's generated `go-client` target: at
the time, that generator emitted a lowercased/re-cased service and op name
instead of the verbatim CSIL names the server's dispatch matches on. That
csilgen defect has since been fixed (regenerated clients emit
`"DomainKeys"`/`"get-domain-keys"` verbatim), so a generated `Rp` client is
now a viable alternative. Until a Go regular-RP SDK is packaged either way,
this is why the pattern below — building
requests directly against `RpcRequest`/`RpcResponse`/`StreamCarrier` with
literal, correct strings — is the right one for `Rp`, too, and it's exactly
what `demoappsite/src/main.rs` (the Rust reference integration) does for the
same reason.

This example reuses two things from this repository, both **already
exported** and safe for an external app to depend on:

- **`github.com/catalystcommunity/csilgen/transports/go`** — the CSIL-RPC
  envelope codec and framing (`RpcRequest`/`RpcResponse`/`StreamCarrier`).
  Not part of this SDK; a standalone transport library this SDK itself
  depends on the same way.
- **`github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated`**
  (package `api`) — the CSIL-generated `Rp*Request`/`Rp*Response` structs and
  their `Encode*`/`Decode*` functions. This subpackage is generic generated
  types + codec for the *whole* `linkkeys.csil`, not local-RP-specific; it
  happens to live under this SDK's module because that's where it's checked
  in, but it has no dependency on anything local-RP-specific.

It also reuses a few small **exported** helpers from the top-level `localrp`
package where doing so avoided reimplementing something this SDK already
gets right: `localrp.NewStdTransport()` (dial + timeouts),
`localrp.Fingerprint()` (the SPKI SHA-256 pin, `crypto.go:40`), and the DNS
TXT parsing helpers (`LinkKeysApisDNSName`, `ParseLinkKeysApisTXT`,
`DefaultDNSResolver`, `DnsResolver`) from `dns.go`.

**What it does *not* reuse, and why:** the actual TLS-pin-and-call routine
(`dialTLS` + `call` in `sdks/local-rp/go/rpc.go`) is unexported — it's
package-private plumbing for `DomainKeys`/`LocalRp` calls this SDK makes for
its own purposes, not a general-purpose client. Rather than changing the SDK
to export it, this example **inlines** an equivalent ~50-line routine
(`dialPinnedTLS` + `rpCall` below), built from the same exported primitives
(`Transport`, `Fingerprint`) `rpc.go` itself is built from. If a future
regular-RP Go SDK gets packaged, this is the piece it would centralize.

## The code

### `go.mod`

A real external app doesn't need a `replace` directive — per this SDK's own
`go.mod` comment, Go's module proxy resolves nested-module subdirectories by
commit pseudo-version directly from the public repo (the same way this SDK
itself depends on `github.com/catalystcommunity/csilgen/transports/go`). The
`replace` here exists only because this example was written and compiled
inside this repo, against an unpublished local checkout.

```go
module example.com/regularrp

go 1.26.4

require (
	github.com/catalystcommunity/csilgen/transports/go v0.0.0-20260713013116-a661c8727022
	github.com/catalystcommunity/linkkeys/sdks/local-rp/go v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// Delete this line in a real external app — see the paragraph above.
replace github.com/catalystcommunity/linkkeys/sdks/local-rp/go => /path/to/local/checkout/sdks/local-rp/go
```

### `rpclient.go` — the RP-call glue

```go
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	rpctransport "github.com/catalystcommunity/csilgen/transports/go"
	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// maxFrameSize bounds a single CSIL-RPC frame, matching the local-RP SDK's
// own cap (sdks/local-rp/go/rpc.go's maxFrameSize) so a malicious/compromised
// RP server can't drive this client to an unbounded allocation via a forged
// length prefix.
const maxFrameSize = 1024 * 1024

// rpConfig is this app's connection to its own co-located RP server: a TCP
// CSIL-RPC address, the RP server's DNS-pinned TLS fingerprints (printed by
// `linkkeys domain dns-check` on the RP, or fetched live from its `_linkkeys`
// TXT record), and the API key minted for this app (see "Prerequisites").
type rpConfig struct {
	tcpAddr      string
	fingerprints []string
	apiKey       string
}

func rpConfigFromEnv() (rpConfig, error) {
	cfg := rpConfig{
		tcpAddr:      os.Getenv("RP_TCP_ADDR"),
		fingerprints: splitNonEmpty(os.Getenv("RP_FINGERPRINTS"), ","),
		apiKey:       os.Getenv("RP_API_KEY"),
	}
	if cfg.tcpAddr == "" || len(cfg.fingerprints) == 0 || cfg.apiKey == "" {
		return rpConfig{}, fmt.Errorf("RP_TCP_ADDR, RP_FINGERPRINTS, and RP_API_KEY must all be set")
	}
	return cfg, nil
}

func splitNonEmpty(s, sep string) []string {
	var out []string
	for _, part := range strings.Split(s, sep) {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// dialPinnedTLS opens a TLS connection to the RP server, pinned to its
// DNS-published fingerprints. There is no CA chain here — DNS `fp=` pinning
// is the entire trust anchor, exactly as sdks/local-rp/go/rpc.go's dialTLS
// (unexported) does for the local-RP SDK's own DomainKeys/LocalRp calls, and
// crates/linkkeys/src/tcp/tls.rs does server-side. dialTLS isn't exported
// from the SDK package, so this app inlines the same short pinning routine
// rather than reaching into SDK internals — reusing what IS exported
// (localrp.NewStdTransport for the dial+timeouts, localrp.Fingerprint for the
// SPKI hash) instead of duplicating those pieces too.
func dialPinnedTLS(cfg rpConfig) (*tls.Conn, error) {
	transport := localrp.NewStdTransport()
	raw, err := transport.Dial(cfg.tcpAddr)
	if err != nil {
		return nil, err
	}

	hostname := cfg.tcpAddr
	if h, _, err := net.SplitHostPort(cfg.tcpAddr); err == nil {
		hostname = h
	}

	tlsCfg := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, // pinned verification below replaces WebPKI chain validation
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificate presented")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("bad certificate encoding: %w", err)
			}
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return fmt.Errorf("certificate is not within its validity period")
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("peer certificate is not an Ed25519 key")
			}
			fp := localrp.Fingerprint([]byte(pub))
			for _, want := range cfg.fingerprints {
				if fp == want {
					return nil
				}
			}
			return fmt.Errorf("certificate fingerprint %s does not match any pinned RP fingerprint", fp)
		},
	}

	conn := tls.Client(raw, tlsCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("TLS handshake with RP server: %w", err)
	}
	return conn, nil
}

// rpCall makes one API-key-authenticated CSIL-RPC call to the `Rp` service on
// this app's own RP server. The API key rides the envelope's `auth` field
// (RpcRequest.WithAuth) — see crates/linkkeys/src/tcp/mod.rs's
// authenticate_tcp_request, which reads exactly that field, and
// services/authorization.rs's required_relation_for_op("Rp", op), which then
// requires the caller's key to hold the `api_access` relation (SEC-06).
func rpCall(cfg rpConfig, op string, payload []byte) ([]byte, error) {
	conn, err := dialPinnedTLS(cfg)
	if err != nil {
		return nil, fmt.Errorf("dial RP: %w", err)
	}
	defer conn.Close()

	carrier := rpctransport.NewStreamCarrierWithMaxFrame(conn, maxFrameSize)

	req := rpctransport.NewRpcRequest("Rp", op, payload).WithAuth(cfg.apiKey)
	frame, err := req.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	if err := carrier.SendFrame(frame); err != nil {
		return nil, fmt.Errorf("send frame: %w", err)
	}

	respBytes, err := carrier.RecvFrame()
	if err != nil {
		return nil, fmt.Errorf("recv frame: %w", err)
	}
	if respBytes == nil {
		return nil, fmt.Errorf("connection closed before response")
	}

	resp, err := rpctransport.DecodeRpcResponse(respBytes)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if err := resp.AsTransportError(); err != nil {
		return nil, fmt.Errorf("Rp/%s: %w", op, err)
	}
	return resp.Payload, nil
}

// signRequest is step 1 of the login flow: sign an auth request addressed to
// the user's chosen LinkKeys domain, naming this app's callback URL and a
// fresh single-use nonce.
func signRequest(cfg rpConfig, callbackURL, nonce string) (string, error) {
	payload := api.EncodeRpSignRequest(api.RpSignRequest{
		CallbackUrl: callbackURL,
		Nonce:       nonce,
	})
	respBytes, err := rpCall(cfg, "sign-request", payload)
	if err != nil {
		return "", err
	}
	resp, err := api.DecodeRpSignResponse(respBytes)
	if err != nil {
		return "", fmt.Errorf("decode sign-request response: %w", err)
	}
	return resp.SignedRequest, nil
}

// decryptToken is step 4: exchange the callback's encrypted_token for the
// signed identity assertion inside it. Only the RP server (which holds this
// app's domain private key) can do this. The returned signed_assertion string
// (base64url(CBOR(SignedIdentityAssertion))) is what the two follow-up calls
// consume — verify-assertion and userinfo-fetch both take it, never the raw
// encrypted_token.
func decryptToken(cfg rpConfig, encryptedToken string) (string, error) {
	payload := api.EncodeRpDecryptRequest(api.RpDecryptRequest{EncryptedToken: encryptedToken})
	respBytes, err := rpCall(cfg, "decrypt-token", payload)
	if err != nil {
		return "", err
	}
	resp, err := api.DecodeRpDecryptResponse(respBytes)
	if err != nil {
		return "", fmt.Errorf("decode decrypt-token response: %w", err)
	}
	return resp.SignedAssertion, nil
}

// verifyAssertion is step 5: verify the decrypted assertion against the
// issuing domain's published keys. Callers MUST check the returned `verified`
// flag — a non-nil error only covers transport/decode failures, not signature
// or trust-chain rejection.
func verifyAssertion(cfg rpConfig, signedAssertion, expectedDomain string) (api.IdentityAssertion, bool, error) {
	payload := api.EncodeRpVerifyRequest(api.RpVerifyRequest{
		SignedAssertion: signedAssertion,
		ExpectedDomain:  expectedDomain,
	})
	respBytes, err := rpCall(cfg, "verify-assertion", payload)
	if err != nil {
		return api.IdentityAssertion{}, false, err
	}
	resp, err := api.DecodeRpVerifyResponse(respBytes)
	if err != nil {
		return api.IdentityAssertion{}, false, fmt.Errorf("decode verify-assertion response: %w", err)
	}
	return resp.Assertion, resp.Verified, nil
}

// userInfoFetch is the optional step 6: fetch the user's consented claims
// from the issuing IDP, via this app's RP server (which proves possession of
// the domain key on the app's behalf). signedAssertion is the decrypt-token
// result — per csil/linkkeys.csil, RpUserInfoRequest.token carries "the
// decrypt-token result" (a URL-param-encoded SignedIdentityAssertion), NOT
// the raw encrypted_token from the callback; the IDP's Identity/get-user-info
// parses it as such (crates/linkkeys/src/tcp/mod.rs, assertion_from_url_param).
// apiBase is the issuing domain's browser-facing HTTPS API base — see
// resolveAPIBase.
func userInfoFetch(cfg rpConfig, signedAssertion, apiBase, domain string) (api.UserInfo, error) {
	payload := api.EncodeRpUserInfoRequest(api.RpUserInfoRequest{
		Token:   signedAssertion,
		ApiBase: apiBase,
		Domain:  domain,
	})
	respBytes, err := rpCall(cfg, "userinfo-fetch", payload)
	if err != nil {
		return api.UserInfo{}, err
	}
	return api.DecodeUserInfo(respBytes)
}

// newNonce generates a fresh single-use login nonce.
func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing is unrecoverable
	}
	return hex.EncodeToString(b)
}

// resolveAPIBase looks up the domain's `_linkkeys_apis` TXT record for its
// published HTTPS API base, falling back to `https://<domain>` if the domain
// publishes no override — the same DNS name and format
// sdks/local-rp/go/dns.go's LinkKeysApisDNSName/ParseLinkKeysApisTXT already
// parse for the local-RP SDK, reused here via the DnsResolver seam rather
// than reimplemented.
func resolveAPIBase(dns localrp.DnsResolver, domain string) string {
	fallback := "https://" + domain
	txts, err := dns.TxtLookup(localrp.LinkKeysApisDNSName(domain))
	if err != nil {
		return fallback
	}
	for _, txt := range txts {
		apis, err := localrp.ParseLinkKeysApisTXT(txt)
		if err != nil || apis.HTTPSBase == nil {
			continue
		}
		return *apis.HTTPSBase
	}
	return fallback
}

// pendingLogin is what the app persists between beginLogin and the callback
// arriving — an ordinary server-side session record (cookie-backed session,
// DB row, whatever the app already uses). This example keeps it in memory
// for clarity; a real app must persist it durably and scope it to the
// browser session that initiated the login.
type pendingLogin struct {
	nonce      string
	userDomain string
}

// beginLogin is steps 1-2: sign an auth request via the RP server and build
// the browser-redirect URL to the user's chosen LinkKeys domain. Only
// `signed_request` (and, optionally, `user_hint`) are read by
// GET /auth/authorize — see crates/linkkeys/src/web/mod.rs's route
// signature (`#[rocket::get("/auth/authorize?<user_hint>&<signed_request>")]`).
func beginLogin(cfg rpConfig, userDomain, userHint, callbackURL string) (redirectURL string, pending pendingLogin, err error) {
	nonce := newNonce()
	signedRequest, err := signRequest(cfg, callbackURL, nonce)
	if err != nil {
		return "", pendingLogin{}, fmt.Errorf("sign-request: %w", err)
	}

	u := url.URL{Scheme: "https", Host: userDomain, Path: "/auth/authorize"}
	q := u.Query()
	q.Set("signed_request", signedRequest)
	if userHint != "" {
		q.Set("user_hint", userHint)
	}
	u.RawQuery = q.Encode()

	return u.String(), pendingLogin{nonce: nonce, userDomain: userDomain}, nil
}

// usedNonces is a placeholder single-use-nonce store. A real app persists
// this durably (a DB table, or Redis SETNX with a TTL past the assertion's
// expires_at) so a leaked/replayed encrypted_token can't be redeemed twice —
// nonce single-use is entirely the app's responsibility; the RP server and
// generated types only hand back the nonce for the app to compare
// (RpVerifyResponse.Assertion.Nonce), they don't enforce it for you at this
// layer. (The IDP itself separately burns the assertion once for the
// userinfo-fetch call, server-side — but callback replay before that point is
// still this app's to guard.)
var usedNonces = map[string]bool{}

// handleCallback is steps 3-5: decrypt the callback's token, verify the
// assertion, and enforce nonce single-use and domain/verified checks before
// trusting the result. It also returns the signed_assertion string from
// decrypt-token, because the optional step 6 (userinfo-fetch) needs that —
// not the raw encrypted_token — as its token.
func handleCallback(cfg rpConfig, pending pendingLogin, encryptedToken string) (api.IdentityAssertion, string, error) {
	signedAssertion, err := decryptToken(cfg, encryptedToken)
	if err != nil {
		return api.IdentityAssertion{}, "", fmt.Errorf("decrypt-token: %w", err)
	}

	assertion, verified, err := verifyAssertion(cfg, signedAssertion, pending.userDomain)
	if err != nil {
		return api.IdentityAssertion{}, "", fmt.Errorf("verify-assertion: %w", err)
	}
	if !verified {
		return api.IdentityAssertion{}, "", fmt.Errorf("assertion did not verify against %s's published keys", pending.userDomain)
	}

	if assertion.Domain != pending.userDomain {
		return api.IdentityAssertion{}, "", fmt.Errorf("domain mismatch: expected %s, got %s", pending.userDomain, assertion.Domain)
	}
	if assertion.Nonce != pending.nonce {
		return api.IdentityAssertion{}, "", fmt.Errorf("nonce mismatch — possible replay")
	}
	if usedNonces[assertion.Nonce] {
		return api.IdentityAssertion{}, "", fmt.Errorf("token already redeemed")
	}
	usedNonces[assertion.Nonce] = true

	return assertion, signedAssertion, nil
}
```

### `main.go` — wiring it into HTTP handlers

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	localrp "github.com/catalystcommunity/linkkeys/sdks/local-rp/go"
)

// sessionStore is a minimal in-memory stand-in for whatever session
// mechanism the app already uses (signed cookie, Redis, a DB table). It maps
// an opaque browser-session id to that browser's pendingLogin while the user
// is off at the IDP, and — after a successful callback — to a logged-in
// session's user facts. A real app should not keep this in a process-local
// map; it won't survive a restart or work behind more than one replica.
type sessionStore struct {
	mu       sync.Mutex
	pending  map[string]pendingLogin
	sessions map[string]loggedInSession
}

type loggedInSession struct {
	userID      string
	userDomain  string
	displayName string
	claims      map[string]string
	expiresAt   time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		pending:  map[string]pendingLogin{},
		sessions: map[string]loggedInSession{},
	}
}

func newSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// app wires the RP client glue in rpclient.go into HTTP handlers. This is
// the shape a real Go web app's login/callback routes would take; sessions,
// CSRF/state handling, and error pages are simplified for the walkthrough.
type app struct {
	rpCfg   rpConfig
	dns     localrp.DnsResolver
	store   *sessionStore
	baseURL string // this app's own public origin, e.g. "https://app.example.com"
}

// handleLogin starts a login for a user-supplied LinkKeys domain (e.g. typed
// into a "Sign in with LinkKeys" form as "alice@example.com" or
// "example.com") and redirects the browser to that domain's authorize page.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	userDomain := r.URL.Query().Get("domain")
	userHint := r.URL.Query().Get("user_hint")
	if userDomain == "" {
		http.Error(w, "missing domain", http.StatusBadRequest)
		return
	}

	callbackURL := a.baseURL + "/auth/callback"
	redirectURL, pending, err := beginLogin(a.rpCfg, userDomain, userHint, callbackURL)
	if err != nil {
		log.Printf("begin login failed: %v", err)
		http.Error(w, "could not start login", http.StatusBadGateway)
		return
	}

	sessionID := newSessionID()
	a.store.mu.Lock()
	a.store.pending[sessionID] = pending
	a.store.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "lk_pending",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // the login round trip should complete within 10 minutes
	})
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleAuthCallback is the app's own callback route (the callbackURL passed
// to beginLogin). The IDP redirects the browser here with
// `?encrypted_token=...` after the user authenticates and consents.
func (a *app) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	encryptedToken := r.URL.Query().Get("encrypted_token")
	if encryptedToken == "" {
		http.Error(w, "missing encrypted_token", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("lk_pending")
	if err != nil {
		http.Error(w, "no pending login found — it may have expired", http.StatusBadRequest)
		return
	}
	a.store.mu.Lock()
	pending, ok := a.store.pending[cookie.Value]
	if ok {
		delete(a.store.pending, cookie.Value) // consume: one callback per beginLogin
	}
	a.store.mu.Unlock()
	if !ok {
		http.Error(w, "no pending login found — it may have expired", http.StatusBadRequest)
		return
	}

	assertion, signedAssertion, err := handleCallback(a.rpCfg, pending, encryptedToken)
	if err != nil {
		log.Printf("callback verification failed: %v", err)
		http.Error(w, "login could not be verified", http.StatusForbidden)
		return
	}

	// Optional: fetch the user's consented claims (email, display name, ...)
	// via the RP server. Skippable if the app only needs proof of identity.
	// The token here is the signed_assertion from decrypt-token — NOT the raw
	// encrypted_token (see userInfoFetch's doc comment).
	claims := map[string]string{}
	apiBase := resolveAPIBase(a.dns, pending.userDomain)
	userInfo, err := userInfoFetch(a.rpCfg, signedAssertion, apiBase, pending.userDomain)
	if err != nil {
		log.Printf("userinfo-fetch failed (continuing without claims): %v", err)
	} else {
		for _, c := range userInfo.Claims {
			claims[c.ClaimType] = string(c.ClaimValue)
		}
	}

	sessionID := newSessionID()
	a.store.mu.Lock()
	a.store.sessions[sessionID] = loggedInSession{
		userID:      assertion.UserId,
		userDomain:  assertion.Domain,
		displayName: derefOr(assertion.DisplayName, assertion.UserId),
		claims:      claims,
		expiresAt:   time.Now().Add(24 * time.Hour),
	}
	a.store.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "lk_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((24 * time.Hour).Seconds()),
	})
	http.SetCookie(w, &http.Cookie{Name: "lk_pending", Path: "/", MaxAge: -1})
	fmt.Fprintf(w, "Logged in as %s@%s\n", assertion.UserId, assertion.Domain)
}

func derefOr(s *string, fallback string) string {
	if s == nil {
		return fallback
	}
	return *s
}

func main() {
	cfg, err := rpConfigFromEnv()
	if err != nil {
		log.Fatalf("RP client config: %v", err)
	}

	a := &app{
		rpCfg:   cfg,
		dns:     localrp.DefaultDNSResolver(),
		store:   newSessionStore(),
		baseURL: "https://app.example.com",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", a.handleLogin)
	mux.HandleFunc("/auth/callback", a.handleAuthCallback)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## App responsibilities

Exactly parallel to what `doc.go`/README.md already document for the
local-RP SDK — this glue code hands back verified protocol facts, and these
responsibilities are entirely yours, whether you write this glue by hand (as
here) or eventually use a packaged regular-RP SDK:

- **Nonce single-use.** `handleCallback` above compares the assertion's
  nonce against the one this app minted and rejects a mismatch, but the
  `usedNonces` map is a placeholder — persist it durably (a unique DB
  constraint, or a cache entry with a TTL past the assertion's
  `expires_at`) so a replayed `encrypted_token` can't be redeemed twice
  server-side. Nothing in the `Rp` service enforces this for your app's
  callback step (the IDP does separately burn the assertion once, but only
  at the point your RP server calls `userinfo-fetch` — replay of the
  callback itself, before that point, is on you).
- **Sessions.** This example's `sessionStore` is a toy (process-local map).
  Use your app's real session mechanism, and make sure `lk_pending` (the
  state tying a browser to its in-flight login) and `lk_session` (the
  logged-in session) are separate, and that `lk_pending` is single-use and
  short-lived.
- **API key storage.** `RP_API_KEY` (step 2 above) authorizes signing and
  decrypting on your domain's behalf — treat it with the same care as a
  database credential, not as ordinary configuration. It's shown once at
  creation time and cannot be retrieved again (mint a new one and
  `deactivate-user`/re-grant if it leaks).
- **Local user records / authorization.** This glue returns
  `IdentityAssertion`/`UserInfo` — protocol facts. Mapping `UserId`+`Domain`
  to a local account, first-login provisioning, and any app-level
  authorization decisions are entirely your app's to make.

## Local-RP vs regular-RP

| | Local RP (`localrp` package, this directory) | Regular RP (this document) |
|---|---|---|
| App identity | A locally-generated Ed25519 key fingerprint (SSH-host-key style) | A DNS domain your app owns |
| DNS required | No | Yes — `_linkkeys` + `_linkkeys_apis` TXT records |
| Where keys live | In the app itself (`LocalRpIdentityToBytes`) | In a separate RP server process your app talks to over TCP |
| Admission | Explicit per-domain approval (`linkkeys local-rp approve <fingerprint>`) — pending until an admin approves | Ordinary DNS-pinned trust, same as any LinkKeys peer |
| Go SDK | This package (`localrp.BeginLocalLogin`/`CompleteLocalLogin`) | None packaged — hand-write the glue this document shows, reusing `generated` + `csilgen/transports/go` |
| Best for | LAN tools, self-hosted apps with no public DNS, desktop apps | Any app that already has (or can get) a domain |

If your app has a domain, use this document's approach. If it doesn't (a LAN
jukebox, a local dev tool), see this package's own `doc.go`/README.md
instead.

## No HTTP path for these calls

There is no JSON-over-HTTPS integration API for these operations: the old
`POST /v1alpha/*.json` RP routes were removed when the server-to-server
surface moved to TCP CSIL-RPC (the remaining `/v1alpha/*` S2S routes in
`crates/linkkeys/src/web/mod.rs` are marked deprecated for the same reason,
and the generic HTTP RPC carrier can't complete this flow anyway —
`verify-assertion` and `userinfo-fetch` need the outbound S2S context only
the TCP carrier has). **`Rp/sign-request`, `Rp/decrypt-token`,
`Rp/verify-assertion`, `Rp/userinfo-fetch`, and `Rp/issue-attestation` over
TCP CSIL-RPC — this document's approach — are the only way to drive these
operations.** `docs/DEPLOYING-RP.md` documents the same TCP integration; if
you find older material referencing `/v1alpha/sign-request.json` and
friends, it predates the TCP migration.

## What was compiled

`rpclient.go` and `main.go` above are copied verbatim from a real module
built and checked in a scratch directory outside this repo; `go.mod` is the
same except its `replace` path was genericized (the compiled one pointed at
this checkout's `sdks/local-rp/go`):

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"   # go 1.26.4
go mod tidy
go build -buildvcs=false ./...   # clean
GOFLAGS=-buildvcs=false go vet ./...   # clean
gofmt -l .                       # no output — already gofmt-clean
```

`-buildvcs=false` is only needed because the scratch directory isn't itself
a git repo; a real app checked into its own repo doesn't need it.
