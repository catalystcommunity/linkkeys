# Accepting regular (DNS-pinned) LinkKeys logins in PHP

This is a worked example for the **other** LinkKeys login mode. The rest of
this directory (`sdks/local-rp/php/`) is the **local-RP** SDK — DNS-less,
SSH-host-key-style identity for LAN apps and desktop tools with no public
domain (see the package [`README.md`](README.md) and
[`docs/local-rp-app-developer-guide.md`](../../../docs/local-rp-app-developer-guide.md)).

This doc is for the *regular* case: a self-hosted PHP web app that has (or
will get) a real public domain, and wants "Log in with LinkKeys" against a
user's own DNS-pinned LinkKeys identity — the same kind of flow as "Sign in
with Google," but where the identity provider is whichever LinkKeys domain
the user tells you, not a fixed one you registered with in advance.

There is **no packaged regular-RP client for PHP**. This doc shows you how
to build the small amount of glue yourself, reusing pieces of the local-RP
SDK sitting right next to it in this directory — its CBOR codec, its TLS
pinning, and its TCP transport are all generic, not local-RP-specific.
Every code block below was written to a real file and run — `php -l` for
every file, plus a wire-format round-trip harness and two CLI-driven runs of
`login.php`/`callback.php` themselves — through a `php:8.3-cli` container
(no system PHP on this box; see "Verifying this example" at the end). It's
not a copy-paste of untested prose.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                Your Application Stack                │
│                                                        │
│  ┌──────────────┐        ┌────────────────────────┐  │
│  │  Your PHP App │  TCP   │  LinkKeys RP Server    │  │
│  │ login.php      │──────►│  (same linkkeys image, │  │
│  │ callback.php   │ CSIL-  │   RP-mode config)      │  │
│  │                │  RPC   │  Holds domain keys     │  │
│  │  Sessions      │        │  Signs auth requests   │  │
│  │  Redirects     │        │  Decrypts tokens       │  │
│  └──────────────┘        └────────────────────────┘  │
│                                                        │
│  Your app never touches a private key. It calls its   │
│  own RP server's `Rp` service over TCP CSIL-RPC,      │
│  authenticated with an API key.                       │
└──────────────────────────────────────────────────────┘
```

This — a self-hosted web app in some language paired with its own LinkKeys
server running in RP mode — is **the archetypal PHP deployment story** for
LinkKeys: PHP apps are almost always deployed exactly this way (app +
sidecar/adjacent service, no embedded native crypto runtime), and it's also
just how every LinkKeys RP integration is meant to work regardless of
language. Full architecture and Helm deployment details:
[`docs/DEPLOYING-RP.md`](../../../docs/DEPLOYING-RP.md).

## Prerequisites

### 1. Deploy your RP server

Follow [`docs/DEPLOYING-RP.md`](../../../docs/DEPLOYING-RP.md) end to end:
same `linkkeys` Docker image and Helm chart as a full IDP, RP-mode values
(no password login, no human user accounts — service accounts only).

### 2. Initialize domain keys and create a service account for this app

Inside the RP pod/container:

```sh
linkkeys domain init
```

Create a service account for this PHP app and mint it an API key:

```sh
linkkeys user create my-webapp "My Web Application" --api-key
```

Save the printed API key (`RP_API_KEY` below) — it is only shown once.

### 3. Grant the account `api_access`

An API key alone is **not** enough to call the `Rp` service. Every `Rp`
operation (`sign-request`, `decrypt-token`, `verify-assertion`,
`userinfo-fetch`) is gated behind a dedicated `api_access` relation on the
domain — a valid key from *any* active user is deliberately not sufficient,
because these ops are oracles over the domain's signing/decryption keys
(`crates/linkkeys/src/services/authorization.rs`, SEC-06):

```rust
// "Rp" => Some(RELATION_API_ACCESS)
```

and enforced on every TCP call before dispatch (`crates/linkkeys/src/tcp/mod.rs`):

```rust
if let Some(required) =
    crate::services::authorization::required_relation_for_op("Rp", op)
{
    if !crate::services::authorization::user_has_permission(
        db_pool, &user.id, required, "domain", &get_domain_name(),
    ) {
        return error_response(5, "Forbidden");
    }
}
```

It is **not** granted automatically by `user create --api-key`. Grant it
explicitly:

```sh
linkkeys relation grant-local my-webapp api_access
```

(`relation grant-local` is DB-direct/break-glass — it needs no server or API
key of its own, which is what resolves the bootstrap chicken-and-egg of
needing a key to grant the first key's own permissions. It's idempotent, so
re-running it is safe.) Or do it in one shot at creation time:

```sh
linkkeys user create my-webapp "My Web Application" --api-key --relation api_access
```

### 4. DNS

Publish this RP server's own `_linkkeys` and `_linkkeys_apis` TXT records —
your PHP app pins its TCP connection to the RP server against the `fp=` set
here, the same way any LinkKeys peer pins any other:

```sh
linkkeys domain dns-check
```

prints the exact records to publish, e.g.:

```
_linkkeys.yourapp.example.com TXT "v=lk1 api=https://yourapp.example.com fp=<fp1> fp=<fp2> fp=<fp3>"
_linkkeys_apis.yourapp.example.com TXT "v=lk1 tcp=yourapp.example.com https=yourapp.example.com"
```

### 5. What this PHP app needs to know

Four values, however you inject config in your deployment (env vars used
below, matching `demoappsite/src/main.rs`'s `RpConfig` — the Rust reference
implementation of this exact flow):

| Env var | Meaning |
|---|---|
| `RP_TCP_ADDR` | Your RP server's `host:port` (default TCP port is 4987) |
| `RP_FINGERPRINTS` | Comma-separated `fp=` values from `linkkeys domain dns-check`, pinning the RP server's TLS cert |
| `RP_API_KEY` | The API key from step 2 |
| `RP_DOMAIN` | Your RP server's own domain name (used as the audience/relying-party identity) |
| `PUBLIC_ORIGIN` | This app's own public origin, e.g. `https://yourapp.example.com`, used to build `callback_url` |

### 6. PHP requirements

Same floor as the local-RP SDK in this directory, because this example
reuses its crypto/TLS layer:

- PHP **>= 8.1**
- `ext-sodium`, `ext-openssl`, `ext-hash` (bundled with PHP; essentially
  always present)
- No Composer required — see "Wiring it together" below.

No system PHP on this box; every code sample here was verified against
`php:8.3-cli`:

```sh
sudo nerdctl run --rm -v "$(pwd)":/repo -w /repo php:8.3-cli php -l some_file.php
```

## The flow

1. Your app calls its RP server's `Rp/sign-request` with a `callback_url`,
   a fresh `nonce`, and (optionally) the claims it wants. The RP server
   signs an auth request with its domain key and hands back an opaque,
   already-signed `signed_request` string — your app never sees or touches
   a key.
2. Your app redirects the user's browser to
   `https://<user's-domain>/auth/authorize?signed_request=<...>` (optionally
   `&user_hint=<...>`). This is the **only** thing the IDP's
   `/auth/authorize` route reads — it's `#[rocket::get("/auth/authorize?<user_hint>&<signed_request>")]`
   in `crates/linkkeys/src/web/mod.rs`; everything else about the request
   (callback URL, nonce, requested claims) travels *inside* the signed
   request, not as separate query params.
3. The user authenticates at their own IDP and consents to the claim
   request. The IDP redirects back to your `callback_url` with
   `?encrypted_token=<...>`.
4. Your app calls `Rp/decrypt-token` with that token. The RP server decrypts
   it with its domain encryption key and returns a `signed_assertion`.
5. Your app calls `Rp/verify-assertion` with the `signed_assertion` and the
   `expected_domain` (the domain you started the login for). The RP server
   fetches and pins that domain's published signing keys and verifies the
   assertion, returning the decoded `IdentityAssertion` plus `verified: true`.
6. Your app checks the assertion's `nonce` against the one it generated in
   step 1, and its `domain` against the one it expected — **this is your
   app's job**; nothing else enforces it (see "App responsibilities" below).
7. Your app calls `Rp/userinfo-fetch` to get the user's actual claim values.

All four `Rp` ops are **TCP CSIL-RPC only** — see "Why TCP, not HTTP" below.

## Why TCP, not HTTP

An earlier revision of `docs/DEPLOYING-RP.md`'s "Web App Integration"
section listed JSON HTTP routes (`POST /v1alpha/sign-request.json` etc.) for
this; the doc now correctly documents the TCP integration. **Those routes do
not exist in the current server** — there is no `sign-request.json`,
`decrypt-token.json`, or `verify-assertion.json` route anywhere in
`crates/linkkeys/src/web/mod.rs`.

The only HTTP RPC surface that exists today is the generic envelope-in-body
carrier at `POST /csil/v1/rpc` (`crates/linkkeys/src/web/mod.rs`), which
runs the *same* dispatcher TCP does. But it can't complete this flow either:
`verify-assertion` and `userinfo-fetch` make their own onward network calls
(fetching the asserting domain's keys, redeeming the assertion), which needs
an async runtime context (`OutboundCtx`) that `/csil/v1/rpc` never provides
— its handler calls `dispatch_envelope(&body, &ready, &pool, None)`, and
`dispatch_rp`'s `verify-assertion`/`userinfo-fetch` arms fail closed
(`error_response(4, "operation unavailable on this carrier")`) whenever that
context is `None`. Only `sign-request`/`decrypt-token` would work over HTTP;
the flow as a whole cannot. TCP CSIL-RPC — what this guide teaches — is not
just the recommended path, it's the only one that actually completes.

## Wiring it together

No Composer required (matching the SDK's own "plain system PHP first"
stance — see its README's "Running the tests"). Vendor the local-RP SDK's
source alongside your app:

```sh
mkdir -p vendor/linkkeys-local-rp
cp -r /path/to/linkkeys/sdks/local-rp/php/src vendor/linkkeys-local-rp/src
```

(A Composer path repository pointing at `sdks/local-rp/php`, or a git
submodule, work just as well if your deployment prefers Composer-managed
vendoring — `sdks/local-rp/php/composer.json` already declares a classmap
autoload. The example below uses a small hand-rolled autoloader instead,
copied from the SDK's own `tests/bootstrap.php`, to stay Composer-optional.)

Project layout:

```
your-app/
  bootstrap.php          # autoload + config + DNS helper (below)
  login.php               # starts a login, redirects to the user's IDP
  callback.php              # handles the IDP's redirect back
  src/
    RpWire.php               # CBOR (de)serialization for the Rp service's types
    RpRpcClient.php            # the TCP CSIL-RPC client itself
  vendor/linkkeys-local-rp/
    src/                        # copied from sdks/local-rp/php/src/ (step above)
```

### `bootstrap.php`

Autoloads the vendored SDK plus this app's own two classes, and holds the
small bits of config/DNS glue `login.php` and `callback.php` share.

```php
<?php

declare(strict_types=1);

/**
 * App bootstrap: autoload the vendored local-RP PHP SDK (copied from
 * sdks/local-rp/php/src/ -- see example.md "Prerequisites") plus this app's
 * own src/ classes, and small config/DNS helpers shared by login.php and
 * callback.php.
 *
 * The autoloader mirrors sdks/local-rp/php/tests/bootstrap.php's approach:
 * this SDK groups several classes per file rather than one-class-per-file,
 * so a strict PSR-4 class->file map doesn't apply -- instead every file
 * under the matched directory is loaded once.
 */

define('LINKKEYS_LOCAL_RP_SDK_SRC', __DIR__ . '/vendor/linkkeys-local-rp/src');

spl_autoload_register(function (string $class): void {
    $prefixes = [
        'LinkKeys\\LocalRp\\' => LINKKEYS_LOCAL_RP_SDK_SRC . '/',
        'Csilgen\\Generated\\' => LINKKEYS_LOCAL_RP_SDK_SRC . '/Generated/',
        'App\\LinkKeysRp\\' => __DIR__ . '/src/',
    ];
    foreach ($prefixes as $prefix => $baseDir) {
        if (str_starts_with($class, $prefix)) {
            foreach (glob($baseDir . '*.php') as $file) {
                require_once $file;
            }
            return;
        }
    }
});

/** This app's own origin, used to build the callback_url. */
function app_origin(): string
{
    return getenv('PUBLIC_ORIGIN') ?: 'https://localhost:8443';
}

/**
 * Connection details for this app's own RP server -- see example.md
 * "Prerequisites": RP_TCP_ADDR/RP_FINGERPRINTS/RP_API_KEY/RP_DOMAIN. Naming
 * mirrors demoappsite/src/main.rs's RpConfig, the Rust reference for this
 * exact flow.
 *
 * @return array{tcp_addr:string,fingerprints:string[],api_key:string,domain:string}
 */
function rp_config(): array
{
    $fingerprints = array_values(array_filter(array_map(
        'trim',
        explode(',', (string) (getenv('RP_FINGERPRINTS') ?: ''))
    )));
    return [
        'tcp_addr' => (getenv('RP_TCP_ADDR') ?: '') ?: '127.0.0.1:4987',
        'fingerprints' => $fingerprints,
        'api_key' => (string) (getenv('RP_API_KEY') ?: ''),
        'domain' => (string) (getenv('RP_DOMAIN') ?: ''),
    ];
}

/**
 * Resolve a domain's HTTPS API base via its `_linkkeys_apis` DNS TXT record
 * (the `https=` field), falling back to `https://{domain}`. Mirrors
 * demoappsite/src/main.rs's resolve_api_base(); used both to build the
 * /auth/authorize redirect and as the api_base passed to userinfo-fetch (the
 * RP server uses it to detect a single-instance IDP+RP self-call).
 */
function resolve_api_base(string $domain): string
{
    $fallback = "https://{$domain}";
    $records = @dns_get_record("_linkkeys_apis.{$domain}", DNS_TXT);
    if ($records === false || $records === []) {
        return $fallback;
    }
    foreach ($records as $record) {
        $txt = $record['txt'] ?? '';
        if (!is_string($txt) || !str_starts_with($txt, 'v=lk1 ')) {
            continue;
        }
        foreach (explode(' ', $txt) as $part) {
            if (str_starts_with($part, 'https=')) {
                return 'https://' . substr($part, strlen('https='));
            }
        }
    }
    return $fallback;
}
```

### `src/RpWire.php`

The local-RP SDK's `src/Wire.php` hand-writes correct CBOR (de)serialization
for the ~19 wire structures the *local-RP* flow needs, working around a
confirmed bug in the generated `src/Generated/codec.php` (every `[* T]`
list-typed field's (de)serializer references an undefined PHP variable, so
list fields silently round-trip as empty — see this package's `README.md`,
"Code generation"). It does **not** cover the `Rp` service's types
(`RpSignRequest`/`Response`, `RpDecryptRequest`/`Response`,
`RpVerifyRequest`/`Response`, `RpUserInfoRequest`, `UserInfo`) — those belong
to the regular-RP flow this SDK doesn't implement. This file is the same
kind of hand-written wire layer for exactly those six structures, reusing
what's already correct and public in the SDK rather than duplicating it:

- `LinkKeys\LocalRp\Cbor` — the generic CBOR codec (not local-RP-specific).
- `LinkKeys\LocalRp\Wire::claimFromMap()` — already public and correct;
  reused as-is for `UserInfo.claims` rather than reimplemented.
- `Csilgen\Generated\*` classes as plain data holders (correct — only the
  generated *codec* is broken).

```php
<?php

declare(strict_types=1);

namespace App\LinkKeysRp;

use Csilgen\Generated\ClaimRequest;
use Csilgen\Generated\IdentityAssertion;
use Csilgen\Generated\RequestedClaim;
use Csilgen\Generated\RpDecryptRequest;
use Csilgen\Generated\RpDecryptResponse;
use Csilgen\Generated\RpSignRequest;
use Csilgen\Generated\RpSignResponse;
use Csilgen\Generated\RpUserInfoRequest;
use Csilgen\Generated\RpVerifyRequest;
use Csilgen\Generated\RpVerifyResponse;
use Csilgen\Generated\UserInfo;
use LinkKeys\LocalRp\Cbor;
use LinkKeys\LocalRp\Wire;

/**
 * Hand-written CBOR (de)serialization for the `Rp` service's request/response
 * types -- RpSignRequest/Response, RpDecryptRequest/Response,
 * RpVerifyRequest/Response, RpUserInfoRequest, UserInfo. The local-RP PHP
 * SDK's src/Wire.php does NOT cover these: it only wires the ~19 structures
 * the *local-RP* (DNS-less) flow needs. This app is a REGULAR (DNS-pinned)
 * relying party calling its own RP server's `Rp` service instead, so it
 * needs this small parallel wire layer. It reuses, rather than
 * reimplements:
 *
 *  - LinkKeys\LocalRp\Cbor -- the SDK's generic CBOR codec, not local-RP
 *    specific, and already a correctness fix for the generated codec.php
 *    bug (see the SDK README's "Code generation" section: every `[* T]`
 *    list field in the generated codec references an undefined PHP
 *    variable and silently round-trips as an empty list).
 *  - LinkKeys\LocalRp\Wire::claimFromMap() -- public, already correct, no
 *    need to reimplement Claim/ClaimSignature decoding for UserInfo.claims.
 *  - Csilgen\Generated\* classes as plain data holders (correct; only the
 *    generated codec is broken).
 *
 * Field names/shapes are taken directly from csil/linkkeys.csil, same as
 * the SDK's own Wire.php.
 */
final class RpWire
{
    public static function encodeRpSignRequest(RpSignRequest $v): string
    {
        $out = [
            'callback_url' => $v->callbackUrl,
            'nonce' => $v->nonce,
        ];
        if ($v->requestedClaims !== null) {
            $out['requested_claims'] = self::claimRequestToMap($v->requestedClaims);
        }
        // flow_context (AuthFlowContext) intentionally omitted here -- this
        // example only performs a first-contact login, not a claims-update
        // re-prompt. Add it the same way if your app needs that flow.
        return Cbor::encodeMap($out);
    }

    /** @return array<string,mixed> */
    private static function claimRequestToMap(ClaimRequest $v): array
    {
        return [
            'required' => array_map([self::class, 'requestedClaimToMap'], $v->required ?? []),
            'optional' => array_map([self::class, 'requestedClaimToMap'], $v->optional ?? []),
        ];
    }

    /** @return array<string,mixed> */
    private static function requestedClaimToMap(RequestedClaim $c): array
    {
        return [
            'claim_type' => $c->claimType,
            'datatype' => $c->datatype,
        ];
    }

    public static function decodeRpSignResponse(string $bytes): RpSignResponse
    {
        $m = Cbor::decode($bytes);
        return new RpSignResponse(['signed_request' => $m['signed_request'] ?? null]);
    }

    public static function encodeRpDecryptRequest(RpDecryptRequest $v): string
    {
        return Cbor::encodeMap(['encrypted_token' => $v->encryptedToken]);
    }

    public static function decodeRpDecryptResponse(string $bytes): RpDecryptResponse
    {
        $m = Cbor::decode($bytes);
        return new RpDecryptResponse(['signed_assertion' => $m['signed_assertion'] ?? null]);
    }

    public static function encodeRpVerifyRequest(RpVerifyRequest $v): string
    {
        return Cbor::encodeMap([
            'signed_assertion' => $v->signedAssertion,
            'expected_domain' => $v->expectedDomain,
        ]);
    }

    public static function decodeRpVerifyResponse(string $bytes): RpVerifyResponse
    {
        $m = Cbor::decode($bytes);
        return new RpVerifyResponse([
            'assertion' => self::identityAssertionFromMap($m['assertion'] ?? []),
            'verified' => $m['verified'] ?? null,
        ]);
    }

    /** @param array<string,mixed> $m */
    private static function identityAssertionFromMap(array $m): IdentityAssertion
    {
        return new IdentityAssertion([
            'user_id' => $m['user_id'] ?? null,
            'domain' => $m['domain'] ?? null,
            'audience' => $m['audience'] ?? null,
            'nonce' => $m['nonce'] ?? null,
            'issued_at' => $m['issued_at'] ?? null,
            'expires_at' => $m['expires_at'] ?? null,
            'authorized_claims' => $m['authorized_claims'] ?? [],
            'display_name' => $m['display_name'] ?? null,
        ]);
    }

    public static function encodeRpUserInfoRequest(RpUserInfoRequest $v): string
    {
        return Cbor::encodeMap([
            'token' => $v->token,
            'api_base' => $v->apiBase,
            'domain' => $v->domain,
        ]);
    }

    public static function decodeUserInfo(string $bytes): UserInfo
    {
        $m = Cbor::decode($bytes);
        $claims = array_map(fn ($c) => Wire::claimFromMap($c), $m['claims'] ?? []);
        return new UserInfo([
            'user_id' => $m['user_id'] ?? null,
            'domain' => $m['domain'] ?? null,
            'display_name' => $m['display_name'] ?? null,
            'claims' => $claims,
        ]);
    }
}
```

### `src/RpRpcClient.php`

The transport. There is no packaged regular-RP client for PHP, so this is
exactly what a PHP app is expected to hand-roll — it's structurally
`sdks/local-rp/php/src/Rpc.php`'s `call()`/frame helpers (length-prefixed
CBOR-over-TLS, tag-24 payload framing — see that file's own docblock for why
it hand-builds the envelope instead of going through the generated client),
reusing this SDK's `Cbor`, `Tls::dialTlsPinned()`, and `StdTransport`
directly (all three are generic — nothing in them is local-RP-specific).
The one real addition versus `Rpc.php` is the envelope's optional `auth`
field
(`~/repos/catalystcommunity/csilgen/docs/csil-rpc-transport.md`, §1.1),
carrying this app's API key: `Rp` is a caller-scoped service gated by
`api_access` (see "Prerequisites" above), unlike the unauthenticated
`LocalRp`/`DomainKeys` ops `Rpc.php` was built for, which authenticate by
DNS-pinned TLS alone and carry no `auth` field.

```php
<?php

declare(strict_types=1);

namespace App\LinkKeysRp;

use Csilgen\Generated\RpDecryptRequest;
use Csilgen\Generated\RpDecryptResponse;
use Csilgen\Generated\RpSignRequest;
use Csilgen\Generated\RpSignResponse;
use Csilgen\Generated\RpUserInfoRequest;
use Csilgen\Generated\RpVerifyRequest;
use Csilgen\Generated\RpVerifyResponse;
use Csilgen\Generated\UserInfo;
use LinkKeys\LocalRp\Cbor;
use LinkKeys\LocalRp\CborBytes;
use LinkKeys\LocalRp\CborTag;
use LinkKeys\LocalRp\StdTransport;
use LinkKeys\LocalRp\Tls;
use LinkKeys\LocalRp\Transport;

/**
 * A minimal CSIL-RPC client for the regular-RP browser login flow: dial this
 * app's own RP server over TCP, TLS-pin its certificate to the RP domain's
 * DNS `fp=` fingerprints (published via `linkkeys domain dns-check` -- see
 * example.md "Prerequisites"), and call the `Rp` service's four
 * browser-login ops.
 *
 * There is no packaged regular-RP client for PHP (unlike the local-RP flow,
 * which ships sdks/local-rp/php/ end-to-end) -- this class is exactly what
 * a PHP app is expected to hand-roll, cribbing the framing from the local-RP
 * SDK's sdks/local-rp/php/src/Rpc.php `call()`/frame helpers. The one real
 * addition versus Rpc.php is the envelope's optional `auth` field
 * (~/repos/catalystcommunity/csilgen/docs/csil-rpc-transport.md sec 1.1),
 * carrying this app's API key: `Rp` is a caller-scoped service
 * (crates/linkkeys/src/services/authorization.rs:
 * `"Rp" => Some(RELATION_API_ACCESS)`), unlike the unauthenticated
 * LocalRp/DomainKeys ops Rpc.php was built for, which authenticate by
 * DNS-pinned TLS alone.
 */
final class RpRpcClient
{
    /** Mirrors the server's own cap (crates/linkkeys-rpc-client/src/lib.rs). */
    private const MAX_FRAME_SIZE = 1024 * 1024;
    private const CSIL_RPC_VERSION = 1;
    private const TAG_ENCODED_CBOR = 24;

    /** @param string[] $fingerprints DNS `_linkkeys` fp= set for the RP's own domain. */
    public function __construct(
        private readonly string $tcpAddr,
        private readonly array $fingerprints,
        private readonly string $apiKey,
        private readonly Transport $transport = new StdTransport(),
    ) {
    }

    public function signRequest(RpSignRequest $req): RpSignResponse
    {
        return RpWire::decodeRpSignResponse(
            $this->call('sign-request', RpWire::encodeRpSignRequest($req))
        );
    }

    public function decryptToken(RpDecryptRequest $req): RpDecryptResponse
    {
        return RpWire::decodeRpDecryptResponse(
            $this->call('decrypt-token', RpWire::encodeRpDecryptRequest($req))
        );
    }

    public function verifyAssertion(RpVerifyRequest $req): RpVerifyResponse
    {
        return RpWire::decodeRpVerifyResponse(
            $this->call('verify-assertion', RpWire::encodeRpVerifyRequest($req))
        );
    }

    public function userinfoFetch(RpUserInfoRequest $req): UserInfo
    {
        return RpWire::decodeUserInfo(
            $this->call('userinfo-fetch', RpWire::encodeRpUserInfoRequest($req))
        );
    }

    /** Dial, TLS-pin, send one framed request, read one framed response, close. */
    private function call(string $op, string $payload): string
    {
        $raw = $this->transport->dial($this->tcpAddr);
        $hostname = Tls::extractHostname($this->tcpAddr);
        try {
            $stream = Tls::dialTlsPinned($raw, $hostname, $this->fingerprints);
        } catch (\Throwable $e) {
            fclose($raw);
            throw $e;
        }
        try {
            self::sendFrame($stream, $this->encodeRequest($op, $payload));
            $respBytes = self::recvFrame($stream);
        } finally {
            fclose($stream);
        }

        $resp = self::decodeResponse($respBytes);
        if ($resp['status'] !== 0) {
            throw new RpRpcServerError($resp['status'], $resp['error'] ?? 'unknown error', $op);
        }
        return $resp['payload'];
    }

    private function encodeRequest(string $op, string $payload): string
    {
        return Cbor::encode([
            'v' => self::CSIL_RPC_VERSION,
            'service' => 'Rp',
            'op' => $op,
            'payload' => Cbor::tag(self::TAG_ENCODED_CBOR, Cbor::bytes($payload)),
            'auth' => $this->apiKey,
        ]);
    }

    /** @return array{status:int, variant:?string, error:?string, payload:string} */
    private static function decodeResponse(string $bytes): array
    {
        $m = Cbor::decode($bytes);
        if (!is_array($m) || !isset($m['status']) || !is_int($m['status'])) {
            throw new RpRpcProtocolError("RPC response envelope missing integer 'status'");
        }
        $payloadTag = $m['payload'] ?? null;
        $payload = '';
        if ($payloadTag instanceof CborTag && $payloadTag->tag === self::TAG_ENCODED_CBOR) {
            $payload = $payloadTag->value instanceof CborBytes ? $payloadTag->value->data : (string) $payloadTag->value;
        }
        return [
            'status' => $m['status'],
            'variant' => $m['variant'] ?? null,
            'error' => $m['error'] ?? null,
            'payload' => $payload,
        ];
    }

    /** @param resource $stream */
    private static function sendFrame($stream, string $data): void
    {
        self::writeAll($stream, pack('N', strlen($data)) . $data);
    }

    /** @param resource $stream */
    private static function writeAll($stream, string $data): void
    {
        $total = strlen($data);
        $written = 0;
        while ($written < $total) {
            $n = fwrite($stream, substr($data, $written));
            if ($n === false || $n === 0) {
                throw new RpRpcTransportError('connection closed or timed out while writing');
            }
            $written += $n;
        }
    }

    /** @param resource $stream */
    private static function readExact($stream, int $n): string
    {
        $buf = '';
        while (strlen($buf) < $n) {
            $chunk = fread($stream, $n - strlen($buf));
            if ($chunk === false || $chunk === '') {
                throw new RpRpcProtocolError('connection closed before expected bytes were received');
            }
            $buf .= $chunk;
        }
        return $buf;
    }

    /** @param resource $stream */
    private static function recvFrame($stream): string
    {
        $lenBytes = self::readExact($stream, 4);
        $len = unpack('N', $lenBytes)[1];
        if ($len > self::MAX_FRAME_SIZE) {
            throw new RpRpcProtocolError("peer frame too large ({$len} bytes, max " . self::MAX_FRAME_SIZE . ')');
        }
        return self::readExact($stream, $len);
    }
}

class RpRpcError extends \RuntimeException
{
}

final class RpRpcProtocolError extends RpRpcError
{
}

final class RpRpcTransportError extends RpRpcError
{
}

final class RpRpcServerError extends RpRpcError
{
    public function __construct(public readonly int $status, public readonly string $errorMessage, string $op)
    {
        parent::__construct("Rp/{$op} failed: server status {$status}: {$errorMessage}");
    }
}
```

### `login.php`

Starts a login: builds a claim request, calls `Rp/sign-request`, stashes
single-use pending-login state in the PHP session, and redirects.

```php
<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use App\LinkKeysRp\RpRpcClient;
use Csilgen\Generated\ClaimRequest;
use Csilgen\Generated\RequestedClaim;
use Csilgen\Generated\RpSignRequest;

session_start();

$cfg = rp_config();
if ($cfg['api_key'] === '' || $cfg['fingerprints'] === [] || $cfg['domain'] === '') {
    http_response_code(500);
    echo 'This app is not configured: set RP_TCP_ADDR, RP_FINGERPRINTS, RP_API_KEY, RP_DOMAIN.';
    exit;
}

// The default claim set (matches the local-RP SDKs' begin_local_login
// default -- see docs/local-rp-app-developer-guide.md "The default claim
// set"): required=[handle], optional=[display_name, email].
$claims = new ClaimRequest([
    'required' => [
        new RequestedClaim(['claim_type' => 'handle', 'datatype' => 'text']),
    ],
    'optional' => [
        new RequestedClaim(['claim_type' => 'display_name', 'datatype' => 'text']),
        new RequestedClaim(['claim_type' => 'email', 'datatype' => 'email']),
    ],
]);

$nonce = bin2hex(random_bytes(16));
$callbackUrl = app_origin() . '/callback.php';

$client = new RpRpcClient($cfg['tcp_addr'], $cfg['fingerprints'], $cfg['api_key']);
try {
    $signed = $client->signRequest(new RpSignRequest([
        'callback_url' => $callbackUrl,
        'nonce' => $nonce,
        'requested_claims' => $claims,
    ]));
} catch (\Throwable $e) {
    // Never leak transport/server internals to the browser.
    error_log('linkkeys sign-request failed: ' . $e->getMessage());
    http_response_code(502);
    echo 'Could not start login (RP server unreachable). Try again shortly.';
    exit;
}

// This is this app's PendingLogin equivalent: single-use state tying the
// callback back to the request we just signed. Stored server-side in the
// PHP session (not a client-visible cookie value) and burned by
// callback.php on its very first read, before any verification -- see
// callback.php's comment on why that ordering matters.
$_SESSION['linkkeys_login'] = [
    'nonce' => $nonce,
    'domain' => $cfg['domain'],
    'api_base' => resolve_api_base($cfg['domain']),
];

$userHint = isset($_GET['identity']) && is_string($_GET['identity']) ? $_GET['identity'] : null;

$redirectUrl = $_SESSION['linkkeys_login']['api_base'] . '/auth/authorize?' . http_build_query(array_filter([
    'signed_request' => $signed->signedRequest,
    'user_hint' => $userHint,
]));

header('Location: ' . $redirectUrl, true, 302);
```

Note `$cfg['domain']` here is *this app's own* RP domain (used as
`expected_domain` in step 5), not the user's IDP domain — the user never
tells this app which IDP to use directly; that's baked into whichever
LinkKeys account they choose to authenticate with when `/auth/authorize`
prompts them. `api_base` is resolved from the **RP's own** `_linkkeys_apis`
`https=` record (falling back to `https://{domain}`) because
`/auth/authorize` is served by the RP's own domain server in this
architecture — the RP server IS the "IDP" here in the sense that matters for
this redirect (it's whichever LinkKeys server holds the private key this
app's users authenticate against).

### `callback.php`

Handles the IDP's redirect back: decrypts and verifies the token, checks the
nonce/domain, fetches claims, and mints this app's own session.

```php
<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use App\LinkKeysRp\RpRpcClient;
use Csilgen\Generated\RpDecryptRequest;
use Csilgen\Generated\RpUserInfoRequest;
use Csilgen\Generated\RpVerifyRequest;

session_start();

// 1. Retrieve and immediately clear the pending-login state. Burning it here
// -- before any verification, and even if what follows fails -- is what
// makes it single-use: a second request carrying the same (or a replayed)
// encrypted_token now has no pending state to check against and is
// rejected outright. This is this app's job: the RP server and the SDK
// wire format do not enforce single-use for you.
$pending = $_SESSION['linkkeys_login'] ?? null;
unset($_SESSION['linkkeys_login']);

if ($pending === null) {
    http_response_code(400);
    echo 'No pending login found (expired, already completed, or a forged callback).';
    exit;
}

$encryptedToken = $_GET['encrypted_token'] ?? null;
if (!is_string($encryptedToken) || $encryptedToken === '') {
    http_response_code(400);
    echo 'Missing encrypted_token.';
    exit;
}

$cfg = rp_config();
$client = new RpRpcClient($cfg['tcp_addr'], $cfg['fingerprints'], $cfg['api_key']);

try {
    // 2. Decrypt the token via the RP server (it holds the domain encryption
    // key; this app never does).
    $decrypted = $client->decryptToken(new RpDecryptRequest([
        'encrypted_token' => $encryptedToken,
    ]));

    // 3. Verify the decrypted assertion against the issuing domain's
    // published signing keys (the RP server fetches + pins those; this app
    // never touches key material at any step).
    $verified = $client->verifyAssertion(new RpVerifyRequest([
        'signed_assertion' => $decrypted->signedAssertion,
        'expected_domain' => $pending['domain'],
    ]));
} catch (\Throwable $e) {
    error_log('linkkeys decrypt/verify failed: ' . $e->getMessage());
    http_response_code(502);
    echo 'Could not complete login (RP server unreachable, or the token/assertion was invalid).';
    exit;
}
$assertion = $verified->assertion;

// 4. Nonce check: ties this callback to the login we started, and -- because
// $pending was already burned above -- can only ever succeed once per
// signed request.
if ($assertion->nonce !== $pending['nonce']) {
    http_response_code(400);
    echo 'Nonce mismatch -- possible replay.';
    exit;
}

// 5. Domain check: the assertion must actually be about the domain this
// login flow was started for.
if ($assertion->domain !== $pending['domain']) {
    http_response_code(400);
    echo 'Domain mismatch.';
    exit;
}

// 6. Fetch the user's claims via the RP server. The IDP binds redemption to
// the audience (this app's RP domain), and only the RP server holds the
// domain key needed to prove that, so this app delegates the fetch to it
// rather than calling the IDP directly.
try {
    $userInfo = $client->userinfoFetch(new RpUserInfoRequest([
        'token' => $decrypted->signedAssertion,
        'api_base' => $pending['api_base'],
        'domain' => $pending['domain'],
    ]));
} catch (\Throwable $e) {
    error_log('linkkeys userinfo-fetch failed: ' . $e->getMessage());
    http_response_code(502);
    echo 'Could not complete login (fetching your claims failed). Try again shortly.';
    exit;
}

// 7. Mint this app's own session. Everything above only produces verified
// protocol facts -- deciding what a "logged in" session means, and any
// local-account mapping, is this app's business logic from here.
$_SESSION['user'] = [
    'user_id' => $userInfo->userId,
    'domain' => $userInfo->domain,
    'display_name' => $userInfo->displayName,
    'claims' => array_map(
        static fn ($c) => ['claim_type' => $c->claimType, 'claim_value' => $c->claimValue],
        $userInfo->claims
    ),
];

header('Location: /', true, 302);
```

## App responsibilities (this example does NOT do these for you)

Same shape as the local-RP SDK's own "App responsibilities" section in this
package's `README.md` — nothing here is magic, and the split of
responsibility is deliberate:

- **Nonce single-use, via the session.** `login.php` generates the nonce and
  stores it (plus the expected domain) in `$_SESSION`; `callback.php` reads
  and immediately `unset()`s that session entry *before* doing any
  verification. That ordering is what makes a replayed `encrypted_token`
  fail fast with "No pending login found" instead of re-running the whole
  decrypt/verify/userinfo sequence a second time. If you skip the `unset()`,
  or do it after verification instead of before, you've reopened a replay
  window.
- **Sessions.** Nothing here mints a session, cookie, or token for you.
  `callback.php` writes `$_SESSION['user']` as an example; your app decides
  what "logged in" actually means (expiry, refresh, local account linkage).
- **API key storage.** `RP_API_KEY` grants `Rp` service access on your RP
  server's domain — treat it as a database credential, not application
  config. Don't log it, don't commit it, and don't return it or its presence
  to a client.
- **Local user records and authorization decisions.** Whether a verified
  `user_id`/`domain` maps to an existing local account, a brand-new one, or
  gets turned away is entirely this app's business logic — this example
  stops at `$_SESSION['user']`.

## Local-RP vs. regular-RP

This directory (`sdks/local-rp/php/`) and this example solve different
problems; use the right one:

| | local-RP (the SDK in this directory) | Regular RP (this example) |
|---|---|---|
| Who's logging in | Any LinkKeys user, at their own DNS-pinned domain | Same |
| Your app's identity | A locally-generated Ed25519 key, SSH-host-key style | Your own DNS-published LinkKeys domain |
| Needs a public domain | No | Yes |
| Needs its own LinkKeys server | No — `sdks/local-rp/php/` is a pure library, no I/O beyond the network calls it makes itself | Yes — a sidecar RP server holding your domain keys |
| Typical app | LAN jukebox, desktop tool, self-hosted app with no public DNS | Any web app with a real domain wanting "Log in with LinkKeys" |
| Key custody | Your app holds its own signing/encryption keypair (`Identity::localRpIdentityToBytes()`) | Your RP server holds the domain keys; your app never touches key material |
| Where the flow is documented | This package's `README.md` + `docs/local-rp-app-developer-guide.md` | This file |

If your app doesn't have (and isn't getting) a public domain, use the
local-RP SDK instead — its README's "Quickstart" is the place to start, and
`begin_local_login`/`complete_local_login` replace steps 1–7 above with two
function calls.

## Verifying this example

No system PHP on this box; every file above was written out and run through
`php:8.3-cli` (the same container pattern `sdks/local-rp/php/run-tests.sh`
documents as its fallback):

```sh
sudo nerdctl run --rm -v "$(pwd)":/repo -w /repo php:8.3-cli php -l bootstrap.php
sudo nerdctl run --rm -v "$(pwd)":/repo -w /repo php:8.3-cli php -l login.php
sudo nerdctl run --rm -v "$(pwd)":/repo -w /repo php:8.3-cli php -l callback.php
sudo nerdctl run --rm -v "$(pwd)":/repo -w /repo php:8.3-cli php -l src/RpWire.php
sudo nerdctl run --rm -v "$(pwd)":/repo -w /repo php:8.3-cli php -l src/RpRpcClient.php
```

All five lint clean. Beyond linting, the wire layer's encode/decode was
round-tripped against hand-built CBOR maps (`RpWire.php`'s
list-typed fields — `requested_claims.required`/`.optional`,
`authorized_claims`, `claims`, `claims[].signatures` — were specifically
checked to survive round-trip, since that's exactly the shape the
generated-codec bug this file works around loses), and `login.php` /
`callback.php` were each executed directly (with env-based config and
`$_GET` set the way a real request would populate them) against a
`127.0.0.1` address with nothing listening: both ran cleanly through all
their non-network logic (config validation, claim-request construction,
session/nonce bookkeeping, the TLS-pin dial attempt itself) and failed with
the intended clean, user-facing error — not a PHP fatal — at the point where
a real RP server would have answered. Running `callback.php` twice in a row
against the same session (simulating a replayed `encrypted_token`) confirmed
the second attempt is rejected immediately with "No pending login found,"
without attempting a network call at all.
