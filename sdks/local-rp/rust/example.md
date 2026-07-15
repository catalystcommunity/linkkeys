# Regular (DNS-pinned) LinkKeys login in Rust

This crate (`linkkeys-local-rp`) implements **local-RP** identity: a locally
installed app authenticates using the fingerprint of its own signing key
instead of a domain. If that's what you want — a LAN box, a desktop tool, a
service with no public DNS — stop here and read this crate's own
[`README.md`](./README.md) instead.

This document is for the *other*, far more common case: your app has a public
domain (or at least a real relying-party identity you're willing to run a
LinkKeys server for) and you want to accept logins from users who prove their
identity against **their own** DNS-pinned LinkKeys domain. That's "regular"
LinkKeys — the protocol's primary mode. There is no separate Rust client SDK
for it; instead you run a small LinkKeys server next to your app in **RP
mode**, and your app talks to that server over the CSIL-RPC TCP transport
using the `linkkeys-rpc-client` crate. Rust is the one language in this repo
with a packaged client for that transport — every other language currently
has to speak the wire protocol by hand or shell out.

Everything below was verified against this repo's own code as of this
writing: `docs/DEPLOYING-RP.md`, `crates/linkkeys/src/tcp/mod.rs`,
`crates/linkkeys/src/services/authorization.rs`, `crates/linkkeys/src/web/rp.rs`,
`csil/linkkeys.csil`, and `demoappsite/src/main.rs` (the reference
integration this walkthrough is a trimmed-down copy of). The example code was
compiled — see "What was compiled" at the end.

## Architecture

```
┌──────────────────────────────────────────────────┐
│            Your Application Stack                 │
│                                                     │
│  ┌──────────────┐    ┌────────────────────────┐   │
│  │   Your App   │    │   LinkKeys RP Server    │   │
│  │  (this doc)  │───►│  (same linkkeys image)  │   │
│  │              │    │                         │   │
│  │  Sessions    │    │  rp.enabled             │   │
│  │  Redirects   │    │  Holds domain keys      │   │
│  │              │    │  Signs auth requests    │   │
│  │              │    │  Decrypts tokens        │   │
│  └──────────────┘    └────────────────────────┘   │
│                                                     │
│  App calls its RP server over TCP CSIL-RPC,        │
│  authenticated with an API key. The app never      │
│  touches a private key.                            │
└──────────────────────────────────────────────────┘
```

Your app is **not** the relying party in the protocol sense — the RP server
is. It holds the domain key pair, signs the outgoing auth request, and
decrypts the token the IDP sends back. Your app is a thin client of that
server: it never sees a private key, only an API key that authorizes it to
call four helper operations. This is the same architecture
`docs/DEPLOYING-RP.md` describes and `demoappsite/` implements; see that doc
for the Helm/Kubernetes deployment side, which this document does not repeat.

## Prerequisites

### 1. Deploy your own RP server

Follow `docs/DEPLOYING-RP.md` end to end: same LinkKeys Docker image/Helm
chart as a full IDP, but with `rp.enabled: true` (no login UI, no human user
accounts, service accounts only). Come back here once it's running.

### 2. Initialize domain keys

```sh
linkkeys domain init
```

### 3. Create a service account for your app, with the `api_access` relation

The `Rp` service (`sign-request`, `decrypt-token`, `verify-assertion`,
`userinfo-fetch`) is authenticated by API key **and** requires the caller to
hold the `api_access` relation on the domain — a valid key alone is not
enough (`crates/linkkeys/src/services/authorization.rs`, `required_relation_for_op`,
marked `SEC-06` in the source: "must require a dedicated api_access relation,
not merely a valid API key — otherwise any active user's key can drive those
oracles"). `user create` can grant it at creation time in one step:

```sh
linkkeys user create my-webapp "My Web Application" --api-key --relation api_access

# User created: id=<uuid>
# API key: <key>
# (save this — it will not be shown again)
```

`--relation` is repeatable and validates against a fixed grantable set
(`admin`, `manage_users`, `manage_claims`, `api_access`, `issue_claims`) —
a typo is rejected at creation time rather than silently producing a key that
reads as "Forbidden" later.

If you already created the service account without `--relation api_access`,
grant it after the fact (idempotent, safe to re-run) directly against the
local database from inside the RP pod:

```sh
linkkeys relation grant-local my-webapp api_access
```

**Doc-vs-code note:** `docs/DEPLOYING-RP.md`'s own "Initial Setup" example
runs `linkkeys user create my-webapp "My Web Application" --api-key` *without*
`--relation api_access`. Followed literally, every `Rp/*` call from your app
would fail with `Forbidden` until you separately ran the `relation
grant-local` command above. Use the one-step `--relation api_access` form
above, or remember the follow-up grant.

### 4. Get the RP server's TLS fingerprints (for pinning)

Your app connects to its own RP server as a TLS client and must pin its
certificate the same way any LinkKeys peer would — this is not a CA-verified
connection. List the RP server's active signing keys from inside the RP pod:

```sh
linkkeys domain list-keys
# ID                                     USAGE    STATUS     FINGERPRINT
# <uuid>                                 sign     active     <fingerprint>
```

Collect the `sign`/`active` fingerprint(s) into a comma-separated list — this
is `RP_FINGERPRINTS` below.

### 5. Publish DNS for the RP server's own domain

The RP server signs the outgoing auth request as *its own* domain (the
`relying_party` field is the RP server's `DOMAIN_NAME` env var — the same
`server.domainName` Helm value from `docs/DEPLOYING-RP.md`'s "Initial Setup"
— see `sign_request_core` in `crates/linkkeys/src/web/rp.rs`). The
issuing IDP needs to resolve that domain's public key to encrypt the token
back to your RP server. Publish what `linkkeys domain dns-check` prints for
the RP server's domain:

```
_linkkeys.<rp-domain> TXT "v=lk1 api=https://<rp-domain> fp=<fingerprint1> fp=<fingerprint2> ..."
_linkkeys_apis.<rp-domain> TXT "v=lk1 tcp=<rp-domain> https=<rp-domain>"
```

This is a **different** domain from the one your end user types into your
login form — that one is the user's own LinkKeys IDP, resolved at request
time by DNS lookup; you don't publish anything for it.

### Environment variables your app needs

| Variable | Where it comes from |
|---|---|
| `RP_TCP_ADDR` | `host:port` of your RP server's TCP listener (step 1); defaults to `127.0.0.1:<DEFAULT_TCP_PORT>` for a sidecar deployment |
| `RP_FINGERPRINTS` | Comma-separated fingerprints from step 4 |
| `RP_API_KEY` | The API key printed in step 3 — store it the same tier as a database credential, never log it |

## The flow, over TCP CSIL-RPC

The HTTP `/v1alpha/*.json` routes that `docs/DEPLOYING-RP.md`'s current "Web
App Integration" section describes (`sign-request.json`, `decrypt-token.json`,
`verify-assertion.json`) **no longer exist in this server** — they were
removed when server-to-server traffic moved to the TCP CSIL-RPC transport
(`git log -p` shows them deleted from `crates/linkkeys/src/web/rp.rs`, with no
matching update to that doc section). Use the `Rp` service over TCP as below;
it is the only carrier this server actually implements for these operations.

1. **`Rp/sign-request`** — `{callback_url, nonce, ?requested_claims,
   ?flow_context}` → `{signed_request}`. Redirect the user's browser to
   `https://<user_domain>/auth/authorize?signed_request=<signed_request>`
   (optionally `&user_hint=<hint>`). Everything the IDP needs —
   `relying_party`, `callback_url`, `nonce` — travels signed inside
   `signed_request`; the IDP's `/auth/authorize` handler reads only
   `signed_request` and `user_hint` from the query string
   (`crates/linkkeys/src/web/mod.rs`, `auth_authorize_get`).
2. The user authenticates at their own IDP and consents to the claims. The
   browser is redirected to your `callback_url` with `?encrypted_token=<...>`.
3. **`Rp/decrypt-token`** — `{encrypted_token}` → `{signed_assertion}`.
4. **`Rp/verify-assertion`** — `{signed_assertion, expected_domain}` →
   `{assertion, verified}`. Pass the **domain the user originally typed**, not
   anything from the token — this is what pins the result to the identity the
   user claimed to have.
5. **`Rp/userinfo-fetch`** (optional) — `{token, api_base, domain}` →
   `UserInfo` (`user_id`, `domain`, `display_name`, `claims`), scoped to the
   claim types the user actually consented to release.

All four `Rp` ops (`sign-request`, `decrypt-token`, `verify-assertion`,
`userinfo-fetch`) are authenticated by putting the API key in the CSIL-RPC
envelope's `auth` field (`RpcRequest::with_auth`); the server's
`authenticate_tcp_request` looks it up via `ApiKeyAuthenticator` and rejects
missing/invalid/deactivated keys before `required_relation_for_op` even runs
(`crates/linkkeys/src/tcp/mod.rs`).

## Code walkthrough

### Cargo.toml

```toml
[dependencies]
rocket = { version = "0.5", features = ["tls", "secrets"] }
liblinkkeys = { path = "../../../crates/liblinkkeys" }
linkkeys-rpc-client = { path = "../../../crates/linkkeys-rpc-client" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1", features = ["full"] }
uuid = { version = "1.10", features = ["v4"] }
log = "0.4"
env_logger = "0.11"
chrono = { version = "0.4", features = ["serde"] }
```

(Adjust the `path` deps to your app's actual location relative to this repo,
or vendor/pin the crates however your build normally consumes them —
`linkkeys-rpc-client` deliberately depends on nothing but `liblinkkeys` and
`csilgen-transport`, so it carries no diesel/network-seam baggage into your
app.)

### Supporting types

Plain app-owned state — none of this comes from the protocol layer:

```rust
use rocket::http::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Mutex;

/// What the app persists between redirecting the browser to the IDP and the
/// callback arriving.
#[derive(Serialize, Deserialize)]
struct AuthState {
    nonce: String,
    domain: String,
}

/// The app's own session, minted only after `verify-assertion` succeeds.
#[derive(Serialize, Deserialize)]
struct Session {
    user_id: String,
    domain: String,
    display_name: String,
}

/// Nonces already redeemed at `/callback` — see "Nonce single-use" below for
/// why an in-process `HashSet` is a stand-in, not a production answer.
struct SeenNonces(Mutex<HashSet<String>>);
```

### RP config and the blocking-client bridge

`linkkeys-rpc-client::send_request` is a **blocking** call (plain
`std::net::TcpStream` + `rustls::StreamOwned`) — there is no async client.
Inside an async framework like Rocket, run it on a blocking thread with
`tokio::task::spawn_blocking`, mirroring how this same server's own Rocket
routes use `spawn_blocking` for their diesel calls (see AGENTS.md's
"Sync/Async Boundary" note — the same boundary applies to your app's outbound
RP calls):

```rust
struct RpConfig {
    tcp_addr: String,
    fingerprints: Vec<String>,
    api_key: String,
}

async fn rp_call<Req, Resp>(
    rp: &RpConfig,
    op: &'static str,
    req: Req,
    encode: fn(&Req) -> Vec<u8>,
    decode: fn(&[u8]) -> Result<Resp, liblinkkeys::generated::codec::CsilCborError>,
) -> Result<Resp, String> {
    let addr = rp.tcp_addr.clone();
    let fingerprints = rp.fingerprints.clone();
    let api_key = rp.api_key.clone();
    let payload = encode(&req);
    let resp_bytes = tokio::task::spawn_blocking(move || {
        linkkeys_rpc_client::send_request(
            &addr,
            fingerprints,
            None, // no client cert: the app has no domain key, only an API key
            "Rp",
            op,
            payload,
            Some(&api_key),
        )
    })
    .await
    .map_err(|e| format!("RP task join failed: {}", e))?
    .map_err(|e| format!("RP {} failed: {}", op, e))?;
    decode(&resp_bytes).map_err(|e| format!("RP {} decode failed: {}", op, e))
}
```

`encode`/`decode` are the generated CSIL codec functions
(`liblinkkeys::generated::encode_rp_sign_request`,
`decode_rp_sign_response`, etc.) — no hand-rolled mirror structs, the same
approach `demoappsite/src/main.rs` uses.

### `/login`: sign the request and redirect

```rust
use liblinkkeys::generated::types as lk;

#[rocket::post("/login", data = "<form>")]
async fn login(
    cookies: &CookieJar<'_>,
    rp_config: &State<RpConfig>,
    form: rocket::form::Form<LoginForm>,
) -> Result<Redirect, RawHtml<String>> {
    let user_domain = form.domain.trim().to_string();
    if user_domain.is_empty() {
        return Err(error_page("Please enter a domain"));
    }

    let nonce = uuid::Uuid::new_v4().to_string();
    let callback_url = format!("{}/callback", get_own_origin());

    let sign_result = rp_call(
        rp_config,
        "sign-request",
        lk::RpSignRequest {
            callback_url,
            nonce: nonce.clone(),
            requested_claims: Some(lk::ClaimRequest {
                required: vec![lk::RequestedClaim {
                    claim_type: "display_name".to_string(),
                    datatype: "text".to_string(),
                }],
                optional: vec![],
            }),
            flow_context: None,
        },
        liblinkkeys::generated::encode_rp_sign_request,
        liblinkkeys::generated::decode_rp_sign_response,
    )
    .await
    .map_err(|e| error_page(&format!("Failed to contact RP service: {}", e)))?;

    // Persist just enough to check the callback: the nonce we generated and
    // the domain the user chose. Here it's a signed, http-only cookie; a
    // server-side session store works too.
    let auth_state = AuthState { nonce, domain: user_domain };
    let mut state_cookie = Cookie::new(
        "auth_state",
        serde_json::to_string(&auth_state).expect("auth_state serializes"),
    );
    state_cookie.set_same_site(SameSite::Lax);
    state_cookie.set_path("/");
    state_cookie.set_http_only(true);
    state_cookie.set_secure(true);
    cookies.add_private(state_cookie);

    let redirect_url = format!(
        "https://{}/auth/authorize?signed_request={}",
        auth_state.domain, sign_result.signed_request
    );

    Ok(Redirect::found(redirect_url))
}
```

`sign_result.signed_request` is already the URL-param-encoded envelope the
IDP expects (`liblinkkeys::encoding::signed_auth_request_to_url_param` on the
server side) — the app doesn't touch its bytes, only forwards it.

### `/callback`: decrypt, verify, and mint a session

```rust
#[rocket::get("/callback?<encrypted_token>")]
async fn callback(
    cookies: &CookieJar<'_>,
    rp_config: &State<RpConfig>,
    seen_nonces: &State<SeenNonces>,
    encrypted_token: &str,
) -> Result<Redirect, RawHtml<String>> {
    let auth_state: AuthState = cookies
        .get_private("auth_state")
        .and_then(|c| serde_json::from_str(c.value()).ok())
        .ok_or_else(|| error_page("No auth state found — login flow may have expired"))?;
    cookies.remove_private("auth_state");

    // Step 3: Rp/decrypt-token
    let decrypt_result = rp_call(
        rp_config,
        "decrypt-token",
        lk::RpDecryptRequest { encrypted_token: encrypted_token.to_string() },
        liblinkkeys::generated::encode_rp_decrypt_request,
        liblinkkeys::generated::decode_rp_decrypt_response,
    )
    .await
    .map_err(|e| error_page(&format!("Failed to decrypt token: {}", e)))?;

    // Step 4: Rp/verify-assertion, pinned to the domain the user typed at
    // /login — never the domain the token claims to be from.
    let verify_result = rp_call(
        rp_config,
        "verify-assertion",
        lk::RpVerifyRequest {
            signed_assertion: decrypt_result.signed_assertion.clone(),
            expected_domain: auth_state.domain.clone(),
        },
        liblinkkeys::generated::encode_rp_verify_request,
        liblinkkeys::generated::decode_rp_verify_response,
    )
    .await
    .map_err(|e| error_page(&format!("Failed to verify assertion: {}", e)))?;

    if !verify_result.verified {
        return Err(error_page("Assertion did not verify"));
    }
    let assertion = &verify_result.assertion;

    // App responsibility: reject on nonce mismatch...
    if assertion.nonce != auth_state.nonce {
        return Err(error_page("Nonce mismatch — possible replay attack"));
    }
    // ...and reject if this nonce has already been redeemed once (single-use).
    {
        let mut seen = seen_nonces.0.lock().expect("seen_nonces lock");
        if !seen.insert(assertion.nonce.clone()) {
            return Err(error_page("This login has already been used"));
        }
    }
    if assertion.domain != auth_state.domain {
        return Err(error_page("Domain mismatch"));
    }

    // Step 5 (optional): Rp/userinfo-fetch for the claims the user consented to.
    let user_info = rp_call(
        rp_config,
        "userinfo-fetch",
        lk::RpUserInfoRequest {
            token: decrypt_result.signed_assertion.clone(),
            api_base: format!("https://{}", auth_state.domain),
            domain: auth_state.domain.clone(),
        },
        liblinkkeys::generated::encode_rp_user_info_request,
        liblinkkeys::generated::decode_user_info,
    )
    .await
    .map_err(|e| error_page(&format!("Failed to fetch user info: {}", e)))?;

    let session = Session {
        user_id: user_info.user_id,
        domain: user_info.domain,
        display_name: user_info.display_name,
    };
    set_session(cookies, &session);
    Ok(Redirect::found("/"))
}
```

The `api_base` field on `RpUserInfoRequest` above is simplified to
`https://<domain>` for brevity; the actual claim redemption still resolves the
issuing domain's `tcp=` endpoint itself and doesn't depend on `api_base` being
exactly right (`fetch_userinfo_core` in `crates/linkkeys/src/web/rp.rs`).
`api_base` is only compared, host-only, against the RP server's own published
API host to decide whether this is a same-instance IDP+RP shortcut — get it
wrong and userinfo-fetch still works, it just always takes the network path
instead of redeeming locally when it could have. `demoappsite/src/main.rs`'s
`resolve_api_base` shows the fuller version: look up the
`_linkkeys_apis.<domain>` DNS TXT record and use its `https=` value, falling
back to `https://<domain>` only if no record is found.

## App responsibilities this walkthrough makes explicit

Exactly as `sdks/local-rp/rust/README.md` says of the local-RP SDK, none of
this is owned by `liblinkkeys` or `linkkeys-rpc-client` — the protocol layer
returns verified facts, and everything below is on your app:

- **Nonce single-use.** `Rp/verify-assertion` tells you the assertion is
  cryptographically valid and which nonce it carries; it does **not** track
  which nonces you've already redeemed. The `SeenNonces` set above is
  in-process and resets on restart — a real deployment should back this with
  a database row or a keyed cache entry with a TTL matching
  `assertion.expires_at`, shared across app instances, so replay is rejected
  even after a restart or behind a load balancer.
- **Domain pinning at verify time.** Always pass the domain the user
  originally typed as `expected_domain` — never a value read back out of the
  token itself — and re-check `assertion.domain` against it after verifying.
- **Sessions, local user records, authorization decisions.** `UserInfo`
  gives you `user_id`, `domain`, `display_name`, and `claims`; turning that
  into a session, a local account row, or an authorization decision is your
  app's own logic, same as for the local-RP SDK.
- **API key storage.** `RP_API_KEY` authorizes your app to drive your RP
  server's signing/decryption oracles (`SEC-06` in
  `services/authorization.rs`). Store and inject it the same way you would a
  database credential — never log it, never put it in a URL, never check it
  into source control.

## Local-RP vs regular RP: which one?

- **Regular (this doc):** your users each have their own DNS-pinned LinkKeys
  domain; your app runs (or is deployed alongside) an RP server that holds a
  domain key of its own. Use this for a normal public-facing web app.
- **Local-RP:** your app has no public DNS and generates its own signing
  identity (fingerprint, not a domain) that a LinkKeys domain admin
  approves out-of-band. See [`README.md`](./README.md) in this same
  directory — it's what this crate (`linkkeys-local-rp`) actually
  implements.

The two are not mutually exclusive at the protocol level, but they are
different SDK surfaces: this crate's public API (`generate_local_rp_identity`,
`begin_local_login`, `complete_local_login`) is the local-RP one. Regular-mode
apps don't call into this crate at all — they deploy an RP server and use
`linkkeys-rpc-client` directly, as shown above.

## HTTP `/v1alpha` routes are deprecated

Server-to-server LinkKeys traffic — domain-key fetch, userinfo redemption,
attestation deposit, and (as used throughout this doc) an app delegating to
its RP server — is TCP-first. The remaining HTTP surface under
`/v1alpha/domain-keys`, `/v1alpha/users/<id>/keys`, `/v1alpha/handshake`, and
`/v1alpha/userinfo` in `crates/linkkeys/src/web/mod.rs` is marked
`deprecated, remove later` in the source and kept only for
backward-compatible peers that haven't migrated. The `Rp/sign-request`,
`Rp/decrypt-token`, and `Rp/verify-assertion` HTTP JSON routes that an earlier
version of `docs/DEPLOYING-RP.md` describes have already been removed
entirely (not merely deprecated) — TCP CSIL-RPC, as shown in this document,
is the only way to reach them now. The browser-facing surface
(`/csil/v1/rpc`, `/auth/authorize`, OAuth) is unaffected — browsers still use
HTTPS, only peer-to-peer server traffic moved to TCP.

## What was compiled

The code in this document is a trimmed, renamed copy of a Rocket app that was
built with `cargo build` (and `cargo clippy`, zero warnings) against this
repo's real `liblinkkeys` and `linkkeys-rpc-client` crates via path
dependencies, in a standalone scratch Cargo project **outside** this
workspace (per this file's own guidance: this SDK crate is a workspace
member, but a regular-mode app is not — it's an independent consumer). It was
not added to `Cargo.toml`'s `[workspace] members` and is not checked in
anywhere; it exists only to prove the snippets above compile against the
generated CSIL types and the real `linkkeys-rpc-client` API as they exist in
this repo today. It does not run against a live server (no live RP/IDP pair
was stood up for this pass) — the wire-level behavior traced above is read
directly from `crates/linkkeys/src/tcp/mod.rs`, `crates/linkkeys/src/web/rp.rs`,
and `demoappsite/src/main.rs`, not exercised end-to-end.
