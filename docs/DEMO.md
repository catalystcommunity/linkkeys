# LinkKeys Browser Auth Demo

This demonstrates the full cross-domain browser authentication flow with
mutual authentication and encrypted token exchange: a user authenticates at
their LinkKeys domain server, and a separate demo application verifies their
identity through a relying party (RP) LinkKeys instance.

## Architecture

Three services run together:

1. **IDP** — The identity provider (full LinkKeys server). Holds user accounts, keys, and claims.
2. **RP** — The relying party (LinkKeys server in RP mode). Holds its own domain keys, signs auth requests, decrypts tokens.
3. **Demo App** — A pure web app (no crypto). Calls the RP service for all cryptographic operations.

```
Browser -> Demo App POST /login
  Demo App -> RP POST /v1alpha/sign-request.json  (sign auth request)
  <- 302 redirect to IDP /auth/authorize?...&relying_party=...&signed_request=...

Browser -> IDP GET /auth/authorize  (verifies signed request, shows login form)
Browser -> IDP POST /auth/authorize  (authenticate, encrypt token for RP)
  <- 302 redirect to Demo App /callback?encrypted_token=...

Browser -> Demo App GET /callback?encrypted_token=...
  Demo App -> RP POST /v1alpha/decrypt-token.json   (decrypt the token)
  Demo App -> RP POST /v1alpha/verify-assertion.json (verify against IDP's keys)
  Demo App -> IDP POST /v1alpha/userinfo.json        (get user info + claims)
  <- Set session cookie, redirect to /
```

## Prerequisites

- Rust toolchain
- Both `postgres` and `sqlite` features enabled (default)

## Quick Start

### Terminal 1: Identity Provider (IDP)

```bash
export DOMAIN_KEY_PASSPHRASE=demo-passphrase
export DATABASE_BACKEND=sqlite
export DATABASE_URL=linkkeys-idp.db
export DOMAIN_NAME=localhost:8443

cargo run --bin linkkeys -- domain init
cargo run --bin linkkeys -- user create alice "Alice Smith" --password alice123

# Note the user UUID printed above, then set some claims
cargo run --bin linkkeys -- claim set <UUID> display_name "Alice Smith"
cargo run --bin linkkeys -- claim set <UUID> email "alice@example.com"
cargo run --bin linkkeys -- claim set <UUID> role "admin"
cargo run --bin linkkeys -- claim set <UUID> over_21 "true"

cargo run --bin linkkeys -- serve
```

The IDP runs on `https://localhost:8443`.

### Terminal 2: Relying Party (RP)

```bash
export DOMAIN_KEY_PASSPHRASE=rp-passphrase
export DATABASE_BACKEND=sqlite
export DATABASE_URL=linkkeys-rp.db
export DOMAIN_NAME=localhost:9443
export HTTPS_PORT=9443
export ENABLE_RP_ENDPOINTS=true
export ENABLE_API_KEY_AUTH=true
export ENABLE_PASSWORD_AUTH=false

cargo run --bin linkkeys -- domain init
cargo run --bin linkkeys -- user create demoapp "Demo App Service" --api-key
# Save the printed API key!

cargo run --bin linkkeys -- serve
```

The RP runs on `https://localhost:9443`.

### Terminal 3: Demo App

```bash
export RP_SERVICE_URL=https://127.0.0.1:9443
export RP_API_KEY=<the-api-key-from-above>
export RP_DOMAIN=localhost:9443
export ALLOW_INVALID_CERTS=true

cargo run --bin demoappsite
```

The demo app runs on `https://localhost:9090`.

### Browser

1. Visit `https://localhost:9090/`
2. Accept the self-signed certificate warning
3. Enter identity: `alice@localhost:8443`
4. Click "Log In with LinkKeys"
5. You'll be redirected to the IDP's login page
6. Accept the self-signed certificate warning for the IDP
7. Enter username: `alice`, password: `alice123`
8. You'll be redirected back to the demo app
9. The dashboard shows your verified identity and claims

### Token Flow

The IDP encrypts the signed assertion with the RP's public key (Ed25519 -> X25519 conversion + AES-256-GCM sealed box). Only the RP can decrypt it. The demo app never sees raw cryptographic material — it passes opaque base64url strings between services.

### Logout

Click "Log Out" on the dashboard. This clears the session cookie.

## Environment Variables

### IDP (Identity Provider)
- `DOMAIN_KEY_PASSPHRASE` — Required. Passphrase for domain key material.
- `DATABASE_BACKEND` — `postgres` or `sqlite` (default: `postgres`)
- `DATABASE_URL` — Connection string
- `DOMAIN_NAME` — The domain's identity (e.g., `localhost:8443`)
- `HTTPS_PORT` — HTTP server port (default: `8443`)
- `TCP_PORT` — TCP server port (default: `4987`)

### RP (Relying Party)
Same as IDP, plus:
- `ENABLE_RP_ENDPOINTS` — Set to `true` to enable RP endpoints
- `ENABLE_API_KEY_AUTH` — Set to `true` to enable bearer token auth
- `ENABLE_PASSWORD_AUTH` — Set to `false` to disable password login UI

### Demo App
- `DEMO_PORT` — HTTP server port (default: `9090`)
- `RP_SERVICE_URL` — URL of the RP service (default: `https://127.0.0.1:8443`)
- `RP_API_KEY` — Bearer token for authenticating to the RP service
- `RP_DOMAIN` — The RP's domain name (used in auth requests)
- `ALLOW_INVALID_CERTS` — Set to `true` to accept self-signed certs (dev only)
