# LinkKeys Browser Auth Demo

This demonstrates the full cross-domain browser authentication flow:
a user authenticates at their LinkKeys domain server, and a separate
demo application verifies their identity cryptographically.

## Prerequisites

- Rust toolchain
- Both `postgres` and `sqlite` features enabled (default)

## Quick Start

### Terminal 1: Domain Server

```bash
# Initialize the domain and create a test user
export DOMAIN_KEY_PASSPHRASE=demo-passphrase
export DATABASE_BACKEND=sqlite
export DATABASE_URL=linkkeys-demo.db
export DOMAIN_NAME=localhost:8443

cargo run --bin linkkeys -- domain init
cargo run --bin linkkeys -- user create alice "Alice Smith" --password alice123

# Note the user UUID printed above, then set some claims
cargo run --bin linkkeys -- claim set <UUID> display_name "Alice Smith"
cargo run --bin linkkeys -- claim set <UUID> email "alice@example.com"
cargo run --bin linkkeys -- claim set <UUID> role "admin"
cargo run --bin linkkeys -- claim set <UUID> over_21 "true"

# Start the server
cargo run --bin linkkeys -- serve
```

The domain server runs on `https://localhost:8443`.

### Terminal 2: Demo App Site

```bash
cargo run --bin demoappsite
```

The demo app runs on `https://localhost:9090`.

### Browser

1. Visit `https://localhost:9090/`
2. Accept the self-signed certificate warning
3. Enter domain: `localhost:8443`
4. Optionally enter username hint: `alice`
5. Click "Log In with LinkKeys"
6. You'll be redirected to the domain server's login page
7. Accept the self-signed certificate warning for the domain server
8. Enter username: `alice`, password: `alice123`
9. You'll be redirected back to the demo app
10. The dashboard shows your verified identity and claims

### What's Happening

```
Browser -> demoappsite POST /login {domain: "localhost:8443"}
  <- 302 redirect to https://localhost:8443/auth/authorize?callback_url=...&nonce=...

Browser -> domain server GET /auth/authorize?...
  <- HTML login form

Browser -> domain server POST /auth/authorize {username, password}
  <- 302 redirect to https://localhost:9090/callback?token=...

Browser -> demoappsite GET /callback?token=...
  demoappsite -> domain server GET /v1alpha/domain-keys  (fetch public keys)
  demoappsite -> domain server POST /v1alpha/userinfo.json  (verify token, get user info + claims)
  demoappsite sets encrypted session cookie
  <- 302 redirect to /

Browser -> demoappsite GET /
  <- Dashboard showing verified identity and claims
```

The token is a `SignedIdentityAssertion` — a CBOR-encoded identity assertion
signed with one of the domain's Ed25519 keys, then base64url-encoded for URL
transport. The demo app verifies the signature by fetching the domain's public
keys and checking them with `liblinkkeys`.

### Logout

Click the "Log Out" button on the dashboard. This clears the session cookie.
Revisiting `/` will show the login form again.

## Environment Variables

### Domain Server
- `DOMAIN_KEY_PASSPHRASE` — Required. Passphrase for encrypting/decrypting domain key material.
- `DATABASE_BACKEND` — `postgres` or `sqlite` (default: `postgres`)
- `DATABASE_URL` — Connection string
- `DOMAIN_NAME` — The domain's identity in assertions (e.g., `localhost:8443`)
- `HTTPS_PORT` — HTTP server port (default: `8443`)
- `TCP_PORT` — TCP server port (default: `4987`)

### Demo App
- `DEMO_PORT` — HTTP server port (default: `9090`)
