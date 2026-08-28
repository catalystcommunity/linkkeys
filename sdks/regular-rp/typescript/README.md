# LinkKeys SDK for TypeScript and Node.js

Use this SDK to add LinkKeys login to a web application. The package has two
entry points:

- `@linkkeys/regular-rp` is for the Node.js application backend.
- `@linkkeys/regular-rp/browser` is for browser code.

The backend entry point contains the RP API key. Do not import it into browser
code. The browser entry point only calls your application backend.

In this guide, an RP server is any LinkKeys server that has the RP function
enabled. It can be a dedicated RP server, or it can be an IDP server that also
has the RP function enabled. For most deployments, enable the RP function on
the IDP server.

## Requirements

- Node.js 22.18 or later
- A LinkKeys RP server for your application domain
- The RP TCP address, TLS key fingerprints, and application API key
- An HTTPS callback URL on the RP domain or a subdomain
- A datastore that can atomically save and take pending login records

See the [RP deployment guide](../../../docs/DEPLOYING-RP.md) before you use the
SDK.

## Install and build this repository package

Run these commands in this directory:

```sh
npm install
npm run build
```

The build puts JavaScript and TypeScript declarations in `dist/`. The package
has no runtime npm dependencies.

## Configure the backend

This example uses the memory store. Use it only for local development. In a
production service, implement `PendingLoginStore` with a shared datastore. Its
`take` operation must read and delete one record as one atomic operation.

```ts
import {
  MemoryPendingLoginStore,
  RegularRpClient,
} from "@linkkeys/regular-rp";

const linkkeys = new RegularRpClient({
  rpDomain: "app.example",
  pendingStore: new MemoryPendingLoginStore(),
  rpServer: {
    tcpAddress: process.env.LINKKEYS_RP_TCP_ADDRESS!,
    fingerprints: process.env.LINKKEYS_RP_FINGERPRINTS!.split(","),
    apiKey: process.env.LINKKEYS_RP_API_KEY!,
    requestTimeoutMs: 15_000,
  },
});
```

Keep the API key in a secret store. Do not put the API key, an encrypted token,
or a claim value in a log.

## Add the backend routes

Adapt these route bodies to your web framework. The login route returns only a
redirect URL. The callback route gives the completed identity to your existing
account and session code.

```ts
// POST /api/linkkeys/login with JSON: { "identity": "alice@id.example" }
const result = await linkkeys.beginLogin({
  identity: request.body.identity,
  callbackUrl: "https://app.example/auth/linkkeys/callback",
  sessionBinding: request.session.id,
  requestedClaims: {
    required: [{ claimType: "email", datatype: "text" }],
    optional: [{ claimType: "over_18", datatype: "bool" }],
  },
  signal: request.signal,
});
response.json({ redirectUrl: result.redirectUrl });

// GET /auth/linkkeys/callback?lk_state=...&encrypted_token=...
const login = await linkkeys.completeLogin({
  state: request.query.lk_state,
  encryptedToken: request.query.encrypted_token,
  sessionBinding: request.session.id,
  signal: request.signal,
});

const localUser = await findOrCreateUser({
  externalUserId: login.userId,
  externalDomain: login.domain,
});
await createApplicationSession(response, localUser);
```

Use `(login.userId, login.domain)` as the external identity key. A user ID is
not globally unique without its domain.

`completeLogin` does these checks before it returns:

1. It takes and deletes the pending state.
2. It checks that the same application session started the login.
3. It asks the RP server to decrypt and verify the assertion.
4. It checks the domain, audience, nonce, issue time, and expiration time.
5. It fetches the released user information.
6. It checks the user and claim subject bindings.
7. It rejects claims that the assertion did not authorize.
8. It requires every required claim.
9. It verifies every claim signature with current DNS-anchored issuer keys.

The result contains only verified claims. Each item has the raw claim and the
list of verified signing domains. Decode `claim.claimValue` only as the datatype
for that claim type permits.

## Add the browser login action

```ts
import { startLinkKeysLogin } from "@linkkeys/regular-rp/browser";

await startLinkKeysLogin({
  backendUrl: "/api/linkkeys/login",
  identity: loginField.value,
});
```

The helper sends the identity to your backend and follows the returned HTTPS
URL. It does not sign a request and it does not hold a LinkKeys secret.

## Production checklist

- Use HTTPS for the application and callback.
- Use a shared datastore for pending login state.
- Make `PendingLoginStore.take` atomic and single-use.
- Bind both SDK calls to the same secure application session.
- Store the RP API key in a secret store.
- Pin the RP TLS key to all active fingerprints during key rotation.
- Set secure, HTTP-only, SameSite cookies for the application session.
- Apply CSRF controls to the login route.
- Rate-limit the login and callback routes.
- Do not use a claim after its expiration time.
- Apply an application trust policy to the verified signing domains.

## Test

```sh
npm test
npm run typecheck
npm run build
```

The tests include the complete application flow, official conformance vectors,
and a loopback TLS server. The transport tests prove the RP key pin, the
CSIL-RPC API-key field, the full RPC deadline, and request cancellation.

You can also test `RegularRpClient` against a deployed RP server. Set these
variables before you run `npm test`:

- `LINKKEYS_LIVE_RP_DOMAIN`
- `LINKKEYS_LIVE_RP_TCP_ADDRESS`
- `LINKKEYS_LIVE_RP_FINGERPRINTS`
- `LINKKEYS_LIVE_RP_API_KEY`
- `LINKKEYS_LIVE_IDENTITY`

The live test starts a login through the high-level SDK. It does not send the
API key to the browser or to the IDP.

See the [authentication and claims flow](../../../docs/authentication-and-claims-flow.md)
for the system diagrams and protocol sequence.
