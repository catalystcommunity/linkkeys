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

## Resolve peer application keys

An application (for example, Tinku) can ask its RP for another instance's
application keys. See `docs/application-keys.md` for the protocol. This
section covers only this SDK's surface.

The application does not call the peer's home domain. It calls its own RP.
The RP does the discovery, the fetch, and the first verification. This SDK
verifies the signed records again before it trusts them.

```ts
import {
  ApplicationKeyClientCache,
  PinnedApplicationKeyOperations,
  PinnedRpcTransport,
  resolveApplicationKeys,
  usableKeys,
} from "@linkkeys/regular-rp";

const rp = new PinnedApplicationKeyOperations(
  new PinnedRpcTransport({ tcpAddress, fingerprints, apiKey }),
);
const cache = new ApplicationKeyClientCache();

const resolved = await resolveApplicationKeys(rp, cache, {
  subjectUserId: "peer-user-id",
  subjectDomain: "peer.example.com",
  applicationId: "tinku",
  instanceId: "peer-instance-1",
});

if (resolved.freshness === "stale") {
  // The RP could not reach the home domain. These are the last verified
  // records. Apply your own policy. Do not treat this result as current.
}

const key = usableKeys(resolved.keys, "sign")[0];
```

Key points:

- `resolveApplicationKeys` returns `freshness` in the same object as `keys`.
  There is no bare key list. You cannot read the keys without also seeing
  whether they are `"fresh"`, `"refreshed"`, or `"stale"`.
- This SDK never upgrades a `"stale"` result from the RP to `"fresh"`.
- The cache key is the subject user ID, the subject domain, the application
  ID, and the instance ID. It is never a handle.
- `ApplicationKeyClientCache` is small and bounded (`DEFAULT_MAX_ENTRIES`,
  128 entries, least-recently-used eviction). It exists only to avoid
  repeated calls to your own RP within a short window
  (`DEFAULT_LOCAL_CACHE_AGE_MS`, 30 seconds). It is not a replacement for the
  RP's own, much longer, cache.
- This SDK re-verifies every cached entry against the current time on every
  call, even a cache hit. A key that expired since the last RP call is never
  presented as usable.
- This SDK implements only the READ side of the application-key protocol:
  it verifies a peer's already-attested keys. It does not add a key, renew
  an attestation, or prove possession of an X25519 key. Those are enrollment
  operations for an application's OWN keys, and are out of scope for this
  package.

## Act-as grants

An act-as grant lets a user allow application C (the grantee) to act as the
user at application D (the audience). The user's home domain signs the grant.
C and D enforce the scope. LinkKeys does not interpret scope strings. See
`docs/spec/reserved/act-as-grants.md` for the protocol and
`docs/act-as-grants.md` for the guide. The protocol is Reserved. It can
change.

The rules in `src/actAs.ts` are a port of `liblinkkeys::act_as`. The tests
replay all four `sdks/regular-rp/conformance/act_as_*.json` files.

### Grantee flow

1. Get a signed scope set (`SignedActAsScopeSet`) from the audience. The
   format of that exchange is between you and the audience.
2. Sign a grant request with `signGrantRequest`. Use a request window of 900
   seconds or less. To show your handle on the consent screen, set
   `granteeHandleClaim` to a signed `handle` claim about the account that
   enrolled your application. That account's domain must sign the claim. A
   local-RP grantee cannot send a handle claim. `signGrantRequest` refuses a
   handle claim about a different account.
3. Send the browser to the URL from `actAsRequestUrl`. The function finds the
   home domain's browser endpoint in DNS and adds the `signed_request` value.
4. The home domain sends the browser to your callback with
   `act_as_grant_id` and your request `nonce`. Make sure that the nonce is
   yours.
5. Sign a refresh request with `signRefreshRequest`, and fetch the grant
   with `ActAsRpClient.refreshGrant`. Your own RP forwards the call.
6. For each call to the audience, make a credential with `present`. Use a new
   nonce for each call.
7. Refresh after `refreshDueAt(grant)` and before the grant expires. Use
   `refreshDecision` and `offeredTerms` to predict what the home domain
   returns. A shorter grant is not an error. An expired grant cannot be
   renewed. Ask the user again.

```ts
import {
  ActAsRpClient,
  PinnedRpcTransport,
  SystemDnsResolver,
  actAsRequestUrl,
  formatActAsTime,
  present,
  signGrantRequest,
  signRefreshRequest,
  type GranteeSigner,
} from "@linkkeys/regular-rp";

const signer: GranteeSigner = {
  kind: "application",
  instanceId: "my-instance-1",
  signer: { keyId: "my-key-1", privateKey: instanceSeed },
};

const now = new Date();
const signedRequest = signGrantRequest({
  grantee,
  scopeSet,
  requestedLifetimeSeconds: 3600,
  callbackUrl: "https://c.example/act-as/callback",
  nonce,
  requestedAt: formatActAsTime(now),
  expiresAt: formatActAsTime(now.getTime() + 300_000),
}, signer);
const redirect = await actAsRequestUrl(new SystemDnsResolver(), userDomain, signedRequest);

// After the callback:
const rp = new ActAsRpClient(new PinnedRpcTransport({ tcpAddress, fingerprints, apiKey }));
const { grant } = await rp.refreshGrant(userDomain, signRefreshRequest({
  grantId, grantee, requestedAt: formatActAsTime(now), expiresAt: formatActAsTime(now.getTime() + 300_000), nonce: refreshNonce,
}, signer));
const credential = present(grant, audience, requestDigest, new Date(), callNonce, signer);
```

A local RP can also be a grantee. Use a `GranteeSigner` with
`kind: "localRp"`, the signed descriptor, its fingerprint, and the descriptor
signing key. The home domain must already approve the local RP.

### Audience: sign a scope set

1. Make an `ActAsScopeSet` with the scopes that you offer to one grantee. The
   set must have 1 to 64 entries. Do not repeat a scope.
2. Optional: set `audienceHandleClaim` to a signed `handle` claim about the
   account that enrolled your application. That account's domain must sign
   the claim.
3. Sign the set with `signScopeSet`. Give ALL current signing keys of your
   instance. The function adds one signature for each key. A verifier needs
   only one valid signature. Thus, when one key expires or is revoked, the
   set stays valid.

```ts
import { signScopeSet } from "@linkkeys/regular-rp";

const signedScopeSet = signScopeSet(scopeSet, "my-instance-1", [
  { keyId: "my-key-1", privateKey: seed1 },
  { keyId: "my-key-2", privateKey: seed2 },
]);
```

`signScopeSet` refuses an empty key list and a key id that is in the list
two times.

### Handle claims

`verifyHandleClaim(claim, party, domainKeys, now)` returns the handle when
the claim is correct. Use it to show the handle of a party. These conditions
must be true:

- The claim type is `handle`, and the claim is about the account of the
  party (`party.subjectUserId`).
- A signature by the party's own `subjectDomain` verifies. The function
  ignores signatures by other domains. `domainKeys` are the keys of that
  domain.
- The claim is not revoked or expired.

If the claim is not correct, the function throws `bad-handle-claim`. Do not
show the handle. Do not block the user because of it.

### Audience verification flow

1. Decode the credential with `decodeActAsCredential`. This function refuses
   input that is too large.
2. Get the signing keys of the grant's subject domain. Get the attested keys
   of the grantee instance (`credentialSignerInstance`) with
   `resolveApplicationKeys` and `usableKeyRefs`. Get your own attested keys
   for the instance that signed the scope set (`credentialScopeSetSigner`)
   with `resolveApplicationKeys` and `attestedKeyRefs`. Do not use
   `usableKeyRefs` for your own keys (see "Key rotation").
3. Get the revocations for the grant with
   `ActAsRpClient.resolveGrantRevocations`. The function returns only
   revocations that verify against the subject domain's keys.
4. Call `verifyCredential` with an `AudienceContext`. Supply your own
   `ApplicationRef`. Do not read it from the request. The function runs the
   seven checks of the specification in order and stops at the first
   failure. Optional: set `revokedKeyPolicy` (see "Revoked keys").
5. Use only `approvedScope` from the result for your policy decision.

```ts
import { ActAsError, verifyCredential } from "@linkkeys/regular-rp";

try {
  const verified = verifyCredential(credential, {
    ownApplication,
    ownScopeSetKeys,
    issuerDomainKeys,
    granteeInstanceKeys,
    expectedRequestDigest,
    revokedGrantIds: revocations.revokedGrantIds,
    maxPresentationAgeSeconds: 300,
    now: new Date(),
    skewSeconds: 60,
    revokedKeyPolicy: "acceptBeforeRevocation",
  });
  // Record verified.nonce before you act. Refuse a nonce that you saw before.
} catch (err) {
  if (err instanceof ActAsError) {
    // err.code tells which check failed.
  }
  throw err;
}
```

### Key rotation

`verifyScopeSet` checks each signature against the key that was valid at the
set's `issued_at`. Thus, you must supply ALL attested keys of the signing
instance, also the keys that expired or were revoked after that time. Use
`attestedKeyRefs`. It keeps each key and sets `revokedAt` on a revoked key.
`usableKeyRefs` keeps only the keys that are usable now. With that list, the
SDK refuses a scope set that was signed before a key rotation.

### Revoked keys

A `RevokedKeyPolicy` tells the SDK how to use a signature by a key that was
revoked after it signed. `verifyScopeSet` and `AudienceContext` accept it:

- `"acceptBeforeRevocation"` (the default): a signature made before the
  revocation time stays valid.
- `"refuseRevoked"`: the SDK refuses each signature by a revoked key.

When no signature is acceptable, `verifyScopeSet` throws
`no-valid-signature`. The message gives each key and the reason: "not a key
of the audience", "not inside its validity window when it signed", "revoked
at X, before it signed", "revoked at X; this verifier refuses revoked keys",
or "signature did not verify".

### Audience responsibilities

The audience owns these items. The SDK does not do them:

- **Replay protection.** Keep each presentation nonce until the accepted
  presentation age passes. Refuse a nonce that you saw before.
- **Revocation freshness.** Decide how often to get revocations. A short grant
  lifetime lowers the need to check.
- **The request digest.** Your application protocol defines what the digest
  covers.

Notes:

- Timestamps that the SDK writes are whole-second RFC3339 UTC with a trailing
  `Z`.
- `verifyCredential` does not check the scope set's expiry. Only the home
  domain checks it, at approval.
- A grant with `device_fingerprint` is refused. Device binding is Reserved.
- The Rust reference checks a domain key's expiry against the system clock.
  This SDK uses the `now` that you supply. Supply the current time.

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

`test/applicationKeys.test.ts` replays every case in
`sdks/regular-rp/conformance/application_key_attestation.json` and
`application_key_revocation.json` — positive and negative — against this
SDK's own verification code. `test/applicationKeyCache.test.ts` proves the
client cache's bound, its RP-failure fallback to a stale result, and that a
cached entry is re-verified against the current time on every call, not just
at fetch time.

`test/actAsConformance.test.ts` replays every case in the four
`act_as_*.json` files. It also proves that the grantee bytes are identical to
the Rust reference for an application grantee and for a local-RP grantee.
`test/actAs.test.ts` tests the RP calls with a fake transport and the browser
URL with a fake DNS resolver.

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
