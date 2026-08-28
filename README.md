# LinkKeys

> **We're in Alpha! Yay!**  
> This project has core functionality implemented but is still evolving. It is stable enough for early adopters, and is in the battle testing phase. Come build it with us!

LinkKeys is authentication for everywhere. It solves three major problems with the internet today:

- Identity security is made hard when it shouldn't be, so let's make it easy to be secure, and only users can say what's easy.
- We are all tired of making new accounts or signing in to websites with social media logins.
- We would like to be able to know the user is a real person, or an adult, or local to us, etc.

If you trust your domain admins (like you do with your email) they handle all the technical headache, and everything else is easy on the user. Apps no longer have to pay for an Auth/SSO provider — they just use LinkKeys and they can stay , so it's all win-win for everyone. One identity, used everywhere that will use LinkKeys.

For the nerdier version:

LinkKeys is a domain-anchored identity protocol and server: domains hold keys, users hold claims (attributes that can be signed), and relying parties verify them over a TCP-first, mutually authenticated protocol (with a browser HTTPS path for interactive flows). See the [authentication and claims flow](docs/authentication-and-claims-flow.md) for an integration overview, [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and philosophy, and [`AGENTS.md`](AGENTS.md) for coding guidelines.

## Quickstart

Use the regular relying-party (RP) flow for a website or app that has a public domain. Your application sends protocol operations to a LinkKeys RP server. The RP server holds the private domain keys. Your application does not hold them.

An RP server is any LinkKeys server that has the RP function enabled. It can be
a dedicated RP server. It can also be an identity-provider (IDP) server that
has the RP function enabled. For most deployments, enable the RP function on
the IDP server.

LinkKeys has a complete regular-RP SDK for TypeScript web applications and
Node.js backends. See the [TypeScript SDK guide](sdks/regular-rp/typescript/README.md).
CSILgen also creates protocol bindings for other languages. These bindings are
not complete application SDKs. See the [regular-RP SDK status](sdks/regular-rp/README.md).

1. [Deploy a LinkKeys server with the RP function enabled](docs/DEPLOYING-RP.md).
   You can enable this function on an IDP server.
2. Initialize its keys and create an API account for your application:

   ```sh
   linkkeys domain init
   linkkeys user create my-app "My Application" --api-key --relation api_access
   linkkeys domain dns-check
   ```

   Save the API key in your secret store. Publish the `_linkkeys` and `_linkkeys_apis` DNS records that `dns-check` shows.

3. Add a field for the user's LinkKeys identity and a login button. Send the
   identity, such as `alice@idp.example`, to an application login route. Add a
   callback route for LinkKeys. Use the SDK in the application backend:

   ```ts
   import { MemoryPendingLoginStore, RegularRpClient } from "@linkkeys/regular-rp";

   const linkkeys = new RegularRpClient({
     rpDomain: "app.example.com",
     pendingStore: new MemoryPendingLoginStore(), // Development only.
     rpServer: {
       tcpAddress: process.env.LINKKEYS_RP_TCP_ADDRESS!,
       fingerprints: process.env.LINKKEYS_RP_FINGERPRINTS!.split(","),
       apiKey: process.env.LINKKEYS_RP_API_KEY!,
     },
   });

   // In the login route:
   const login = await linkkeys.beginLogin({
     identity: request.body.identity,
     callbackUrl: "https://app.example.com/linkkeys/callback",
     sessionBinding: request.session.id,
   });
   response.json({ redirectUrl: login.redirectUrl });

   // In the callback route:
   const user = await linkkeys.completeLogin({
     state: request.query.lk_state,
     encryptedToken: request.query.encrypted_token,
     sessionBinding: request.session.id,
   });
   await createSession(user.userId, user.domain, user.claims);
   ```

   The memory store is only for local development. Use a shared datastore in
   production. Its `take` operation must delete the pending login atomically.
   Store the RP API key as a secret. Do not log the API key, tokens, pending
   state, or claim values.

4. After `completeLogin` succeeds, the result contains the verified user ID,
   domain, display name, and claims. Use the user ID and domain together as the
   external identity. Find or create the related local user record. Store only
   the claims that the application needs. Keep their expiration data. Refresh
   stored claims when LinkKeys returns new data. Then create a session with the
   existing application session system.

The user's LinkKeys identity provider maintains the login credentials. Your application does not need to store a LinkKeys password. Your application still maintains its local user records, cached claims, sessions, and access rules.

If your desktop, LAN, or self-hosted app has no public DNS, use the [local-RP app guide](docs/local-rp-app-developer-guide.md). Its language table links to each SDK quickstart. This mode does not need a separate RP server. The user's LinkKeys domain must approve the app identity.

See the [`docs/` index](docs/README.md) for more guides. To change LinkKeys itself, see [`contributing.md`](contributing.md).
