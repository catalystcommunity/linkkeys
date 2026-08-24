# LinkKeys

> **We're in Alpha! Yay!**  
> This project has core functionality implemented but is still evolving. It is stable enough for early adopters, and is in the battle testing phase. Come build it with us!

LinkKeys is authentication for everywhere. It solves three major problems with the internet today:

- Identity security is made hard when it shouldn't be, so let's make it easy to be secure, and only users can say what's easy.
- We are all tired of making new accounts or signing in to websites with social media logins.
- We would like to be able to know the user is a real person, or an adult, or local to us, etc.

If you trust your domain admins (like you do with your email) they handle all the technical headache, and everything else is easy on the user. Apps no longer have to pay for an Auth/SSO provider — they just use LinkKeys and they can stay , so it's all win-win for everyone. One identity, used everywhere that will use LinkKeys.

For the nerdier version:

LinkKeys is a domain-anchored identity protocol and server: domains hold keys, users hold claims (attributes that can be signed), and relying parties verify them over a TCP-first, mutually authenticated protocol (with a browser HTTPS path for interactive flows). See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and philosophy, and [`AGENTS.md`](AGENTS.md) for coding guidelines.

## Quickstart

Use the regular relying-party (RP) flow for a website or app that has a public domain. Your application sends protocol operations to a LinkKeys RP server. The RP server holds the private domain keys. Your application does not hold them.

LinkKeys supports Rust, Go, TypeScript and Node.js, Python, PHP, Java, Kotlin, C# and .NET, Dart, Ruby, Elixir, C, Zig, and OCaml. Each language has a regular-RP example and a local-RP SDK guide in [`sdks/local-rp/`](sdks/local-rp/). The code below uses Python only as one concrete example.

1. [Deploy a LinkKeys server in RP mode](docs/DEPLOYING-RP.md).
2. Initialize its keys and create an API account for your application:

   ```sh
   linkkeys domain init
   linkkeys user create my-app "My Application" --api-key --relation api_access
   linkkeys domain dns-check
   ```

   Save the API key in your secret store. Publish the `_linkkeys` and `_linkkeys_apis` DNS records that `dns-check` shows.

3. Add a field for the user's LinkKeys login and a login button to your page. Send the value, such as `alice@idp.example`, to a login route. Add a callback route for the response from LinkKeys. Select your language in [`sdks/local-rp/`](sdks/local-rp/). For Python, the [complete example](sdks/local-rp/python/example.md) supplies the `begin_login` and `complete_login` helpers used below.

   ```python
   # Login route
   redirect_url, pending = begin_login(
       rp_config,
       "https://app.example.com/linkkeys/callback",
       "alice@idp.example",
   )
   pending_logins.put_once(browser_session_id, pending)
   return redirect(redirect_url)

   # Callback route
   pending = pending_logins.take_once(browser_session_id)
   user_info = complete_login(rp_config, pending, encrypted_token)
   return create_session(user_info.user_id, user_info.domain, user_info.claims)
   ```

   Consume the pending login before you verify the callback. Do not permit a second use. Store the RP API key as a secret. Do not log the API key, tokens, or claim values.

4. After `complete_login` succeeds, `user_info` contains the verified user ID, domain, display name, and released claims. Use the user ID and domain together as the external identity. Find or create the related local user record. Store the claims that your application needs, including their expiration data, in your datastore. Refresh the stored claims when LinkKeys returns new claim data. Then create a session with your existing session system.

The user's LinkKeys identity provider maintains the login credentials. Your application does not need to store a LinkKeys password. Your application still maintains its local user records, cached claims, sessions, and access rules.

If your desktop, LAN, or self-hosted app has no public DNS, use the [local-RP app guide](docs/local-rp-app-developer-guide.md). Its language table links to each SDK quickstart. This mode does not need a separate RP server. The user's LinkKeys domain must approve the app identity.

To change LinkKeys itself, see [`contributing.md`](contributing.md).
