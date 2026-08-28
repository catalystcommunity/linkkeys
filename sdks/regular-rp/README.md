# Regular-RP SDKs and generated bindings

Use a regular-RP SDK when a public web application uses a LinkKeys RP server.
The application backend connects to the RP server. Browser code connects only
to the application backend.

An RP server is any LinkKeys server that has the RP function enabled. It can be
a dedicated RP server, or it can be an IDP server that also has the RP function
enabled. The combined IDP and RP configuration is the common configuration.

## SDK status

| Language | Status | Guide |
| --- | --- | --- |
| TypeScript and Node.js | Complete browser and backend SDK | [Use the TypeScript SDK](typescript/README.md) |
| Other generated languages | Bindings only; not ready as application SDKs | See [Generated bindings](#generated-bindings) |

The TypeScript SDK includes:

- a browser login helper;
- a Node.js backend client;
- a pinned TCP CSIL-RPC transport with API-key authentication;
- identity and IDP endpoint discovery;
- signed request and callback helpers;
- single-use pending login storage interfaces;
- assertion, subject, audience, nonce, and time checks;
- required-claim and released-claim checks;
- claim-signature verification with DNS-anchored issuer keys;
- build output, TypeScript declarations, examples, and tests.

The SDK does not create an application account or session. These items belong
to the application. The application must map `(user_id, domain)` to its local
user and then use its normal session system.

## Generated bindings

CSILgen creates typed service bindings for these languages:

| Rust | Go | TypeScript | Python | Java |
| --- | --- | --- | --- | --- |
| Kotlin | C# | Dart | PHP | Ruby |
| Elixir | C | Zig | OCaml | Swift |

Each language directory contains a `generated/` directory. A generated binding
contains protocol types, CBOR codecs, and typed service operations. It does not
contain the complete web login flow, secure state storage, a pinned network
transport, all application checks, or framework integration. Do not describe a
generated binding as a LinkKeys application SDK.

The generated bindings are the internal protocol layer for future complete
SDKs. Do not use them in browser code. An RP API key can sign and decrypt data.
Keep it in the application backend.

## Regenerate the bindings

Run this command from the repository root:

```sh
./tools.sh generate-regular-rp-bindings
```

The command generates every target from `csil/linkkeys.csil`. Do not edit a
file in a `generated/` directory. Change the CSIL source or CSILgen instead.

See the [authentication and claims flow](../../docs/authentication-and-claims-flow.md)
for the complete web application sequence.
