# Act-as grants

An act-as grant lets one application act as a user at a second application.
The user decides. The user's home domain signs the decision. The two
applications enforce what it means.

This guide is for operators and application developers. The protocol rules
are in [`spec/reserved/act-as-grants.md`](spec/reserved/act-as-grants.md).

## The parts

| Part | Example | What it does |
| --- | --- | --- |
| User | Alice | Approves or refuses the grant. Can stop it at any time. |
| Home domain | Alice's LinkKeys server | Shows the consent page. Signs the grant. Renews it when allowed. Publishes revocations. |
| Grantee | Application C | Asks for the grant. Holds it. Signs each call to the audience. |
| Audience | Application D | Writes and signs the list of scopes. Checks each call. Decides what each scope allows. |

C and D are applications with enrolled application keys
([`application-keys.md`](application-keys.md)). C can also be a local RP that
the home domain already approved. D cannot be a local RP.

The home domain never sees a call from C to D. It does not interpret scopes.
It keeps no list of which applications can act at which other applications.

## How a grant is made

1. C asks D for a signed scope set. C can send the user's preferred languages.
   D signs the list of scopes it offers C, with optional descriptions in one
   language, and an expiry. The format of this call is between C and D.
2. C signs an `ActAsGrantRequest` and sends the browser to
   `https://<home domain>/auth/act-as?signed_request=<value>`.
3. The home domain checks C's signature, D's signature, and the scope set's
   expiry. It then shows the consent page.
4. Alice sees who asks, at which application, and D's list. She can remove
   items, shorten the lifetime, and shorten the renewal window. She cannot add
   items.
5. The home domain signs the grant and sends the browser back to C's callback
   with `act_as_grant_id` and the request `nonce`.
6. C fetches the grant with `ActAs/refresh-grant` over TCP.

## How a grant is used

For each call to D, C sends an `ActAsCredential`: the signed grant and a
presentation that C signs for this call. D checks the credential with
`liblinkkeys::act_as::verify_credential`, or the same checks in its SDK. D
uses only the approved scope that the check returns.

D needs these public inputs, all cacheable:

- The signing keys of the user's home domain.
- C's attested application keys, for the instance that signed.
- D's own attested keys, to check its own scope set.
- The grant revocations it knows, from `ActAs/get-grant-revocations`.

D owns replay protection. Record each presentation nonce until the accepted
presentation age passes.

## Lifetime and renewal

A grant lasts one hour by default. With a renewal window above 0, C can renew
the grant without Alice until the window ends. C calls `ActAs/refresh-grant`
when less than half of the grant's life remains. The home domain then signs a
new grant, which never lasts past the end of the window.

C gets what Alice and the domain allow. A shorter grant is not an error. If
the grant is not enough, C asks Alice again.

## What the consent page shows

For each application, the page shows its domain first. Then it tells the user
whether the domain was trusted before: earlier use by this user, a key pin on
this server, or the operator's trusted-issuer list. When none applies, the
page warns that the application is new. Then it shows the account handle (only
from a signed handle claim that verifies), the application id, and the account
id.

To show a handle, C puts a signed `handle` claim about its enrolling account
in the grant request, and D puts one in its scope set. The claim must be
signed by that account's own domain.

## Key rotation

D signs each scope set with all its current signing keys. One valid signature
is enough, so a set survives when one key expires or is revoked. When D checks
its own scope set, it must supply all its attested keys, including expired and
revoked ones with their revocation times. A list of usable keys only would
refuse sets signed before a rotation.

## Stopping a grant

Alice stops a grant from her account page, under "Applications that act for
you". The home domain signs a revocation and refuses every later renewal. D
learns of the revocation from the public revocation read. A short grant
lifetime limits how long a revoked grant can still work at a D that does not
check often.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `ACT_AS_GRANT_DEFAULT_LIFETIME_SECONDS` | `3600` | The lifetime the consent page selects first. |
| `ACT_AS_GRANT_MAX_LIFETIME_SECONDS` | `86400` | The longest lifetime a user can choose. |
| `ACT_AS_GRANT_MAX_RENEWAL_WINDOW_SECONDS` | `2592000` (30 days) | The longest renewal window a user can choose. `0` turns off renewal. |
| `ACT_AS_CLOCK_SKEW_SECONDS` | `300` | The clock skew the home domain accepts on requests. |
| `ACT_AS_DENIED_SCOPES` | empty | Scopes this domain removes from every consent page. |
| `ACT_AS_REVOKED_KEY_POLICY` | `accept-before-revocation` | How this domain treats an audience scope-set signature by a key revoked since: `accept-before-revocation` or `refuse-revoked`. |

The server refuses to start when the default lifetime is larger than the
maximum, or when a value is not a whole number.

`ACT_AS_DENIED_SCOPES` is a comma-separated list. Each entry is
`<audience domain>/<application id>/<scope>`. Any part can be `*`. For
example:

```text
ACT_AS_DENIED_SCOPES=bank.example/*/transfer,*/*/admin
```

The consent page shows a denied scope as removed. The user cannot restore it.

A local RP can be a grantee only when the domain's local-RP policy is not
`disabled`, and only after an administrator approved it. Administrator
accounts cannot make act-as grants.

## Operations

| Operation | Carrier | Authentication |
| --- | --- | --- |
| `GET /auth/act-as` | Browser | None. The consent page needs a browser session. |
| `BrowserAuthorization/inspect-act-as` | Browser | Browser session |
| `BrowserAuthorization/complete-act-as` | Browser | Browser session |
| `Account/list-act-as-grants` | Browser or TCP | User session or API key |
| `Account/revoke-act-as-grant` | Browser or TCP | User session or API key |
| `ActAs/refresh-grant` | TCP only | The grantee's signature |
| `ActAs/get-grant-revocations` | TCP or browser carrier | None. Rate limited. |

`ActAs/refresh-grant` may need to fetch the grantee's keys from its home
domain, so it is available only on the TCP carrier.
