# Upgrade Notes

This file collects the steps an operator must do when they upgrade across the
named versions. Put the applicable entries in the release notes of each
release.

## API keys after the full-user-ID update

New API keys use `<user-id>.<secret>`. LinkKeys stores a SHA-256 digest because
the secret has 256 random bits. This format gives the server one exact account
lookup and does not need password-strength hashing.

Older keys with an eight-character user prefix still work. Their first
successful use changes the stored bcrypt value to the SHA-256 digest. LinkKeys
checks a maximum of 32 active legacy credentials for one prefix. If a prefix
has more than 32 active legacy credentials, all old keys for that prefix fail.
Current keys and old keys that LinkKeys already upgraded do not use this limit.

Before the upgrade, find service accounts that share an eight-character
prefix. If a prefix has more than 32 active legacy credentials, create a new
API account for each application. Copy only the required relations. Update the
application secret. Then remove the old credential or account.

## Upgrading to the release after 0.14.3

### Re-vouch encryption keys made before 0.14.1 (required)

Version 0.14.1 changed the vouch domain-separation tag from
`linkkeys-key-vouch-v1` to `linkkeys-key-vouch-v1alpha`. A vouch is a
signature that a signing key makes over the encryption key, one time, when the
encryption key is created. Vouches made before 0.14.1 do not verify on peers
that run 0.14.1 or later. Peers then drop the encryption key, and cross-domain
logins to the affected domain fail at the token-encryption step.

Domains initialized before 2026-07-16 are affected. Do one of these:

- Restart the server. On start, `serve` now examines the domain's own vouches
  and re-signs each vouch that does not verify under the current tag.
- Or run `linkkeys domain re-vouch` on the server. The command shows, for each
  encryption key, whether the vouch was already valid or was re-signed.

Both procedures are idempotent and safe to repeat.

Related repair: `linkkeys domain init` no longer counts revoked encryption
keys. A domain whose only encryption key was revoked can run `domain init`
again to generate a new one.

### The authorize API now speaks CBOR, and API errors are structured (breaking)

`POST /rp/authorize/validate` and `POST /rp/authorize/finalize` no longer
accept or return JSON. The request and response bodies are CSIL CBOR
(`AuthorizeValidateRequest`, `AuthorizeFinalizeRequest`, and their responses in
`csil/linkkeys.csil`). Update client apps that call these routes.

Every API failure now returns a CBOR `ApiError` body: a machine-readable
`code` and a human-readable `message` that names the failed step. The codes a
client must handle on finalize:

- `request_already_used` — the login request is spent; start a new login.
- `rp_key_fetch_failed` — the relying party's keys could not be fetched or
  pinned; its operator checks DNS records and endpoint.
- `rp_encrypt_key_untrusted` — the relying party has no vouched encryption
  key; its operator runs `linkkeys domain re-vouch`.
- `signing_failed`, `storage_failed` — fault on the identity provider; its
  operator checks the server log.

A failed finalize no longer consumes the login request: the relying-party key
fetch happens before the single-use nonce burn, so the same signed request can
be retried after the cause is repaired.

## Upgrading to the release after 0.14.4

### `Admin/list-users` now excludes purged users by default (breaking)

Before this release, `list-users` returned every user, including purged
(tombstoned) ones. Now it excludes purged users unless the request sets
`include_purged: true`.

A caller that relies on the old behavior must set `include_purged: true` in
`ListUsersRequest`. This includes:

- Any script or SDK that lists users and expects tombstoned accounts to
  appear.
- Dashboards that count total users, including purged ones.

`list-users` also now honors `offset` and `limit`. It ignored them before this
release and always returned the full set. `limit` defaults to 200 and is
capped at 1000 regardless of what the caller asks for.

### `AdminUser` gained two optional fields

`AdminUser` now carries `purged_at` and `purge_reason` when the user is
purged. Both fields are absent (not present in the CBOR map) for a user that
is not purged. A client built against an older CSIL subset that does not know
these field names is unaffected: CSIL decode looks fields up by name and
ignores keys it does not recognize.

### New op: `Admin/get-user-claims`

`get-user-claims` returns full claim values (value bytes and signatures) for
one user, unlike `list-user-claims`, which returns claim type names only. It
requires the `manage_claims` relation, the same as `list-user-claims`,
`set-claim`, and `remove-claim`.

Request: `AdminUserClaimsRequest { user_id: text }`.
Response: `AdminUserClaimsResponse { claims: [* Claim] }`.

An unknown `user_id` returns a `404` service error with message
`"User not found"`, matching `get-user`'s error shape.

A server built before this release does not know the `get-user-claims` op. It
answers with the standard unknown-op error: status `UnknownServiceOrOp`
(wire code 2), message `"Unknown Admin operation: get-user-claims"`. A client
should treat that status as "this server predates get-user-claims" and fall
back to `list-user-claims` (type names only, no values).

## Upgrading to the release after 0.14.5

### `POST /rp/authorize/validate` can report silent re-consent (additive)

`AuthorizeValidateRequest` gained an optional `user_id` field. A caller that
sends it asks the server to also check that user's standing consent grant
for the relying party. `AuthorizeValidateResponse` gained two optional
fields that answer that check: `already_consented` (`true` when a standing
grant already covers every required claim) and `authorized_claims` (the claim
types a finalize would release without showing consent again). An administrator
`forced_allow` rule does not replace the first disclosure. A new forced claim
opens consent once before the server can add it to the standing grant.

Both response fields are absent when `user_id` was not sent, when no standing
grant covers the request, or when the answer would be "no" for any other reason
(a `claims_update` request, an unknown `user_id`, or a required claim that has
no active value to release). The server does not send `false` as a "no" value.
`authorized_claims` can be an empty list when the saved decision approves no
optional claims. A client on the old CSIL subset that never sends `user_id` sees
a byte-identical response to before this change.

A client that wants this convenience: send the signed-in user's `user_id` on
`/rp/authorize/validate`, and when `already_consented` is `true`, skip the
consent screen and call `/rp/authorize/finalize` with `authorized_claims`
directly. Always keep the normal consent-screen fallback for every other
case, including a finalize that fails.

A server built before this release ignores an unknown `user_id` field (CSIL
decode looks fields up by name) and never sends the new response fields, so
a client that sends `user_id` against an older server simply never sees
`already_consented`.

### `BrowserAuthorization/inspect` can report standing consent (additive)

`BrowserAuthorizationInspectResponse` gained optional `already_consented` and
`authorized_claims` fields. The built-in SPA uses these fields to complete a
normal repeat login without a new consent screen.

`BrowserAuthorizationCompleteRequest` gained the optional
`use_standing_grant` field. The SPA sends `true` after an inspection reports
standing consent. The server then checks the grant and the current release
policy again. It does not trust the claim list from the inspection. If the
grant no longer covers the request, the server rejects the completion and the
SPA shows the consent screen.

The server omits these fields for the first disclosure, for a `claims_update`
request, and when a new administrator-forced claim is not in the prior grant.
The SPA shows the normal consent screen in these cases. It also shows the
screen if silent completion fails.

Older generated clients ignore the additional response keys. New generated
clients accept an older server that omits them. An older server ignores the
optional completion field.
