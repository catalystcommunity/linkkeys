# Upgrade Notes

This file collects the steps an operator must do when they upgrade across the
named versions. Put the applicable entries in the release notes of each
release.

## Millisecond timestamps (the release after 0.16.11)

Version 0.16.11 sends stored times with microsecond precision. The web UI
decodes replies with the generated TypeScript codec. That codec rejects a
time that is finer than a millisecond, because a JavaScript `Date` holds
milliseconds. After sign-in, the UI shows "Could not sign in" or "Could not
check your session". The TypeScript regular-RP SDK cannot decode the same
replies.

This release stores and sends each time with millisecond precision:

- A migration changes each Postgres `timestamptz` column to `timestamptz(3)`.
  It rounds the stored values down to milliseconds. Postgres then keeps each
  later write at millisecond precision.
- A migration rewrites the SQLite timestamp text that has more than three
  fraction digits.
- The server makes each new time with millisecond precision.

The migrations run when the server starts. You do not have to do a manual
step. The Postgres migration rewrites each table that has a timestamp
column, so the first start can take more time on a large database.

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

## Upgrading to the release with user authentication activity

### New op: `Admin/get-user-authentication-activity`

This operation returns authentication activity for one user. It requires the
`manage_users` relation. The response contains these fields:

- `last_authenticated_at`: The time of the last successful authentication.
- `last_seen_at`: The last activity time that LinkKeys recorded for a
  successful authentication. Browser-session refreshes update this value.
- `successful_authentication_count`: The number of successful authentications
  that LinkKeys recorded.
- `active_browser_session_count`: The number of browser sessions that are not
  expired, idle, or revoked.

The first three values are in the durable `user_authentication_activity`
table. They remain after LinkKeys removes a browser-session row. LinkKeys adds
this table to encrypted backups. A user who has not authenticated has absent
timestamps and a successful-authentication count of zero.

On the first start after the upgrade, LinkKeys copies available activity from
existing browser-session rows. It cannot restore data from session rows that
were removed before the upgrade.

LinkKeys removes the durable activity when it purges the user. The operation
does not return sign-in, sign-out, or failed-attempt history. That history
needs a separate retention policy and API.

## Upgrading to the release after 0.16.3

### A newly requested optional claim opens consent once (behavior change, additive fields)

Before this release, a silent login ignored an optional claim that the
application added after the first consent. The user never saw the claim, and
the IDP never released it.

Now a claim that the application did not request at the last consent stops the
silent login. This rule applies to optional claims and required claims. The
consent screen opens one time and marks each new claim. A claim that the user
declines is recorded as seen and does not open the screen again. The IDP uses
the `requested_types` column that each consent grant already stores. No
migration is necessary.

`BrowserConsentClaim` gained the optional `newly_requested` field. It is `true`
for a new claim and absent in all other cases, including the first consent.
`AuthorizeValidateResponse` gained the optional `newly_requested_claims` field.
The server sends it only when the caller sent `user_id`, a prior grant exists,
and at least one claim is new. When this field is present, `already_consented`
is absent. A custom consent UI can use this field to mark the new claims.

Older clients ignore the new fields. Their consent screen opens for a new claim
but does not mark it as new.

### App access policies and password locks (new feature, migrations, additive fields)

Two migrations run at start: `password_lock` adds `users.password_locked`, and
`app_access_policies` adds three tables. Backups include the new tables and
the new column. See [app-access-policies.md](app-access-policies.md).

New `Admin` operations, all with the `admin` relation:
`set-user-password-lock`, `list-app-access-policies`, `set-app-access-policy`,
`remove-app-access-policy`, and `preview-app-access`.

New optional fields:

- `AdminUser.password_locked`: present and `true` only for a locked account.
- `access_denied` (type `AppAccessDenial`) on `BrowserAuthorizationInspectResponse`,
  `BrowserLocalRpInspectResponse`, `BrowserActAsInspectResponse`, and
  `AuthorizeValidateResponse`.
- `BrowserLocalRpInspectResponse.admission` can be `blocked`.

With no policies, sign-in does not change. An application that owns its consent
UI (it calls `/rp/authorize/validate` and `/rp/authorize/finalize`) should show
a blocked page when `access_denied` is present. An older client ignores the
field; its finalize then fails with `forbidden`, and the message contains the
admin messages.

## Upgrading to the release with off-domain callbacks

### Callback hosts outside the RP domain (behavior change, additive fields)

Before this release, the IDP refused a callback host that was not the RP domain
or a subdomain of it (`/app/error?reason=callback_off_domain`). Now the IDP
accepts any https callback in a valid signed request. The RP domain signature
authorizes the callback. The IDP still refuses a callback that is not https or
that contains user information. `Rp/sign-request` applies the same check.

The user's IDP enforces this rule. A callback outside the RP domain works only
when the user's IDP runs this release or a later release. An older IDP shows
`callback_off_domain`.

`Rp/sign-request` now names the calling API-key account in the signed request.
The IDP consent screen shows the display name of that account. Give each
application account a display name that users recognize.

New optional fields:

- `AuthRequest.application` (type `RelyingPartyApplication`): the API-key
  account that called `Rp/sign-request`. Older IDPs ignore it.
- `BrowserAuthorizationInspectResponse.application` and `callback_host`.
- `AuthorizeValidateResponse.application`. A custom consent UI should show
  the application name, and the `callback_url` host when that host is not in
  `relying_party`.

The reason code `callback_off_domain` is removed.

### Standing consent is per application (behavior change, migration, additive fields)

An application is now an `ApplicationRef`: the calling API-key account, the RP
domain, and an application ID. This is the same identity that act-as grants
use. `Rp/sign-request` takes an optional `application_id`. When it is absent,
the RP server uses the account username. A username that is not a valid
identifier (1-128 of `A-Z a-z 0-9 - _ .`) makes `sign-request` fail; send
`application_id` for that account.

The IDP keys standing consent by `(user, RP domain, application)`. A grant for
one application does not cover a sibling application of the same RP domain.

The migration `consent_grant_application` adds two columns to
`consent_grants` and changes its unique index. Backups include the columns.
Grants from before the upgrade have no application. They do not cover a
request that names an application, so each user sees the consent screen one
more time for each application.

`ConsentGrant` gained the optional `application`. When present, it is bound
into the consent signature. Grants without it keep their signatures.

An application that also uses act-as grants should send the `application_id`
that it enrolled with.

## Upgrading to the release after 0.16.7

### Records signed in older formats are re-signed (automatic, no action)

No operator action is necessary. Start the new release. The server repairs
the records at start-up, as it applies a migration.

Releases before 0.14.1 signed claims, consent grants, and key revocation
certificates in older payload formats. Release 0.14.1 changed every
domain-separation tag to the `-v1alpha` epoch. Current verifiers accept only
the current format, and no release re-signed the stored records. Thus, claims
from before 2026-07-16 do not verify. A relying party that verifies claim
signatures (for example, `grafana-linkkeys-login` with the Go SDK
`VerifyClaim`) rejects them with `signature_invalid`. Relying parties that do
not verify signatures show no error.

The known older formats are:

| Record | Format | Commit |
|---|---|---|
| Claim | `linkkeys-claim-v1`, bare user ID and signing domain | 05b7588 |
| Claim | `linkkeys-claim-v1`, `user@domain` subject | 54b4873 |
| Claim | `linkkeys-claim-v2`, adds `attested_at` | 59428af |
| Consent grant | `linkkeys-consent-v1` | 0026221 |
| Key revocation | `linkkeys-key-revocation-v1` | 4a8b759 |
| Key vouch | `linkkeys-key-vouch-v1` | cdd5009 |

On start, `serve` examines each active claim about a local user, each active
consent grant, and each issued key revocation:

- If the current verifier accepts the signatures of this domain, the server
  does not change the record.
- If each signature of this domain verifies with a key of this domain (active
  or retired) in the current format or a known older format, the server
  re-signs the record with the active signing keys. The claim ID, type,
  value, expiry, and attestation time do not change.
- If no signature of this domain verifies, the server does not change the
  record and logs a warning with its ID. A re-sign would make a tampered row
  valid. Remove or re-issue the record.
- Signatures of other domains stay as they are. The server logs the record ID.
  Only the issuer can re-sign them.

The server logs one summary line for each kind of record: checked, current,
stale, re-signed, unverifiable, and foreign. The pass is idempotent, so it
does nothing on later starts. A server without `DOMAIN_KEY_PASSPHRASE` has no
signing keys, so it only reports.

Some SQLite claims from before 2026-07-02 have an `attested_at` value in the
form `YYYY-MM-DD HH:MM:SS`. This value is not RFC 3339, and no verifier can
use it. The server re-signs these claims with a new attestation time, and
writes a `claim.reattested` audit entry for each one.

An unverifiable record is the only case that needs an operator. The server
cannot prove that it signed the record, so it must not re-sign it. Find these
records in the start-up log.

For diagnosis only, `linkkeys domain verify-signatures` shows the same report
without a restart. It does not change data, and it exits with status 1 when a
record needs attention. Do not use it as an upgrade step.

`domain re-vouch` and the start-up re-vouch use the same rule. They re-sign a
vouch only when a signing key of this domain made it, in the current format
or as `linkkeys-key-vouch-v1`. The server logs any other vouch and does not change the key. That is a
security event, not an upgrade step: revoke that key with
`linkkeys domain revoke-key`, and then run `linkkeys domain init` to make a
new encryption key.

Two kinds of signed data are not stored, so they need no repair. Sealed boxes
and login proofs are single-use. The server signs domain claims about an RP
again for each request. But a file of pre-signed domain claims
(`RP_DOMAIN_CLAIMS_SIGNED`) that was signed before 0.14.1 does not verify. Only
the issuer can sign it again.

## Upgrading to the release after 0.16.9

### Servers: no action

The server and the libraries use the `time` crate in place of `chrono`
(RUSTSEC-2026-0543: `chrono` is unmaintained). The timestamp text does not
change: signed payloads, test vectors, and stored SQLite text are
byte-identical, and the server reads rows that older releases wrote.

### Rust consumers of `liblinkkeys` and `linkkeys-local-rp` (required)

Public functions and fields that used `chrono::DateTime<chrono::Utc>` now use
`time::OffsetDateTime`. Durations are `time::Duration`. When you move your
pinned revision past this release:

- Add `time = "0.3"` to your dependencies.
- Pass `time::OffsetDateTime::now_utc()` where you passed `chrono::Utc::now()`.
- Write and read LinkKeys timestamp text with `liblinkkeys::timestamp`:
  `Rfc3339::to_rfc3339` (import the trait) and `parse_rfc3339`. These keep
  the LinkKeys text format. The `time` crate's own RFC 3339 format writes
  different bytes (`Z` in place of `+00:00`).

If your own code still uses `chrono`, convert at the call:
`time::OffsetDateTime::from_unix_timestamp_nanos(dt.timestamp_nanos_opt().unwrap() as i128)`.

### Servers: API-key rate limit

A request with an API key is charged to the rate limit of its network source
only when the key is refused. Before, each request was charged. A busy
application with a valid key is no longer limited by this check. A source
that is limited now gets status `Unavailable` (6) over CSIL-RPC, and HTTP 429
on the bearer-token HTTP routes. Before, it got `Forbidden` (5). Retry
`Unavailable` later. Do not treat it as a refused key.

The API key of a deactivated or purged account is refused on every carrier.

### Servers: display names

Admin `create-user` and `update-user` remove control characters, line and
paragraph separators, and bidirectional control characters from
`display_name`. They refuse a name longer than `DISPLAY_NAME_MAX_CHARS`
characters (default 256; Helm `server.displayNameMaxChars`). `serve` does not
start when the value is not an integer greater than zero.

The consent screen of an identity provider cleans the application name in a
sign-in request the same way, and shortens it to the limit. The consent text
for an application is now
`<display name> (<application_id> with RP domain <RP domain> and returning to <callback host>)`.
`BrowserAuthorizationInspectResponse` has a new optional field `return_host`.

### Helm: `ENABLE_RP_ENDPOINTS` removed

The chart no longer sets `ENABLE_RP_ENDPOINTS`. No code read it. The `Rp`
service is available to each account with the `api_access` relation.
`rp.enabled` now only applies `rp.apiKeyAuth` and `rp.passwordAuth`.

### csilgen 0.3.3 and error code numbers

The generated code in this repository comes from csilgen 0.3.3.
`tools.sh` checks the version (`CSILGEN_VERSION`) before it generates.
`./tools.sh csil-check` fails on a lint warning.

csilgen 0.3.0 to 0.3.3 change these items:

- Each generated Rust encoder returns a `Result`. A value with no wire form
  (for example, a `timestamp` outside UTC years 0001 to 9999) gives an error,
  not a panic. The server then replies with transport status 6 (internal).
- A generated client of an operation with declared error arms (the `Rp`
  operations with `RpError`) needs a transport with `call_reply`. This
  method gives the reply `variant` with the payload. A hand-written transport
  of an SDK must add this method.
- Each generated Go client call gives the same error types for every
  operation (csilgen 0.3.1):
  - `*RPCEncodeError` when the request has no wire form.
  - `*RPCDecodeError` when the reply does not decode, or when the reply
    variant is missing or unknown.
  - `*RPCApplicationError[RpError]` for a declared `RpError` refusal.
  - The transport error, unchanged, for a transport failure.

  Before, only the `Rp` operations wrapped a decode error, and an encode
  error had no type. The generated `ClientError` type is removed. No call
  returned it. Use `errors.As` with the types above.

`ApiError.code` is now a CBOR unsigned integer, not a text label. The labels
in the generated types do not change. The numbers are:

| Code | Number |
| --- | --- |
| `request_already_used` | 1 |
| `rp_key_fetch_failed` | 2 |
| `rp_encrypt_key_untrusted` | 3 |
| `signing_failed` | 4 |
| `storage_failed` | 5 |
| `bad_request` | 6 |
| `unauthorized` | 7 |
| `forbidden` | 8 |
| `not_found` | 9 |
| `internal` | 10 |

A client that decodes `ApiError` with its own code, not with the generated
types or an SDK of this release, must read the number.

## Upgrading to the release with typed CSIL and application accounts

This release changes the wire format and every signed structure. In alpha,
old formats are not accepted: upgrade every LinkKeys server and every SDK
together. Stored records are re-signed at start-up (see below).

### Wire format: timestamps and enums (breaking)

- Every time field is a CSIL `timestamp`: CBOR tag 0 with RFC 3339 text in
  UTC. Before, these fields were untagged text.
- Every field with a fixed set of values is a named-number enum and travels
  as a CBOR unsigned integer. The labels in the generated types do not
  change. A client that does not use the generated types or an SDK of this
  release must read the numbers:

| Enum | Numbers |
| --- | --- |
| `KeyAlgorithm` | ed25519=1, x25519=2 |
| `KeyUsage` | sign=1, encrypt=2, agree=3 |
| `AeadSuite` | aes_256_gcm=1, chacha20_poly1305=2 |
| `ClaimValueType` | text=1, url=2, email=3, bool=4, int=5, float=6, decimal=7, date=8, timestamp=9, opaque=10 |
| `SetRule` | user_self=1, idp_on_request=2, trusted_issuer_only=3, admin_only=4, deny=5 |
| `SigningRule` | self_signed=1, verified=2, attested=3, unsigned=4 |
| `SetClaimOutcome` | signed=1, stored_unsigned=2, verification_required=3, queued=4 |
| `ReleaseDisposition` | forced_allow=1, forced_deny=2 |
| `ConsentRowPolicy` | user=1, forced_allow=2, forced_deny=3 |
| `ClaimApprovalStatus` | pending=1, approved=2, rejected=3 |
| `PinRecheckOutcome` | first_seen=1, unchanged=2, rotated=3, mismatch=4, error=5 |
| `NotificationPurpose` | verify_contact=1, reset_password=2 |
| `NotificationChannel` | email=1 |
| `DestinationKind` | email=1 |
| `LocalRpPolicy` | disabled=1, admin_approval_required=2, allow_by_default=3 |
| `LocalRpStatus` | pending=1, approved=2, denied=3, revoked=4 |
| `LocalRpAdmission` | consent=1, pending=2, blocked=3 |
| `AppAccessMode` | allow=1, deny=2 |
| `AppAccessTargetKind` | everyone=1, user=2, group=3, claim=4 |
| `ClaimOperator` | present=1, absent=2, equals=3, age_under=4, age_at_least=5 |
| `ApplicationKeyChallengePurpose` | add=1, renew=2 |
| `AuthFlow` | login=1, claims_update=2 |
| `RpCacheStatus` | fresh=1, refreshed=2, stale=3 |
| `AccountKind` | human=1, application=2 |
| `RpErrorCode` | not_application_account=1, application_mismatch=2, application_user_limit=3, bad_request=4, upstream_failed=5, internal=6 |
| `IssuedClaimOutcome` | deposited=1, handoff=2, skipped=3, failed=4 |

- `PinRecheckResult` has a new optional `message` (set with `error`).
- The local-RP callback box KDF still binds the suite text
  (`aes-256-gcm`, `chacha20-poly1305`). Only the header field is a number.
- The sealed application-key challenge array starts with the `AeadSuite`
  number, not its text.

### Signed payloads: timestamps are whole Unix seconds (breaking)

The signed tuples of claims, consent grants, domain claims, key revocations,
encryption-key vouches, signing requests, and application-key revocations
now carry each timestamp as an integer of whole Unix seconds. A signed
timestamp with a fraction of a second is refused. The byte envelopes
(identity assertions, act-as records, application-key records, local-RP
records) sign their encoded bytes and change with the encoding.

### Servers: stored records are upgraded at start-up (automatic)

`serve` re-signs, at start-up, every record this domain signed in the
earlier format, after it proves the signature is its own:

- claims, consent grants, issued key revocations, and encryption-key
  vouches;
- application-key attestations. The attestation of a revoked key is left
  as it is; no verifier can read it, so the key stays unusable;
- signed times with a fraction of a second are cut to whole seconds and
  written back. A claim that changes this way gets a `claim.reattested`
  audit entry.

Act-as grants embed a scope set that the audience application signed, so
this domain cannot re-sign them. Grants in the earlier encoding are removed
(audit `act_as_grant.dropped`); users grant access again. Cached peer
records on a relying party that do not decode are fetched again.

`linkkeys domain verify-signatures` reports the same without changes.

### Application accounts (breaking, migration)

- An account is `human` or `application` (`AdminUser.kind`). An application
  account has an administrator-set `application_id` and API keys only.
- The migration makes every active account that has an API key and no
  password an application account with `application_id` = its username.
  That is the id that `Rp/sign-request` used, so consent is kept.
- `Admin/create-user` takes an optional `application_id`; with it the
  account is an application account and the response carries its first API
  key. The CLI has `linkkeys user create NAME "Display" --application-id ID`.
- `Rp/sign-request` lost `application_id`. Only an application account can
  call it; the signed request names the account's own application.
- `Account/enroll-application-instance` from an application account must
  use the account's `application_id`.
- New Admin operations: `rename-user`, `set-application-id`,
  `create-api-key`, `revoke-api-key` (relation `admin`); `list-api-keys`,
  `get-account-limits`, `set-account-limits`, `get-application-usage`
  (relation `manage_users`). An older server answers them with
  `UnknownServiceOrOp` (wire status 2).

### Shared relying parties: application isolation (breaking)

- `AuthRequest.application` is required, and the IDP copies it into the new
  required `IdentityAssertion.application`.
- `Rp/decrypt-token`, `Rp/verify-assertion`, and `Rp/userinfo-fetch` refuse
  a token or assertion for another application of the RP with
  `RpError { code: application_mismatch }`.
- `Rp/decrypt-token` now verifies the assertion against the issuing
  domain's keys, and accepts it only for an open login that the same
  application started with `Rp/sign-request` (the assertion nonce must be
  the nonce the application sent, at most one hour old). A login is finished
  once; a replayed token gets `RpError { code: bad_request }`. It needs the
  TCP carrier. An application must call `sign-request` and `decrypt-token`
  with the same account.
- These four operations now have typed replies: status 0 with `variant`
  `RpSignResponse` / `RpDecryptResponse` / `RpVerifyResponse` / `UserInfo`,
  or `RpError { code: RpErrorCode, message }`. A transport status still
  means the server could not answer (authentication, throttling, malformed
  envelope).
- Keep `RP_ISSUE_CLAIMS` empty on a shared RP: `Rp/issue-attestation` signs
  with the shared domain key for every tenant.

### Shared relying parties: limits and usage (new)

- `Admin/set-account-limits` sets, per account: `max_api_keys`,
  `max_distinct_users` with `distinct_user_window_days` (default 30), and
  `requests_per_minute` with `request_burst`. No limit is the default.
- `decrypt-token` counts each verified user of an application as a keyed
  hash of `user_id@domain` (key derived from `DOMAIN_KEY_PASSPHRASE`; a new
  passphrase resets the counts). A new user over `max_distinct_users` gets
  `RpError { code: application_user_limit }`; a user already in the window
  continues to work.
- An account over its request rate gets transport status Unavailable (6).
- `Admin/get-application-usage` returns the distinct-user count, the limit,
  and daily `Rp` operation counts. Counts are kept in memory and written
  about once a minute.
- API keys have a name, a four-character hint, a creation time, and a last
  use time (updated at most once a minute). Existing keys are named
  `default`.

### Servers: new settings

- `LINKKEYS_PRIVATE_PEER_ALLOWLIST`: comma-separated `host=address` entries.
  A peer on a private address is reached only when its host and address are
  both listed. Every other private address stays refused.
  `LINKKEYS_ALLOW_PRIVATE_PEERS=true` still opens every private address
  (development only).
- `HEADLESS=true`: for a relying party that serves no person. The browser
  UI, the browser carrier (`/csil/v1/rpc`), and password authentication are
  off; HTTPS answers health checks only; Admin is served over TCP only.
  Publish only `tcp=` in `_linkkeys_apis`.
- Local-RP policy rows keep working with the old hyphenated text and are
  written with the CSIL label (`admin_approval_required`). The CLI accepts
  both spellings.
