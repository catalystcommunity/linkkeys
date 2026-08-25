# Outbound communications and account recovery

Status: Implemented.

Scope: This document defines the LinkKeys server design. It does not define a
LinkKeys protocol requirement.

Absorbs: This document replaces the outbound email limitation in
[`claim-policy-and-consent.md`](../claim-policy-and-consent.md) and the temporary
email design in `crates/linkkeys/src/email.rs`.

## Current implementation

The server implements the CSIL operations, the account challenge model, the
verified contact model, the encrypted outbox model, and database browser
sessions. PostgreSQL and SQLite use the same service rules. A request creates
the challenge and outbox item in one transaction. A contact confirmation adds
the contact and signed claims and consumes the challenge in one transaction. A
password reset updates the password, consumes all active reset challenges, and
revokes all browser sessions in one transaction.

The server stores only SHA-256 token digests. It uses 32 random bytes for each
token. It encrypts each secret outbox payload with
`OUTBOX_ENCRYPTION_KEY`. Backups exclude browser sessions, challenges, and
outbox items. A restore also removes existing data from these tables. User
purge operations remove the account data from these tables. The old log email
transport is removed.

The server includes a Lettre SMTP transport and a durable outbox worker. The
worker uses leases, bounded retries, jitter, expiry, and secret-payload
redaction. It claims only work for its channel. It stops each delivery attempt
before its lease ends. It reports email capabilities only after the worker is
ready.

The embedded UI includes contact verification and password recovery. These
functions stay unavailable when the operator does not configure SMTP or
disables password authentication.

## Goals

The server must support email verification and password recovery when an
operator configures a suitable outbound channel. The design must also support
other channels in the future. A later channel can use SMS, a push service, or
another transport.

The first channel is email. The first email transport is SMTP.

The server must remain useful without outbound communications. It must report
the available account actions to the UI. The UI must not offer an action that
the server cannot complete.

## Component boundaries

All database, network, SMTP, and worker code belongs in the `linkkeys` server
crate. `liblinkkeys` must remain a pure library with no I/O.

The outbound path has three layers:

1. A notification intent states the purpose. Examples are `verify_contact` and
   `reset_password`.
2. A delivery channel selects a destination and renders channel content.
   Email is the first delivery channel.
3. A channel transport sends prepared content. SMTP is the first email
   transport.

This split prevents SMTP terms from entering account service code. It also lets
one email channel use SMTP now and a provider API later.

The server interfaces have these roles:

- `NotificationDispatcher` creates a durable notification intent.
- `DeliveryChannel` reports the purposes that it supports and prepares the
  channel content.
- `EmailTransport` sends a prepared email message.
- An outbox worker claims pending work and calls the selected channel.

These names describe server interfaces. CSIL remains the source of truth for
service requests and responses.

## Capabilities

The server must report notification capabilities through CSIL. The report must
include each available purpose and channel. It must not expose transport
credentials or internal transport names.

For example, a server can report that it supports password recovery by email.
The UI can then show the password recovery action. If no compatible channel is
available, the UI must hide or disable that action and explain why.

## Durable outbox

The request handler must not wait for SMTP. It must create the challenge and an
outbox item in one database transaction. The handler can then return after the
transaction commits.

An outbox item must include:

- a stable item ID;
- the notification purpose and channel;
- the normalized destination;
- an encrypted payload for data that the worker needs;
- the creation and expiry times;
- the attempt count and next attempt time;
- the state;
- a worker lease and lease expiry time when a worker owns the item;
- a safe error category for the last failure.

Use a dedicated `OUTBOX_ENCRYPTION_KEY` to protect sensitive outbox payloads.
The key is required when an enabled channel sends secret links. Do not reuse a
database password, domain signing key, or browser session key.

The worker must remove the encrypted payload after a successful handoff. It
must also remove the payload when the item expires or enters a terminal failure
state. Backup code must exclude browser sessions, challenges, and outbox items.
A restore must remove existing rows from these tables. Purge code must remove
the applicable account rows and their secret data.

The PostgreSQL and SQLite implementations can use different claim queries.
Both implementations must provide the same lease behavior. A worker that stops
must not hold work forever.

SMTP provides at-least-once delivery, not exactly-once delivery. A process can
stop after an SMTP server accepts a message but before LinkKeys records success.
This event can cause a duplicate message. All action tokens must therefore be
single-use and safe when a user receives a duplicate message.

Retry temporary failures with bounded exponential backoff and jitter. Do not
retry permanent address or policy failures. Stop when the item expires or
reaches the configured attempt limit.

## Contact verification

The server stores verified destinations in a private
`verified_contact_methods` model. A record contains:

- the account ID;
- the channel;
- the normalized destination;
- the verification time;
- the allowed purposes;
- an optional revocation time.

This model is server data. It is not a LinkKeys protocol claim. The existing
signed `email` and `email_verified` claims remain the protocol-facing result of
email verification.

An active destination can belong to only one account. A user who verifies a
new destination for a channel replaces the previous active destination for
that channel. This rule gives password recovery one unambiguous account and
one destination.

The verification flow is:

1. A signed-in user requests verification for an email address.
2. The user confirms the current password. This step prevents a stolen session
   or API key from adding a password recovery address.
3. The server normalizes the address and applies rate limits.
4. The server creates 32 random bytes with the operating-system random source.
5. The URL fragment contains the raw token. The challenge table stores only
   its SHA-256 digest. The browser does not send the fragment in an HTTP
   request.
6. The challenge binds the account, normalized address, purpose, and expiry.
7. The same transaction checks that the password credential is still active.
   It revokes an older pending challenge for the same account and purpose and
   creates the outbox item.
8. The worker sends the link. The default expiry is 24 hours.
9. The signed-in user opens the link with the same account session.
10. One transaction checks that the account is active, consumes the challenge,
   revokes the old contact for the channel, records the new contact, and adds
   the signed `email` and
   `email_verified` claims.

The email link uses this browser path:

```text
<PUBLIC_ORIGIN>/app/verify/contact#token=<secret>
```

The consume operation must be atomic. A second use must fail. An expired,
revoked, or unknown token must produce the same public error.

The account-session requirement applies to the core LinkKeys flow. A product
extension can add a sign-up flow before login. That extension must use a
separate service operation and policy.

## Password recovery

The password recovery form accepts a username or email address. Its public
response is always the same. The response must not reveal whether an account or
verified contact exists.

The recovery flow is:

1. The server normalizes the submitted identifier.
2. The server performs a password-verification cost on a no-match path.
3. The server applies limits for the source address, destination digest, and
   account when an account is known.
4. If an active account has a verified contact that permits recovery, one
   transaction rechecks the account and contact. It then creates a challenge
   and outbox item.
5. The challenge uses a 32-byte random token. The database stores only its
   SHA-256 digest.
6. A new challenge revokes older active password recovery challenges and
   removes the secret payload from their pending outbox items. The default
   expiry is 60 minutes.
7. The reset page asks for a new password and confirmation. Both password
   fields use `autocomplete="new-password"`.
8. One transaction rechecks the active account and recovery contact, validates
   the token, replaces the password credential, consumes all active reset
   challenges, and invalidates earlier browser sessions.

The recovery link uses this browser path:

```text
<PUBLIC_ORIGIN>/app/password/reset#token=<secret>
```

LinkKeys stores opaque browser sessions in the database. Password recovery
revokes all browser sessions for the account. It does not change API keys or
device credentials.

## SMTP transport

LinkKeys uses Lettre for SMTP. Lettre uses the MIT license, which is compatible
with this repository's Apache-2.0 license. The repository has a `cargo-deny`
policy for licenses, advisories, and sources. Run `./tools.sh audit` after a
dependency change.

The normal LinkKeys build includes SMTP with Rustls support. SMTP stays disabled
at runtime until an operator configures it. The normal build does not include
native TLS, DKIM, or sendmail support.

Disable Lettre's default features. Use this standard feature set:

- `builder`;
- `smtp-transport`;
- `pool`;
- `tokio1-rustls`;
- `ring`;
- `rustls-platform-verifier`.

Add a LinkKeys Cargo feature named `smtp-native-tls`. This feature adds Lettre's
Tokio native-TLS support. On Linux, this can add an OpenSSL build and runtime
dependency. If an operator selects native TLS in a build without this feature,
LinkKeys must stop at startup with a clear error.

Do not depend on Lettre's default TLS builder choice. Select its Rustls or
native-TLS builder explicitly from LinkKeys configuration.

## SMTP configuration

Use these settings:

| Setting | Meaning |
| --- | --- |
| `SMTP_HOST` | SMTP server host. Its presence enables the SMTP transport. |
| `SMTP_PORT` | SMTP server port. Use the mode-specific default when absent. |
| `SMTP_SECURITY` | `starttls`, `tls`, or `plaintext`. |
| `SMTP_TLS_BACKEND` | `rustls` by default, or `native` in a compatible build. |
| `SMTP_ALLOW_PLAINTEXT` | Explicit acknowledgement for a trusted plaintext relay. |
| `SMTP_USERNAME` | Optional SMTP authentication username. |
| `SMTP_PASSWORD` | Optional SMTP authentication password. |
| `SMTP_FROM` | Required sender mailbox. |
| `SMTP_TIMEOUT_SECONDS` | Connection and command timeout. |
| `PUBLIC_ORIGIN` | Public HTTPS origin used in action links. |
| `OUTBOX_ENCRYPTION_KEY` | Key for sensitive pending outbox payloads. |
| `OUTBOX_MAX_ATTEMPTS` | Maximum delivery attempts. The default is `8`. |
| `OUTBOX_LEASE_SECONDS` | Worker lease period. It must be at least two times `SMTP_TIMEOUT_SECONDS`. The default is `60`. |
| `OUTBOX_POLL_MILLISECONDS` | Worker poll period. The default is `1000`. |

`starttls` means that STARTTLS is required. Do not support opportunistic
STARTTLS with plaintext fallback.

`tls` means implicit TLS from the first connection byte.

`plaintext` is only for a trusted local relay. It requires
`SMTP_ALLOW_PLAINTEXT=true`, and the SMTP host must be a loopback address.
LinkKeys always rejects plaintext SMTP to a non-loopback host.

Validate all enabled SMTP settings at startup. Do not start a server that shows
an account action but cannot create its public link or transport message.

The SMTP relay owns SPF and DKIM for the first release. LinkKeys does not sign
DKIM messages in the process.

## Security and logs

Never log:

- a raw action token;
- a complete action URL;
- an email address or other contact destination;
- an SMTP username or password;
- a message body;
- a browser session value.

Logs can contain the outbox item ID, purpose, channel, attempt number, duration,
and safe result category. Metrics can count requests, queued items, attempts,
successes, temporary failures, permanent failures, and queue age.

The production server must not have a transport that writes secret links to a
log. Tests can use an in-memory transport. Local development can use a file
transport or a local SMTP capture service when the operator enables it.

## CSIL changes

The CSIL contract defines these operations:

| Operation | Access | Result |
| --- | --- | --- |
| `Notification/get-capabilities` | Public | Enabled purpose, channel, and destination-kind records. |
| `Account/list-verified-contact-methods` | Current account | The caller's verified contact methods. |
| `Account/revoke-verified-contact-method` | Current account | Removes one recovery contact from the caller. |
| `Account/request-contact-verification` | Current account and current password | The challenge expiry after the transaction commits. |
| `Account/confirm-contact-verification` | Current account | The verified contact method and resulting signed claims. |
| `Recovery/request-password-recovery` | Public | An empty generic response. |
| `Recovery/validate-password-recovery` | Public | The expiry and password policy for a valid token. |
| `Recovery/complete-password-recovery` | Public | Success after password update and session invalidation. |

`Account/request-verification` remains the existing claim-attestation signing
request operation. Contact verification uses distinct operation names.

Generated types and service traits must remain the source of truth. Browser
routes can adapt these operations, but they must not define duplicate request
or response types.

## Test requirements

Test PostgreSQL and SQLite. Use real database transactions and the DataUtils
pattern.

Tests must cover:

- capability reports with no channel and with SMTP;
- transaction rollback when challenge or outbox creation fails;
- worker leases, retry limits, expiry, and terminal failures;
- duplicate delivery after an uncertain SMTP result;
- token digest storage and one-time consume behavior;
- address and account mismatch behavior;
- generic password recovery responses and timing work;
- rate limits;
- session invalidation after password recovery;
- startup validation for every TLS mode and unavailable native TLS;
- log capture that proves that no token, destination, credential, or body is
  present.

Use an in-memory email transport in service tests. Use a local test SMTP server
only for SMTP integration tests.

## Operator procedure

1. Generate a new 32-byte outbox key. Keep it in a secret store.
2. Set `PUBLIC_ORIGIN` to the public HTTPS origin.
3. Set `SMTP_HOST`, `SMTP_FROM`, and the required SMTP security settings.
4. Set `OUTBOX_ENCRYPTION_KEY` to the generated key.
5. Start LinkKeys and check that the worker reports that it is ready.
6. Send one verification message and one password recovery message through a
   test account.

The HTTP recovery and login limits use the direct network peer address by
default. Set `TRUSTED_PROXY_CIDRS` when a trusted reverse proxy connects to
LinkKeys. LinkKeys then reads `X-Forwarded-For` only from a peer in those
networks. Add only proxy networks that remove client-supplied forwarding
headers. Do not use an all-address network. Use a shared edge limit when more
than one LinkKeys replica serves the same domain.

Do not change `OUTBOX_ENCRYPTION_KEY` while pending items exist. A changed key
makes those payloads unreadable. Let the items finish or expire before you
rotate the key.

## Local development

Run `./tools.sh test-smtp` for an automated SMTP protocol test. The test starts
an in-process loopback relay. It does not use an SMTP account or an external
service.

Run `./tools.sh smtp-demo` for a manual browser flow. This command starts a
local Mailpit inbox and a disposable LinkKeys server. It uses an isolated SQLite
database. The command prints the LinkKeys URL and demo sign-in values. Open
`http://127.0.0.1:8025` to read verification and password recovery messages.
Both Mailpit ports bind to the local computer only. Press Ctrl-C to stop
LinkKeys. Run `./tools.sh smtp-down` when you finish.
