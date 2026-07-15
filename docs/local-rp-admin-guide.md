# Domain admin guide: DNS-less local RP approvals

If your domain allows DNS-less local RP logins (see
[`local-rp-operator-guide.md`](local-rp-operator-guide.md) for the policy
vocabulary and how it's set), this is what you as a domain admin need to
know about approving, denying, and revoking the apps that use it. For the
full protocol design and the reasoning behind each rule below, see
[`dns-less-local-rp-design.md`](../dns-less-local-rp-design.md) at the repo
root.

## The approval model: fingerprint is identity, app name is not

A local RP has no DNS to prove control of a domain, so its identity is the
SHA-256 hex fingerprint of its signing public key instead — the same
fingerprint format LinkKeys already uses for domain and user keys, SSH-host-
key style. **Approval keys on the fingerprint alone.**

The app also reports a display name and, optionally, a local domain/origin
hint. These are shown to admins and to users on the consent screen, always
labeled unverified — the app chooses this text itself, and nothing stops it
from choosing a misleading one. Treat it as audit context, never as part of
an identity decision: two different fingerprints with the same claimed name
are two different apps, and the same fingerprint changing its claimed name
over time is not a new app.

**Drift warning:** if an already-known fingerprint shows up on a later login
attempt with a changed `app_name` or `local_domain_hint`, the server logs a
warning (`local RP <fingerprint> metadata drift on repeat attempt: [...]`).
This is currently **log-only** — it is not surfaced in `local-rp list`/`get`
output or persisted as a historical diff; those commands only ever show the
most recently reported metadata plus `first seen`/`last seen` timestamps. If
you want to catch drift, watch the server logs, or compare a fingerprint's
`app_name` between visits yourself using the timestamps as a guide.

## The pending queue

An entry is added to the pending queue only when an **authenticated user of
your domain** actually attempts a login through an unknown local RP
fingerprint (under `admin-approval-required` policy). Anonymous requests —
someone merely visiting the login URL without authenticating — never create
a queue entry. This keeps the queue from being flooded by unauthenticated
probing.

- **Deduped by fingerprint:** a repeat attempt from an already-pending
  fingerprint refreshes its `last_seen_at` and reported metadata rather than
  creating a second entry.
- **Capped:** the queue accepts at most 100 pending entries
  (`MAX_PENDING_LOCAL_RPS` in `crates/linkkeys/src/services/local_rp.rs`) at
  once. Once at capacity, a genuinely new fingerprint's login attempt is
  rejected outright (`PendingCapReached`) until the queue is worked down by
  approving or denying existing entries.
- **No proactive notification.** Admins are not paged, emailed, or otherwise
  alerted when something lands in the pending queue — this is deferred to a
  future events/notification system and deliberately not built yet. You
  must check the queue yourself (`linkkeys local-rp list --status pending`).

## CLI verbs

All local RP admin operations are TCP CSIL-RPC calls under the `Admin`
service, authenticated with an API key belonging to a user holding the
`admin` relation on your domain (`RELATION_ADMIN`, mapped explicitly in
`crates/linkkeys/src/services/authorization.rs` — not a fallthrough default).
Set `LINKKEYS_API_KEY` in your environment before running these; `--server`
defaults to `localhost:<TCP_PORT>` (or `$LINKKEYS_SERVER:<TCP_PORT>` if set).

If you don't already have an admin-relation API key, mint one directly
against the database (DB-direct, break-glass — the same bootstrap path used
for the very first admin):

```sh
linkkeys user create <username> "<display name>" --api-key --admin
# prints the API key once — save it
```

### List

```sh
linkkeys local-rp list
linkkeys local-rp list --status pending
linkkeys local-rp list --status pending --offset 0 --limit 20
linkkeys local-rp list --server linkkeys.example.com:4987
```

`--status` filters to one of `pending`, `approved`, `denied`, `revoked`.
Omit it to see every fingerprint on the domain, oldest-created first. Each
entry prints its short (16-hex-char) and full fingerprint, status, claimed
app name (marked unverified), domain hint if reported, first-seen /
last-seen timestamps, and admin notes if any.

### Get

```sh
linkkeys local-rp get <full-fingerprint>
```

Same detail as one `list` entry, for a single fingerprint. The fingerprint
argument must be the full hex string — the CLI's short-prefix display is for
reading, not for typing back in.

### Approve

```sh
linkkeys local-rp approve <full-fingerprint>
linkkeys local-rp approve <full-fingerprint> --admin-notes "verified with the jukebox's maintainer over Matrix"
```

Valid from `pending` or `denied` (an admin changing their mind). Once
approved, the fingerprint's future login attempts proceed straight to
consent — no more pending gate.

### Deny

```sh
linkkeys local-rp deny <full-fingerprint>
linkkeys local-rp deny <full-fingerprint> --admin-notes "unrecognized, no response from claimed maintainer"
```

Valid from `pending` only. A denied fingerprint's future login attempts are
rejected on the IDP's own error page — the browser is never redirected to
its callback URL with error details (design doc: never leak error detail to
a pending/denied/revoked RP's callback).

### Revoke

```sh
linkkeys local-rp revoke <full-fingerprint>
linkkeys local-rp revoke <full-fingerprint> --admin-notes "key compromise reported 2026-07-12"
```

Valid from `approved` only, and **terminal** — there is no un-revoking.
Revoking stops future logins immediately and deletes that fingerprint's
outstanding claim tickets (both by rejecting redemption at the approval-
status check, and by proactively deleting the rows). It does not reach into
app sessions already minted from a prior login — those are the app's to
manage. If the same app wants back in after revocation, it needs a new key
pair (a new identity, requiring fresh approval) — see
[`local-rp-key-lifecycle.md`](local-rp-key-lifecycle.md).

### Domain policy (get-policy / set-policy)

```sh
linkkeys local-rp get-policy
linkkeys local-rp set-policy allow-by-default
linkkeys local-rp set-policy disabled
linkkeys local-rp set-policy admin-approval-required
```

Same `Admin` service, same `admin`-relation auth as every verb above. See
[`local-rp-operator-guide.md`](local-rp-operator-guide.md) for what each
policy value means. `get-policy` always returns the *effective* policy
(`admin-approval-required` if the domain has never set one); `set-policy`
rejects any value outside the three-value vocabulary with a clean error
rather than writing it.

## Status transition rules

The only valid transitions (enforced server-side; anything else, including
`denied → pending` or `revoked → approved`, is rejected):

| From | To |
|---|---|
| `pending` | `approved` |
| `pending` | `denied` |
| `denied` | `approved` |
| `approved` | `revoked` |

There is no path back out of `revoked`. There is no direct `pending →
revoked` (a fingerprint must be approved before it can be revoked) and no
`denied → revoked` (deny it, or approve-then-revoke, but revocation itself
only makes sense once something was actually allowed to run).

## Troubleshooting: connection/DNS errors on TCP-backed commands

`linkkeys local-rp <verb>` (and every other `--server`-targeted TCP CLI
command, e.g. `linkkeys user list --server ...` — this is not specific to
local RP) used to **panic** during DNS fingerprint pinning, because
`linkkeys::dns::resolve_fingerprints` unconditionally built and blocked on a
*new* Tokio runtime from inside the CLI's own already-running
`#[rocket::main]` runtime ("Cannot start a runtime from within a runtime").
That is now fixed: `resolve_fingerprints` detects the ambient runtime
(`crates/linkkeys/src/dns.rs`) and drives the lookup on it instead of
nesting a second one, so these commands now fail cleanly on a real DNS/
connection problem instead of panicking. Regression coverage:
`crates/linkkeys/src/dns.rs`'s
`test_resolve_from_within_multi_thread_runtime_does_not_panic` /
`test_resolve_from_within_current_thread_runtime_does_not_panic`.

A clean failure still looks like an error, just not a panic, e.g.:

```
Error: TLS error: DNS fingerprint resolution for <host>: DNS lookup failed: no TXT record at _linkkeys.<host>: ...
```

Two environment-variable escape hatches remain, for their legitimate uses —
not to work around the old panic, which no longer needs working around:

- `LINKKEYS_FINGERPRINTS=<hex>,<hex>,...` — pins fingerprints directly
  instead of resolving them from DNS. Useful for a domain with no real DNS
  yet (bootstrap, local/dev testing) or as a temporary pin while DNS
  propagates. Get the fingerprints from `linkkeys domain list-keys` on the
  target domain if you operate it, or from `linkkeys domain dns-check`'s
  expected TXT record.
- `LINKKEYS_ALLOW_PRIVATE_PEERS=true` — needed if the target server is on
  loopback/LAN (`crates/linkkeys-rpc-client` otherwise refuses to dial a
  non-public address as an SSRF guard). Only for local/LAN operation, e.g. a
  domain server you're standing up on your own network.
