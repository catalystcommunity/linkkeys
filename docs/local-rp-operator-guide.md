# Operating DNS-less local RP mode

This is the operator-facing guide for the DNS-less local RP identity feature:
how it lets locally installed apps (LAN jukeboxes, desktop tools,
self-hosted services with no public DNS) use a LinkKeys domain for login
without running their own DNS-pinned relying party. For the full protocol
design and rationale, see [`dns-less-local-rp-design.md`](../dns-less-local-rp-design.md)
at the repo root — that document is the normative spec, especially its "Wire
Precision" section. This guide only covers what an operator running a
LinkKeys domain server needs to know.

See also: [`local-rp-admin-guide.md`](local-rp-admin-guide.md) (day-to-day
approval workflow), [`local-rp-key-lifecycle.md`](local-rp-key-lifecycle.md)
(expiration/rotation), and [`local-rp-security-tradeoffs.md`](local-rp-security-tradeoffs.md)
(what this protects against and what it doesn't).

## Enabling or disabling local RP mode for a domain

Each domain has one of three admission policies, stored per-domain
(`local_rp_domain_policy` table, keyed on domain):

| Policy value | Meaning |
|---|---|
| `disabled` | No local RP logins are accepted for this domain at all. |
| `admin-approval-required` | **Default.** An unknown fingerprint is queued for admin review; only an approved fingerprint can complete a login. |
| `allow-by-default` | An unknown fingerprint is auto-approved on first authenticated login attempt. For domains that have explicitly decided to accept that risk. |

If a domain has never set a policy, the effective policy is
`admin-approval-required` — this is the deliberate default (design doc:
"the default should be admin approval").

Set or read the policy with the `local-rp` CLI verbs (TCP, admin relation
required — same auth as list/get/approve/deny/revoke below):

```sh
# Effective policy: the stored value, or "admin-approval-required" if unset.
linkkeys local-rp get-policy

# One of: disabled, admin-approval-required, allow-by-default.
linkkeys local-rp set-policy allow-by-default
```

Both go over the `Admin` service (`get-local-rp-policy`/`set-local-rp-policy`
ops, `DbPool::effective_local_rp_policy`/`DbPool::set_local_rp_domain_policy`
in `crates/linkkeys/src/db/mod.rs`). `set-policy` validates against the
vocabulary above and rejects anything else with a clean error — it never
writes an invalid value.

## What the public TCP surface exposes

Local RP mode adds one new TCP CSIL-RPC service, `LocalRp`, and reuses two
existing ones. All of it is TCP-only — there are no HTTP routes for any of
this (design doc: "There are no HTTP routes for any of this. HTTPS is
browser-only in LinkKeys").

- **Domain public-key fetch** (`Handshake/get-domain-keys`) and **revocation
  fetch** (`Handshake/get-revocations`) — pre-existing operations, unchanged
  in shape by this feature. They accept unauthenticated TCP peers (no mutual
  TLS client auth required): the response is public verification material,
  not a secret. `GetDomainKeysResponse` carries an optional
  `recent_revocations_available` flag so a caller knows to pull revocations
  without a DNS round-trip.
- **Claim-ticket redemption** (`LocalRp/redeem-claim-ticket`) — also accepts
  an unauthenticated TLS peer, but authentication happens at the
  *application layer*: the request is `SignedLocalRpTicketRedemptionRequest`,
  signed with the local RP's signing key over context
  `linkkeys-local-rp-ticket-redemption`. The server looks up the claimed
  fingerprint, verifies the signature against that fingerprint's **stored**
  signing key (never a key supplied in the request), and only then proceeds
  — so a stolen ticket is useless without the RP's private key, and nothing
  is trusted before possession is proven.

None of these three operations require an API key or admin relation; they
are the intentionally-public surface a local RP's SDK talks to directly.
Admin operations (list/get/approve/deny/revoke) are a separate, authenticated
part of the `Admin` service — see the admin guide.

### Rate limits

- **Ticket redemption** (`crate::services::ratelimit::TICKET_REDEMPTION` in
  `crates/linkkeys/src/services/ratelimit.rs`): a token bucket keyed by the
  local RP's fingerprint, ~20 rapid attempts then one every 3 seconds. This
  bucket is only debited **after** the redemption signature verifies against
  the stored key — never before. That ordering matters: the fingerprint in
  a redemption request is attacker-chosen, so metering before proof-of-
  possession would let anyone who can reach the TCP port spam a *victim*
  app's fingerprint and exhaust its bucket. An unverified request costs the
  server one indexed lookup plus one Ed25519 verify and never touches the
  limiter.
- **Domain-key and revocation fetch** are not separately rate-limited beyond
  the server's existing unmetered-read posture for those ops (they were
  already unauthenticated, unmetered reads before this feature).

## What gets stored

Three tables, all covered by PostgreSQL and SQLite migrations
(`migrations/{postgres,sqlite}/2026-07-12-000002_local_rp_persistence`):

- **`local_rp_domain_policy`** — one row per domain: `domain`, `policy`.
- **`local_rps`** — the approval registry, one row per fingerprint:
  `fingerprint` (the identity key), `signing_public_key`,
  `encryption_public_key`, `app_name` and `local_domain_hint` (display/audit
  metadata only — see the admin guide on why these are never treated as
  identity), `status` (`pending`/`approved`/`denied`/`revoked`),
  `created_at`/`updated_at`/`expires_at`/`last_seen_at`, `admin_notes`.
- **`local_rp_claim_tickets`** — claim-get tickets: `ticket_hash` (SHA-256
  hex of the 32 random ticket bytes — **the raw ticket is never stored or
  logged**, only its hash, matching how session/credential secrets are
  handled elsewhere in this codebase), `fingerprint` binding, `user_id`,
  `user_domain`, `granted_claims` (the consent-frozen claim-name set, as
  JSON), `expires_at`.

No private key material for local RPs is ever stored server-side — only the
two public keys per fingerprint. The app's private signing/encryption keys
never leave the app.

## Backup coverage

All three tables above are part of the domain's encrypted backup/restore
artifact — they're listed in `SNAPSHOT_TABLES`
(`crates/linkkeys/src/backup/mod.rs`), the single source of truth for what a
`linkkeys backup`/`linkkeys restore` round-trip covers, and a drift-guard
test asserts every application table is in that list. No separate backup
step is needed for local RP data: it comes along with an ordinary domain
backup.

```sh
linkkeys backup --out domain-backup.bin      # includes local RP policy/registry/tickets
linkkeys restore --in domain-backup.bin
```

See `linkkeys backup --help` / `linkkeys restore --help` for the full flag
set (key rotation, passphrase embedding, `--force`); this feature adds no
new backup flags or behavior.

## Operational notes

- **Revoking a local RP stops future logins and kills its outstanding claim
  tickets**, but does **not** reach into sessions the app already minted
  from a prior successful login — those are the app's own to manage. This
  is enforced two ways: claim-ticket redemption re-checks the bound RP's
  approval status on every call (the actual enforcement point — a revoked
  RP's tickets fail redemption even before any cleanup runs), and revocation
  also proactively deletes that fingerprint's outstanding ticket rows
  (`crate::services::local_rp::transition_status`, belt-and-suspenders
  cleanup — a failure there is logged, not propagated, since the status
  change is what's authoritative).
- **Purging a user deletes that user's outstanding local-RP claim tickets.**
  User purge minimizes the `users` row rather than deleting it (existing
  purge behavior), so a ticket's foreign key to that row does not cascade
  away on its own. `linkkeys user purge-local` explicitly deletes the
  purged user's outstanding local-RP claim tickets as part of that
  operation; redemption also independently rejects a deactivated or purged
  user's ticket at redemption time as a backstop.
- **Expired tickets** are not deleted automatically on a timer within the
  server process; `crate::services::local_rp::purge_expired_tickets` exists
  for this and mirrors the shape of the existing pin-recheck cron job
  (`crate::services::pins::recheck_all`) — wire it to whatever periodic job
  runner the deployment already uses for that kind of housekeeping, the same
  way `linkkeys pins recheck` is intended to be cron-driven.
- **Never logged**: private keys, nonces, claim tickets (raw bytes), full
  claim values, or decrypted callback payloads. Only a ticket's hash, a
  fingerprint, and (on revocation) counts/warnings ever appear in logs.
