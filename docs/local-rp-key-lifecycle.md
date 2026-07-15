# DNS-less local RP: key expiration and rotation

A local RP identity has exactly one signing key and one encryption key —
never more, never fewer. This document covers their lifetime, the
expiration-warning thresholds every SDK reports identically, and what
rotation means. See [`dns-less-local-rp-design.md`](../dns-less-local-rp-design.md)
("One Signing Key and One Encryption Key") for the full rationale.

## Default lifetime

**10 years** from generation (`generate_local_rp_identity`'s `now`
argument), applied to both keys and the descriptor that binds them
together. Every SDK's reference constant is 3650 days
(`DEFAULT_LIFETIME` in the Rust SDK, `crates/liblinkkeys/src/local_rp.rs`
uses the same figure in its own tests). This is a deliberately long,
SSH-host-key-style lifetime: rotation is meant to be a rare, deliberate
operator event, not a routine one.

## Expiration thresholds (`check_expirations`)

Every SDK exposes `check_expirations(identity, now)`, which reports the
exact expiry datetime and one of four warning levels, computed purely from
remaining time — the SDK never blocks a login or forces rotation on its
own; that decision belongs to your app:

| Level | Threshold |
|---|---|
| `notice` | More than 180 days remain. |
| `warning` | 180 days or fewer remain (more than 90). |
| `critical` | 90 days or fewer remain (more than 30). |
| `expired` | 30 days or fewer remain, or `now >= expires_at`. |

These thresholds are identical across every SDK and are pinned by the
shared conformance vector suite (`sdks/local-rp/conformance/`), so a Go app
and a PHP app checking the same identity bytes at the same `now` will agree
on the level. What you do with the result — warn an admin, warn the user,
block login proactively, kick off a rotation flow — is entirely app policy.

## Rotation = a new identity, not a renewal

There is no continuity-of-key story in this protocol. **Rotating** a local
RP's keys means generating a brand-new signing/encryption keypair, which
produces a **new fingerprint** — a new identity from every domain's point of
view, indistinguishable from an app you'd never seen before:

- It requires **re-approval at every LinkKeys domain** that previously
  allowed the old fingerprint. Nothing carries over automatically, even
  under `allow-by-default` policy (auto-approval only applies to true first
  contact — see the admin guide's status-transition notes).
  Under `admin-approval-required`, the new fingerprint queues exactly like
  any unknown app.
- The old fingerprint's approval status, if any, is untouched — it isn't
  deleted or migrated. If you want the old identity to stop working
  entirely, revoke it explicitly (see the admin guide) as a separate step.
- There is no "same app, new key" signal in the protocol. A domain admin
  has no way to know two fingerprints belong to the same app other than
  the app's own (unverified) claimed name and any out-of-band
  communication.

This is intentional, not a missing feature: automatic rotation without a
DNS/domain anchor would create ambiguous trust-transfer semantics — a
compromised app could otherwise "rotate" into a domain's approval without
review. If your app needs stable, continuous identity across a key change,
or organization-level key continuity, run a normal DNS-pinned RP or IDP
instead of local RP mode.

## Practical guidance

- Plan for rotation as a scheduled, deliberate maintenance operation, not
  an automated one. Watch `check_expirations`, and start the "generate new
  identity, get it re-approved everywhere that matters" process well before
  `expired` — `critical` (30 days) is a reasonable last-call point given
  domain admins may need time to review and approve.
- If a key is lost, compromised, or believed compromised, do not wait for
  natural expiry: generate a new identity immediately, get it approved,
  and ask affected domain admins to revoke the old fingerprint (see the
  admin guide's "Revoke" section — revocation kills the old identity's
  outstanding claim tickets and future logins immediately, but does not
  reach into app sessions already minted from it).
