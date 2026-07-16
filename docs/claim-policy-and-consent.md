# Claim signing, policy management, and privacy consent

This describes how LinkKeys decides **what claims exist**, **how they get signed**,
**who may set them**, and **what gets released to which sites** — and the web
surfaces a person (technical or not) uses to control all of it.

The design separates three layers, each owned by a different party and each a
strict bound on the next:

| Layer | Owner | Question it answers | Where |
|---|---|---|---|
| Claim‑type registry | Domain admin | What may exist, who may set it, how it's signed | `/policy-admin` |
| Claims + signing prefs | The user | My values, and which I keep signed | `/account/identity` |
| Release / consent | The user (within admin bounds) | Who actually receives each claim | consent screen + `/account/identity` |

A non‑technical user never sees the word "sign." They fill in values and see a
**Verified ✓** badge when the domain was able to validate and sign them.

---

## 1. Signing lanes

Every claim type has a `signing_rule` that puts it in one of four lanes. This is
the spine of the system (`liblinkkeys::claim_policy`).

| Lane | `signing_rule` | Meaning | IDP signs? |
|---|---|---|---|
| A | `self_signed` | A CSIL primitive the IDP validates and signs **on set** | Yes, immediately |
| B | `verified` | The IDP signs only **after a built‑in verification flow** | Yes, after the flow |
| C | `attested` | The IDP doesn't vouch for the value; it admits an **external trusted‑issuer** signature | No (custodies an external sig) |
| D | `unsigned` | Never carries a domain signature | No |

A claim type also carries:

- `value_type` — the CSIL primitive the IDP can validate (`text`, `url`, `email`,
  `bool`, `int`, `float`, `decimal`, `date`, `timestamp`) or `opaque` (not
  validatable). The IDP only ever self‑signs a value it can validate.
- `set_rule` — who may set it: `user_self`, `idp_on_request`,
  `trusted_issuer_only`, `admin_only`, `deny`.
- `max_bytes` — size bound (default 33792 ≈ 33 KiB).
- `requires_approval` — a user set is queued for an admin instead of signed now.
- `user_settable` — whether a user may set it at all (enforced server‑side, not
  just hidden in the UI).
- `default_auto_sign` — the default of the user's per‑type auto‑sign toggle.

### Seeded starter registry

Shipped on first boot (idempotent insert‑if‑absent, so admin edits are never
overwritten):

- **Lane A, auto‑sign on:** `display_name`, `handle`, `website` (url),
  `avatar_url` (url).
- **Lane B:** `email` (verified via an email round‑trip) and `email_verified`
  (a bool the IDP sets as a side effect — not user‑settable).
- **Lane C (suggested):** `legal_name`, `date_of_birth`, `age_over_21` — set as
  `trusted_issuer_only` / `attested`. No issuers are trusted by default; an admin
  adds the domains they recognize (e.g. a government entity for `age_over_21`).
  **See the limitation in §6 — external‑signature storage is not wired yet.**

### The set decision (pure)

`liblinkkeys::claim_policy::evaluate_set(policy, setter, value)` returns a
`SetAction` (`SelfSign`, `Verify`, `AcceptAttested`, `Queue`, `StoreUnsigned`) or
a machine‑readable `RejectionReason` (`UnknownClaimType`, `ValueTypeMismatch`,
`ValueTooLarge{limit}`, `SetterNotAuthorized`). It is pure and unit‑tested, so the
same decision is reproducible from web, a future CLI, or a native agent.

---

## 2. The profile / identity editor (`/account/identity`)

What the user sees:

- One card per claim type the admin marked `user_settable`: a value field, a
  **Keep this verified** toggle (auto‑sign), a **Verified ✓ / Not verified**
  badge, and a **Share with any domain automatically** checkbox.
- Saving a lane‑A value validates and (if auto‑sign is on) signs it immediately.
  Turning auto‑sign off stores the value **unsigned** on the next save.
- Saving `email` starts the verification flow (an email with a confirmation
  link; the stub logs the link — see §6). Confirming signs `email` +
  `email_verified`.
- **Profiles:** when the operator raises `MAX_PROFILES_PER_ACCOUNT` above 1, a
  section appears to create additional pseudonymous profiles. Users never delete
  a profile — that's an admin action.

One active claim is kept per (subject, type): a new value revokes the prior one.

---

## 3. The admin policy editor (`/policy-admin`)

Gated by the `manage_claims` relation. Four sections, all guided forms (dropdowns,
not a policy language):

1. **Claim types** — view/add/edit/delete registry entries (value type, set rule,
   signing lane, flags).
2. **Trusted issuers** — domains whose signature is accepted as attestation for a
   claim type (lane C).
3. **Release defaults** — per‑audience `forced_allow` / `forced_deny`. Audience
   `*` is the global default; `forced_deny` wins over `forced_allow`.
4. **Pending approvals** — queue of user‑set claims awaiting approval; **Approve**
   signs with the domain keys and stores, **Reject** discards.

---

## 4. Privacy consent — "even my mom"

Two paths let a person control what sites receive, without understanding crypto:

- **Per‑login consent screen** (existing): the RP asks for claims; the user
  checks what to share. Rows the user has standing‑allowed arrive **pre‑checked**.
- **Standing release preferences** (new): from the identity editor, the user can
  **Share <claim> with any domain automatically**. This records a preference for
  audience `*` (any domain). At consent time those rows are pre‑checked, so the
  user confirms with one click — affirmative consent is preserved, friction is
  gone.

Standing preferences are user‑owned and can never override an admin `forced_deny`
(deny always wins), and they only set the consent **default** — they do not
auto‑release without the user submitting the consent form. (Auto‑skip of the
prompt still keys off real prior consent grants, not standing prefs.)

Release policy is loaded **per audience** from the `release_policies` table
(`domain_policy_for`). It fails **closed**: if the policy can't be loaded, the
login/consent aborts rather than releasing claims an admin denied.

---

## 5. Data model & env

New tables (Postgres + SQLite, single‑file idempotent migrations):

- `claim_type_policies` — the registry.
- `trusted_issuers` — `(claim_type, issuer_domain)`.
- `profile_claim_prefs` — per‑profile auto‑sign toggle.
- `release_policies` — `(audience, claim_type, disposition)`; `*` = global.
- `claim_approval_queue` — pending approvals.
- `email_verifications` — single‑use verification tokens (24h TTL).
- `user_release_prefs` — `(user_id, audience, claim_type)`; `*` = any domain.

Env:

- `CONSENT_FORCED_ALLOW` / `CONSENT_FORCED_DENY` — **deprecated**. Seeded once into
  `release_policies` (audience `*`) on first boot if the table is empty; the DB is
  now the source of truth. A `TODO` marks removal in a later session.
- `PUBLIC_ORIGIN` — base URL for verification links (falls back to
  `https://<DOMAIN_NAME>`).
- `MAX_PROFILES_PER_ACCOUNT` — default 1 (hides multi‑profile UI).

---

## 6. Known limitations / follow‑ups

1. **Lane‑C external‑signature storage — DONE (foundation).** `claim_signatures`
   no longer FKs `signed_by_key_id` to `domain_keys` and the column is widened to
   text, so an issuer's signature stores verbatim. An append‑only `peer_keys`
   cache (with the issuer's `expires_at`/`revoked_at`) lets stored signatures be
   re‑verified later. `services::attestation` provides `verify_and_store_attested`
   (trusted‑issuer gate → signature verify → store) and `verify_stored_claim`
   (the one‑click verify). The issuer's signature is **kept and exposed** per
   `docs/claim-trust-verification.md`. Deposit is a **CBOR-RPC op**
   (`Attestation/deposit-claim`, server-to-server, dispatched like the other
   protocol services — not a REST route). The user-initiated **signing request**
   is `liblinkkeys::signing_request` + the CSIL `SigningRequest` envelope;
   `attestation::mint_signing_request` produces it (TTL `SIGNING_REQUEST_TTL_SECONDS`,
   default 2 days for non-portable-device logistics). The full loop has UIs:
   **Request** (`/account/request-verification` → QR + base64 + file download),
   **Issue/receive** (`/policy-admin/issue` — admin pastes a request, it's
   verified against the subject's keys, the admin signs the attested claim). The
   issuer then **deposits it server-to-server** to the subject's home domain over
   the generic CBOR-RPC carrier (`POST /csil/v1/rpc` → `Attestation/deposit-claim`,
   resolved via DNS / the request's `callback`) — no user round-trip; if the
   domain is unreachable it falls back to handing the user the claim. Trusting an
   issuer caches its keys (so the sync deposit op verifies). The carrier speaks
   the **canonical CSIL-RPC v1 transport** (`csilgen-transport` — tag-24 payloads,
   `id`/`variant`, the status registry; vendored under `crates/csilgen-transport`
   for now, to swap for the git/published crate later), and `/csil/v1/rpc` is the
   single CBOR-RPC carrier over the web (shares `dispatch()` with TCP), so the web
   carries the whole RPC surface without per-op routes. The identity page's
   **Verified credentials** section runs `verify_stored_claim` live and shows
   "signed by `<domain>` ✓" per held claim. Nothing left on the attestation track.
2. **Email sending is a stub** that logs the link (`crate::email`). Add an SMTP /
   provider backend before production; gate link logging behind a dev flag.
3. **Verification email rate limiting is basic.** Requests are throttled per
   subject, but a real SMTP/provider backend should revisit provider-side
   throttles and outstanding-token caps.
4. **Per‑profile claim keying is pending.** Claims are still keyed by account id,
   so the identity editor operates on the default profile. Raising
   `MAX_PROFILES_PER_ACCOUNT` and using extra personas needs per‑profile claim
   keying first (it currently fails closed — no leak).
5. **CSIL claim-policy self-service is not fully extended.** Attestation deposit
   is in CSIL, and the claim-type registry + its per-locale name translations
   are now on the `Admin` CSIL service too (`list-claim-types`/`set-claim-type`/
   `remove-claim-type`/`set-claim-type-label`/`remove-claim-type-label`,
   `admin`-relation only — the same DB calls `/policy-admin`'s forms make; also
   on the CLI as `linkkeys policy ...`). Trusted issuers, release defaults, and
   the approval queue are still server web/DB-only flows; a later pass should
   extend those the same way. Pure logic already lives in
   `liblinkkeys::claim_policy`.

---

## 7. Suggested test flow (trust IDP → apps; users choose per‑domain / any‑domain)

1. As admin, open `/policy-admin`. Confirm the seeded claim types; add any you
   want (e.g. `pronouns`, lane A). Optionally add a `forced_deny` rule for a
   sensitive type, or a `forced_allow` for a specific app audience.
2. As a user, open `/account/identity`. Fill in `display_name`, `handle`,
   `website` → they show **Verified ✓**. Verify `email` (grab the link from the
   server log). Tick **Share with any domain automatically** for `handle`.
3. From a relying‑party app, start a login that requests `handle`, `display_name`,
   `email`. On the consent screen, `handle` is pre‑checked (standing "any domain"
   pref); the user confirms.
4. Confirm the RP receives exactly the consented claims (scoped by
   `compute_authorized_claims`), and that an admin `forced_deny` on a type
   suppresses it even if the user checked it.
