# DNS-less local RP: security tradeoffs

An honest accounting of what DNS-less local RP mode protects against, what
it doesn't, and the tradeoffs accepted deliberately in its design. Read
alongside [`dns-less-local-rp-design.md`](../dns-less-local-rp-design.md) at
the repo root, especially its "Security Review Checklist" and "Core
Decisions" sections, which this document does not restate wholesale.

## What admin approval does and does not protect against

Local RP mode replaces DNS proof-of-control (which a LAN app has no way to
obtain) with **domain-admin approval keyed on a key fingerprint**. This is a
different kind of guarantee than DNS-pinned RP identity, and it's important
not to overstate it:

**What it protects against:**

- A domain's users being silently opted into logging in to an arbitrary,
  unreviewed app. Under the default policy (`admin-approval-required`), no
  local RP can complete a login until a human admin has looked at it.
- Impersonation-by-fingerprint. The fingerprint is a SHA-256 hash of a
  32-byte public key; an attacker cannot produce a signature that verifies
  against an approved fingerprint without the matching private key. There
  is no fingerprint collision or forgery path available to a network
  attacker.
- Silent identity swap after approval. Approval is keyed on the fingerprint,
  never on the app's self-reported name — so an attacker cannot get a new,
  malicious app approved just by claiming the same name as an already-
  trusted one (see the admin guide's drift-warning section).

**What it does not protect against:**

- **Admin misjudgment.** Approval is a human decision based on a name the
  app chose for itself, a "first seen" date, and whatever out-of-band
  verification the admin bothered to do. Nothing in the protocol proves the
  app is what its name claims, or that it is trustworthy, or that it will
  stay trustworthy. This is closer to SSH host-key TOFU than to a CA-backed
  guarantee.
- **A pre-approval compromise of the app itself.** If an app's local RP
  private key is stolen before an admin ever reviews it, the admin has
  nothing to distinguish the attacker's traffic from the legitimate app's —
  same fingerprint, same behavior. Post-approval theft is exactly why
  revocation exists (see "Revocation semantics" below), but it requires
  someone to notice and act.
- **The app's own security posture.** Approval says nothing about how the
  app stores the claims it receives, how it manages its own sessions, or
  whether it has other vulnerabilities. LinkKeys' local RP mode secures the
  *login exchange*, not the app.
- **Users evaluating the "unverified" warning correctly.** The consent
  screen labels the app name as unverified and shows a non-DNS-verified
  warning, but the design doc names this directly: *"Users will trust
  whatever name is shown; the UI has to carry the skepticism for them."*
  Some users will not read it.

## The DNS-anchored trust model and the LAN-resolver tradeoff

Once a local RP knows which LinkKeys domain a user selected, it needs that
domain's public keys and revocation list authenticated somehow — an
unauthenticated fetch would let a LAN attacker substitute domain keys and
defeat every downstream signature check. The anchor is the same one
LinkKeys already uses everywhere else: `_linkkeys.{domain}` DNS TXT `fp=`
records, pinned exactly as `crates/linkkeys/src/tcp/tls.rs` pins the S2S TCP
path.

This means local RP mode's security is only as good as DNS resolution is
trustworthy for the resolving app. The accepted tradeoff, stated in the
design doc's "Decided" section: the default DNS resolver is the OS-
configured system resolver — the easiest path — and LAN resolver spoofing
(a hostile DHCP server or compromised router pushing a malicious resolver)
is an accepted, documented risk for this mode, not a gap being silently
ignored. It's judged low-added-risk for the LAN scenarios this mode targets,
and it matches LinkKeys' existing DNS-anchored trust model everywhere else.

**Hardening available:** every SDK's DNS resolver is an injectable seam.
Operationally sensitive deployments should supply a resolver that doesn't
trust the LAN's default (e.g. a DoH endpoint) rather than relying on the
system resolver. This is app/deployment-level configuration, not a protocol
requirement.

## Browser-as-carrier guarantees

The browser only ever carries signed and/or encrypted blobs between the
local RP and the IDP — it is never trusted with protocol state beyond
ordinary redirect mechanics, and every value that matters is either signed,
encrypted, or both:

- The login request is signed by the local RP's key (envelope pattern,
  context `linkkeys-local-rp-login-request`).
- The callback is signed by the domain's keys and then encrypted to the
  local RP's encryption key (negotiated AEAD suite, `aes-256-gcm` baseline).
  The cleartext callback header (fingerprint, nonce, state, chosen suite,
  timestamps) is routing/decryption metadata only, bound into the AEAD
  associated data so it can't be tampered independently of the ciphertext —
  the authoritative copies of every one of those fields live inside the
  ciphertext and are what the SDK actually checks.
- Every value an attacker could tamper with in transit (audience, issuer,
  callback URL, nonce/state, timestamps) is checked by the SDK against the
  decrypted, verified payload — never against the unauthenticated URL
  parameters or header a browser could have altered.

A network position that can see or redirect browser traffic (a malicious
Wi-Fi AP, a browser extension, a captive portal) cannot forge a login result
without the domain's signing key, and cannot read claim values without the
local RP's encryption key. It *can* deny service (drop or corrupt the
callback), which fails safely — an SDK that can't decrypt/verify simply
rejects, with no partial-trust path.

## Ticket possession-proof semantics

The callback carries a claim-get ticket, not claims. The ticket itself is
32 opaque random bytes; the server stores only its SHA-256 hash, never the
raw value, in the same way session/credential secrets are handled elsewhere
in this codebase. Redemption requires a **signed** request
(`SignedLocalRpTicketRedemptionRequest`, context
`linkkeys-local-rp-ticket-redemption`) — the server verifies that signature
against the **stored** signing key for the fingerprint the request claims,
never a key supplied in the request itself. A stolen ticket alone is
useless without the local RP's private signing key: possession of the
ticket bytes is necessary but not sufficient.

Tickets are deliberately multi-use within their validity window (default 1
hour) so the app can retry or refresh, and every redemption returns claim
*values* as of redemption time even though the claim *set* was frozen at
consent — if the user edits their email between consent and redemption, the
app sees the new value. This is a deliberate design choice (see the design
doc's "Decided" section), not an oversight: it trades a small window of
value-freshness against not having to re-run consent for every claim fetch.

## Revocation semantics

Revoking a local RP fingerprint (admin guide, "Revoke") is **terminal** —
there is no un-revoking; a revoked app must generate a new identity and get
re-approved to come back. Its effect is narrowly scoped and worth stating
precisely:

- **Future logins through that fingerprint are rejected** at the IDP, with
  no redirect to its callback URL (so no error detail leaks to a
  potentially-hostile callback endpoint).
- **Outstanding claim tickets die immediately.** Redemption re-checks the
  bound fingerprint's approval status on every call — this re-check, not
  any cleanup step, is the actual enforcement point — and revocation also
  proactively deletes that fingerprint's ticket rows as belt-and-suspenders
  cleanup.
- **App sessions already minted are the app's own to manage.** Revocation
  does not, and cannot, reach into whatever session/cookie/token your app
  created after a prior successful login — LinkKeys has no visibility into
  app-side session state at all. If a compromise requires killing active
  app sessions, that is a separate operation your app must perform itself.

## The callback URL http-allowed rationale

Both `http` and `https` callback URLs are accepted; every other scheme
(`javascript:`, `data:`, custom app schemes like `myapp:`) is rejected
outright, with a friendly, non-technical, i18n-cataloged error shown on the
IDP's own page — never a redirect carrying error detail to the rejected
scheme. The `http` allowance is deliberate, not a shortcut: a DNS-less
LAN/loopback RP has no way to obtain a browser-trusted TLS certificate for
itself (that's the entire premise of this mode — no DNS), so requiring
`https` for the callback leg would make the mode unusable for its target
audience. It's safe to allow because **protocol security does not depend on
that leg's transport**: the payload is already signed by the domain and
encrypted to the local RP's key before it's placed in the callback URL, so
an on-path observer of the browser's final hop learns nothing usable from
seeing the encrypted blob in plaintext HTTP. The transport-level
confidentiality that `https` would add here is redundant with what the
protocol already guarantees cryptographically for this specific leg — the
tradeoff is deliberate, not a security regression.

One explicit non-goal falls out of the scheme restriction: a native mobile
app cannot take a login via this mode, because custom URL schemes (the
standard mobile deep-link pattern) are rejected. There is no supported
workaround; mobile apps needing LinkKeys login should use a different flow.

## The Ed25519 verifier-strictness open item

This is a genuinely open item, not a resolved tradeoff — flagged here for
visibility, not because it has a fix. Ed25519 implementations differ across
languages on signature-malleability edge cases: non-canonical `S` values and
small-order `A` (public key) components. Some verifiers reject these
(`verify_strict`-style checks); others accept them. The reference
implementation (`crates/liblinkkeys/src/crypto.rs`) explicitly uses
`ed25519-dalek`'s `verify_strict`, but the SDK matrix spans OpenSSL, JCA,
libsodium/`ext/sodium`, BoringSSL (via `dart:io`), and Erlang/OTP's
`:crypto` — and these genuinely differ on acceptance at those edges. The
shared conformance vector suite (`sdks/local-rp/conformance/`) does not
currently include malleability-edge test vectors, so this divergence is not
pinned by test.

Why this is currently judged low-risk rather than urgent: every signature
in this protocol is produced by an honest signer over well-formed envelope
bytes (a local RP's own key, or a domain's own key) — there is no known
path where an attacker benefits from a malleable-but-valid alternate
signature encoding of an honestly-signed message in this protocol's flows.
Adding malleability-edge vectors to the conformance suite would pin
acceptance behavior deliberately, closing the gap between "no known
exploit" and "verified consistent," rather than leaving it to backend
accident. That work has not been done yet.
