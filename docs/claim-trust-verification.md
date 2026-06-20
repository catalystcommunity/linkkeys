# Claim trust & verification model (decided — do not revisit)

This records the identity/trust decisions so we don't relitigate them. It is the
authority for how subjects, profiles, and signatures relate.

## 1. One account = one UUID = the subject of everything

A human's account has exactly **one UUID**. Every assertion and every claim binds
that account UUID as its subject. **Profiles are NOT their own UUID.** The subject
a relying party sees is the account UUID.

A signature must bind a subject id, or the signed claim would be replayable to
anyone at the domain ("portable across the entire domain" — unacceptable). The
account UUID is that binding.

## 2. Profiles are override sets, not identities

A **profile** is a named **override set**: per-claim value overrides plus a
release policy, layered over the one account identity — "use *this* avatar_url
and stage name with gaming sites, but not with family." When a profile is
presented, the domain emits the overridden values **signed by the domain, still
bound to the account UUID**. Profiles let you *present differently*; they do not
make you a *different cryptographic subject*.

Consequently profiles are **not unlinkable**. Two profiles share the account UUID,
so an RP (or a breach) can correlate them.

## 3. Unlinkability is a separate account, not a profile

If you need a persona that cannot be correlated with your main identity (a
political forum, an adult site), create **another account** — possibly at another
domain. The system supports this; a device can be enrolled in multiple
accounts/domains, so switching is smooth. Each account is its own UUID and is
cryptographically independent.

This is honest about the limit: we do not pretend a profile gives you
unlinkability it can't deliver. Operational correlation (timing, IP, reused
values) remains the user's/domain's responsibility, not something tech fully
solves.

## 4. Third-party signatures are KEPT and EXPOSED — trust but verify

When a third party (a government, a trusted company, "Bob's Junkyard," a
neighbor) attests a claim, **their signature stays on the claim and is shown to
relying parties and verifiers.** We do **NOT** strip it and have the domain
re-attest in its place.

Rejected alternative (domain re-attests, hides the issuer): it destroys the
credibility the issuer was supposed to add. If RPs only see "the domain says so,"
then anyone can spin up a domain, build a little trust, and sign whatever they
want. **Trust but verify** is the whole point — the issuer's signature must be
independently checkable against the issuer's public keys.

So a claim carries one or more signatures; each names its signing domain and is
verifiable against that domain's DNS-pinned keys (multi-signature is already in
the protocol). A forum profile might show "**age ≥ 21** — signed by `dmv.ca.gov`"
or "**over 18** — signed by `bobs-junkyard.example`." Whether that signer is
worth trusting is the **viewer's / RP's** decision, surfaced and verifiable at one
click via the viewer's own domain IDP.

## 5. Issuers choose what and for how many UUIDs they sign

An issuer signs a claim bound to a UUID. A government may choose to issue its
**official digital ID** (carrying the legitimizing "license number" it can look
up in its database) for only **one** UUID per person. But it is **encouraged** to
sign the *attribute* claims people actually need everywhere — `age_over_21`,
`is_real_person`, `sex`, etc. — for **multiple** UUIDs, *without* the legitimizing
official-ID field. That lets a person carry verified age onto a separate,
unlinkable account without dragging their official identity along.

And no issuer is privileged: **any party can sign any claim**. A site that won't
accept government can accept whoever it wants; a person who distrusts a given
signer can ignore that claim. We do not designate official signers.

## 6. We provide tools, not trust

We do **not** solve trust. We make it easy for non-technical people to decide how
*they* want to solve it:

- A claim shows **what** is asserted and **who** signed it.
- Verification is one click, performed by the viewer's own domain IDP against the
  signer's DNS-pinned public keys.
- RPs configure which signers they display/accept; users configure which they
  present. Both choices are theirs.

The credibility of a claim = (the signers, verifiable) × (the verifier's trust in
those signers). The system guarantees the first and never dictates the second.

## 7. Implications for the data model

- **Claims bind the account UUID.** `claims.user_id` / `consent_grants.user_id`
  stay keyed to the account (`users.id`). We are **not** repointing them at a
  per-profile UUID. (The branch's `subject_profiles` migration is dropped.)
- **Profiles** remain rows under an account but are override sets, not subjects.
  Per-profile **value overrides** (+ re-signing the overridden value with the
  domain key, bound to the account UUID) are the future presentation feature.
  The root/never-leaked-anchor distinction is moot — there is one account UUID.
- **Third-party claim storage** must keep the issuer's signature(s). The
  `claim_signatures.signed_by_key_id → domain_keys(id)` FK can't hold external
  signer keys, so this needs the **append-only peer-key cache** (rotate, never
  delete, so old signatures stay verifiable) and a relaxed/repointed signer
  reference. RPs verify a claim's signatures against the relevant domains' keys
  (via the verifier's IDP), never needing the subject's domain to vouch.
- **Verification endpoint**: the viewer's IDP resolves each signer domain's keys
  (cached) and checks every signature on a claim — the "one click" of §6.
