# Claim endorsements and shareable signing requests (design)

> **Status: Design, decisions settled (§8).** Not implemented. Non-normative.
> The protocol parts go into `spec/claims.md` (as a Reserved section) and the
> not-yet-written `spec/attestation.md`.

## 1. Goals

- **Endorsement:** a user signs another user's claim. "Alice confirms that Bob
  is a real person."
- **Attestation by an authorized user:** a user with the right relation makes
  their *domain* sign another user's claim. "A DMV clerk makes `dmv.example`
  sign Bob's `age_over_21`."
- One **link** starts both. Bob sends a link. Alice opens it, reviews, signs.
- User keys stay, and they get a real job: they make endorsements.
- Social disputes ("who at your domain signed this?") get signed evidence.

## 2. What exists now

| Item | State |
| --- | --- |
| User keys | Built at user creation: three Ed25519 keys (2, 3, 4 year life), private halves encrypted under the domain passphrase. Served by `GetUserKeys` over TCP. **The private halves are never used.** Signing user keys carry no domain vouch. |
| Attested claims (lane C) | Built. `SigningRequest` (home-domain-signed, addressed to one `issuer_domain`). The issuer operator pastes the base64 text in the browser app (`BrowserIssuer` inspect/issue). The issuer signs with its **domain** keys and deposits to the subject's domain over TCP, or hands back a code. |
| Who may issue | `issue_claims` relation on a `claim_type`, or `manage_claims` on the domain. |
| Receiving gate | `trusted_issuers (claim_type, issuer_domain)`. The issuer signature is kept and shown (`claim-trust-verification.md` §4). |
| Transport | Copy/paste or QR of base64. No link. No request status. No record at the requester's domain. |
| Operator record | None. The issued claim says "domain X". No record of which operator at X did it, at either domain. |

So the "domain signs on a user's word" half exists in rough form. The "user
signs" half does not exist.

## 3. Two kinds of confirmation

| | Endorsement | Attestation |
| --- | --- | --- |
| Statement | "`alice@A` confirms this." | "Domain `A` confirms this." |
| Signed with | Alice's user key, vouched by domain A | Domain A's signing keys |
| Weight comes from | The person | The institution |
| Who may make it | Any user of A (domain policy may limit) | Users with `issue_claims` on the type |
| Value | Bob proposes it. Alice confirms the exact value. | The issuer decides the value. |
| Admission at Bob's domain | Must answer a live request. Not gated on `trusted_issuers`. | Must answer a live request. Gated on `trusted_issuers`, as now. |
| Who did it | The endorser, in the signed record. | The operator, in a signed audit entry (§5.1). |

The rule holds for both: **a user signing a claim is the domain signing the
user's verification.** For an endorsement the domain signs once, ahead of time,
by vouching the user key. For an attestation the domain signs each claim, and
signs an audit entry that names the operator.

## 4. Endorsement format

### 4.1 User-key vouch

Domain A signs, with a signing key, the deterministic CBOR of:

```
["linkkeys-user-key-vouch-v1alpha", user_id@A, key_id, fingerprint, key_expires_at]
```

This is the encryption-key vouch pattern (`keys.md` §4), bound to the user.
`UserPublicKey` already has `? signed_by_key_id` and `? key_signature`; signing
keys start to fill them too. A startup repair vouches the existing user keys
(upgrades are automatic), provisions keys for any account that has none, and
rotates keys before they expire.

### 4.2 The endorsement

```
ClaimEndorsement = {
  endorsement_id,
  subject: user_id@subject_domain,
  claim_type, claim_value,
  endorser_user_id, endorser_domain,
  ? endorser_handle,               ; stated by the endorser's domain (§4.3)
  ? endorser_login_id,             ; stated by the endorser's domain (§4.3)
  endorser_key: UserPublicKey,     ; includes the domain vouch, so the record is portable
  request_id,                      ; the request this answers
  attested_at, ? expires_at,
  signature                        ; endorser user key
}
```

Tag: `linkkeys-claim-endorsement-v1alpha`. The signature binds every field
above it.

It binds the **value**, not the `claim_id`. Bob's domain re-signs claims on
upgrade and makes a new `claim_id` when the value changes. An endorsement of
the same value survives a re-sign. An endorsement of an old value stops
matching the new value, which is correct.

Verification needs only domain A's pinned keys: anchor → vouch → endorser key →
signature. Key expiry and revocation follow I-7. `liblinkkeys::endorsement`
holds the payload builder and verifier.

### 4.3 Endorser identifiers

`endorser_handle` and `endorser_login_id` are optional. The endorser's domain
puts one in only when the request's responder policy names users by that kind
of identifier (§6.2), so an endorser does not reveal more than the match needs.
The review page tells Alice which identifier will be included.

They are inside the user-key signature. The endorser's domain custodies the user
key, so the domain is the party that states them. That is the same trust as the
signature itself.

A handle can change between request and answer. Then the match fails, and Bob
must update the request. Matching by UUID never has that problem.

### 4.4 Release and display

Bob's domain stores endorsements next to the claim. When it releases the claim
to an RP, it releases the matching endorsements with it. No new consent: the
endorsement is about a claim the user already chose to release. `UserInfo`
claims gain `? endorsements: [* ClaimEndorsement]`.

The RP shows "confirmed by …" with, in this order:

1. `endorser_handle@endorser_domain`, if the record carries it;
2. the endorser's handle, if the endorser's domain releases it publicly;
3. `endorser_user_id@endorser_domain`.

## 5. Attestation polish

Attestation stays a lane-C `Claim` signed by domain keys. The claim payload does
not change.

### 5.1 Signed audit entry

The issuing domain writes an audit entry for each attestation, signs it with
its domain keys, and sends it to the subject's domain with the claim.

```
AttestationAuditEntry = {
  entry_id,
  claim_id, claim_type,
  subject: user_id@subject_domain,
  issuer_domain,
  operator_user_id,
  ? operator_handle,
  request_id,
  issued_at
}
SignedAttestationAuditEntry = { entry: bytes, signatures: [* ClaimSignature] }
```

Tag: `linkkeys-attestation-audit-v1alpha`.

- The issuer keeps the entry in its own audit log.
- `DepositClaimRequest` gains `? audit: SignedAttestationAuditEntry`. The
  subject's domain checks the issuer's signatures and that `claim_id`,
  `claim_type`, and subject match the deposited claim, then stores the entry in
  its own audit log, verbatim.
- The subject's domain does not re-sign it. The issuer's signature is the
  evidence. Anyone who gets the entry can check it against the issuer's pinned
  keys.
- The subject and the subject's admins can see it ("`clerk-7` at `dmv.example`
  signed this"). It is not released to RPs with the claim. The claim's weight is
  the domain; the entry is for resolving disputes.

A domain that sends no audit entry is still conformant for deposit. The subject's
domain MAY refuse attestations without one, by its own policy.

### 5.2 Other changes

- **Same entry point.** The link flow in §6 leads to the same review page. If
  Alice holds `issue_claims` for the type, the page offers "Confirm as
  yourself" and "Confirm as `A`".
- **Same-domain case.** When issuer and subject are on one domain, deposit is a
  local write. The audit entry is still made and signed.

## 6. Shareable requests (the link)

### 6.1 Request record

Bob makes a request on his home domain. The domain stores it and signs it.

`SigningRequest` changes:

| Field | Change |
| --- | --- |
| `kind` | New: `endorse`, `attest`, or `either`. |
| `issuer_domain` | Becomes optional. Absent = open request. |
| `? responder_policy` | New: who may answer (§6.2). Absent = anyone. |
| `? proposed_values` | New: the values Bob asks to confirm (needed for `endorse`). |
| `max_responses` | New: how many answers the request takes. Default 10 for an open request, 1 for a request to one person. |

Bob's domain tracks status: pending, answered (by whom, how many), expired,
withdrawn.

### 6.2 Responder policy (advanced options)

The simple form is "anyone with the link, up to N answers". Under **Advanced
options**, Bob can limit who may answer:

| Rule | Matches |
| --- | --- |
| `domain: A` | Any user at domain A. |
| `user: <uuid>@A` | That account. Exact. |
| `user: handle:<handle>@A` | The account whose endorsement states that handle. |
| `user: login:<login_id>@A` | The account whose endorsement states that login id. |

A policy is a list of rules; an answer must match one. For an attestation,
`domain: A` is the useful rule ("only `dmv.example` may answer").

Bob's domain checks the policy at deposit. It matches UUID rules against
`endorser_user_id`, handle and login rules against the identifiers in the
signed endorsement (§4.3), and domain rules against `endorser_domain` or
`issuer_domain`. No resolve call to another domain is needed.

The policy is inside the signed request, so the answering domain can see it and
include the right identifier.

### 6.3 Link and hand-off

```
https://<bob-home>/r/<request_id>
```

1. Alice opens the link. Bob's domain shows what Bob asks, and "Open in my
   LinkKeys".
2. Alice enters her handle or domain. If the policy names one domain, the page
   goes there directly.
3. The browser goes to `https://<alice-home>/app/confirm#<signed request>`. The
   request is in the URL fragment, so it does not go into server logs.
4. Alice's domain checks the request against Bob's domain's pinned keys. Alice
   signs in, reviews, and confirms or declines. If the policy cannot match her,
   the page says so before she signs.
5. Alice's domain signs (endorsement, or attestation + audit entry) and
   deposits to Bob's domain over TCP: `deposit-endorsement`, or `deposit-claim`
   with the audit entry. Both carry `request_id`.
6. If the deposit fails, Alice gets a code to send to Bob, as now.

A QR code carries the same link. Paste of the bare base64 still works.

No phone-home: Alice's domain talks to Bob's domain once, to deposit. Bob's
domain does not call Alice's.

### 6.4 Gate at Bob's domain

- A deposit must name a live `request_id` of the subject, match its
  `responder_policy`, and fit in `max_responses`. Otherwise it is rejected.
- An endorsement must match a claim Bob holds, or a value he proposed.
- **Unsolicited deposits are rejected.** The server emits an event
  `endorsement.unsolicited` (subject, endorser, claim type, time; no claim
  value) through an event-emitter seam that does nothing by default. A later
  system can use it to host an inbox. The inbox protocol is out of scope.

### 6.5 Endorser-side policy

At Alice's domain:

- Domain toggle `allow_user_endorsements` (default on).
- Optional per-claim-type deny list (a domain may forbid its users to endorse
  `age_over_21`).
- Rate limit per user per day.

## 7. CSIL changes (outline)

- `UserPublicKey`: vouch fields documented for signing keys (no shape change).
- New `ClaimEndorsement`, `DepositEndorsementRequest/Response`.
- New `AttestationAuditEntry`, `SignedAttestationAuditEntry`;
  `DepositClaimRequest` gains `? audit`.
- `SigningRequest`: `kind`, optional `issuer_domain`, `responder_policy`,
  `proposed_values`, `max_responses`. New `ResponderRule`.
- `Account`: `create-signing-request`, `list-my-signing-requests`,
  `withdraw-signing-request`, `list-my-endorsements`, `remove-endorsement`,
  `list-attestation-audit` (for claims about me).
- `Browser`: `inspect-confirm-request`, `complete-confirm-request` (one review
  page for both kinds; replaces `BrowserIssuer` inspect/issue).
- Domain service (TCP): `deposit-endorsement`.

## 8. Decisions (settled 2026-11-14)

| # | Question | Decision | Trade-off accepted |
| --- | --- | --- | --- |
| E1 | What signs an endorsement | Endorser's user key; the domain vouches the user key once. §4.1. | A vouch format, a startup repair, and a three-step verify chain. |
| E2 | Shape | Separate `ClaimEndorsement`, bound to the value. §4.2. | A new type, table, and release path. |
| E3 | Open links | Open, up to N answers. Advanced responder policy: any user at a domain, or a list of users by UUID, handle, or login id. §6.1, §6.2. | An open request can be answered by anyone with the link until it expires or reaches N. |
| E3a | Matching a handle or login id | The endorser's domain states it inside the signed endorsement. §4.3. | The endorser reveals that identifier to Bob's domain; a handle change before the answer breaks the match. |
| E4 | Unsolicited endorsements | Rejected. Stub event `endorsement.unsolicited` for a future inbox system. §6.4. | No spontaneous vouching until that system exists. |
| E5 | Display name | Stated handle, else public handle, else UUID. §4.4. | Endorsers with private handles show as UUIDs. |
| E6 | Operator of an attestation | Issuer signs an audit entry and sends it with the claim; the subject's domain stores it verbatim. Not released to RPs. §5.1. | Staff identity is visible to the subject and the subject's admins. |

## 9. Plan

| Phase | Work |
| --- | --- |
| **P1 — user keys** | Vouch payload in `liblinkkeys` + vectors. Startup repair: vouch existing user signing keys; provision keys for accounts with none; rotate before expiry. `GetUserKeys` serves vouches. |
| **P2 — endorsements** | `liblinkkeys::endorsement` + vectors. CSIL types; regenerate. Table `claim_endorsements` (both backends). `deposit-endorsement`. Release with claims. |
| **P3 — requests and links** | `SigningRequest` fields and `responder_policy` matching in `liblinkkeys` (pure). `signing_requests` table at the requester. `/r/<id>` landing page, `/app/confirm` review page (endorse or attest), deposit with `request_id`, status. Event-emitter seam + `endorsement.unsolicited` stub. QR. |
| **P4 — attestation audit** | `AttestationAuditEntry` + vectors. Audit tables at issuer and subject. `deposit-claim` with `audit`. Same-domain local deposit. Retire the paste-only `BrowserIssuer` screens behind the review page. |
| **P5 — RP side** | RP SDKs verify and expose endorsements (Go and TypeScript first). Web UI shows "confirmed by" and, for the subject, "signed by `operator` at `issuer`". |
