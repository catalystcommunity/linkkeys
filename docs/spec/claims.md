# Claims

The claim wire format, what a signature covers, and how a claim is verified.

Claims are the only mechanism for conveying human-meaningful information. The
protocol itself deals in identifiers, keys, and signatures; everything a human
would recognize — a name, an age threshold, an organizational role — is a claim.

Which claim types a domain recognizes, who may set them, and when a domain will
release them is **policy**, specified separately in `claim-policy.md`. This
document is the format and verification contract that every verifier must
implement.

Read [`README.md`](README.md) first for status markers and invariants.

## 1. Structure *(Normative)*

| Field | Required | Signed | Meaning |
| --- | --- | --- | --- |
| `claim_id` | yes | yes | Identifies this claim. |
| `user_id` | yes | yes | The subject, at the subject's home domain. |
| `claim_type` | yes | yes | What is being claimed. |
| `claim_value` | yes | yes | Arbitrary bytes. |
| `signatures` | yes | — | One or more signatures (§2). |
| `attested_at` | yes | yes | RFC3339 UTC — when this claim was signed. |
| `created_at` | yes | **no** | Assigned by the holder's storage on insert. |
| `expires_at` | no | yes | RFC3339 UTC. |
| `revoked_at` | no | — | Checked at verification (§4). |

`claim_value` is bytes, not text. It may contain any byte sequence, including
nulls. A verifier MUST NOT assume it is UTF-8 unless the claim type's policy says
so.

`created_at` is deliberately outside the signature: it records when a particular
holder stored the claim, which is a local fact and differs between holders of the
same claim. `attested_at` is the signed, portable time.

`expires_at` and `attested_at` MUST be stored and served **byte-identical** to
what was signed. Both are normalized to whole-second RFC3339 at signing time so
they survive a round trip through storage without changing representation. A
holder that re-renders a timestamp — adding fractional seconds, changing offset
spelling — destroys every signature over that claim.

## 2. What a signature covers *(Normative)*

Each signature covers the deterministic CBOR encoding of this eight-element
tuple:

```
("linkkeys-claim-v1alpha",
 claim_id,
 claim_type,
 claim_value,                    ; as a CBOR byte string
 "{user_id}@{subject_domain}",   ; the full subject identity
 signing_domain,                 ; the attestor for THIS signature
 expires_at,                     ; absent when the claim does not expire
 attested_at)
```

Two bindings in that tuple carry most of its security value.

**The subject is bound as a full identity**, `user_id@subject_domain`, never a
bare `user_id`. An identifier is only unique within its home domain, so without
this a claim about a user at one domain could be replayed as a claim about the
same identifier at another. Neither an identifier nor a domain name contains
`@`, so the separator is unambiguous.

**The signing domain is bound per signature.** Each signature over a claim covers
a payload naming *its own* attestor. This is what prevents a signature produced
by domain A from being presented as domain B's attestation of the same claim.

A consequence worth stating plainly: the payload is **not the same bytes** for
two different signing domains. A verifier MUST reconstruct the payload once per
distinct signing domain, not once per claim.

## 3. Multiple signers *(Normative)*

A claim may carry signatures from more than one domain — the subject's home
domain attesting it holds the claim, and a third party countersigning it. Order
is not significant, and composition is open-ended: any domain may add an
attestation without invalidating existing ones.

### 3.1 The quorum rule

**Every distinct domain that signed the claim MUST contribute at least one
signature from a currently-valid signing key of that domain.**

Within a domain the rule is permissive: that domain is satisfied as soon as one
of its signatures verifies, which is what lets a domain sign with several of its
keys and survive the rotation of any one of them.

Across domains the rule is strict: it is a conjunction, not a disjunction. A
claim bearing signatures from domains A and B is accepted only if *both* verify.

> **Rationale.** The strict reading is the safe one. If any single domain's
> signature sufficed, an attacker could append a signature from a domain the
> verifier happens to trust and have the claim accepted on that basis alone,
> while the presence of the other signatures implied a stronger endorsement than
> was actually checked. Requiring all signers to verify means a claim's apparent
> endorsement and its verified endorsement are the same thing.

### 3.2 Unsigned claims

An empty signature set MUST be rejected. It is not a claim that "nobody vouches
for" — it is not a claim.

### 3.3 Missing keys are not failures

When a verifier lacks the keys for a domain that signed, it MUST distinguish that
outcome from a verification failure, so the caller can fetch the missing keys and
retry. Treating "I could not check this" as "this is invalid" makes claim
verification depend on cache state; treating it as valid is worse.

Claim verification itself performs no I/O. Key resolution happens before it.

## 4. Verification *(Normative — R1)*

To accept a claim, a verifier MUST:

1. Establish `subject_domain` from **authoritative context** — the envelope the
   claim was retrieved from — and never from a field the presenter controls.
   Binding the wrong subject domain defeats §2's replay protection entirely.
2. For each distinct signing domain, reconstruct the payload (§2) for that
   domain and satisfy the quorum rule (§3.1).
3. For each signature counted: the referenced key MUST exist in that domain's
   trusted key set, MUST have usage `sign`, and MUST be currently valid.
4. Reject the claim if `revoked_at` is set.
5. Reject the claim if `expires_at` is in the past. An unparseable `expires_at`
   is a rejection, never a claim that does not expire.

Steps 4 and 5 are separate from the signature check. A caller that needs only the
cryptographic quorum — for instance to decide whether to store a claim it will
evaluate later — may perform steps 1–3 alone, but MUST NOT treat that as
acceptance.

## 5. Revocation is not retroactive *(Normative)*

Per invariant I-7, a signature made while its key was still in good standing
remains trustworthy after that key is revoked.

For a **stored attestation**, a verifier MUST compare the claim's signed
`attested_at` against the signing key's revocation instant:

- `attested_at` strictly before the revocation instant → the signature counts.
- `attested_at` at or after it → the signature MUST NOT count.
- Either timestamp absent or unparseable → the signature MUST NOT count.

The comparison is safe because `attested_at` is inside the signed payload (§2)
and therefore cannot be moved by a presenter.

For a **live or replayable** exchange — a consent grant, a signing request, any
credential whose value is its recency — a verifier MUST reject a revoked key
outright and MUST NOT apply the time-relative rule. There the presenter chooses
which credential to present, so accepting one because it is *dated* before a
revocation would let a holder of compromised key material choose its own
validity.

> **Rationale.** Without this, revoking one compromised key destroys every claim
> that key ever signed. For long-lived attestations — an age threshold, a
> professional credential — routine key hygiene would mean re-issuing history,
> and domains would be pushed toward not rotating keys. The rule that protects
> users from a compromise must not be the rule that punishes them for it.

### 5.1 Structures without a signed attestation time

A claim about a *domain* carries no signed attestation time. Until it does, a
verifier has no tamper-evident instant to compare and MUST reject a revoked
signer outright — the fail-closed reading. This is a known gap, not an intended
asymmetry: the same argument in §5 applies, and the field is what is missing.

## 6. Claim policy

Value types, which claim types a domain recognizes, who may set a value, which
issuers a domain trusts, and the rules governing release to a relying party are
specified in `claim-policy.md`. They are properties of an issuing domain rather
than of the claim format, and a verifier implementing this document needs none of
them to verify a claim it has been given.
