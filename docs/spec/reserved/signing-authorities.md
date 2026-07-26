# Signing Authorities / Web of Trust

> **Status: Reserved.** Designed, not implemented. No code, no conformance
> vectors. This WILL change. An implementation MUST NOT rely on anything here for
> interoperability, and no conformance level includes it.
>
> Recorded so that Normative mechanisms are not designed in ways that would
> foreclose it.

## Problem

Anchor discovery plus pinning (see [`../trust-and-anchors.md`](../trust-and-anchors.md))
establishes trust on first contact. It does not help a verifier that has never
contacted a domain and wants assurance *before* first contact.

## Sketch

A signing authority attests that a domain controls the keys it publishes.
Anyone may operate one; the intent is several, geographically distributed, with
at least one free instance.

**Signing:**

1. The authority reads the domain's published anchor.
2. The authority validates that the domain controls the private keys matching
   those fingerprints, by challenge or by verifying a signed message. A further
   binding-level challenge may be used for stronger assurance.
3. The authority signs each of the domain's keys with each of its own keys.
4. The domain publishes those signatures, referenced to the authority's domain,
   separately from its own anchor record.

**Verification:**

1. The verifier encounters an unpinned domain.
2. The verifier discovers the domain's anchor and connects on that basis.
3. The verifier asks which authorities have signed for the domain.
4. If the verifier already trusts any named authority, it retrieves the
   corresponding signatures and validates them against that authority's keys —
   cached, or freshly discovered.
5. Signing timestamps determine freshness. The verifier decides its own staleness
   threshold. Suggested starting point: re-sign monthly, accept for ~3 months.

## Constraints any implementation must respect

- **Invariant I-3 is not negotiable.** This raises assurance *on top of* a pin.
  It never substitutes for pinning and never excuses a pin Mismatch
  retroactively. A domain failing its pin check is refused no matter who has
  signed for it.
- **No gatekeeping.** Structurally similar to certificate authorities, minus
  mandatory payment and minus a fixed root set. Anyone may be an authority;
  trust in one is earned socially, not purchased. Paid or credentialed
  attestation may exist for specific claim types — that is a social arrangement
  layered on the same mechanism, not a change to it.
- **Freshness is the verifier's call.** This specification will not mandate a
  re-verification interval.

## Open questions

- How authorities are named and discovered, and whether that reuses the anchor
  binding or needs its own.
- Whether authority signatures are published by the domain (as sketched) or
  served by the authority, and what that implies for availability.
- Revocation of an authority's own attestation, and whether the two-of-N quorum
  from `keys.md` §5 applies to authorities.
- Whether parent/child domain delegation is this mechanism or a distinct one.
  Tracked separately in [`subdomain-hierarchies.md`](subdomain-hierarchies.md),
  which argues organizational containment may need semantics a third-party
  attestation cannot express.
