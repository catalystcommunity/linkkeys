# Subdomain Trust Hierarchies

> **Status: Reserved.** Designed, not implemented. No code, no conformance
> vectors. This WILL change. An implementation MUST NOT rely on anything here for
> interoperability, and no conformance level includes it.
>
> This is intended to become part of the specification. It is Reserved because
> nothing implements it yet, not because its place is in doubt.

## What is already true *(pointer to Normative behavior)*

A subdomain is already a domain. `sub.example.com` publishes its own anchor at
`_linkkeys.sub.example.com`, holds its own signing keys subject to the same
three-key floor, and is discovered, pinned, and verified by exactly the rules in
[`../trust-and-anchors.md`](../trust-and-anchors.md) and
[`../keys.md`](../keys.md). Nothing about a subdomain requires this document
today.

What is missing is any *relationship* between the two. A verifier that trusts
`example.com` learns nothing about `sub.example.com`, and vice versa. They are
unrelated domains that happen to share a name suffix.

## Problem

Two distinct needs, which should not be conflated:

1. **Delegation.** An organization wants `sub.example.com` to be recognizably
   *part of* `example.com` — so that trusting the parent confers some trust in
   the child, and so that a child's compromise is bounded and revocable by the
   parent.
2. **Bootstrapping.** A newly created subdomain wants to be trusted immediately
   by parties that already trust its parent, without waiting for first contact to
   establish a pin.

Need 2 is close to what [`signing-authorities.md`](signing-authorities.md)
addresses generically. Need 1 is not — it is about organizational containment,
which a third-party attestation does not express.

## Sketch

A parent domain signs an assertion binding a child domain's anchor set to itself.
The child publishes that binding; a verifier that already trusts the parent can
accept the child on the strength of it.

Mechanically this reuses the existing primitives: the parent's signing keys, a
domain-separation tag, deterministic CBOR over a canonical tuple, and — almost
certainly — the same two-of-N quorum that governs revocation, so a single
compromised parent key cannot enroll arbitrary subdomains.

## Constraints any implementation must respect

- **Invariant I-3 still holds.** A parent binding raises assurance on top of the
  child's own pin. It does not replace anchor discovery for the child, and does
  not excuse a pin Mismatch on the child.
- **The child keeps its own keys.** A subdomain is not operated with its parent's
  keys, and a parent MUST NOT be able to sign *as* the child. Delegation confers
  recognition, not key material.
- **Suffix relationships are not trust relationships.** An implementation MUST
  NOT infer any trust from name structure alone. `evil.example.com` shares a
  suffix with `example.com` and means nothing without a signed binding. This
  holds today and must survive this mechanism.
- **Delegation must be revocable and bounded in time**, or a compromised child is
  unrecoverable without a parent anchor edit — the same failure the in-protocol
  revocation certificate exists to avoid.

## Open questions

- Whether delegation is one level or transitive, and if transitive, what bounds
  depth. Unbounded transitivity makes the blast radius of a parent compromise
  hard to reason about.
- Whether a verifier trusting a parent should accept children *automatically* or
  only when it has separately expressed interest in the child. Automatic
  acceptance is convenient and is also how a parent compromise becomes an
  internet-wide event.
- Whether this shares a mechanism with [`signing-authorities.md`](signing-authorities.md)
  — a parent is arguably just an authority the child's namespace implies — or
  whether organizational containment needs semantics an authority cannot express.
- How a parent revokes a delegation, and whether a child can decline or exit one.
  A subdomain operator who loses control of the parent should not thereby lose
  their identity.
- Interaction with domain migration: whether moving out from under a parent is
  migration, delegation revocation, or both.
