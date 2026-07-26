# The LinkKeys Specification

This directory is the LinkKeys protocol specification. It defines what an
implementation must do to interoperate with other implementations.

It is deliberately **not** documentation for this repository's server. Operator
guides, deployment instructions, and design rationale live elsewhere in `docs/`
and are non-normative. If a statement in this directory conflicts with a
statement outside it, this directory wins.

## Contents

| Document | Covers | State |
| --- | --- | --- |
| [`trust-and-anchors.md`](trust-and-anchors.md) | Anchor discovery, the `DNS-TXT` binding, establishing the trusted key set, pinning policy | Written |
| [`keys.md`](keys.md) | Key kinds and custody, the three-key floor, validity, vouching, revocation certificates and quorum | Written |
| [`reserved/signing-authorities.md`](reserved/signing-authorities.md) | Web of trust | Reserved |
| [`reserved/device-keys.md`](reserved/device-keys.md) | Device and application key enrollment, cascade revocation | Reserved |
| [`reserved/subdomain-hierarchies.md`](reserved/subdomain-hierarchies.md) | Parent/child domain delegation | Reserved |
| [`assertions.md`](assertions.md) | Handshake, negotiation, assertion format, verifier obligations, domain separation | Written |
| [`claims.md`](claims.md) | Claim format, signed payload, multi-signer quorum, verification | Written |
| `claim-policy.md` | Value types, signing lanes, set rules, trusted issuers, release rules | Not yet written |
| `browser-binding.md` | Interactive authorization and consent flow (I2/R2) | Not yet written |
| `local-rp.md` | DNS-less claim-ticket issuance and redemption (I4/R3) | Not yet written |
| `attestation.md` | Third-party claim deposit (I3) | Not yet written |
| `conformance/` | Per-role checklists and the vector index | Not yet written |

## How to read this specification

Every section carries exactly one of three statuses. The status is stated in the
section heading or in a callout immediately beneath it. Statuses are never mixed
within a paragraph — if part of a mechanism is Reserved, that part is a separate
subsection.

| Status | Meaning |
| --- | --- |
| **Normative** | Specified, implemented, and covered by conformance vectors. An implementation that claims the relevant conformance role MUST behave as described. |
| **Reserved** | Designed but not implemented. The design is recorded so implementers do not build themselves into a corner. It WILL change. An implementation MUST NOT rely on it for interoperability and MUST NOT claim conformance to it. |
| **Rationale** | Explanation, motivation, and worked examples. Carries no obligations. |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as described
in RFC 2119.

A section may only be promoted from Reserved to Normative once it has both an
implementation and conformance vectors. "It compiles" is not promotion — an
implemented mechanism with no vectors stays Reserved, because nothing stops a
second implementation from diverging from it silently.

## Actors

LinkKeys defines three actors. An implementation may embody more than one, but
the conformance obligations are separate.

- **Identity Provider (IDP)** — holds a domain's keys, custodies its users'
  keys, and issues assertions about them. Answers for a domain.
- **Relying Party (RP)** — consumes assertions about users from domains other
  than its own, and verifies them. Never issues.
- **Signing Authority** — attests that a domain controls the keys it publishes.
  *Reserved.*

The user's browser, device, and applications are participants but are not
conformance actors: they hold no protocol obligations that a server does not
verify.

## Conformance roles and levels

Conformance is claimed per role. Levels within a role are cumulative — R2
includes R1. Levels across roles are independent: an RP claiming R2 has no IDP
obligations whatsoever.

### Role R — Relying Party (verifier)

| Level | Name | Obligations |
| --- | --- | --- |
| **R1** | Core verification | Anchor discovery and pinning; handshake; assertion verification; CBOR encoding; CSIL-RPC over TCP. |
| **R2** | Browser-facing | R1, plus the interactive redirect/callback flow. Required only if the implementation serves browsers. |
| **R3** | Local RP | R1, plus DNS-less claim-ticket redemption. |

### Role I — Identity Provider (issuer)

| Level | Name | Obligations |
| --- | --- | --- |
| **I1** | Core issuance | Anchor publication; handshake; domain key and revocation service; user key service; assertion issuance and userinfo release. |
| **I2** | Browser-facing | I1, plus the interactive authorization and consent flow, and the message catalog service. Required only if the implementation serves browsers. |
| **I3** | Attestation | I1, plus accepting claims deposited by third-party issuers. |
| **I4** | Local RP | I1, plus local-RP registration, policy, and ticket issuance. |

### Role S — Signing Authority

*Reserved.* No levels defined.

## Invariants

These hold across every level and role. A change to any of them is a protocol
revision, not a feature.

### I-1 — Facade viability *(Normative)*

No normative operation may assume that a LinkKeys implementation is the system
of record for its users. An implementation MUST be able to front an external
directory it does not own and cannot modify — Active Directory, Google
Workspace, LDAP, an existing application database — exposing those accounts as
LinkKeys identities without owning their lifecycle.

This is why user administration and account self-service are outside the
specification (see the classification table): an implementation fronting an
external directory has no such surface, and must still be fully conformant.

### I-2 — Anchor discovery is abstract *(Normative)*

The normative concept is **anchor discovery**: obtaining the authoritative set
of key fingerprints for a domain from a source that speaks for that domain. DNS
TXT records are the first *binding* of that concept, not the concept itself.

Normative text refers to anchor discovery. Only the binding document may name
DNS. Additional bindings may be specified without re-cutting the trust layer,
and an implementation may support more than one.

### I-3 — Pinning is a floor, never replaced *(Normative)*

First-seen pinning of a domain's anchor set establishes the trust baseline.
Higher-assurance mechanisms — signing authorities, out-of-band verification —
raise assurance *on top of* a pin. No mechanism may substitute for the pin or
retroactively excuse a pin violation.

### I-4 — Server-to-server is TCP-first *(Normative)*

Server-to-server traffic — IDP to IDP, RP to IDP — is CSIL-RPC over TCP. HTTPS
is the browser transport. An implementation MUST NOT require HTTPS of a peer
server, and MUST NOT treat an HTTPS-only peer as conformant at R1 or I1.

### I-5 — CBOR is the wire encoding *(Normative)*

CBOR is the encoding in all cases, for every consumer, including browsers.
Signatures are computed over CBOR bytes.

There is no JSON representation of protocol messages, and an implementation MUST
NOT introduce one. A JSON rendering is not signature-preserving: a party
verifying against re-encoded bytes is not verifying the bytes that were signed.
Offering JSON "for convenience" hands implementers a path that appears to work
and is silently unverifiable.

This constrains the protocol, not an implementation's internals. Storing a
message catalog, a database column, a configuration file, or a test fixture as
JSON is not a protocol representation and is unaffected. The rule is about what
crosses the wire and what signatures cover.

### I-6 — Attest, never authorize *(Normative)*

A device or application key proves *origin*. It is never, by itself, the
authority for a privileged action. Authorization is always the domain's signed
assertion.

> The device and application key hierarchy this invariant governs is
> **Reserved**. The invariant is stated here now so that no Normative mechanism
> is designed in a way that would violate it later.

### I-7 — Revocation is timestamped, never retroactive *(Normative)*

Revocation carries a UTC timestamp. Messages verified before that timestamp
remain valid. Messages after it are suspect. The protocol does not invalidate
history, and does not decide what a verifier should do about suspect messages.

### I-8 — Domain separation tags carry an epoch *(Normative)*

Domain-separation tags are suffixed with a protocol epoch, not a per-change
version. Within an epoch, a change to signed content is handled by re-signing,
not by migration.

## Non-goals

Stated so that implementers stop looking for them, and so that proposals adding
them are recognized as out of scope.

- **Device management.** LinkKeys identifies devices; it does not manage them.
  It may integrate with management systems; enrollment is a trust partnership,
  not device control.
- **Reputation.** The primitives make reputation systems buildable. Building one
  is not this specification's job.
- **Solving phishing and social engineering.** Tools that help humans decide are
  in scope. Deciding for them is not.
- **A JSON representation of protocol messages.** There is no JSON encoding of
  any protocol message, at any layer, for any consumer — including browsers. CBOR
  is the encoding, end to end. A JSON rendering would not be signature-preserving
  (invariant I-5), so offering one as a "convenience" would create exactly the
  class of bug that invariant exists to prevent: a party verifying a signature
  over bytes that are not the bytes that were signed. Browsers reach the full
  protocol surface over the same CBOR RPC carrier every other client uses.
- **Legacy algorithm compatibility.** No accommodation for pre-Ed25519/X25519
  systems. Proxying is their operator's problem.
- **Nation-state adversaries as a primary design target.** Geographic
  distribution helps. Beyond that, out of scope.

## Capability classification

Status columns reflect what is *implemented and vector-covered in the reference
implementation today*, not what is intended.

### Protocol services

| Capability | CSIL service | Class | Status | Role/Level |
| --- | --- | --- | --- | --- |
| Version and algorithm negotiation | `Handshake` | Core | Normative | I1, R1 |
| Domain key and revocation service | `DomainKeys` | Core | Normative | I1, R1 |
| User key service | `UserKeys` | Core | Normative | I1 |
| Assertion redemption / userinfo release | `Identity` | Core | Normative | I1, R1 |
| Message catalog | `I18n` | Extension | Normative | I2 |
| Third-party claim deposit | `Attestation` | Extension | Normative | I3 |
| DNS-less claim-ticket redemption | `LocalRp` | Extension | Normative | I4, R3 |
| Domain administration | `Admin` | Out of scope | — | — |
| Account self-service | `Account` | Out of scope | — | — |
| RP verification obligations | `Rp`: `verify-assertion`, `userinfo-fetch` | Core | Normative | R1 |
| RP-server delegation helpers | `Rp`: `sign-request`, `decrypt-token`, `issue-attestation` | Deployment profile | — | — |
| Liveness and readiness | `Ops` | Out of scope | — | — |
| Demo scaffolding | `Hello`, `Guestbook` | Out of scope | — | — |

`Admin` and `Account` are out of scope by invariant I-1, not by omission. The
*concepts* they manipulate — claim types, release rules, trusted issuers,
revocations — are normative data model, specified independently of any
management interface.

`Rp` is a deployment convenience for browser-facing relying parties that hold no
domain key of their own. The onward server-to-server calls it makes are
normative; the delegation surface itself is this implementation's design.

### Mechanisms not expressed as services

| Capability | Class | Status | Notes |
| --- | --- | --- | --- |
| Anchor discovery, `DNS-TXT` binding | Core | Normative | Implemented; conformance vectors exist. |
| First-seen pinning and rotation policy | Core | Normative | Implemented. Single-key rotation accepted; see the trust document. |
| Assertion format and domain separation | Core | Normative | Implemented; epoch-suffixed tags. |
| Claim model, policy, and release rules | Core | Normative | Data model normative; management interface is not. |
| Profiles / presentable pseudonyms | Core | **Reserved** | Implemented, but no conformance vectors. Blocked on vectors, not on design. |
| Browser redirect and consent flow | Extension | Normative | I2, R2. |
| Signing authorities / web of trust | Extension | **Reserved** | No implementation. Raises assurance atop I-3; never replaces it. |
| Device keys, app keys, cascade revocation | Extension | **Reserved** | No implementation. Governed in advance by I-6. |
| Local authenticator agent | Extension | **Reserved** | Distinct from Local RP — see naming note below. |
| Domain migration | Extension | **Reserved** | No implementation. |

> **Naming.** *Local RP* (an installed application acting as its own relying
> party without DNS) and *local authenticator agent* (a user-side process
> holding device keys) are different things that will be confused if they keep
> similar names. The agent must be renamed before it acquires a specification
> page.

## Extraction plan

This specification lives in this repository so that conformance vectors stay
adjacent to the code that generates and consumes them. It is written to be
extracted.

Normative text MUST NOT reference:

- crate, module, or file names from this repository
- build tooling, test commands, or environment variables
- this implementation's database schema, storage choices, or deployment topology
- any language-specific type or API

Where a normative statement needs an example, the example is marked Rationale
and is clearly this implementation's choice rather than an obligation.

**Extraction trigger:** the first independent implementation begins. At that
point this directory moves to its own repository, and conformance vectors move
with it.
