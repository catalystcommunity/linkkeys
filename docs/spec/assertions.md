# Handshake and Identity Assertions

Negotiation, the identity assertion format, and — the part that carries the most
weight — what a verifier is obliged to check.

Read [`README.md`](README.md) first for status markers and invariants.

## 1. Handshake *(Normative — I1, R1)*

Handshake establishes which protocol version and which algorithms both sides
support. It is called before any other operation.

**Request** carries the caller's protocol version and its advertised algorithms:
a list of signing algorithms, and optionally a list of AEAD suites.

**Response** carries the responder's protocol version and the negotiated
algorithms.

The current protocol version is `v1alpha`.

### 1.1 Negotiation rules

For signing algorithms, the responder MUST reply with the intersection of the
caller's advertised list and its own support.

For AEAD suites:

- When the caller advertises a list, the responder MUST reply with the
  intersection. It MUST NOT name a suite the caller did not advertise.
- When the caller omits the list entirely, the responder MUST reply with its own
  full supported set.

An absent list MUST NOT be read as "supports nothing." A caller that has not
opted into suite negotiation, or predates it, sends nothing — and a responder
that answered with an empty set would prevent that caller from ever discovering
what is available. Omission means "unstated," and the responder answers by
disclosing its own capability.

An empty intersection is a valid response. It means no common algorithm exists,
and the caller MUST NOT proceed by guessing.

> **Rationale.** Negotiating from the first message is what makes the protocol
> evolvable across deployments nobody controls. The asymmetry between "advertised
> nothing" and "advertised an empty list" is deliberate: the first is a caller
> that does not know about the field, the second is a caller that knows and
> supports none.

## 2. The identity assertion *(Normative)*

An assertion is a domain's signed statement that a user authenticated to it, made
for one specific audience.

| Field | Required | Meaning |
| --- | --- | --- |
| `user_id` | yes | The subject's identifier at the issuing domain. |
| `domain` | yes | The issuing domain. `user_id@domain` is the full identity. |
| `audience` | yes | The single relying party this assertion is for. |
| `nonce` | yes | Binds the assertion to one specific request. |
| `issued_at` | yes | RFC3339 UTC. |
| `expires_at` | yes | RFC3339 UTC. |
| `authorized_claims` | yes | Claim types this redemption may release. |
| `display_name` | no | Convenience only; carries no authority. |

### 2.1 `authorized_claims` is fail-closed

`authorized_claims` is the effective set of claim types the redemption may
release, as resolved by the user's consent together with the issuing domain's
policy. It is required, and an empty list releases nothing.

A userinfo response MUST be scoped to exactly this set. An implementation MUST
NOT treat an absent or empty list as "no restriction" — that inversion turns a
consent failure into a full disclosure.

### 2.2 Signed envelope

The signed form carries three fields: the assertion as **raw CBOR bytes**, the
identifier of the signing key, and the signature.

The signature covers exactly the bytes carried in the assertion field.

A verifier MUST verify the signature over the bytes **as received**, and only
then decode them. It MUST NOT decode first and verify against a re-encoded form.
Re-encoding is not guaranteed to reproduce the signed bytes, and a verifier that
does it is checking a signature over something other than what was signed.

## 3. Verifier obligations *(Normative — R1)*

Signature validity is necessary and **not sufficient**. A verifier MUST perform
all of the following before acting on an assertion. Omitting any one of them
leaves an exploitable gap, noted per step.

1. **Resolve the signing key** from the issuing domain's trusted key set, as
   established in [`trust-and-anchors.md`](trust-and-anchors.md). A key that is
   not in the trusted set MUST be rejected, never fetched-and-trusted inline.
2. **Require signing usage.** The resolved key's usage MUST be `sign`. An
   encryption key that happens to share an identifier MUST NOT be accepted as a
   signer, independently of whether the algorithm would have failed anyway.
3. **Require key validity.** The key MUST NOT be revoked or expired. A key whose
   expiry cannot be parsed is invalid, never non-expiring.
4. **Verify the signature** over the received bytes (§2.2).
5. **Decode** the assertion.
6. **Check expiry.** An assertion past `expires_at` MUST be rejected.
7. **Check the audience.** The `audience` MUST identify this verifier. *Skipping
   this accepts assertions minted for a different relying party* — the single
   most damaging omission available here, because a hostile relying party can
   replay assertions it legitimately received.
8. **Check the nonce.** It MUST correspond to an outstanding request from this
   verifier, and MUST be single-use. *Skipping this permits replay of a
   previously valid assertion.*
9. **Check the issuing domain** is the domain the verifier expected to
   authenticate this user.

> **Implementation note (Rationale).** Steps 1–6 are naturally a library
> concern; 7–9 depend on request context a verification routine does not have.
> That split is an implementation convenience and changes nothing about the
> obligation: an implementation that performs only 1–6 is not conformant at R1.
> A verification routine that cannot check audience and nonce SHOULD make that
> gap explicit to its caller rather than appearing complete.

## 4. Domain separation

### 4.1 The rule *(Normative)*

Signed payloads throughout this protocol are constructed as a deterministic CBOR
tuple whose first element is a domain-separation tag identifying what is being
signed. Tags carry a protocol epoch suffix (invariant I-8), currently
`-v1alpha`. Within an epoch, changes to signed structures are handled by
re-signing rather than migration.

Current tags:

| Tag | Signs |
| --- | --- |
| `linkkeys-identity-assertion-v1alpha` | An identity assertion (§4.2) |
| `linkkeys-claim-v1alpha` | A claim ([`claims.md`](claims.md)) |
| `linkkeys-domain-claim-v1alpha` | A claim about a domain |
| `linkkeys-key-revocation-v1alpha` | A key revocation certificate |
| `linkkeys-key-vouch-v1alpha` | A signing key's vouch for an encryption key |
| `linkkeys-consent-v1alpha` | A consent grant |
| `linkkeys-signing-request-v1alpha` | A signing request |
| `linkkeys-sealed-box-v1alpha` | A sealed box |
| `linkkeys-local-rp-descriptor-v1alpha` | A local-RP descriptor (see `local-rp.md`) |
| `linkkeys-local-rp-login-request-v1alpha` | A local-RP login request |
| `linkkeys-local-rp-callback-v1alpha` | A local-RP callback payload |
| `linkkeys-local-rp-ticket-redemption-v1alpha` | A local-RP claim-ticket redemption |
| `linkkeys-local-rp-callback-box-v1alpha` | The local-RP callback sealed box (KDF context, not a signature payload) |

Every tag carries the epoch suffix without exception. The last five are envelope
context strings and a key-derivation context rather than signature payload
prefixes, but they are epoch-pinned on the same rule: they participate in
constructions whose meaning must not silently change across an epoch boundary.

> **Implementers porting between languages:** `linkkeys-local-rp-callback-v1alpha`
> is a proper prefix of nothing, but the *unsuffixed* form
> `linkkeys-local-rp-callback` is a prefix of `linkkeys-local-rp-callback-box`.
> Any tooling that rewrites these strings must match the longest form first or it
> will corrupt the box tag.

### 4.2 The assertion payload *(Normative)*

An assertion signature covers the deterministic CBOR encoding of this
two-element array:

```
("linkkeys-identity-assertion-v1alpha", assertion_bytes)
```

where `assertion_bytes` is a CBOR **byte string** holding the assertion's own
CBOR encoding — the same bytes carried in the envelope's assertion field.

The assertion is embedded opaquely rather than re-encoded structurally, so that
a verifier signs and checks over the exact bytes it received (§2.2). An
implementation MUST NOT decode the assertion and rebuild the payload from the
decoded form.

> **Rationale.** Two-element `(tag, opaque bytes)` rather than the flat tagged
> tuple used elsewhere: the assertion is already a self-contained CBOR structure,
> and flattening its fields into the signature payload would force the verifier
> to re-encode in order to check — reintroducing precisely the mismatch §2.2
> forbids.
