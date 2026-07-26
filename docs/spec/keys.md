# Keys

The key model: what keys exist, what makes one valid, and how one is retired.

Read [`README.md`](README.md) first for the status markers and invariants.
Discovery and pinning of the domain key set is in
[`trust-and-anchors.md`](trust-and-anchors.md).

## 1. Key kinds *(Normative)*

| Kind | Held by | Purpose |
| --- | --- | --- |
| Domain signing key | The domain | Root of trust. Signs assertions, claims, vouches, and revocations. Published in the anchor. |
| Domain encryption key | The domain | Receives encrypted material. Not published in the anchor; vouched by a signing key. |
| User key | Custodied by the domain | Represents an identity at that domain. Never leaves the domain's custody. |

Device and application keys are **Reserved** (§6).

### 1.1 Custody

User private keys are custodied by the domain and are never stored unencrypted.
A user's key material never leaves the domain's custody, which is what makes a
lost device an inconvenience rather than an identity loss.

Custody is a trust relationship, not a technical guarantee. The domain
administrator is a custodian. This specification provides mechanisms that
constrain a custodian (revocation quorums, §5); it does not and cannot prevent a
custodian from acting within their custody.

> **Rationale.** This is the same trust a user already extends to an email
> provider, with better tooling for accountability. The escape valve is that
> self-hosting is achievable and migration is possible — neither of which is a
> cryptographic property.

## 2. The three-key floor *(Normative)*

A domain MUST publish at least three signing keys. They are equal peers: no key
holds a role the others do not, and any key may participate in any operation for
which a signing key is eligible.

This is a hard minimum, not a recommendation, because **revocation is impossible
below it**. Revoking a key requires a quorum of two *distinct* signing keys of
the domain, and the key being revoked may never count toward the quorum (§5). A
domain with two keys therefore cannot revoke either one: removing the target
leaves exactly one eligible signer, and the quorum can never be met. A
compromised key would remain authoritative until the anchor itself is edited,
which is precisely the slow, out-of-band path that in-protocol revocation exists
to avoid.

The floor also underwrites the pin rotation policy — see
[`trust-and-anchors.md`](trust-and-anchors.md) §4.2.

Three is a floor, not a target. A domain MAY publish more, and distributing keys
across separate hosts or locations is a deployment decision this specification
does not constrain.

## 3. Key properties *(Normative)*

### 3.1 Algorithms

Signing is Ed25519. Encryption is X25519. Authenticated encryption is
`aes-256-gcm` or `chacha20-poly1305`.

Algorithm identifiers are carried explicitly on the wire and negotiated at
handshake. An implementation MUST NOT infer an algorithm from key length or
context, and MUST reject a key whose stated algorithm it does not support rather
than attempting a fallback.

There is no accommodation for algorithms outside this set. See the non-goals in
[`README.md`](README.md).

### 3.2 Fingerprints

A key's fingerprint is the SHA-256 digest of its public key bytes, rendered as
64 lowercase hexadecimal characters. Comparison is case-insensitive.

A fingerprint transmitted alongside a key is informational only. Any decision
that depends on a fingerprint MUST recompute it from the key's public key bytes.
See [`trust-and-anchors.md`](trust-and-anchors.md) §3.1.

### 3.3 Validity

A signing key is **valid** only if it is neither expired nor revoked.

- **Expiry** is an explicit timestamp on the key. A key whose expiry cannot be
  parsed MUST be treated as invalid — never as non-expiring.
- **Revocation** is an explicit timestamp (§5).

An implementation MUST evaluate validity at the moment of use. A key that was
valid when a session began is not thereby valid for the rest of it.

### 3.4 Ephemerality

Keys are intended to be short-lived. Rotation and revocation are ordinary
operations, not incidents, and an implementation MUST NOT treat either as an
error state.

Verifying old material does not require the key to still be valid — it requires
the public key as it existed when the material was signed, together with the
knowledge that trust held at that time. Caching public keys is therefore
encouraged, and third-party archives of historical public keys are a legitimate
thing to build. Nothing in this specification depends on such an archive
existing.

## 4. Vouching *(Normative)*

A signing key vouches for an encryption key by signing the deterministic CBOR
encoding of:

```
("linkkeys-key-vouch-v1alpha", {encryption key fingerprint}, {encryption key expiry})
```

The full acceptance rule is in [`trust-and-anchors.md`](trust-and-anchors.md)
§3.2. The property that matters here: a vouch binds the encryption key's
*identity and lifetime* together, so an encryption key cannot be silently
extended beyond what its voucher signed, and cannot outlive the trust of its
voucher.

## 5. Revocation *(Normative)*

### 5.1 Sibling-signed certificates

A revocation certificate is a portable, verifiable statement that a specific key
is revoked as of a specific instant. It is verifiable by any party that holds the
domain's pinned key set, without waiting for an anchor edit to propagate.

A certificate carries the target key's identifier, the target's fingerprint, the
revocation instant, and one or more signatures.

Each signature covers the deterministic CBOR encoding of the five-element tuple:

```
("linkkeys-key-revocation-v1alpha",
 {target key id}, {target fingerprint}, {revoked at}, {signing key's domain})
```

The signing domain is bound **per signature**, which is what prevents a
signature from being replayed under a different domain's identity.

### 5.2 Quorum

To accept a revocation certificate, an implementation MUST count signatures that
satisfy all of:

- the signature verifies over the canonical payload above;
- the signing key belongs to the domain in question and is **currently valid**;
- the signing key is **not** the target of the revocation;
- the signature's bound domain matches the domain being verified.

Distinct signing keys are counted once each. The certificate is accepted only if
**at least two distinct** such keys signed it. Otherwise it MUST be rejected.

A key may never authorize its own revocation. An implementation MUST enforce this
during verification and MUST NOT rely on the certificate's producer having
omitted the target.

> **Rationale.** The quorum is what makes revocation resistant to a single
> compromised key. An attacker holding one domain key cannot revoke the honest
> keys out from under the domain, and cannot un-revoke themselves. It is also the
> direct reason for the three-key floor (§2).

### 5.3 Temporal semantics

Revocation carries a UTC instant. Per invariant I-7, material verified as of
before that instant remains valid; material after it is suspect. Revocation is
never retroactive.

This specification does not define what a verifier should do with suspect
material. That is a human decision, and implementations MUST surface it as one
rather than silently choosing.

### 5.4 Effect on cached keys

When a key is retired — by an accepted revocation certificate, or by
disappearing from the anchor under the pin rotation rule — an implementation MUST
stop honoring any cached copy of it for subsequent verification.

## 6. Device and application keys *(Reserved)*

> **Reserved.** Not implemented. Will change. MUST NOT be relied on for
> interoperability, and no conformance level includes it.

The intent is that device and application keys are **not** owned by the user key.
They are independent primitives that *enroll* into a partnership with a domain,
in the way a workstation joins a directory. A device key represents that device;
it is associated with a user through enrollment, not possessed by them.

Invariant I-6 governs this material in advance: such a key proves **origin**, and
is never by itself the authority for a privileged action. Authorization remains
the domain's signed assertion. The invariant is Normative today precisely so that
no mechanism specified before this section is built gets designed in a way that
would violate it.

Design sketch in [`reserved/device-keys.md`](reserved/device-keys.md).
