# Application Keys

The application-key wire format, what each signature covers, and how a verifier
decides whether an application key is usable.

An application makes and holds its own key pairs and signs its own messages.
The home domain never holds an application private key and never signs an
application message. The home domain only attests that a public key belongs to
one account, one application, and one application instance, for a short and
renewable period. Home-domain work then scales with key enrollment and
attestation renewal, not with messages or peers.

Operator guidance (configuration, caches, abuse controls, signing cost) is in
[`../application-keys.md`](../application-keys.md). It is non-normative.

Read [`README.md`](README.md) first for status markers and invariants.

## 1. Identity and key kinds *(Normative)*

An application key is bound to one instance, identified by four values:

| Field | Meaning |
| --- | --- |
| `subject_user_id` | The account's one canonical UUID. Never a profile. |
| `subject_domain` | The account's home domain. |
| `application_id` | The application. |
| `instance_id` | One installation of the application. |

A profile is a presentation persona, not a second identity. An application key
MUST NOT attach to a profile.

| `key_usage` | `algorithm` | Purpose |
| --- | --- | --- |
| `sign` | `ed25519` | Signs application messages and quorum signatures. |
| `agree` | `x25519` | Key agreement only. Cannot sign. Never counts toward a quorum. |

A verifier MUST reject a key whose `algorithm` does not match its `key_usage`,
whose public key is not 32 bytes, or whose `fingerprint` does not equal the
fingerprint recomputed from the public key ([`keys.md`](keys.md) §3.2).

All valid keys of one usage are equal. There is no preferred key, and array
order carries no meaning anywhere in this protocol. An application selects any
valid key and names it by `key_id`.

### 1.1 Key count

An instance MUST hold at least two valid signing keys after initial enrollment.
It SHOULD hold at least three. With only two, the keys can authorize an
addition, but neither can be revoked by sibling quorum, because a target never
signs its own revocation (§6).

### 1.2 Invariant I-6

An application key proves origin. It is never, by itself, the authority for a
privileged action (invariant I-6). An attestation states that a key belongs to
an instance. It does not state what that instance may do.

## 2. Signature inputs *(Normative)*

Every signed structure except a revocation is signed over the deterministic
CBOR encoding of a two-element array:

```
[tag, payload]      ; tag: tstr, payload: bstr (the structure's CBOR bytes)
```

| Structure | Tag | Signer |
| --- | --- | --- |
| Attestation | `linkkeys-application-key-attestation-v1alpha` | Home domain signing key |
| Addition (quorum) | `linkkeys-application-key-addition-v1alpha` | Existing application signing keys |
| Possession proof | `linkkeys-application-key-possession-v1alpha` | The new or target key |
| Renewal (sibling) | `linkkeys-application-key-renewal-v1alpha` | Sibling application signing key |
| Revocation (sibling) | `linkkeys-application-key-revocation-v1alpha` | Sibling application signing keys |

The possession tag differs from the addition and renewal tags on purpose. The
same payload bytes are signed by the new or target key, to prove possession,
and by the authorizing keys, to prove authorization. A shared tag would let one
signature be presented as the other. A verifier MUST NOT accept a signature
made under one tag as a signature under another.

A revocation is verified from its fields, not from stored bytes. Its signature
covers the deterministic CBOR encoding of this eight-element array:

```
["linkkeys-application-key-revocation-v1alpha",
 subject_user_id,
 subject_domain,
 application_id,
 instance_id,
 target_key_id,
 target_fingerprint,
 revoked_at]
```

Every identifier is bound, so a revocation cannot move between subjects,
applications, or instances.

## 3. Attestations *(Normative)*

| Field | Meaning |
| --- | --- |
| `subject_user_id`, `subject_domain`, `application_id`, `instance_id` | The instance (§1). |
| `key_id` | The key's identifier within the instance. |
| `key_usage`, `algorithm`, `public_key`, `fingerprint` | The key (§1). |
| `key_created_at`, `key_expires_at` | The life of the key. |
| `attested_at`, `attestation_expires_at` | The life of this proof. |

A `SignedApplicationKeyAttestation` carries the attestation's exact CBOR bytes
and one or more home-domain signatures over them (§2). The home domain MUST
store and serve those bytes verbatim. It MUST NOT re-encode or re-sign on read.

Each key has its own attestation. There is no signed key-set manifest.

The life of an attestation is normally much shorter than the life of the key.
An expired attestation does not revoke the key. It means the verifier has no
current proof and must get a renewed one.

### 3.1 Verifying an attestation

A verifier MUST accept an attestation only if all these are true:

1. The bytes decode as an `ApplicationKeyAttestation`.
2. `subject_domain` equals the domain the verifier expects. The verifier
   supplies this value. It MUST NOT take it from the attestation.
3. The key passes the shape checks in §1.
4. At least one signature is from a signing key of that domain that is valid
   now, and verifies over the attestation signature input (§2).

One valid domain signature is sufficient. The domain's own key set is already
established by its anchor ([`trust-and-anchors.md`](trust-and-anchors.md)).

Whether the attestation is current is a separate decision (§7).

## 4. Proof of possession *(Normative)*

Every key added to an instance, and every key renewed, MUST prove that the
requester holds its private key.

- A **signing key** signs the addition or renewal bytes under the possession
  tag. The result is `possession_proof`.
- An **agreement key** cannot sign. The home domain seals a single-use
  challenge to the claimed X25519 public key. The application opens it and
  returns the plaintext in the request's `challenge` field. A request for an
  agreement key MUST NOT carry `possession_proof`. A verifier MUST reject one
  that does, because a signature proves nothing about an X25519 key.

The sealed challenge is the deterministic CBOR encoding of a four-element
array:

```
[suite, ephemeral_public_key, aead_nonce, ciphertext]
; suite: tstr ("chacha20-poly1305")
; ephemeral_public_key, aead_nonce, ciphertext: bstr
```

It uses the sealed-box construction under `linkkeys-sealed-box-v1alpha`
([`assertions.md`](assertions.md)). The suite is fixed, not negotiated. It is
carried in the encoding so that a change is detectable.

The home domain MUST check that the returned challenge equals the single-use
nonce it issued under `challenge_id`. That check needs server state and is not
part of signature verification.

Proof of possession is one layer of defense. The primary control against a
misattributed agreement key is the key-agreement handshake. A protocol that
uses an agreement key SHOULD bind the attested identity into the handshake
transcript, for example through the Noise prologue or the HPKE `info` string.

## 5. Adding a key *(Normative)*

An `ApplicationKeyAddition` names the instance, the new key, a requested key
lifetime, the challenge, and a request window (`requested_at`, `expires_at`).

A verifier MUST accept an addition only if all these are true:

1. The instance fields equal the expected instance.
2. The new key passes the shape checks in §1.
3. `requested_at` is before `expires_at`, and `now` is inside that window
   within the permitted clock skew.
4. `requested_key_lifetime_seconds` is positive.
5. Possession is proven (§4).
6. At least **two distinct** signing keys of the instance, each valid now,
   signed the addition signature input (§2).

The new key MUST NOT count toward the quorum, even if it appears in the
verifier's key list. A key MUST NOT count twice. A signature from an unknown,
expired, revoked, or agreement key does not count.

Two valid signing keys authorize any new key, signing or agreement.

## 6. Revoking a key *(Normative)*

An `ApplicationKeyRevocation` names the instance, the target key and its
fingerprint, the effective time `revoked_at`, and the signatures.

A verifier MUST accept a revocation only if all these are true:

1. The instance fields equal the expected instance.
2. The target key is known, and its fingerprint equals `target_fingerprint`.
3. At least **two distinct** signing keys of the instance signed the
   revocation payload (§2), each **valid at `revoked_at`**.

The target MUST NOT sign or count toward its own revocation.

Signers are judged at `revoked_at`, not at the verification time. Revocation is
permanent, so the record must stay verifiable after its signers expire or are
rotated out. A signer that was valid when it signed authorized the revocation.

A home domain MUST NOT accept a revocation whose `revoked_at` is later than
`now` plus the permitted skew. A verifier that reads a stored record later does
not re-judge this.

Revocation follows invariant I-7. It is timestamped and never retroactive.

## 7. Renewing an attestation *(Normative)*

Renewal makes a new attestation for the same key. It never makes a new key and
never changes key equality.

An `ApplicationKeyRenewal` names the instance, the target `key_id`, the
challenge, and a request window. A verifier MUST accept a renewal only if all
these are true:

1. The instance fields equal the expected instance, and `key_id` equals the
   target.
2. `now` is inside the request window within the permitted skew.
3. The target is not revoked and is inside its own validity window.
4. For a **signing** target: `possession_proof` verifies with the target key
   over the possession signature input. No sibling signature is required.
5. For an **agreement** target: there is no `possession_proof`, and at least
   **one** sibling signing key, valid now and not the target, signed the
   renewal signature input. Possession is proven by the returned challenge
   (§4).

### 7.1 Idempotent renewal

While the current attestation keeps more than one half of its lifetime, the
home domain SHOULD return the stored attestation bytes and make no new
signature. An application SHOULD renew when less than one half of the lifetime
remains.

This is a load control. It turns the common renewal into a read of stored
bytes, and it absorbs retry storms, restart storms, and clients with a skewed
clock.

## 8. Initial enrollment *(Reserved)*

> **Reserved.** Implemented, with no conformance vectors. An implementation
> MUST NOT rely on this section for interoperability.

Initial enrollment is the only exception to the addition quorum. The account
owner authenticates to the home domain and approves the instance. The request
enrolls at least two signing keys together, and three are recommended. Each key
proves its own possession (§4). Key identifiers MUST be unique within the
request.

After enrollment, the normal quorum rules apply. An instance that loses its
quorum MUST enroll again. A new enrollment is a trust reset, and the home
domain records it.

## 9. Key-set verification *(Reserved)*

> **Reserved.** Implemented, with no conformance vectors. An implementation
> MUST NOT rely on this section for interoperability.

A peer that reads an instance's keys verifies the whole response in this order:

1. Verify every attestation (§3.1). Only attested keys exist for the steps
   that follow.
2. Verify every revocation (§6) against the attested sibling keys.
3. Classify each key at `now`:
   - **Revoked**, if an accepted revocation is effective at or before `now`
     plus skew.
   - **Key expired**, if `key_expires_at` plus skew is at or before `now`.
   - **Attestation expired**, if `attestation_expires_at` plus skew is at or
     before `now`. A renewed attestation can make the key usable again.
   - **Usable**, otherwise.

A bad record does not fail the whole set. The verifier records each rejected
record with its reason. A caller that requires completeness checks that no
record was rejected.

The public read returns every revocation inside a configured look-back window.
It never truncates or paginates revocations, because a partial list would make
a revoked key look valid. The look-back MUST be larger than the maximum key
lifetime plus the maximum attestation lifetime plus the permitted skew.

## 10. Device coupling *(Reserved)*

An application key MAY later be signed by an enrolled device key, to attest
that it runs on that device. See [`reserved/device-keys.md`](reserved/device-keys.md).

## 11. Conformance vectors

The vectors for §2 to §7 are in `sdks/regular-rp/conformance/`. They cover the
attestation, addition, renewal, revocation, and sealed challenge, with positive
and negative cases. `crates/liblinkkeys/tests/application_key_conformance.rs`
verifies them against the reference implementation.
