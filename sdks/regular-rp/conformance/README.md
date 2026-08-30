# Application keys — conformance vectors

This directory is the shared test suite for the application-key protocol
(signing-things-request.md) in every LinkKeys SDK, in every language. It is
generated once from the Rust `liblinkkeys` implementation
(`crates/liblinkkeys/src/application_keys.rs`) and checked into every SDK's
test run unchanged. If your SDK passes every case (positive AND negative) in
every file here, its wire constructions and verification rules are
conformant.

Application keys are a **regular-RP** concern: an application instance (e.g.
Tinku) enrolls, renews, and revokes its own signing/key-agreement keys through
its regular RP, and any RP (including a DNS-less one) reads and verifies
attestations anonymously. That is why these vectors live in a sibling
directory to `sdks/local-rp/conformance/` rather than inside it — the two
protocols are independent and this directory does not depend on that one.

**Authority**: `signing-things-request.md` at the repo root is the normative
design document. This README describes the JSON schema of the vectors; the
design doc is the source of truth for *why* the rules are the way they are.
If the two ever disagree, the design doc and `application_keys.rs` win and
this file (or the generator) has a bug.

**Consumer zero**: `crates/liblinkkeys/tests/application_key_conformance.rs`
reads these same files and verifies every case against the real Rust
implementation, as part of the normal `cargo test -p liblinkkeys` run. That
test is the best worked example of "how to consume these vectors" available,
independent of language.

## Conventions used throughout

- **Hex fields** (any key ending `_hex`) are lowercase hex, no `0x` prefix,
  no separators — decode with any standard hex decoder.
- Every case that is expected to fail carries `"expected_valid": false` and
  lives under `negative_cases[]` (never `cases[]`). Your SDK's assertion
  should simply be: attempt the operation, check whether it succeeded, and
  require that outcome to match `expected_valid`. Exact error *types* are
  intentionally not part of the contract — only pass/fail is portable.
- All key material in every file is **fixed, publicly-known, test-only**.
  The seeds are literally repeated-byte constants (e.g. 32 bytes of `0x01`).
  Never reuse any key from this directory for anything real.
- All timestamps are fixed RFC3339 constants baked into the generator, not
  wall-clock time — **except** domain signing key expiry, which the Rust
  implementation deliberately checks against wall-clock time
  (`crypto::signing_key_validity`, via `assertions::check_signing_key_valid`)
  rather than an injected `now`. Domain signing keys in these vectors
  therefore carry a far-future `expires_at` (year 2126) so the vectors do
  not go stale. Application key (`ApplicationKeyRef`) validity, by contrast,
  IS checked against an explicit injected `now` everywhere — that `now` and
  its `skew_seconds` are published alongside each case that needs them.
- Regenerating the vectors is deterministic (see "Regenerating" below) — the
  same run always produces byte-identical files.

## The five signature contexts

Every signed structure in this protocol is verified over
`CBOR([tag: tstr, payload: bstr])` — the same two-element CBOR array pattern
`local_rp::envelope_signature_input` uses (`application_keys.rs` reuses that
exact function), **except** `ApplicationKeyRevocation`, whose signed payload
is built from the revocation's own fields rather than from stored bytes (see
`application_key_revocation.json` below). A signature over one structure must
**never** verify as another — `application_key_attestation.json` includes a
"wrong domain-separation tag" negative case proving exactly this.

| Structure | Tag |
|---|---|
| Attestation | `linkkeys-application-key-attestation-v1alpha` |
| Addition (quorum) | `linkkeys-application-key-addition-v1alpha` |
| Possession proof (new/target key) | `linkkeys-application-key-possession-v1alpha` |
| Renewal (sibling quorum) | `linkkeys-application-key-renewal-v1alpha` |
| Revocation (sibling quorum) | `linkkeys-application-key-revocation-v1alpha` |

The possession tag is deliberately distinct from the addition and renewal
tags: the same payload bytes are signed by the new/target key (proving
possession) and by the authorizing quorum (proving authorization), and a
shared tag would let one signature be presented as the other. Two of this
directory's negative cases (`quorum_signature_as_possession_proof` in
`application_key_addition.json`) exist specifically to catch an SDK that
merges these two tags.

## File-by-file schema

### `application_key_attestation.json`

The home domain's short-lived, per-key attestation.

```
tag                        — ATTESTATION_TAG
attestation_lifetime_seconds — DEFAULT_ATTESTATION_LIFETIME_SECONDS (86400)
instance                   — {subject_user_id, subject_domain,
                               application_id, instance_id}
domain_signing_key         — Ed25519, seed/private/public/fingerprint
application_key            — the Ed25519 key being attested
attestation                — {attested_at, attestation_expires_at}
attestation_cbor_hex        — exact deterministic CBOR of ApplicationKeyAttestation
signature_input_cbor_hex    — CBOR([ATTESTATION_TAG, attestation_cbor_hex])
signed                     — {attestation_cbor_hex, signatures: [{domain,
                               signed_by_key_id, signature_hex}]}
domain_keys                 — the verifier's DomainPublicKey list
expected_domain             — the domain to verify against
```

`cases[]` (1): the domain-signed attestation verifies against `domain_keys`
with `expected_domain`.

`negative_cases[]` (3):

- `wrong_domain_separation_tag` — the exact same attestation bytes, but
  signed under `ADDITION_TAG` instead of `ATTESTATION_TAG`.
- `tampered_attestation_byte` — last byte of the attestation CBOR flipped,
  original signature reused. (This may also break CBOR/UTF-8 decoding itself,
  depending on which byte is hit — either outcome is an acceptable "not
  valid" result; your SDK only needs to fail, not fail a specific way.)
- `attestation_for_different_subject_domain` — a genuinely-signed attestation
  whose `subject_domain` field is `evil.example`, verified with
  `expected_domain` set to the real domain. The signature itself verifies
  fine; the identity binding must still refuse it.

To validate a case: decode `signed.attestation_cbor_hex`, recompute
`CBOR([ATTESTATION_TAG, attestation_cbor_hex])` and confirm it matches what
you would produce, then Ed25519-verify each signature against `domain_keys`
entries whose `key_usage` is `sign` and whose validity window (checked
against **wall-clock time**, per the note above) covers now. Also confirm the
decoded attestation's `subject_domain` equals `expected_domain`.

### `application_key_addition.json`

A two-signing-key quorum authorizes adding a new application key, which
separately proves possession of its own private key.

```
quorum_tag / possession_tag / quorum_size — ADDITION_TAG / POSSESSION_TAG / 2
instance
existing_keys                — the quorum-eligible ApplicationKeyRef list
new_key                       — the key being added (Ed25519, in this file)
impostor_key                  — a real, unrelated Ed25519 key used only by
                                the possession_proof_wrong_key negative case
addition_cbor_hex             — exact deterministic CBOR of ApplicationKeyAddition
addition_signature_input_cbor_hex    — CBOR([ADDITION_TAG, addition_cbor_hex])
possession_signature_input_cbor_hex  — CBOR([POSSESSION_TAG, addition_cbor_hex])
now / skew_seconds            — shared by every case and negative case below
```

Each case/negative case carries its own `existing_keys` (usually the shared
list, but the `new_key_signs_own_authorization` case substitutes a variant)
and a `signed` object: `{addition_cbor_hex, signatures: [{signed_by_key_id,
signature_hex}], possession_proof_hex}`.

`cases[]` (1): `existing_keys` = [app-key-a, app-key-b] authorize app-key-new,
which separately proves possession.

`negative_cases[]` (5):

- `one_signature_insufficient` — only app-key-a signed: 1 < quorum of 2.
- `duplicate_signer` — app-key-a signed twice (two signature entries, same
  `signed_by_key_id`); a key never counts twice, so still 1.
- `new_key_signs_own_authorization` — app-key-new is listed among
  `existing_keys` too (as a compromised/confused server might present it)
  AND signs the quorum message for its own addition. It must never count
  toward its own authorization, so only app-key-a counts: 1.
- `possession_proof_wrong_key` — a valid two-signature quorum, but the
  possession proof was signed by `impostor_key` instead of the new key. This
  is the exact attack the possession proof exists to stop: enrolling a
  public key you do not hold.
- `quorum_signature_as_possession_proof` — the new key's own quorum-tagged
  signature (over `addition_signature_input_cbor_hex`, as if it were an
  authorizing signer) is offered as the possession proof, which must instead
  cover `possession_signature_input_cbor_hex`. Same payload bytes, different
  tag; must not verify.

### `application_key_renewal.json`

Renews the attestation of an **existing** key without creating a new one. An
Ed25519 target proves current possession by signing for itself directly; an
X25519 (key-agreement) target cannot sign, so a sibling signing key vouches
for it instead (`RENEWAL_QUORUM = 1`).

```
renewal_tag / possession_tag / renewal_quorum — RENEWAL_TAG / POSSESSION_TAG / 1
instance
keys.app_key_a       — Ed25519, used as both a self-renewing target and,
                        elsewhere, a vouching sibling
keys.app_key_agree   — X25519, the sibling-renewed target
```

Each case/negative case is self-contained:

```
target                              — the ApplicationKeyRef being renewed
sibling_keys                        — vouching-eligible keys (empty for the
                                       Ed25519 self-renewal case)
renewal_cbor_hex                     — exact deterministic CBOR of ApplicationKeyRenewal
renewal_signature_input_cbor_hex     — CBOR([RENEWAL_TAG, renewal_cbor_hex])
possession_signature_input_cbor_hex  — CBOR([POSSESSION_TAG, renewal_cbor_hex])
signed                               — {renewal_cbor_hex, signatures: [...],
                                        possession_proof_hex}
now / skew_seconds
```

`cases[]` (2):

- `ed25519_self_renewal` — app-key-a signs `possession_signature_input`
  directly for itself. No sibling signatures used.
- `x25519_sibling_renewal` — app-key-agree (cannot sign) is renewed on a
  single sibling signature from app-key-a, meeting `RENEWAL_QUORUM = 1`. No
  `possession_proof` is present (the field is `null`).

`negative_cases[]` (1):

- `no_possession_proof` — app-key-a's renewal carries neither a
  `possession_proof` nor any sibling signature. An Ed25519 target's renewal
  MUST carry current proof of possession.

### `application_key_revocation.json`

Two DISTINCT, currently-valid sibling signing keys revoke a target key, which
never signs or counts toward its own revocation.

Unlike the other three files, the signed payload here is built from the
revocation's **fields**, not from stored raw bytes — the same
tuple-with-the-tag-first pattern as `revocation::revocation_payload`:

```
CBOR([REVOCATION_TAG, subject_user_id, subject_domain, application_id,
      instance_id, target_key_id, target_fingerprint, revoked_at])
```

an eight-element CBOR array (tag plus seven fields).

```
tag / quorum          — REVOCATION_TAG / 2
instance
keys                   — [app-key-a, app-key-b, app-key-c] — app-key-c is
                          the revocation target throughout this file
target_key_id / target_fingerprint / revoked_at
revocation_payload_cbor_hex — CBOR([REVOCATION_TAG, ...]) for the fields above
signer_keys             — Ed25519 seed/private/public/fingerprint for a, b,
                          and the target (c)
```

Each case/negative case carries a `revocation` object: the full
`ApplicationKeyRevocation` fields plus `revocation_cbor_hex` (its CSIL wire
encoding — note this is a SEPARATE encoding from `revocation_payload_cbor_hex`,
which is only the signed-over tuple, not the wire struct).

`cases[]` (1): `two_sibling_revocation` — app-key-a and app-key-b revoke
app-key-c. Meets `REVOCATION_QUORUM = 2`.

`negative_cases[]` (3):

- `one_signature_insufficient` — only app-key-a signed: 1 < 2.
- `target_signs_own_revocation` — app-key-a plus the TARGET key (app-key-c)
  itself. The target's signature is cryptographically valid but must be
  ignored: 1.
- `tampered_revoked_at` — a valid two-signer revocation whose `revoked_at`
  was changed after signing. The recomputed payload no longer matches either
  signature.

### `application_key_sealed_challenge.json`

The X25519 proof-of-possession exchange (`seal_challenge` / `open_challenge`
in `application_keys.rs`): the home domain seals a random challenge nonce to
the claimed X25519 public key; only the real private-key holder can recover
and return it.

`sealed_cbor_hex` is `CBOR([suite: tstr, ephemeral_public_key: bstr,
aead_nonce: bstr, ciphertext: bstr])` — a **four**-element array, not a bare
concatenation.

Production `seal_challenge` draws its ephemeral X25519 key and AEAD nonce
from the OS RNG, which conformance vectors cannot use directly. This file was
produced with `seal_challenge_with_randomness` — the same
explicit-randomness seam `local_rp::seal_local_rp_callback_with_randomness`
already established for the local-RP callback box — so the sealed bytes are
byte-stable across regeneration. **Do not use this seam, or the ephemeral
private key it published, in production code.**

```
suite                       — CHALLENGE_SEAL_SUITE ("chacha20-poly1305")
nonce_hex                   — the challenge plaintext (32 bytes)
ephemeral_private_key_hex / aead_nonce_hex — the seam's explicit randomness
recipient / wrong_recipient  — two real, unrelated X25519 keypairs
sealed_cbor_hex               — the sealed challenge bytes
```

`cases[]` (1): `opens_with_correct_key` — opening `sealed_cbor_hex` with
`recipient`'s private key recovers `nonce_hex` exactly
(`expected_plaintext_hex`).

`negative_cases[]` (2):

- `refused_by_wrong_key` — the same sealed bytes opened with
  `wrong_recipient`'s private key (a real, different X25519 key).
- `refused_when_corrupted` — the sealed bytes with the last byte flipped
  (part of the AEAD ciphertext/tag), opened with the CORRECT key. Carries its
  own `sealed_cbor_hex`, distinct from the top-level one.

## Regenerating

```sh
cargo run -p liblinkkeys --example generate_application_key_vectors
```

Optionally pass an output directory as the first argument (default is this
directory, resolved relative to the crate — not the current working
directory). The generator is deterministic: every seed, nonce, and timestamp
is a fixed constant (see the constants at the top of
`crates/liblinkkeys/examples/generate_application_key_vectors.rs`), so
re-running it produces byte-identical files. If a re-run produces a diff,
either the generator changed on purpose (commit the new vectors) or something
in `liblinkkeys` is non-deterministic where it should not be (investigate
before committing).

`tools.sh` has no subcommand for this (or for the sibling
`generate_conformance_vectors` example) — run the `cargo run` command above
directly.

After regenerating, run the consumer-zero test:

```sh
cargo test -p liblinkkeys --test application_key_conformance
```
