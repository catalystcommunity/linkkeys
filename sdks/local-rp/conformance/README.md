# DNS-less local RP — conformance vectors

This directory is the shared test suite for every LinkKeys local-RP SDK, in
every language. It is generated once from the Rust `liblinkkeys`
implementation and checked into every SDK's test run unchanged. If your SDK
passes every case (positive AND negative) in every file here, its wire
constructions are conformant.

**Authority**: `dns-less-local-rp-design.md` at the repo root, section "Wire
Precision (Normative)", is the normative specification. This README describes
the JSON schema of the vectors; the design doc is the source of truth for
*why* the bytes look the way they do. If the two ever disagree, the design
doc wins and this file (or the generator) has a bug.

**Consumer zero**: `crates/liblinkkeys/tests/conformance.rs` reads these same
files and verifies every case against the real Rust implementation, as part
of the normal `cargo test -p liblinkkeys` run. That test is the best worked
example of "how to consume these vectors" available, independent of language.

## Conventions used throughout

- **Hex fields** (any key ending `_hex`) are lowercase hex, no `0x` prefix, no
  separators — decode with any standard hex decoder.
- **Base64url fields** (`base64url_unpadded`, and free-text `input` fields in
  negative cases) use the URL-safe alphabet (`-` and `_` in place of `+` and
  `/`) with **no padding** (`=`) characters. This is the same encoding
  `crates/liblinkkeys/src/encoding.rs` uses via `base64ct::Base64UrlUnpadded`.
- Every case that is expected to fail carries `"expected_valid": false` (or,
  for `envelopes.json`, is listed under `negative_cases` rather than `cases`).
  Your SDK's assertion should simply be: attempt the operation, check whether
  it succeeded, and require that outcome to match `expected_valid`. Exact
  error *types* are intentionally not part of the contract — every SDK has
  its own error taxonomy; only pass/fail is portable.
- All key material in `keys.json` is **fixed, publicly-known, test-only**.
  The seeds are literally repeated-byte constants (e.g. 32 bytes of `0x01`).
  Never reuse any key from this directory for anything real.
- All timestamps are fixed RFC3339 constants baked into the generator, not
  wall-clock time. Regenerating the vectors is deterministic (see
  "Regenerating" below) — the same run always produces byte-identical files.

## The four signature contexts

Every signed structure in this protocol is verified over
`CBOR([context: tstr, payload: bstr])` — a two-element CBOR array, context
string first, then the exact payload bytes as a CBOR byte string. This is
**not** a bare `context || payload` concatenation; see `envelopes.json` below
and the design doc's "Signature input bytes" for why the CBOR array framing
matters. There is no signature versioning: Ed25519 only, forever, for these
four structures.

| Structure | Context string |
|---|---|
| Local RP descriptor | `linkkeys-local-rp-descriptor` |
| Local RP login request | `linkkeys-local-rp-login-request` |
| Local RP callback payload | `linkkeys-local-rp-callback` |
| Local RP ticket redemption request | `linkkeys-local-rp-ticket-redemption` |

A signature over one structure must **never** verify as another — every
structure's vector in `envelopes.json` includes three "wrong context" negative
cases proving exactly this.

## AEAD suite registry

Suite ids are exact, case-sensitive strings from a closed registry — never
"close enough", never case-folded:

| Suite id | Status |
|---|---|
| `aes-256-gcm` | Mandatory to implement (baseline) |
| `chacha20-poly1305` | Optional |

The local RP descriptor advertises suites it supports, in preference order;
the IDP picks one from that list and binds the choice into the callback
header (see `callback_box.json`). An SDK must never decrypt with a suite
absent from its own advertised list, even if that suite is a valid registry
member (`callback_box.json`'s `unadvertised_suite_rejected` case).

## Callback sealed box: KDF/AAD construction summary

(Full authority: design doc, "Callback sealed box".) For a chosen suite:

1. Ephemeral X25519 keypair; ECDH with the recipient's (local RP's) X25519
   encryption public key. An all-zero shared secret (forced by a low-order/
   all-zero ephemeral public key) must be rejected outright.
2. KDF/AAD-prefix context: `tag || suite_id_utf8 || ephemeral_public(32) ||
   recipient_public(32)` — raw byte concatenation. `tag` is the ASCII bytes
   of `linkkeys-local-rp-callback-box`.
3. AEAD key = HKDF-SHA256(salt=none, ikm=shared_secret).expand(info=context,
   32 bytes).
4. AEAD = the negotiated suite, random 12-byte nonce (fixed, for these
   vectors — see below).
5. AAD = `context || header_cbor_bytes`, where `header_cbor_bytes` is the
   **exact** bytes shipped as `LocalRpEncryptedCallback.header` (i.e. the
   canonical CBOR encoding of `LocalRpCallbackHeader`, which already contains
   the ephemeral public key and AEAD nonce — both exist before encryption).

The plaintext being encrypted is the CBOR encoding of a
`SignedLocalRpCallbackPayload` envelope (itself a domain-signed envelope
around `LocalRpCallbackPayload`, context `linkkeys-local-rp-callback` — see
`envelopes.json`).

## File-by-file schema

### `keys.json`

Fixed test-only key material, referenced by name from every other file.

```
local_rp.signing            — Ed25519: seed_hex, private_key_hex (== seed_hex
                               for Ed25519 — the "private key" IS the 32-byte
                               seed), public_key_hex, fingerprint_hex
local_rp.encryption          — X25519: private_key_hex, public_key_hex
domain_signing_key           — Ed25519, PLUS key_id (a domain holds several
                               signing keys; this is the one used to sign the
                               callback payload in every vector here)
domain_encryption_recipient  — X25519: a SECOND, distinct keypair. It is
                               NOT the callback box's real recipient (that's
                               local_rp.encryption) — it exists purely to
                               give callback_box.json a real-but-wrong key
                               for its "wrong recipient key" negative case.
```

`fingerprint_hex` is `sha256(public_key_bytes)`, lowercase hex, 64 characters
— the same fingerprint format used everywhere in LinkKeys (DNS `fp=` records,
TLS SPKI pinning, local RP identity).

### `envelopes.json`

One `cases[]` entry per signed structure (`descriptor`, `login_request`,
`callback_payload`, `ticket_redemption`), plus `negative_cases[]`.

Each entry:

```
structure               — which of the four structures
envelope_field           — the CSIL field name the payload bytes are shipped
                            under (e.g. "descriptor", "request", "payload")
context                  — the context string used (see table above)
signing_key_id            — present ONLY for callback_payload (domain keys
                            have ids; local-RP-signed envelopes don't, since
                            a local RP has exactly one signing key)
payload_cbor_hex          — exact bytes of the payload being enveloped
signature_input_cbor_hex  — CBOR([context, payload_cbor_hex]) — what the
                            signature actually covers
signature_hex             — Ed25519 signature over signature_input_cbor_hex
verify_key_hex            — the Ed25519 public key to verify against
expected_valid            — true for cases[], false for negative_cases[]
```

To validate a case: recompute `CBOR([context, payload_cbor_hex])` yourself and
confirm it equals `signature_input_cbor_hex` (this is the part every SDK must
implement correctly — two-element CBOR array, definite-length, context as a
CBOR text string, payload as a CBOR byte string); then Ed25519-verify
`signature_hex` over that message with `verify_key_hex`, and check the result
against `expected_valid`.

`negative_cases[]` covers, per structure: one tampered-payload case (last
byte flipped, original signature reused), one wrong-key case (a real but
different Ed25519 key), and three wrong-context cases (the structure's own
payload+signature, verified under each of the *other* three context strings).
That's `4 × 5 = 20` negative cases.

### `callback_box.json`

`positive_cases[]` has one entry per suite (`aes-256-gcm`,
`chacha20-poly1305`), both sealing the **same plaintext** — the
`callback_payload` envelope from `envelopes.json`, re-encoded as a
`SignedLocalRpCallbackPayload` — to `local_rp.encryption` from `keys.json`.

```
suite                     — "aes-256-gcm" | "chacha20-poly1305"
ephemeral_private_key_hex — FIXED (not random — see "Regenerating" below)
ephemeral_public_key_hex
aead_nonce_hex            — FIXED, 12 bytes
recipient_public_key_hex  — == local_rp.encryption.public_key_hex
decrypt_private_key_hex   — == local_rp.encryption.private_key_hex
fingerprint               — == local_rp.signing.fingerprint_hex (the audience)
nonce_hex / state_hex     — the protocol nonce/state (also inside the
                             payload — a real IDP binds these together;
                             see design doc's callback flow)
issued_at / expires_at    — RFC3339
header_cbor_hex           — exact bytes of LocalRpCallbackHeader (this is
                             also `LocalRpEncryptedCallback.header`)
kdf_context_hex           — the KDF info / AAD-prefix bytes (see summary
                             above) — publish so you can unit-test your own
                             HKDF derivation independent of a full decrypt
aad_hex                   — kdf_context_hex || header_cbor_hex
plaintext_cbor_hex        — the SignedLocalRpCallbackPayload envelope bytes
                             (decrypting should reproduce this exactly)
ciphertext_hex
allowed_suites            — the suite list to pass as the decrypting side's
                             own "advertised/allowed" set (both suites, for
                             the positive cases)
expected_valid            — true
```

`negative_cases[]` (13 total), all built from the `aes-256-gcm` positive case
unless noted:

- 8 **header-field-flip** cases (`header_<field>_flip_fails_aad`) — one field
  of the decoded `LocalRpCallbackHeader` changed, then re-encoded and swapped
  in with the *original, untouched* ciphertext. Fields covered: `fingerprint`,
  `nonce`, `state`, `suite` (swapped to the other real suite id), `issued_at`,
  `expires_at`, `ephemeral_public_key` (one byte flipped — a garden-variety
  tamper, not the low-order case below), `aead_nonce`. Every one of these must
  fail because the header is bound as AEAD associated data.
- `unadvertised_suite_rejected` — a validly-encrypted `chacha20-poly1305`
  ciphertext, opened with `allowed_suites: ["aes-256-gcm"]` only. Must fail
  even though the suite is a real registry member.
- `unknown_suite_id_rejected` — header's `suite` field set to a string
  outside the registry entirely (`"made-up-suite"`).
- `low_order_ephemeral_key_rejected` — header's `ephemeral_public_key`
  replaced with 32 zero bytes (a low-order X25519 point that forces an
  all-zero ECDH output regardless of the recipient's private key). This must
  be rejected as a low-order/non-contributory key, distinct from an ordinary
  AEAD-tag failure — implementations should reject this before or as part of
  deriving the AEAD key, not merely observe a tag mismatch.
- `wrong_recipient_key_rejected` — the original, untouched
  `header_cbor_hex`/`ciphertext_hex`, opened with
  `domain_encryption_recipient`'s private key instead of the true recipient's.
- `truncated_ciphertext_rejected` — last 4 bytes of the ciphertext dropped
  (chops into the AEAD authentication tag).

Every negative case carries its own `header_cbor_hex`, `ciphertext_hex`,
`decrypt_private_key_hex`, and `allowed_suites` so it can be attempted in
isolation without cross-referencing the positive case.

### `url_params.json`

```
cases[].name                   — "signed_local_rp_login_request" |
                                  "local_rp_encrypted_callback"
cases[].cbor_hex                — CBOR bytes of the OUTER envelope struct
                                   (SignedLocalRpLoginRequest, or
                                   LocalRpEncryptedCallback)
cases[].base64url_unpadded       — the exact query-parameter value
negative_cases[].input           — a string that MUST fail to decode
negative_cases[].expected_valid  — always false
```

- `signed_local_rp_login_request` is the value of the begin route's
  `?signed_request=` query parameter
  (`GET /auth/local-rp?signed_request=<this>`).
- `local_rp_encrypted_callback` is the value of the callback redirect's
  `&encrypted_token=` query parameter, and is the SAME ciphertext as
  `callback_box.json`'s `aes-256-gcm` positive case, just wrapped in the
  outer `LocalRpEncryptedCallback` envelope and base64url-encoded.
- `padded_base64_rejected`: a valid unpadded string with one `=` appended.
  Your decoder must reject standard base64 padding.
- `standard_alphabet_rejected`: one `-`/`_` character swapped for `+`/`/`.
  Your decoder must reject the standard (non-URL-safe) alphabet.

### `dns.json`

Mirrors `crates/liblinkkeys/src/dns.rs`'s own test cases for the two TXT
record types.

```
linkkeys_txt.valid_cases[]     — txt, expected_fingerprints[] (order preserved)
linkkeys_txt.invalid_cases[]   — txt, expected_error (symbolic string, see below)
linkkeys_txt.no_record_case    — txt: null, documentation_only: true —
                                  represents no TXT record existing at all
                                  (NXDOMAIN / empty answer), which is a DNS
                                  lookup outcome, not a parser input. Nothing
                                  to parse; treat absence as "untrusted".
linkkeys_apis_txt.valid_cases[]    — txt, expected_tcp (nullable),
                                      expected_https_base (nullable)
linkkeys_apis_txt.invalid_cases[]  — txt, expected_error
default_tcp_port                    — the port implied when `tcp=` omits one
```

`expected_error` symbolic values (map these to your own error type):
`missing_version`, `unsupported_version`, `missing_apis_endpoint`,
`no_linkkeys_record`, `invalid_format`.

Record format reminder: `_linkkeys.{domain}` TXT is
`v=lk1 fp={hex} fp={hex} ...` (the trust anchor — pinned signing-key
fingerprints); `_linkkeys_apis.{domain}` TXT is
`v=lk1 tcp={host[:port]} https={host[:port][/path]}` (service endpoints —
SDKs use `tcp=`, browsers use `https=`). Both require a `v=lk1` tag; fields
are whitespace-separated and order-independent.

### `tickets.json`

```
cases[].ticket_hex   — 32 opaque bytes (a claim ticket is never structured —
                        just random bytes)
cases[].sha256_hex   — sha256(ticket_bytes), lowercase hex — what the SERVER
                        stores; the raw ticket itself never touches server
                        storage or logs
```

`ticket_a`'s bytes are the same ones used as `claim_ticket` in
`envelopes.json`'s `ticket_redemption` case and in `callback_box.json`'s
plaintext — the same ticket, referenced consistently end-to-end. See
`envelopes.json`'s `ticket_redemption` case for the full signed redemption
request envelope (payload/signature/context) that presents this ticket.

### `claims.json`

Claim wire encoding and claim-signature verification
(`crates/liblinkkeys/src/claims.rs`). Claims are what `complete_local_login`
ultimately delivers to app code — SDKs receive them inside
`LocalRpTicketRedemptionResponse` and must verify their signatures.

**The trap this file exists to catch**: `Claim.claim_value` is CBOR **bytes**
(bstr, major type 2) — never a text string — both on the wire and inside the
signed payload. An SDK that wires it as text (tstr) will pass its own
self-tests perfectly (sign-wrong/verify-wrong is self-consistent) and only
cross-implementation vectors expose the bug. The
`claim_non_utf8_binary_value` case is the discriminator: its value bytes are
not valid UTF-8, so a tstr codec cannot even represent them; and the
`claim_value_as_cbor_text_rejected` decode-negative case is a wire message a
strict bstr codec must refuse.

**Signed payload construction** (per signature; from `claim_sign_payload`):

```
CBOR([
  "linkkeys-claim-v1alpha",          ; tag, tstr
  claim_id,                     ; tstr
  claim_type,                   ; tstr
  claim_value,                  ; bstr  <-- BYTES, here too
  "user_id@subject_domain",     ; tstr  — ONE string, '@'-joined
  signing_domain,               ; tstr  — this signature's attestor
  expires_at,                   ; tstr, or CBOR null when absent
  attested_at                   ; tstr
])
```

An **eight-element** CBOR array, tag first. Notes SDK authors need:

- The subject is the single combined string `user_id@subject_domain`, not two
  separate elements. Neither a uuid nor a DNS name contains `@`, so the join
  is unambiguous. This is what stops a claim about `user@A` being replayed as
  `user@B` (the `subject_domain_replay` negative case).
- `subject_domain` comes from the authoritative context the verifier fetched
  the claim from (for local-RP SDKs: the callback payload's `user_domain`) —
  never from attacker-controlled input.
- `signing_domain` is bound per signature; a multi-domain claim has a
  *different* payload per signing domain.
- An absent `expires_at` is CBOR null **inside the array** (the array is
  always 8 elements). On the wire struct, an absent `expires_at`/`revoked_at`
  is an omitted map key.
- `created_at` is deliberately NOT signed (database-assigned).

**Verification rules** (`verify_claim` / `verify_claim_signatures`): every
**distinct** domain appearing in the claim's signatures must contribute at
least one signature that verifies against a currently-valid signing key of
that domain (revoked/expired/non-sign-usage keys don't count; key validity is
wall-clock-evaluated, as in `revocations.json`). A claim with zero signatures
is invalid. `verify_claim` additionally rejects a claim whose own
`revoked_at` is set or whose `expires_at` has passed.

File layout:

```
tag / payload_layout / subject_domain — constants and the fixture domain
signer_keys[]        — claim-key-1, claim-key-2 (real signers) plus a third
                        keypair used only to supply a WRONG public key in the
                        wrong_signer_key case; seeds/private/public/fingerprint
domain_keys[]        — the DEFAULT verification key list (claim-key-1 and
                        claim-key-2 as currently-valid signing keys)
cases[]              — positive: name, description, subject_domain, expanded
                        claim (claim_value_hex, signatures[] each with
                        signature_hex + signed_payload_cbor_hex), and
                        claim_cbor_hex (the exact wire bytes; decoding then
                        re-encoding must reproduce them byte-identically)
negative_cases[]     — name, description, subject_domain, claim_cbor_hex,
                        expected_error, and an optional domain_keys override
                        (when absent, verify against the file-level default)
decode_negative_cases[] — claim_cbor_hex that must FAIL to decode
ticket_redemption_response — response_cbor_hex plus its scalar fields
```

The three positive cases: `claim_utf8_text_value` (UTF-8 value — still bstr
on the wire), `claim_non_utf8_binary_value` (the tstr/bstr discriminator),
`claim_multiple_signatures` (two `ClaimSignature`s from two keys of one
domain — one valid signature per domain suffices).

The four verification negatives (`expected_error` values in parens):
`tampered_claim_value_byte` (`signature_invalid`), `wrong_signer_key` — same
key id, different real public key (`signature_invalid`),
`signer_key_not_found` (`key_not_found`), `subject_domain_replay` — the
unmodified claim verified under `evil.example` (`signature_invalid`).

`ticket_redemption_response` is a full `LocalRpTicketRedemptionResponse`
containing all three positive-case claims in order — the wire message where
SDKs actually consume Claims. Round-trip it byte-exactly AND verify the
embedded claims' signatures; decoding without verifying fails the point.

### `revocations.json`

Sibling-signed key revocation certificates
(`crates/liblinkkeys/src/revocation.rs`). Every SDK's `complete_local_login`
fetches revocation certificates alongside domain keys (`get-revocations`) and
must apply them: a key targeted by a valid certificate is revoked, no matter
what the fetched key entry itself says. Skipping this check is a security
gap, not a scope decision.

**Signed payload construction** (differs from the local-RP envelopes!): each
sibling signature covers `CBOR([tag, target_key_id, target_fingerprint,
revoked_at, signing_domain])` — a **five-element** CBOR array with the
domain-separation tag `linkkeys-key-revocation-v1alpha` first. This is the older
house tuple pattern, *not* the two-element `CBOR([context, payload])` envelope
framing. The signing domain is bound into each signature individually, so a
signature can never be replayed for another domain.

**Verification rules** (encode exactly these — they are what
`verify_revocation_certificate` enforces):

1. Walk the certificate's signatures. Skip any whose `signed_by_key_id`
   equals the certificate's `target_key_id` (a key never authorizes its own
   revocation), any whose `domain` field differs from the domain being
   verified, and any whose signer key is absent from the fetched key list or
   is not a currently-valid signing key (wrong `key_usage`, expired, or
   itself revoked).
2. For the rest, recompute the payload using the signature's **wire** `domain`
   field and verify the Ed25519 signature with the signer's public key.
3. Count **distinct** signer key ids that verified. The certificate is valid
   iff that count reaches the quorum (**2**).

Note on clocks: in the Rust implementation, signer-key expiry/revocation
validity is evaluated against **wall-clock time** (`check_signing_key_valid`
has no `now` parameter), unlike the payload-timestamp checks elsewhere which
take an explicit `now`. That is why the fixture keys carry a far-future
`expires_at` (2126) — and why your SDK should be conscious of *which* clock
each check uses.

File layout:

```
tag / quorum / domain      — the library constants and the fixture domain
domain_keys[]              — 5 signing keys: sibling-key-1/2/3 (all currently
                              valid; key 3 is the revocation target),
                              sibling-key-expired (expires_at in the past),
                              sibling-key-revoked (revoked_at set). Each has
                              seed_hex/private_key_hex/public_key_hex/
                              fingerprint_hex plus the DomainPublicKey wire
                              fields (created_at, expires_at, revoked_at).
certificate_cases[]        — see below
application_case           — see below
```

Each `certificate_cases[]` entry:

```
name / description
verify_domain               — the domain to pass to verification (differs
                               from the signing domain only in the
                               wrong-domain case)
certificate                 — expanded fields: target_key_id,
                               target_fingerprint, revoked_at, signatures[]
certificate.signatures[]    — domain, signed_by_key_id, signature_hex, plus
                               signed_payload_cbor_hex: the exact bytes that
                               signature was computed over (informational —
                               in tamper/cross-domain cases it intentionally
                               differs from what a verifier would recompute;
                               a `note` marks those)
certificate_cbor_hex        — the certificate's CSIL CBOR wire encoding
expected_valid              — overall verification outcome
expected_counted_signers    — how many distinct signers must survive the
                               filtering rules above (useful for pinpointing
                               which rule an implementation got wrong)
```

The nine cases:

- `valid_quorum_two_siblings` — keys 1+2 revoke key 3. Valid (2 signers).
- `single_signature_insufficient` — key 1 only. 1 < quorum.
- `target_self_signature_does_not_count` — key 1 + the target key 3 itself.
  The target's signature is cryptographically valid but must be ignored: 1.
- `tampered_revoked_at` — `revoked_at` changed after signing; both
  signatures now cover stale bytes: 0.
- `tampered_signature_byte` — key 1's signature byte-flipped; key 2 intact: 1.
- `verified_under_wrong_domain` — the valid certificate verified with
  `verify_domain: evil.example`: 0 (every signature's domain mismatches).
- `cross_domain_signature_reuse` — key 1's signature covers a payload bound
  to `evil.example` but its wire `domain` field claims the real domain; the
  recomputed payload differs, so it fails: 1. This is the attack the
  per-signature domain binding exists to stop.
- `expired_sibling_does_not_count` — key 1 + the expired sibling: 1.
- `revoked_sibling_does_not_count` — key 1 + the already-revoked sibling: 1.

`application_case` — the flow `complete_local_login` actually exercises:

```
envelope                — a SignedLocalRpCallbackPayload signed by the
                           TARGET key (sibling-key-3): payload_cbor_hex,
                           signing_key_id, signature_hex, context
verify_now              — the `now` to verify the envelope's timestamps with
clock_skew_seconds      — 300
certificate_ref         — points at valid_quorum_two_siblings
expected_valid_before_revocation — true: the fetched key list shows key 3
                           with NO revoked_at, so the envelope verifies
expected_valid_after_revocation  — false: after verifying the certificate
                           and marking its target revoked (as of the
                           certificate's revoked_at), the same envelope must
                           fail signature verification
```

The point of the application case: the fetched `domain_keys` entry for key 3
looks perfectly valid on its own. Only applying the revocation certificate
reveals it is dead. An SDK that verifies certificates but forgets to *apply*
them to the key set fails this case.

### `expirations.json`

Two independent sections:

```
check_expirations.expires_at       — the (fixed) identity expiry under test
check_expirations.thresholds_days  — {notice: 180, warning: 90, critical: 30}
check_expirations.cases[]          — {now, expected_level}
```

`expected_level` is one of `ok`, `notice`, `warning`, `critical`, `expired`.
Thresholds are **inclusive at the boundary**: exactly 180 days remaining is
already `notice` (not `ok`), exactly 90 is already `warning`, exactly 30 is
already `critical`, and `now >= expires_at` is `expired`. The cases walk
every boundary from both sides (one day/second before and at/after each
threshold) so an off-by-one in your comparison operators shows up
immediately.

```
check_timestamps.issued_at / expires_at / skew_seconds
check_timestamps.cases[]  — {now, expected_valid, description}
```

This is the generic bounded-clock-skew check used for descriptor/login-
request/callback-payload freshness (default skew: ±300 seconds). Cases hit
the exact skew boundary on both the leading (`issued_at - skew`) and trailing
(`expires_at + skew`) edges, one second before (still valid) and one second
past (invalid).

## Regenerating

```sh
cargo run -p liblinkkeys --example generate_conformance_vectors
```

Optionally pass an output directory as the first argument (default is this
directory, resolved relative to the crate — not the current working
directory). The generator is deterministic: every seed, nonce, and timestamp
is a fixed constant (see the constants at the top of
`crates/liblinkkeys/examples/generate_conformance_vectors.rs`), so re-running
it produces byte-identical files. If a re-run produces a diff, either the
generator changed on purpose (commit the new vectors) or something in
`liblinkkeys` is non-deterministic where Wire Precision requires it not to be
(investigate before committing).

After regenerating, run the consumer-zero test:

```sh
cargo test -p liblinkkeys --test conformance
```
