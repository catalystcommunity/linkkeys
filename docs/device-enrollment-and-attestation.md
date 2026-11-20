# Device enrollment and attestation (design)

> **Status: Design, decisions settled (§10).** Not implemented. Non-normative.
> The protocol parts move into
> [`spec/reserved/device-keys.md`](spec/reserved/device-keys.md), and that page
> replaces its sketch.

## 1. Goals

- A device proves "I am an enrolled device of `user@domain`" to any verifier.
- It works on every device. A device uses its hardware key store (TPM, Secure
  Enclave, StrongBox) when it has one. A device without one uses a software key.
- One device can enroll in many domains, and for many accounts.
- A device belongs to a user. One device can belong to more than one user.
- Every application on a device gets the same device proof by the same call.
- No vendor phone-home. No heartbeat. No device management.

## 2. Non-goals

- **Device management.** A domain does not own a device. Enrollment is a
  partnership. Remote wipe, policy push, and inventory are MDM functions.
  LinkKeys does not supply them.
- **Vendor attestation services.** We do not call Apple App Attest, Google Play
  Integrity, or any other online vendor service.
- **A verdict on device health.** The protocol proves origin. A human decides
  how much a given key store is worth (invariant I-6).

## 3. What exists now

| Item | State |
| --- | --- |
| Reserved sketch | `spec/reserved/device-keys.md`, `spec/keys.md` §6. Enrollment, coupling, and cascade revocation are named. No wire format. |
| Invariant I-6 | Normative. A device key proves origin. It never authorizes by itself. |
| Application keys | Normative and built. Instance enrollment, 24 h attestations, sibling quorum add and revoke, public lookup, RP cache resolve. Device enrollment copies the user-approved enrollment and the public lookup. It does not copy the short-lived attestation: a device is enrolled, not given a renewable permission. |
| Act-as grants | Built. CSIL has `ActAsGrant.? device_fingerprint`. The "Device binding" section is reserved and not built. |
| Auth factors | `AuthenticationEvidence.method_types` already counts distinct methods. A test uses `"device"` as a method type. No device credential exists. |
| Algorithms | `liblinkkeys::crypto::SigningAlgorithm` has Ed25519 only. |
| Kerberos notes | `kerberos_comparison.md`: "LinkKeys enrolls the device once. After that, apps ride the trust chain down." |

The gap: there is no device key, no enrollment, no device proof, and no
algorithm that hardware key stores support.

## 4. Model

```
Device (hardware or software key store)
 └── Enrollment  (one device key per device + account)
       ├── enrolled at:   home domain of the account
       ├── recorded by:   that home domain, one signed record, no expiry
       ├── status from:   that home domain, on request (enrolled / revoked)
       └── used by:       every application on the device, through one agent
```

**We enroll the device. We do not give it powers.** The enrollment record says
"domain D enrolled this key for this account at time T." It is a fact, not a
permission. It does not expire and is not renewed. A device proof says "this
request came from this device." Neither one authorizes anything (I-6).

**The key is the device.** A device cannot change its key. It can only
unenroll. A new key is a new device, with a new enrollment.

### 4.1 One key per enrollment

An enrollment is one (device, account) pair. Each enrollment has its own key
pair. The device makes a new key for each enrollment.

Reason: one shared device key across enrollments links every account on the
device. `claim-trust-verification.md` §3 says that a separate account is the
way to get an unlinkable persona, and that "a device can be enrolled in
multiple accounts/domains." A shared key breaks that promise. Separate keys keep
it, and cost nothing: a TPM or Secure Enclave can hold many keys under one
hardware root.

Results:

- **Many domains:** each domain sees its own key. Domains do not see each other.
- **Many users on one device:** each user enrolls. Each gets an own key. The
  domain does not know that two accounts share the device. It does not need to.
- **Revocation at one domain** has no effect on other enrollments.
- **An RP** sees the device id of the enrollment for that account. The same
  user's other account on the same phone shows as a different device. That is
  the intent.

### 4.2 Device identity

The `device_key_id` is the fingerprint of the enrollment public key
(`keys.md` §3.2). It is self-certifying. The domain assigns no device id.

A user-visible label ("Tod's laptop") stays private to the account. It is never
in a signed record that leaves the domain.

### 4.3 Key protection

The device states how it holds the key:

| `protection` | Meaning | Examples |
| --- | --- | --- |
| `hardware` | Key is in a hardware key store. It cannot be exported. | TPM 2.0, Secure Enclave, Android StrongBox / TEE, Windows Platform Crypto Provider |
| `os_keystore` | OS-protected software store. | Windows CNG software KSP, macOS keychain (no SE), Linux kernel keyring |
| `software` | Encrypted key file. | Fallback on any device |

This matters for "the key is the device." A hardware key cannot be copied. A
`software` key can, and a copy looks like the same device. Verifiers see the
level and decide.

The value is a claim by the device. An enrollment MAY carry `evidence` that
supports it:

| `evidence_format` | Verifiable offline? |
| --- | --- |
| `tpm2-certify` (TPM2_Certify + EK certificate chain) | Yes, against manufacturer roots |
| `android-key-attestation` (X.509 chain) | Yes, against the Google root. A revocation-list fetch is optional. |
| none | — |

Apple Secure Enclave has no offline attestation without App Attest. An iOS or
macOS device can say `hardware` but cannot prove it. The UI shows "not
verified" for that case. We state this; we do not hide it.

A domain MAY check evidence, MAY show the result, and MAY refuse an enrollment
by its own policy. Evidence checks are pluggable and optional. A domain that
checks no evidence is still conformant.

**Phase 1 checks `tpm2-certify`.** The check is a pure function in
`liblinkkeys::device::evidence`. The trusted TPM manufacturer roots (Infineon,
STMicroelectronics, Nuvoton, Intel PTT, AMD fTPM) are data that the caller
passes in, so the library does no I/O. The server ships a default set in
`crates/linkkeys/assets/tpm-trust/` (32 anchors, 159 intermediates, built from
the vendors' servers against pinned fingerprints; see its README) and lets the
operator replace it. This adds X.509 parsing (RustCrypto `x509-cert`,
pure Rust). `android-key-attestation` is a later phase.

### 4.4 Algorithms

Hardware key stores do P-256. Few do Ed25519. So device keys accept two
algorithms:

| `algorithm` | Use |
| --- | --- |
| `p256` (ECDSA P-256, SHA-256, deterministic CBOR input) | Hardware and OS key stores |
| `ed25519` | Software fallback |

This adds P-256 verification to `liblinkkeys`. It needs one new dependency, the
RustCrypto `p256` crate. It is pure Rust, audited, and WASM-safe. Domain, user,
and application keys stay Ed25519.

## 5. Enrollment

Enrollment is the one interactive step. It uses a user code, like the OAuth
device grant (RFC 8628), so it works on a device with no browser (a CLI, a TV, a
server).

```
Device SDK                       Home domain                     User (any browser)
     |  start-enrollment  ---------->|                                   |
     |  (pubkey, alg, protection,    |                                   |
     |   evidence?, possession sig)  |                                   |
     |<---- enrollment_id, user_code,|                                   |
     |      verification_url, expiry |                                   |
     |                               |<--- sign in, enter/confirm code --|
     |                               |     name the device, approve      |
     |  complete-enrollment -------->|                                   |
     |  (device-key signed, polled)  |                                   |
     |<---- SignedDeviceEnrollment --|                                   |
```

Rules:

1. The device makes the key pair first. The private key never leaves the key
   store.
2. `start-enrollment` carries a possession proof: the new key signs the request
   under its own tag.
3. The user signs in at the home domain by the normal methods. The domain MAY
   ask for more factors.
4. The browser page shows the code, the stated protection, and the evidence
   result. The user approves or denies.
5. The device polls `complete-enrollment` with a request that the device key
   signs. Poll interval and code life are short (default 5 s and 10 min).
6. A browser on the same device can skip code entry: the SDK opens
   `verification_url` with the code in the URL fragment.

Transport: the device is not a server, so invariant I-4 does not apply. The
SDK uses CSIL-RPC over TCP when it can reach it, and the HTTPS carrier
(`/csil/v1/rpc`) when not. Mobile networks often block uncommon ports.

## 6. Enrollment record and status

### 6.1 The enrollment record

At approval, the home domain signs a `DeviceEnrollment` one time:

| Field | Meaning |
| --- | --- |
| `subject_user_id`, `subject_domain` | The account. Never a profile. |
| `device_key_id`, `algorithm`, `public_key` | The device key. Fixed for the life of the enrollment. |
| `protection`, `evidence_verified` | What the device stated, and whether the domain checked evidence. |
| `enrolled_at` | When the user approved. |

Tag: `linkkeys-device-enrollment-v1alpha`. Envelope: exact CBOR bytes plus a
signature list, like `SignedApplicationKeyAttestation`. The domain stores and
serves the bytes verbatim.

The record has no expiry and no renewal. A domain key that signed it can later
expire or be revoked; per I-7 the record keeps its meaning, because
`enrolled_at` is signed. The device holds the record and attaches it to proofs.

### 6.2 Status lookup

Another domain asks the home domain if it still enrolls a device. It uses the
identifiers from the enrollment record:

```
Device/get-enrollment-status(subject_user_id, device_key_id)
  -> SignedDeviceEnrollmentStatus {
       subject_user_id, subject_domain, device_key_id,
       state,            ; "enrolled" | "revoked" | "unknown"
       ? revoked_at,
       checked_at
     }
```

Tag: `linkkeys-device-enrollment-status-v1alpha`. Rules:

- CSIL-RPC over TCP (I-4). Anonymous. Rate limited.
- A lookup, never an enumeration. The caller must already know both ids. A
  `device_key_id` is a key fingerprint and cannot be guessed. No call lists the
  devices of an account to anyone but the account.
- The answer is signed, so the caller can keep it as evidence of what it was
  told and when.
- How often to ask is the verifier's decision. LinkKeys sets no interval.

No renewal, no heartbeat. A device talks to its home domain only to enroll,
to sign in, and to unenroll.

## 7. Device proofs (what applications produce)

A device proof is the one thing applications ask for:

```
DeviceProof = {
  subject_user_id, subject_domain,
  device_key_id,
  audience,          ; who will verify (domain, or domain + application)
  challenge,         ; verifier nonce, or a hash of the request being approved
  issued_at, expires_at          ; short: default 2 min
}
SignedDeviceProof = { proof: bytes, signature: bytes,
                      enrollment: SignedDeviceEnrollment }
```

Tag: `linkkeys-device-proof-v1alpha`. The proof carries the enrollment record,
so a verifier needs only the home domain's pinned keys to check it.

A verifier MUST check: the enrollment record (home domain signatures), the proof
signature against the enrolled key, audience, challenge, and expiry. A proof
says the request came from the device. It does not say the device is still
enrolled. For that, see §6.2 and §8.2.

`liblinkkeys::device` holds `build_proof_payload`, `verify_device_enrollment`,
`verify_device_proof`, and `verify_enrollment_status` as pure functions. Every
RP SDK wraps them.

### 7.1 The device SDK: the same proof for every application

Applications use one **device SDK** call. Every application gets the same
enrolled key for the same enrollment. That is "the same device proof" across
applications.

```
device.list_enrollments()                    -> [{domain, user_id, label}]
device.prove(enrollment, audience, challenge) -> SignedDeviceProof
```

**Library first.** When the device has a hardware key store, the hardware
already stops the key from being copied. No extra process is needed. The SDK is
a library that each application links. It reads a per-OS-user enrollment store
(the signed enrollment records and the wrapped key handles) and asks the key
store to sign. The access boundary is the OS user, as with any hardware key that
has no PIN.

**Agent only where the platform needs one.** The SDK talks to a **device agent**
process in two cases:

1. **Software keys.** Without hardware, the key is a file. If every application
   can read the file, every application can copy the key. The agent holds the
   key and gives out signatures only, like `ssh-agent`.
2. **Mobile, across vendors.** Android keystore keys belong to one app. iOS
   keychain keys are shared only inside one vendor's access group. For one key
   to serve applications of different vendors, one app holds it and the others
   ask that app.

The SDK picks the path. The application code and the wire format are the same
on both paths.

| Platform | Hardware key store | Path |
| --- | --- | --- |
| Linux, Windows | TPM 2.0 (`tss-esapi`), Windows Platform Crypto Provider (CNG) | Library |
| macOS | Secure Enclave (`security-framework`) | Library |
| Any desktop, no hardware | — | Agent (local socket / named pipe, per OS user) |
| Android | Keystore / StrongBox | Library inside one app; agent app for sharing across vendors (later) |
| iOS | Secure Enclave | Library; keys shared inside one vendor's keychain access group. A cross-vendor agent app is later. |
| Browser only | WebAuthn platform credential (P-256) at the home domain | No SDK. Only the home domain verifies it, so it is a login factor (§8.1), not a proof for other verifiers. |

The SDK and the agent are a new crate in this workspace. They are never part of
`liblinkkeys`, because they do I/O. Key store backends are features: `software`,
`tpm2`, `windows-cng`, `secure-enclave`.

> **Naming.** `spec/reserved/device-keys.md` warns that "local RP" and a local
> authenticator must not get similar names. This design uses **device SDK** and
> **device agent**.

## 8. What a device proof is used for

All uses layer on top of the domain's assertion. None replaces it (I-6).

### 8.1 Login factor at the home domain (the Kerberos part)

A new credential type `device`. A device proof with audience = the home domain
counts as method `device` in `AuthenticationEvidence`. Results:

- An application on an enrolled device signs the user in with no password
  prompt. This is the "log in once, everything works" goal.
- Password + device = two distinct factors for `minimum_factor_count: 2`.

### 8.2 Login at a third-party application

The application runs on DeviceA. Its RP is at domain B. The user's home domain
is A.

```
App on DeviceA        Device SDK          Home domain A              RP at domain B
  | start login ------------------------------------------------------->|
  |<-------------------------------------------- signed auth request ---|
  | prove(audience=B, challenge=hash(auth request)) ->|                 |
  |<- SignedDeviceProof --|                           |                 |
  | auth request + proof ---------------------------->|                 |
  |                       |  check proof against its  |                 |
  |                       |  enrollment table (live)  |                 |
  |                       |  issue assertion:         |                 |
  |                       |  device_key_id = DeviceA  |                 |
  |<------------------------------------ assertion ---|                 |
  | assertion + proof ------------------------------------------------>|
  |                       |                           |   check both    |
```

1. Domain A checks the proof against its own live enrollment table. It counts
   the `device` factor (§8.1). It issues an assertion with
   `? device_key_id`, bound into the signature.
2. RP B checks the assertion against domain A's pinned keys, as now.
3. RP B also checks the device proof itself: enrollment record, signature,
   audience = B, challenge = its own auth request. RP B does not rely only on
   domain A's word. A malicious administrator at A holds domain and user keys,
   but not the device key, so A cannot fake DeviceA.
4. RP B remembers the device: `(user_id@A, device_key_id, public_key,
   protection, first_seen)`. On later logins it knows "known device" or "new
   device", and applies its own policy (for example, tell the user about a new
   device).

**Freshness.** A login is a status check at no extra cost: domain A issues an
assertion that names DeviceA only while DeviceA is enrolled. RP B needs
`get-enrollment-status` (§6.2) only when it relies on the device outside a fresh
login, for example for device-signed requests later in a session (§8.3).

### 8.3 Request signing for high-value actions

An RP sends a challenge that is the hash of the exact action ("pay 500 to X").
The device signs it. The RP checks it against the device key it remembered at
login, and asks `get-enrollment-status` if its last answer is older than its
own policy allows. A malicious domain administrator cannot forge it: they hold
domain and user keys, not the device key. This is additive to the assertion.

### 8.4 Application-key coupling and cascade revocation

At application-instance enrollment, the instance MAY carry a device proof over
the addition bytes. The home domain records the coupling. When the user revokes
the device, the domain revokes every coupled application key and stops renewing
their attestations.
A verifier sees normal application-key revocations; it needs no new logic.

### 8.5 Act-as device binding

Fills the reserved section in `spec/reserved/act-as-grants.md`: the device
co-signs the grant, and the domain sets `device_fingerprint` to the
`device_key_id`.

## 9. Revocation and unenrollment

| Who | How | Effect |
| --- | --- | --- |
| User | Account page "Remove this device" | Domain sets `revoked_at`, refuses the device as a login factor, answers `revoked` to status lookups, revokes coupled application keys. |
| Domain admin | Admin API / UI | Same. |
| Device | `Device/unenroll`, signed by the device key | Same. A thief can only remove trust, so self-revocation is safe. |

A revoked enrollment never comes back. To use the device again, it makes a new
key and enrolls as a new device.

Revocation follows I-7: proofs and grants made before `revoked_at` keep their
meaning. Verifiers learn of a revocation at the next login (no assertion names
the device) or at their next status lookup.

## 10. Decisions (settled 2026-11-14)

| # | Question | Decision | Trade-off accepted |
| --- | --- | --- | --- |
| D1 | Key scope | One key per (device, account). §4.1. | Nobody, the home domain included, can tell that two enrollments are the same physical device. |
| D2 | Algorithms | `p256` for hardware, `ed25519` for software. §4.4. | One new dependency (`p256`); a second algorithm in every SDK verifier. |
| D3 | Attestation model | Lasting enrollment record + status lookup. §6. We enroll the device; we do not give it powers. | Verifiers that act outside a fresh login must ask for status themselves. |
| D4 | Evidence in phase 1 | Check `tpm2-certify` in phase 1. §4.3. | A TPM manufacturer root set to maintain; X.509 parsing in phase 1. |
| D5 | How applications reach the key | Device SDK library first; device agent only for software keys and cross-vendor mobile. §7.1. | Two code paths inside the SDK. |
| D6 | CSIL placement | New `Device` service (anonymous and device-signed calls, status lookup) + `Account` calls for the browser side. | One more service in CSIL and TCP dispatch. |
| D7 | Shared-device link | Not now. Later, if needed, a user opt-in claim. | A family computer shows as unrelated devices. |
| D8 | Device proof path to a third-party RP | Next to the assertion. The assertion carries only `device_key_id`. §8.2. | The application forwards two items; the RP checks that the ids match. |

## 11. Plan

Each phase ends with tests green on Postgres and SQLite, and conformance vectors
for every new signed structure.

| Phase | Work |
| --- | --- |
| **P0** | Rewrite `spec/reserved/device-keys.md` from this page. |
| **P1 — library** | `liblinkkeys`: P-256 verify (+ sign for the SDK), `device` module (enrollment record, status, proof, unenroll payloads and verifiers), `device::evidence` (`tpm2-certify`, roots passed in), domain-separation tags, vectors. The evidence and anchor-loading files carry the trust-critical marker and return capability types (`docs/trust-change-control.md` §3.1). |
| **P2 — CSIL + server** | CSIL `Device` service and types; regenerate. Tables `device_enrollments` (with the signed record bytes) and `device_enrollment_requests` (both backends, single migration each). Enrollment with user code, status lookup, unenroll. Account page: list, approve, rename, remove. |
| **P3 — device SDK** | `crates/linkkeys-device`: enrollment store, library path with `tpm2` and `software` backends, CLI (`enroll`, `list`, `prove`, `unenroll`). Then the device agent for software keys, `windows-cng`, and `secure-enclave`. |
| **P4 — use** | `device` credential type and login factor (§8.1). Third-party login with `device_key_id` in assertions (§8.2). RP SDK `verifyDeviceProof`, known-device memory, and `getEnrollmentStatus` (Go and TypeScript first, then the rest). |
| **P5 — coupling** | Application-key coupling and cascade revocation (§8.4). Act-as device binding (§8.5). |
| **P6 — reach** | WebAuthn browser path. Android agent app. `android-key-attestation` evidence. |
