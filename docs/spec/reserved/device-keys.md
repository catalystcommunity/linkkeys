# Device and Application Keys

> **Status: Reserved.** Designed, not implemented. No code, no conformance
> vectors. This WILL change. An implementation MUST NOT rely on anything here for
> interoperability, and no conformance level includes it.
>
> Recorded so that Normative mechanisms are not designed in ways that would
> foreclose it. Invariant I-6 is already Normative for exactly this reason.

## The distinction this exists to preserve

Domain and user keys form a **custody** hierarchy held by the domain. Device and
application keys are **not** part of it. They are independent primitives that
*enroll* into a partnership with a domain — closer to a workstation joining a
directory than to a subkey being issued.

```
CUSTODY (domain-held):
  Domain signing keys (≥3, equal peers)        ← root of trust
    └── User keys (custodied by the domain, never leave it)

ENROLLMENT / PARTNERSHIP (not user-owned):
  Device keys — enrolled to the domain, associated with a user;
                held on the device, never leave it
    └── Application keys — optionally signed by ("coupled to") a device key
```

A device key represents *that device*. It is associated with a user through
enrollment; the user key does not own it, and the domain does not control it
unless the device chooses to enforce that. On a shared system, two users might
use the same application key or separate instances — their call. The load-bearing
property is that the key is *enrolled*: as long as it does not change, it
represents the same device or application, tied to a user.

## Sketch

- **Device keys** live in the device's secure enclave or best available
  equivalent; the private key never leaves the device. The domain learns only the
  public key, at enrollment.
- **Application keys** are per-application. An application key MAY be signed by a
  device key to attest "I am running on this enrolled device" — an *optional*
  coupling, present only when the application was enrolled to be coupled.
- **Cascade revocation** is what coupling buys: revoking a lost device's
  enrollment can deny every session and every application coupled to it.

### Enrollment

1. The user reaches an enrollment interface — web page, native application,
   whatever the domain and device provide.
2. The interface communicates with the domain.
3. The user proves identity by whatever means the domain accepts.
4. The device's public key is registered.
5. Thereafter the user sees nothing, unless something is wrong or an additional
   factor is required.

## Constraints any implementation must respect

- **Attest, never authorize (invariant I-6).** A device or application key proves
  *origin*. It is never by itself the authority for a privileged action.
  Authorization remains the domain's signed assertion.
- **High-value flows layer, they do not replace.** For bank-tier operations the
  device additionally signs the specific request, acting as a factor that even a
  malicious domain administrator cannot forge — they hold the domain and user
  keys, not the device key. This is additive to the domain's assertion.
- **Identification, not management.** LinkKeys identifies devices; it does not
  manage them. Integration with management systems is possible; enrollment is a
  trust partnership, not device control. Device management is an explicit
  non-goal.
- **Attestation strength is a human judgment.** How much to trust a given
  device's enclave or keystore is for the user and administrator to decide. The
  protocol supplies the primitive — a signature proving origin — not a verdict
  that the device is trustworthy.

## Naming hazard

*Local RP* (an installed application acting as its own relying party without DNS,
which is Normative and implemented) is a different thing from a *local
authenticator agent* (a user-side process holding device keys, which is Reserved
and unbuilt). These must not end up with similar names. Rename the agent before
it acquires a page of its own.

## Open questions

- Wire format for enrollment, and whether it is a new service or an extension of
  an existing one.
- How cascade revocation is expressed and verified — whether it reuses the
  two-of-N revocation certificate from `keys.md` §5 or needs its own shape.
- Whether application-key coupling is visible to a relying party, and if so how a
  relying party is meant to act on it without violating I-6.
- What, if anything, a domain learns about a device beyond its public key.
