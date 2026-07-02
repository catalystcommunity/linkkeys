# csilgen change request: revocation certificate wire codec + pin-recheck RPC op

Date: 2026-07-02. Context: SEC-08 / SEC-01/02 security remediation.

## Blocker discovered

Running the pinned `csilgen` against the **current** `csil/linkkeys.csil` (no CSIL
change) already rewrites the checked-in generated code by ~330 net lines
(codec.gen.rs churns 859 lines, services.rs shrinks ~190). The installed
`csilgen` has therefore drifted from whatever version produced the committed
`crates/liblinkkeys/src/generated/`. Regenerating would bundle that unrelated
toolchain-version change into the security work and risk breakage.

Per AGENTS.md ("fix the generator or the CSIL instead", CSIL changes go through a
separate csilgen session), the regen is deferred to a dedicated pass that
reconciles the generator version with the checked-in output.

## What was done WITHOUT regen

- `RevocationCertificate` is defined in `csil/linkkeys.csil` (spec of record).
- The signing/verifying logic is hand-written in `liblinkkeys::revocation`
  (build + verify, ≥2 distinct valid sibling signatures over the
  `linkkeys-key-revocation-v1` canonical tuple; the revoked key may not sign its
  own revocation). Unit-tested. This mirrors how `claims` / `assertions` /
  `signing_request` hand-write their sign/verify logic.
- Server-side, `linkkeys domain revoke-key` produces a sibling-signed certificate
  from the remaining active signing keys and records it in the audit log.

## Follow-ups that NEED the regen (do in the dedicated csilgen session)

1. **Emit `RevocationCertificate` into the generated codec** so it can be
   serialized on the wire, then replace the hand-written CBOR summary in
   `domain revoke-key` with the generated encode, and publish/serve the cert.
2. **Inter-domain revocation-cert exchange**: a service op for a domain to serve
   its revocation certificates, and a verifier path that, on a pin recheck
   retiring a key, fetches + verifies a cert and marks the peer key `revoked`
   (with proof) rather than merely deactivated. Wire into
   `liblinkkeys::revocation::verify_revocation_certificate`.
3. **Admin-gated `recheck-pins` RPC op**: add `RecheckPinsRequest`/`Response` to
   CSIL and an `Admin` op that calls `services::pins::recheck_all`. It needs the
   outbound net context threaded into the Admin dispatch (currently only the `Rp`
   path receives `outbound`). Until then, `linkkeys pins recheck` (CLI, cron-
   friendly) is the trigger.

## Expected CSIL (already added, pending regen)

```
RevocationCertificate = {
    target_key_id: text,
    target_fingerprint: text,
    revoked_at: text,
    signatures: [* ClaimSignature]
}
```

Plus (to author in the regen session): `RecheckPinsRequest`/`RecheckPinsResponse`
and the `Admin/recheck-pins` op.
