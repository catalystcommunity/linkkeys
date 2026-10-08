# Act-As Grants

> **Status: Reserved.** Implemented in the reference server, the regular-RP
> Go and TypeScript SDKs, and every local-RP SDK, with conformance vectors in
> `sdks/regular-rp/conformance/act_as_*.json`. It stays Reserved until the
> design is reviewed in use. It MAY change. An implementation MUST NOT rely on
> anything here for interoperability, and no conformance level includes it.
>
> Device binding (see "Device binding") is not implemented.

## Problem

A user is signed in to application C. C must act at application D for the
user. C, D, and the user's home domain can be in one domain, two domains, or
three domains.

An identity assertion has one audience. An assertion for C does not let C act
at D, and D MUST refuse it. LinkKeys has no way to express "this user lets C
act for them at D".

## Principle *(Rationale)*

An act-as grant is a fact that the user states and the home domain signs.
It is not a policy decision.

- LinkKeys asserts who the user is, which enrolled device the user is on, and
  that the user lets C act at D. Nothing more.
- C and D own all policy about what C can do at D. Scope strings are opaque to
  LinkKeys. D defines them and D enforces them.
- No party is in the request path between C and D. D verifies with public,
  cacheable material only: domain keys, application-key attestations, and
  revocations.
- Every check is a signature by a domain that DNS names. Same-domain and
  cross-domain deployments use the same rules.

A home domain cannot know every application that exists now or in the future.
A design that needs a home-domain policy for each application pair does not
scale. This is the main difference from Kerberos constrained delegation, where
the KDC evaluates policy on every hop. See "Naming".

## Identities

An application is identified by the identity that an application-key
attestation binds ([`../application-keys.md`](../application-keys.md) §1):

```text
ApplicationRef = {
    subject_user_id: text,   ;; the account that enrolled the application
    subject_domain: text,    ;; that account's home domain
    application_id: text
}
```

`ApplicationRef` has no `instance_id`. Any enrolled instance of an application
can use a grant to that application. Each instance proves membership with its
own attested application key.

A grantee is an application or a local RP:

```text
GranteeRef = {
    ? application: ApplicationRef,
    ? local_rp_descriptor_fingerprint: text
}
```

Exactly one field MUST be present. A local RP is identified by the fingerprint
of its descriptor signing key.

The audience MUST be an `ApplicationRef`. A local RP MUST NOT be an audience,
because a peer cannot resolve its keys through DNS.

A **grantee key** is an attested application key of the grantee, or the
descriptor signing key when the grantee is a local RP.

A grantee proves that a grantee key signed something with a `GranteeProof`:

```text
GranteeProof = {
    ? application_instance_id: text,
    ? local_rp_descriptor: SignedLocalRpDescriptor,
    signature: ApplicationKeySignature
}
```

Exactly one of the first two fields MUST be present, and it MUST match the
grantee's form. For an application, `application_instance_id` names the
instance whose attested key signed, so a verifier can resolve the attestation.
For a local RP, `local_rp_descriptor` carries the signed descriptor, its
fingerprint MUST equal the grantee's, and `signed_by_key_id` MUST be that
fingerprint. A verifier MUST check the descriptor's own signature and validity
window.

A home domain MUST accept a local-RP grantee only where its local-RP policy
admits local RPs, and only for a local RP it already approved.

## Scope sets

The audience signs the complete set of scope strings that a grantee can ask
for:

```text
ActAsScopeEntry = {
    scope: text,
    ? description: text
}

ActAsScopeSet = {
    audience: ApplicationRef,
    grantee: GranteeRef,
    entries: [+ ActAsScopeEntry],
    ? language: text,          ;; BCP 47 tag of the descriptions
    ? audience_handle_claim: Claim,
    issued_at: text,
    expires_at: text
}

SignedActAsScopeSet = {
    scope_set: bytes,                         ;; CBOR(ActAsScopeSet)
    signer_instance_id: text,                 ;; the audience instance that signed
    signatures: [+ ApplicationKeySignature]   ;; its current signing keys
}

ActAsScopeSetRequest = {
    grantee: GranteeRef,
    scope: [+ text],
    ? locale_preferences: [* text]       ;; BCP 47, most preferred first
}
```

Rules:

- The grantee gets the signed set from the audience. The transport for that
  exchange is an application protocol. This specification defines only the
  types and the signature.
- The audience chooses which strings to sign and MAY refuse. It writes all
  descriptions in one language. It SHOULD use the grantee's locale
  preferences to choose that language.
- A description is OPTIONAL. A consent surface MUST show a string without a
  description as the raw string.
- A scope string MUST NOT appear more than once in `entries`.
- A set MUST have between 1 and 64 entries. A scope string MUST be 1 to 256
  bytes, and a description at most 1024 bytes. The consent surface must show
  every entry, so the set stays bounded.
- The audience instance SHOULD sign with every current signing key, like a
  domain signs attestations and grants. A verifier MUST accept the set when at
  least one signature is by a key that was valid at the set's `issued_at` and
  that its revoked-key policy accepts (see "Revoked keys"). One expired or
  revoked key never invalidates the others. A later key rotation does not
  invalidate a set that a user already approved.
- A verifier MUST check signatures against all attested keys of the signing
  instance, including keys that expired or were revoked since, with their
  revocation times. A list of currently usable keys only would refuse sets
  signed before a rotation.
- `audience_handle_claim` is OPTIONAL. See "Handle claims".
- The scope set is the audience's statement. A grantee cannot add, remove, or
  reword an entry without breaking the signature.

## Grants

```text
ActAsGrant = {
    grant_id: text,
    user_id: text,
    subject_domain: text,
    grantee: GranteeRef,
    audience: ApplicationRef,
    scope_set: SignedActAsScopeSet,
    approved_scope: [+ text],
    issued_at: text,
    expires_at: text,
    series_issued_at: text,
    renewable_until: text,
    ? device_fingerprint: text
}

SignedActAsGrant = {
    grant: bytes,                    ;; CBOR(ActAsGrant)
    signatures: [* ClaimSignature]
}
```

- `scope_set` is the audience's signed set, unchanged.
- `approved_scope` is the set of strings that the user approved. Every string
  MUST be a `scope` in `scope_set`. It MUST NOT contain duplicates. It equals
  all of `scope_set` unless the user or home-domain policy removed entries.
- `series_issued_at` is the issue time of the first grant in a renewal series.
- `renewable_until` is the latest time at which any grant in the series can
  expire.
- `device_fingerprint` is reserved for device binding. See "Device binding".
  Until device binding is specified, a home domain MUST NOT set it, and a
  verifier MUST refuse a grant that carries it.
- The user's home domain signs the grant. A device key MAY co-sign it later.

An `ActAsGrant` is not a `ConsentGrant`. A `ConsentGrant` releases claims
to one audience. An act-as grant names a grantee and an audience. Separate
domain-separation tags make sure a verifier cannot accept one as the other.

## Domain separation

| Tag | Signed by | Covers |
| --- | --- | --- |
| `linkkeys-act-as-scope-set-v1alpha` | Audience application key | `ActAsScopeSet` bytes |
| `linkkeys-act-as-grant-v1alpha` | Home domain | `ActAsGrant` bytes |
| `linkkeys-act-as-grant-request-v1alpha` | Grantee key | `ActAsGrantRequest` bytes |
| `linkkeys-act-as-refresh-request-v1alpha` | Grantee key | `ActAsRefreshRequest` bytes |
| `linkkeys-act-as-presentation-v1alpha` | Grantee key | `ActAsPresentation` bytes |
| `linkkeys-act-as-grant-revocation-v1alpha` | Home domain | `ActAsGrantRevocation` bytes |

Every signature covers the deterministic CBOR encoding of the two-element
array `[tag, payload_bytes]`, the same construction as application keys
([`../application-keys.md`](../application-keys.md) §2).

Each signature MUST bind the user identity, the grantee, and the audience,
directly or through the signed bytes.

## Issuing a grant

1. The grantee sends the user's browser to the user's home domain with an
   `ActAsGrantRequest`. The request carries the grantee, the
   `SignedActAsScopeSet`, an OPTIONAL requested lifetime, an OPTIONAL
   requested renewal window, a callback URL, a nonce, and a request window
   (`requested_at`, `expires_at`). A grantee key signs it. The browser route
   is `GET /auth/act-as?signed_request=<base64url(CBOR(SignedActAsGrantRequest))>`.
   A home domain MAY refuse a request window longer than it keeps nonces. The
   reference implementation refuses windows longer than 900 seconds.
2. The home domain MUST verify that the signing key belongs to the grantee.
   For an application, it resolves the application-key attestation. For a
   local RP, it verifies the descriptor that the request carries.
3. The home domain MUST resolve the audience's attestation and verify the
   scope set signature. It MUST refuse a scope set that has expired, or whose
   `grantee` is not the requesting grantee. It MUST NOT need to contact the
   audience for anything except public keys and attestations.
4. The home domain authenticates the user and shows a consent surface. The
   surface MUST show the identities of the grantee and the audience, and MUST
   state that the audience wrote the scope list. See "Consent surface".
5. Home-domain policy MAY remove entries before the user sees them. The
   surface MUST show removed entries as removed. The user MUST NOT be able to
   restore them.
6. The user MAY remove more entries. Nobody can add an entry. If no entry
   remains, the home domain MUST NOT issue a grant.
7. The home domain MUST treat the request nonce as single-use. It signs and
   stores the grant, and sends the browser to the callback URL with
   `act_as_grant_id` and the request `nonce` as query parameters. A grant with
   scope descriptions can exceed URL limits, so the grant itself does not
   travel through the browser.
8. The grantee fetches the grant with a refresh request (see "Refresh and
   renewal"). The grant is not secret, but only the grantee can fetch it.

A grant MUST NOT be issued without the user's approval. A grantee cannot get a
grant on its own word.

### Lifetime and renewal window

The grantee MAY request a lifetime and a renewal window. An absent renewal
window means 0. An absent lifetime sets no limit from the grantee.

The home domain bounds both values with its own maximums. The user MAY lower
either value. The issued values are:

```text
lifetime        = min(user choice, requested lifetime if present, domain max lifetime)
renewal_window  = min(user choice, requested renewal window, domain max window)
issued_at       = now
expires_at      = issued_at + lifetime
renewable_until = issued_at + lifetime + renewal_window
```

The home domain MUST NOT issue more than the grantee requested. A grant with a
shorter lifetime, a shorter renewal window, or fewer scopes is not an error.
The grantee uses the grant that it receives, or it stops.

A home domain SHOULD use a default lifetime of 3600 seconds and a default
renewal window of 0.

## Refresh and renewal

The renewal window is the number of seconds, after the first grant expires,
during which the grantee can renew without the user. A window of 0 means no
renewal.

The grantee sends an `ActAsRefreshRequest` to the user's home domain with the
`ActAs/refresh-grant` operation. The request names the `grant_id`, the
grantee, a request window, and a nonce. A grantee key signs it. The same
operation fetches a new grant and renews a current one.

A home domain MAY refuse a request window that is longer than the window it
accepts for a grant request. The reference implementation refuses refresh
windows longer than 900 seconds, so a captured refresh request stops working
soon after it is signed.

The home domain MUST refuse a refresh unless all these are true:

- The grant exists, and the request's grantee equals the grant's grantee.
  An unknown grant and another grantee's grant MUST get the same answer.
  A request that names the right grantee but carries a proof that does not
  verify gets a signature error, not "not found". This tells a caller who
  already knows a grant id and its grantee that the grant exists. Grant ids
  are random, so this is accepted in exchange for useful errors to a grantee
  whose key is wrong.
- The signing key belongs to the grantee, as in "Issuing a grant".
- The grant series is not revoked.
- The user account is active.
- The current grant has not expired. An expired grant cannot be renewed. The
  grantee must ask the user again.

The home domain then returns the stored grant, or signs a renewed one. It
signs a renewed grant only when all these are true:

- Less than one half of the current grant's life remains.
- `now` is before `renewable_until`.
- The renewed expiry is later than the current expiry.

Otherwise it returns the stored grant bytes. A refresh is never an error
merely because renewal is not allowed or not due.

The renewed grant MUST keep `grant_id`, user, grantee, audience, `scope_set`,
`approved_scope`, `series_issued_at`, `renewable_until`, and
`device_fingerprint`. Only `issued_at` and `expires_at` change:

```text
expires_at = min(now + original lifetime, renewable_until)
```

Renewal MUST NOT check the expiry of `scope_set`. That expiry controls only
when a user can approve the set.

Returning stored bytes while more than one half of the life remains is a load
control. It absorbs retry storms and clients with a skewed clock. The grantee
SHOULD refresh when less than one half of the life remains.

## Presentation

For each call to the audience, the grantee sends the `SignedActAsGrant`
and a presentation signature. The presentation covers a hash of the grant
bytes, the audience's `ApplicationRef`, a digest of the request, a timestamp,
and a nonce. A grantee key signs it. A local-RP grantee also sends its signed
descriptor.

The audience owns replay protection for presentations. The audience also
chooses how old a presentation it accepts. `grant_hash` is the SHA-256 of the
`SignedActAsGrant.grant` bytes. The meaning of the request digest is defined
by the audience's application protocol.

```text
ActAsPresentation = {
    grant_hash: bytes,
    audience: ApplicationRef,
    request_digest: bytes,
    presented_at: text,
    nonce: bytes
}

ActAsCredential = {
    grant: SignedActAsGrant,
    presentation: SignedActAsPresentation   ;; { presentation: bytes, proof: GranteeProof }
}
```

## Verification at the audience

An audience MUST accept a grant only if all these are true:

1. The grant signature verifies against an active signing key of the grant's
   `subject_domain`, under the grant tag.
2. `audience` equals the verifier's own `ApplicationRef`. The verifier
   supplies this value. It MUST NOT read it from the request.
3. `issued_at <= now < expires_at`, within the verifier's clock-skew
   allowance.
4. The caller is the grantee. For an application, the caller's attestation is
   valid and not revoked, and its `subject_user_id`, `subject_domain`, and
   `application_id` equal `grantee`. For a local RP, the descriptor signature
   is valid and its fingerprint equals `grantee`.
5. The presentation signature verifies with that grantee key, under the
   presentation tag, and covers this grant, this audience, and this request.
6. `scope_set` verifies with a key of the audience, under the scope-set tag.
   Its `audience` is the verifier and its `grantee` equals the grant's
   `grantee`. Every string in `approved_scope` is in `scope_set`.
7. No revocation record that the verifier holds names the `grant_id`.

The verifier MUST NOT check the expiry of `scope_set` at this point.

The result is the verified user identity, the grantee, the approved scope
strings, and the expiry. The verifier's policy MUST use only
`approved_scope`, never the full scope set.

Claims that the grantee sends with a presentation are verified separately,
under the claims specification.

## Revoked keys

Revocation invalidates one key, never the other keys of the same party. The
protocol does not require a verifier to trust a revoked key's signatures made
before the revocation. Each verifier chooses:

- **Accept before revocation** (the default). A signature made before the
  key's `revoked_at` stays valid, as invariant I-7 states.
- **Refuse revoked.** Any signature by a key that is now revoked is refused.

Every party that verifies, the home domain and each audience, chooses for
itself. When no signature is acceptable, the verifier MUST say which keys it
refused and why: unknown key, outside its validity window when it signed,
revoked before it signed, or refused by policy.

## Handle claims

A request MAY carry a signed `handle` claim about the account that enrolled
the grantee (`grantee_handle_claim`). A scope set MAY carry one about the
account that enrolled the audience (`audience_handle_claim`). A handle claim
counts only when all these are true:

- Its `claim_type` is `handle` and its `user_id` is the party's
  `subject_user_id`.
- A signature by the party's own `subject_domain` verifies under the claims
  specification. Signatures by other domains are ignored.
- It is not revoked or expired.

A claim that does not count is not shown. It does not block consent.

## Consent surface

The consent surface MUST show, for the grantee and for the audience:

1. The domain, first and most prominent. A local-RP grantee has no domain;
   show its descriptor name and fingerprint instead.
2. Whether the domain was trusted before, from these signals: the user's
   earlier grants or claim consents involving the domain, an existing key pin
   for the domain on this home domain, and the operator's trusted-issuer list.
   For a local RP: the user's earlier grants to the same fingerprint, and the
   domain's approval. When no signal is present, the surface SHOULD warn that
   the party is new to the user and to this home domain.
3. The handle, when a handle claim counts.
4. The application id and the enrolling account's `subject_user_id`.

Two accounts on one domain can enroll applications with the same id. The
handle and the account id are what tell them apart.

## Revocation

The user revokes a grant at the home domain. The revocation names the
`grant_id` and covers every grant in the series, including later renewals. The
home domain MUST refuse renewal of a revoked series.

Scope is immutable after signing. To change scope, the user revokes the grant
and the grantee asks again.

The home domain signs each revocation as an `ActAsGrantRevocation`
(`grant_id`, `user_id`, `subject_domain`, `revoked_at`). It publishes them
through the public `ActAs/get-grant-revocations` read, keyed by `grant_id`,
with batch lookup of 1 to 100 ids. The read MUST NOT list grants by user, because
that would publish which applications a user uses. Revocation follows
invariant I-7: it is timestamped and never retroactive.

The audience chooses how fresh its revocation data must be. A short grant
lifetime lowers the need to check.

## Device binding

Device keys are Reserved ([`device-keys.md`](device-keys.md)). This section only
reserves the shape.

- The home domain issues a device-enrollment claim about the user. Its value
  is the device fingerprint. It travels with normal claim release.
- At approval, the user MAY bind the grant to the current device. The home
  domain sets `device_fingerprint`, and the device key co-signs the grant.
- Under invariant I-6, a device signature proves origin. It never authorizes
  an action by itself. The authority is the user's grant, signed by the home
  domain.

## Non-goals

- LinkKeys does not interpret scope strings.
- LinkKeys does not keep a registry of applications, scopes, or allowed
  application pairs.
- No chains. A grantee cannot pass a grant to a third application.
- No grant without the user.

## Naming *(Rationale)*

An act-as grant lets the grantee act as the user at the audience, within the
approved scope. It is not impersonation. The audience always knows the
grantee, because the grantee's own key signs every presentation. The
audience can apply different policy to a user acting directly and a grantee
acting as that user.

The mechanism fills the role that Kerberos calls constrained delegation
(S4U2Proxy). The name differs on purpose. In Kerberos, the KDC decides on
every hop whether a service can act for the user. Here, the user decides
once, the home domain signs that decision, and the audience decides what it
means.

Do not call this mechanism delegation. The `Rp` service's "RP-server
delegation helpers" (`sign-request`, `decrypt-token`, `issue-attestation`)
are a different thing. They let a browser-facing RP hand key-bearing steps to
its own RP server.
