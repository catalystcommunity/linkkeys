# Trust and Anchor Discovery

How a party learns which keys speak for a domain, and how that knowledge is
maintained over time.

Read [`README.md`](README.md) first for the status markers (Normative /
Reserved / Rationale) and the invariants referenced here.

## 1. Anchor discovery *(Normative)*

**Anchor discovery** is the act of obtaining the authoritative set of key
fingerprints for a domain from a source that speaks for that domain.

An implementation MUST perform anchor discovery before trusting any key
attributed to a domain it has not already pinned. The discovered fingerprint set
— not the keys themselves — is authoritative for *which* keys speak for a
domain. Key material is retrieved separately and validated against the anchor
(§3).

Anchor discovery is defined independently of any transport. A **binding**
specifies how the fingerprint set is actually obtained. This specification
defines one binding (§2). An implementation MUST support at least one binding
and MAY support several.

> **Rationale.** Separating the concept from the binding is invariant I-2. DNS is
> the first binding because it is universally deployed and already the thing
> domain owners control, but it is not load-bearing to the trust model: nothing
> in pinning, verification, or revocation depends on the anchor having arrived
> over DNS specifically. A future binding can be added without re-cutting this
> layer.

## 2. The `DNS-TXT` binding *(Normative)*

Two TXT records are published. They are deliberately separate: the trust anchor
must be stable, while service endpoints move.

### 2.1 Trust anchor record

Published at `_linkkeys.{domain}`:

```
v=lk1 fp={fingerprint} fp={fingerprint} fp={fingerprint}
```

- `v=lk1` MUST be present. A record without it is not a LinkKeys record. A
  record carrying a different version MUST be rejected, not ignored.
- Each `fp=` value is the lowercase hex SHA-256 digest of a signing key's public
  key bytes: exactly 64 hexadecimal characters. Comparison is case-insensitive.
- At least three `fp=` values MUST be published. See `keys.md` §2 for why three
  is a floor rather than a recommendation.
- Field order is not significant. Duplicate values are not significant.
- Only **signing** keys appear here. Encryption keys are never published in the
  anchor (§3.2).

A parser MUST accept a syntactically valid record carrying zero `fp=` values.
Rejecting it is the pinning layer's job, not the parser's — a record that parses
to an empty fingerprint set yields no trustworthy keys and fails closed
downstream.

### 2.2 Service endpoint record

Published at `_linkkeys_apis.{domain}`:

```
v=lk1 tcp={host[:port]} https={host[:port][/path]}
```

- At least one of `tcp=` or `https=` MUST be present.
- `tcp=` is the server-to-server endpoint. When the port is omitted it defaults
  to **4987**. Implementations MUST normalize a parsed value to an explicit
  `host:port`.
- `https=` is the browser-facing endpoint. The scheme is implied and MUST NOT be
  written. The port defaults to 443 and stays implicit.
- The host is always a hostname. IPv6 is reached through the hostname's AAAA
  record; an inline address literal MUST NOT be published, which is what allows
  a bare `:` to unambiguously separate host from port.

Endpoints carry no authority. Discovering an endpoint here says nothing about
whether the keys served from it are trustworthy — that is settled entirely by
the anchor record and §3.

> **Rationale.** Endpoint changes are routine operations; anchor changes are
> security events. Separating the records means moving a service does not touch
> the record whose stability the pin depends on.

### 2.3 Publication constraints

A single DNS TXT character-string is limited to 255 bytes. A longer record must
be split into multiple strings, which resolvers and zone tooling handle
inconsistently. Implementations that generate records SHOULD warn when a record
would exceed 255 bytes.

## 3. Establishing the trusted key set *(Normative)*

Given a fetched set of candidate keys and a discovered fingerprint set, an
implementation determines which keys are trustworthy as follows.

### 3.1 Signing keys are pinned directly

For each candidate key with usage `sign`, the implementation MUST **recompute**
the fingerprint from the key's public key bytes and keep the key only if that
recomputed value is a member of the discovered fingerprint set.

The `fingerprint` field transmitted alongside a key MUST NOT be trusted for this
comparison. It is attacker-controlled. An implementation that compares the wire
field against the anchor instead of recomputing has no security property at all:
a forged key claiming a pinned fingerprint would be accepted.

Fingerprint values in the anchor set that are not syntactically valid (§2.1) MUST
be ignored rather than treated as matchable.

### 3.2 Encryption keys are vouched, not pinned

Keys with usage `encrypt` are not present in the anchor. Such a key is trusted
only when a signing key that *is* pinned vouches for it.

A vouch is a signature by the signing key over the deterministic CBOR encoding
of the tuple:

```
("linkkeys-key-vouch-v1alpha", {encryption key fingerprint}, {encryption key expiry})
```

The encryption key carries the vouching key's identifier and the signature. To
accept an encryption key, an implementation MUST verify that:

1. the encryption key names a signing key that is in the pinned set, and
2. that signing key is itself currently valid — neither expired nor revoked, and
3. the signature verifies over the payload built from the **recomputed**
   encryption key fingerprint and its stated expiry.

> **Rationale.** This keeps the anchor small and lets encryption keys rotate
> without a DNS edit — re-vouch and republish in-protocol. It also means an
> encryption key can never outlive the trust of the signing key that vouched for
> it, because a revoked signer's vouches stop verifying.

### 3.3 Fail closed

Any key that is neither pinned nor vouched MUST be dropped. If the resulting
trusted set is empty, the implementation MUST treat the domain as having no
trustworthy keys and MUST NOT proceed. An empty trusted set is never equivalent
to "no constraint."

## 4. Pinning *(Normative)*

Anchor discovery over an unauthenticated binding is trust-on-first-use. Pinning
is what converts "an attacker who wins the binding at any moment wins" into "an
attacker must win first contact and sustain it."

### 4.1 Canonical pin form

A pin is the discovered fingerprint set, deduplicated and sorted. Ordering and
duplication in the published record MUST NOT change pin identity: a record that
lists the same fingerprints in a different order is the same pin.

### 4.2 Pin policy

On each discovery for a domain, compare the freshly discovered set against the
stored pin. Let *removed* be the set of pinned fingerprints that are no longer
advertised.

| Condition | Outcome | Obligation |
| --- | --- | --- |
| No stored pin | **First seen** | Store the pin. Trust. |
| Fresh set equals pin | **Unchanged** | Trust. |
| \|removed\| ≤ 1 | **Rotated** | Re-pin to the fresh set. Retire any cached copy of the removed key so it is no longer honored. Trust. |
| \|removed\| > 1 | **Mismatch** | Refuse. Escalate to a human. MUST NOT trust. |

Additions alone are never dangerous and impose no ceiling: a domain may
introduce any number of new keys in one step. The policy constrains
*disappearance*, because that is the direction in which an attacker replaces a
domain's identity.

An implementation MUST fail closed on internal error during a pin check. A
storage failure is a Mismatch, not a pass.

> **Why one removal.** Combined with the three-key floor (`keys.md` §2), a single
> permitted removal guarantees that at least two previously-pinned keys survive
> every accepted transition. Continuity is therefore always anchored by a
> majority of the prior set. If the floor were two keys, one removal would leave
> a single key vouching for the domain's identity; at one key, the rule would
> permit wholesale identity replacement by an attacker who wins the binding once.

### 4.3 Rechecking

Pins SHOULD be rechecked on an interval independent of protocol traffic, so that
a domain that is rarely contacted does not accumulate an unbounded window in
which a substituted anchor goes unnoticed. This specification does not mandate an
interval.

A Mismatch MUST be recorded durably and surfaced for human decision. The protocol
does not decide what to do about a mismatched domain; it decides only that
automatic trust stops.

## 5. Higher-assurance trust *(Reserved)*

> **Reserved.** Not implemented. Will change. MUST NOT be relied on for
> interoperability, and no conformance level includes it.

Signing authorities are intended to let a verifier accept a domain it has never
contacted, by recognizing a third party that has attested the domain controls its
published keys.

Per invariant I-3, any such mechanism raises assurance *on top of* a pin. It
never substitutes for pinning, and it never excuses a pin violation
retroactively: a domain whose pin check returns Mismatch is refused regardless of
who has signed for it.

Design sketch, obligations deliberately unstated, in
[`reserved/signing-authorities.md`](reserved/signing-authorities.md).

## 6. Subdomain delegation *(Reserved)*

> **Reserved.** Not implemented. Will change. MUST NOT be relied on for
> interoperability, and no conformance level includes it.

A subdomain is already an ordinary domain under §1–§4: it publishes its own
anchor, is pinned independently, and shares nothing with its parent but a name
suffix.

Normatively today, and under any future mechanism: an implementation MUST NOT
infer trust from name structure. Sharing a suffix with a trusted domain confers
nothing.

Delegating trust from a parent domain to a child is sketched in
[`reserved/subdomain-hierarchies.md`](reserved/subdomain-hierarchies.md).
