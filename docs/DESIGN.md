# LinkKeys Design

LinkKeys is a specification and reference implementation for distributed, federated identity built on public key infrastructure. It provides actual single sign-on — not "login with a provider" — across the entire internet, controlled by domain administrators and their users rather than corporations.

## Core Philosophy

**Technology cannot solve social problems, but it can build tools that enable humans to solve their own social problems.**

This principle governs every design decision. We provide cryptographic primitives and protocols. Humans decide how to use them. We never enforce policy where we can instead enable choice.

### Design Priorities (ordered)

1. **Non-technical users come first.** My mother should enjoy a secure digital life without understanding cryptography. If she has to think about keys, we failed.
2. **Security by default.** Every default must be the safe choice. Unsafe options may exist but require deliberate action.
3. **Simplicity over cleverness.** Simpler is better. Three similar lines beat a premature abstraction. A clear protocol beats an optimized one.
4. **Assume malice and incompetence.** Every feature must be evaluated against both malicious and incompetent actors before it ships.
5. **Ease of administration.** Domain admins must have simple tooling and clear docs. Making security easy is how you get security adopted.
6. **Developer accessibility.** Consuming developers — mobile, web, systems, embedded — should not need to understand PKI internals to integrate.

## Identity Model

### What is an identity?

An identity is:

- A UUID (v4 or v7)
- At a domain (domain.tld or sub.domain.tld)
- With a set of public/private keypairs

That's it. Everything meaningful to humans — display name, age verification, organizational role — is expressed through signed claims, not baked into the identity itself.

### Key Hierarchy

```
Domain Keys (≥3, equal, held on domain server(s))
  └── User Keys (held on domain server, never leave it)
        └── Device Keys (held on device, never leave it)
              └── App Keys (per-application, signed by device key)
```

- **Domain keys** are the root of trust. At least three, for redundancy and rotation without disruption. Published as fingerprints in DNS TXT records at the `@` record for the domain. Keys are equal — no special roles (signing vs encryption vs revocation). Any can do anything.
- **User keys** are custodied by the domain server. The user's private keys never leave the domain server. This means a lost device is an inconvenience, not a catastrophe. The domain admin is a custodian — users must trust their domain admin, just as they trust their email provider today, but with better tooling for accountability.
- **Device keys** live in the device's secure enclave (or best available equivalent). The device private key never leaves the device. Trust with the domain is established through the device's public key.
- **App keys** are per-application (browser, email client, etc.) and signed by the device key. Applications enroll in the trust relationship through the device.

### Key Properties

- **Algorithm:** Ed25519 for signing, X25519 for encryption. Algorithm negotiation is built into the protocol from day one for future evolution. No backwards compatibility with older algorithms — old systems that cannot upgrade are a problem for their users to proxy.
- **Ephemeral by design.** Keys should be short-lived. Rotation and revocation are first-class operations, not exceptional events. Losing a key is normal. An archive from 20 years ago just needs the cached public key from that era to verify, because trust was established at time of transmission.
- **Revocation is timestamped in UTC.** Messages received after a revocation timestamp are suspect. Messages before it remain valid. No retroactive invalidation. Human choice governs what to do with suspect messages.

## Trust Model

### DNS-Based Key Discovery

A domain publishes at least three key fingerprints in DNS TXT records at its `@` record. This is the root anchor — if you own the DNS, you control your identity.

### Key Signing (Web of Trust)

When a domain is not yet trusted, the verifier asks: "Who signed your keys?"

**Signing process:**

1. A signing service (anyone can run one; the project will operate at least one free instance) periodically inspects a domain's TXT records from public DNS.
2. The signing service validates that the domain controls the private keys matching those fingerprints (via challenge or message verification). An additional DNS challenge step can be used for stronger assurance.
3. The signing service signs each of the domain's keys with each of its own private keys (at least three).
4. The domain stores these signatures in TXT records referencing the signing service's domain (not at `@`, which is reserved for the domain's own fingerprints).

**Verification process:**

1. Verifier encounters an untrusted domain.
2. Verifier asks for the domain's signing authorities (a list of domains).
3. If the verifier already trusts any of those signing authorities, it fetches that authority's TXT records and validates the signatures against cached public keys.
4. Signing timestamps (UTC) determine freshness. The verifier decides how long to trust without re-verification. Suggested default: ~3 months. Signing services should re-sign monthly. But we're not anyone's boss.

This is structurally similar to TLS certificate authorities, but without payment or corporate gatekeeping. Anyone can be a signing authority. Trust is earned socially, not purchased.

### Trust Hierarchies

Subdomains (sub.domain.tld) can participate in trust hierarchies under their parent domain. The mechanics follow the same pattern — key fingerprints in DNS, signing by parent or external authorities.

### Caching

Caching public keys is encouraged. Third parties could build large caches of historical public keys for verification of old messages. The system does not depend on this but benefits from it.

## Claims

A claim is:

- A string key (the claim type)
- A value of bytes (the claim content)
- A signature over the whole thing

Claims are signed individually so users and domains can decide which to share, with whom, and when. Claims can be signed by multiple parties — a user's domain signs it, and a third party (like a government agency) can countersign it.

**Example:** A DMV employee (who doesn't need to understand cryptography) scans a QR code, verifies physical documents, and the DMV's domain signs an "over-21" claim for the user. The user can present this claim to any service that trusts the DMV's domain as a claim authority. The claim may include the user's domain as a binding, so it cannot be transferred without the issuer's awareness.

Claims are the only mechanism for conveying human-meaningful information. The protocol itself only deals with UUIDs, keys, and signatures.

## Protocol

### Wire Format

CBOR is the wire protocol in all cases. Efficient binary encoding matters for low-end hardware and scale.

JSON wrappers will be provided as an optional part of the spec for web browser consumption, potentially via WASM. The core protocol is CBOR. JSON is a convenience layer, not a first-class citizen.

### Service Definitions

All services and data structures are defined in CSIL (CBOR Service Interface Language). CSIL definitions live in `csil/` and are used to generate protocol types, serialization code, and validation logic. The CSIL definitions are part of the spec.

### Transport

The protocol is transport-agnostic but TCP is preferred. HTTP flows exist where needed (web enrollment, browser-based interactions) but are not the primary transport. A single server binary should handle everything — no requirement to run multiple services to participate in the ecosystem.

### Negotiation

Protocol version and algorithm negotiation happen at handshake. This is critical because the system is distributed and we control only the suggested spec, not actual deployments. Good negotiation from the start prevents painful migrations later.

### Versioning

The protocol is versioned. The spec will maintain multiple active versions with deprecation periods. Like email, once a flow is supported in the wild, it's difficult to close. Negotiation on handshake determines which version is used for a given interaction.

## Authentication Flows

### Device Enrollment

When a user's device is not yet enrolled with their domain:

1. The user is directed to an enrollment interface (webpage, native app, whatever the domain provides).
2. The interface communicates with the domain server.
3. The user proves their identity (login, existing session, admin-assisted, etc.).
4. The device's public key is registered with the domain server.
5. After enrollment, the device can silently authenticate — the user sees nothing unless something is wrong.

### Cross-Domain Authentication (the "login" flow)

When a user visits a new service:

1. Three-way negotiation: user ↔ user's domain server ↔ service's domain server.
2. Trust is established between the two domains (via key signing verification).
3. Identity is exchanged with only the claims approved for that service.
4. The user is "logged in" in whatever way the service handles sessions. The service is encouraged to maintain its own internal account tied to UUID@domain.tld, but the service does not own the identity.

The user (like my mother) ideally sees nothing. It just works.

### Domain Migration

Migration between domains is encouraged but not enforced (we can't enforce it). A base expectation of one year of redirection is suggested. Domain A can sign claims for domain B asserting that a user has migrated. Trust tooling should keep humans in the loop for migration verification. Refusing to allow migration is a socially unacceptable position, but we provide tools, not mandates.

## Threat Model

### Priority 1: Compromised Domain Server

The most critical technical threat. Domain servers hold user private keys.

**Mitigations:**
- At least three domain keys, distributable across multiple servers in different locations.
- If one server is compromised (even by a nation-state): revoke its key at the other servers, remove it from DNS TXT records, generate a new server/key.
- Encrypted backups with long passphrases are standard practice, with tooling to make this easy.
- Multi-admin signing for sensitive operations (a primitive we provide; adoption is a domain's choice).

### Priority 2: Malicious Domain Admin

A social problem with technical mitigations.

**Mitigations:**
- Device keys provide a check — certain actions require device key signatures that the admin cannot forge.
- Multi-admin primitives so critical actions require multiple signers.
- Users should not join domains they do not trust. Easy self-hosting with clear instructions is the escape valve.
- Migration tooling lets users leave.

### Priority 3: Compromised Device

Annoying but manageable.

**Mitigations:**
- Device keys are just device keys. Revoking them at the domain server is straightforward.
- OS-level secure enclave integration via the SDK makes key extraction difficult.
- App-level keys limit blast radius — one compromised app doesn't compromise the device identity.
- Rootkits make enforcement impossible, but that's a social problem (what you install), and this system provides better security than app-store curation.

### Priority 4: Social Engineering / Phishing

Technology cannot solve this. But tools can help.

**Mitigations:**
- Claim-based permissions allow delegation: "require my co-signer for banking transactions" so a family member can protect a vulnerable user.
- Domain admins can deny trust with unknown domains, blocking entire classes of phishing.
- Spam blocking works across domains — block individual users or entire domains that don't control their users' behavior.
- Reputation systems become easy to build on top of these primitives (but reputation is not part of this spec).

### Priority 5: Nation-State Adversary

Geo-distribute domain services. Beyond that, there are limits to what any system can do against this level of adversary. Not a primary design target.

## Error Handling

Helpful error messages are required — ease of use is the point. Security means:

- Never log sensitive information (keys, claim values, session tokens).
- Describe how to get more information rather than dumping internals.
- Errors should help developers and admins diagnose problems without leaking information that aids attackers.

## Project Structure

```
linkkeys/
├── crates/
│   ├── liblinkkeys/        # Core library — all protocol logic, crypto, types
│   └── linkkeys/           # Server binary — CLI, TCP/HTTP, database, plugins
├── csil/                   # CSIL service and type definitions (part of the spec)
├── docs/                   # Design docs and eventually the formal spec
├── migrations/             # Database migrations
├── website/                # Static site (pysocha, eventually)
└── diesel.toml
```

### Where things go

- **Protocol types, cryptographic operations, key management logic, claim handling, serialization/deserialization, algorithm negotiation** → `liblinkkeys`. This is the library other languages and implementations consume. It must have zero I/O dependencies where possible (for future WASM targets). System-level operations (secure enclave access) may need feature-gated modules.
- **Server lifecycle, CLI, database access, network listeners, HTTP routes, plugin hosting** → `linkkeys` (the binary crate).
- **Service definitions, message schemas, protocol data structures** → `csil/`. These are the source of truth. Generated code flows into the appropriate crate.
- **Spec documents, design rationale, admin guides** → `docs/`.

### Adding a new feature

1. Ask: "How does a malicious actor abuse this?" and "How does an incompetent user misuse this?" Answer both before writing code.
2. Define the data structures and service interfaces in CSIL first.
3. Implement the core logic in `liblinkkeys` with no I/O dependencies.
4. Expose it through the server binary if it requires network/database access.
5. Write tests. They must pass before merge. No exceptions.

## Codebase Guidelines

### Tests

- All tests must pass at all times. A broken test is a blocking issue.
- Unit tests for cryptographic correctness and protocol logic in `liblinkkeys`.
- Integration tests from the API back through to a real database using the DataUtils pattern — tests run inside a transaction for isolation and rollback.
- The compliance test suite (for validating other implementations) is separate and does not test this implementation's internals. It speaks the protocol to a target server and validates behavior, including failure cases.

### Simplicity

- Simpler is better. Do the simplest thing that works.
- Don't abstract until you must. Don't optimize until you've measured.
- Every dependency is a liability. Justify each one.

### Security

- Every default is the safe default.
- Never log sensitive information.
- Assume every input is hostile at system boundaries.
- Key material handling follows the principle of least exposure — keys exist in memory for the minimum time necessary.

### The Spec

LinkKeys is a specification first and an implementation second. This repo is the reference implementation. The CSIL definitions and documentation in `docs/` are the spec. A separate compliance test suite will allow any implementation to validate itself. The spec is free, open, and must remain so. The incentives require it.
