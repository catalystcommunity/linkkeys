# Application keys

An application makes and keeps its own keys. The application signs its own
messages. The home domain does not sign application messages. The home domain
only attests that a public key belongs to one account, one application, and one
application instance.

This design keeps the work of the home domain proportional to key enrollment
and attestation renewal. The work is not proportional to the number of messages
or the number of peers.

## What each part does

### The application

- It makes signing key pairs and key-agreement key pairs.
- It keeps every private key local.
- It keeps more than one valid key, so that it can rotate keys safely.
- It signs its messages locally.
- It selects any valid local key for an operation.
- It approves or refuses its peers with its own policy.
- It protects itself against replayed messages.

### The home domain

- It connects an application instance to a canonical account identity.
- It verifies proof of possession at enrollment and at renewal.
- It verifies application-key quorum operations.
- It makes a short attestation for each public key.
- It publishes keys, attestations, and revocations.

The home domain does not authorize the peers of an application. It does not
read application messages. It does not sign application messages. It does not
keep application private keys.

## Identity

An account has one canonical identity. The identity is `UUID@domain`. The
`subject_user_id` field always holds that account UUID.

A profile is not a second identity. A profile only changes how an account shows
itself in a context. An application key attaches to the canonical account
identity.

A peer must keep the canonical identity of the other peer. A peer must not make
a permanent approval that depends only on a handle. A handle can move to a
different account.

## Key rules

### Key types

Ed25519 keys sign. X25519 keys do key agreement.

An X25519 key cannot sign. An X25519 key cannot be part of a quorum.

### How many keys

An instance must keep a minimum of two valid signing keys. An instance should
keep a minimum of three valid signing keys.

Three keys let two keys revoke the third key. If an instance has only two
signing keys, the two keys cannot revoke each other. The target key cannot sign
its own revocation.

All valid keys of the same type are equal. There is no preferred key. The
application selects any valid key and puts the key ID in the message.

### To add a key

Two different, currently valid signing keys must authorize a new key. This rule
applies to a signing key and to a key-agreement key.

The new key must also prove that it holds its private key. The new key cannot
be part of the two-key quorum.

### Proof of possession

An Ed25519 key proves possession directly. It signs the challenge of the home
domain.

An X25519 key cannot sign. The home domain seals a challenge to the X25519
public key. The application decrypts the challenge. The application returns the
decrypted challenge in the addition request. The addition request carries the
signatures of the quorum, so this proves control of the X25519 private key and
connects that control to the quorum.

This proof is one layer of defense. The primary control is the handshake. Put
the attested canonical identity in the handshake transcript. Use the Noise
prologue or the HPKE `info` string. A peer then finds a key that does not
belong to the identity that it expects.

### Initial enrollment

Initial enrollment is the only exception to the quorum rule. The account owner
authenticates with the home domain and approves the application instance. The
first request enrolls a minimum of two signing keys together. Each key proves
its own possession.

The application should enroll three signing keys at this time.

After initial enrollment, the normal quorum rules apply. If an application
loses the ability to make a quorum, it must do a new enrollment. A new
enrollment is a trust reset. The home domain records the trust reset.

### To renew an attestation

A key can live longer than one attestation.

Renewal makes a new attestation for the same key. Renewal does not make a new
key. The home domain refuses renewal for a revoked key. Renewal must include
current proof of possession.

Renewal is idempotent. If the current attestation keeps more than one half of
its life, the home domain returns the stored bytes. The home domain does not
make a new signature. Applications must renew when less than one half of the
life remains.

This rule is a load control. It makes the usual renewal a read of stored bytes.
It absorbs retry storms, restart storms, and clients with an incorrect clock.

The home domain also applies a quota for each subject, application, and
instance. Authentication is not a rate limit.

### To revoke a key

Two different, currently valid signing keys of the same instance must sign a
revocation. The target key must not sign its own revocation. This rule applies
to a signing key and to a key-agreement key.

Revocation is permanent. A revocation has an effective time.

A verifier judges the signers of a revocation at the effective time, not at the
time of the check. A revocation must stay verifiable after its signers expire.

## Attestations

The home domain attests each public key separately. It does not sign one list
of keys.

The signature covers the exact CBOR bytes of the attestation. The tag is
`linkkeys-application-key-attestation-v1alpha`. The home domain stores those
bytes and serves them without a change. The home domain does not sign again
when it answers a read.

A key is acceptable for use only if all of these conditions are true:

- The attestation of the home domain verifies.
- The attestation is not expired.
- The key is not expired.
- No accepted revocation applies at the time of use.
- The key type and the algorithm agree with the operation.

An expired attestation does not revoke the key. It shows that the peer does not
have current proof. A new attestation can make the same key acceptable again.

## Domain-separation tags

| Structure | Tag |
| --- | --- |
| Attestation | `linkkeys-application-key-attestation-v1alpha` |
| Addition quorum signature | `linkkeys-application-key-addition-v1alpha` |
| Proof of possession | `linkkeys-application-key-possession-v1alpha` |
| Renewal sibling signature | `linkkeys-application-key-renewal-v1alpha` |
| Revocation sibling signature | `linkkeys-application-key-revocation-v1alpha` |

The `-v1alpha` part is an epoch marker. It is not a version counter. It changes
only when the protocol leaves alpha. Do not change a tag inside one epoch.

The addition tag and the possession tag are different on purpose. The two
signatures cover the same bytes. A shared tag would let one signature be used
as the other.

## Operations

All of these operations are available on the TCP CSIL-RPC carrier.

| Service and operation | Authentication |
| --- | --- |
| `ApplicationKeys/get-application-keys` | None |
| `ApplicationKeys/start-key-challenge` | None |
| `ApplicationKeys/add-key` | The signatures of the application quorum |
| `ApplicationKeys/renew-attestation` | The proof of possession of the key |
| `ApplicationKeys/revoke-key` | The signatures of two sibling keys |
| `Account/enroll-application-instance` | The account of the user |
| `Rp/resolve-domain-keys` | The API key of the application |
| `Rp/resolve-application-keys` | The API key of the application |

The add, renew, and revoke operations do not use an API key. The authority for
these operations is the application key quorum. The signed request is the
authentication.

`start-key-challenge` gives the same answer for a known instance and for an
unknown instance. A challenge is of no use without the matching private key. A
different answer would show which instances exist.

There is no operation that lists the applications of a subject. There is no
operation that lists the instances of a subject. A caller must know all three
identifiers before it can read. This surface is a lookup, not a search.

## The public read

`ApplicationKeys/get-application-keys` is anonymous. The request has no API key
and needs no client certificate.

An anonymous response is not an untrusted response. The caller must do all of
this:

1. Find the home domain with LinkKeys DNS discovery.
2. Pin the TLS key of the server to the fingerprint set from DNS.
3. Verify every signed object in the response.
4. Get the revocations and apply them.

The revocation list is complete for the configured look-back window. The list
is never short and never paginated. A caller that read one page and stopped
could keep a revoked key that looks valid. If an instance has more records than
the configured maximum, the operation returns an error.

## Configuration

| Variable | Default | What it does |
| --- | --- | --- |
| `APPLICATION_KEY_ATTESTATION_LIFETIME_SECONDS` | `86400` | The life of one attestation. This value is also the revocation propagation window. |
| `APPLICATION_KEY_MAX_LIFETIME_SECONDS` | `31536000` | The longest key life that this domain attests. |
| `APPLICATION_KEY_REVOCATION_WINDOW_SECONDS` | `94608000` | How far back the public read reports revocations. |
| `APPLICATION_KEY_CLOCK_SKEW_SECONDS` | `300` | The permitted clock difference for each timestamp check. |
| `APPLICATION_KEY_CHALLENGE_TTL_SECONDS` | `300` | How long an issued challenge stays usable. |
| `APPLICATION_KEY_MAX_KEYS_PER_INSTANCE` | `16` | The maximum number of keys for one instance. |
| `APPLICATION_KEY_MAX_REVOCATIONS` | `1024` | The maximum number of revocation records in one response. |
| `APPLICATION_KEY_MAX_RESPONSE_BYTES` | `524288` | The maximum size of one encoded public response. |
| `APPLICATION_KEY_RENEWAL_QUOTA_PER_HOUR` | `60` | Renewals for each subject, application, and instance. |
| `APPLICATION_KEY_ADDITION_QUOTA_PER_HOUR` | `10` | Key additions for each subject, application, and instance. |

The server refuses to start if the revocation window is too short. The window
must be longer than the maximum key life plus the maximum attestation life plus
the permitted clock difference. A shorter window could remove a record that
still decides the answer. A revoked key that has not expired could then look
valid.

Lower `APPLICATION_KEY_ATTESTATION_LIFETIME_SECONDS` to make the revocation
propagation window shorter. A lower value increases the signing load on the
home domain. Keep the value much larger than the permitted clock difference.

## Cost and the warm signer

The home domain signs each attestation with its own signing keys. That
signature is the costly part of this design.

Each signing path decrypts the private key of the domain at the time of use.
That work runs Argon2id. A domain with three signing keys pays about three
Argon2id operations for one signing operation.

Attestation renewal is the first scheduled load of this type. The home domain
therefore keeps a warm signing key in memory for the attestation path. The warm
signer:

- Locks the pages of the key with `mlock`, to keep the key out of swap and out
  of a hibernation image.
- Clears the key material when it drops it.
- Removes the key at a bounded interval and derives it again.

The warm signer is not a security boundary. On Linux, one process reads the
memory of a different process only with the same user ID or with
`CAP_SYS_PTRACE`. Run the server with its own user ID. If other workloads share
the host, use process isolation, or use a PKCS#11 or KMS interface that keeps
the key out of this address space.

## Caches

Caching is a necessary part of this design. It is not an option.

The home domain caches its encoded public responses. The database stays the
source of truth. Each write that adds, renews, expires, or revokes a key clears
the affected cache entry after the database transaction is successful.

A relying-party server keeps a cache of verified remote keys, attestations, and
revocations. The relying party must not show an expired attestation as current.
If the home domain is not available, the relying party can return the last
verified records with clear freshness data. It must mark the result as stale.

A caller can ask for a shorter maximum cache age. A caller cannot ask for a
longer age than the operator permits.

### Home-domain cache configuration

| Variable | Default | What it does |
| --- | --- | --- |
| `PUBKEY_CACHE_MAX_ENTRIES` | `10000` | The most cached application-key responses the home domain keeps. |
| `PUBKEY_CACHE_MAX_BYTES` | `67108864` | The memory budget for those responses. The cache does not grow above this value. |
| `PUBKEY_CACHE_TTL_SECONDS` | `300` | How long a cached answer stays usable. A write to a key clears its entry before this time ends. |
| `PUBKEY_CACHE_NEGATIVE_TTL_SECONDS` | `10` | How long the home domain remembers that an instance does not exist. This value must stay much lower than `PUBKEY_CACHE_TTL_SECONDS`. |
| `DOMAIN_KEY_SNAPSHOT_TTL_SECONDS` | `60` | A short time limit on the domain-key snapshot. It protects against a missed invalidation, and against the recent-revocation flag going stale because time passed. |

The cache keeps the encoded bytes of a response. A cache hit does not read the
database again and does not encode the response again.

Concurrent requests that miss on the same entry make one database query. The
other requests wait for that result. This prevents a cache stampede.

### RP cache configuration

| Variable | Default | What it does |
| --- | --- | --- |
| `RP_CACHE_MAX_AGE_SECONDS` | `3600` | The most a cached answer can age before the RP fetches new data. A caller can ask for a shorter age. A caller cannot ask for a longer age. |
| `RP_CACHE_REFRESH_AHEAD_SECONDS` | `300` | How long before the maximum age ends the RP refreshes the entry on its own. |
| `RP_CACHE_MAX_ENTRIES` | `10000` | The most entries the RP keeps for each cached resource (remote domains, remote application instances). The RP removes the least-recently-used entries above this count. |
| `RP_CACHE_REVOCATION_CHECK_INTERVAL_SECONDS` | `900` | A second, shorter age limit that applies to the revocation check only. Set this lower than `RP_CACHE_MAX_AGE_SECONDS` to force more frequent revocation checks without a shorter cache life for the rest of the data. |

The RP stores the SIGNED attestation and revocation records, not a summary
built from them. This is what lets a restart keep useful cache state.

If the home domain does not answer, and the RP holds a cached answer, the RP
returns the cached answer and marks it `stale`. A stale answer is the last
verified record. It is not current trust. If the home domain does not answer,
and the RP holds no cached answer, the RP returns an error. It never returns
an empty answer as if all were well.

## Abuse controls

The public reads stay anonymous, but they have bounded abuse controls:

- A token bucket for each source IP address. The default is 100 requests each
  minute.
- A bounded count of different source addresses in each time window. The
  default threshold is 10000 sources each minute. Above the threshold, the
  server does not make new per-source state. A new source uses one shared
  overflow bucket.
- An independent global token bucket, so that a rotation of source addresses
  cannot go around the limit.

The limits use the direct socket address of the peer. The server uses a
proxy-supplied address only if the operator configures that proxy as trusted.
The server normalizes an IPv6 address to a configurable prefix. The default
prefix is `/64`.

The limits never use an application ID, a subject UUID, or an instance ID as
the key. An attacker could otherwise send a value that belongs to somebody else
and empty the bucket of that user.

### Abuse control configuration

| Variable | Default | What it does |
| --- | --- | --- |
| `PUBLIC_READ_RATE_PER_MINUTE` | `100` | Requests each minute for one source address. |
| `PUBLIC_READ_BURST` | `100` | The size of the token bucket for one source address. |
| `PUBLIC_READ_GLOBAL_RATE_PER_SECOND` | `2000` | Requests each second for all sources together. |
| `PUBLIC_READ_GLOBAL_BURST` | `4000` | The size of the global token bucket. |
| `PUBLIC_READ_DISTINCT_SOURCE_THRESHOLD` | `10000` | The most different source addresses the server tracks in one window. |
| `PUBLIC_READ_WINDOW_SECONDS` | `60` | The length of the window for the distinct-source count. |
| `PUBLIC_READ_IPV6_PREFIX` | `64` | The IPv6 prefix length the server uses to make one bucket. |
| `PUBLIC_READ_TRUSTED_PROXIES` | empty | The proxies whose supplied source address the server accepts. The server trusts no proxy by default. |
| `PUBLIC_READ_OVERFLOW_RATE_PER_SECOND` | `50` | Requests each second for all new sources together during protection mode. |
| `PUBLIC_READ_OVERFLOW_BURST` | `100` | The size of the shared overflow bucket. |
| `WARM_SIGNER_TTL_SECONDS` | `900` | How long the home domain keeps a warm signing key before it removes the key and derives it again. |

The overflow bucket is small on purpose. It exists so that protection mode does
not refuse all new sources. It does not give an attacker that changes its
address a second large budget.

The server answers a limited request with the `Unavailable` status, not with
`Forbidden`. `Forbidden` tells a client that its credentials are wrong and that
it must stop. `Unavailable` tells the client to wait and try again, which is the
correct action. The message contains the number of seconds to wait.
