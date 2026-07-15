/* Sibling-signed key revocation certificate verification — mirrors
 * `crates/liblinkkeys/src/revocation.rs`. Only verification is needed
 * here; building/signing a certificate is a domain-admin/server-side
 * operation. */
#ifndef LRP_INTERNAL_REVOCATION_H
#define LRP_INTERNAL_REVOCATION_H

#include "linkkeys_local_rp.h"
#include "types.h"

#define LRP_REVOCATION_QUORUM 2

/* Recomputes `CBOR([TAG, target_key_id, target_fingerprint, revoked_at,
 * signing_domain])` — a five-element array (the older house tuple
 * pattern), NOT the two-element `[context, payload]` envelope framing.
 * Exposed for tests. */
int lrp_revocation_payload(const char *target_key_id, const char *target_fingerprint,
                            const char *revoked_at, const char *signing_domain, lrp_bytes *out,
                            lrp_error *err);

/* Counts distinct signer key ids that survive the full filtering rules
 * (conformance README, revocations.json "Verification rules"). Exposed so
 * tests can pinpoint which rule failed via expected_counted_signers. */
size_t lrp_count_revocation_signers(const lrp_w_revocation_certificate *cert,
                                     const lrp_domain_public_key *domain_keys,
                                     size_t domain_keys_count, const char *domain);

/* Requires at least LRP_REVOCATION_QUORUM distinct valid signers. */
int lrp_verify_revocation_certificate(const lrp_w_revocation_certificate *cert,
                                       const lrp_domain_public_key *domain_keys,
                                       size_t domain_keys_count, const char *domain,
                                       lrp_error *err);

#endif
