/* Claim signature/revocation/expiry verification — mirrors
 * `crates/liblinkkeys/src/claims.rs`. Only verification is needed here;
 * signing a claim is an IDP-side operation, out of scope for a local-RP
 * SDK. */
#ifndef LRP_INTERNAL_CLAIMS_H
#define LRP_INTERNAL_CLAIMS_H

#include "linkkeys_local_rp.h"

/* A signing domain and the set of its currently-known public keys, as
 * supplied to lrp_verify_claim (mirrors liblinkkeys::claims::DomainKeySet).
 * This module performs no I/O — the caller resolves/fetches these first. */
typedef struct lrp_domain_key_set {
    const char *domain;
    const lrp_domain_public_key *keys;
    size_t keys_count;
} lrp_domain_key_set;

/* Full claim verification: the cryptographic per-domain quorum (every
 * distinct domain that signed the claim must contribute at least one
 * signature from a currently-valid key of that domain, over the payload
 * bound to `subject_domain`) plus the claim's own revocation/expiry
 * (evaluated at wall-clock time, matching
 * `liblinkkeys::claims::verify_claim`). */
int lrp_verify_claim(const lrp_claim *claim, const char *subject_domain,
                      const lrp_domain_key_set *domain_key_sets, size_t domain_key_sets_count,
                      lrp_error *err);

#endif
