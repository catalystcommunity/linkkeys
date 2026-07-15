/* DNS TXT record parsing, fingerprint pinning, and signing-key vouch
 * verification — mirrors `crates/liblinkkeys/src/dns.rs`. This module
 * performs no I/O itself except `lrp_default_dns_resolver`'s
 * implementation (libresolv `res_query`); parsing/pinning/vouching are
 * pure and directly conformance-tested against `dns.json`.
 */
#ifndef LRP_INTERNAL_DNS_H
#define LRP_INTERNAL_DNS_H

#include "cbor.h"
#include "linkkeys_local_rp.h"

#define LRP_DEFAULT_TCP_PORT 4987

typedef enum lrp_dns_parse_error {
    LRP_DNS_ERR_NONE = 0,
    LRP_DNS_ERR_MISSING_VERSION,
    LRP_DNS_ERR_UNSUPPORTED_VERSION,
    LRP_DNS_ERR_MISSING_APIS_ENDPOINT,
} lrp_dns_parse_error;

/* Symbolic name matching dns.json's expected_error strings. */
const char *lrp_dns_parse_error_name(lrp_dns_parse_error e);

/* "_linkkeys." + domain / "_linkkeys_apis." + domain, heap-allocated. */
int lrp_linkkeys_dns_name(const char *domain, lrp_str *out, lrp_error *err);
int lrp_linkkeys_apis_dns_name(const char *domain, lrp_str *out, lrp_error *err);

typedef struct lrp_linkkeys_record {
    char **fingerprints;
    size_t fingerprints_count;
} lrp_linkkeys_record;
void lrp_linkkeys_record_free(lrp_linkkeys_record *r);

/* Parse a single `_linkkeys` TXT record string. */
lrp_dns_parse_error lrp_parse_linkkeys_txt(const char *txt, lrp_linkkeys_record *out);

typedef struct lrp_linkkeys_apis {
    lrp_str tcp;        /* .data == NULL if absent */
    lrp_str https_base; /* .data == NULL if absent */
} lrp_linkkeys_apis;
void lrp_linkkeys_apis_free(lrp_linkkeys_apis *a);

/* Parse a single `_linkkeys_apis` TXT record string. */
lrp_dns_parse_error lrp_parse_linkkeys_apis_txt(const char *txt, lrp_linkkeys_apis *out);

int lrp_is_valid_fingerprint(const char *fp);

/* Establish the trusted key set from a fetched key list and the DNS-pinned
 * fingerprint set: signing keys are pinned directly (recomputed
 * fingerprint must be a pinned member); encryption keys are trusted only
 * when a pinned signing key vouches for them. Deep-copies the kept keys
 * into a freshly allocated array (caller frees with
 * lrp_domain_public_keys_array_free); an empty result means "no
 * trustworthy keys" and callers MUST fail closed. */
int lrp_trust_keys(const lrp_domain_public_key *keys, size_t keys_count, const char *const *pinned,
                    size_t pinned_count, lrp_domain_public_key **out_trusted,
                    size_t *out_trusted_count, lrp_error *err);

/* --------------------------------------------------------------------- */
/* DNS TXT lookup: default resolver (libresolv)                          */
/* --------------------------------------------------------------------- */

lrp_dns_resolver lrp_default_dns_resolver(void);

#endif
