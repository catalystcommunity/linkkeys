#include "claims.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"
#include "crypto.h"
#include "error.h"
#include "local_rp.h"
#include "time_util.h"

static const char CLAIM_PAYLOAD_TAG[] = "linkkeys-claim-v2";

/* `(TAG, claim_id, claim_type, claim_value: bstr, "user_id@subject_domain",
 * signing_domain, expires_at: tstr/null, attested_at)` — an 8-element CBOR
 * array (Rust tuple encoding), matching
 * `liblinkkeys::claims::claim_sign_payload` exactly. */
static int claim_sign_payload(const lrp_claim *claim, const char *subject_domain,
                               const char *signing_domain, lrp_bytes *out, lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    int rc = 0;
    rc |= cbor_write_array_header(&b, 8);
    rc |= cbor_write_text_cstr(&b, CLAIM_PAYLOAD_TAG);
    rc |= cbor_write_text_cstr(&b, claim->claim_id.data);
    rc |= cbor_write_text_cstr(&b, claim->claim_type.data);
    rc |= cbor_write_bytes(&b, claim->claim_value.data, claim->claim_value.len);
    {
        size_t len = strlen(claim->user_id.data) + 1 + strlen(subject_domain) + 1;
        char *subject = (char *)malloc(len);
        if (subject == NULL) {
            cbor_buf_free(&b);
            return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
        }
        snprintf(subject, len, "%s@%s", claim->user_id.data, subject_domain);
        rc |= cbor_write_text_cstr(&b, subject);
        free(subject);
    }
    rc |= cbor_write_text_cstr(&b, signing_domain);
    rc |= cbor_write_opt_text_cstr(&b, claim->expires_at.data);
    rc |= cbor_write_text_cstr(&b, claim->attested_at.data);
    if (rc != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "claim sign payload: out of memory");
    }
    *out = cbor_buf_release(&b);
    return 0;
}

static int verify_one_signature(const lrp_claim_signature *sig, const uint8_t *payload,
                                 size_t payload_len, const lrp_domain_public_key *keys,
                                 size_t keys_count, lrp_error *err) {
    const lrp_domain_public_key *key = NULL;
    for (size_t i = 0; i < keys_count; i++) {
        if (strcmp(keys[i].key_id.data, sig->signed_by_key_id.data) == 0) {
            key = &keys[i];
            break;
        }
    }
    if (key == NULL) {
        return lrp_fail(err, LRP_ERR_CLAIM, "signing key not found: %s", sig->signed_by_key_id.data);
    }
    if (strcmp(key->key_usage.data, "sign") != 0) {
        return lrp_fail(err, LRP_ERR_CLAIM, "claim signature verification failed");
    }
    if (lrp_check_signing_key_valid(key, err) != 0) {
        err->code = LRP_ERR_CLAIM;
        return -1;
    }
    if (lrp_resolve_and_verify(key->algorithm.data, payload, payload_len, sig->signature.data,
                                sig->signature.len, key->public_key.data, key->public_key.len,
                                err) != 0) {
        err->code = LRP_ERR_CLAIM;
        return -1;
    }
    return 0;
}

static int find_domain_key_set(const lrp_domain_key_set *sets, size_t n, const char *domain,
                                const lrp_domain_key_set **out) {
    for (size_t i = 0; i < n; i++) {
        if (strcmp(sets[i].domain, domain) == 0) {
            *out = &sets[i];
            return 1;
        }
    }
    return 0;
}

static int domain_already_seen(const char **seen, size_t seen_n, const char *domain) {
    for (size_t i = 0; i < seen_n; i++) {
        if (strcmp(seen[i], domain) == 0) return 1;
    }
    return 0;
}

static int verify_claim_signatures(const lrp_claim *claim, const char *subject_domain,
                                    const lrp_domain_key_set *domain_key_sets,
                                    size_t domain_key_sets_count, lrp_error *err) {
    if (claim->signatures_count == 0) {
        return lrp_fail(err, LRP_ERR_CLAIM, "claim has no signatures");
    }

    const char **seen = (const char **)malloc(claim->signatures_count * sizeof(char *));
    if (seen == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    size_t seen_n = 0;

    int rc = 0;
    for (size_t i = 0; i < claim->signatures_count && rc == 0; i++) {
        const char *signing_domain = claim->signatures[i].domain.data;
        if (domain_already_seen(seen, seen_n, signing_domain)) continue;
        seen[seen_n++] = signing_domain;

        const lrp_domain_key_set *set = NULL;
        if (!find_domain_key_set(domain_key_sets, domain_key_sets_count, signing_domain, &set)) {
            rc = lrp_fail(err, LRP_ERR_CLAIM, "no public keys available for signing domain: %s",
                           signing_domain);
            break;
        }

        lrp_bytes payload = {0};
        if (claim_sign_payload(claim, subject_domain, signing_domain, &payload, err) != 0) {
            rc = -1;
            break;
        }

        int satisfied = 0;
        lrp_error last_err = {0};
        last_err.code = LRP_ERR_CLAIM;
        snprintf(last_err.message, sizeof(last_err.message),
                 "no valid signature for signing domain: %s", signing_domain);
        for (size_t j = 0; j < claim->signatures_count; j++) {
            if (strcmp(claim->signatures[j].domain.data, signing_domain) != 0) continue;
            lrp_error try_err = {0};
            if (verify_one_signature(&claim->signatures[j], payload.data, payload.len,
                                      set->keys, set->keys_count, &try_err) == 0) {
                satisfied = 1;
                break;
            }
            last_err = try_err;
        }
        lrp_bytes_free(&payload);
        if (!satisfied) {
            if (err != NULL) *err = last_err;
            rc = -1;
        }
    }
    free(seen);
    return rc;
}

int lrp_verify_claim(const lrp_claim *claim, const char *subject_domain,
                      const lrp_domain_key_set *domain_key_sets, size_t domain_key_sets_count,
                      lrp_error *err) {
    if (verify_claim_signatures(claim, subject_domain, domain_key_sets, domain_key_sets_count,
                                 err) != 0) {
        return -1;
    }
    if (claim->revoked_at.data != NULL) {
        return lrp_fail(err, LRP_ERR_CLAIM, "claim has been revoked");
    }
    if (claim->expires_at.data != NULL) {
        int64_t expires;
        if (lrp_parse_rfc3339(claim->expires_at.data, &expires, NULL) != 0) {
            return lrp_fail(err, LRP_ERR_CLAIM, "claim has an invalid expires_at");
        }
        if (lrp_wall_clock_now() > expires) {
            return lrp_fail(err, LRP_ERR_CLAIM, "claim has expired");
        }
    }
    return 0;
}
