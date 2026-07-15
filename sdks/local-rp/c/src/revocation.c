#include "revocation.h"

#include <stdlib.h>
#include <string.h>

#include "cbor.h"
#include "crypto.h"
#include "error.h"
#include "local_rp.h"

static const char REVOCATION_TAG[] = "linkkeys-key-revocation-v1";

int lrp_revocation_payload(const char *target_key_id, const char *target_fingerprint,
                            const char *revoked_at, const char *signing_domain, lrp_bytes *out,
                            lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    int rc = 0;
    rc |= cbor_write_array_header(&b, 5);
    rc |= cbor_write_text_cstr(&b, REVOCATION_TAG);
    rc |= cbor_write_text_cstr(&b, target_key_id);
    rc |= cbor_write_text_cstr(&b, target_fingerprint);
    rc |= cbor_write_text_cstr(&b, revoked_at);
    rc |= cbor_write_text_cstr(&b, signing_domain);
    if (rc != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "revocation payload: out of memory");
    }
    *out = cbor_buf_release(&b);
    return 0;
}

size_t lrp_count_revocation_signers(const lrp_w_revocation_certificate *cert,
                                     const lrp_domain_public_key *domain_keys,
                                     size_t domain_keys_count, const char *domain) {
    /* Distinct signer key ids counted so far, bounded by signatures_count. */
    const char **counted =
        (const char **)malloc(cert->signatures_count > 0 ? cert->signatures_count * sizeof(char *) : 1);
    size_t counted_n = 0;

    for (size_t i = 0; i < cert->signatures_count; i++) {
        const lrp_claim_signature *sig = &cert->signatures[i];

        /* A key can never authorize its own revocation. */
        if (strcmp(sig->signed_by_key_id.data, cert->target_key_id.data) == 0) continue;
        /* The signature must be bound to this domain. */
        if (strcmp(sig->domain.data, domain) != 0) continue;

        const lrp_domain_public_key *key = NULL;
        for (size_t k = 0; k < domain_keys_count; k++) {
            if (strcmp(domain_keys[k].key_id.data, sig->signed_by_key_id.data) == 0) {
                key = &domain_keys[k];
                break;
            }
        }
        if (key == NULL) continue;
        /* Only a currently-valid signing key counts toward the quorum. */
        if (lrp_check_signing_key_valid(key, NULL) != 0) continue;

        lrp_bytes payload = {0};
        if (lrp_revocation_payload(cert->target_key_id.data, cert->target_fingerprint.data,
                                    cert->revoked_at.data, sig->domain.data, &payload, NULL) != 0) {
            continue;
        }
        int ok = lrp_resolve_and_verify(key->algorithm.data, payload.data, payload.len,
                                         sig->signature.data, sig->signature.len,
                                         key->public_key.data, key->public_key.len, NULL) == 0;
        lrp_bytes_free(&payload);
        if (!ok) continue;

        int already = 0;
        for (size_t c = 0; c < counted_n; c++) {
            if (strcmp(counted[c], sig->signed_by_key_id.data) == 0) {
                already = 1;
                break;
            }
        }
        if (!already) counted[counted_n++] = sig->signed_by_key_id.data;
    }

    free(counted);
    return counted_n;
}

int lrp_verify_revocation_certificate(const lrp_w_revocation_certificate *cert,
                                       const lrp_domain_public_key *domain_keys,
                                       size_t domain_keys_count, const char *domain,
                                       lrp_error *err) {
    size_t got = lrp_count_revocation_signers(cert, domain_keys, domain_keys_count, domain);
    if (got >= LRP_REVOCATION_QUORUM) return 0;
    return lrp_fail(err, LRP_ERR_REVOCATION,
                     "revocation certificate has %zu valid sibling signatures; %d required", got,
                     LRP_REVOCATION_QUORUM);
}
