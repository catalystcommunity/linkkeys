#include <stdlib.h>
#include "types.h"

#include <string.h>

#include "error.h"

/* ============================ encoders ================================ */

int lrp_encode_descriptor(const char *app_name, const char *local_domain_hint,
                           const uint8_t signing_public_key[32],
                           const uint8_t encryption_public_key[32], const char *fingerprint,
                           const char *const *supported_suites, size_t supported_suites_count,
                           const char *created_at, const char *expires_at, lrp_bytes *out,
                           lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    int has_hint = local_domain_hint != NULL;
    size_t n = 7 + (has_hint ? 1 : 0);
    int rc = 0;
    rc |= cbor_write_map_header(&b, n);
    rc |= cbor_write_text_cstr(&b, "app_name");
    rc |= cbor_write_text_cstr(&b, app_name);
    if (has_hint) {
        rc |= cbor_write_text_cstr(&b, "local_domain_hint");
        rc |= cbor_write_text_cstr(&b, local_domain_hint);
    }
    rc |= cbor_write_text_cstr(&b, "signing_public_key");
    rc |= cbor_write_bytes(&b, signing_public_key, 32);
    rc |= cbor_write_text_cstr(&b, "encryption_public_key");
    rc |= cbor_write_bytes(&b, encryption_public_key, 32);
    rc |= cbor_write_text_cstr(&b, "fingerprint");
    rc |= cbor_write_text_cstr(&b, fingerprint);
    rc |= cbor_write_text_cstr(&b, "supported_suites");
    rc |= cbor_write_array_header(&b, supported_suites_count);
    for (size_t i = 0; i < supported_suites_count && rc == 0; i++) {
        rc |= cbor_write_text_cstr(&b, supported_suites[i]);
    }
    rc |= cbor_write_text_cstr(&b, "created_at");
    rc |= cbor_write_text_cstr(&b, created_at);
    rc |= cbor_write_text_cstr(&b, "expires_at");
    rc |= cbor_write_text_cstr(&b, expires_at);
    if (rc != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode descriptor: out of memory");
    }
    *out = cbor_buf_release(&b);
    return 0;
}

int lrp_encode_login_request(const uint8_t *descriptor_cbor, size_t descriptor_cbor_len,
                              const uint8_t *descriptor_sig, size_t descriptor_sig_len,
                              const char *callback_url, const uint8_t *nonce, size_t nonce_len,
                              const uint8_t *state, size_t state_len,
                              const char *const *requested_claims, size_t requested_claims_count,
                              const char *const *required_claims, size_t required_claims_count,
                              const char *issued_at, const char *expires_at, lrp_bytes *out,
                              lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    int rc = 0;
    rc |= cbor_write_map_header(&b, 8);

    rc |= cbor_write_text_cstr(&b, "descriptor");
    rc |= cbor_write_map_header(&b, 2);
    rc |= cbor_write_text_cstr(&b, "descriptor");
    rc |= cbor_write_bytes(&b, descriptor_cbor, descriptor_cbor_len);
    rc |= cbor_write_text_cstr(&b, "signature");
    rc |= cbor_write_bytes(&b, descriptor_sig, descriptor_sig_len);

    rc |= cbor_write_text_cstr(&b, "callback_url");
    rc |= cbor_write_text_cstr(&b, callback_url);
    rc |= cbor_write_text_cstr(&b, "nonce");
    rc |= cbor_write_bytes(&b, nonce, nonce_len);
    rc |= cbor_write_text_cstr(&b, "state");
    rc |= cbor_write_bytes(&b, state, state_len);

    rc |= cbor_write_text_cstr(&b, "requested_claims");
    rc |= cbor_write_array_header(&b, requested_claims_count);
    for (size_t i = 0; i < requested_claims_count && rc == 0; i++) {
        rc |= cbor_write_text_cstr(&b, requested_claims[i]);
    }
    rc |= cbor_write_text_cstr(&b, "required_claims");
    rc |= cbor_write_array_header(&b, required_claims_count);
    for (size_t i = 0; i < required_claims_count && rc == 0; i++) {
        rc |= cbor_write_text_cstr(&b, required_claims[i]);
    }

    rc |= cbor_write_text_cstr(&b, "issued_at");
    rc |= cbor_write_text_cstr(&b, issued_at);
    rc |= cbor_write_text_cstr(&b, "expires_at");
    rc |= cbor_write_text_cstr(&b, expires_at);

    if (rc != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode login request: out of memory");
    }
    *out = cbor_buf_release(&b);
    return 0;
}

int lrp_encode_ticket_redemption_request(const uint8_t *claim_ticket, size_t claim_ticket_len,
                                          const char *fingerprint, const char *issued_at,
                                          lrp_bytes *out, lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    int rc = 0;
    rc |= cbor_write_map_header(&b, 3);
    rc |= cbor_write_text_cstr(&b, "claim_ticket");
    rc |= cbor_write_bytes(&b, claim_ticket, claim_ticket_len);
    rc |= cbor_write_text_cstr(&b, "fingerprint");
    rc |= cbor_write_text_cstr(&b, fingerprint);
    rc |= cbor_write_text_cstr(&b, "issued_at");
    rc |= cbor_write_text_cstr(&b, issued_at);
    if (rc != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode ticket redemption request: out of memory");
    }
    *out = cbor_buf_release(&b);
    return 0;
}

int lrp_encode_empty_request(lrp_bytes *out, lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    if (cbor_write_map_header(&b, 0) != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode empty request: out of memory");
    }
    *out = cbor_buf_release(&b);
    return 0;
}

int lrp_encode_get_revocations_request(const char *since, lrp_bytes *out, lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    int rc = 0;
    rc |= cbor_write_map_header(&b, since != NULL ? 1 : 0);
    if (since != NULL) {
        rc |= cbor_write_text_cstr(&b, "since");
        rc |= cbor_write_text_cstr(&b, since);
    }
    if (rc != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode get-revocations request: out of memory");
    }
    *out = cbor_buf_release(&b);
    return 0;
}

/* ============================ decoders ================================ */

static int get_fixed_bytes(const cbor_value *root, const char *key, uint8_t *out, size_t want_len,
                            lrp_error *err) {
    lrp_bytes tmp = {0};
    if (cbor_get_bytes(root, key, &tmp, err) != 0) return -1;
    if (tmp.len != want_len) {
        lrp_bytes_free(&tmp);
        return lrp_fail(err, LRP_ERR_DECODE, "field '%s' must be %zu bytes", key, want_len);
    }
    memcpy(out, tmp.data, want_len);
    lrp_bytes_free(&tmp);
    return 0;
}

/* --- LocalRpEncryptedCallback ------------------------------------------ */

void lrp_w_encrypted_callback_free(lrp_w_encrypted_callback *v) {
    if (v == NULL) return;
    lrp_bytes_free(&v->header);
    lrp_bytes_free(&v->ciphertext);
}

int lrp_decode_encrypted_callback(const uint8_t *data, size_t len, lrp_w_encrypted_callback *out,
                                   lrp_error *err) {
    memset(out, 0, sizeof(*out));
    cbor_value *root = NULL;
    if (cbor_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;
    if (cbor_get_bytes(root, "header", &out->header, err) != 0) goto done;
    if (cbor_get_bytes(root, "ciphertext", &out->ciphertext, err) != 0) goto done;
    rc = 0;
done:
    cbor_value_free(root);
    free(root);
    if (rc != 0) {
        lrp_w_encrypted_callback_free(out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

/* --- LocalRpCallbackHeader ---------------------------------------------- */

void lrp_w_callback_header_free(lrp_w_callback_header *v) {
    if (v == NULL) return;
    lrp_str_free(&v->fingerprint);
    lrp_bytes_free(&v->nonce);
    lrp_bytes_free(&v->state);
    lrp_str_free(&v->suite);
    lrp_str_free(&v->issued_at);
    lrp_str_free(&v->expires_at);
}

int lrp_decode_callback_header(const uint8_t *data, size_t len, lrp_w_callback_header *out,
                                lrp_error *err) {
    memset(out, 0, sizeof(*out));
    cbor_value *root = NULL;
    if (cbor_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;
    if (cbor_get_text(root, "fingerprint", &out->fingerprint, err) != 0) goto done;
    if (cbor_get_bytes(root, "nonce", &out->nonce, err) != 0) goto done;
    if (cbor_get_bytes(root, "state", &out->state, err) != 0) goto done;
    if (cbor_get_text(root, "suite", &out->suite, err) != 0) goto done;
    if (get_fixed_bytes(root, "ephemeral_public_key", out->ephemeral_public_key, 32, err) != 0) {
        goto done;
    }
    if (get_fixed_bytes(root, "aead_nonce", out->aead_nonce, 12, err) != 0) goto done;
    if (cbor_get_text(root, "issued_at", &out->issued_at, err) != 0) goto done;
    if (cbor_get_text(root, "expires_at", &out->expires_at, err) != 0) goto done;
    rc = 0;
done:
    cbor_value_free(root);
    free(root);
    if (rc != 0) {
        lrp_w_callback_header_free(out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

int lrp_encode_callback_header(const lrp_w_callback_header *h, lrp_bytes *out, lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    int rc = 0;
    rc |= cbor_write_map_header(&b, 8);
    rc |= cbor_write_text_cstr(&b, "fingerprint");
    rc |= cbor_write_text_cstr(&b, h->fingerprint.data);
    rc |= cbor_write_text_cstr(&b, "nonce");
    rc |= cbor_write_bytes(&b, h->nonce.data, h->nonce.len);
    rc |= cbor_write_text_cstr(&b, "state");
    rc |= cbor_write_bytes(&b, h->state.data, h->state.len);
    rc |= cbor_write_text_cstr(&b, "suite");
    rc |= cbor_write_text_cstr(&b, h->suite.data);
    rc |= cbor_write_text_cstr(&b, "ephemeral_public_key");
    rc |= cbor_write_bytes(&b, h->ephemeral_public_key, 32);
    rc |= cbor_write_text_cstr(&b, "aead_nonce");
    rc |= cbor_write_bytes(&b, h->aead_nonce, 12);
    rc |= cbor_write_text_cstr(&b, "issued_at");
    rc |= cbor_write_text_cstr(&b, h->issued_at.data);
    rc |= cbor_write_text_cstr(&b, "expires_at");
    rc |= cbor_write_text_cstr(&b, h->expires_at.data);
    if (rc != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode callback header: out of memory");
    }
    *out = cbor_buf_release(&b);
    return 0;
}

/* --- SignedLocalRpCallbackPayload ---------------------------------------- */

void lrp_w_signed_callback_payload_free(lrp_w_signed_callback_payload *v) {
    if (v == NULL) return;
    lrp_bytes_free(&v->payload);
    lrp_str_free(&v->signing_key_id);
    lrp_bytes_free(&v->signature);
}

int lrp_decode_signed_callback_payload(const uint8_t *data, size_t len,
                                        lrp_w_signed_callback_payload *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    cbor_value *root = NULL;
    if (cbor_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;
    if (cbor_get_bytes(root, "payload", &out->payload, err) != 0) goto done;
    if (cbor_get_text(root, "signing_key_id", &out->signing_key_id, err) != 0) goto done;
    if (cbor_get_bytes(root, "signature", &out->signature, err) != 0) goto done;
    rc = 0;
done:
    cbor_value_free(root);
    free(root);
    if (rc != 0) {
        lrp_w_signed_callback_payload_free(out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

/* --- LocalRpCallbackPayload ---------------------------------------------- */

void lrp_w_callback_payload_free(lrp_w_callback_payload *v) {
    if (v == NULL) return;
    lrp_str_free(&v->user_id);
    lrp_str_free(&v->user_domain);
    lrp_bytes_free(&v->claim_ticket);
    lrp_str_free(&v->audience_fingerprint);
    lrp_str_free(&v->callback_url);
    lrp_bytes_free(&v->nonce);
    lrp_bytes_free(&v->state);
    lrp_str_free(&v->issued_at);
    lrp_str_free(&v->expires_at);
}

int lrp_decode_callback_payload(const uint8_t *data, size_t len, lrp_w_callback_payload *out,
                                 lrp_error *err) {
    memset(out, 0, sizeof(*out));
    cbor_value *root = NULL;
    if (cbor_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;
    if (cbor_get_text(root, "user_id", &out->user_id, err) != 0) goto done;
    if (cbor_get_text(root, "user_domain", &out->user_domain, err) != 0) goto done;
    if (cbor_get_bytes(root, "claim_ticket", &out->claim_ticket, err) != 0) goto done;
    if (cbor_get_text(root, "audience_fingerprint", &out->audience_fingerprint, err) != 0) goto done;
    if (cbor_get_text(root, "callback_url", &out->callback_url, err) != 0) goto done;
    if (cbor_get_bytes(root, "nonce", &out->nonce, err) != 0) goto done;
    if (cbor_get_bytes(root, "state", &out->state, err) != 0) goto done;
    if (cbor_get_text(root, "issued_at", &out->issued_at, err) != 0) goto done;
    if (cbor_get_text(root, "expires_at", &out->expires_at, err) != 0) goto done;
    rc = 0;
done:
    cbor_value_free(root);
    free(root);
    if (rc != 0) {
        lrp_w_callback_payload_free(out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

/* --- ClaimSignature / Claim / DomainPublicKey / RevocationCertificate --- */

static void claim_signature_free_fields(lrp_claim_signature *s) {
    lrp_str_free(&s->domain);
    lrp_str_free(&s->signed_by_key_id);
    lrp_bytes_free(&s->signature);
}

static int decode_claim_signature_from_value(const cbor_value *v, lrp_claim_signature *out,
                                              lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (cbor_get_text(v, "domain", &out->domain, err) != 0) goto fail;
    if (cbor_get_text(v, "signed_by_key_id", &out->signed_by_key_id, err) != 0) goto fail;
    if (cbor_get_bytes(v, "signature", &out->signature, err) != 0) goto fail;
    return 0;
fail:
    claim_signature_free_fields(out);
    return -1;
}

static int decode_claim_signature_array(const cbor_value *arr, lrp_claim_signature **out,
                                         size_t *out_count, lrp_error *err) {
    *out = NULL;
    *out_count = 0;
    if (arr->items_len == 0) return 0;
    lrp_claim_signature *items =
        (lrp_claim_signature *)calloc(arr->items_len, sizeof(lrp_claim_signature));
    if (items == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    for (size_t i = 0; i < arr->items_len; i++) {
        if (decode_claim_signature_from_value(&arr->items[i], &items[i], err) != 0) {
            for (size_t j = 0; j < i; j++) claim_signature_free_fields(&items[j]);
            free(items);
            return -1;
        }
    }
    *out = items;
    *out_count = arr->items_len;
    return 0;
}

void lrp_claim_free_fields(lrp_claim *c) {
    if (c == NULL) return;
    lrp_str_free(&c->claim_id);
    lrp_str_free(&c->user_id);
    lrp_str_free(&c->claim_type);
    lrp_bytes_free(&c->claim_value);
    for (size_t i = 0; i < c->signatures_count; i++) claim_signature_free_fields(&c->signatures[i]);
    free(c->signatures);
    c->signatures = NULL;
    c->signatures_count = 0;
    lrp_str_free(&c->attested_at);
    lrp_str_free(&c->created_at);
    lrp_str_free(&c->expires_at);
    lrp_str_free(&c->revoked_at);
}

void lrp_claims_array_free(lrp_claim *arr, size_t n) {
    if (arr == NULL) return;
    for (size_t i = 0; i < n; i++) lrp_claim_free_fields(&arr[i]);
    free(arr);
}

static int decode_claim_from_value(const cbor_value *v, lrp_claim *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    const cbor_value *sig_arr;
    if (cbor_get_text(v, "claim_id", &out->claim_id, err) != 0) goto fail;
    if (cbor_get_text(v, "user_id", &out->user_id, err) != 0) goto fail;
    if (cbor_get_text(v, "claim_type", &out->claim_type, err) != 0) goto fail;
    if (cbor_get_bytes(v, "claim_value", &out->claim_value, err) != 0) goto fail;
    if (cbor_get_array(v, "signatures", &sig_arr, err) != 0) goto fail;
    if (decode_claim_signature_array(sig_arr, &out->signatures, &out->signatures_count, err) != 0) {
        goto fail;
    }
    if (cbor_get_text(v, "attested_at", &out->attested_at, err) != 0) goto fail;
    if (cbor_get_text(v, "created_at", &out->created_at, err) != 0) goto fail;
    cbor_get_text_opt(v, "expires_at", &out->expires_at);
    cbor_get_text_opt(v, "revoked_at", &out->revoked_at);
    return 0;
fail:
    lrp_claim_free_fields(out);
    return -1;
}

int lrp_decode_claim(const uint8_t *data, size_t len, lrp_claim *out, lrp_error *err) {
    cbor_value *root = NULL;
    if (cbor_decode(data, len, &root, err) != 0) return -1;
    int rc = decode_claim_from_value(root, out, err);
    cbor_value_free(root);
    free(root);
    return rc;
}

static int encode_claim_signature(const lrp_claim_signature *sig, lrp_bytes *out, lrp_error *err) {
    cbor_buf dbuf, kbuf, sbuf, outbuf;
    cbor_buf_init(&dbuf);
    cbor_buf_init(&kbuf);
    cbor_buf_init(&sbuf);
    cbor_buf_init(&outbuf);
    int rc = 0;
    rc |= cbor_write_text_cstr(&dbuf, sig->domain.data);
    rc |= cbor_write_text_cstr(&kbuf, sig->signed_by_key_id.data);
    rc |= cbor_write_bytes(&sbuf, sig->signature.data, sig->signature.len);
    cbor_map_entry entries[3] = {
        {"domain", dbuf.data, dbuf.len},
        {"signed_by_key_id", kbuf.data, kbuf.len},
        {"signature", sbuf.data, sbuf.len},
    };
    if (rc == 0) rc = cbor_write_canon_map(&outbuf, entries, 3);
    cbor_buf_free(&dbuf);
    cbor_buf_free(&kbuf);
    cbor_buf_free(&sbuf);
    if (rc != 0) {
        cbor_buf_free(&outbuf);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode claim signature: out of memory");
    }
    *out = cbor_buf_release(&outbuf);
    return 0;
}

static int encode_claim_signature_array(const lrp_claim_signature *sigs, size_t count,
                                         lrp_bytes *out, lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    if (cbor_write_array_header(&b, count) != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode claim signatures: out of memory");
    }
    for (size_t i = 0; i < count; i++) {
        lrp_bytes enc = {0};
        if (encode_claim_signature(&sigs[i], &enc, err) != 0) {
            cbor_buf_free(&b);
            return -1;
        }
        int rc = cbor_write_raw(&b, enc.data, enc.len);
        lrp_bytes_free(&enc);
        if (rc != 0) {
            cbor_buf_free(&b);
            return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode claim signatures: out of memory");
        }
    }
    *out = cbor_buf_release(&b);
    return 0;
}

int lrp_encode_claim(const lrp_claim *claim, lrp_bytes *out, lrp_error *err) {
    int has_expires = claim->expires_at.data != NULL;
    int has_revoked = claim->revoked_at.data != NULL;

    lrp_bytes sigs_bytes = {0};
    if (encode_claim_signature_array(claim->signatures, claim->signatures_count, &sigs_bytes, err) !=
        0) {
        return -1;
    }

    cbor_buf user_id_b, claim_id_b, claim_type_b, claim_value_b, attested_b, created_b, expires_b,
        revoked_b, outbuf;
    cbor_buf_init(&user_id_b);
    cbor_buf_init(&claim_id_b);
    cbor_buf_init(&claim_type_b);
    cbor_buf_init(&claim_value_b);
    cbor_buf_init(&attested_b);
    cbor_buf_init(&created_b);
    cbor_buf_init(&expires_b);
    cbor_buf_init(&revoked_b);
    cbor_buf_init(&outbuf);

    int rc = 0;
    rc |= cbor_write_text_cstr(&user_id_b, claim->user_id.data);
    rc |= cbor_write_text_cstr(&claim_id_b, claim->claim_id.data);
    rc |= cbor_write_text_cstr(&claim_type_b, claim->claim_type.data);
    rc |= cbor_write_bytes(&claim_value_b, claim->claim_value.data, claim->claim_value.len);
    rc |= cbor_write_text_cstr(&attested_b, claim->attested_at.data);
    rc |= cbor_write_text_cstr(&created_b, claim->created_at.data);
    if (has_expires) rc |= cbor_write_text_cstr(&expires_b, claim->expires_at.data);
    if (has_revoked) rc |= cbor_write_text_cstr(&revoked_b, claim->revoked_at.data);

    cbor_map_entry entries[9];
    size_t n = 0;
    entries[n++] = (cbor_map_entry){"user_id", user_id_b.data, user_id_b.len};
    entries[n++] = (cbor_map_entry){"claim_id", claim_id_b.data, claim_id_b.len};
    entries[n++] = (cbor_map_entry){"claim_type", claim_type_b.data, claim_type_b.len};
    entries[n++] = (cbor_map_entry){"claim_value", claim_value_b.data, claim_value_b.len};
    entries[n++] = (cbor_map_entry){"signatures", sigs_bytes.data, sigs_bytes.len};
    entries[n++] = (cbor_map_entry){"attested_at", attested_b.data, attested_b.len};
    entries[n++] = (cbor_map_entry){"created_at", created_b.data, created_b.len};
    if (has_expires) entries[n++] = (cbor_map_entry){"expires_at", expires_b.data, expires_b.len};
    if (has_revoked) entries[n++] = (cbor_map_entry){"revoked_at", revoked_b.data, revoked_b.len};

    if (rc == 0) rc = cbor_write_canon_map(&outbuf, entries, n);

    cbor_buf_free(&user_id_b);
    cbor_buf_free(&claim_id_b);
    cbor_buf_free(&claim_type_b);
    cbor_buf_free(&claim_value_b);
    cbor_buf_free(&attested_b);
    cbor_buf_free(&created_b);
    cbor_buf_free(&expires_b);
    cbor_buf_free(&revoked_b);
    lrp_bytes_free(&sigs_bytes);

    if (rc != 0) {
        cbor_buf_free(&outbuf);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode claim: out of memory");
    }
    *out = cbor_buf_release(&outbuf);
    return 0;
}

static void domain_public_key_free_fields_local(lrp_domain_public_key *k) {
    lrp_str_free(&k->key_id);
    lrp_bytes_free(&k->public_key);
    lrp_str_free(&k->fingerprint);
    lrp_str_free(&k->algorithm);
    lrp_str_free(&k->key_usage);
    lrp_str_free(&k->created_at);
    lrp_str_free(&k->expires_at);
    lrp_str_free(&k->revoked_at);
    lrp_str_free(&k->signed_by_key_id);
    lrp_bytes_free(&k->key_signature);
}

void lrp_domain_public_key_free_fields(lrp_domain_public_key *k) {
    domain_public_key_free_fields_local(k);
}

void lrp_domain_public_keys_array_free(lrp_domain_public_key *arr, size_t n) {
    if (arr == NULL) return;
    for (size_t i = 0; i < n; i++) domain_public_key_free_fields_local(&arr[i]);
    free(arr);
}

static int decode_domain_public_key_from_value(const cbor_value *v, lrp_domain_public_key *out,
                                                lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (cbor_get_text(v, "key_id", &out->key_id, err) != 0) goto fail;
    if (cbor_get_bytes(v, "public_key", &out->public_key, err) != 0) goto fail;
    if (cbor_get_text(v, "fingerprint", &out->fingerprint, err) != 0) goto fail;
    if (cbor_get_text(v, "algorithm", &out->algorithm, err) != 0) goto fail;
    if (cbor_get_text(v, "key_usage", &out->key_usage, err) != 0) goto fail;
    if (cbor_get_text(v, "created_at", &out->created_at, err) != 0) goto fail;
    if (cbor_get_text(v, "expires_at", &out->expires_at, err) != 0) goto fail;
    cbor_get_text_opt(v, "revoked_at", &out->revoked_at);
    cbor_get_text_opt(v, "signed_by_key_id", &out->signed_by_key_id);
    cbor_get_bytes_opt(v, "key_signature", &out->key_signature);
    return 0;
fail:
    domain_public_key_free_fields_local(out);
    return -1;
}

/* --- LocalRpTicketRedemptionResponse -------------------------------------- */

void lrp_w_ticket_redemption_response_free(lrp_w_ticket_redemption_response *v) {
    if (v == NULL) return;
    lrp_str_free(&v->user_id);
    lrp_str_free(&v->user_domain);
    lrp_claims_array_free(v->claims, v->claims_count);
    v->claims = NULL;
    v->claims_count = 0;
    lrp_str_free(&v->ticket_expires_at);
}

int lrp_decode_ticket_redemption_response(const uint8_t *data, size_t len,
                                           lrp_w_ticket_redemption_response *out,
                                           lrp_error *err) {
    memset(out, 0, sizeof(*out));
    cbor_value *root = NULL;
    if (cbor_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;
    const cbor_value *claims_arr;
    if (cbor_get_text(root, "user_id", &out->user_id, err) != 0) goto done;
    if (cbor_get_text(root, "user_domain", &out->user_domain, err) != 0) goto done;
    if (cbor_get_array(root, "claims", &claims_arr, err) != 0) goto done;
    if (claims_arr->items_len > 0) {
        out->claims = (lrp_claim *)calloc(claims_arr->items_len, sizeof(lrp_claim));
        if (out->claims == NULL) {
            lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
            goto done;
        }
        for (size_t i = 0; i < claims_arr->items_len; i++) {
            if (decode_claim_from_value(&claims_arr->items[i], &out->claims[i], err) != 0) {
                out->claims_count = i;
                goto done;
            }
        }
        out->claims_count = claims_arr->items_len;
    }
    if (cbor_get_text(root, "ticket_expires_at", &out->ticket_expires_at, err) != 0) goto done;
    rc = 0;
done:
    cbor_value_free(root);
    free(root);
    if (rc != 0) {
        lrp_w_ticket_redemption_response_free(out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

int lrp_encode_ticket_redemption_response(const lrp_w_ticket_redemption_response *resp,
                                           lrp_bytes *out, lrp_error *err) {
    lrp_bytes claims_bytes = {0};
    {
        cbor_buf cb;
        cbor_buf_init(&cb);
        if (cbor_write_array_header(&cb, resp->claims_count) != 0) {
            cbor_buf_free(&cb);
            return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY,
                             "encode ticket redemption response: out of memory");
        }
        int rc = 0;
        for (size_t i = 0; i < resp->claims_count; i++) {
            lrp_bytes enc = {0};
            if (lrp_encode_claim(&resp->claims[i], &enc, err) != 0) {
                rc = -1;
                break;
            }
            int wr = cbor_write_raw(&cb, enc.data, enc.len);
            lrp_bytes_free(&enc);
            if (wr != 0) {
                rc = lrp_fail(err, LRP_ERR_OUT_OF_MEMORY,
                               "encode ticket redemption response: out of memory");
                break;
            }
        }
        if (rc != 0) {
            cbor_buf_free(&cb);
            return -1;
        }
        claims_bytes = cbor_buf_release(&cb);
    }

    cbor_buf user_id_b, user_domain_b, ticket_expires_b, outbuf;
    cbor_buf_init(&user_id_b);
    cbor_buf_init(&user_domain_b);
    cbor_buf_init(&ticket_expires_b);
    cbor_buf_init(&outbuf);
    int rc = 0;
    rc |= cbor_write_text_cstr(&user_id_b, resp->user_id.data);
    rc |= cbor_write_text_cstr(&user_domain_b, resp->user_domain.data);
    rc |= cbor_write_text_cstr(&ticket_expires_b, resp->ticket_expires_at.data);

    cbor_map_entry entries[4] = {
        {"claims", claims_bytes.data, claims_bytes.len},
        {"user_id", user_id_b.data, user_id_b.len},
        {"user_domain", user_domain_b.data, user_domain_b.len},
        {"ticket_expires_at", ticket_expires_b.data, ticket_expires_b.len},
    };
    if (rc == 0) rc = cbor_write_canon_map(&outbuf, entries, 4);

    cbor_buf_free(&user_id_b);
    cbor_buf_free(&user_domain_b);
    cbor_buf_free(&ticket_expires_b);
    lrp_bytes_free(&claims_bytes);

    if (rc != 0) {
        cbor_buf_free(&outbuf);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode ticket redemption response: out of memory");
    }
    *out = cbor_buf_release(&outbuf);
    return 0;
}

/* --- GetDomainKeysResponse ----------------------------------------------- */

void lrp_w_get_domain_keys_response_free(lrp_w_get_domain_keys_response *v) {
    if (v == NULL) return;
    lrp_str_free(&v->domain);
    lrp_domain_public_keys_array_free(v->keys, v->keys_count);
    v->keys = NULL;
    v->keys_count = 0;
}

int lrp_decode_get_domain_keys_response(const uint8_t *data, size_t len,
                                         lrp_w_get_domain_keys_response *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    cbor_value *root = NULL;
    if (cbor_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;
    const cbor_value *keys_arr;
    if (cbor_get_text(root, "domain", &out->domain, err) != 0) goto done;
    if (cbor_get_array(root, "keys", &keys_arr, err) != 0) goto done;
    if (keys_arr->items_len > 0) {
        out->keys = (lrp_domain_public_key *)calloc(keys_arr->items_len, sizeof(lrp_domain_public_key));
        if (out->keys == NULL) {
            lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
            goto done;
        }
        for (size_t i = 0; i < keys_arr->items_len; i++) {
            if (decode_domain_public_key_from_value(&keys_arr->items[i], &out->keys[i], err) != 0) {
                out->keys_count = i;
                goto done;
            }
        }
        out->keys_count = keys_arr->items_len;
    }
    {
        int present = 0, value = 0;
        cbor_get_bool_opt(root, "recent_revocations_available", &present, &value);
        out->recent_revocations_present = present;
        out->recent_revocations_available = value;
    }
    rc = 0;
done:
    cbor_value_free(root);
    free(root);
    if (rc != 0) {
        lrp_w_get_domain_keys_response_free(out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

/* --- RevocationCertificate / GetRevocationsResponse ----------------------- */

void lrp_w_revocation_certificate_free(lrp_w_revocation_certificate *v) {
    if (v == NULL) return;
    lrp_str_free(&v->target_key_id);
    lrp_str_free(&v->target_fingerprint);
    lrp_str_free(&v->revoked_at);
    for (size_t i = 0; i < v->signatures_count; i++) claim_signature_free_fields(&v->signatures[i]);
    free(v->signatures);
    v->signatures = NULL;
    v->signatures_count = 0;
}

static int decode_revocation_certificate_from_value(const cbor_value *v,
                                                      lrp_w_revocation_certificate *out,
                                                      lrp_error *err) {
    memset(out, 0, sizeof(*out));
    const cbor_value *sig_arr;
    if (cbor_get_text(v, "target_key_id", &out->target_key_id, err) != 0) goto fail;
    if (cbor_get_text(v, "target_fingerprint", &out->target_fingerprint, err) != 0) goto fail;
    if (cbor_get_text(v, "revoked_at", &out->revoked_at, err) != 0) goto fail;
    if (cbor_get_array(v, "signatures", &sig_arr, err) != 0) goto fail;
    if (decode_claim_signature_array(sig_arr, &out->signatures, &out->signatures_count, err) != 0) {
        goto fail;
    }
    return 0;
fail:
    lrp_w_revocation_certificate_free(out);
    return -1;
}

int lrp_decode_revocation_certificate(const uint8_t *data, size_t len,
                                       lrp_w_revocation_certificate *out, lrp_error *err) {
    cbor_value *root = NULL;
    if (cbor_decode(data, len, &root, err) != 0) return -1;
    int rc = decode_revocation_certificate_from_value(root, out, err);
    cbor_value_free(root);
    free(root);
    return rc;
}

void lrp_w_get_revocations_response_free(lrp_w_get_revocations_response *v) {
    if (v == NULL) return;
    for (size_t i = 0; i < v->count; i++) lrp_w_revocation_certificate_free(&v->items[i]);
    free(v->items);
    v->items = NULL;
    v->count = 0;
}

int lrp_decode_get_revocations_response(const uint8_t *data, size_t len,
                                         lrp_w_get_revocations_response *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    cbor_value *root = NULL;
    if (cbor_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;
    const cbor_value *arr;
    if (cbor_get_array(root, "revocations", &arr, err) != 0) goto done;
    if (arr->items_len > 0) {
        out->items =
            (lrp_w_revocation_certificate *)calloc(arr->items_len, sizeof(lrp_w_revocation_certificate));
        if (out->items == NULL) {
            lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
            goto done;
        }
        for (size_t i = 0; i < arr->items_len; i++) {
            if (decode_revocation_certificate_from_value(&arr->items[i], &out->items[i], err) != 0) {
                out->count = i;
                goto done;
            }
        }
        out->count = arr->items_len;
    }
    rc = 0;
done:
    cbor_value_free(root);
    free(root);
    if (rc != 0) {
        lrp_w_get_revocations_response_free(out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}
