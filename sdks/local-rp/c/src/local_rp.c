#include <stdlib.h>
#include "local_rp.h"

#include <string.h>
#include <time.h>

#include <openssl/crypto.h>

#include "error.h"
#include "time_util.h"

static const char LOCAL_RP_CALLBACK_BOX_TAG[] = "linkkeys-local-rp-callback-box";

int lrp_envelope_signature_input(const char *context, const uint8_t *payload, size_t payload_len,
                                  lrp_bytes *out, lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    int rc = 0;
    rc |= cbor_write_array_header(&b, 2);
    rc |= cbor_write_text_cstr(&b, context);
    rc |= cbor_write_bytes(&b, payload, payload_len);
    if (rc != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "envelope signature input: out of memory");
    }
    *out = cbor_buf_release(&b);
    return 0;
}

int lrp_sign_envelope(const char *context, const uint8_t *payload, size_t payload_len,
                       const uint8_t signing_private_key[32], lrp_bytes *out_signature,
                       lrp_error *err) {
    lrp_bytes sig_input = {0};
    if (lrp_envelope_signature_input(context, payload, payload_len, &sig_input, err) != 0) {
        return -1;
    }
    uint8_t sig[64];
    int rc = lrp_ed25519_sign(signing_private_key, sig_input.data, sig_input.len, sig, err);
    lrp_bytes_free(&sig_input);
    if (rc != 0) return -1;
    uint8_t *heap_sig = (uint8_t *)malloc(64);
    if (heap_sig == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    memcpy(heap_sig, sig, 64);
    out_signature->data = heap_sig;
    out_signature->len = 64;
    return 0;
}

int64_t lrp_wall_clock_now(void) { return (int64_t)time(NULL); }

int lrp_check_timestamps(const char *issued_at, const char *expires_at, int64_t now_unix,
                          int64_t skew_seconds, lrp_error *err) {
    int64_t issued, expires;
    if (lrp_parse_rfc3339(issued_at, &issued, err) != 0) return -1;
    if (lrp_parse_rfc3339(expires_at, &expires, err) != 0) return -1;
    if (now_unix + skew_seconds < issued) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "timestamp is not yet valid");
    }
    if (now_unix - skew_seconds > expires) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "timestamp has expired");
    }
    return 0;
}

int lrp_check_expirations_impl(const char *expires_at, int64_t now_unix,
                                lrp_expiration_status *out, lrp_error *err) {
    int64_t expires;
    if (lrp_parse_rfc3339(expires_at, &expires, err) != 0) return -1;
    int64_t remaining = expires - now_unix;
    lrp_expiration_level level;
    if (now_unix >= expires) {
        level = LRP_EXPIRATION_EXPIRED;
    } else if (remaining <= (int64_t)30 * 86400) {
        level = LRP_EXPIRATION_CRITICAL;
    } else if (remaining <= (int64_t)90 * 86400) {
        level = LRP_EXPIRATION_WARNING;
    } else if (remaining <= (int64_t)180 * 86400) {
        level = LRP_EXPIRATION_NOTICE;
    } else {
        level = LRP_EXPIRATION_OK;
    }
    out->level = level;
    out->expires_at_unix = expires;
    out->now_unix = now_unix;
    return 0;
}

/* Constant-time byte-equality (SEC fix): the length check is inherently
 * public (nonce/state are always caller-generated, fixed-size values, so
 * leaking their length is not a secret), but the byte comparison itself
 * must not branch on secret content — `CRYPTO_memcmp` (not `memcmp`, which
 * OpenSSL and most libc implementations short-circuit on the first
 * mismatching byte) is OpenSSL's documented constant-time comparison
 * primitive. */
static int constant_time_bytes_eq(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
    if (a_len != b_len) return 0;
    if (a_len == 0) return 1;
    return CRYPTO_memcmp(a, b, a_len) == 0;
}

int lrp_verify_nonce_state(const uint8_t *expected_nonce, size_t expected_nonce_len,
                            const uint8_t *expected_state, size_t expected_state_len,
                            const uint8_t *actual_nonce, size_t actual_nonce_len,
                            const uint8_t *actual_state, size_t actual_state_len, lrp_error *err) {
    if (!constant_time_bytes_eq(expected_nonce, expected_nonce_len, actual_nonce, actual_nonce_len)) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "nonce does not match");
    }
    if (!constant_time_bytes_eq(expected_state, expected_state_len, actual_state, actual_state_len)) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "state does not match");
    }
    return 0;
}

int lrp_verify_audience(const char *payload_audience_fingerprint, const char *local_rp_fingerprint,
                         lrp_error *err) {
    if (strcmp(payload_audience_fingerprint, local_rp_fingerprint) != 0) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "audience fingerprint does not match");
    }
    return 0;
}

int lrp_verify_issuer(const char *payload_user_domain, const char *expected_domain,
                       lrp_error *err) {
    if (strcmp(payload_user_domain, expected_domain) != 0) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "issuing domain does not match");
    }
    return 0;
}

int lrp_verify_callback_url(const char *payload_callback_url, const char *arrived_url,
                             lrp_error *err) {
    if (strcmp(payload_callback_url, arrived_url) != 0) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "callback URL does not match");
    }
    return 0;
}

static int bytes_eq(const lrp_bytes *a, const uint8_t *b, size_t b_len) {
    return a->len == b_len && (b_len == 0 || memcmp(a->data, b, b_len) == 0);
}

int lrp_check_callback_header_matches_payload(const lrp_w_callback_header *header,
                                               const lrp_w_callback_payload *payload,
                                               lrp_error *err) {
    if (strcmp(header->fingerprint.data, payload->audience_fingerprint.data) != 0) {
        return lrp_fail(err, LRP_ERR_VERIFICATION,
                         "callback header does not match signed payload field: fingerprint");
    }
    if (!bytes_eq(&payload->nonce, header->nonce.data, header->nonce.len)) {
        return lrp_fail(err, LRP_ERR_VERIFICATION,
                         "callback header does not match signed payload field: nonce");
    }
    if (!bytes_eq(&payload->state, header->state.data, header->state.len)) {
        return lrp_fail(err, LRP_ERR_VERIFICATION,
                         "callback header does not match signed payload field: state");
    }
    if (strcmp(header->issued_at.data, payload->issued_at.data) != 0) {
        return lrp_fail(err, LRP_ERR_VERIFICATION,
                         "callback header does not match signed payload field: issued_at");
    }
    if (strcmp(header->expires_at.data, payload->expires_at.data) != 0) {
        return lrp_fail(err, LRP_ERR_VERIFICATION,
                         "callback header does not match signed payload field: expires_at");
    }
    return 0;
}

int lrp_check_signing_key_valid(const lrp_domain_public_key *key, lrp_error *err) {
    if (strcmp(key->key_usage.data, "sign") != 0) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "signature verification failed");
    }
    if (key->revoked_at.data != NULL) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "signing key has been revoked: %s",
                         key->key_id.data);
    }
    int64_t expires;
    if (lrp_parse_rfc3339(key->expires_at.data, &expires, NULL) != 0) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "signing key has an invalid expires_at: %s",
                         key->key_id.data);
    }
    if (lrp_wall_clock_now() > expires) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "signing key has expired: %s", key->key_id.data);
    }
    return 0;
}

int lrp_verify_local_rp_callback_payload(const lrp_w_signed_callback_payload *signed_payload,
                                          const lrp_domain_public_key *domain_keys,
                                          size_t domain_keys_count, int64_t now_unix,
                                          int64_t skew_seconds, lrp_w_callback_payload *out_payload,
                                          lrp_error *err) {
    const lrp_domain_public_key *key = NULL;
    for (size_t i = 0; i < domain_keys_count; i++) {
        if (strcmp(domain_keys[i].key_id.data, signed_payload->signing_key_id.data) == 0) {
            key = &domain_keys[i];
            break;
        }
    }
    if (key == NULL) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "signing key not found: %s",
                         signed_payload->signing_key_id.data);
    }
    if (lrp_check_signing_key_valid(key, err) != 0) return -1;

    lrp_bytes sig_input = {0};
    if (lrp_envelope_signature_input(LRP_CTX_CALLBACK, signed_payload->payload.data,
                                      signed_payload->payload.len, &sig_input, err) != 0) {
        return -1;
    }
    int vrc = lrp_resolve_and_verify(key->algorithm.data, sig_input.data, sig_input.len,
                                      signed_payload->signature.data, signed_payload->signature.len,
                                      key->public_key.data, key->public_key.len, err);
    lrp_bytes_free(&sig_input);
    if (vrc != 0) return -1;

    if (lrp_decode_callback_payload(signed_payload->payload.data, signed_payload->payload.len,
                                     out_payload, err) != 0) {
        return -1;
    }
    if (lrp_check_timestamps(out_payload->issued_at.data, out_payload->expires_at.data, now_unix,
                              skew_seconds, err) != 0) {
        lrp_w_callback_payload_free(out_payload);
        memset(out_payload, 0, sizeof(*out_payload));
        return -1;
    }
    return 0;
}

/* --------------------------------------------------------------------- */
/* Callback sealed box                                                   */
/* --------------------------------------------------------------------- */

int lrp_local_rp_callback_kdf(lrp_aead_suite suite, const uint8_t ephemeral_public[32],
                               const uint8_t recipient_public[32], const uint8_t *shared_secret,
                               size_t shared_secret_len, uint8_t out_key[32], lrp_bytes *out_context,
                               lrp_error *err) {
    const char *suite_id = lrp_aead_suite_str(suite);
    size_t suite_id_len = strlen(suite_id);
    size_t tag_len = sizeof(LOCAL_RP_CALLBACK_BOX_TAG) - 1;
    size_t ctx_len = tag_len + suite_id_len + 32 + 32;
    uint8_t *ctx = (uint8_t *)malloc(ctx_len);
    if (ctx == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    size_t off = 0;
    memcpy(ctx + off, LOCAL_RP_CALLBACK_BOX_TAG, tag_len);
    off += tag_len;
    memcpy(ctx + off, suite_id, suite_id_len);
    off += suite_id_len;
    memcpy(ctx + off, ephemeral_public, 32);
    off += 32;
    memcpy(ctx + off, recipient_public, 32);
    off += 32;

    if (lrp_hkdf_sha256(shared_secret, shared_secret_len, ctx, ctx_len, out_key, err) != 0) {
        free(ctx);
        return -1;
    }
    out_context->data = ctx;
    out_context->len = ctx_len;
    return 0;
}

static int suite_in_list(const char *suite_str, const char *const *allowed, size_t allowed_count) {
    for (size_t i = 0; i < allowed_count; i++) {
        if (strcmp(suite_str, allowed[i]) == 0) return 1;
    }
    return 0;
}

int lrp_open_local_rp_callback(const uint8_t *header_bytes, size_t header_len,
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                const uint8_t recipient_private_key[32],
                                const uint8_t recipient_public_key[32],
                                const char *const *allowed_suites, size_t allowed_suites_count,
                                lrp_w_callback_header *out_header,
                                lrp_w_signed_callback_payload *out_signed_payload,
                                lrp_error *err) {
    memset(out_header, 0, sizeof(*out_header));
    memset(out_signed_payload, 0, sizeof(*out_signed_payload));

    if (lrp_decode_callback_header(header_bytes, header_len, out_header, err) != 0) return -1;

    lrp_aead_suite suite;
    if (lrp_aead_suite_parse(out_header->suite.data, &suite) != 0) {
        lrp_fail(err, LRP_ERR_VERIFICATION, "unsupported AEAD suite: %s", out_header->suite.data);
        goto fail_header;
    }
    if (!suite_in_list(out_header->suite.data, allowed_suites, allowed_suites_count)) {
        lrp_fail(err, LRP_ERR_VERIFICATION, "AEAD suite was not advertised/allowed: %s",
                 out_header->suite.data);
        goto fail_header;
    }

    uint8_t shared_secret[32];
    if (lrp_x25519_ecdh(recipient_private_key, out_header->ephemeral_public_key, shared_secret,
                         err) != 0) {
        goto fail_header;
    }

    uint8_t aead_key[32];
    lrp_bytes kdf_context = {0};
    if (lrp_local_rp_callback_kdf(suite, out_header->ephemeral_public_key, recipient_public_key,
                                   shared_secret, 32, aead_key, &kdf_context, err) != 0) {
        goto fail_header;
    }

    uint8_t *aad = (uint8_t *)malloc(kdf_context.len + header_len);
    if (aad == NULL) {
        lrp_bytes_free(&kdf_context);
        lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
        goto fail_header;
    }
    memcpy(aad, kdf_context.data, kdf_context.len);
    memcpy(aad + kdf_context.len, header_bytes, header_len);
    size_t aad_len = kdf_context.len + header_len;
    lrp_bytes_free(&kdf_context);

    lrp_bytes plaintext = {0};
    int drc = lrp_aead_decrypt(suite, aead_key, out_header->aead_nonce, aad, aad_len, ciphertext,
                                ciphertext_len, &plaintext, err);
    free(aad);
    if (drc != 0) goto fail_header;

    int decrc =
        lrp_decode_signed_callback_payload(plaintext.data, plaintext.len, out_signed_payload, err);
    lrp_bytes_free(&plaintext);
    if (decrc != 0) goto fail_header;

    return 0;

fail_header:
    lrp_w_callback_header_free(out_header);
    memset(out_header, 0, sizeof(*out_header));
    return -1;
}
