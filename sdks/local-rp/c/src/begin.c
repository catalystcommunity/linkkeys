/* begin_local_login (design doc: "SDK API Shape", "Flow" steps 4-6).
 * Pure/offline: no network access happens here. Mirrors
 * `sdks/local-rp/rust/src/begin.rs`. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"
#include "crypto.h"
#include "encoding.h"
#include "error.h"
#include "local_rp.h"
#include "time_util.h"

static const char *const DEFAULT_REQUESTED_CLAIMS[] = {"display_name", "email", "handle"};
#define DEFAULT_REQUESTED_CLAIMS_COUNT 3
static const char *const DEFAULT_REQUIRED_CLAIMS[] = {"handle"};
#define DEFAULT_REQUIRED_CLAIMS_COUNT 1
#define DEFAULT_LOGIN_REQUEST_LIFETIME_SECONDS 300

void lrp_login_redirect_free(lrp_login_redirect *r) {
    if (r == NULL) return;
    lrp_str_free(&r->redirect_url);
}

void lrp_pending_login_free(lrp_pending_login *p) {
    if (p == NULL) return;
    lrp_bytes_free(&p->nonce);
    lrp_bytes_free(&p->state);
    lrp_str_free(&p->user_domain);
    lrp_str_free(&p->callback_url);
    for (size_t i = 0; i < p->required_claims_count; i++) free(p->required_claims[i]);
    free(p->required_claims);
    p->required_claims = NULL;
    p->required_claims_count = 0;
}

/* Bumped from "LKP1": the blob now also carries required_claims (SEC fix,
 * identity binding) — "LKP1" blobs predate that field and are no longer
 * accepted, forcing an explicit re-`begin` rather than silently completing
 * with an empty (unenforced) required-claims set. */
static const uint8_t PENDING_LOGIN_MAGIC[4] = {'L', 'K', 'P', '2'};

int lrp_pending_login_to_bytes(const lrp_pending_login *p, lrp_bytes *out, lrp_error *err) {
    size_t total = 4 + 4 + p->nonce.len + 4 + p->state.len + 4 + strlen(p->user_domain.data) + 4 +
                   strlen(p->callback_url.data) + 4;
    for (size_t i = 0; i < p->required_claims_count; i++) total += 4 + strlen(p->required_claims[i]);
    uint8_t *buf = (uint8_t *)malloc(total);
    if (buf == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    size_t off = 0;
    memcpy(buf + off, PENDING_LOGIN_MAGIC, 4);
    off += 4;
    uint32_t sizes[4] = {(uint32_t)p->nonce.len, (uint32_t)p->state.len,
                          (uint32_t)strlen(p->user_domain.data), (uint32_t)strlen(p->callback_url.data)};
    const uint8_t *ptrs[4] = {p->nonce.data, p->state.data, (const uint8_t *)p->user_domain.data,
                              (const uint8_t *)p->callback_url.data};
    for (int i = 0; i < 4; i++) {
        uint8_t be[4] = {(uint8_t)(sizes[i] >> 24), (uint8_t)(sizes[i] >> 16),
                         (uint8_t)(sizes[i] >> 8), (uint8_t)sizes[i]};
        memcpy(buf + off, be, 4);
        off += 4;
        if (sizes[i] > 0) memcpy(buf + off, ptrs[i], sizes[i]);
        off += sizes[i];
    }
    {
        uint32_t rc = (uint32_t)p->required_claims_count;
        uint8_t be[4] = {(uint8_t)(rc >> 24), (uint8_t)(rc >> 16), (uint8_t)(rc >> 8), (uint8_t)rc};
        memcpy(buf + off, be, 4);
        off += 4;
    }
    for (size_t i = 0; i < p->required_claims_count; i++) {
        uint32_t n = (uint32_t)strlen(p->required_claims[i]);
        uint8_t be[4] = {(uint8_t)(n >> 24), (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n};
        memcpy(buf + off, be, 4);
        off += 4;
        if (n > 0) memcpy(buf + off, p->required_claims[i], n);
        off += n;
    }
    out->data = buf;
    out->len = total;
    return 0;
}

int lrp_pending_login_from_bytes(const uint8_t *data, size_t len, lrp_pending_login *out,
                                  lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (len < 4 || memcmp(data, PENDING_LOGIN_MAGIC, 4) != 0) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT,
                         "pending login blob too short or has an unrecognized magic prefix");
    }
    size_t off = 4;
    lrp_bytes *byte_fields[2] = {&out->nonce, &out->state};
    lrp_str *str_fields[2] = {&out->user_domain, &out->callback_url};
    for (int i = 0; i < 4; i++) {
        if (off + 4 > len) goto too_short;
        uint32_t n = ((uint32_t)data[off] << 24) | ((uint32_t)data[off + 1] << 16) |
                     ((uint32_t)data[off + 2] << 8) | data[off + 3];
        off += 4;
        if (off + n > len) goto too_short;
        if (i < 2) {
            byte_fields[i]->data = (uint8_t *)malloc(n > 0 ? n : 1);
            if (byte_fields[i]->data == NULL) {
                lrp_pending_login_free(out);
                return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
            }
            memcpy(byte_fields[i]->data, data + off, n);
            byte_fields[i]->len = n;
        } else {
            str_fields[i - 2]->data = (char *)malloc((size_t)n + 1);
            if (str_fields[i - 2]->data == NULL) {
                lrp_pending_login_free(out);
                return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
            }
            memcpy(str_fields[i - 2]->data, data + off, n);
            str_fields[i - 2]->data[n] = '\0';
        }
        off += n;
    }
    if (off + 4 > len) goto too_short;
    uint32_t claims_count = ((uint32_t)data[off] << 24) | ((uint32_t)data[off + 1] << 16) |
                             ((uint32_t)data[off + 2] << 8) | data[off + 3];
    off += 4;
    /* Bound the declared count against the remaining input before
     * allocating (mirrors the CBOR decoder's own DoS hardening): each
     * entry needs at least 4 length-prefix bytes, so a declared count that
     * cannot possibly fit is rejected up front rather than driving a huge
     * calloc. */
    if ((size_t)claims_count > (len - off) / 4) goto too_short;
    if (claims_count > 0) {
        out->required_claims = (char **)calloc(claims_count, sizeof(char *));
        if (out->required_claims == NULL) {
            lrp_pending_login_free(out);
            return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
        }
    }
    for (uint32_t i = 0; i < claims_count; i++) {
        if (off + 4 > len) goto too_short;
        uint32_t n = ((uint32_t)data[off] << 24) | ((uint32_t)data[off + 1] << 16) |
                     ((uint32_t)data[off + 2] << 8) | data[off + 3];
        off += 4;
        if (off + n > len) goto too_short;
        char *s = (char *)malloc((size_t)n + 1);
        if (s == NULL) {
            lrp_pending_login_free(out);
            return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
        }
        memcpy(s, data + off, n);
        s[n] = '\0';
        out->required_claims[i] = s;
        out->required_claims_count = i + 1;
        off += n;
    }
    return 0;
too_short:
    lrp_pending_login_free(out);
    return lrp_fail(err, LRP_ERR_INVALID_INPUT, "pending login blob truncated");
}

static int validate_callback_scheme(const char *url, lrp_error *err) {
    if (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0) return 0;
    return lrp_fail(err, LRP_ERR_INVALID_INPUT, "callback_url must be http:// or https://");
}

int lrp_begin_local_login(const lrp_begin_login_config *config, lrp_login_redirect *out_redirect,
                           lrp_pending_login *out_pending, lrp_error *err) {
    memset(out_redirect, 0, sizeof(*out_redirect));
    memset(out_pending, 0, sizeof(*out_pending));

    if (config->identity == NULL) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "identity is required");
    }
    if (validate_callback_scheme(config->callback_url, err) != 0) return -1;
    if (config->user_domain == NULL || config->user_domain[0] == '\0') {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "user_domain must not be empty");
    }

    uint8_t nonce[32], state[32];
    if (lrp_rand_bytes(nonce, 32, err) != 0) return -1;
    if (lrp_rand_bytes(state, 32, err) != 0) return -1;

    const char *const *requested = config->requested_claims;
    size_t requested_count = config->requested_claims_count;
    if (requested == NULL || requested_count == 0) {
        requested = DEFAULT_REQUESTED_CLAIMS;
        requested_count = DEFAULT_REQUESTED_CLAIMS_COUNT;
    }
    const char *const *required = config->required_claims;
    size_t required_count = config->required_claims_count;
    if (required == NULL || required_count == 0) {
        required = DEFAULT_REQUIRED_CLAIMS;
        required_count = DEFAULT_REQUIRED_CLAIMS_COUNT;
    }
    int64_t lifetime = config->request_lifetime_seconds > 0 ? config->request_lifetime_seconds
                                                              : DEFAULT_LOGIN_REQUEST_LIFETIME_SECONDS;
    char issued_at[32], expires_at[32];
    lrp_format_rfc3339(config->now_unix, issued_at);
    lrp_format_rfc3339(config->now_unix + lifetime, expires_at);

    lrp_bytes request_bytes = {0};
    if (lrp_encode_login_request(config->identity->descriptor_cbor.data,
                                  config->identity->descriptor_cbor.len,
                                  config->identity->descriptor_signature.data,
                                  config->identity->descriptor_signature.len, config->callback_url,
                                  nonce, 32, state, 32, requested, requested_count, required,
                                  required_count, issued_at, expires_at, &request_bytes, err) != 0) {
        return -1;
    }

    lrp_bytes signature = {0};
    if (lrp_sign_envelope(LRP_CTX_LOGIN_REQUEST, request_bytes.data, request_bytes.len,
                           config->identity->signing_private_key, &signature, err) != 0) {
        lrp_bytes_free(&request_bytes);
        return -1;
    }

    /* SignedLocalRpLoginRequest = { request: bytes, signature: bytes } */
    cbor_buf sb;
    cbor_buf_init(&sb);
    int rc = 0;
    rc |= cbor_write_map_header(&sb, 2);
    rc |= cbor_write_text_cstr(&sb, "request");
    rc |= cbor_write_bytes(&sb, request_bytes.data, request_bytes.len);
    rc |= cbor_write_text_cstr(&sb, "signature");
    rc |= cbor_write_bytes(&sb, signature.data, signature.len);
    lrp_bytes_free(&request_bytes);
    lrp_bytes_free(&signature);
    if (rc != 0) {
        cbor_buf_free(&sb);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode signed login request: out of memory");
    }
    lrp_bytes signed_request = cbor_buf_release(&sb);

    lrp_str encoded = {0};
    rc = lrp_base64url_encode(signed_request.data, signed_request.len, &encoded, err);
    lrp_bytes_free(&signed_request);
    if (rc != 0) return -1;

    size_t url_len = strlen("https://") + strlen(config->user_domain) +
                      strlen("/auth/local-rp?signed_request=") + strlen(encoded.data) + 1;
    char *redirect_url = (char *)malloc(url_len);
    if (redirect_url == NULL) {
        lrp_str_free(&encoded);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    }
    snprintf(redirect_url, url_len, "https://%s/auth/local-rp?signed_request=%s",
             config->user_domain, encoded.data);
    lrp_str_free(&encoded);

    out_redirect->redirect_url.data = redirect_url;

    out_pending->nonce.data = (uint8_t *)malloc(32);
    memcpy(out_pending->nonce.data, nonce, 32);
    out_pending->nonce.len = 32;
    out_pending->state.data = (uint8_t *)malloc(32);
    memcpy(out_pending->state.data, state, 32);
    out_pending->state.len = 32;
    out_pending->user_domain.data = strdup(config->user_domain);
    out_pending->callback_url.data = strdup(config->callback_url);

    /* SEC fix (identity binding): retain the resolved (default-applied)
     * required_claims set so complete_local_login can re-enforce it against
     * the redemption's VERIFIED claims later — see lrp_pending_login's
     * docs. */
    if (required_count > 0) {
        out_pending->required_claims = (char **)calloc(required_count, sizeof(char *));
        if (out_pending->required_claims == NULL) {
            lrp_pending_login_free(out_pending);
            lrp_login_redirect_free(out_redirect);
            return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
        }
        for (size_t i = 0; i < required_count; i++) {
            out_pending->required_claims[i] = strdup(required[i]);
        }
        out_pending->required_claims_count = required_count;
    }

    return 0;
}
