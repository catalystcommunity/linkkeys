/* generate_local_rp_identity, raw-byte storage helpers, and
 * check_expirations (design doc: "SDK API Shape", "Byte Storage Helpers",
 * "Expiration Helper"). Mirrors `sdks/local-rp/rust/src/identity.rs`. */
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include "cbor.h"
#include "crypto.h"
#include "error.h"
#include "local_rp.h"
#include "time_util.h"

static const char *const DEFAULT_SUITES[] = {"aes-256-gcm", "chacha20-poly1305"};
#define DEFAULT_SUITES_COUNT 2
#define DEFAULT_LIFETIME_SECONDS ((int64_t)3650 * 86400)

static int is_blank(const char *s) {
    if (s == NULL) return 1;
    for (const char *p = s; *p != '\0'; p++) {
        if (!isspace((unsigned char)*p)) return 0;
    }
    return 1;
}

const char *lrp_expiration_level_name(lrp_expiration_level level) {
    switch (level) {
        case LRP_EXPIRATION_OK: return "ok";
        case LRP_EXPIRATION_NOTICE: return "notice";
        case LRP_EXPIRATION_WARNING: return "warning";
        case LRP_EXPIRATION_CRITICAL: return "critical";
        case LRP_EXPIRATION_EXPIRED: return "expired";
        default: return "unknown";
    }
}

void lrp_identity_free(lrp_identity *id) {
    if (id == NULL) return;
    OPENSSL_cleanse(id->signing_private_key, sizeof(id->signing_private_key));
    OPENSSL_cleanse(id->encryption_private_key, sizeof(id->encryption_private_key));
    lrp_bytes_free(&id->descriptor_cbor);
    lrp_bytes_free(&id->descriptor_signature);
    memset(id, 0, sizeof(*id));
}

int lrp_generate_local_rp_identity(const lrp_generate_identity_config *config, lrp_identity *out,
                                    lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (is_blank(config->app_name)) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "app_name must not be empty");
    }

    if (lrp_ed25519_generate(out->signing_private_key, out->signing_public_key, err) != 0) {
        return -1;
    }
    if (lrp_x25519_generate(out->encryption_private_key, out->encryption_public_key, err) != 0) {
        lrp_identity_free(out);
        return -1;
    }

    const char *const *suites = DEFAULT_SUITES;
    size_t suites_count = DEFAULT_SUITES_COUNT;
    if (config->supported_suites != NULL && config->supported_suites_count > 0) {
        suites = config->supported_suites;
        suites_count = config->supported_suites_count;
    }

    int64_t lifetime =
        config->lifetime_seconds > 0 ? config->lifetime_seconds : DEFAULT_LIFETIME_SECONDS;
    char created_at[32], expires_at[32];
    lrp_format_rfc3339(config->now_unix, created_at);
    lrp_format_rfc3339(config->now_unix + lifetime, expires_at);

    lrp_fingerprint_hex(out->signing_public_key, 32, out->fingerprint);

    lrp_bytes descriptor_cbor = {0};
    if (lrp_encode_descriptor(config->app_name, config->local_domain_hint, out->signing_public_key,
                               out->encryption_public_key, out->fingerprint, suites, suites_count,
                               created_at, expires_at, &descriptor_cbor, err) != 0) {
        lrp_identity_free(out);
        return -1;
    }

    lrp_bytes signature = {0};
    if (lrp_sign_envelope(LRP_CTX_DESCRIPTOR, descriptor_cbor.data, descriptor_cbor.len,
                           out->signing_private_key, &signature, err) != 0) {
        lrp_bytes_free(&descriptor_cbor);
        lrp_identity_free(out);
        return -1;
    }

    out->descriptor_cbor = descriptor_cbor;
    out->descriptor_signature = signature;
    return 0;
}

/* --------------------------------------------------------------------- */
/* Byte storage helpers                                                  */
/* --------------------------------------------------------------------- */

static const uint8_t IDENTITY_BUNDLE_MAGIC[4] = {'L', 'K', 'I', '1'};

int lrp_local_rp_identity_to_bytes(const lrp_identity *id, lrp_bytes *out, lrp_error *err) {
    size_t total =
        4 + 32 + 32 + 4 + id->descriptor_cbor.len + 4 + id->descriptor_signature.len;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (buf == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    size_t off = 0;
    memcpy(buf + off, IDENTITY_BUNDLE_MAGIC, 4);
    off += 4;
    memcpy(buf + off, id->signing_private_key, 32);
    off += 32;
    memcpy(buf + off, id->encryption_private_key, 32);
    off += 32;
    uint32_t dlen = (uint32_t)id->descriptor_cbor.len;
    uint8_t dlen_be[4] = {(uint8_t)(dlen >> 24), (uint8_t)(dlen >> 16), (uint8_t)(dlen >> 8),
                          (uint8_t)dlen};
    memcpy(buf + off, dlen_be, 4);
    off += 4;
    memcpy(buf + off, id->descriptor_cbor.data, id->descriptor_cbor.len);
    off += id->descriptor_cbor.len;
    uint32_t slen = (uint32_t)id->descriptor_signature.len;
    uint8_t slen_be[4] = {(uint8_t)(slen >> 24), (uint8_t)(slen >> 16), (uint8_t)(slen >> 8),
                          (uint8_t)slen};
    memcpy(buf + off, slen_be, 4);
    off += 4;
    memcpy(buf + off, id->descriptor_signature.data, id->descriptor_signature.len);
    off += id->descriptor_signature.len;

    out->data = buf;
    out->len = total;
    return 0;
}

static int read_be32(const uint8_t *p, uint32_t *out) {
    *out = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
    return 0;
}

int lrp_local_rp_identity_from_bytes(const uint8_t *data, size_t len, lrp_identity *out,
                                      lrp_error *err) {
    memset(out, 0, sizeof(*out));
    const size_t header_len = 4 + 32 + 32 + 4;
    if (len < header_len || memcmp(data, IDENTITY_BUNDLE_MAGIC, 4) != 0) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT,
                         "identity bundle too short or has an unrecognized magic prefix");
    }
    memcpy(out->signing_private_key, data + 4, 32);
    memcpy(out->encryption_private_key, data + 36, 32);
    uint32_t dlen;
    read_be32(data + 68, &dlen);
    if (header_len + dlen + 4 > len) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT,
                         "identity bundle descriptor length exceeds available bytes");
    }
    const uint8_t *descriptor_ptr = data + header_len;
    uint32_t slen;
    read_be32(descriptor_ptr + dlen, &slen);
    if (header_len + dlen + 4 + slen > len) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT,
                         "identity bundle signature length exceeds available bytes");
    }
    const uint8_t *sig_ptr = descriptor_ptr + dlen + 4;

    /* Rebuild public keys / fingerprint by decoding the embedded
     * descriptor, exactly mirroring what was stored (design doc: "Public
     * keys and the fingerprint are read back out of the embedded
     * descriptor rather than re-derived from the private keys"). */
    cbor_value *root = NULL;
    if (cbor_decode(descriptor_ptr, dlen, &root, err) != 0) {
        return lrp_fail(err, LRP_ERR_DECODE, "identity bundle descriptor: invalid CBOR");
    }
    int rc = -1;
    lrp_bytes signing_pub = {0}, enc_pub = {0};
    lrp_str fp = {0};
    if (cbor_get_bytes(root, "signing_public_key", &signing_pub, err) == 0 &&
        cbor_get_bytes(root, "encryption_public_key", &enc_pub, err) == 0 &&
        cbor_get_text(root, "fingerprint", &fp, err) == 0 && signing_pub.len == 32 &&
        enc_pub.len == 32) {
        memcpy(out->signing_public_key, signing_pub.data, 32);
        memcpy(out->encryption_public_key, enc_pub.data, 32);
        snprintf(out->fingerprint, sizeof(out->fingerprint), "%s", fp.data);
        rc = 0;
    } else if (err != NULL && err->code == LRP_OK) {
        lrp_fail(err, LRP_ERR_DECODE, "identity bundle descriptor payload missing fields");
    }
    lrp_bytes_free(&signing_pub);
    lrp_bytes_free(&enc_pub);
    lrp_str_free(&fp);
    cbor_value_free(root);
    free(root);
    if (rc != 0) return -1;

    out->descriptor_cbor.data = (uint8_t *)malloc(dlen > 0 ? dlen : 1);
    if (out->descriptor_cbor.data == NULL) {
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    }
    memcpy(out->descriptor_cbor.data, descriptor_ptr, dlen);
    out->descriptor_cbor.len = dlen;

    out->descriptor_signature.data = (uint8_t *)malloc(slen > 0 ? slen : 1);
    if (out->descriptor_signature.data == NULL) {
        lrp_bytes_free(&out->descriptor_cbor);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    }
    memcpy(out->descriptor_signature.data, sig_ptr, slen);
    out->descriptor_signature.len = slen;
    return 0;
}

/* --------------------------------------------------------------------- */
/* Expiration helper                                                     */
/* --------------------------------------------------------------------- */

int lrp_check_expirations(const lrp_identity *id, int64_t now_unix, lrp_expiration_status *out,
                           lrp_error *err) {
    cbor_value *root = NULL;
    if (cbor_decode(id->descriptor_cbor.data, id->descriptor_cbor.len, &root, err) != 0) {
        return -1;
    }
    lrp_str expires_at = {0};
    int rc = cbor_get_text(root, "expires_at", &expires_at, err);
    cbor_value_free(root);
    free(root);
    if (rc != 0) return -1;
    rc = lrp_check_expirations_impl(expires_at.data, now_unix, out, err);
    lrp_str_free(&expires_at);
    return rc;
}
