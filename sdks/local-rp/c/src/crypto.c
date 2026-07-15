#include <stdlib.h>
#include "crypto.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include "error.h"

void lrp_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    unsigned int outlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}

static const char HEX_CHARS[] = "0123456789abcdef";

void lrp_fingerprint_hex(const uint8_t *public_key, size_t public_key_len,
                          char out[LRP_FINGERPRINT_HEX_LEN + 1]) {
    uint8_t digest[32];
    lrp_sha256(public_key, public_key_len, digest);
    for (size_t i = 0; i < 32; i++) {
        out[i * 2] = HEX_CHARS[digest[i] >> 4];
        out[i * 2 + 1] = HEX_CHARS[digest[i] & 0x0f];
    }
    out[64] = '\0';
}

int lrp_rand_bytes(uint8_t *out, size_t len, lrp_error *err) {
    if (len == 0) return 0;
    if (RAND_bytes(out, (int)len) != 1) {
        return lrp_fail(err, LRP_ERR_CRYPTO, "RAND_bytes failed");
    }
    return 0;
}

int lrp_bytes_to_hex(const uint8_t *data, size_t len, lrp_str *out, lrp_error *err) {
    char *buf = (char *)malloc(len * 2 + 1);
    if (buf == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    for (size_t i = 0; i < len; i++) {
        buf[i * 2] = HEX_CHARS[data[i] >> 4];
        buf[i * 2 + 1] = HEX_CHARS[data[i] & 0x0f];
    }
    buf[len * 2] = '\0';
    out->data = buf;
    return 0;
}

static int hex_nibble(char c, uint8_t *out) {
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0'); return 0; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(c - 'a' + 10); return 0; }
    if (c >= 'A' && c <= 'F') { *out = (uint8_t)(c - 'A' + 10); return 0; }
    return -1;
}

int lrp_hex_to_bytes(const char *hex, lrp_bytes *out, lrp_error *err) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return lrp_fail(err, LRP_ERR_INVALID_INPUT, "hex string has odd length");
    size_t n = len / 2;
    uint8_t *buf = (uint8_t *)malloc(n > 0 ? n : 1);
    if (buf == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    for (size_t i = 0; i < n; i++) {
        uint8_t hi, lo;
        if (hex_nibble(hex[i * 2], &hi) != 0 || hex_nibble(hex[i * 2 + 1], &lo) != 0) {
            free(buf);
            return lrp_fail(err, LRP_ERR_INVALID_INPUT, "invalid hex character");
        }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    out->data = buf;
    out->len = n;
    return 0;
}

/* --------------------------------------------------------------------- */
/* Ed25519                                                                */
/* --------------------------------------------------------------------- */

int lrp_ed25519_generate(uint8_t seed_out[32], uint8_t pub_out[32], lrp_error *err) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY *pkey = NULL;
    int rc = -1;
    if (pctx != NULL && EVP_PKEY_keygen_init(pctx) == 1 && EVP_PKEY_generate(pctx, &pkey) == 1) {
        size_t seed_len = 32, pub_len = 32;
        if (EVP_PKEY_get_raw_private_key(pkey, seed_out, &seed_len) == 1 && seed_len == 32 &&
            EVP_PKEY_get_raw_public_key(pkey, pub_out, &pub_len) == 1 && pub_len == 32) {
            rc = 0;
        }
    }
    if (rc != 0) lrp_fail(err, LRP_ERR_CRYPTO, "ed25519: key generation failed");
    if (pkey != NULL) EVP_PKEY_free(pkey);
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    return rc;
}

int lrp_ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t msg_len,
                      uint8_t sig_out[64], lrp_error *err) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    if (pkey == NULL) return lrp_fail(err, LRP_ERR_CRYPTO, "ed25519: failed to load private key");
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int rc = -1;
    if (mdctx != NULL && EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) == 1) {
        size_t siglen = 64;
        if (EVP_DigestSign(mdctx, sig_out, &siglen, msg, msg_len) == 1 && siglen == 64) {
            rc = 0;
        }
    }
    if (rc != 0) lrp_fail(err, LRP_ERR_CRYPTO, "ed25519: signing failed");
    if (mdctx != NULL) EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int lrp_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msg_len,
                        const uint8_t *sig, size_t sig_len, lrp_error *err) {
    if (sig_len != 64) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "ed25519: signature must be 64 bytes");
    }
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    if (pkey == NULL) return lrp_fail(err, LRP_ERR_VERIFICATION, "ed25519: invalid public key");
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int rc = -1;
    if (mdctx != NULL && EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len) == 1) {
        rc = 0;
    }
    if (rc != 0) lrp_fail(err, LRP_ERR_VERIFICATION, "ed25519: signature verification failed");
    if (mdctx != NULL) EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int lrp_resolve_and_verify(const char *algorithm, const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len, const uint8_t *pubkey,
                            size_t pubkey_len, lrp_error *err) {
    if (algorithm == NULL || strcmp(algorithm, "ed25519") != 0) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "unsupported signing algorithm: %s",
                         algorithm != NULL ? algorithm : "(null)");
    }
    if (pubkey_len != 32) {
        return lrp_fail(err, LRP_ERR_VERIFICATION, "ed25519: public key must be 32 bytes");
    }
    return lrp_ed25519_verify(pubkey, msg, msg_len, sig, sig_len, err);
}

/* --------------------------------------------------------------------- */
/* X25519                                                                 */
/* --------------------------------------------------------------------- */

int lrp_x25519_generate(uint8_t priv_out[32], uint8_t pub_out[32], lrp_error *err) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    int rc = -1;
    if (pctx != NULL && EVP_PKEY_keygen_init(pctx) == 1 && EVP_PKEY_generate(pctx, &pkey) == 1) {
        size_t priv_len = 32, pub_len = 32;
        if (EVP_PKEY_get_raw_private_key(pkey, priv_out, &priv_len) == 1 && priv_len == 32 &&
            EVP_PKEY_get_raw_public_key(pkey, pub_out, &pub_len) == 1 && pub_len == 32) {
            rc = 0;
        }
    }
    if (rc != 0) lrp_fail(err, LRP_ERR_CRYPTO, "x25519: key generation failed");
    if (pkey != NULL) EVP_PKEY_free(pkey);
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    return rc;
}

int lrp_x25519_derive_public(const uint8_t priv[32], uint8_t pub_out[32], lrp_error *err) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    if (pkey == NULL) return lrp_fail(err, LRP_ERR_CRYPTO, "x25519: failed to load private key");
    size_t pub_len = 32;
    int rc = -1;
    if (EVP_PKEY_get_raw_public_key(pkey, pub_out, &pub_len) == 1 && pub_len == 32) rc = 0;
    if (rc != 0) lrp_fail(err, LRP_ERR_CRYPTO, "x25519: failed to derive public key");
    EVP_PKEY_free(pkey);
    return rc;
}

int lrp_x25519_ecdh(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t secret_out[32],
                     lrp_error *err) {
    EVP_PKEY *priv_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    EVP_PKEY_CTX *ctx = NULL;
    int rc = -1;
    if (priv_pkey != NULL && peer_pkey != NULL) {
        ctx = EVP_PKEY_CTX_new(priv_pkey, NULL);
        if (ctx != NULL && EVP_PKEY_derive_init(ctx) == 1 &&
            EVP_PKEY_derive_set_peer(ctx, peer_pkey) == 1) {
            size_t outlen = 32;
            if (EVP_PKEY_derive(ctx, secret_out, &outlen) == 1 && outlen == 32) {
                rc = 0;
            }
        }
    }
    if (rc != 0) {
        lrp_fail(err, LRP_ERR_CRYPTO, "x25519: ECDH derivation failed");
    } else {
        /* Wire Precision: reject an all-zero (low-order/non-contributory)
         * shared secret explicitly, rather than merely using it as an AEAD
         * key and letting a downstream tag check catch it implicitly. */
        static const uint8_t zero32[32] = {0};
        if (memcmp(secret_out, zero32, 32) == 0) {
            rc = lrp_fail(err, LRP_ERR_CRYPTO,
                           "x25519: non-contributory (low-order) public key rejected");
        }
    }
    if (ctx != NULL) EVP_PKEY_CTX_free(ctx);
    if (priv_pkey != NULL) EVP_PKEY_free(priv_pkey);
    if (peer_pkey != NULL) EVP_PKEY_free(peer_pkey);
    return rc;
}

/* --------------------------------------------------------------------- */
/* HKDF-SHA256                                                            */
/* --------------------------------------------------------------------- */

int lrp_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len,
                     uint8_t out32[32], lrp_error *err) {
    static const uint8_t empty = 0;
    const uint8_t *salt_ptr = &empty;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    int rc = -1;
    if (pctx != NULL && EVP_PKEY_derive_init(pctx) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt_ptr, 0) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) == 1) {
        size_t outlen = 32;
        if (EVP_PKEY_derive(pctx, out32, &outlen) == 1 && outlen == 32) {
            rc = 0;
        }
    }
    if (rc != 0) lrp_fail(err, LRP_ERR_CRYPTO, "HKDF-SHA256 derivation failed");
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    return rc;
}

/* --------------------------------------------------------------------- */
/* AEAD suite registry + dispatch                                        */
/* --------------------------------------------------------------------- */

const char *lrp_aead_suite_str(lrp_aead_suite s) {
    switch (s) {
        case LRP_SUITE_AES_256_GCM: return "aes-256-gcm";
        case LRP_SUITE_CHACHA20_POLY1305: return "chacha20-poly1305";
        default: return "";
    }
}

int lrp_aead_suite_parse(const char *s, lrp_aead_suite *out) {
    if (s == NULL) return -1;
    if (strcmp(s, "aes-256-gcm") == 0) { *out = LRP_SUITE_AES_256_GCM; return 0; }
    if (strcmp(s, "chacha20-poly1305") == 0) { *out = LRP_SUITE_CHACHA20_POLY1305; return 0; }
    return -1;
}

static const EVP_CIPHER *cipher_for(lrp_aead_suite suite) {
    return suite == LRP_SUITE_AES_256_GCM ? EVP_aes_256_gcm() : EVP_chacha20_poly1305();
}

#define LRP_AEAD_TAG_LEN 16

int lrp_aead_encrypt(lrp_aead_suite suite, const uint8_t key[32], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len, const uint8_t *plaintext,
                      size_t plaintext_len, lrp_bytes *out_ciphertext, lrp_error *err) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t *ct = (uint8_t *)malloc(plaintext_len > 0 ? plaintext_len : 1);
    int rc = -1;
    int len = 0, ct_len = 0;
    if (ctx == NULL || ct == NULL) goto done;
    if (EVP_EncryptInit_ex(ctx, cipher_for(suite), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, ct, &len, plaintext, (int)plaintext_len) != 1) goto done;
        ct_len = len;
    }
    if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &len) != 1) goto done;
    ct_len += len;
    {
        uint8_t tag[LRP_AEAD_TAG_LEN];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, LRP_AEAD_TAG_LEN, tag) != 1) goto done;
        uint8_t *full = (uint8_t *)malloc((size_t)ct_len + LRP_AEAD_TAG_LEN);
        if (full == NULL) goto done;
        memcpy(full, ct, (size_t)ct_len);
        memcpy(full + ct_len, tag, LRP_AEAD_TAG_LEN);
        out_ciphertext->data = full;
        out_ciphertext->len = (size_t)ct_len + LRP_AEAD_TAG_LEN;
    }
    rc = 0;
done:
    if (rc != 0) lrp_fail(err, LRP_ERR_CRYPTO, "AEAD encryption failed");
    free(ct);
    if (ctx != NULL) EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int lrp_aead_decrypt(lrp_aead_suite suite, const uint8_t key[32], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext,
                      size_t ciphertext_len, lrp_bytes *out_plaintext, lrp_error *err) {
    if (ciphertext_len < LRP_AEAD_TAG_LEN) {
        return lrp_fail(err, LRP_ERR_CRYPTO, "AEAD ciphertext shorter than tag length");
    }
    size_t body_len = ciphertext_len - LRP_AEAD_TAG_LEN;
    const uint8_t *tag = ciphertext + body_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t *pt = (uint8_t *)malloc(body_len > 0 ? body_len : 1);
    int rc = -1;
    int len = 0, pt_len = 0;
    if (ctx == NULL || pt == NULL) goto done;
    if (EVP_DecryptInit_ex(ctx, cipher_for(suite), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    if (body_len > 0) {
        if (EVP_DecryptUpdate(ctx, pt, &len, ciphertext, (int)body_len) != 1) goto done;
        pt_len = len;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, LRP_AEAD_TAG_LEN, (void *)tag) != 1) {
        goto done;
    }
    if (EVP_DecryptFinal_ex(ctx, pt + pt_len, &len) != 1) goto done; /* auth failure surfaces here */
    pt_len += len;
    rc = 0;
done:
    if (rc == 0) {
        out_plaintext->data = pt;
        out_plaintext->len = (size_t)pt_len;
    } else {
        lrp_fail(err, LRP_ERR_CRYPTO, "AEAD decryption/authentication failed");
        free(pt);
    }
    if (ctx != NULL) EVP_CIPHER_CTX_free(ctx);
    return rc;
}
