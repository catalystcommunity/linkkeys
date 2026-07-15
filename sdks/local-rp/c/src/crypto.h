/* Crypto primitives via OpenSSL libcrypto (EVP), per the design doc's C
 * row of the Language Crypto Matrix: OpenSSL, not libsodium, because
 * libsodium's AES-256-GCM is AES-NI-hardware-gated and therefore not
 * portable, and the protocol's baseline suite is aes-256-gcm.
 *
 * API choices (report these back — see the task's "Report back" ask):
 * - Ed25519 / X25519: EVP_PKEY_new_raw_private_key/raw_public_key +
 *   EVP_DigestSign/EVP_DigestVerify with a NULL message digest (Ed25519 is
 *   PureEdDSA — one-shot, no prehash), and EVP_PKEY_derive for X25519 ECDH.
 * - HKDF-SHA256: EVP_PKEY_CTX with EVP_PKEY_HKDF (works unchanged across
 *   OpenSSL 1.1.1 and 3.x), default EXTRACT_AND_EXPAND mode, empty salt —
 *   matches `Hkdf::<Sha256>::new(None, ikm).expand(info, 32)` byte-for-byte
 *   (HMAC treats a 0-length key identically to a hash-length all-zero key,
 *   both zero-pad to the block size), verified against
 *   `callback_box.json`'s `kdf_context_hex`/ciphertexts in tests.
 * - AES-256-GCM / ChaCha20-Poly1305: EVP_{En,De}cryptInit_ex +
 *   EVP_CIPHER_CTX_ctrl for IV length and the 16-byte tag, dispatched
 *   through one `cipher_for(suite)` lookup shared by encrypt/decrypt —
 *   mirroring `liblinkkeys::crypto::aead_encrypt`/`aead_decrypt`'s single
 *   dispatch point. Ciphertext output is `ciphertext || 16-byte tag`
 *   (RustCrypto `Aead` trait convention, matching the conformance vectors).
 */
#ifndef LRP_INTERNAL_CRYPTO_H
#define LRP_INTERNAL_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "linkkeys_local_rp.h"

/* --------------------------------------------------------------------- */
/* Hashing / fingerprint / randomness                                    */
/* --------------------------------------------------------------------- */

void lrp_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* sha256(public_key_bytes) lowercase hex, NUL-terminated (65 bytes) — the
 * canonical LinkKeys fingerprint format. */
void lrp_fingerprint_hex(const uint8_t *public_key, size_t public_key_len,
                          char out[LRP_FINGERPRINT_HEX_LEN + 1]);

int lrp_rand_bytes(uint8_t *out, size_t len, lrp_error *err);

/* --------------------------------------------------------------------- */
/* Ed25519                                                                */
/* --------------------------------------------------------------------- */

int lrp_ed25519_generate(uint8_t seed_out[32], uint8_t pub_out[32], lrp_error *err);
int lrp_ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t msg_len,
                      uint8_t sig_out[64], lrp_error *err);
/* Returns 0 if the signature verifies, -1 (with *err set) otherwise —
 * including a malformed public key or signature length, which must never
 * crash the caller. */
int lrp_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msg_len,
                        const uint8_t *sig, size_t sig_len, lrp_error *err);

/* Resolve a wire algorithm string (only "ed25519" is registered — see
 * liblinkkeys::crypto::SigningAlgorithm) and verify. */
int lrp_resolve_and_verify(const char *algorithm, const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len, const uint8_t *pubkey,
                            size_t pubkey_len, lrp_error *err);

/* --------------------------------------------------------------------- */
/* X25519                                                                 */
/* --------------------------------------------------------------------- */

int lrp_x25519_generate(uint8_t priv_out[32], uint8_t pub_out[32], lrp_error *err);

/* Derive the public key for a raw X25519 private scalar. Used only by
 * tests, which are not guaranteed a `recipient_public_key_hex` field on
 * every fixture case. */
int lrp_x25519_derive_public(const uint8_t priv[32], uint8_t pub_out[32], lrp_error *err);

/* ECDH, rejecting an all-zero (low-order/non-contributory) result
 * explicitly, per Wire Precision's "reject_low_order". */
int lrp_x25519_ecdh(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t secret_out[32],
                     lrp_error *err);

/* --------------------------------------------------------------------- */
/* HKDF-SHA256                                                            */
/* --------------------------------------------------------------------- */

int lrp_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len,
                     uint8_t out32[32], lrp_error *err);

/* --------------------------------------------------------------------- */
/* AEAD suite registry                                                   */
/* --------------------------------------------------------------------- */

typedef enum lrp_aead_suite {
    LRP_SUITE_AES_256_GCM = 0,
    LRP_SUITE_CHACHA20_POLY1305,
} lrp_aead_suite;

const char *lrp_aead_suite_str(lrp_aead_suite s);
/* Returns 0 and sets *out for a registered id, -1 (no error set — this is
 * an ordinary "not found", not a failure) for anything else. Exact,
 * case-sensitive strings only — never "close enough". */
int lrp_aead_suite_parse(const char *s, lrp_aead_suite *out);

/* Ciphertext is `ciphertext || 16-byte tag`. */
int lrp_aead_encrypt(lrp_aead_suite suite, const uint8_t key[32], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len, const uint8_t *plaintext,
                      size_t plaintext_len, lrp_bytes *out_ciphertext, lrp_error *err);
int lrp_aead_decrypt(lrp_aead_suite suite, const uint8_t key[32], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext,
                      size_t ciphertext_len, lrp_bytes *out_plaintext, lrp_error *err);

#endif
