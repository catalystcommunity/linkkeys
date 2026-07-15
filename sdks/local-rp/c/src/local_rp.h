/* Pure local-RP protocol helpers: envelope signature input, timestamp /
 * expiration checks, nonce/state/audience/issuer/callback-url checks, and
 * the callback sealed box (KDF + AEAD + header AAD binding). Mirrors
 * `crates/liblinkkeys/src/local_rp.rs` — see that file's module docs and
 * `dns-less-local-rp-design.md`'s "Wire Precision (Normative)" for the
 * exact byte-level contract every function here implements.
 */
#ifndef LRP_INTERNAL_LOCAL_RP_H
#define LRP_INTERNAL_LOCAL_RP_H

#include "crypto.h"
#include "types.h"

/* The four mandatory signature context strings (Wire Precision). A
 * signature over one structure must never verify as another. */
#define LRP_CTX_DESCRIPTOR "linkkeys-local-rp-descriptor"
#define LRP_CTX_LOGIN_REQUEST "linkkeys-local-rp-login-request"
#define LRP_CTX_CALLBACK "linkkeys-local-rp-callback"
#define LRP_CTX_TICKET_REDEMPTION "linkkeys-local-rp-ticket-redemption"

/* Default bounded clock-skew tolerance (seconds), Wire Precision. */
#define LRP_DEFAULT_CLOCK_SKEW_SECONDS 300

/* `CBOR([context: tstr, payload: bstr])` — the exact signature input for
 * every one of the four local-RP envelope structures (Wire Precision,
 * "Signature input bytes"). NOT a bare concatenation. */
int lrp_envelope_signature_input(const char *context, const uint8_t *payload, size_t payload_len,
                                  lrp_bytes *out, lrp_error *err);

/* Sign `payload` under `context` with the local RP's own Ed25519 key
 * (descriptor / login request / ticket redemption — all self-asserted,
 * verified against their own embedded key, SSH-host-key style). */
int lrp_sign_envelope(const char *context, const uint8_t *payload, size_t payload_len,
                       const uint8_t signing_private_key[32], lrp_bytes *out_signature,
                       lrp_error *err);

/* Real system wall-clock unix seconds. Used ONLY for domain signing-key
 * validity checks (expiry/revocation), which — like
 * `liblinkkeys::assertions::check_signing_key_valid` — are evaluated
 * against wall-clock time, independent of any caller-supplied `now` used
 * for payload timestamp bounds. See revocations.json's note on this. */
int64_t lrp_wall_clock_now(void);

/* Check `(issued_at, expires_at)` against `now`, tolerant of `skew_seconds`
 * clock skew in either direction. Boundaries inclusive. */
int lrp_check_timestamps(const char *issued_at, const char *expires_at, int64_t now_unix,
                          int64_t skew_seconds, lrp_error *err);

int lrp_check_expirations_impl(const char *expires_at, int64_t now_unix,
                                lrp_expiration_status *out, lrp_error *err);

int lrp_verify_nonce_state(const uint8_t *expected_nonce, size_t expected_nonce_len,
                            const uint8_t *expected_state, size_t expected_state_len,
                            const uint8_t *actual_nonce, size_t actual_nonce_len,
                            const uint8_t *actual_state, size_t actual_state_len, lrp_error *err);
int lrp_verify_audience(const char *payload_audience_fingerprint, const char *local_rp_fingerprint,
                         lrp_error *err);
int lrp_verify_issuer(const char *payload_user_domain, const char *expected_domain,
                       lrp_error *err);
int lrp_verify_callback_url(const char *payload_callback_url, const char *arrived_url,
                             lrp_error *err);
int lrp_check_callback_header_matches_payload(const lrp_w_callback_header *header,
                                               const lrp_w_callback_payload *payload,
                                               lrp_error *err);

/* Domain-signing-key validity: key_usage == "sign" and not revoked/expired
 * at `lrp_wall_clock_now()`. Shared by callback-payload envelope
 * verification, claim-signature verification, and revocation-certificate
 * signer filtering. */
int lrp_check_signing_key_valid(const lrp_domain_public_key *key, lrp_error *err);

/* Verify a domain-signed SignedLocalRpCallbackPayload envelope against a
 * fetched key set: resolve signing_key_id, check key validity, verify the
 * envelope signature, decode the payload, check its issued_at/expires_at
 * bounds. Nothing inside `out_payload` is trustworthy before this
 * succeeds. */
int lrp_verify_local_rp_callback_payload(const lrp_w_signed_callback_payload *signed_payload,
                                          const lrp_domain_public_key *domain_keys,
                                          size_t domain_keys_count, int64_t now_unix,
                                          int64_t skew_seconds, lrp_w_callback_payload *out_payload,
                                          lrp_error *err);

/* --------------------------------------------------------------------- */
/* Callback sealed box (Wire Precision: "Callback sealed box")           */
/* --------------------------------------------------------------------- */

/* `tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)`,
 * then HKDF-SHA256(salt=none, ikm=shared_secret).expand(info=context, 32).
 * `out_context` doubles as the AEAD associated-data prefix; caller appends
 * the exact header bytes to it. */
int lrp_local_rp_callback_kdf(lrp_aead_suite suite, const uint8_t ephemeral_public[32],
                               const uint8_t recipient_public[32], const uint8_t *shared_secret,
                               size_t shared_secret_len, uint8_t out_key[32], lrp_bytes *out_context,
                               lrp_error *err);

/* Open a LocalRpEncryptedCallback with the local RP's encryption private
 * key. `recipient_public_key` is the local RP's own encryption public key
 * (already known — no need to re-derive it from the private key).
 * `allowed_suites` is this identity's own descriptor's advertised list: a
 * header naming a suite outside it is rejected even if the suite id is a
 * real registry member. Returns the decoded header (cleartext routing
 * metadata) and the still-domain-signature-UNVERIFIED signed callback
 * payload; callers must still call
 * `lrp_verify_local_rp_callback_payload` + `lrp_check_callback_header_matches_payload`
 * before trusting anything. */
int lrp_open_local_rp_callback(const uint8_t *header_bytes, size_t header_len,
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                const uint8_t recipient_private_key[32],
                                const uint8_t recipient_public_key[32],
                                const char *const *allowed_suites, size_t allowed_suites_count,
                                lrp_w_callback_header *out_header,
                                lrp_w_signed_callback_payload *out_signed_payload, lrp_error *err);

#endif
