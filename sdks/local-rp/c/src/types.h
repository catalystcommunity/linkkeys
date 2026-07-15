/* CSIL wire types this SDK needs, plus their CBOR encode/decode.
 *
 * Field-order note (see cbor.h): the generated Rust codec decodes every
 * CSIL type map by KEY LOOKUP, not position, so this encoder is free to
 * choose its own field order for structures the local RP builds and signs
 * (LocalRpDescriptor, LocalRpLoginRequest, LocalRpTicketRedemptionRequest,
 * EmptyRequest, GetRevocationsRequest) — verified against the round-trip
 * and flow tests, not byte-for-byte against a fixed vector (only the
 * signature INPUT bytes for pre-built vectors are byte-for-byte checked;
 * see local_rp.h's envelope_signature_input). Decoders below accept
 * whatever field order a peer used, exactly like the Rust codec does.
 *
 * Types this SDK never needs to decode fully (LocalRpDescriptor payload
 * beyond a couple of fields, LocalRpLoginRequest) are decoded narrowly via
 * plain cbor_map_get calls at their one call site instead of getting a
 * dedicated struct here — see local_rp.c.
 */
#ifndef LRP_INTERNAL_TYPES_H
#define LRP_INTERNAL_TYPES_H

#include "cbor.h"
#include "linkkeys_local_rp.h"

/* ----------------------------- encoders ------------------------------- */

int lrp_encode_descriptor(const char *app_name, const char *local_domain_hint,
                           const uint8_t signing_public_key[32],
                           const uint8_t encryption_public_key[32], const char *fingerprint,
                           const char *const *supported_suites, size_t supported_suites_count,
                           const char *created_at, const char *expires_at, lrp_bytes *out,
                           lrp_error *err);

int lrp_encode_login_request(const uint8_t *descriptor_cbor, size_t descriptor_cbor_len,
                              const uint8_t *descriptor_sig, size_t descriptor_sig_len,
                              const char *callback_url, const uint8_t *nonce, size_t nonce_len,
                              const uint8_t *state, size_t state_len,
                              const char *const *requested_claims, size_t requested_claims_count,
                              const char *const *required_claims, size_t required_claims_count,
                              const char *issued_at, const char *expires_at, lrp_bytes *out,
                              lrp_error *err);

int lrp_encode_ticket_redemption_request(const uint8_t *claim_ticket, size_t claim_ticket_len,
                                          const char *fingerprint, const char *issued_at,
                                          lrp_bytes *out, lrp_error *err);

int lrp_encode_empty_request(lrp_bytes *out, lrp_error *err);
int lrp_encode_get_revocations_request(const char *since, lrp_bytes *out, lrp_error *err);

/* ----------------------------- decoders ------------------------------- */

typedef struct lrp_w_encrypted_callback {
    lrp_bytes header;
    lrp_bytes ciphertext;
} lrp_w_encrypted_callback;
void lrp_w_encrypted_callback_free(lrp_w_encrypted_callback *v);
int lrp_decode_encrypted_callback(const uint8_t *data, size_t len, lrp_w_encrypted_callback *out,
                                   lrp_error *err);

typedef struct lrp_w_callback_header {
    lrp_str fingerprint;
    lrp_bytes nonce;
    lrp_bytes state;
    lrp_str suite;
    uint8_t ephemeral_public_key[32];
    uint8_t aead_nonce[12];
    lrp_str issued_at;
    lrp_str expires_at;
} lrp_w_callback_header;
void lrp_w_callback_header_free(lrp_w_callback_header *v);
int lrp_decode_callback_header(const uint8_t *data, size_t len, lrp_w_callback_header *out,
                                lrp_error *err);
/* Re-encode a (possibly tampered) header the same way the decoder expects
 * it — used only by tests that build negative header-flip cases. */
int lrp_encode_callback_header(const lrp_w_callback_header *h, lrp_bytes *out, lrp_error *err);

typedef struct lrp_w_signed_callback_payload {
    lrp_bytes payload;
    lrp_str signing_key_id;
    lrp_bytes signature;
} lrp_w_signed_callback_payload;
void lrp_w_signed_callback_payload_free(lrp_w_signed_callback_payload *v);
int lrp_decode_signed_callback_payload(const uint8_t *data, size_t len,
                                        lrp_w_signed_callback_payload *out, lrp_error *err);

typedef struct lrp_w_callback_payload {
    lrp_str user_id;
    lrp_str user_domain;
    lrp_bytes claim_ticket;
    lrp_str audience_fingerprint;
    lrp_str callback_url;
    lrp_bytes nonce;
    lrp_bytes state;
    lrp_str issued_at;
    lrp_str expires_at;
} lrp_w_callback_payload;
void lrp_w_callback_payload_free(lrp_w_callback_payload *v);
int lrp_decode_callback_payload(const uint8_t *data, size_t len, lrp_w_callback_payload *out,
                                 lrp_error *err);

void lrp_claim_free_fields(lrp_claim *c);
void lrp_claims_array_free(lrp_claim *arr, size_t n);
void lrp_domain_public_key_free_fields(lrp_domain_public_key *k);
void lrp_domain_public_keys_array_free(lrp_domain_public_key *arr, size_t n);

/* Decode a single Claim from its standalone CBOR encoding (used directly by
 * claims.json conformance vectors, which ship `claim_cbor_hex` for one
 * claim rather than a whole response — same pattern as
 * lrp_decode_revocation_certificate below). */
int lrp_decode_claim(const uint8_t *data, size_t len, lrp_claim *out, lrp_error *err);

/* Re-encode a decoded Claim into its canonical CBOR wire form. claim_value
 * is written as a byte string (never text — see claims.json's README
 * section on the bstr/tstr trap); an absent expires_at/revoked_at is an
 * omitted map key, never CBOR null; map key order is the RFC 8949
 * canonical order the Rust ciborium generator emits (cbor_write_canon_map).
 * Used only by conformance tests to verify byte-exact round-tripping — the
 * SDK itself only ever receives Claims, never builds them. */
int lrp_encode_claim(const lrp_claim *claim, lrp_bytes *out, lrp_error *err);

typedef struct lrp_w_ticket_redemption_response {
    lrp_str user_id;
    lrp_str user_domain;
    lrp_claim *claims;
    size_t claims_count;
    lrp_str ticket_expires_at;
} lrp_w_ticket_redemption_response;
void lrp_w_ticket_redemption_response_free(lrp_w_ticket_redemption_response *v);
int lrp_decode_ticket_redemption_response(const uint8_t *data, size_t len,
                                           lrp_w_ticket_redemption_response *out, lrp_error *err);
/* Re-encode a decoded LocalRpTicketRedemptionResponse into its canonical
 * CBOR wire form. Used only by conformance tests. */
int lrp_encode_ticket_redemption_response(const lrp_w_ticket_redemption_response *resp,
                                           lrp_bytes *out, lrp_error *err);

typedef struct lrp_w_get_domain_keys_response {
    lrp_str domain;
    lrp_domain_public_key *keys;
    size_t keys_count;
    int recent_revocations_present;
    int recent_revocations_available;
} lrp_w_get_domain_keys_response;
void lrp_w_get_domain_keys_response_free(lrp_w_get_domain_keys_response *v);
int lrp_decode_get_domain_keys_response(const uint8_t *data, size_t len,
                                         lrp_w_get_domain_keys_response *out, lrp_error *err);

typedef struct lrp_w_revocation_certificate {
    lrp_str target_key_id;
    lrp_str target_fingerprint;
    lrp_str revoked_at;
    lrp_claim_signature *signatures;
    size_t signatures_count;
} lrp_w_revocation_certificate;
void lrp_w_revocation_certificate_free(lrp_w_revocation_certificate *v);

typedef struct lrp_w_get_revocations_response {
    lrp_w_revocation_certificate *items;
    size_t count;
} lrp_w_get_revocations_response;
void lrp_w_get_revocations_response_free(lrp_w_get_revocations_response *v);
int lrp_decode_get_revocations_response(const uint8_t *data, size_t len,
                                         lrp_w_get_revocations_response *out, lrp_error *err);

/* Decode a single RevocationCertificate from its standalone CBOR encoding
 * (used directly by revocation-certificate conformance vectors, which ship
 * `certificate_cbor_hex` for one certificate rather than a whole response). */
int lrp_decode_revocation_certificate(const uint8_t *data, size_t len,
                                       lrp_w_revocation_certificate *out, lrp_error *err);

#endif
