/* Act-as grantee internals: the deterministic builders behind
 * lrp_begin_act_as / lrp_refresh_act_as_grant. They take every input
 * explicitly (nonce, times), so tests can reproduce the conformance
 * vector bytes in sdks/regular-rp/conformance/act_as_grantee_signing.json.
 *
 * Every map is written with cbor_write_canon_map, so the bytes equal the
 * generated CSIL codec's canonical output (optional fields omitted when
 * absent). */
#ifndef LRP_INTERNAL_ACT_AS_H
#define LRP_INTERNAL_ACT_AS_H

#include "cbor.h"
#include "linkkeys_local_rp.h"

#define LRP_ACT_AS_TAG_GRANT_REQUEST "linkkeys-act-as-grant-request-v1alpha"
#define LRP_ACT_AS_TAG_REFRESH_REQUEST "linkkeys-act-as-refresh-request-v1alpha"
#define LRP_ACT_AS_TAG_PRESENTATION "linkkeys-act-as-presentation-v1alpha"

/* Whole-second RFC3339 UTC ending in "Z" (liblinkkeys act_as::format_time).
 * `out` must hold at least 32 bytes. */
void lrp_act_as_format_time(int64_t unix_seconds, char out[32]);

/* CBOR(SignedActAsGrantRequest). `scope_set_cbor` is decoded and
 * re-encoded canonically, exactly like the generated codec does. */
int lrp_act_as_sign_grant_request(const lrp_identity *identity, const uint8_t *scope_set_cbor,
                                  size_t scope_set_cbor_len, int has_lifetime,
                                  int64_t lifetime_seconds, int has_renewal_window,
                                  int64_t renewal_window_seconds, const char *callback_url,
                                  const char *nonce, const char *requested_at,
                                  const char *expires_at, lrp_bytes *out, lrp_error *err);

/* CBOR(SignedActAsRefreshRequest). */
int lrp_act_as_sign_refresh_request(const lrp_identity *identity, const char *grant_id,
                                    const char *requested_at, const char *expires_at,
                                    const char *nonce, lrp_bytes *out, lrp_error *err);

/* Decode a SignedActAsGrant and write its canonical encoding to `out`.
 * `*out_grant` (optional) points at the grant bytes inside `v`. */
int lrp_act_as_reencode_signed_grant(const cbor_value *v, cbor_buf *out,
                                     const cbor_value **out_grant, lrp_error *err);

#endif
