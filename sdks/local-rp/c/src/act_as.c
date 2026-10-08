/* Act-as grants, grantee side (docs/spec/reserved/act-as-grants.md).
 * Mirrors liblinkkeys::act_as (GranteeSigner::LocalRp, sign_grant_request,
 * sign_refresh_request, present) for a local RP. A local RP can be a
 * grantee only after its home domain approved it, and can never be an
 * audience, so this file has no audience-side verification.
 *
 * Encoding: every map goes through cbor_write_canon_map, which sorts
 * entries by their encoded key bytes. That is the generated CSIL codec's
 * canonical order, so the signed bytes equal the vectors in
 * sdks/regular-rp/conformance/act_as_grantee_signing.json. Received
 * structures (SignedActAsScopeSet, SignedActAsGrant) are decoded by key
 * and re-encoded canonically, exactly like a decode/encode round trip in
 * the generated codec. */
#include "act_as.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp */

#include <openssl/crypto.h>

#include "browser.h"
#include "crypto.h"
#include "encoding.h"
#include "error.h"
#include "identity_input.h"
#include "local_rp.h"
#include "rpc.h"
#include "time_util.h"

/* --------------------------------------------------------------------- */
/* Canonical map builder                                                  */
/* --------------------------------------------------------------------- */

#define MB_MAX 8

/* Collects (key, encoded value) pairs, then writes one canonical map.
 * Any write failure is sticky in `rc`; mb_finish always frees. */
typedef struct {
    cbor_map_entry entries[MB_MAX];
    cbor_buf values[MB_MAX];
    size_t n;
    int rc;
} map_builder;

static void mb_init(map_builder *m) { memset(m, 0, sizeof(*m)); }

static cbor_buf *mb_slot(map_builder *m, const char *key) {
    if (m->n >= MB_MAX) {
        m->rc = -1;
        return NULL;
    }
    cbor_buf_init(&m->values[m->n]);
    m->entries[m->n].key = key;
    return &m->values[m->n++];
}

static void mb_text(map_builder *m, const char *key, const char *s, size_t len) {
    cbor_buf *b = mb_slot(m, key);
    if (b != NULL && cbor_write_text(b, s, len) != 0) m->rc = -1;
}

static void mb_cstr(map_builder *m, const char *key, const char *s) { mb_text(m, key, s, strlen(s)); }

static void mb_bytes(map_builder *m, const char *key, const uint8_t *data, size_t len) {
    cbor_buf *b = mb_slot(m, key);
    if (b != NULL && cbor_write_bytes(b, data, len) != 0) m->rc = -1;
}

static void mb_uint(map_builder *m, const char *key, uint64_t v) {
    cbor_buf *b = mb_slot(m, key);
    if (b != NULL && cbor_write_uint(b, v) != 0) m->rc = -1;
}

/* An already-encoded CBOR item (a nested map). */
static void mb_raw(map_builder *m, const char *key, const cbor_buf *item) {
    cbor_buf *b = mb_slot(m, key);
    if (b != NULL && cbor_write_raw(b, item->data, item->len) != 0) m->rc = -1;
}

static int mb_finish(map_builder *m, cbor_buf *out) {
    int rc = m->rc;
    if (rc == 0) {
        for (size_t i = 0; i < m->n; i++) {
            m->entries[i].value_data = m->values[i].data;
            m->entries[i].value_len = m->values[i].len;
        }
        rc = cbor_write_canon_map(out, m->entries, m->n);
    }
    for (size_t i = 0; i < m->n; i++) cbor_buf_free(&m->values[i]);
    m->n = 0;
    return rc;
}

static int oom(lrp_error *err, const char *what) {
    return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "%s: out of memory", what);
}

/* --------------------------------------------------------------------- */
/* Small helpers                                                          */
/* --------------------------------------------------------------------- */

void lrp_act_as_format_time(int64_t unix_seconds, char out[32]) {
    /* lrp_format_rfc3339 writes "...+00:00"; the act-as wire form ends in
     * "Z" (liblinkkeys act_as::format_time). */
    lrp_format_rfc3339(unix_seconds, out);
    size_t len = strlen(out);
    if (len >= 6 && strcmp(out + len - 6, "+00:00") == 0) {
        out[len - 6] = 'Z';
        out[len - 5] = '\0';
    }
}

static const cbor_value *field_of(const cbor_value *map, const char *key, cbor_type type) {
    const cbor_value *v = cbor_map_get(map, key);
    return (v != NULL && v->type == type) ? v : NULL;
}

/* Fresh 32 random bytes as unpadded base64url text. */
static int random_nonce_text(lrp_str *out, lrp_error *err) {
    uint8_t raw[32];
    if (lrp_rand_bytes(raw, sizeof(raw), err) != 0) return -1;
    return lrp_base64url_encode(raw, sizeof(raw), out, err);
}

static int validate_callback_scheme(const char *url, lrp_error *err) {
    if (url != NULL && (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0)) {
        return 0;
    }
    return lrp_fail(err, LRP_ERR_INVALID_INPUT, "callback_url must be http:// or https://");
}

/* GranteeRef = { local_rp_descriptor_fingerprint: text } */
static int write_grantee_ref(cbor_buf *out, const lrp_identity *identity) {
    map_builder m;
    mb_init(&m);
    mb_cstr(&m, "local_rp_descriptor_fingerprint", identity->fingerprint);
    return mb_finish(&m, out);
}

/* Sign CBOR([tag, payload]) with the descriptor signing key and write
 * { <payload_key>: bytes, proof: GranteeProof } — the shape shared by
 * SignedActAsGrantRequest, SignedActAsRefreshRequest, and
 * SignedActAsPresentation. */
static int sign_and_wrap(const lrp_identity *identity, const char *tag, const char *payload_key,
                         const cbor_buf *payload, cbor_buf *out, lrp_error *err) {
    lrp_bytes signature = {0};
    if (lrp_sign_envelope(tag, payload->data, payload->len, identity->signing_private_key,
                          &signature, err) != 0) {
        return -1;
    }

    cbor_buf descriptor, key_sig, proof;
    cbor_buf_init(&descriptor);
    cbor_buf_init(&key_sig);
    cbor_buf_init(&proof);
    map_builder m;
    int rc;

    /* SignedLocalRpDescriptor = { descriptor: bytes, signature: bytes } */
    mb_init(&m);
    mb_bytes(&m, "descriptor", identity->descriptor_cbor.data, identity->descriptor_cbor.len);
    mb_bytes(&m, "signature", identity->descriptor_signature.data,
             identity->descriptor_signature.len);
    rc = mb_finish(&m, &descriptor);

    /* ApplicationKeySignature = { signed_by_key_id: fingerprint, signature } */
    if (rc == 0) {
        mb_init(&m);
        mb_cstr(&m, "signed_by_key_id", identity->fingerprint);
        mb_bytes(&m, "signature", signature.data, signature.len);
        rc = mb_finish(&m, &key_sig);
    }

    /* GranteeProof = { local_rp_descriptor, signature } */
    if (rc == 0) {
        mb_init(&m);
        mb_raw(&m, "local_rp_descriptor", &descriptor);
        mb_raw(&m, "signature", &key_sig);
        rc = mb_finish(&m, &proof);
    }

    if (rc == 0) {
        mb_init(&m);
        mb_bytes(&m, payload_key, payload->data, payload->len);
        mb_raw(&m, "proof", &proof);
        rc = mb_finish(&m, out);
    }

    lrp_bytes_free(&signature);
    cbor_buf_free(&descriptor);
    cbor_buf_free(&key_sig);
    cbor_buf_free(&proof);
    return rc != 0 ? oom(err, "act-as signed envelope") : 0;
}

/* --------------------------------------------------------------------- */
/* Received structures: decode by key, re-encode canonically              */
/* --------------------------------------------------------------------- */

/* SignedActAsScopeSet = { scope_set: bytes, signer_instance_id: text,
 *                         signatures: [+ ApplicationKeySignature] }
 * ApplicationKeySignature = { signed_by_key_id: text, signature: bytes }
 * `scope_set` stays opaque bytes, so ActAsScopeSet fields such as
 * audience_handle_claim pass through unchanged. */
static int reencode_scope_set(const cbor_value *v, cbor_buf *out, lrp_error *err) {
    const cbor_value *scope_set = field_of(v, "scope_set", CBOR_T_BYTES);
    const cbor_value *signer = field_of(v, "signer_instance_id", CBOR_T_TEXT);
    const cbor_value *sigs = field_of(v, "signatures", CBOR_T_ARRAY);
    if (scope_set == NULL || signer == NULL || sigs == NULL || sigs->items_len == 0) {
        return lrp_fail(err, LRP_ERR_DECODE, "SignedActAsScopeSet is missing a required field");
    }
    cbor_buf arr;
    cbor_buf_init(&arr);
    int rc = cbor_write_array_header(&arr, sigs->items_len);
    for (size_t i = 0; rc == 0 && i < sigs->items_len; i++) {
        const cbor_value *s = &sigs->items[i];
        const cbor_value *key_id = field_of(s, "signed_by_key_id", CBOR_T_TEXT);
        const cbor_value *sig_bytes = field_of(s, "signature", CBOR_T_BYTES);
        if (key_id == NULL || sig_bytes == NULL) {
            cbor_buf_free(&arr);
            return lrp_fail(err, LRP_ERR_DECODE, "SignedActAsScopeSet signature is missing a field");
        }
        map_builder m;
        mb_init(&m);
        mb_text(&m, "signed_by_key_id", (const char *)key_id->bytes, key_id->bytes_len);
        mb_bytes(&m, "signature", sig_bytes->bytes, sig_bytes->bytes_len);
        rc = mb_finish(&m, &arr);
    }
    if (rc == 0) {
        map_builder m;
        mb_init(&m);
        mb_bytes(&m, "scope_set", scope_set->bytes, scope_set->bytes_len);
        mb_text(&m, "signer_instance_id", (const char *)signer->bytes, signer->bytes_len);
        mb_raw(&m, "signatures", &arr);
        rc = mb_finish(&m, out);
    }
    cbor_buf_free(&arr);
    return rc != 0 ? oom(err, "SignedActAsScopeSet") : 0;
}

/* SignedActAsGrant = { grant: bytes, signatures: [* ClaimSignature] }
 * ClaimSignature   = { domain: text, signed_by_key_id: text, signature: bytes } */
int lrp_act_as_reencode_signed_grant(const cbor_value *v, cbor_buf *out,
                                     const cbor_value **out_grant, lrp_error *err) {
    const cbor_value *grant = field_of(v, "grant", CBOR_T_BYTES);
    const cbor_value *sigs = field_of(v, "signatures", CBOR_T_ARRAY);
    if (grant == NULL || sigs == NULL) {
        return lrp_fail(err, LRP_ERR_DECODE, "SignedActAsGrant is missing a required field");
    }
    cbor_buf arr;
    cbor_buf_init(&arr);
    int rc = cbor_write_array_header(&arr, sigs->items_len);
    for (size_t i = 0; rc == 0 && i < sigs->items_len; i++) {
        const cbor_value *s = &sigs->items[i];
        const cbor_value *domain = field_of(s, "domain", CBOR_T_TEXT);
        const cbor_value *key_id = field_of(s, "signed_by_key_id", CBOR_T_TEXT);
        const cbor_value *sig = field_of(s, "signature", CBOR_T_BYTES);
        if (domain == NULL || key_id == NULL || sig == NULL) {
            cbor_buf_free(&arr);
            return lrp_fail(err, LRP_ERR_DECODE, "SignedActAsGrant signature is missing a field");
        }
        map_builder m;
        mb_init(&m);
        mb_text(&m, "domain", (const char *)domain->bytes, domain->bytes_len);
        mb_text(&m, "signed_by_key_id", (const char *)key_id->bytes, key_id->bytes_len);
        mb_bytes(&m, "signature", sig->bytes, sig->bytes_len);
        rc = mb_finish(&m, &arr);
    }
    if (rc == 0) {
        map_builder m;
        mb_init(&m);
        mb_bytes(&m, "grant", grant->bytes, grant->bytes_len);
        mb_raw(&m, "signatures", &arr);
        rc = mb_finish(&m, out);
    }
    cbor_buf_free(&arr);
    if (rc != 0) return oom(err, "SignedActAsGrant");
    if (out_grant != NULL) *out_grant = grant;
    return 0;
}

/* --------------------------------------------------------------------- */
/* Deterministic builders                                                 */
/* --------------------------------------------------------------------- */

int lrp_act_as_sign_grant_request(const lrp_identity *identity, const uint8_t *scope_set_cbor,
                                  size_t scope_set_cbor_len, int has_lifetime,
                                  int64_t lifetime_seconds, int has_renewal_window,
                                  int64_t renewal_window_seconds, const char *callback_url,
                                  const char *nonce, const char *requested_at,
                                  const char *expires_at, lrp_bytes *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (has_lifetime && lifetime_seconds <= 0) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "requested lifetime must be positive");
    }
    if (has_renewal_window && renewal_window_seconds < 0) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "requested renewal window must not be negative");
    }
    if (scope_set_cbor == NULL || scope_set_cbor_len == 0) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "scope set is required");
    }

    cbor_value *decoded = NULL;
    if (cbor_decode(scope_set_cbor, scope_set_cbor_len, &decoded, err) != 0) return -1;
    cbor_buf scope_set, grantee, request, signed_buf;
    cbor_buf_init(&scope_set);
    cbor_buf_init(&grantee);
    cbor_buf_init(&request);
    cbor_buf_init(&signed_buf);
    int rc = reencode_scope_set(decoded, &scope_set, err);
    cbor_value_free(decoded);
    free(decoded);

    if (rc == 0 && write_grantee_ref(&grantee, identity) != 0) rc = oom(err, "GranteeRef");
    if (rc == 0) {
        /* A local RP has no enrolling account: grantee_handle_claim is
         * always omitted. */
        map_builder m;
        mb_init(&m);
        mb_raw(&m, "grantee", &grantee);
        mb_raw(&m, "scope_set", &scope_set);
        if (has_lifetime) mb_uint(&m, "requested_lifetime_seconds", (uint64_t)lifetime_seconds);
        if (has_renewal_window) {
            mb_uint(&m, "requested_renewal_window_seconds", (uint64_t)renewal_window_seconds);
        }
        mb_cstr(&m, "callback_url", callback_url);
        mb_cstr(&m, "nonce", nonce);
        mb_cstr(&m, "requested_at", requested_at);
        mb_cstr(&m, "expires_at", expires_at);
        if (mb_finish(&m, &request) != 0) rc = oom(err, "ActAsGrantRequest");
    }
    if (rc == 0) {
        rc = sign_and_wrap(identity, LRP_ACT_AS_TAG_GRANT_REQUEST, "request", &request, &signed_buf,
                           err);
    }
    cbor_buf_free(&scope_set);
    cbor_buf_free(&grantee);
    cbor_buf_free(&request);
    if (rc != 0) {
        cbor_buf_free(&signed_buf);
        return -1;
    }
    *out = cbor_buf_release(&signed_buf);
    return 0;
}

int lrp_act_as_sign_refresh_request(const lrp_identity *identity, const char *grant_id,
                                    const char *requested_at, const char *expires_at,
                                    const char *nonce, lrp_bytes *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    cbor_buf grantee, request, signed_buf;
    cbor_buf_init(&grantee);
    cbor_buf_init(&request);
    cbor_buf_init(&signed_buf);
    int rc = 0;
    if (write_grantee_ref(&grantee, identity) != 0) rc = oom(err, "GranteeRef");
    if (rc == 0) {
        map_builder m;
        mb_init(&m);
        mb_cstr(&m, "grant_id", grant_id);
        mb_raw(&m, "grantee", &grantee);
        mb_cstr(&m, "requested_at", requested_at);
        mb_cstr(&m, "expires_at", expires_at);
        mb_cstr(&m, "nonce", nonce);
        if (mb_finish(&m, &request) != 0) rc = oom(err, "ActAsRefreshRequest");
    }
    if (rc == 0) {
        rc = sign_and_wrap(identity, LRP_ACT_AS_TAG_REFRESH_REQUEST, "request", &request,
                           &signed_buf, err);
    }
    cbor_buf_free(&grantee);
    cbor_buf_free(&request);
    if (rc != 0) {
        cbor_buf_free(&signed_buf);
        return -1;
    }
    *out = cbor_buf_release(&signed_buf);
    return 0;
}

/* --------------------------------------------------------------------- */
/* Public API                                                             */
/* --------------------------------------------------------------------- */

void lrp_act_as_redirect_free(lrp_act_as_redirect *r) {
    if (r == NULL) return;
    lrp_str_free(&r->redirect_url);
}

void lrp_pending_act_as_free(lrp_pending_act_as *p) {
    if (p == NULL) return;
    lrp_str_free(&p->nonce);
    lrp_str_free(&p->user_domain);
    lrp_str_free(&p->callback_url);
}

void lrp_act_as_grant_free(lrp_act_as_grant *g) {
    if (g == NULL) return;
    lrp_bytes_free(&g->signed_grant_cbor);
    g->newly_signed = 0;
}

void lrp_act_as_credential_free(lrp_act_as_credential *c) {
    if (c == NULL) return;
    lrp_bytes_free(&c->credential_cbor);
    lrp_bytes_free(&c->presentation_cbor);
    memset(c->grant_hash, 0, sizeof(c->grant_hash));
}

static char *dup_or_null(const char *s) { return s == NULL ? NULL : strdup(s); }

int lrp_begin_act_as(const lrp_begin_act_as_config *config, lrp_act_as_redirect *out_redirect,
                     lrp_pending_act_as *out_pending, lrp_error *err) {
    memset(out_redirect, 0, sizeof(*out_redirect));
    memset(out_pending, 0, sizeof(*out_pending));
    if (config->identity == NULL) return lrp_fail(err, LRP_ERR_INVALID_INPUT, "identity is required");
    if (validate_callback_scheme(config->callback_url, err) != 0) return -1;
    lrp_parsed_identity_input identity;
    if (lrp_parse_identity_input(config->user_domain, &identity, err) != 0) return -1;
    int64_t window = config->request_window_seconds;
    if (window == 0) window = LRP_ACT_AS_DEFAULT_REQUEST_WINDOW_SECONDS;
    if (window < 0 || window > LRP_ACT_AS_MAX_REQUEST_WINDOW_SECONDS) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "request window must be 1 to %d seconds",
                        LRP_ACT_AS_MAX_REQUEST_WINDOW_SECONDS);
    }

    lrp_str nonce = {0};
    if (random_nonce_text(&nonce, err) != 0) return -1;
    char requested_at[32], expires_at[32];
    lrp_act_as_format_time(config->now_unix, requested_at);
    lrp_act_as_format_time(config->now_unix + window, expires_at);

    lrp_bytes signed_request = {0};
    if (lrp_act_as_sign_grant_request(
            config->identity, config->scope_set_cbor, config->scope_set_cbor_len,
            config->has_requested_lifetime, config->requested_lifetime_seconds,
            config->has_requested_renewal_window, config->requested_renewal_window_seconds,
            config->callback_url, nonce.data, requested_at, expires_at, &signed_request,
            err) != 0) {
        lrp_str_free(&nonce);
        return -1;
    }
    lrp_str encoded = {0};
    int rc = lrp_base64url_encode(signed_request.data, signed_request.len, &encoded, err);
    lrp_bytes_free(&signed_request);
    if (rc != 0) {
        lrp_str_free(&nonce);
        return -1;
    }

    /* Same discovery and fallback as begin_local_login. The pending domain
     * stays the identity domain, never the discovered service host. */
    lrp_dns_resolver default_dns_storage = lrp_default_dns_resolver();
    lrp_dns_resolver *dns = config->dns != NULL ? config->dns : &default_dns_storage;
    rc = lrp_resolve_browser_endpoint(dns, identity.domain, LRP_BROWSER_ROUTE_ACT_AS, encoded.data,
                                      &out_redirect->redirect_url, err);
    lrp_str_free(&encoded);
    if (rc != 0) {
        lrp_str_free(&nonce);
        return -1;
    }

    out_pending->nonce = nonce;
    out_pending->user_domain.data = dup_or_null(identity.domain);
    out_pending->callback_url.data = dup_or_null(config->callback_url);
    if (out_pending->user_domain.data == NULL || out_pending->callback_url.data == NULL) {
        lrp_pending_act_as_free(out_pending);
        lrp_act_as_redirect_free(out_redirect);
        return oom(err, "pending act-as");
    }
    return 0;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Percent-decode s[0..len) into a fresh NUL-terminated string. A '+' is
 * kept as is: the home domain percent-encodes, so it never sends one for
 * a space. A malformed escape or an embedded NUL is refused. */
static int percent_decode(const char *s, size_t len, lrp_str *out, lrp_error *err) {
    char *buf = (char *)malloc(len + 1);
    if (buf == NULL) return oom(err, "callback parameter");
    size_t w = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '%') {
            if (len - i < 3) {
                free(buf);
                return lrp_fail(err, LRP_ERR_INVALID_INPUT, "callback has a malformed escape");
            }
            int h = hex_value(s[i + 1]), l = hex_value(s[i + 2]);
            if (h < 0 || l < 0 || (h == 0 && l == 0)) {
                free(buf);
                return lrp_fail(err, LRP_ERR_INVALID_INPUT, "callback has a malformed escape");
            }
            buf[w++] = (char)((h << 4) | l);
            i += 2;
        } else {
            buf[w++] = c;
        }
    }
    buf[w] = '\0';
    out->data = buf;
    return 0;
}

int lrp_complete_act_as_callback(const lrp_pending_act_as *pending, const char *callback,
                                 lrp_str *out_grant_id, lrp_error *err) {
    memset(out_grant_id, 0, sizeof(*out_grant_id));
    if (pending == NULL || pending->nonce.data == NULL || callback == NULL) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "pending state and callback are required");
    }
    const char *query = strchr(callback, '?');
    query = query != NULL ? query + 1 : callback;
    const char *fragment = strchr(query, '#');
    const char *end = fragment != NULL ? fragment : query + strlen(query);

    lrp_str grant_id = {0}, nonce = {0};
    const char *p = query;
    while (p < end) {
        const char *amp = memchr(p, '&', (size_t)(end - p));
        const char *pair_end = amp != NULL ? amp : end;
        const char *eq = memchr(p, '=', (size_t)(pair_end - p));
        if (eq != NULL) {
            size_t key_len = (size_t)(eq - p);
            lrp_str *target = NULL;
            if (key_len == 15 && memcmp(p, "act_as_grant_id", 15) == 0) target = &grant_id;
            if (key_len == 5 && memcmp(p, "nonce", 5) == 0) target = &nonce;
            if (target != NULL) {
                if (target->data != NULL) {
                    lrp_str_free(&grant_id);
                    lrp_str_free(&nonce);
                    return lrp_fail(err, LRP_ERR_INVALID_INPUT,
                                    "callback repeats an act-as parameter");
                }
                if (percent_decode(eq + 1, (size_t)(pair_end - eq - 1), target, err) != 0) {
                    lrp_str_free(&grant_id);
                    lrp_str_free(&nonce);
                    return -1;
                }
            }
        }
        p = amp != NULL ? amp + 1 : end;
    }

    if (grant_id.data == NULL || grant_id.data[0] == '\0' || nonce.data == NULL) {
        lrp_str_free(&grant_id);
        lrp_str_free(&nonce);
        return lrp_fail(err, LRP_ERR_INVALID_INPUT,
                        "callback must carry act_as_grant_id and nonce");
    }
    size_t want_len = strlen(pending->nonce.data);
    int match = strlen(nonce.data) == want_len &&
                CRYPTO_memcmp(nonce.data, pending->nonce.data, want_len) == 0;
    lrp_str_free(&nonce);
    if (!match) {
        lrp_str_free(&grant_id);
        return lrp_fail(err, LRP_ERR_VERIFICATION, "act-as callback nonce does not match");
    }
    *out_grant_id = grant_id;
    return 0;
}

/* The grant the home domain returned must be the one we asked for: its
 * grant_id, this local RP as the only grantee form, and the user's home
 * domain as subject_domain. The domain signature is not checked here; the
 * audience checks it. */
static int text_eq(const cbor_value *v, const char *s, int ignore_case) {
    size_t n = strlen(s);
    if (v == NULL || v->bytes_len != n) return 0;
    return ignore_case ? strncasecmp((const char *)v->bytes, s, n) == 0
                       : memcmp(v->bytes, s, n) == 0;
}

static int check_returned_grant(const cbor_value *grant_bytes, const char *grant_id,
                                const char *user_domain, const lrp_identity *identity,
                                lrp_error *err) {
    cbor_value *grant = NULL;
    if (cbor_decode(grant_bytes->bytes, grant_bytes->bytes_len, &grant, err) != 0) return -1;
    const cbor_value *grantee = field_of(grant, "grantee", CBOR_T_MAP);
    int ok = text_eq(field_of(grant, "grant_id", CBOR_T_TEXT), grant_id, 0) &&
             text_eq(field_of(grant, "subject_domain", CBOR_T_TEXT), user_domain, 1) &&
             grantee != NULL && cbor_map_get(grantee, "application") == NULL &&
             text_eq(field_of(grantee, "local_rp_descriptor_fingerprint", CBOR_T_TEXT),
                     identity->fingerprint, 0);
    cbor_value_free(grant);
    free(grant);
    if (!ok) {
        return lrp_fail(err, LRP_ERR_VERIFICATION,
                        "refreshed grant does not name the requested grant, grantee, and domain");
    }
    return 0;
}

int lrp_refresh_act_as_grant(const lrp_refresh_act_as_config *config, lrp_act_as_grant *out,
                             lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (config->identity == NULL || config->grant_id == NULL || config->grant_id[0] == '\0') {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "identity and grant_id are required");
    }
    lrp_parsed_identity_input identity;
    if (lrp_parse_identity_input(config->user_domain, &identity, err) != 0) return -1;

    lrp_transport default_transport_storage = lrp_default_transport(LRP_ADDRESS_PERMISSIVE);
    lrp_dns_resolver default_dns_storage = lrp_default_dns_resolver();
    lrp_transport *transport =
        config->transport != NULL ? config->transport : &default_transport_storage;
    lrp_dns_resolver *dns = config->dns != NULL ? config->dns : &default_dns_storage;

    lrp_str nonce = {0};
    if (random_nonce_text(&nonce, err) != 0) return -1;
    char requested_at[32], expires_at[32];
    lrp_act_as_format_time(config->now_unix, requested_at);
    lrp_act_as_format_time(config->now_unix + LRP_ACT_AS_REFRESH_WINDOW_SECONDS, expires_at);
    lrp_bytes signed_request = {0};
    int rc = lrp_act_as_sign_refresh_request(config->identity, config->grant_id, requested_at,
                                             expires_at, nonce.data, &signed_request, err);
    lrp_str_free(&nonce);
    if (rc != 0) return -1;

    /* RefreshActAsGrantRequest = { request: SignedActAsRefreshRequest } */
    cbor_buf inner, payload;
    cbor_buf_init(&inner);
    cbor_buf_init(&payload);
    rc = cbor_write_raw(&inner, signed_request.data, signed_request.len);
    lrp_bytes_free(&signed_request);
    if (rc == 0) {
        map_builder m;
        mb_init(&m);
        mb_raw(&m, "request", &inner);
        rc = mb_finish(&m, &payload);
    }
    cbor_buf_free(&inner);
    if (rc != 0) {
        cbor_buf_free(&payload);
        return oom(err, "RefreshActAsGrantRequest");
    }

    lrp_domain_endpoint endpoint = {0};
    if (lrp_discover_domain_endpoint(dns, identity.domain, &endpoint, err) != 0) {
        cbor_buf_free(&payload);
        return -1;
    }
    lrp_bytes resp_bytes = {0};
    rc = lrp_rpc_call(transport, &endpoint, "ActAs", "refresh-grant", payload.data, payload.len,
                      &resp_bytes, err);
    lrp_domain_endpoint_free(&endpoint);
    cbor_buf_free(&payload);
    if (rc != 0) return -1;

    /* RefreshActAsGrantResponse = { grant: SignedActAsGrant, signed: bool } */
    cbor_value *resp = NULL;
    rc = cbor_decode(resp_bytes.data, resp_bytes.len, &resp, err);
    lrp_bytes_free(&resp_bytes);
    if (rc != 0) return -1;
    const cbor_value *grant = field_of(resp, "grant", CBOR_T_MAP);
    const cbor_value *signed_flag = field_of(resp, "signed", CBOR_T_BOOL);
    cbor_buf grant_buf;
    cbor_buf_init(&grant_buf);
    const cbor_value *grant_bytes = NULL;
    if (grant == NULL || signed_flag == NULL) {
        rc = lrp_fail(err, LRP_ERR_DECODE, "refresh-grant response is missing a required field");
    } else {
        rc = lrp_act_as_reencode_signed_grant(grant, &grant_buf, &grant_bytes, err);
    }
    if (rc == 0) rc = check_returned_grant(grant_bytes, config->grant_id, identity.domain,
                                            config->identity, err);
    int newly_signed = rc == 0 ? signed_flag->bool_val : 0;
    cbor_value_free(resp);
    free(resp);
    if (rc != 0) {
        cbor_buf_free(&grant_buf);
        return -1;
    }
    out->signed_grant_cbor = cbor_buf_release(&grant_buf);
    out->newly_signed = newly_signed != 0;
    return 0;
}

int lrp_act_as_present(const lrp_act_as_present_config *config, lrp_act_as_credential *out,
                       lrp_error *err) {
    memset(out, 0, sizeof(*out));
    const lrp_application_ref *aud = &config->audience;
    if (config->identity == NULL || config->signed_grant_cbor == NULL ||
        config->signed_grant_cbor_len == 0 || aud->subject_user_id == NULL ||
        aud->subject_domain == NULL || aud->application_id == NULL || config->nonce == NULL ||
        config->nonce_len == 0 || (config->request_digest == NULL && config->request_digest_len > 0)) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT,
                        "identity, grant, audience, and nonce are required");
    }

    cbor_value *decoded = NULL;
    if (cbor_decode(config->signed_grant_cbor, config->signed_grant_cbor_len, &decoded, err) != 0) {
        return -1;
    }
    cbor_buf grant_buf, audience, presentation, signed_presentation, credential;
    cbor_buf_init(&grant_buf);
    cbor_buf_init(&audience);
    cbor_buf_init(&presentation);
    cbor_buf_init(&signed_presentation);
    cbor_buf_init(&credential);
    const cbor_value *grant_bytes = NULL;
    int rc = lrp_act_as_reencode_signed_grant(decoded, &grant_buf, &grant_bytes, err);
    if (rc == 0) lrp_sha256(grant_bytes->bytes, grant_bytes->bytes_len, out->grant_hash);
    cbor_value_free(decoded);
    free(decoded);

    char presented_at[32];
    lrp_act_as_format_time(config->now_unix, presented_at);
    map_builder m;
    if (rc == 0) {
        /* ApplicationRef */
        mb_init(&m);
        mb_cstr(&m, "subject_user_id", aud->subject_user_id);
        mb_cstr(&m, "subject_domain", aud->subject_domain);
        mb_cstr(&m, "application_id", aud->application_id);
        if (mb_finish(&m, &audience) != 0) rc = oom(err, "ApplicationRef");
    }
    if (rc == 0) {
        /* ActAsPresentation */
        mb_init(&m);
        mb_bytes(&m, "grant_hash", out->grant_hash, sizeof(out->grant_hash));
        mb_raw(&m, "audience", &audience);
        mb_bytes(&m, "request_digest", config->request_digest, config->request_digest_len);
        mb_cstr(&m, "presented_at", presented_at);
        mb_bytes(&m, "nonce", config->nonce, config->nonce_len);
        if (mb_finish(&m, &presentation) != 0) rc = oom(err, "ActAsPresentation");
    }
    if (rc == 0) {
        rc = sign_and_wrap(config->identity, LRP_ACT_AS_TAG_PRESENTATION, "presentation",
                           &presentation, &signed_presentation, err);
    }
    if (rc == 0) {
        /* ActAsCredential = { grant, presentation } */
        mb_init(&m);
        mb_raw(&m, "grant", &grant_buf);
        mb_raw(&m, "presentation", &signed_presentation);
        if (mb_finish(&m, &credential) != 0) rc = oom(err, "ActAsCredential");
    }
    cbor_buf_free(&grant_buf);
    cbor_buf_free(&audience);
    cbor_buf_free(&signed_presentation);
    if (rc != 0) {
        cbor_buf_free(&presentation);
        cbor_buf_free(&credential);
        memset(out->grant_hash, 0, sizeof(out->grant_hash));
        return -1;
    }
    out->credential_cbor = cbor_buf_release(&credential);
    out->presentation_cbor = cbor_buf_release(&presentation);
    return 0;
}
