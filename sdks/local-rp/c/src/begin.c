/* begin_local_login (design doc: "SDK API Shape", "Flow" steps 4-6).
 * Mirrors `sdks/local-rp/rust/src/begin.rs` / `sdks/local-rp/go/begin.go`.
 *
 * The signing work is pure/offline. The one network touch is a DNS TXT
 * lookup of `_linkkeys_apis.<user_domain>` to discover the browser-facing
 * HTTPS endpoint (the identity domain is a trust domain, not necessarily
 * the host serving the login routes — see src/browser.c). The resolver is
 * injectable via lrp_begin_login_config.dns; on any discovery failure the
 * redirect falls back to `https://<user_domain>`. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browser.h"
#include "cbor.h"
#include "crypto.h"
#include "encoding.h"
#include "error.h"
#include "identity_input.h"
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

static int identity_username_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           strchr("!#$%&'*+-/=?^_`{|}~.", c) != NULL;
}

static int validate_identity_domain(const char *domain) {
    size_t domain_len = strlen(domain);
    if (domain_len == 0 || domain_len > 259) return 0;
    const char *colon = strrchr(domain, ':');
    size_t host_len = domain_len;
    if (colon != NULL) {
        if (strchr(domain, ':') != colon || colon == domain || colon[1] == '\0') return 0;
        for (const char *p = colon + 1; *p != '\0'; p++) {
            if (*p < '0' || *p > '9') return 0;
        }
        char *end = NULL;
        long port = strtol(colon + 1, &end, 10);
        if (*end != '\0' || port < 1 || port > 65535) return 0;
        host_len = (size_t)(colon - domain);
    }
    if (host_len == 0 || host_len > 253 || (colon == NULL && memchr(domain, '.', host_len) == NULL)) return 0;
    size_t label_len = 0;
    for (size_t i = 0; i <= host_len; i++) {
        unsigned char c = (unsigned char)(i == host_len ? '.' : domain[i]);
        if (c == '.') {
            if (label_len == 0 || label_len > 63 || domain[i - label_len] == '-' || domain[i - 1] == '-') return 0;
            label_len = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-')) return 0;
            label_len++;
        }
    }
    return 1;
}

int lrp_parse_identity_input(const char *value, lrp_parsed_identity_input *out, lrp_error *err) {
    if (value == NULL) return lrp_fail(err, LRP_ERR_INVALID_INPUT, "identity must be a username@domain or a domain");
    while (*value == ' ' || *value == '\t' || *value == '\r' || *value == '\n') value++;
    size_t len = strlen(value);
    while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\t' || value[len - 1] == '\r' || value[len - 1] == '\n')) len--;
    const char *at = memchr(value, '@', len);
    if (len == 0 || (at != NULL && memchr(at + 1, '@', len - (size_t)(at + 1 - value)) != NULL)) goto invalid;
    size_t username_len = at == NULL ? 0 : (size_t)(at - value);
    const char *domain = at == NULL ? value : at + 1;
    size_t domain_len = len - (size_t)(domain - value);
    if (username_len > 64 || domain_len > 259 || domain_len == 0) goto invalid;
    memset(out, 0, sizeof(*out));
    if (at != NULL) {
        if (username_len == 0 || value[0] == '.' || value[username_len - 1] == '.') goto invalid;
        for (size_t i = 0; i < username_len; i++) {
            if ((unsigned char)value[i] > 127 || !identity_username_char((unsigned char)value[i]) ||
                (value[i] == '.' && i > 0 && value[i - 1] == '.')) goto invalid;
        }
        memcpy(out->username, value, username_len);
        out->username[username_len] = '\0';
        out->has_username = 1;
    }
    memcpy(out->domain, domain, domain_len);
    out->domain[domain_len] = '\0';
    for (size_t i = 0; i < domain_len; i++) {
        unsigned char c = (unsigned char)out->domain[i];
        if (c > 127) goto invalid;
        if (c >= 'A' && c <= 'Z') out->domain[i] = (char)(c + ('a' - 'A'));
    }
    if (!validate_identity_domain(out->domain)) goto invalid;
    return 0;
invalid:
    return lrp_fail(err, LRP_ERR_INVALID_INPUT, "identity must be a username@domain or a domain");
}

int lrp_begin_local_login(const lrp_begin_login_config *config, lrp_login_redirect *out_redirect,
                           lrp_pending_login *out_pending, lrp_error *err) {
    memset(out_redirect, 0, sizeof(*out_redirect));
    memset(out_pending, 0, sizeof(*out_pending));

    if (config->identity == NULL) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "identity is required");
    }
    if (validate_callback_scheme(config->callback_url, err) != 0) return -1;
    lrp_parsed_identity_input identity;
    if (lrp_parse_identity_input(config->user_domain, &identity, err) != 0) return -1;

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

    /* Wire Precision: "Begin route: GET /auth/local-rp?signed_request=<...>"
     * — mirrors the existing GET /auth/authorize?signed_request=... shape.
     * The host comes from `_linkkeys_apis.<user_domain>` discovery (with a
     * fallback to the identity domain itself); pending.user_domain stays
     * the identity domain — verification is bound to it, never to the
     * discovered service host. */
    lrp_dns_resolver default_dns_storage = lrp_default_dns_resolver();
    lrp_dns_resolver *dns = config->dns != NULL ? config->dns : &default_dns_storage;
    lrp_str redirect = {0};
    rc = lrp_resolve_browser_endpoint(dns, identity.domain, LRP_BROWSER_ROUTE_LOCAL_RP,
                                      encoded.data, &redirect, err);
    lrp_str_free(&encoded);
    if (rc != 0) return -1;
    if (identity.has_username) {
        /* The endpoint's query is exactly `signed_request=<value>` (no
         * fragment), so appending one more encoded pair is well-formed. */
        lrp_str encoded_username = {0};
        if (lrp_percent_encode_query_value(identity.username, &encoded_username, err) != 0) {
            lrp_str_free(&redirect);
            return -1;
        }
        size_t url_len = strlen(redirect.data) + strlen("&username=") + strlen(encoded_username.data) + 1;
        char *with_username = (char *)malloc(url_len);
        if (with_username == NULL) {
            lrp_str_free(&encoded_username);
            lrp_str_free(&redirect);
            return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
        }
        snprintf(with_username, url_len, "%s&username=%s", redirect.data, encoded_username.data);
        lrp_str_free(&encoded_username);
        lrp_str_free(&redirect);
        redirect.data = with_username;
    }

    out_redirect->redirect_url = redirect;

    out_pending->nonce.data = (uint8_t *)malloc(32);
    memcpy(out_pending->nonce.data, nonce, 32);
    out_pending->nonce.len = 32;
    out_pending->state.data = (uint8_t *)malloc(32);
    memcpy(out_pending->state.data, state, 32);
    out_pending->state.len = 32;
    out_pending->user_domain.data = strdup(identity.domain);
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
