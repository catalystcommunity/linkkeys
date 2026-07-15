#include "dns.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/nameser.h>
#include <resolv.h>

#include "crypto.h"
#include "error.h"
#include "local_rp.h"

const char *lrp_dns_parse_error_name(lrp_dns_parse_error e) {
    switch (e) {
        case LRP_DNS_ERR_NONE: return "none";
        case LRP_DNS_ERR_MISSING_VERSION: return "missing_version";
        case LRP_DNS_ERR_UNSUPPORTED_VERSION: return "unsupported_version";
        case LRP_DNS_ERR_MISSING_APIS_ENDPOINT: return "missing_apis_endpoint";
        default: return "unknown";
    }
}

int lrp_linkkeys_dns_name(const char *domain, lrp_str *out, lrp_error *err) {
    size_t len = strlen("_linkkeys.") + strlen(domain) + 1;
    char *buf = (char *)malloc(len);
    if (buf == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    snprintf(buf, len, "_linkkeys.%s", domain);
    out->data = buf;
    return 0;
}

int lrp_linkkeys_apis_dns_name(const char *domain, lrp_str *out, lrp_error *err) {
    size_t len = strlen("_linkkeys_apis.") + strlen(domain) + 1;
    char *buf = (char *)malloc(len);
    if (buf == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    snprintf(buf, len, "_linkkeys_apis.%s", domain);
    out->data = buf;
    return 0;
}

void lrp_linkkeys_record_free(lrp_linkkeys_record *r) {
    if (r == NULL) return;
    for (size_t i = 0; i < r->fingerprints_count; i++) free(r->fingerprints[i]);
    free(r->fingerprints);
    r->fingerprints = NULL;
    r->fingerprints_count = 0;
}

void lrp_linkkeys_apis_free(lrp_linkkeys_apis *a) {
    if (a == NULL) return;
    lrp_str_free(&a->tcp);
    lrp_str_free(&a->https_base);
}

/* Splits `txt` on ASCII whitespace into a NUL-terminated array of
 * non-owning slices (indices into a mutable copy). Caller frees `copy`. */
typedef struct { char *start; } token;

static size_t tokenize(char *copy, token *out, size_t max_tokens) {
    size_t n = 0;
    char *p = copy;
    while (*p != '\0' && n < max_tokens) {
        while (*p != '\0' && isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;
        out[n].start = p;
        while (*p != '\0' && !isspace((unsigned char)*p)) p++;
        if (*p != '\0') {
            *p = '\0';
            p++;
        }
        n++;
    }
    return n;
}

static lrp_dns_parse_error require_lk1_version(token *tokens, size_t n) {
    const char *version = NULL;
    for (size_t i = 0; i < n; i++) {
        if (strncmp(tokens[i].start, "v=", 2) == 0) {
            version = tokens[i].start + 2;
            break;
        }
    }
    if (version == NULL) return LRP_DNS_ERR_MISSING_VERSION;
    if (strcmp(version, "lk1") != 0) return LRP_DNS_ERR_UNSUPPORTED_VERSION;
    return LRP_DNS_ERR_NONE;
}

#define MAX_TXT_TOKENS 64

lrp_dns_parse_error lrp_parse_linkkeys_txt(const char *txt, lrp_linkkeys_record *out) {
    memset(out, 0, sizeof(*out));
    char *copy = strdup(txt);
    token tokens[MAX_TXT_TOKENS];
    size_t n = tokenize(copy, tokens, MAX_TXT_TOKENS);
    lrp_dns_parse_error e = require_lk1_version(tokens, n);
    if (e != LRP_DNS_ERR_NONE) {
        free(copy);
        return e;
    }
    char **fps = NULL;
    size_t count = 0;
    if (n > 0) fps = (char **)calloc(n, sizeof(char *));
    for (size_t i = 0; i < n; i++) {
        if (strncmp(tokens[i].start, "fp=", 3) == 0) {
            fps[count++] = strdup(tokens[i].start + 3);
        }
    }
    out->fingerprints = fps;
    out->fingerprints_count = count;
    free(copy);
    return LRP_DNS_ERR_NONE;
}

static char *normalize_tcp_endpoint(const char *value) {
    if (value[0] == '\0' || strchr(value, ':') != NULL) {
        return strdup(value);
    }
    size_t len = strlen(value) + 32;
    char *out = (char *)malloc(len);
    snprintf(out, len, "%s:%d", value, LRP_DEFAULT_TCP_PORT);
    return out;
}

lrp_dns_parse_error lrp_parse_linkkeys_apis_txt(const char *txt, lrp_linkkeys_apis *out) {
    memset(out, 0, sizeof(*out));
    char *copy = strdup(txt);
    token tokens[MAX_TXT_TOKENS];
    size_t n = tokenize(copy, tokens, MAX_TXT_TOKENS);
    lrp_dns_parse_error e = require_lk1_version(tokens, n);
    if (e != LRP_DNS_ERR_NONE) {
        free(copy);
        return e;
    }
    for (size_t i = 0; i < n; i++) {
        if (out->tcp.data == NULL && strncmp(tokens[i].start, "tcp=", 4) == 0) {
            const char *v = tokens[i].start + 4;
            if (v[0] != '\0') out->tcp.data = normalize_tcp_endpoint(v);
        }
        if (out->https_base.data == NULL && strncmp(tokens[i].start, "https=", 6) == 0) {
            const char *v = tokens[i].start + 6;
            if (v[0] != '\0') {
                size_t len = strlen(v) + 9;
                char *buf = (char *)malloc(len);
                snprintf(buf, len, "https://%s", v);
                out->https_base.data = buf;
            }
        }
    }
    free(copy);
    if (out->tcp.data == NULL && out->https_base.data == NULL) {
        return LRP_DNS_ERR_MISSING_APIS_ENDPOINT;
    }
    return LRP_DNS_ERR_NONE;
}

int lrp_is_valid_fingerprint(const char *fp) {
    size_t len = strlen(fp);
    if (len != LRP_FINGERPRINT_HEX_LEN) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)fp[i])) return 0;
    }
    return 1;
}

static void lower_copy(char *dst, const char *src, size_t n) {
    for (size_t i = 0; i < n; i++) dst[i] = (char)tolower((unsigned char)src[i]);
    dst[n] = '\0';
}

static int fingerprint_pinned(const char *fp_lower, const char *const *pinned, size_t pinned_count) {
    char buf[LRP_FINGERPRINT_HEX_LEN + 1];
    for (size_t i = 0; i < pinned_count; i++) {
        if (!lrp_is_valid_fingerprint(pinned[i])) continue;
        lower_copy(buf, pinned[i], LRP_FINGERPRINT_HEX_LEN);
        if (strcmp(buf, fp_lower) == 0) return 1;
    }
    return 0;
}

static const char KEY_VOUCH_TAG[] = "linkkeys-key-vouch-v1";

static int key_vouch_payload(const char *enc_fingerprint, const char *enc_expires_at,
                              lrp_bytes *out, lrp_error *err) {
    cbor_buf b;
    cbor_buf_init(&b);
    int rc = 0;
    rc |= cbor_write_array_header(&b, 3);
    rc |= cbor_write_text_cstr(&b, KEY_VOUCH_TAG);
    rc |= cbor_write_text_cstr(&b, enc_fingerprint);
    rc |= cbor_write_text_cstr(&b, enc_expires_at);
    if (rc != 0) {
        cbor_buf_free(&b);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "key vouch payload: out of memory");
    }
    *out = cbor_buf_release(&b);
    return 0;
}

static int verify_key_vouch(const lrp_domain_public_key *enc_key,
                             const lrp_domain_public_key *signing_key) {
    if (enc_key->signed_by_key_id.data == NULL ||
        strcmp(enc_key->signed_by_key_id.data, signing_key->key_id.data) != 0) {
        return 0;
    }
    if (lrp_check_signing_key_valid(signing_key, NULL) != 0) return 0;
    if (enc_key->key_signature.data == NULL) return 0;

    char recomputed_fp[LRP_FINGERPRINT_HEX_LEN + 1];
    lrp_fingerprint_hex(enc_key->public_key.data, enc_key->public_key.len, recomputed_fp);

    lrp_bytes payload = {0};
    if (key_vouch_payload(recomputed_fp, enc_key->expires_at.data, &payload, NULL) != 0) return 0;
    int ok = lrp_resolve_and_verify(signing_key->algorithm.data, payload.data, payload.len,
                                     enc_key->key_signature.data, enc_key->key_signature.len,
                                     signing_key->public_key.data, signing_key->public_key.len,
                                     NULL) == 0;
    lrp_bytes_free(&payload);
    return ok;
}

static int domain_public_key_deep_copy(const lrp_domain_public_key *src, lrp_domain_public_key *dst,
                                        lrp_error *err) {
    memset(dst, 0, sizeof(*dst));
#define DUP_STR(field)                                                    \
    if (src->field.data != NULL) {                                       \
        dst->field.data = strdup(src->field.data);                       \
        if (dst->field.data == NULL) goto oom;                          \
    }
#define DUP_BYTES(field)                                                  \
    if (src->field.data != NULL) {                                       \
        dst->field.data = (uint8_t *)malloc(src->field.len);              \
        if (dst->field.data == NULL) goto oom;                          \
        memcpy(dst->field.data, src->field.data, src->field.len);        \
        dst->field.len = src->field.len;                                 \
    }
    DUP_STR(key_id);
    DUP_BYTES(public_key);
    DUP_STR(fingerprint);
    DUP_STR(algorithm);
    DUP_STR(key_usage);
    DUP_STR(created_at);
    DUP_STR(expires_at);
    DUP_STR(revoked_at);
    DUP_STR(signed_by_key_id);
    DUP_BYTES(key_signature);
#undef DUP_STR
#undef DUP_BYTES
    return 0;
oom:
    lrp_domain_public_key_free_fields(dst);
    return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
}

int lrp_trust_keys(const lrp_domain_public_key *keys, size_t keys_count, const char *const *pinned,
                    size_t pinned_count, lrp_domain_public_key **out_trusted,
                    size_t *out_trusted_count, lrp_error *err) {
    *out_trusted = NULL;
    *out_trusted_count = 0;

    /* Capacity: at most keys_count trusted keys. */
    lrp_domain_public_key *trusted =
        (lrp_domain_public_key *)calloc(keys_count > 0 ? keys_count : 1, sizeof(lrp_domain_public_key));
    if (trusted == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    size_t trusted_n = 0;

    /* Pass 1: pin signing keys directly. */
    for (size_t i = 0; i < keys_count; i++) {
        if (strcmp(keys[i].key_usage.data, "sign") != 0) continue;
        char fp[LRP_FINGERPRINT_HEX_LEN + 1];
        lrp_fingerprint_hex(keys[i].public_key.data, keys[i].public_key.len, fp);
        if (!fingerprint_pinned(fp, pinned, pinned_count)) continue;
        if (domain_public_key_deep_copy(&keys[i], &trusted[trusted_n], err) != 0) {
            lrp_domain_public_keys_array_free(trusted, trusted_n);
            return -1;
        }
        trusted_n++;
    }
    size_t pinned_signing_n = trusted_n; /* first pinned_signing_n entries are the pinned signing keys */

    /* Pass 2: vouch-verify encryption keys against the pinned signing keys. */
    for (size_t i = 0; i < keys_count; i++) {
        if (strcmp(keys[i].key_usage.data, "encrypt") != 0) continue;
        int vouched = 0;
        for (size_t j = 0; j < pinned_signing_n; j++) {
            if (verify_key_vouch(&keys[i], &trusted[j])) {
                vouched = 1;
                break;
            }
        }
        if (!vouched) continue;
        if (domain_public_key_deep_copy(&keys[i], &trusted[trusted_n], err) != 0) {
            lrp_domain_public_keys_array_free(trusted, trusted_n);
            return -1;
        }
        trusted_n++;
    }

    if (trusted_n == 0) {
        free(trusted);
        *out_trusted = NULL;
        *out_trusted_count = 0;
        return 0;
    }
    *out_trusted = trusted;
    *out_trusted_count = trusted_n;
    return 0;
}

/* --------------------------------------------------------------------- */
/* Default DNS resolver (libresolv)                                      */
/* --------------------------------------------------------------------- */

static int default_txt_lookup(lrp_dns_resolver *self, const char *name, lrp_txt_records *out,
                               lrp_error *err) {
    (void)self;
    out->entries = NULL;
    out->count = 0;

    unsigned char response[8192];
    int len = res_query(name, C_IN, T_TXT, response, (int)sizeof(response));
    if (len < 0) {
        return lrp_fail(err, LRP_ERR_DNS, "DNS TXT query failed for %s", name);
    }
    ns_msg handle;
    if (ns_initparse(response, len, &handle) < 0) {
        return lrp_fail(err, LRP_ERR_DNS, "DNS response parse failed for %s", name);
    }
    int count = ns_msg_count(handle, ns_s_an);
    if (count <= 0) return 0;

    char **entries = (char **)calloc((size_t)count, sizeof(char *));
    if (entries == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    size_t n = 0;
    for (int i = 0; i < count; i++) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) != 0) continue;
        if (ns_rr_type(rr) != ns_t_txt) continue;
        const unsigned char *rdata = ns_rr_rdata(rr);
        uint16_t rdlen = ns_rr_rdlen(rr);
        char *buf = (char *)malloc((size_t)rdlen + 1);
        if (buf == NULL) continue;
        size_t bl = 0;
        uint16_t pos = 0;
        while (pos < rdlen) {
            uint8_t clen = rdata[pos];
            pos++;
            if ((uint32_t)pos + clen > rdlen) break;
            memcpy(buf + bl, rdata + pos, clen);
            bl += clen;
            pos = (uint16_t)(pos + clen);
        }
        buf[bl] = '\0';
        entries[n++] = buf;
    }
    out->entries = entries;
    out->count = n;
    return 0;
}

lrp_dns_resolver lrp_default_dns_resolver(void) {
    lrp_dns_resolver r;
    r.ctx = NULL;
    r.txt_lookup = default_txt_lookup;
    return r;
}
