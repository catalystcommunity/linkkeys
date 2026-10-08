/* Browser endpoint discovery: resolve an identity domain's browser-facing
 * HTTPS base from its `_linkkeys_apis` TXT record, and build browser route
 * URLs against it. Mirrors `sdks/local-rp/go/browser.go`.
 *
 * The identity domain (the domain the user selected, e.g. `todandlorna.com`)
 * is a trust and discovery domain. It is not necessarily the host that
 * serves the browser login routes — the `https=` endpoint of
 * `_linkkeys_apis.<identity-domain>` is (docs/spec/trust-and-anchors.md:
 * "`https=` is the browser-facing endpoint"). These helpers are shared by
 * lrp_begin_local_login (route LRP_BROWSER_ROUTE_LOCAL_RP) and by
 * regular-RP application glue (route LRP_BROWSER_ROUTE_AUTHORIZE), so
 * discovery is implemented once.
 *
 * C has no URL library, so the base is validated by a small, strict
 * grammar (`https://host[:port][/path]`, nothing else) and the pieces are
 * joined explicitly. The query value is percent-encoded with the unreserved
 * set so it can never corrupt the query. All of it is covered by
 * tests/test_browser.c. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browser.h"
#include "dns.h"
#include "error.h"

/* The validated pieces of a browser base: `authority` is host[:port] (no
 * userinfo), `path` is the optional prefix starting at its leading '/'. */
typedef struct {
    const char *authority;
    size_t authority_len;
    const char *path;
    size_t path_len;
} browser_base_parts;

static int is_host_char(unsigned char c) {
    return isalnum(c) || c == '-' || c == '.';
}

/* pchar / "/" per RFC 3986 (unreserved, pct-encoded marker, sub-delims,
 * ':' and '@'), which is what a path prefix may legitimately contain. '?'
 * and '#' are deliberately absent: they would start a query/fragment. */
static int is_path_char(unsigned char c) {
    if (isalnum(c)) return 1;
    return c != '\0' && strchr("-._~%!$&'()*+,;=:@/", c) != NULL;
}

/* Checks that base is a usable https browser base URL: https scheme, a
 * host (with an optional port), an optional path prefix, and nothing else.
 * A TXT record value must never smuggle in userinfo, a query, a fragment,
 * or (via lrp_parse_linkkeys_apis_txt's unconditional `https://` prefix
 * plus this check) a non-HTTPS scheme. */
static int validate_browser_base(const char *base, browser_base_parts *out, lrp_error *err) {
    if (base == NULL || strncmp(base, "https://", 8) != 0) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base must use https");
    }
    const char *authority = base + 8;
    size_t authority_len = strcspn(authority, "/?#");
    if (authority_len == 0) return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base has no host");
    if (memchr(authority, '@', authority_len) != NULL) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base must be host[:port][/path] only");
    }
    const char *colon = memchr(authority, ':', authority_len);
    size_t host_len = colon != NULL ? (size_t)(colon - authority) : authority_len;
    if (host_len == 0) return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base has no host");
    for (size_t i = 0; i < host_len; i++) {
        if (!is_host_char((unsigned char)authority[i])) {
            return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base host has an invalid character");
        }
    }
    if (colon != NULL) {
        const char *port = colon + 1;
        size_t port_len = authority_len - host_len - 1;
        if (port_len == 0 || port_len > 5) {
            return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base port is invalid");
        }
        long value = 0;
        for (size_t i = 0; i < port_len; i++) {
            if (!isdigit((unsigned char)port[i])) {
                return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base port is invalid");
            }
            value = value * 10 + (port[i] - '0');
        }
        if (value < 1 || value > 65535) {
            return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base port is invalid");
        }
    }
    const char *path = authority + authority_len;
    if (*path == '?' || *path == '#') {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base must be host[:port][/path] only");
    }
    size_t path_len = strlen(path);
    for (size_t i = 0; i < path_len; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c == '?' || c == '#') {
            return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base must be host[:port][/path] only");
        }
        if (!is_path_char(c)) {
            return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser base path has an invalid character");
        }
    }
    out->authority = authority;
    out->authority_len = authority_len;
    out->path = path;
    out->path_len = path_len;
    return 0;
}

int lrp_percent_encode_query_value(const char *value, lrp_str *out, lrp_error *err) {
    static const char hex[] = "0123456789ABCDEF";
    memset(out, 0, sizeof(*out));
    if (value == NULL) return lrp_fail(err, LRP_ERR_INVALID_INPUT, "query value is required");
    size_t len = strlen(value);
    /* Worst case every byte becomes %XX. */
    char *buf = (char *)malloc(len * 3 + 1);
    if (buf == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    size_t offset = 0;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        unsigned char c = *p;
        if (isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
            buf[offset++] = (char)c;
        } else {
            buf[offset++] = '%';
            buf[offset++] = hex[c >> 4];
            buf[offset++] = hex[c & 15];
        }
    }
    buf[offset] = '\0';
    out->data = buf;
    return 0;
}

int lrp_resolve_browser_base(lrp_dns_resolver *dns, const char *identity_domain, lrp_str *out,
                             lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (dns == NULL || dns->txt_lookup == NULL) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "dns resolver is required");
    }
    if (identity_domain == NULL || identity_domain[0] == '\0') {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "identity domain is required");
    }
    lrp_str name = {0};
    if (lrp_linkkeys_apis_dns_name(identity_domain, &name, err) != 0) return -1;
    lrp_txt_records txts = {0};
    if (dns->txt_lookup(dns, name.data, &txts, err) != 0) {
        lrp_str_free(&name);
        return -1;
    }
    char *found = NULL;
    for (size_t i = 0; i < txts.count && found == NULL; i++) {
        lrp_linkkeys_apis apis;
        if (lrp_parse_linkkeys_apis_txt(txts.entries[i], &apis) == LRP_DNS_ERR_NONE &&
            apis.https_base.data != NULL) {
            browser_base_parts parts;
            lrp_error skipped = {0};
            if (validate_browser_base(apis.https_base.data, &parts, &skipped) == 0) {
                found = apis.https_base.data;
                apis.https_base.data = NULL;
            }
        }
        lrp_linkkeys_apis_free(&apis);
    }
    lrp_txt_records_free(&txts);
    if (found == NULL) {
        int rc = lrp_fail(err, LRP_ERR_DNS, "no usable %s TXT record with an https= endpoint",
                          name.data);
        lrp_str_free(&name);
        return rc;
    }
    lrp_str_free(&name);
    out->data = found;
    return 0;
}

int lrp_build_browser_endpoint(const char *browser_base, const char *route,
                               const char *signed_request, lrp_str *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    browser_base_parts parts;
    if (validate_browser_base(browser_base, &parts, err) != 0) return -1;
    if (route == NULL || route[0] != '/') {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "route must start with /");
    }
    lrp_str encoded = {0};
    if (lrp_percent_encode_query_value(signed_request, &encoded, err) != 0) return -1;

    /* Preserve the prefix, but never emit "//" between prefix and route. */
    size_t prefix_len = parts.path_len;
    while (prefix_len > 0 && parts.path[prefix_len - 1] == '/') prefix_len--;

    size_t total = strlen("https://") + parts.authority_len + prefix_len + strlen(route) +
                   strlen("?signed_request=") + strlen(encoded.data) + 1;
    char *buf = (char *)malloc(total);
    if (buf == NULL) {
        lrp_str_free(&encoded);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    }
    int n = snprintf(buf, total, "https://%.*s%.*s%s?signed_request=%s", (int)parts.authority_len,
                     parts.authority, (int)prefix_len, parts.path, route, encoded.data);
    lrp_str_free(&encoded);
    if (n < 0 || (size_t)n >= total) {
        free(buf);
        return lrp_fail(err, LRP_ERR_INVALID_INPUT, "browser endpoint could not be formatted");
    }
    out->data = buf;
    return 0;
}

int lrp_resolve_browser_endpoint(lrp_dns_resolver *dns, const char *identity_domain,
                                 const char *route, const char *signed_request, lrp_str *out,
                                 lrp_error *err) {
    memset(out, 0, sizeof(*out));
    lrp_str base = {0};
    /* Discovery failures are not surfaced: the fallback preserves the
     * pre-discovery behavior, so a domain that serves its browser routes at
     * the apex keeps working without a `_linkkeys_apis` record. A scratch
     * error is passed (not NULL) because a caller-supplied resolver may not
     * be NULL-safe. */
    lrp_error discovery_err = {0};
    if (lrp_resolve_browser_base(dns, identity_domain, &base, &discovery_err) != 0) {
        size_t len = strlen("https://") + strlen(identity_domain) + 1;
        base.data = (char *)malloc(len);
        if (base.data == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
        snprintf(base.data, len, "https://%s", identity_domain);
    }
    int rc = lrp_build_browser_endpoint(base.data, route, signed_request, out, err);
    lrp_str_free(&base);
    return rc;
}
