/* Browser endpoint discovery tests — parity with
 * sdks/local-rp/go/browser_test.go. Every lrp_begin_local_login call here
 * injects a fake resolver with canned `_linkkeys_apis` answers (or a hard
 * failure); no test performs a live DNS request. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cbor.h"
#include "encoding.h"
#include "linkkeys_local_rp.h"
#include "test_util.h"

#define BROWSER_TEST_DOMAIN "ident.example.test"

/* --------------------------------------------------------------------- */
/* Fake resolver: canned TXT answers for _linkkeys_apis.<domain>, or a     */
/* lookup failure when `fail` is set.                                     */
/* --------------------------------------------------------------------- */

typedef struct {
    const char *const *txts;
    size_t count;
    int fail;
} fake_apis_ctx;

static int fake_apis_lookup(lrp_dns_resolver *self, const char *name, lrp_txt_records *out,
                            lrp_error *err) {
    fake_apis_ctx *ctx = (fake_apis_ctx *)self->ctx;
    out->entries = NULL;
    out->count = 0;
    if (ctx->fail || strcmp(name, "_linkkeys_apis." BROWSER_TEST_DOMAIN) != 0) {
        if (err != NULL) {
            err->code = LRP_ERR_DNS;
            snprintf(err->message, sizeof(err->message), "fake SERVFAIL for %s", name);
        }
        return -1;
    }
    if (ctx->count == 0) return 0;
    out->entries = (char **)calloc(ctx->count, sizeof(char *));
    for (size_t i = 0; i < ctx->count; i++) out->entries[i] = strdup(ctx->txts[i]);
    out->count = ctx->count;
    return 0;
}

static lrp_dns_resolver fake_resolver(fake_apis_ctx *ctx) {
    lrp_dns_resolver r;
    r.ctx = ctx;
    r.txt_lookup = fake_apis_lookup;
    return r;
}

/* Runs begin against `dns` for BROWSER_TEST_DOMAIN. Returns 0 on success;
 * the caller frees redirect/pending/identity. */
static int begin_with(lrp_dns_resolver *dns, const char *user_domain, lrp_identity *identity,
                      lrp_login_redirect *redirect, lrp_pending_login *pending) {
    lrp_error err = {0};
    lrp_generate_identity_config gen_cfg;
    memset(&gen_cfg, 0, sizeof(gen_cfg));
    gen_cfg.app_name = "browser-test";
    gen_cfg.now_unix = (int64_t)time(NULL);
    if (lrp_generate_local_rp_identity(&gen_cfg, identity, &err) != 0) return -1;

    lrp_begin_login_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity = identity;
    cfg.callback_url = "http://app.lan:8080/cb";
    cfg.user_domain = user_domain;
    cfg.now_unix = (int64_t)time(NULL);
    cfg.dns = dns;
    int rc = lrp_begin_local_login(&cfg, redirect, pending, &err);
    if (rc != 0) lrp_identity_free(identity);
    return rc;
}

static int has_prefix(const char *s, const char *prefix) {
    return s != NULL && strncmp(s, prefix, strlen(prefix)) == 0;
}

/* Case 1: a valid https= host is used for the redirect instead of the
 * identity domain. Case 8: pending.user_domain stays the identity domain —
 * verification stays bound to it, not to the service host. */
static void test_begin_uses_discovered_https_host(void) {
    const char *const txts[] = {"v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test"};
    fake_apis_ctx ctx = {txts, 1, 0};
    lrp_dns_resolver dns = fake_resolver(&ctx);
    lrp_identity id = {0};
    lrp_login_redirect redirect = {0};
    lrp_pending_login pending = {0};
    T_CHECK(begin_with(&dns, BROWSER_TEST_DOMAIN, &id, &redirect, &pending) == 0,
            "browser: begin with discovered host succeeds");
    T_CHECK(has_prefix(redirect.redirect_url.data,
                       "https://linkkeys.ident.example.test/auth/local-rp?signed_request="),
            "browser: redirect uses the discovered https host");
    T_CHECK(!has_prefix(redirect.redirect_url.data, "https://" BROWSER_TEST_DOMAIN "/"),
            "browser: redirect does not use the identity domain");
    T_CHECK(pending.user_domain.data != NULL && strcmp(pending.user_domain.data, BROWSER_TEST_DOMAIN) == 0,
            "browser: pending.user_domain stays the identity domain");
    lrp_login_redirect_free(&redirect);
    lrp_pending_login_free(&pending);
    lrp_identity_free(&id);
}

/* Case 2: an https= value with a path prefix preserves that prefix. */
static void test_begin_preserves_https_path_prefix(void) {
    const char *const txts[] = {"v=lk1 https=login.example.test/linkkeys"};
    fake_apis_ctx ctx = {txts, 1, 0};
    lrp_dns_resolver dns = fake_resolver(&ctx);
    lrp_identity id = {0};
    lrp_login_redirect redirect = {0};
    lrp_pending_login pending = {0};
    T_CHECK(begin_with(&dns, BROWSER_TEST_DOMAIN, &id, &redirect, &pending) == 0,
            "browser: begin with path prefix succeeds");
    T_CHECK(has_prefix(redirect.redirect_url.data,
                       "https://login.example.test/linkkeys/auth/local-rp?signed_request="),
            "browser: https= path prefix is preserved");
    lrp_login_redirect_free(&redirect);
    lrp_pending_login_free(&pending);
    lrp_identity_free(&id);
}

/* Case 3: a record with only tcp= falls back to the identity domain. */
static void test_begin_tcp_only_falls_back(void) {
    const char *const txts[] = {"v=lk1 tcp=linkkeys.ident.example.test"};
    fake_apis_ctx ctx = {txts, 1, 0};
    lrp_dns_resolver dns = fake_resolver(&ctx);
    lrp_identity id = {0};
    lrp_login_redirect redirect = {0};
    lrp_pending_login pending = {0};
    T_CHECK(begin_with(&dns, BROWSER_TEST_DOMAIN, &id, &redirect, &pending) == 0,
            "browser: begin with tcp-only record succeeds");
    T_CHECK(has_prefix(redirect.redirect_url.data,
                       "https://" BROWSER_TEST_DOMAIN "/auth/local-rp?signed_request="),
            "browser: tcp-only record falls back to the identity domain");
    lrp_login_redirect_free(&redirect);
    lrp_pending_login_free(&pending);
    lrp_identity_free(&id);
}

/* Case 4: a DNS lookup error falls back to the identity domain. */
static void test_begin_dns_error_falls_back(void) {
    fake_apis_ctx ctx = {NULL, 0, 1};
    lrp_dns_resolver dns = fake_resolver(&ctx);
    lrp_identity id = {0};
    lrp_login_redirect redirect = {0};
    lrp_pending_login pending = {0};
    T_CHECK(begin_with(&dns, BROWSER_TEST_DOMAIN, &id, &redirect, &pending) == 0,
            "browser: begin with DNS error succeeds");
    T_CHECK(has_prefix(redirect.redirect_url.data,
                       "https://" BROWSER_TEST_DOMAIN "/auth/local-rp?signed_request="),
            "browser: DNS error falls back to the identity domain");
    lrp_login_redirect_free(&redirect);
    lrp_pending_login_free(&pending);
    lrp_identity_free(&id);
}

/* Cases 5 + 6: invalid TXT records are ignored, and across several records
 * the FIRST valid record with https= is selected. */
static void test_begin_selects_first_valid_https_across_records(void) {
    const char *const txts[] = {
        "not a linkkeys record",
        "v=lk2 https=wrong-version.example.test",
        "v=lk1 tcp=tcp-only.example.test",
        "v=lk1 https=first.example.test",
        "v=lk1 https=second.example.test",
    };
    fake_apis_ctx ctx = {txts, 5, 0};
    lrp_dns_resolver dns = fake_resolver(&ctx);
    lrp_identity id = {0};
    lrp_login_redirect redirect = {0};
    lrp_pending_login pending = {0};
    T_CHECK(begin_with(&dns, BROWSER_TEST_DOMAIN, &id, &redirect, &pending) == 0,
            "browser: begin across several records succeeds");
    T_CHECK(has_prefix(redirect.redirect_url.data,
                       "https://first.example.test/auth/local-rp?signed_request="),
            "browser: first valid https= record is selected");
    lrp_login_redirect_free(&redirect);
    lrp_pending_login_free(&pending);
    lrp_identity_free(&id);
}

/* Case 7: signed_request rides the discovered URL unchanged — it decodes to
 * the signed login request whose fields match this login. */
static void test_begin_signed_request_survives_discovered_url(void) {
    const char *const txts[] = {"v=lk1 https=login.example.test/linkkeys"};
    fake_apis_ctx ctx = {txts, 1, 0};
    lrp_dns_resolver dns = fake_resolver(&ctx);
    lrp_identity id = {0};
    lrp_login_redirect redirect = {0};
    lrp_pending_login pending = {0};
    T_CHECK(begin_with(&dns, BROWSER_TEST_DOMAIN, &id, &redirect, &pending) == 0,
            "browser: begin for round-trip succeeds");

    const char *marker = "?signed_request=";
    const char *param = strstr(redirect.redirect_url.data, marker);
    T_CHECK(param != NULL, "browser: signed_request query parameter present");
    if (param == NULL) goto done;
    param += strlen(marker);
    size_t param_len = strcspn(param, "&#");
    char *value = (char *)malloc(param_len + 1);
    memcpy(value, param, param_len);
    value[param_len] = '\0';

    lrp_error err = {0};
    lrp_bytes signed_bytes = {0};
    T_CHECK(lrp_base64url_decode(value, &signed_bytes, &err) == 0,
            "browser: signed_request decodes as base64url");
    free(value);

    cbor_value *signed_root = NULL;
    lrp_bytes request_bytes = {0};
    cbor_value *request_root = NULL;
    lrp_str callback_url = {0};
    lrp_bytes nonce = {0};
    if (cbor_decode(signed_bytes.data, signed_bytes.len, &signed_root, &err) == 0 &&
        cbor_get_bytes(signed_root, "request", &request_bytes, &err) == 0 &&
        cbor_decode(request_bytes.data, request_bytes.len, &request_root, &err) == 0 &&
        cbor_get_text(request_root, "callback_url", &callback_url, &err) == 0 &&
        cbor_get_bytes(request_root, "nonce", &nonce, &err) == 0) {
        T_CHECK(strcmp(callback_url.data, "http://app.lan:8080/cb") == 0,
                "browser: decoded callback_url matches the begin config");
        T_CHECK(nonce.len == pending.nonce.len && memcmp(nonce.data, pending.nonce.data, nonce.len) == 0,
                "browser: decoded nonce matches the pending nonce");
    } else {
        T_CHECK(0, "browser: signed_request decodes to a login request");
    }
    lrp_str_free(&callback_url);
    lrp_bytes_free(&nonce);
    cbor_value_free(request_root);
    free(request_root);
    lrp_bytes_free(&request_bytes);
    cbor_value_free(signed_root);
    free(signed_root);
    lrp_bytes_free(&signed_bytes);
done:
    lrp_login_redirect_free(&redirect);
    lrp_pending_login_free(&pending);
    lrp_identity_free(&id);
}

/* A full login keeps the username hint on the discovered URL. */
static void test_begin_username_hint_on_discovered_url(void) {
    const char *const txts[] = {"v=lk1 https=login.example.test/linkkeys"};
    fake_apis_ctx ctx = {txts, 1, 0};
    lrp_dns_resolver dns = fake_resolver(&ctx);
    lrp_identity id = {0};
    lrp_login_redirect redirect = {0};
    lrp_pending_login pending = {0};
    T_CHECK(begin_with(&dns, "Alice+work@" BROWSER_TEST_DOMAIN, &id, &redirect, &pending) == 0,
            "browser: full login with discovered host succeeds");
    T_CHECK(has_prefix(redirect.redirect_url.data,
                       "https://login.example.test/linkkeys/auth/local-rp?signed_request="),
            "browser: full login uses the discovered base");
    const char *tail = strstr(redirect.redirect_url.data, "&username=Alice%2Bwork");
    T_CHECK(tail != NULL && tail[strlen("&username=Alice%2Bwork")] == '\0',
            "browser: username hint is appended, encoded, at the end");
    lrp_login_redirect_free(&redirect);
    lrp_pending_login_free(&pending);
    lrp_identity_free(&id);
}

/* Case 9: a zero-initialized config (dns == NULL) is the pre-discovery
 * caller shape and still compiles; NULL selects the library default. The
 * default path is not executed here — that would be a live DNS request. */
static void test_begin_config_without_resolver_still_compiles(void) {
    lrp_begin_login_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.callback_url = "http://app.lan:8080/cb";
    cfg.user_domain = BROWSER_TEST_DOMAIN;
    T_CHECK(cfg.dns == NULL, "browser: zeroed config has no injected resolver");
    lrp_dns_resolver def = lrp_default_dns_resolver();
    T_CHECK(def.txt_lookup != NULL, "browser: default resolver is available");
}

/* --------------------------------------------------------------------- */
/* Direct tests for the exported helpers                                  */
/* --------------------------------------------------------------------- */

static void test_resolve_browser_base(void) {
    lrp_error err = {0};
    lrp_str base = {0};
    const char *const ok_txts[] = {"v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys"};
    fake_apis_ctx ok_ctx = {ok_txts, 1, 0};
    lrp_dns_resolver ok_dns = fake_resolver(&ok_ctx);
    T_CHECK(lrp_resolve_browser_base(&ok_dns, BROWSER_TEST_DOMAIN, &base, &err) == 0,
            "browser: resolve_browser_base succeeds on a valid record");
    T_CHECK(base.data != NULL && strcmp(base.data, "https://login.example.test:8443/linkkeys") == 0,
            "browser: resolve_browser_base returns the https= base with port and prefix");
    lrp_str_free(&base);

    /* A record whose https= value smuggles URL structure is skipped; with
     * no other candidate, resolution errors so the caller can fall back. */
    const char *hostile[] = {
        "v=lk1 https=user@evil.example.test",
        "v=lk1 https=evil.example.test/x?y=1",
        "v=lk1 https=evil.example.test/x#frag",
        "v=lk1 https=evil.example.test:notaport",
    };
    for (size_t i = 0; i < sizeof(hostile) / sizeof(hostile[0]); i++) {
        const char *const one[] = {hostile[i]};
        fake_apis_ctx ctx = {one, 1, 0};
        lrp_dns_resolver dns = fake_resolver(&ctx);
        memset(&err, 0, sizeof(err));
        T_CHECK(lrp_resolve_browser_base(&dns, BROWSER_TEST_DOMAIN, &base, &err) != 0 &&
                    err.code == LRP_ERR_DNS,
                "browser: resolve_browser_base rejects a hostile https= record");
        lrp_str_free(&base);
    }

    const char *const tcp_only[] = {"v=lk1 tcp=only.example.test"};
    fake_apis_ctx tcp_ctx = {tcp_only, 1, 0};
    lrp_dns_resolver tcp_dns = fake_resolver(&tcp_ctx);
    memset(&err, 0, sizeof(err));
    T_CHECK(lrp_resolve_browser_base(&tcp_dns, BROWSER_TEST_DOMAIN, &base, &err) != 0 &&
                err.code == LRP_ERR_DNS,
            "browser: resolve_browser_base errors when no record has https=");
    lrp_str_free(&base);

    fake_apis_ctx fail_ctx = {NULL, 0, 1};
    lrp_dns_resolver fail_dns = fake_resolver(&fail_ctx);
    memset(&err, 0, sizeof(err));
    T_CHECK(lrp_resolve_browser_base(&fail_dns, BROWSER_TEST_DOMAIN, &base, &err) != 0,
            "browser: resolve_browser_base surfaces a lookup failure");
    lrp_str_free(&base);
}

static void test_build_browser_endpoint(void) {
    lrp_error err = {0};
    lrp_str url = {0};
    T_CHECK(lrp_build_browser_endpoint("https://h.example.test", LRP_BROWSER_ROUTE_LOCAL_RP,
                                       "PAYLOAD-123_abc", &url, &err) == 0,
            "browser: build_browser_endpoint succeeds on a plain base");
    T_CHECK(url.data != NULL &&
                strcmp(url.data, "https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc") == 0,
            "browser: build_browser_endpoint joins base, route and query");
    lrp_str_free(&url);

    /* Path prefix, with and without a trailing slash, and the regular-RP
     * route — the same helper serves /auth/authorize glue. */
    const char *prefixed[] = {"https://h.example.test/pfx", "https://h.example.test/pfx/"};
    for (size_t i = 0; i < 2; i++) {
        T_CHECK(lrp_build_browser_endpoint(prefixed[i], LRP_BROWSER_ROUTE_AUTHORIZE, "s", &url, &err) == 0,
                "browser: build_browser_endpoint accepts a path prefix");
        T_CHECK(url.data != NULL &&
                    strcmp(url.data, "https://h.example.test/pfx/auth/authorize?signed_request=s") == 0,
                "browser: path prefix is preserved without a double slash");
        lrp_str_free(&url);
    }

    T_CHECK(lrp_build_browser_endpoint("https://h.example.test:8443/x", LRP_BROWSER_ROUTE_LOCAL_RP, "s",
                                       &url, &err) == 0,
            "browser: build_browser_endpoint accepts a port");
    T_CHECK(url.data != NULL &&
                strcmp(url.data, "https://h.example.test:8443/x/auth/local-rp?signed_request=s") == 0,
            "browser: port and prefix are preserved");
    lrp_str_free(&url);

    /* A value that is not base64url is escaped rather than corrupting the
     * query. */
    T_CHECK(lrp_build_browser_endpoint("https://h.example.test", LRP_BROWSER_ROUTE_LOCAL_RP, "a&b#c", &url,
                                       &err) == 0,
            "browser: build_browser_endpoint accepts a non-base64url value");
    T_CHECK(url.data != NULL &&
                strcmp(url.data, "https://h.example.test/auth/local-rp?signed_request=a%26b%23c") == 0,
            "browser: query value is percent-encoded");
    lrp_str_free(&url);

    /* A non-HTTPS scheme must never be selectable. */
    const char *bad[] = {
        "http://h.example.test",   "ftp://h.example.test",          "https://",
        "https://u:p@h.example.test", "https://h.example.test/x?y=1", "https://h.example.test/x#f",
        "https://h.example.test:notaport", "https://h.example .test",  "h.example.test",
        "https://:443",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        memset(&err, 0, sizeof(err));
        T_CHECK(lrp_build_browser_endpoint(bad[i], LRP_BROWSER_ROUTE_LOCAL_RP, "s", &url, &err) != 0 &&
                    err.code == LRP_ERR_INVALID_INPUT,
                "browser: build_browser_endpoint rejects an invalid base");
        lrp_str_free(&url);
    }
    memset(&err, 0, sizeof(err));
    T_CHECK(lrp_build_browser_endpoint("https://h.example.test", "auth/no-leading-slash", "s", &url, &err) != 0,
            "browser: build_browser_endpoint rejects a route without a leading slash");
    lrp_str_free(&url);
}

int run_browser_tests(void) {
    test_begin_uses_discovered_https_host();
    test_begin_preserves_https_path_prefix();
    test_begin_tcp_only_falls_back();
    test_begin_dns_error_falls_back();
    test_begin_selects_first_valid_https_across_records();
    test_begin_signed_request_survives_discovered_url();
    test_begin_username_hint_on_discovered_url();
    test_begin_config_without_resolver_still_compiles();
    test_resolve_browser_base();
    test_build_browser_endpoint();
    return 0;
}
