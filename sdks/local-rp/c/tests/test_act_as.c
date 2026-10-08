/* Act-as grantee tests: exact bytes from
 * sdks/regular-rp/conformance/act_as_grantee_signing.json (local_rp_grantee
 * case), begin act-as URL discovery with a fake resolver, and callback
 * nonce checks. The refresh tests use the fake IDP in test_flow.c. No test
 * here touches the network. Run from sdks/local-rp/c/. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "act_as.h"
#include "cbor.h"
#include "crypto.h"
#include "encoding.h"
#include "local_rp.h"
#include "test_util.h"
#include "time_util.h"

#define ACT_AS_VECTORS "../../regular-rp/conformance/act_as_grantee_signing.json"
#define ACT_AS_TEST_DOMAIN "ident.example.test"

static int bytes_eq(const lrp_bytes *a, const uint8_t *b, size_t len) {
    return a->len == len && (len == 0 || memcmp(a->data, b, len) == 0);
}

json_value *t_act_as_load_vectors(void) {
    json_value *v = json_parse_file(ACT_AS_VECTORS);
    if (v == NULL) {
        fprintf(stderr, "could not load act-as vectors: %s\n", ACT_AS_VECTORS);
        exit(2);
    }
    return v;
}

void t_act_as_vector_identity(const json_value *vec, lrp_identity *out) {
    memset(out, 0, sizeof(*out));
    const json_value *local = json_get(vec, "local_rp_grantee");
    t_hex_field_fixed(local, "signing_private_key_hex", out->signing_private_key, 32);
    lrp_bytes signed_desc = t_hex_field(local, "signed_descriptor_cbor_hex");
    cbor_value *root = NULL;
    lrp_error err = {0};
    if (cbor_decode(signed_desc.data, signed_desc.len, &root, &err) != 0 ||
        cbor_get_bytes(root, "descriptor", &out->descriptor_cbor, &err) != 0 ||
        cbor_get_bytes(root, "signature", &out->descriptor_signature, &err) != 0) {
        fprintf(stderr, "fixture error: signed descriptor: %s\n", err.message);
        exit(2);
    }
    cbor_value_free(root);
    free(root);
    lrp_bytes_free(&signed_desc);
    const char *fp = json_str(json_get(local, "fingerprint"));
    snprintf(out->fingerprint, sizeof(out->fingerprint), "%s", fp);
}

static const json_value *local_case(const json_value *vec) {
    const json_value *cases = json_get(vec, "cases");
    for (size_t i = 0; i < json_len(cases); i++) {
        const char *name = json_str(json_get(json_at(cases, i), "name"));
        if (name != NULL && strcmp(name, "local_rp_grantee") == 0) return json_at(cases, i);
    }
    fprintf(stderr, "fixture error: no local_rp_grantee case\n");
    exit(2);
}

/* --------------------------------------------------------------------- */
/* Vector bytes                                                          */
/* --------------------------------------------------------------------- */

static void test_act_as_vector_bytes(void) {
    json_value *vec = t_act_as_load_vectors();
    lrp_identity id;
    t_act_as_vector_identity(vec, &id);
    const json_value *c = local_case(vec);
    lrp_error err = {0};

    /* Grant request. */
    const json_value *g = json_get(c, "grant_request");
    const json_value *in = json_get(g, "inputs");
    lrp_bytes scope_set = t_hex_field(in, "scope_set_signed_cbor_hex");
    const json_value *life = json_get(in, "requested_lifetime_seconds");
    const json_value *ren = json_get(in, "requested_renewal_window_seconds");
    lrp_bytes signed_req = {0};
    int rc = lrp_act_as_sign_grant_request(
        &id, scope_set.data, scope_set.len, !json_is_null_or_absent(life),
        json_is_null_or_absent(life) ? 0 : (int64_t)life->num_val, !json_is_null_or_absent(ren),
        json_is_null_or_absent(ren) ? 0 : (int64_t)ren->num_val,
        json_str(json_get(in, "callback_url")), json_str(json_get(in, "nonce")),
        json_str(json_get(in, "requested_at")), json_str(json_get(in, "expires_at")), &signed_req,
        &err);
    T_CHECK(rc == 0, "act-as vector: grant request signs");
    lrp_bytes want = t_hex_field(g, "signed_cbor_hex");
    T_CHECK(bytes_eq(&signed_req, want.data, want.len), "act-as vector: signed grant request bytes");
    lrp_bytes_free(&want);
    {
        cbor_value *root = NULL;
        lrp_bytes request = {0};
        want = t_hex_field(g, "request_cbor_hex");
        T_CHECK(cbor_decode(signed_req.data, signed_req.len, &root, &err) == 0 &&
                    cbor_get_bytes(root, "request", &request, &err) == 0 &&
                    bytes_eq(&request, want.data, want.len),
                "act-as vector: grant request payload bytes");
        lrp_bytes_free(&want);
        lrp_bytes_free(&request);
        cbor_value_free(root);
        free(root);
    }
    lrp_str url_param = {0};
    T_CHECK(lrp_base64url_encode(signed_req.data, signed_req.len, &url_param, &err) == 0 &&
                strcmp(url_param.data, json_str(json_get(g, "url_param"))) == 0,
            "act-as vector: grant request url_param");
    lrp_str_free(&url_param);
    lrp_bytes_free(&signed_req);
    lrp_bytes_free(&scope_set);

    /* Refresh request. */
    const json_value *r = json_get(c, "refresh_request");
    in = json_get(r, "inputs");
    lrp_bytes signed_refresh = {0};
    rc = lrp_act_as_sign_refresh_request(&id, json_str(json_get(in, "grant_id")),
                                         json_str(json_get(in, "requested_at")),
                                         json_str(json_get(in, "expires_at")),
                                         json_str(json_get(in, "nonce")), &signed_refresh, &err);
    want = t_hex_field(r, "signed_cbor_hex");
    T_CHECK(rc == 0 && bytes_eq(&signed_refresh, want.data, want.len),
            "act-as vector: signed refresh request bytes");
    lrp_bytes_free(&want);
    lrp_bytes_free(&signed_refresh);

    /* Presentation / credential. */
    const json_value *p = json_get(c, "presentation");
    in = json_get(p, "inputs");
    const json_value *aud = json_get(in, "audience");
    lrp_bytes grant = t_hex_field(in, "grant_signed_cbor_hex");
    lrp_bytes digest = t_hex_field(in, "request_digest_hex");
    lrp_bytes nonce = t_hex_field(in, "nonce_hex");
    int64_t presented_at = 0;
    lrp_parse_rfc3339(json_str(json_get(in, "presented_at")), &presented_at, &err);
    lrp_act_as_present_config pc;
    memset(&pc, 0, sizeof(pc));
    pc.identity = &id;
    pc.signed_grant_cbor = grant.data;
    pc.signed_grant_cbor_len = grant.len;
    pc.audience.subject_user_id = json_str(json_get(aud, "subject_user_id"));
    pc.audience.subject_domain = json_str(json_get(aud, "subject_domain"));
    pc.audience.application_id = json_str(json_get(aud, "application_id"));
    pc.request_digest = digest.data;
    pc.request_digest_len = digest.len;
    pc.nonce = nonce.data;
    pc.nonce_len = nonce.len;
    pc.now_unix = presented_at;
    lrp_act_as_credential cred = {0};
    rc = lrp_act_as_present(&pc, &cred, &err);
    T_CHECK(rc == 0, "act-as vector: present succeeds");
    want = t_hex_field(p, "grant_hash_hex");
    T_CHECK(want.len == 32 && memcmp(cred.grant_hash, want.data, 32) == 0,
            "act-as vector: grant hash");
    lrp_bytes_free(&want);
    want = t_hex_field(p, "presentation_cbor_hex");
    T_CHECK(bytes_eq(&cred.presentation_cbor, want.data, want.len),
            "act-as vector: presentation bytes");
    lrp_bytes_free(&want);
    want = t_hex_field(p, "credential_cbor_hex");
    T_CHECK(bytes_eq(&cred.credential_cbor, want.data, want.len),
            "act-as vector: credential bytes");
    lrp_bytes_free(&want);
    lrp_act_as_credential_free(&cred);

    /* Present refuses a missing nonce and a grant that does not decode. */
    pc.nonce_len = 0;
    T_CHECK(lrp_act_as_present(&pc, &cred, &err) != 0 && err.code == LRP_ERR_INVALID_INPUT,
            "act-as present: empty nonce is refused");
    pc.nonce_len = nonce.len;
    uint8_t junk[] = {0xa1, 0x61, 0x78, 0x01};
    pc.signed_grant_cbor = junk;
    pc.signed_grant_cbor_len = sizeof(junk);
    T_CHECK(lrp_act_as_present(&pc, &cred, &err) != 0 && err.code == LRP_ERR_DECODE &&
                cred.credential_cbor.data == NULL,
            "act-as present: grant without fields is refused");

    lrp_bytes_free(&grant);
    lrp_bytes_free(&digest);
    lrp_bytes_free(&nonce);
    lrp_identity_free(&id);
    json_free(vec);
}

/* --------------------------------------------------------------------- */
/* begin act-as                                                          */
/* --------------------------------------------------------------------- */

typedef struct {
    const char *txt; /* NULL => lookup fails */
} act_as_dns_ctx;

static int act_as_dns_lookup(lrp_dns_resolver *self, const char *name, lrp_txt_records *out,
                             lrp_error *err) {
    act_as_dns_ctx *ctx = (act_as_dns_ctx *)self->ctx;
    out->entries = NULL;
    out->count = 0;
    if (ctx->txt == NULL || strcmp(name, "_linkkeys_apis." ACT_AS_TEST_DOMAIN) != 0) {
        if (err != NULL) {
            err->code = LRP_ERR_DNS;
            snprintf(err->message, sizeof(err->message), "fake SERVFAIL");
        }
        return -1;
    }
    out->entries = (char **)calloc(1, sizeof(char *));
    out->entries[0] = strdup(ctx->txt);
    out->count = 1;
    return 0;
}

static int has_prefix(const char *s, const char *prefix) {
    return s != NULL && strncmp(s, prefix, strlen(prefix)) == 0;
}

static void begin_config(lrp_begin_act_as_config *cfg, const lrp_identity *id,
                         const lrp_bytes *scope_set, lrp_dns_resolver *dns) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->identity = id;
    cfg->user_domain = "Alice@Ident.Example.Test";
    cfg->scope_set_cbor = scope_set->data;
    cfg->scope_set_cbor_len = scope_set->len;
    cfg->has_requested_lifetime = 1;
    cfg->requested_lifetime_seconds = 1800;
    cfg->callback_url = "http://app.lan:8080/act-as/callback";
    cfg->now_unix = 1790000000;
    cfg->dns = dns;
}

static void test_begin_act_as(void) {
    json_value *vec = t_act_as_load_vectors();
    lrp_identity id;
    t_act_as_vector_identity(vec, &id);
    lrp_bytes scope_set =
        t_hex_field(json_get(json_get(local_case(vec), "grant_request"), "inputs"),
                    "scope_set_signed_cbor_hex");
    lrp_error err = {0};

    /* Discovered https= host. */
    act_as_dns_ctx ctx = {"v=lk1 tcp=t.example.test https=login.example.test/linkkeys"};
    lrp_dns_resolver dns = {&ctx, act_as_dns_lookup};
    lrp_begin_act_as_config cfg;
    begin_config(&cfg, &id, &scope_set, &dns);
    lrp_act_as_redirect redirect = {0};
    lrp_pending_act_as pending = {0};
    int rc = lrp_begin_act_as(&cfg, &redirect, &pending, &err);
    T_CHECK(rc == 0, "begin act-as: succeeds");
    const char *prefix = "https://login.example.test/linkkeys/auth/act-as?signed_request=";
    T_CHECK(has_prefix(redirect.redirect_url.data, prefix), "begin act-as: discovered host");
    T_CHECK(pending.user_domain.data != NULL &&
                strcmp(pending.user_domain.data, ACT_AS_TEST_DOMAIN) == 0,
            "begin act-as: pending keeps the identity domain");
    T_CHECK(pending.callback_url.data != NULL &&
                strcmp(pending.callback_url.data, cfg.callback_url) == 0,
            "begin act-as: pending keeps the callback URL");
    T_CHECK(pending.nonce.data != NULL && strlen(pending.nonce.data) == 43,
            "begin act-as: nonce is 32 random bytes as base64url");

    /* The signed_request decodes, carries the pending nonce and the request
     * window, and verifies with the descriptor signing key. */
    if (rc == 0) {
        lrp_bytes signed_req = {0};
        cbor_value *root = NULL, *req = NULL, *desc = NULL;
        lrp_bytes request = {0}, desc_bytes = {0}, sig = {0}, pub = {0}, input = {0};
        lrp_str nonce = {0}, requested_at = {0}, expires_at = {0};
        int ok = lrp_base64url_decode(redirect.redirect_url.data + strlen(prefix), &signed_req,
                                      &err) == 0 &&
                 cbor_decode(signed_req.data, signed_req.len, &root, &err) == 0 &&
                 cbor_get_bytes(root, "request", &request, &err) == 0 &&
                 cbor_decode(request.data, request.len, &req, &err) == 0 &&
                 cbor_get_text(req, "nonce", &nonce, &err) == 0 &&
                 cbor_get_text(req, "requested_at", &requested_at, &err) == 0 &&
                 cbor_get_text(req, "expires_at", &expires_at, &err) == 0;
        T_CHECK(ok && strcmp(nonce.data, pending.nonce.data) == 0,
                "begin act-as: request nonce equals pending nonce");
        int64_t ra = 0, ea = 0;
        T_CHECK(ok && lrp_parse_rfc3339(requested_at.data, &ra, &err) == 0 &&
                    lrp_parse_rfc3339(expires_at.data, &ea, &err) == 0 && ra == cfg.now_unix &&
                    ea == cfg.now_unix + 300 && requested_at.data[strlen(requested_at.data) - 1] == 'Z',
                "begin act-as: default 300 s window, Z timestamps");
        const cbor_value *proof = cbor_map_get(root, "proof");
        const cbor_value *pdesc = cbor_map_get(proof, "local_rp_descriptor");
        const cbor_value *psig = cbor_map_get(proof, "signature");
        ok = ok && cbor_get_bytes(pdesc, "descriptor", &desc_bytes, &err) == 0 &&
             cbor_decode(desc_bytes.data, desc_bytes.len, &desc, &err) == 0 &&
             cbor_get_bytes(desc, "signing_public_key", &pub, &err) == 0 && pub.len == 32 &&
             cbor_get_bytes(psig, "signature", &sig, &err) == 0 &&
             lrp_envelope_signature_input(LRP_ACT_AS_TAG_GRANT_REQUEST, request.data, request.len,
                                          &input, &err) == 0 &&
             lrp_ed25519_verify(pub.data, input.data, input.len, sig.data, sig.len, &err) == 0;
        T_CHECK(ok, "begin act-as: request verifies with the descriptor key");
        lrp_bytes_free(&signed_req);
        lrp_bytes_free(&request);
        lrp_bytes_free(&desc_bytes);
        lrp_bytes_free(&sig);
        lrp_bytes_free(&pub);
        lrp_bytes_free(&input);
        lrp_str_free(&nonce);
        lrp_str_free(&requested_at);
        lrp_str_free(&expires_at);
        if (root != NULL) {
            cbor_value_free(root);
            free(root);
        }
        if (req != NULL) {
            cbor_value_free(req);
            free(req);
        }
        if (desc != NULL) {
            cbor_value_free(desc);
            free(desc);
        }
    }
    lrp_act_as_redirect_free(&redirect);
    lrp_pending_act_as_free(&pending);

    /* DNS failure falls back to the identity domain. */
    act_as_dns_ctx failing = {NULL};
    dns.ctx = &failing;
    rc = lrp_begin_act_as(&cfg, &redirect, &pending, &err);
    T_CHECK(rc == 0 && has_prefix(redirect.redirect_url.data,
                                  "https://" ACT_AS_TEST_DOMAIN "/auth/act-as?signed_request="),
            "begin act-as: DNS failure falls back to the identity domain");
    lrp_act_as_redirect_free(&redirect);
    lrp_pending_act_as_free(&pending);

    /* Refusals. */
    cfg.request_window_seconds = 901;
    T_CHECK(lrp_begin_act_as(&cfg, &redirect, &pending, &err) != 0 &&
                err.code == LRP_ERR_INVALID_INPUT && redirect.redirect_url.data == NULL,
            "begin act-as: window over 900 s is refused");
    cfg.request_window_seconds = 0;
    cfg.callback_url = "myapp://cb";
    T_CHECK(lrp_begin_act_as(&cfg, &redirect, &pending, &err) != 0 &&
                err.code == LRP_ERR_INVALID_INPUT,
            "begin act-as: non-http callback is refused");
    cfg.callback_url = "http://app.lan:8080/act-as/callback";
    cfg.requested_lifetime_seconds = 0;
    T_CHECK(lrp_begin_act_as(&cfg, &redirect, &pending, &err) != 0 &&
                err.code == LRP_ERR_INVALID_INPUT,
            "begin act-as: non-positive lifetime is refused");
    cfg.requested_lifetime_seconds = 1800;
    uint8_t junk[] = {0x01};
    cfg.scope_set_cbor = junk;
    cfg.scope_set_cbor_len = sizeof(junk);
    T_CHECK(lrp_begin_act_as(&cfg, &redirect, &pending, &err) != 0 && err.code == LRP_ERR_DECODE,
            "begin act-as: scope set that is not SignedActAsScopeSet is refused");

    lrp_bytes_free(&scope_set);
    lrp_identity_free(&id);
    json_free(vec);
}

/* --------------------------------------------------------------------- */
/* Callback                                                              */
/* --------------------------------------------------------------------- */

static void test_act_as_callback(void) {
    lrp_pending_act_as pending = {0};
    pending.nonce.data = strdup("abc_DEF-123");
    lrp_error err = {0};
    lrp_str grant_id = {0};

    int rc = lrp_complete_act_as_callback(
        &pending, "http://app.lan/cb?x=1&act_as_grant_id=grant%2D1&nonce=abc_DEF-123", &grant_id,
        &err);
    T_CHECK(rc == 0 && grant_id.data != NULL && strcmp(grant_id.data, "grant-1") == 0,
            "act-as callback: full URL, matching nonce returns the grant id");
    lrp_str_free(&grant_id);

    rc = lrp_complete_act_as_callback(&pending, "nonce=abc_DEF-123&act_as_grant_id=g2", &grant_id,
                                      &err);
    T_CHECK(rc == 0 && strcmp(grant_id.data, "g2") == 0, "act-as callback: bare query works");
    lrp_str_free(&grant_id);

    const char *bad[] = {
        "http://app.lan/cb?act_as_grant_id=g&nonce=abc_DEF-124",   /* wrong nonce */
        "http://app.lan/cb?act_as_grant_id=g&nonce=abc_DEF-12",    /* prefix nonce */
        "http://app.lan/cb?act_as_grant_id=g&nonce=abc_DEF-1234",  /* longer nonce */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        rc = lrp_complete_act_as_callback(&pending, bad[i], &grant_id, &err);
        T_CHECK(rc != 0 && err.code == LRP_ERR_VERIFICATION && grant_id.data == NULL,
                "act-as callback: nonce mismatch is refused");
    }
    const char *malformed[] = {
        "http://app.lan/cb?nonce=abc_DEF-123",                                   /* no grant id */
        "http://app.lan/cb?act_as_grant_id=g",                                    /* no nonce */
        "http://app.lan/cb?act_as_grant_id=g&act_as_grant_id=h&nonce=abc_DEF-123", /* repeated */
        "http://app.lan/cb?act_as_grant_id=&nonce=abc_DEF-123",                   /* empty id */
        "http://app.lan/cb?act_as_grant_id=g%2&nonce=abc_DEF-123",                /* bad escape */
        "http://app.lan/cb?act_as_grant_id=g%00x&nonce=abc_DEF-123",              /* NUL */
    };
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
        rc = lrp_complete_act_as_callback(&pending, malformed[i], &grant_id, &err);
        T_CHECK(rc != 0 && err.code == LRP_ERR_INVALID_INPUT && grant_id.data == NULL,
                "act-as callback: malformed callback is refused");
    }
    lrp_pending_act_as_free(&pending);
}

int run_act_as_tests(void) {
    test_act_as_vector_bytes();
    test_begin_act_as();
    test_act_as_callback();
    return 0;
}
