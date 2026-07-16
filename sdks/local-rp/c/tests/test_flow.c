/* Flow tests: a real loopback TCP+TLS "fake IDP" server, written with the
 * same libcrypto/libssl this SDK uses (never a forked `openssl s_server`),
 * exercising begin_local_login -> (test builds the IDP's callback exactly
 * per Wire Precision) -> complete_local_login end to end, plus the sibling
 * failure modes the design doc's "Tests and Verification" list calls out:
 * DNS pin mismatch, wrong decryption key, nonce/state mismatch, and
 * non-http(s) callback scheme rejection.
 *
 * The server plays the IDP: one Ed25519 keypair is used both as its TLS
 * certificate identity and as its sole domain signing key (its fingerprint
 * is the `_linkkeys` `fp=` value) — the same "single active signing key"
 * shape a minimal real domain would have, and sufficient to exercise every
 * verification step in this SDK's complete_local_login chain.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "cbor.h"
#include "crypto.h"
#include "encoding.h"
#include "error.h"
#include "local_rp.h"
#include "revocation.h"
#include "rpc.h"
#include "test_util.h"
#include "time_util.h"

#define FLOW_DOMAIN "conformance-flow.test"
#define FLOW_KEY_ID "domain-key-1"
#define FLOW_USER_ID "user-1"

/* get-revocations response behavior, selected per test (SEC fix tests:
 * FIX B fail-closed, FIX A5 quorum-revoked signing key). Zero-value
 * (REVOKE_MODE_EMPTY) is the well-behaved default every other test relies
 * on implicitly via `memset(&fx, 0, sizeof(fx))`. */
#define REVOKE_MODE_EMPTY 0                    /* well-behaved: empty revocation list */
#define REVOKE_MODE_SERVER_ERROR 1              /* CSIL-RPC error status (FIX B negative case) */
#define REVOKE_MODE_DROP_CONNECTION 2           /* accept, then close without responding */
#define REVOKE_MODE_QUORUM_REVOKE_DOMAIN_KEY 3  /* valid quorum-signed cert targeting FLOW_KEY_ID */

typedef struct {
    int listen_fd;
    SSL_CTX *ssl_ctx;
    uint8_t domain_priv[32];
    uint8_t domain_pub[32];
    char domain_fp[LRP_FINGERPRINT_HEX_LEN + 1];
    int max_connections;

    /* --- Hostile-IDP test knobs; all zero-value ("well-behaved") unless a
     * test explicitly sets them before start_flow_fixture spins up the
     * server thread. --- */

    /* redeem-claim-ticket response overrides (SEC fix, FIX A identity
     * binding). NULL => the honest default (FLOW_USER_ID / FLOW_DOMAIN). */
    const char *redemption_user_id_override;
    const char *redemption_user_domain_override;
    const char *claim_user_id_override;
    int omit_claims; /* 1 => the redemption response carries zero claims */

    /* get-revocations response behavior (FIX B / FIX A5). */
    int revocations_mode;
    /* Two sibling signing keys for the REVOKE_MODE_QUORUM_REVOKE_DOMAIN_KEY
     * case: LRP_REVOCATION_QUORUM (2) distinct valid signers are required
     * to make a revocation certificate verify. Their key ids are
     * "sibling-key-1"/"sibling-key-2". */
    uint8_t sibling_priv[2][32];
    uint8_t sibling_pub[2][32];
    int sibling_keys_count; /* 0 or 2 */
} flow_server;

static X509 *make_self_signed_cert(EVP_PKEY *pkey) {
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600L * 24);
    X509_set_pubkey(x, pkey);
    X509_NAME *name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"lrp-flow-test", -1,
                                -1, 0);
    X509_set_issuer_name(x, name);
    X509_sign(x, pkey, NULL); /* Ed25519 is one-shot: NULL digest */
    return x;
}

/* --------------------------------------------------------------------- */
/* Minimal server-side CSIL-RPC: decode request, dispatch, encode response */
/* --------------------------------------------------------------------- */

static int srv_read_all(SSL *ssl, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_read(ssl, buf + off, (int)(len - off));
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int srv_write_all(SSL *ssl, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, buf + off, (int)(len - off));
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int srv_read_frame(SSL *ssl, lrp_bytes *out) {
    uint8_t lenbuf[4];
    if (srv_read_all(ssl, lenbuf, 4) != 0) return -1;
    uint32_t len =
        ((uint32_t)lenbuf[0] << 24) | ((uint32_t)lenbuf[1] << 16) | ((uint32_t)lenbuf[2] << 8) | lenbuf[3];
    uint8_t *buf = (uint8_t *)malloc(len > 0 ? len : 1);
    if (len > 0 && srv_read_all(ssl, buf, len) != 0) {
        free(buf);
        return -1;
    }
    out->data = buf;
    out->len = len;
    return 0;
}

static int srv_send_frame(SSL *ssl, const uint8_t *data, size_t len) {
    uint8_t lenbuf[4] = {(uint8_t)(len >> 24), (uint8_t)(len >> 16), (uint8_t)(len >> 8),
                          (uint8_t)len};
    if (srv_write_all(ssl, lenbuf, 4) != 0) return -1;
    if (len == 0) return 0;
    return srv_write_all(ssl, data, len);
}

static void encode_rpc_response_ok(const uint8_t *payload, size_t payload_len, lrp_bytes *out) {
    cbor_buf b;
    cbor_buf_init(&b);
    cbor_write_map_header(&b, 3);
    cbor_write_text_cstr(&b, "v");
    cbor_write_uint(&b, 1);
    cbor_write_text_cstr(&b, "status");
    cbor_write_uint(&b, 0);
    cbor_write_text_cstr(&b, "payload");
    cbor_write_tag24(&b, payload, payload_len);
    *out = cbor_buf_release(&b);
}

static void write_domain_signing_key(cbor_buf *out, const char *key_id, const uint8_t pub[32],
                                      const char *created_at, const char *expires_at) {
    cbor_write_map_header(out, 7);
    cbor_write_text_cstr(out, "key_id");
    cbor_write_text_cstr(out, key_id);
    cbor_write_text_cstr(out, "public_key");
    cbor_write_bytes(out, pub, 32);
    cbor_write_text_cstr(out, "fingerprint");
    char fp[LRP_FINGERPRINT_HEX_LEN + 1];
    lrp_fingerprint_hex(pub, 32, fp);
    cbor_write_text_cstr(out, fp);
    cbor_write_text_cstr(out, "algorithm");
    cbor_write_text_cstr(out, "ed25519");
    cbor_write_text_cstr(out, "key_usage");
    cbor_write_text_cstr(out, "sign");
    cbor_write_text_cstr(out, "created_at");
    cbor_write_text_cstr(out, created_at);
    cbor_write_text_cstr(out, "expires_at");
    cbor_write_text_cstr(out, expires_at);
}

/* `keys` always includes the primary FLOW_KEY_ID signing key, plus (when
 * srv->sibling_keys_count > 0, for the FIX A5 quorum-revocation test) the
 * sibling signing keys a revocation certificate quorum-signs against. */
static void build_get_domain_keys_response(const flow_server *srv, lrp_bytes *out) {
    char created_at[32], expires_at[32];
    lrp_format_rfc3339(lrp_wall_clock_now() - 3600, created_at);
    lrp_format_rfc3339(lrp_wall_clock_now() + 3600L * 24 * 365, expires_at);

    cbor_buf key;
    cbor_buf_init(&key);
    write_domain_signing_key(&key, FLOW_KEY_ID, srv->domain_pub, created_at, expires_at);

    cbor_buf resp;
    cbor_buf_init(&resp);
    cbor_write_map_header(&resp, 3);
    cbor_write_text_cstr(&resp, "domain");
    cbor_write_text_cstr(&resp, FLOW_DOMAIN);
    cbor_write_text_cstr(&resp, "keys");
    cbor_write_array_header(&resp, 1 + (size_t)srv->sibling_keys_count);
    cbor_write_raw(&resp, key.data, key.len);
    cbor_buf_free(&key);
    for (int i = 0; i < srv->sibling_keys_count; i++) {
        char kid[32];
        snprintf(kid, sizeof(kid), "sibling-key-%d", i + 1);
        cbor_buf sk;
        cbor_buf_init(&sk);
        write_domain_signing_key(&sk, kid, srv->sibling_pub[i], created_at, expires_at);
        cbor_write_raw(&resp, sk.data, sk.len);
        cbor_buf_free(&sk);
    }
    /* FIX B: this SDK must fetch get-revocations unconditionally regardless
     * of this flag now, so both `0` (here) and `1` are exercised across the
     * test suite without changing SDK behavior — kept `0` (the honest,
     * conservative default) so a regression back to trusting this flag
     * would show up as the flow tests below failing closed. */
    cbor_write_text_cstr(&resp, "recent_revocations_available");
    cbor_write_bool(&resp, 0);

    encode_rpc_response_ok(resp.data, resp.len, out);
    cbor_buf_free(&resp);
}

/* Builds the DomainKeys/get-revocations response per srv->revocations_mode:
 * an empty list (well-behaved), a server error, or (REVOKE_MODE_
 * QUORUM_REVOKE_DOMAIN_KEY) a single certificate revoking FLOW_KEY_ID,
 * quorum-signed by the two sibling keys build_get_domain_keys_response also
 * advertises. REVOKE_MODE_DROP_CONNECTION is handled by the caller (no
 * response is written at all). */
static void build_get_revocations_response(const flow_server *srv, lrp_bytes *out) {
    if (srv->revocations_mode == REVOKE_MODE_SERVER_ERROR) {
        cbor_buf b;
        cbor_buf_init(&b);
        cbor_write_map_header(&b, 3);
        cbor_write_text_cstr(&b, "v");
        cbor_write_uint(&b, 1);
        cbor_write_text_cstr(&b, "status");
        cbor_write_uint(&b, 2);
        cbor_write_text_cstr(&b, "error");
        cbor_write_text_cstr(&b, "simulated get-revocations failure");
        *out = cbor_buf_release(&b);
        return;
    }

    cbor_buf resp;
    cbor_buf_init(&resp);
    cbor_write_map_header(&resp, 1);
    cbor_write_text_cstr(&resp, "revocations");

    if (srv->revocations_mode == REVOKE_MODE_QUORUM_REVOKE_DOMAIN_KEY) {
        char revoked_at[32];
        lrp_format_rfc3339(lrp_wall_clock_now(), revoked_at);
        lrp_bytes rev_payload = {0};
        lrp_revocation_payload(FLOW_KEY_ID, srv->domain_fp, revoked_at, FLOW_DOMAIN, &rev_payload,
                                NULL);

        cbor_buf cert;
        cbor_buf_init(&cert);
        cbor_write_map_header(&cert, 4);
        cbor_write_text_cstr(&cert, "target_key_id");
        cbor_write_text_cstr(&cert, FLOW_KEY_ID);
        cbor_write_text_cstr(&cert, "target_fingerprint");
        cbor_write_text_cstr(&cert, srv->domain_fp);
        cbor_write_text_cstr(&cert, "revoked_at");
        cbor_write_text_cstr(&cert, revoked_at);
        cbor_write_text_cstr(&cert, "signatures");
        cbor_write_array_header(&cert, (size_t)srv->sibling_keys_count);
        for (int i = 0; i < srv->sibling_keys_count; i++) {
            uint8_t sig[64];
            lrp_error serr = {0};
            lrp_ed25519_sign(srv->sibling_priv[i], rev_payload.data, rev_payload.len, sig, &serr);
            char kid[32];
            snprintf(kid, sizeof(kid), "sibling-key-%d", i + 1);
            cbor_buf s;
            cbor_buf_init(&s);
            cbor_write_map_header(&s, 3);
            cbor_write_text_cstr(&s, "domain");
            cbor_write_text_cstr(&s, FLOW_DOMAIN);
            cbor_write_text_cstr(&s, "signed_by_key_id");
            cbor_write_text_cstr(&s, kid);
            cbor_write_text_cstr(&s, "signature");
            cbor_write_bytes(&s, sig, 64);
            cbor_write_raw(&cert, s.data, s.len);
            cbor_buf_free(&s);
        }
        lrp_bytes_free(&rev_payload);

        cbor_write_array_header(&resp, 1);
        cbor_write_raw(&resp, cert.data, cert.len);
        cbor_buf_free(&cert);
    } else {
        cbor_write_array_header(&resp, 0);
    }

    encode_rpc_response_ok(resp.data, resp.len, out);
    cbor_buf_free(&resp);
}

/* `(TAG, claim_id, claim_type, claim_value: bstr, "user_id@domain",
 * signing_domain, expires_at: null, attested_at)` — mirrors
 * `liblinkkeys::claims::claim_sign_payload`; duplicated here (rather than
 * exposed from the library) since only this test's fake IDP ever needs to
 * SIGN a claim — the SDK itself only verifies. */
static void claim_sign_payload(const char *claim_id, const char *claim_type,
                                const char *claim_value, const char *subject, const char *domain,
                                const char *attested_at, lrp_bytes *out) {
    cbor_buf b;
    cbor_buf_init(&b);
    cbor_write_array_header(&b, 8);
    cbor_write_text_cstr(&b, "linkkeys-claim-v1alpha");
    cbor_write_text_cstr(&b, claim_id);
    cbor_write_text_cstr(&b, claim_type);
    cbor_write_bytes(&b, (const uint8_t *)claim_value, strlen(claim_value));
    cbor_write_text_cstr(&b, subject);
    cbor_write_text_cstr(&b, domain);
    cbor_write_null(&b);
    cbor_write_text_cstr(&b, attested_at);
    *out = cbor_buf_release(&b);
}

/* `redemption_user_id`/`redemption_user_domain` are the top-level identity
 * the LocalRpTicketRedemptionResponse itself carries; `claim_user_id` is
 * the (separately overridable) user_id embedded in — and signed as part
 * of — the one returned claim. A hostile IDP controls its own signing key,
 * so making `claim_user_id` differ from `redemption_user_id` still
 * produces a claim whose signature verifies fine (FIX A test 2: the
 * signature alone proves the domain signed *that* claim, not that it's the
 * claim for *this* login) — exactly the gap the SDK's added
 * claim.user_id == payload.user_id check must close. */
static void build_redeem_response_ex(const flow_server *srv, const char *redemption_user_id,
                                      const char *redemption_user_domain, const char *claim_user_id,
                                      int omit_claims, lrp_bytes *out) {
    char attested_at[32], ticket_expires_at[32];
    lrp_format_rfc3339(lrp_wall_clock_now(), attested_at);
    lrp_format_rfc3339(lrp_wall_clock_now() + 3600, ticket_expires_at);

    cbor_buf resp;
    cbor_buf_init(&resp);
    cbor_write_map_header(&resp, 4);
    cbor_write_text_cstr(&resp, "user_id");
    cbor_write_text_cstr(&resp, redemption_user_id);
    cbor_write_text_cstr(&resp, "user_domain");
    cbor_write_text_cstr(&resp, redemption_user_domain);
    cbor_write_text_cstr(&resp, "claims");

    if (omit_claims) {
        cbor_write_array_header(&resp, 0);
    } else {
        char subject[128];
        snprintf(subject, sizeof(subject), "%s@%s", claim_user_id, FLOW_DOMAIN);
        lrp_bytes sign_payload = {0};
        claim_sign_payload("claim-handle-1", "handle", "flowtestuser", subject, FLOW_DOMAIN,
                            attested_at, &sign_payload);
        uint8_t sig[64];
        lrp_error err = {0};
        lrp_ed25519_sign(srv->domain_priv, sign_payload.data, sign_payload.len, sig, &err);
        lrp_bytes_free(&sign_payload);

        cbor_buf claim_sig;
        cbor_buf_init(&claim_sig);
        cbor_write_map_header(&claim_sig, 3);
        cbor_write_text_cstr(&claim_sig, "domain");
        cbor_write_text_cstr(&claim_sig, FLOW_DOMAIN);
        cbor_write_text_cstr(&claim_sig, "signed_by_key_id");
        cbor_write_text_cstr(&claim_sig, FLOW_KEY_ID);
        cbor_write_text_cstr(&claim_sig, "signature");
        cbor_write_bytes(&claim_sig, sig, 64);

        cbor_buf claim;
        cbor_buf_init(&claim);
        cbor_write_map_header(&claim, 7);
        cbor_write_text_cstr(&claim, "claim_id");
        cbor_write_text_cstr(&claim, "claim-handle-1");
        cbor_write_text_cstr(&claim, "user_id");
        cbor_write_text_cstr(&claim, claim_user_id);
        cbor_write_text_cstr(&claim, "claim_type");
        cbor_write_text_cstr(&claim, "handle");
        cbor_write_text_cstr(&claim, "claim_value");
        cbor_write_bytes(&claim, (const uint8_t *)"flowtestuser", strlen("flowtestuser"));
        cbor_write_text_cstr(&claim, "signatures");
        cbor_write_array_header(&claim, 1);
        cbor_write_raw(&claim, claim_sig.data, claim_sig.len);
        cbor_write_text_cstr(&claim, "attested_at");
        cbor_write_text_cstr(&claim, attested_at);
        cbor_write_text_cstr(&claim, "created_at");
        cbor_write_text_cstr(&claim, attested_at);
        cbor_buf_free(&claim_sig);

        cbor_write_array_header(&resp, 1);
        cbor_write_raw(&resp, claim.data, claim.len);
        cbor_buf_free(&claim);
    }

    cbor_write_text_cstr(&resp, "ticket_expires_at");
    cbor_write_text_cstr(&resp, ticket_expires_at);

    encode_rpc_response_ok(resp.data, resp.len, out);
    cbor_buf_free(&resp);
}

static void build_redeem_response(const flow_server *srv, lrp_bytes *out) {
    const char *redemption_user_id =
        srv->redemption_user_id_override != NULL ? srv->redemption_user_id_override : FLOW_USER_ID;
    const char *redemption_user_domain = srv->redemption_user_domain_override != NULL
                                              ? srv->redemption_user_domain_override
                                              : FLOW_DOMAIN;
    const char *claim_user_id =
        srv->claim_user_id_override != NULL ? srv->claim_user_id_override : FLOW_USER_ID;
    build_redeem_response_ex(srv, redemption_user_id, redemption_user_domain, claim_user_id,
                              srv->omit_claims, out);
}

static void handle_one_request(const flow_server *srv, SSL *ssl) {
    lrp_bytes frame = {0};
    if (srv_read_frame(ssl, &frame) != 0) return;
    lrp_error err = {0};
    cbor_value *root = NULL;
    if (cbor_decode(frame.data, frame.len, &root, &err) != 0) {
        lrp_bytes_free(&frame);
        return;
    }
    lrp_bytes_free(&frame);
    lrp_str service = {0}, op = {0};
    cbor_get_text(root, "service", &service, &err);
    cbor_get_text(root, "op", &op, &err);

    int is_get_revocations = service.data != NULL && op.data != NULL &&
                              strcmp(service.data, "DomainKeys") == 0 &&
                              strcmp(op.data, "get-revocations") == 0;
    if (is_get_revocations && srv->revocations_mode == REVOKE_MODE_DROP_CONNECTION) {
        /* FIX B negative case: accept the connection, decode the request,
         * then close without writing any response at all — simulating a
         * dropped/hung peer. The client's read_frame must observe this as
         * a transport failure, not silently proceed as if revocations were
         * empty. */
        lrp_str_free(&service);
        lrp_str_free(&op);
        cbor_value_free(root);
        free(root);
        return;
    }

    lrp_bytes resp = {0};
    if (service.data != NULL && op.data != NULL && strcmp(service.data, "DomainKeys") == 0 &&
        strcmp(op.data, "get-domain-keys") == 0) {
        build_get_domain_keys_response(srv, &resp);
    } else if (is_get_revocations) {
        build_get_revocations_response(srv, &resp);
    } else if (service.data != NULL && op.data != NULL && strcmp(service.data, "LocalRp") == 0 &&
               strcmp(op.data, "redeem-claim-ticket") == 0) {
        build_redeem_response(srv, &resp);
    } else {
        cbor_buf b;
        cbor_buf_init(&b);
        cbor_write_map_header(&b, 3);
        cbor_write_text_cstr(&b, "v");
        cbor_write_uint(&b, 1);
        cbor_write_text_cstr(&b, "status");
        cbor_write_uint(&b, 2);
        cbor_write_text_cstr(&b, "error");
        cbor_write_text_cstr(&b, "unknown-service-or-op");
        resp = cbor_buf_release(&b);
    }
    lrp_str_free(&service);
    lrp_str_free(&op);
    cbor_value_free(root);
    free(root);

    srv_send_frame(ssl, resp.data, resp.len);
    lrp_bytes_free(&resp);
}

static void *server_thread_main(void *arg) {
    flow_server *srv = (flow_server *)arg;
    for (int i = 0; i < srv->max_connections; i++) {
        int fd = accept(srv->listen_fd, NULL, NULL);
        if (fd < 0) break;
        SSL *ssl = SSL_new(srv->ssl_ctx);
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) == 1) {
            handle_one_request(srv, ssl);
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }
    return NULL;
}

/* --------------------------------------------------------------------- */
/* Fake DNS resolver: canned answers pointing at the loopback server      */
/* --------------------------------------------------------------------- */

typedef struct {
    char domain_txt[256];   /* _linkkeys.<domain> answer */
    char apis_txt[256];     /* _linkkeys_apis.<domain> answer */
} fake_dns_ctx;

static int fake_txt_lookup(lrp_dns_resolver *self, const char *name, lrp_txt_records *out,
                            lrp_error *err) {
    (void)err;
    fake_dns_ctx *ctx = (fake_dns_ctx *)self->ctx;
    const char *answer = NULL;
    if (strstr(name, "_linkkeys_apis.") == name) {
        answer = ctx->apis_txt;
    } else if (strstr(name, "_linkkeys.") == name) {
        answer = ctx->domain_txt;
    }
    if (answer == NULL) {
        out->entries = NULL;
        out->count = 0;
        return 0;
    }
    out->entries = (char **)malloc(sizeof(char *));
    out->entries[0] = strdup(answer);
    out->count = 1;
    return 0;
}

/* --------------------------------------------------------------------- */
/* Test scaffolding: spin up one server, wire up begin_local_login's       */
/* callback to a hand-built (test-side) IDP response.                     */
/* --------------------------------------------------------------------- */

typedef struct {
    flow_server srv;
    pthread_t thread;
    fake_dns_ctx dns_ctx;
    lrp_dns_resolver dns;
    int port;
} flow_fixture;

static int start_flow_fixture(flow_fixture *fx, int max_connections) {
    lrp_error err = {0};
    if (lrp_ed25519_generate(fx->srv.domain_priv, fx->srv.domain_pub, &err) != 0) return -1;
    lrp_fingerprint_hex(fx->srv.domain_pub, 32, fx->srv.domain_fp);
    fx->srv.max_connections = max_connections;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, fx->srv.domain_priv, 32);
    X509 *cert = make_self_signed_cert(pkey);
    fx->srv.ssl_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(fx->srv.ssl_ctx, cert);
    SSL_CTX_use_PrivateKey(fx->srv.ssl_ctx, pkey);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* Bounds the server thread's final accept() so it exits promptly (and
     * stop_flow_fixture's pthread_join returns) even when a test case uses
     * fewer than `max_connections` real connections — e.g. a negative case
     * that fails before ever reaching the network. */
    struct timeval accept_timeout = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &accept_timeout, sizeof(accept_timeout));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return -1;
    if (listen(fd, 8) != 0) return -1;
    socklen_t alen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &alen);
    fx->port = ntohs(addr.sin_port);
    fx->srv.listen_fd = fd;

    /* Callers that want the FIX A5 (quorum-revoked signing key) test must
     * generate fx->srv.sibling_priv/pub and set sibling_keys_count = 2
     * BEFORE calling start_flow_fixture: their fingerprints need to be
     * directly DNS-pinned too (lrp_trust_keys only pins "sign" keys whose
     * fingerprint appears in the `fp=` set), one `fp=` token per key. */
    {
        int off = snprintf(fx->dns_ctx.domain_txt, sizeof(fx->dns_ctx.domain_txt), "v=lk1 fp=%s",
                            fx->srv.domain_fp);
        for (int i = 0; i < fx->srv.sibling_keys_count && off > 0 &&
                        (size_t)off < sizeof(fx->dns_ctx.domain_txt);
             i++) {
            char sib_fp[LRP_FINGERPRINT_HEX_LEN + 1];
            lrp_fingerprint_hex(fx->srv.sibling_pub[i], 32, sib_fp);
            off += snprintf(fx->dns_ctx.domain_txt + off, sizeof(fx->dns_ctx.domain_txt) - (size_t)off,
                             " fp=%s", sib_fp);
        }
    }
    snprintf(fx->dns_ctx.apis_txt, sizeof(fx->dns_ctx.apis_txt), "v=lk1 tcp=127.0.0.1:%d", fx->port);
    fx->dns.ctx = &fx->dns_ctx;
    fx->dns.txt_lookup = fake_txt_lookup;

    pthread_create(&fx->thread, NULL, server_thread_main, &fx->srv);
    return 0;
}

static void stop_flow_fixture(flow_fixture *fx) {
    pthread_join(fx->thread, NULL);
    SSL_CTX_free(fx->srv.ssl_ctx);
    close(fx->srv.listen_fd);
}

/* Builds the encrypted_token= value and arrived_url the fake IDP would
 * deliver for a successful login, per Wire Precision's callback
 * construction. `suite` selects the AEAD suite (both are exercised across
 * the test cases). Returns 0 on success. */
static int build_idp_callback(const lrp_identity *identity, const lrp_pending_login *pending,
                               const char *user_domain, const char *audience_fingerprint,
                               const uint8_t domain_priv[32], lrp_aead_suite suite, char **out_token,
                               char **out_arrived_url) {
    char issued_at[32], expires_at[32];
    lrp_format_rfc3339(lrp_wall_clock_now(), issued_at);
    lrp_format_rfc3339(lrp_wall_clock_now() + 300, expires_at);

    cbor_buf pb;
    cbor_buf_init(&pb);
    cbor_write_map_header(&pb, 9);
    cbor_write_text_cstr(&pb, "user_id");
    cbor_write_text_cstr(&pb, FLOW_USER_ID);
    cbor_write_text_cstr(&pb, "user_domain");
    cbor_write_text_cstr(&pb, user_domain);
    cbor_write_text_cstr(&pb, "claim_ticket");
    uint8_t ticket[32];
    lrp_error err = {0};
    lrp_rand_bytes(ticket, 32, &err);
    cbor_write_bytes(&pb, ticket, 32);
    cbor_write_text_cstr(&pb, "audience_fingerprint");
    cbor_write_text_cstr(&pb, audience_fingerprint);
    cbor_write_text_cstr(&pb, "callback_url");
    cbor_write_text_cstr(&pb, pending->callback_url.data);
    cbor_write_text_cstr(&pb, "nonce");
    cbor_write_bytes(&pb, pending->nonce.data, pending->nonce.len);
    cbor_write_text_cstr(&pb, "state");
    cbor_write_bytes(&pb, pending->state.data, pending->state.len);
    cbor_write_text_cstr(&pb, "issued_at");
    cbor_write_text_cstr(&pb, issued_at);
    cbor_write_text_cstr(&pb, "expires_at");
    cbor_write_text_cstr(&pb, expires_at);
    lrp_bytes payload_bytes = cbor_buf_release(&pb);

    lrp_bytes sig = {0};
    lrp_sign_envelope(LRP_CTX_CALLBACK, payload_bytes.data, payload_bytes.len, domain_priv, &sig,
                       &err);

    cbor_buf spb;
    cbor_buf_init(&spb);
    cbor_write_map_header(&spb, 3);
    cbor_write_text_cstr(&spb, "payload");
    cbor_write_bytes(&spb, payload_bytes.data, payload_bytes.len);
    cbor_write_text_cstr(&spb, "signing_key_id");
    cbor_write_text_cstr(&spb, FLOW_KEY_ID);
    cbor_write_text_cstr(&spb, "signature");
    cbor_write_bytes(&spb, sig.data, sig.len);
    lrp_bytes_free(&payload_bytes);
    lrp_bytes_free(&sig);
    lrp_bytes plaintext = cbor_buf_release(&spb);

    uint8_t ephemeral_priv[32], ephemeral_pub[32];
    lrp_x25519_generate(ephemeral_priv, ephemeral_pub, &err);
    uint8_t aead_nonce[12];
    lrp_rand_bytes(aead_nonce, 12, &err);

    lrp_w_callback_header header;
    memset(&header, 0, sizeof(header));
    header.fingerprint.data = strdup(audience_fingerprint);
    header.nonce.data = (uint8_t *)malloc(pending->nonce.len);
    memcpy(header.nonce.data, pending->nonce.data, pending->nonce.len);
    header.nonce.len = pending->nonce.len;
    header.state.data = (uint8_t *)malloc(pending->state.len);
    memcpy(header.state.data, pending->state.data, pending->state.len);
    header.state.len = pending->state.len;
    header.suite.data = strdup(lrp_aead_suite_str(suite));
    memcpy(header.ephemeral_public_key, ephemeral_pub, 32);
    memcpy(header.aead_nonce, aead_nonce, 12);
    header.issued_at.data = strdup(issued_at);
    header.expires_at.data = strdup(expires_at);

    lrp_bytes header_bytes = {0};
    lrp_encode_callback_header(&header, &header_bytes, &err);
    lrp_w_callback_header_free(&header);

    uint8_t shared_secret[32];
    lrp_x25519_ecdh(ephemeral_priv, identity->encryption_public_key, shared_secret, &err);
    uint8_t aead_key[32];
    lrp_bytes kdf_ctx = {0};
    lrp_local_rp_callback_kdf(suite, ephemeral_pub, identity->encryption_public_key, shared_secret,
                               32, aead_key, &kdf_ctx, &err);
    uint8_t *aad = (uint8_t *)malloc(kdf_ctx.len + header_bytes.len);
    memcpy(aad, kdf_ctx.data, kdf_ctx.len);
    memcpy(aad + kdf_ctx.len, header_bytes.data, header_bytes.len);
    size_t aad_len = kdf_ctx.len + header_bytes.len;
    lrp_bytes_free(&kdf_ctx);

    lrp_bytes ciphertext = {0};
    int erc = lrp_aead_encrypt(suite, aead_key, aead_nonce, aad, aad_len, plaintext.data,
                                plaintext.len, &ciphertext, &err);
    free(aad);
    lrp_bytes_free(&plaintext);
    if (erc != 0) {
        lrp_bytes_free(&header_bytes);
        return -1;
    }

    cbor_buf eb;
    cbor_buf_init(&eb);
    cbor_write_map_header(&eb, 2);
    cbor_write_text_cstr(&eb, "header");
    cbor_write_bytes(&eb, header_bytes.data, header_bytes.len);
    cbor_write_text_cstr(&eb, "ciphertext");
    cbor_write_bytes(&eb, ciphertext.data, ciphertext.len);
    lrp_bytes_free(&header_bytes);
    lrp_bytes_free(&ciphertext);
    lrp_bytes encrypted = cbor_buf_release(&eb);

    lrp_str token = {0};
    lrp_base64url_encode(encrypted.data, encrypted.len, &token, &err);
    lrp_bytes_free(&encrypted);

    size_t url_len = strlen(pending->callback_url.data) + strlen("?encrypted_token=") +
                      strlen(token.data) + 1;
    char *arrived_url = (char *)malloc(url_len);
    snprintf(arrived_url, url_len, "%s?encrypted_token=%s", pending->callback_url.data, token.data);

    *out_token = token.data;
    *out_arrived_url = arrived_url;
    return 0;
}

/* Shared setup for the hostile-IDP tests below: generates a fresh identity
 * and begins a login against `FLOW_DOMAIN`, with the caller's own
 * required_claims list (NULL/0 => begin_local_login's defaults, ["handle"]).
 * Returns 0 on success. */
static int setup_login(const char *app_name, const char *const *required_claims,
                        size_t required_claims_count, lrp_identity *out_identity,
                        lrp_pending_login *out_pending) {
    lrp_error err = {0};
    lrp_generate_identity_config gen_cfg;
    memset(&gen_cfg, 0, sizeof(gen_cfg));
    gen_cfg.app_name = app_name;
    gen_cfg.now_unix = lrp_wall_clock_now();
    if (lrp_generate_local_rp_identity(&gen_cfg, out_identity, &err) != 0) return -1;

    lrp_login_redirect redirect = {0};
    lrp_begin_login_config begin_cfg;
    memset(&begin_cfg, 0, sizeof(begin_cfg));
    begin_cfg.identity = out_identity;
    begin_cfg.callback_url = "http://127.0.0.1:9999/callback";
    begin_cfg.user_domain = FLOW_DOMAIN;
    begin_cfg.required_claims = required_claims;
    begin_cfg.required_claims_count = required_claims_count;
    begin_cfg.now_unix = lrp_wall_clock_now();
    int rc = lrp_begin_local_login(&begin_cfg, &redirect, out_pending, &err);
    lrp_login_redirect_free(&redirect);
    if (rc != 0) lrp_identity_free(out_identity);
    return rc;
}

/* Runs identity/pending through build_idp_callback + complete_local_login
 * against `fx` and returns complete_local_login's return code (0 success,
 * -1 failure); *out_err carries the failure detail. Frees token/arrived_url
 * itself; does not touch identity/pending ownership. */
static int run_complete(flow_fixture *fx, const lrp_identity *identity,
                         const lrp_pending_login *pending, lrp_verified_login *out_verified,
                         lrp_error *out_err) {
    char *token = NULL, *arrived_url = NULL;
    if (build_idp_callback(identity, pending, FLOW_DOMAIN, identity->fingerprint, fx->srv.domain_priv,
                            LRP_SUITE_AES_256_GCM, &token, &arrived_url) != 0) {
        return -1;
    }

    lrp_transport transport = lrp_default_transport(LRP_ADDRESS_PERMISSIVE);
    lrp_complete_login_config complete_cfg;
    memset(&complete_cfg, 0, sizeof(complete_cfg));
    complete_cfg.identity = identity;
    complete_cfg.pending = pending;
    complete_cfg.encrypted_token = token;
    complete_cfg.arrived_url = arrived_url;
    complete_cfg.now_unix = lrp_wall_clock_now();
    complete_cfg.transport = &transport;
    complete_cfg.dns = &fx->dns;

    int rc = lrp_complete_local_login(&complete_cfg, out_verified, out_err);
    free(token);
    free(arrived_url);
    return rc;
}

/* --------------------------------------------------------------------- */
/* Hostile-IDP tests (SEC fixes): each proves complete_local_login FAILS   */
/* CLOSED (never returns success) when a malicious/compromised IDP tries   */
/* one of the identity-binding, required-claims, or revocation attacks.    */
/* --------------------------------------------------------------------- */

/* (1) The ticket-redemption response's top-level identity disagrees with
 * the signed callback payload's identity. The redemption response carries
 * no signature of its own — a compromised/malicious IDP could otherwise
 * launder consent given to one user onto another user's claims. */
static void test_flow_redemption_identity_mismatch_is_fatal(void) {
    flow_fixture fx;
    memset(&fx, 0, sizeof(fx));
    fx.srv.redemption_user_id_override = "attacker-controlled-user";
    /* Exactly 3 connections: fetch_domain_keys (get-domain-keys +
     * get-revocations) + redeem-claim-ticket; the identity-mismatch check
     * fires right after, with no further network access. */
    if (start_flow_fixture(&fx, 3) != 0) {
        T_CHECK(0, "identity: redemption-mismatch fixture starts");
        return;
    }

    lrp_identity identity = {0};
    lrp_pending_login pending = {0};
    T_CHECK(setup_login("Redemption Mismatch App", NULL, 0, &identity, &pending) == 0,
             "identity: begin_local_login succeeds (redemption-mismatch case)");

    lrp_verified_login verified = {0};
    lrp_error err = {0};
    int rc = run_complete(&fx, &identity, &pending, &verified, &err);
    T_CHECK(rc != 0,
             "identity: ticket redemption identity != signed callback payload identity is FATAL");
    if (rc == 0) lrp_verified_login_free(&verified);

    lrp_pending_login_free(&pending);
    lrp_identity_free(&identity);
    stop_flow_fixture(&fx);
}

/* (2) A single claim inside an otherwise-valid, correctly-signed redemption
 * response names a different user_id than the signed callback payload's
 * subject. The claim's own signature only proves the issuing domain signed
 * *that* claim (a malicious IDP controls its own signing key and can sign
 * whatever claim content it likes) — never that it's the claim for *this*
 * login. */
static void test_flow_claim_user_id_mismatch_is_fatal(void) {
    flow_fixture fx;
    memset(&fx, 0, sizeof(fx));
    fx.srv.claim_user_id_override = "attacker-controlled-claim-subject";
    /* Exactly 3 connections, same shape as the redemption-mismatch case
     * above: the claim.user_id check fires during claim verification,
     * after redemption, with no further network access. */
    if (start_flow_fixture(&fx, 3) != 0) {
        T_CHECK(0, "identity: claim-user-id-mismatch fixture starts");
        return;
    }

    lrp_identity identity = {0};
    lrp_pending_login pending = {0};
    T_CHECK(setup_login("Claim Mismatch App", NULL, 0, &identity, &pending) == 0,
             "identity: begin_local_login succeeds (claim-mismatch case)");

    lrp_verified_login verified = {0};
    lrp_error err = {0};
    int rc = run_complete(&fx, &identity, &pending, &verified, &err);
    T_CHECK(rc != 0,
             "identity: claim.user_id != payload.user_id is FATAL even with a validly signed claim");
    if (rc == 0) lrp_verified_login_free(&verified);

    lrp_pending_login_free(&pending);
    lrp_identity_free(&identity);
    stop_flow_fixture(&fx);
}

/* (3) The app-declared required_claims are actually enforced against the
 * VERIFIED claim set: an empty claim response, and a claim response missing
 * one of several required claim types, must both be FATAL. */
static void test_flow_required_claims_not_satisfied_is_fatal(void) {
    flow_fixture fx;
    memset(&fx, 0, sizeof(fx));
    /* Two sub-cases share one server/fixture, neither depends on the
     * other's state: 3 connections each (fetch_domain_keys + redeem), 6
     * total — the required-claims check fires after redeem/claim
     * verification, with no further network access. */
    if (start_flow_fixture(&fx, 6) != 0) {
        T_CHECK(0, "required-claims: fixture starts");
        return;
    }

    /* (3a) "empty": the IDP returns zero claims while the login required
     * the default set (["handle"]). */
    {
        fx.srv.omit_claims = 1;
        lrp_identity identity = {0};
        lrp_pending_login pending = {0};
        T_CHECK(setup_login("Required Claims Empty App", NULL, 0, &identity, &pending) == 0,
                 "required-claims: begin_local_login succeeds (empty case)");
        lrp_verified_login verified = {0};
        lrp_error err = {0};
        int rc = run_complete(&fx, &identity, &pending, &verified, &err);
        T_CHECK(rc != 0, "required-claims: an empty verified claim set against a required claim is "
                          "FATAL");
        if (rc == 0) lrp_verified_login_free(&verified);
        lrp_pending_login_free(&pending);
        lrp_identity_free(&identity);
        fx.srv.omit_claims = 0;
    }

    /* (3b) "insufficient": the IDP returns one claim ("handle") but the
     * login required a second claim type ("email") the IDP never
     * provides. */
    {
        const char *required[] = {"handle", "email"};
        lrp_identity identity = {0};
        lrp_pending_login pending = {0};
        T_CHECK(setup_login("Required Claims Insufficient App", required, 2, &identity, &pending) == 0,
                 "required-claims: begin_local_login succeeds (insufficient case)");
        lrp_verified_login verified = {0};
        lrp_error err = {0};
        int rc = run_complete(&fx, &identity, &pending, &verified, &err);
        T_CHECK(rc != 0, "required-claims: a verified claim set missing one required claim type is "
                          "FATAL");
        if (rc == 0) lrp_verified_login_free(&verified);
        lrp_pending_login_free(&pending);
        lrp_identity_free(&identity);
    }

    stop_flow_fixture(&fx);
}

/* (4) FIX B: DomainKeys/get-revocations errors or a dropped connection must
 * fail fetch_domain_keys CLOSED — never silently proceed as though nothing
 * were revoked. */
static void test_flow_revocations_fetch_failure_fails_closed(void) {
    static const struct {
        int mode;
        const char *desc;
    } cases[] = {
        {REVOKE_MODE_SERVER_ERROR, "revocations: get-revocations server error fails closed"},
        {REVOKE_MODE_DROP_CONNECTION, "revocations: get-revocations dropped connection fails closed"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        flow_fixture fx;
        memset(&fx, 0, sizeof(fx));
        fx.srv.revocations_mode = cases[i].mode;
        /* Exactly 2 connections: get-domain-keys (succeeds) then
         * get-revocations (the failure under test). */
        if (start_flow_fixture(&fx, 2) != 0) {
            T_CHECK(0, "revocations: fetch-failure fixture starts");
            continue;
        }

        lrp_error err = {0};
        lrp_identity identity = {0};
        lrp_generate_identity_config gen_cfg;
        memset(&gen_cfg, 0, sizeof(gen_cfg));
        gen_cfg.app_name = "Revocation Fetch Failure App";
        gen_cfg.now_unix = lrp_wall_clock_now();
        lrp_generate_local_rp_identity(&gen_cfg, &identity, &err);

        lrp_domain_public_key *keys = NULL;
        size_t keys_count = 0;
        lrp_transport transport = lrp_default_transport(LRP_ADDRESS_PERMISSIVE);
        int rc = lrp_fetch_domain_keys(&transport, &fx.dns, FLOW_DOMAIN, &keys, &keys_count, &err);
        T_CHECK(rc != 0, cases[i].desc);
        lrp_domain_public_keys_array_free(keys, keys_count);

        lrp_identity_free(&identity);
        stop_flow_fixture(&fx);
    }
}

/* (5) A signing key named by a quorum-verified (>= LRP_REVOCATION_QUORUM
 * distinct valid sibling signers) revocation certificate must no longer be
 * trusted — a callback signed with it must be rejected, even though the
 * signature itself is cryptographically valid. */
static void test_flow_revoked_signing_key_is_rejected(void) {
    flow_fixture fx;
    memset(&fx, 0, sizeof(fx));
    fx.srv.revocations_mode = REVOKE_MODE_QUORUM_REVOKE_DOMAIN_KEY;
    fx.srv.sibling_keys_count = 2;
    lrp_error kerr = {0};
    for (int i = 0; i < 2; i++) {
        T_CHECK(lrp_ed25519_generate(fx.srv.sibling_priv[i], fx.srv.sibling_pub[i], &kerr) == 0,
                 "revocations: sibling signing key generates");
    }
    /* Exactly 2 connections: get-domain-keys + get-revocations. The
     * revoked-key check happens locally (payload signature verification
     * fails to find a still-trusted signing key), before redeem-claim-
     * ticket would ever be attempted. */
    if (start_flow_fixture(&fx, 2) != 0) {
        T_CHECK(0, "revocations: quorum-revoke fixture starts");
        return;
    }

    lrp_identity identity = {0};
    lrp_pending_login pending = {0};
    T_CHECK(setup_login("Revoked Key App", NULL, 0, &identity, &pending) == 0,
             "revocations: begin_local_login succeeds (quorum-revoke case)");

    lrp_verified_login verified = {0};
    lrp_error err = {0};
    int rc = run_complete(&fx, &identity, &pending, &verified, &err);
    T_CHECK(rc != 0,
             "revocations: a callback signed by a quorum-revoked signing key is FATAL");
    if (rc == 0) lrp_verified_login_free(&verified);

    lrp_pending_login_free(&pending);
    lrp_identity_free(&identity);
    stop_flow_fixture(&fx);
}

static void test_flow_happy_path(void) {
    flow_fixture fx;
    memset(&fx, 0, sizeof(fx));
    /* FIX B: fetch_domain_keys now always makes TWO calls (get-domain-keys
     * + get-revocations), not one — main flow (2+redeem=3) + nonce-mismatch
     * sub-test (2, fails before redeem) + wrong-decrypt-key sub-test (0,
     * fails before any network call) = 5 real connections; one spare slot
     * (matching this test's original pre-FIX-B buffer convention) avoids
     * this being a tight bound on future sub-tests. */
    if (start_flow_fixture(&fx, 6) != 0) {
        T_CHECK(0, "flow: fixture starts");
        return;
    }

    lrp_error err = {0};
    lrp_identity identity = {0};
    lrp_generate_identity_config gen_cfg;
    memset(&gen_cfg, 0, sizeof(gen_cfg));
    gen_cfg.app_name = "Flow Test App";
    gen_cfg.now_unix = lrp_wall_clock_now();
    T_CHECK(lrp_generate_local_rp_identity(&gen_cfg, &identity, &err) == 0,
             "flow: generate_local_rp_identity succeeds");

    lrp_login_redirect redirect = {0};
    lrp_pending_login pending = {0};
    lrp_begin_login_config begin_cfg;
    memset(&begin_cfg, 0, sizeof(begin_cfg));
    begin_cfg.identity = &identity;
    begin_cfg.callback_url = "http://127.0.0.1:9999/callback";
    begin_cfg.user_domain = FLOW_DOMAIN;
    begin_cfg.now_unix = lrp_wall_clock_now();
    T_CHECK(lrp_begin_local_login(&begin_cfg, &redirect, &pending, &err) == 0,
             "flow: begin_local_login succeeds");
    T_CHECK(strstr(redirect.redirect_url.data, "https://" FLOW_DOMAIN "/auth/local-rp?signed_request=") ==
                 redirect.redirect_url.data,
             "flow: redirect URL has the expected shape");

    char *token = NULL, *arrived_url = NULL;
    T_CHECK(build_idp_callback(&identity, &pending, FLOW_DOMAIN, identity.fingerprint,
                                fx.srv.domain_priv, LRP_SUITE_AES_256_GCM, &token,
                                &arrived_url) == 0,
             "flow: fake IDP builds a callback");

    lrp_transport transport = lrp_default_transport(LRP_ADDRESS_PERMISSIVE);
    lrp_verified_login verified = {0};
    lrp_complete_login_config complete_cfg;
    memset(&complete_cfg, 0, sizeof(complete_cfg));
    complete_cfg.identity = &identity;
    complete_cfg.pending = &pending;
    complete_cfg.encrypted_token = token;
    complete_cfg.arrived_url = arrived_url;
    complete_cfg.now_unix = lrp_wall_clock_now();
    complete_cfg.transport = &transport;
    complete_cfg.dns = &fx.dns;

    lrp_error cerr = {0};
    int rc = lrp_complete_local_login(&complete_cfg, &verified, &cerr);
    T_CHECK(rc == 0, "flow: complete_local_login succeeds end to end");
    if (rc == 0) {
        T_CHECK(strcmp(verified.user_id.data, FLOW_USER_ID) == 0, "flow: verified user_id matches");
        T_CHECK(strcmp(verified.user_domain.data, FLOW_DOMAIN) == 0,
                 "flow: verified user_domain matches");
        T_CHECK(verified.claims_count == 1, "flow: exactly one verified claim returned");
        if (verified.claims_count == 1) {
            T_CHECK(strcmp(verified.claims[0].claim_type.data, "handle") == 0,
                     "flow: verified claim type matches");
            T_CHECK(memcmp(verified.claims[0].claim_value.data, "flowtestuser", 12) == 0,
                     "flow: verified claim value matches");
        }
        T_CHECK(strcmp(verified.local_rp_fingerprint, identity.fingerprint) == 0,
                 "flow: verified local_rp_fingerprint matches identity");
        lrp_verified_login_free(&verified);
    } else {
        fprintf(stderr, "  (complete_local_login error: %s)\n", cerr.message);
    }

    /* -- Failure mode: nonce/state mismatch. -- */
    {
        char *token2 = NULL, *arrived2 = NULL;
        build_idp_callback(&identity, &pending, FLOW_DOMAIN, identity.fingerprint, fx.srv.domain_priv,
                            LRP_SUITE_AES_256_GCM, &token2, &arrived2);
        lrp_pending_login corrupted = pending;
        uint8_t bad_nonce[32];
        memcpy(bad_nonce, pending.nonce.data, 32);
        bad_nonce[0] ^= 0xff;
        corrupted.nonce.data = bad_nonce;
        lrp_verified_login v2 = {0};
        lrp_complete_login_config cfg2 = complete_cfg;
        cfg2.pending = &corrupted;
        cfg2.encrypted_token = token2;
        cfg2.arrived_url = arrived2;
        lrp_error err2 = {0};
        int rc2 = lrp_complete_local_login(&cfg2, &v2, &err2);
        T_CHECK(rc2 != 0, "flow: nonce mismatch is rejected");
        if (rc2 == 0) lrp_verified_login_free(&v2);
        free(token2);
        free(arrived2);
    }

    /* -- Failure mode: wrong decryption key (a different identity). -- */
    {
        lrp_identity other_identity = {0};
        lrp_generate_identity_config other_cfg = gen_cfg;
        other_cfg.app_name = "Other App";
        lrp_generate_local_rp_identity(&other_cfg, &other_identity, &err);

        char *token3 = NULL, *arrived3 = NULL;
        build_idp_callback(&identity, &pending, FLOW_DOMAIN, identity.fingerprint, fx.srv.domain_priv,
                            LRP_SUITE_AES_256_GCM, &token3, &arrived3);
        lrp_verified_login v3 = {0};
        lrp_complete_login_config cfg3 = complete_cfg;
        cfg3.identity = &other_identity; /* wrong encryption key */
        cfg3.encrypted_token = token3;
        cfg3.arrived_url = arrived3;
        lrp_error err3 = {0};
        int rc3 = lrp_complete_local_login(&cfg3, &v3, &err3);
        T_CHECK(rc3 != 0, "flow: wrong local RP identity (decrypt key) is rejected");
        if (rc3 == 0) lrp_verified_login_free(&v3);
        free(token3);
        free(arrived3);
        lrp_identity_free(&other_identity);
    }

    free(token);
    free(arrived_url);
    lrp_login_redirect_free(&redirect);
    lrp_pending_login_free(&pending);
    lrp_identity_free(&identity);
    stop_flow_fixture(&fx);
}

static void test_flow_dns_pin_mismatch(void) {
    flow_fixture fx;
    memset(&fx, 0, sizeof(fx));
    if (start_flow_fixture(&fx, 1) != 0) {
        T_CHECK(0, "flow: pin-mismatch fixture starts");
        return;
    }
    /* Corrupt the published fp= value so it no longer matches the server's
     * real TLS certificate fingerprint. */
    snprintf(fx.dns_ctx.domain_txt, sizeof(fx.dns_ctx.domain_txt),
             "v=lk1 fp=%064d", 0);

    lrp_error err = {0};
    lrp_identity identity = {0};
    lrp_generate_identity_config gen_cfg;
    memset(&gen_cfg, 0, sizeof(gen_cfg));
    gen_cfg.app_name = "Pin Test App";
    gen_cfg.now_unix = lrp_wall_clock_now();
    lrp_generate_local_rp_identity(&gen_cfg, &identity, &err);

    lrp_domain_public_key *keys = NULL;
    size_t keys_count = 0;
    lrp_transport transport = lrp_default_transport(LRP_ADDRESS_PERMISSIVE);
    int rc = lrp_fetch_domain_keys(&transport, &fx.dns, FLOW_DOMAIN, &keys, &keys_count, &err);
    T_CHECK(rc != 0, "flow: DNS fp= pin mismatch causes fetch_domain_keys to fail closed");
    lrp_domain_public_keys_array_free(keys, keys_count);

    lrp_identity_free(&identity);
    stop_flow_fixture(&fx);
}

static void test_begin_rejects_non_http_scheme(void) {
    lrp_error err = {0};
    lrp_identity identity = {0};
    lrp_generate_identity_config gen_cfg;
    memset(&gen_cfg, 0, sizeof(gen_cfg));
    gen_cfg.app_name = "Scheme Test App";
    gen_cfg.now_unix = lrp_wall_clock_now();
    T_CHECK(lrp_generate_local_rp_identity(&gen_cfg, &identity, &err) == 0,
             "scheme: generate_local_rp_identity succeeds");

    lrp_login_redirect redirect = {0};
    lrp_pending_login pending = {0};
    lrp_begin_login_config begin_cfg;
    memset(&begin_cfg, 0, sizeof(begin_cfg));
    begin_cfg.identity = &identity;
    begin_cfg.callback_url = "myapp://callback";
    begin_cfg.user_domain = "example.com";
    begin_cfg.now_unix = lrp_wall_clock_now();
    lrp_error berr = {0};
    int rc = lrp_begin_local_login(&begin_cfg, &redirect, &pending, &berr);
    T_CHECK(rc != 0 && berr.code == LRP_ERR_INVALID_INPUT,
             "scheme: begin_local_login rejects a non-http(s) callback URL");

    lrp_login_redirect_free(&redirect);
    lrp_pending_login_free(&pending);
    lrp_identity_free(&identity);
}

int run_flow_tests(void) {
    test_begin_rejects_non_http_scheme();
    test_flow_happy_path();
    test_flow_dns_pin_mismatch();
    test_flow_redemption_identity_mismatch_is_fatal();
    test_flow_claim_user_id_mismatch_is_fatal();
    test_flow_required_claims_not_satisfied_is_fatal();
    test_flow_revocations_fetch_failure_fails_closed();
    test_flow_revoked_signing_key_is_rejected();
    return 0;
}
