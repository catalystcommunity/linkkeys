#include "rpc.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "cbor.h"
#include "crypto.h"
#include "error.h"
#include "local_rp.h"
#include "revocation.h"
#include "time_util.h"

void lrp_domain_endpoint_free(lrp_domain_endpoint *e) {
    if (e == NULL) return;
    for (size_t i = 0; i < e->fingerprints_count; i++) free(e->fingerprints[i]);
    free(e->fingerprints);
    e->fingerprints = NULL;
    e->fingerprints_count = 0;
    free(e->tcp_addr);
    e->tcp_addr = NULL;
}

int lrp_discover_domain_endpoint(lrp_dns_resolver *dns, const char *domain,
                                  lrp_domain_endpoint *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));

    lrp_str anchor_name = {0};
    if (lrp_linkkeys_dns_name(domain, &anchor_name, err) != 0) return -1;
    lrp_txt_records anchor_txts = {0};
    int rc = dns->txt_lookup(dns, anchor_name.data, &anchor_txts, err);
    lrp_str_free(&anchor_name);
    if (rc != 0) return -1;

    char **fps = NULL;
    size_t fps_n = 0;
    for (size_t i = 0; i < anchor_txts.count && fps_n == 0; i++) {
        lrp_linkkeys_record rec;
        if (lrp_parse_linkkeys_txt(anchor_txts.entries[i], &rec) == LRP_DNS_ERR_NONE &&
            rec.fingerprints_count > 0) {
            fps = rec.fingerprints;
            fps_n = rec.fingerprints_count;
        } else {
            lrp_linkkeys_record_free(&rec);
        }
    }
    lrp_txt_records_free(&anchor_txts);
    if (fps_n == 0) {
        return lrp_fail(err, LRP_ERR_DNS, "no usable _linkkeys.%s TXT record with fp= entries",
                         domain);
    }

    lrp_str apis_name = {0};
    if (lrp_linkkeys_apis_dns_name(domain, &apis_name, err) != 0) {
        for (size_t i = 0; i < fps_n; i++) free(fps[i]);
        free(fps);
        return -1;
    }
    lrp_txt_records apis_txts = {0};
    rc = dns->txt_lookup(dns, apis_name.data, &apis_txts, err);
    lrp_str_free(&apis_name);
    if (rc != 0) {
        for (size_t i = 0; i < fps_n; i++) free(fps[i]);
        free(fps);
        return -1;
    }

    char *tcp_addr = NULL;
    for (size_t i = 0; i < apis_txts.count && tcp_addr == NULL; i++) {
        lrp_linkkeys_apis apis;
        if (lrp_parse_linkkeys_apis_txt(apis_txts.entries[i], &apis) == LRP_DNS_ERR_NONE &&
            apis.tcp.data != NULL) {
            tcp_addr = apis.tcp.data;
            apis.tcp.data = NULL;
        }
        lrp_linkkeys_apis_free(&apis);
    }
    lrp_txt_records_free(&apis_txts);
    if (tcp_addr == NULL) {
        for (size_t i = 0; i < fps_n; i++) free(fps[i]);
        free(fps);
        return lrp_fail(err, LRP_ERR_DNS, "no usable _linkkeys_apis.%s TXT record with tcp= entry",
                         domain);
    }

    out->fingerprints = fps;
    out->fingerprints_count = fps_n;
    out->tcp_addr = tcp_addr;
    return 0;
}

/* --------------------------------------------------------------------- */
/* lrp_conn -> OpenSSL BIO adapter                                       */
/* --------------------------------------------------------------------- */

static int bio_conn_write(BIO *b, const char *buf, int len) {
    lrp_conn *conn = (lrp_conn *)BIO_get_data(b);
    long n = conn->write(conn, (const uint8_t *)buf, (size_t)len);
    BIO_clear_retry_flags(b);
    if (n <= 0) {
        BIO_set_retry_write(b);
        return -1;
    }
    return (int)n;
}

static int bio_conn_read(BIO *b, char *buf, int len) {
    lrp_conn *conn = (lrp_conn *)BIO_get_data(b);
    long n = conn->read(conn, (uint8_t *)buf, (size_t)len);
    BIO_clear_retry_flags(b);
    if (n < 0) {
        BIO_set_retry_read(b);
        return -1;
    }
    return (int)n; /* 0 == clean EOF */
}

static long bio_conn_ctrl(BIO *b, int cmd, long num, void *ptr) {
    (void)b;
    (void)num;
    (void)ptr;
    if (cmd == BIO_CTRL_FLUSH) return 1;
    return 0;
}

static int bio_conn_create(BIO *b) {
    BIO_set_init(b, 1);
    return 1;
}

static int bio_conn_destroy(BIO *b) {
    if (b == NULL) return 0;
    BIO_set_data(b, NULL);
    BIO_set_init(b, 0);
    return 1;
}

static BIO_METHOD *g_bio_conn_method = NULL;
static pthread_once_t g_bio_conn_method_once = PTHREAD_ONCE_INIT;

static void init_bio_conn_method(void) {
    g_bio_conn_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "lrp_conn");
    BIO_meth_set_write(g_bio_conn_method, bio_conn_write);
    BIO_meth_set_read(g_bio_conn_method, bio_conn_read);
    BIO_meth_set_ctrl(g_bio_conn_method, bio_conn_ctrl);
    BIO_meth_set_create(g_bio_conn_method, bio_conn_create);
    BIO_meth_set_destroy(g_bio_conn_method, bio_conn_destroy);
}

/* Thread-safe lazy init (pthread_once) — this is called from
 * lrp_rpc_call, which the app may invoke concurrently from multiple
 * threads on distinct connections (see README's "Thread safety"). */
static BIO_METHOD *bio_conn_method(void) {
    pthread_once(&g_bio_conn_method_once, init_bio_conn_method);
    return g_bio_conn_method;
}

/* --------------------------------------------------------------------- */
/* TLS connect + DNS fp= pin verification                                */
/* --------------------------------------------------------------------- */

static int cert_fingerprint(X509 *cert, char out_fp[LRP_FINGERPRINT_HEX_LEN + 1], lrp_error *err) {
    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    if (pkey == NULL || EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        return lrp_fail(err, LRP_ERR_TLS, "peer certificate is not an Ed25519 key");
    }
    uint8_t raw[32];
    size_t raw_len = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(pkey, raw, &raw_len) != 1 || raw_len != 32) {
        return lrp_fail(err, LRP_ERR_TLS, "failed to extract Ed25519 SPKI bytes");
    }
    lrp_fingerprint_hex(raw, 32, out_fp);
    return 0;
}

typedef struct lrp_tls_conn {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    lrp_conn raw; /* the dialed transport connection; closed on lrp_tls_close */
} lrp_tls_conn;

static void lrp_tls_close(lrp_tls_conn *t) {
    if (t == NULL) return;
    if (t->ssl != NULL) {
        SSL_shutdown(t->ssl);
        SSL_free(t->ssl); /* also frees the attached BIO */
    }
    if (t->ssl_ctx != NULL) SSL_CTX_free(t->ssl_ctx);
    if (t->raw.close != NULL) t->raw.close(&t->raw);
}

/* Dial `endpoint.tcp_addr` via `transport`, complete a TLS handshake with
 * WebPKI chain validation disabled (SSL_VERIFY_NONE — the pin IS the trust
 * anchor here, not a CA chain), then MANDATORILY verify the peer
 * certificate's Ed25519 SPKI fingerprint is a member of
 * `endpoint->fingerprints`. */
static int tls_connect_pinned(lrp_transport *transport, const lrp_domain_endpoint *endpoint,
                               lrp_tls_conn *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (transport->dial(transport, endpoint->tcp_addr, &out->raw, err) != 0) return -1;

    out->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (out->ssl_ctx == NULL) {
        lrp_fail(err, LRP_ERR_TLS, "SSL_CTX_new failed");
        goto fail;
    }
    SSL_CTX_set_min_proto_version(out->ssl_ctx, TLS1_2_VERSION);
    /* WebPKI validity is not the anchor; the manual pin check below is. */
    SSL_CTX_set_verify(out->ssl_ctx, SSL_VERIFY_NONE, NULL);

    out->ssl = SSL_new(out->ssl_ctx);
    if (out->ssl == NULL) {
        lrp_fail(err, LRP_ERR_TLS, "SSL_new failed");
        goto fail;
    }
    BIO *bio = BIO_new(bio_conn_method());
    if (bio == NULL) {
        lrp_fail(err, LRP_ERR_TLS, "BIO_new failed");
        goto fail;
    }
    BIO_set_data(bio, &out->raw);
    SSL_set_bio(out->ssl, bio, bio); /* SSL now owns `bio` (one reference for both r/w) */

    if (SSL_connect(out->ssl) != 1) {
        lrp_fail(err, LRP_ERR_TLS, "TLS handshake failed");
        goto fail;
    }

    X509 *cert = SSL_get1_peer_certificate(out->ssl);
    if (cert == NULL) {
        lrp_fail(err, LRP_ERR_TLS, "no peer certificate presented");
        goto fail;
    }
    char fp[LRP_FINGERPRINT_HEX_LEN + 1];
    int frc = cert_fingerprint(cert, fp, err);
    X509_free(cert);
    if (frc != 0) goto fail;

    int matched = 0;
    for (size_t i = 0; i < endpoint->fingerprints_count; i++) {
        if (strcasecmp(fp, endpoint->fingerprints[i]) == 0) {
            matched = 1;
            break;
        }
    }
    if (!matched) {
        lrp_fail(err, LRP_ERR_TLS,
                 "certificate fingerprint does not match any pinned fingerprint for this domain");
        goto fail;
    }
    return 0;

fail:
    lrp_tls_close(out);
    memset(out, 0, sizeof(*out));
    return -1;
}

/* --------------------------------------------------------------------- */
/* Frame I/O + CSIL-RPC envelope                                         */
/* --------------------------------------------------------------------- */

static int ssl_write_all(SSL *ssl, const uint8_t *data, size_t len, lrp_error *err) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_write(ssl, data + off, (int)(len - off));
        if (n <= 0) return lrp_fail(err, LRP_ERR_TRANSPORT, "TLS write failed");
        off += (size_t)n;
    }
    return 0;
}

static int ssl_read_all(SSL *ssl, uint8_t *data, size_t len, lrp_error *err) {
    size_t off = 0;
    while (off < len) {
        int n = SSL_read(ssl, data + off, (int)(len - off));
        if (n <= 0) return lrp_fail(err, LRP_ERR_TRANSPORT, "TLS read failed or connection closed");
        off += (size_t)n;
    }
    return 0;
}

static int send_frame(SSL *ssl, const uint8_t *data, size_t len, lrp_error *err) {
    uint8_t lenbuf[4] = {(uint8_t)(len >> 24), (uint8_t)(len >> 16), (uint8_t)(len >> 8),
                          (uint8_t)len};
    if (ssl_write_all(ssl, lenbuf, 4, err) != 0) return -1;
    if (len == 0) return 0;
    return ssl_write_all(ssl, data, len, err);
}

static int read_frame(SSL *ssl, lrp_bytes *out, lrp_error *err) {
    uint8_t lenbuf[4];
    if (ssl_read_all(ssl, lenbuf, 4, err) != 0) return -1;
    uint32_t len =
        ((uint32_t)lenbuf[0] << 24) | ((uint32_t)lenbuf[1] << 16) | ((uint32_t)lenbuf[2] << 8) | lenbuf[3];
    if (len > LRP_MAX_RPC_FRAME_SIZE) {
        return lrp_fail(err, LRP_ERR_PROTOCOL, "peer frame too large (%u bytes, max %d)", len,
                         LRP_MAX_RPC_FRAME_SIZE);
    }
    uint8_t *buf = (uint8_t *)malloc(len > 0 ? len : 1);
    if (buf == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    if (len > 0 && ssl_read_all(ssl, buf, len, err) != 0) {
        free(buf);
        return -1;
    }
    out->data = buf;
    out->len = len;
    return 0;
}

static int encode_rpc_request(const char *service, const char *op, const uint8_t *payload,
                               size_t payload_len, lrp_bytes *out, lrp_error *err) {
    cbor_buf vbuf, sbuf, obuf, pbuf, outbuf;
    cbor_buf_init(&vbuf);
    cbor_buf_init(&sbuf);
    cbor_buf_init(&obuf);
    cbor_buf_init(&pbuf);
    cbor_buf_init(&outbuf);
    int rc = 0;
    rc |= cbor_write_uint(&vbuf, 1);
    rc |= cbor_write_text_cstr(&sbuf, service);
    rc |= cbor_write_text_cstr(&obuf, op);
    rc |= cbor_write_tag24(&pbuf, payload, payload_len);
    cbor_map_entry entries[4] = {
        {"v", vbuf.data, vbuf.len},
        {"service", sbuf.data, sbuf.len},
        {"op", obuf.data, obuf.len},
        {"payload", pbuf.data, pbuf.len},
    };
    if (rc == 0) rc = cbor_write_canon_map(&outbuf, entries, 4);
    cbor_buf_free(&vbuf);
    cbor_buf_free(&sbuf);
    cbor_buf_free(&obuf);
    cbor_buf_free(&pbuf);
    if (rc != 0) {
        cbor_buf_free(&outbuf);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode RPC request: out of memory");
    }
    *out = cbor_buf_release(&outbuf);
    return 0;
}

typedef struct {
    int64_t status;
    lrp_str variant;
    lrp_str error_msg;
    lrp_bytes payload;
} rpc_response;

static void rpc_response_free(rpc_response *r) {
    lrp_str_free(&r->variant);
    lrp_str_free(&r->error_msg);
    lrp_bytes_free(&r->payload);
}

static int decode_rpc_response(const uint8_t *data, size_t len, rpc_response *out, lrp_error *err) {
    memset(out, 0, sizeof(*out));
    cbor_value *root = NULL;
    if (cbor_decode(data, len, &root, err) != 0) return -1;
    int rc = -1;
    uint64_t v = 0, status = 0;
    if (cbor_get_uint(root, "v", &v, err) != 0) goto done;
    if (v != 1) {
        lrp_fail(err, LRP_ERR_PROTOCOL, "unsupported CSIL-RPC transport version %llu",
                 (unsigned long long)v);
        goto done;
    }
    if (cbor_get_uint(root, "status", &status, err) != 0) goto done;
    out->status = (int64_t)status;
    cbor_get_text_opt(root, "variant", &out->variant);
    cbor_get_text_opt(root, "error", &out->error_msg);
    {
        const cbor_value *pv = cbor_map_get(root, "payload");
        if (pv != NULL && pv->type == CBOR_T_TAG && pv->tag == 24 && pv->tag_inner != NULL &&
            pv->tag_inner->type == CBOR_T_BYTES) {
            if (cbor_as_bytes(pv->tag_inner, &out->payload, err) != 0) goto done;
        }
    }
    rc = 0;
done:
    cbor_value_free(root);
    free(root);
    if (rc != 0) {
        rpc_response_free(out);
        memset(out, 0, sizeof(*out));
    }
    return rc;
}

int lrp_rpc_call(lrp_transport *transport, const lrp_domain_endpoint *endpoint, const char *service,
                  const char *op, const uint8_t *payload, size_t payload_len, lrp_bytes *out_payload,
                  lrp_error *err) {
    lrp_tls_conn conn;
    if (tls_connect_pinned(transport, endpoint, &conn, err) != 0) return -1;

    lrp_bytes req = {0};
    int rc = encode_rpc_request(service, op, payload, payload_len, &req, err);
    if (rc == 0) rc = send_frame(conn.ssl, req.data, req.len, err);
    lrp_bytes_free(&req);
    if (rc != 0) {
        lrp_tls_close(&conn);
        return -1;
    }

    lrp_bytes resp_bytes = {0};
    if (read_frame(conn.ssl, &resp_bytes, err) != 0) {
        lrp_tls_close(&conn);
        return -1;
    }
    lrp_tls_close(&conn);

    rpc_response resp;
    rc = decode_rpc_response(resp_bytes.data, resp_bytes.len, &resp, err);
    lrp_bytes_free(&resp_bytes);
    if (rc != 0) return -1;

    if (resp.status != 0) {
        if (err != NULL) {
            err->code = LRP_ERR_SERVER;
            snprintf(err->message, sizeof(err->message), "server error (%lld): %s",
                     (long long)resp.status,
                     resp.error_msg.data != NULL ? resp.error_msg.data : "unknown error");
        }
        rpc_response_free(&resp);
        return -1;
    }

    *out_payload = resp.payload;
    resp.payload.data = NULL;
    resp.payload.len = 0;
    rpc_response_free(&resp);
    return 0;
}

/* --------------------------------------------------------------------- */
/* High-level operations                                                 */
/* --------------------------------------------------------------------- */

int lrp_fetch_domain_keys(lrp_transport *transport, lrp_dns_resolver *dns, const char *domain,
                           lrp_domain_public_key **out_keys, size_t *out_count, lrp_error *err) {
    *out_keys = NULL;
    *out_count = 0;

    lrp_domain_endpoint endpoint = {0};
    if (lrp_discover_domain_endpoint(dns, domain, &endpoint, err) != 0) return -1;

    lrp_bytes req = {0};
    if (lrp_encode_empty_request(&req, err) != 0) {
        lrp_domain_endpoint_free(&endpoint);
        return -1;
    }
    lrp_bytes resp_bytes = {0};
    int rc = lrp_rpc_call(transport, &endpoint, "DomainKeys", "get-domain-keys", req.data, req.len,
                           &resp_bytes, err);
    lrp_bytes_free(&req);
    if (rc != 0) {
        lrp_domain_endpoint_free(&endpoint);
        return -1;
    }

    lrp_w_get_domain_keys_response resp = {0};
    rc = lrp_decode_get_domain_keys_response(resp_bytes.data, resp_bytes.len, &resp, err);
    lrp_bytes_free(&resp_bytes);
    if (rc != 0) {
        lrp_domain_endpoint_free(&endpoint);
        return -1;
    }

    lrp_domain_public_key *trusted = NULL;
    size_t trusted_count = 0;
    const char *const *pinned = (const char *const *)endpoint.fingerprints;
    rc = lrp_trust_keys(resp.keys, resp.keys_count, pinned, endpoint.fingerprints_count, &trusted,
                         &trusted_count, err);
    lrp_w_get_domain_keys_response_free(&resp);
    if (rc != 0) {
        lrp_domain_endpoint_free(&endpoint);
        return -1;
    }
    if (trusted_count == 0) {
        lrp_domain_endpoint_free(&endpoint);
        return lrp_fail(err, LRP_ERR_NO_TRUSTED_KEYS,
                         "no trusted public keys could be established for domain: %s", domain);
    }

    /* SEC fix (fail-open -> fail-closed): ALWAYS fetch get-revocations for
     * this domain, regardless of recent_revocations_available/_present —
     * that flag is merely a server-side optimization hint, never a trust
     * decision this client may rely on. A compromised/malicious IDP could
     * otherwise simply omit or clear the flag to suppress delivery of a
     * revocation targeting one of its own keys, silently defeating
     * revocation entirely. A get-revocations fetch or decode failure is
     * therefore FATAL (fails the whole call) — revocation delivery is
     * exactly the mechanism that lets a verifier learn a key it would
     * otherwise trust has been compromised, so proceeding without it on
     * error would defeat the purpose of checking at all. An empty *list* is
     * a legitimate, successful "nothing revoked" answer; a failure to even
     * ask is not. */
    {
        char since[32];
        lrp_format_rfc3339(lrp_wall_clock_now() - (int64_t)30 * 86400, since);
        lrp_bytes rreq = {0};
        if (lrp_encode_get_revocations_request(since, &rreq, err) != 0) {
            lrp_domain_endpoint_free(&endpoint);
            lrp_domain_public_keys_array_free(trusted, trusted_count);
            return -1;
        }
        lrp_bytes rresp_bytes = {0};
        int rrc = lrp_rpc_call(transport, &endpoint, "DomainKeys", "get-revocations", rreq.data,
                                rreq.len, &rresp_bytes, err);
        lrp_bytes_free(&rreq);
        if (rrc != 0) {
            lrp_domain_endpoint_free(&endpoint);
            lrp_domain_public_keys_array_free(trusted, trusted_count);
            return -1;
        }
        lrp_w_get_revocations_response revs = {0};
        rrc = lrp_decode_get_revocations_response(rresp_bytes.data, rresp_bytes.len, &revs, err);
        lrp_bytes_free(&rresp_bytes);
        if (rrc != 0) {
            lrp_domain_endpoint_free(&endpoint);
            lrp_domain_public_keys_array_free(trusted, trusted_count);
            return -1;
        }
        for (size_t i = 0; i < revs.count; i++) {
            lrp_error verify_ignore = {0};
            if (lrp_verify_revocation_certificate(&revs.items[i], trusted, trusted_count, domain,
                                                   &verify_ignore) == 0) {
                /* Drop the targeted key in place (compaction). */
                size_t w = 0;
                for (size_t r = 0; r < trusted_count; r++) {
                    if (strcmp(trusted[r].key_id.data, revs.items[i].target_key_id.data) == 0) {
                        lrp_domain_public_key_free_fields(&trusted[r]);
                        continue;
                    }
                    if (w != r) trusted[w] = trusted[r];
                    w++;
                }
                trusted_count = w;
            }
        }
        lrp_w_get_revocations_response_free(&revs);
    }

    lrp_domain_endpoint_free(&endpoint);
    if (trusted_count == 0) {
        free(trusted);
        return lrp_fail(err, LRP_ERR_NO_TRUSTED_KEYS,
                         "no trusted public keys could be established for domain: %s", domain);
    }
    *out_keys = trusted;
    *out_count = trusted_count;
    return 0;
}

int lrp_redeem_claim_ticket(lrp_transport *transport, lrp_dns_resolver *dns, const char *domain,
                             const uint8_t *signed_request, size_t signed_request_len,
                             lrp_w_ticket_redemption_response *out, lrp_error *err) {
    lrp_domain_endpoint endpoint = {0};
    if (lrp_discover_domain_endpoint(dns, domain, &endpoint, err) != 0) return -1;

    lrp_bytes resp_bytes = {0};
    int rc = lrp_rpc_call(transport, &endpoint, "LocalRp", "redeem-claim-ticket", signed_request,
                           signed_request_len, &resp_bytes, err);
    lrp_domain_endpoint_free(&endpoint);
    if (rc != 0) return -1;

    rc = lrp_decode_ticket_redemption_response(resp_bytes.data, resp_bytes.len, out, err);
    lrp_bytes_free(&resp_bytes);
    return rc;
}
