/* Conformance vector runner: consumes every file under
 * sdks/local-rp/conformance/ (the shared cross-language test suite) and
 * exercises this SDK's implementation against every case, positive AND
 * negative — see conformance/README.md. Run from sdks/local-rp/c/ (paths
 * are relative to that directory: `../conformance/ (*.json)`). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "cbor.h"
#include "claims.h"
#include "crypto.h"
#include "dns.h"
#include "encoding.h"
#include "error.h"
#include "json.h"
#include "local_rp.h"
#include "revocation.h"
#include "test_util.h"
#include "time_util.h"
#include "types.h"

#define CONFORMANCE_DIR "../conformance/"

static json_value *load(const char *name) {
    char path[512];
    snprintf(path, sizeof(path), CONFORMANCE_DIR "%s", name);
    json_value *v = json_parse_file(path);
    if (v == NULL) {
        fprintf(stderr, "could not load conformance fixture: %s\n", path);
        exit(2);
    }
    return v;
}

/* ======================================================================= */
/* keys.json                                                               */
/* ======================================================================= */

static void test_keys(void) {
    json_value *doc = load("keys.json");
    const json_value *lrp_signing = json_get(json_get(doc, "local_rp"), "signing");
    lrp_bytes pub = t_hex_field(lrp_signing, "public_key_hex");
    const char *expected_fp = json_str(json_get(lrp_signing, "fingerprint_hex"));
    char fp[LRP_FINGERPRINT_HEX_LEN + 1];
    lrp_fingerprint_hex(pub.data, pub.len, fp);
    T_CHECK(strcmp(fp, expected_fp) == 0, "keys: local_rp.signing fingerprint matches crypto::fingerprint");
    lrp_bytes_free(&pub);

    const json_value *domain_signing = json_get(doc, "domain_signing_key");
    lrp_bytes dpub = t_hex_field(domain_signing, "public_key_hex");
    const char *expected_dfp = json_str(json_get(domain_signing, "fingerprint_hex"));
    char dfp[LRP_FINGERPRINT_HEX_LEN + 1];
    lrp_fingerprint_hex(dpub.data, dpub.len, dfp);
    T_CHECK(strcmp(dfp, expected_dfp) == 0, "keys: domain_signing_key fingerprint matches");
    lrp_bytes_free(&dpub);

    json_free(doc);
}

/* ======================================================================= */
/* envelopes.json                                                          */
/* ======================================================================= */

static void run_envelope_case(const json_value *c, int default_expected_valid) {
    const char *context = json_str(json_get(c, "context"));
    lrp_bytes payload = t_hex_field(c, "payload_cbor_hex");
    lrp_bytes expected_sig_input = t_hex_field(c, "signature_input_cbor_hex");
    lrp_bytes signature = t_hex_field(c, "signature_hex");
    lrp_bytes verify_key = t_hex_field(c, "verify_key_hex");
    const json_value *ev = json_get(c, "expected_valid");
    int expected_valid = ev != NULL ? json_bool(ev) : default_expected_valid;

    lrp_bytes recomputed = {0};
    lrp_error err = {0};
    int rc = lrp_envelope_signature_input(context, payload.data, payload.len, &recomputed, &err);
    T_CHECK(rc == 0, "envelope: signature input construction succeeds");
    T_CHECK(recomputed.len == expected_sig_input.len &&
                 memcmp(recomputed.data, expected_sig_input.data, recomputed.len) == 0,
             "envelope: recomputed signature input matches vector");

    lrp_error verr = {0};
    int vrc = lrp_ed25519_verify(verify_key.data, recomputed.data, recomputed.len, signature.data,
                                  signature.len, &verr);
    T_CHECK((vrc == 0) == expected_valid, "envelope: verify outcome matches expected_valid");

    lrp_bytes_free(&payload);
    lrp_bytes_free(&expected_sig_input);
    lrp_bytes_free(&signature);
    lrp_bytes_free(&verify_key);
    lrp_bytes_free(&recomputed);
}

static void test_envelopes(void) {
    json_value *doc = load("envelopes.json");
    const json_value *cases = json_get(doc, "cases");
    for (size_t i = 0; i < json_len(cases); i++) run_envelope_case(json_at(cases, i), 1);
    const json_value *neg = json_get(doc, "negative_cases");
    for (size_t i = 0; i < json_len(neg); i++) run_envelope_case(json_at(neg, i), 0);
    T_CHECK(json_len(cases) == 4, "envelopes: 4 positive structure cases present");
    T_CHECK(json_len(neg) == 20, "envelopes: 20 negative cases present (4 structures x 5)");
    json_free(doc);
}

/* ======================================================================= */
/* callback_box.json                                                       */
/* ======================================================================= */

static char **strings_from_json_array(const json_value *arr, size_t *out_count) {
    size_t n = json_len(arr);
    char **out = (char **)calloc(n > 0 ? n : 1, sizeof(char *));
    for (size_t i = 0; i < n; i++) out[i] = strdup(json_str(json_at(arr, i)));
    *out_count = n;
    return out;
}

static void free_strings(char **arr, size_t n) {
    for (size_t i = 0; i < n; i++) free(arr[i]);
    free(arr);
}

static void run_callback_box_positive(const json_value *c) {
    const char *suite_str = json_str(json_get(c, "suite"));
    uint8_t ephemeral_priv[32], ephemeral_pub[32], aead_nonce[12], recipient_pub[32],
        decrypt_priv[32];
    t_hex_field_fixed(c, "ephemeral_private_key_hex", ephemeral_priv, 32);
    t_hex_field_fixed(c, "ephemeral_public_key_hex", ephemeral_pub, 32);
    t_hex_field_fixed(c, "aead_nonce_hex", aead_nonce, 12);
    t_hex_field_fixed(c, "recipient_public_key_hex", recipient_pub, 32);
    t_hex_field_fixed(c, "decrypt_private_key_hex", decrypt_priv, 32);
    lrp_bytes header = t_hex_field(c, "header_cbor_hex");
    lrp_bytes kdf_context = t_hex_field(c, "kdf_context_hex");
    lrp_bytes aad = t_hex_field(c, "aad_hex");
    lrp_bytes plaintext = t_hex_field(c, "plaintext_cbor_hex");
    lrp_bytes ciphertext = t_hex_field(c, "ciphertext_hex");
    size_t allowed_count;
    char **allowed = strings_from_json_array(json_get(c, "allowed_suites"), &allowed_count);

    lrp_aead_suite suite;
    T_CHECK(lrp_aead_suite_parse(suite_str, &suite) == 0, "callback_box: suite id parses");

    /* Low-level KDF/AAD check against the fixture's own published bytes. */
    uint8_t shared_secret[32];
    lrp_error err = {0};
    T_CHECK(lrp_x25519_ecdh(decrypt_priv, ephemeral_pub, shared_secret, &err) == 0,
             "callback_box: ECDH succeeds");
    uint8_t key[32];
    lrp_bytes ctx = {0};
    T_CHECK(lrp_local_rp_callback_kdf(suite, ephemeral_pub, recipient_pub, shared_secret, 32, key,
                                        &ctx, &err) == 0,
             "callback_box: KDF succeeds");
    T_CHECK(ctx.len == kdf_context.len && memcmp(ctx.data, kdf_context.data, ctx.len) == 0,
             "callback_box: KDF context matches kdf_context_hex");

    uint8_t *aad_recomputed = (uint8_t *)malloc(ctx.len + header.len);
    memcpy(aad_recomputed, ctx.data, ctx.len);
    memcpy(aad_recomputed + ctx.len, header.data, header.len);
    T_CHECK(ctx.len + header.len == aad.len &&
                 memcmp(aad_recomputed, aad.data, aad.len) == 0,
             "callback_box: AAD == kdf_context || header");

    lrp_bytes decrypted = {0};
    T_CHECK(lrp_aead_decrypt(suite, key, aead_nonce, aad_recomputed, ctx.len + header.len,
                               ciphertext.data, ciphertext.len, &decrypted, &err) == 0,
             "callback_box: low-level AEAD decrypt succeeds");
    T_CHECK(decrypted.len == plaintext.len && memcmp(decrypted.data, plaintext.data, plaintext.len) == 0,
             "callback_box: decrypted plaintext matches plaintext_cbor_hex exactly");

    /* High-level path: full lrp_open_local_rp_callback. */
    lrp_w_callback_header hdr = {0};
    lrp_w_signed_callback_payload sp = {0};
    lrp_error err2 = {0};
    int orc = lrp_open_local_rp_callback(header.data, header.len, ciphertext.data, ciphertext.len,
                                          decrypt_priv, recipient_pub, (const char *const *)allowed,
                                          allowed_count, &hdr, &sp, &err2);
    T_CHECK(orc == 0, "callback_box: lrp_open_local_rp_callback succeeds on a valid positive case");
    if (orc == 0) {
        lrp_w_callback_header_free(&hdr);
        lrp_w_signed_callback_payload_free(&sp);
    }

    lrp_bytes_free(&header);
    lrp_bytes_free(&kdf_context);
    lrp_bytes_free(&aad);
    lrp_bytes_free(&plaintext);
    lrp_bytes_free(&ciphertext);
    lrp_bytes_free(&ctx);
    free(aad_recomputed);
    lrp_bytes_free(&decrypted);
    free_strings(allowed, allowed_count);
}

static void run_callback_box_negative(const json_value *c) {
    uint8_t decrypt_priv[32];
    t_hex_field_fixed(c, "decrypt_private_key_hex", decrypt_priv, 32);
    uint8_t recipient_pub[32];
    lrp_error derr = {0};
    lrp_x25519_derive_public(decrypt_priv, recipient_pub, &derr);
    lrp_bytes header = t_hex_field(c, "header_cbor_hex");
    lrp_bytes ciphertext = t_hex_field(c, "ciphertext_hex");
    size_t allowed_count;
    char **allowed = strings_from_json_array(json_get(c, "allowed_suites"), &allowed_count);

    lrp_w_callback_header hdr = {0};
    lrp_w_signed_callback_payload sp = {0};
    lrp_error err = {0};
    int rc = lrp_open_local_rp_callback(header.data, header.len, ciphertext.data, ciphertext.len,
                                         decrypt_priv, recipient_pub, (const char *const *)allowed,
                                         allowed_count, &hdr, &sp, &err);
    T_CHECK(rc != 0, "callback_box negative case correctly rejected");
    if (rc == 0) {
        lrp_w_callback_header_free(&hdr);
        lrp_w_signed_callback_payload_free(&sp);
    }

    lrp_bytes_free(&header);
    lrp_bytes_free(&ciphertext);
    free_strings(allowed, allowed_count);
}

static void test_callback_box(void) {
    json_value *doc = load("callback_box.json");
    const json_value *pos = json_get(doc, "positive_cases");
    for (size_t i = 0; i < json_len(pos); i++) run_callback_box_positive(json_at(pos, i));
    T_CHECK(json_len(pos) == 2, "callback_box: 2 positive cases (one per suite)");

    const json_value *neg = json_get(doc, "negative_cases");
    for (size_t i = 0; i < json_len(neg); i++) run_callback_box_negative(json_at(neg, i));
    T_CHECK(json_len(neg) == 13, "callback_box: 13 negative cases present");
    json_free(doc);
}

/* ======================================================================= */
/* tickets.json                                                            */
/* ======================================================================= */

static void test_tickets(void) {
    json_value *doc = load("tickets.json");
    const json_value *cases = json_get(doc, "cases");
    for (size_t i = 0; i < json_len(cases); i++) {
        const json_value *c = json_at(cases, i);
        lrp_bytes ticket = t_hex_field(c, "ticket_hex");
        lrp_bytes expected = t_hex_field(c, "sha256_hex");
        uint8_t digest[32];
        lrp_sha256(ticket.data, ticket.len, digest);
        T_CHECK(expected.len == 32 && memcmp(digest, expected.data, 32) == 0,
                 "tickets: sha256(ticket) matches sha256_hex");
        lrp_bytes_free(&ticket);
        lrp_bytes_free(&expected);
    }
    json_free(doc);
}

/* ======================================================================= */
/* url_params.json                                                         */
/* ======================================================================= */

static void test_url_params(void) {
    json_value *doc = load("url_params.json");
    const json_value *cases = json_get(doc, "cases");
    for (size_t i = 0; i < json_len(cases); i++) {
        const json_value *c = json_at(cases, i);
        lrp_bytes cbor_bytes = t_hex_field(c, "cbor_hex");
        const char *b64 = json_str(json_get(c, "base64url_unpadded"));

        lrp_bytes decoded = {0};
        lrp_error err = {0};
        int rc = lrp_base64url_decode(b64, &decoded, &err);
        T_CHECK(rc == 0, "url_params: decode succeeds");
        T_CHECK(decoded.len == cbor_bytes.len && memcmp(decoded.data, cbor_bytes.data, decoded.len) == 0,
                 "url_params: decoded bytes match cbor_hex");

        lrp_str encoded = {0};
        T_CHECK(lrp_base64url_encode(cbor_bytes.data, cbor_bytes.len, &encoded, &err) == 0,
                 "url_params: encode succeeds");
        T_CHECK(strcmp(encoded.data, b64) == 0, "url_params: re-encode matches base64url_unpadded");

        lrp_bytes_free(&cbor_bytes);
        lrp_bytes_free(&decoded);
        lrp_str_free(&encoded);
    }

    const json_value *neg = json_get(doc, "negative_cases");
    for (size_t i = 0; i < json_len(neg); i++) {
        const json_value *c = json_at(neg, i);
        const char *input = json_str(json_get(c, "input"));
        lrp_bytes decoded = {0};
        lrp_error err = {0};
        int rc = lrp_base64url_decode(input, &decoded, &err);
        T_CHECK(rc != 0, "url_params negative case correctly rejected");
        lrp_bytes_free(&decoded);
    }
    json_free(doc);
}

/* ======================================================================= */
/* dns.json                                                                 */
/* ======================================================================= */

static lrp_dns_parse_error error_from_name(const char *name) {
    if (strcmp(name, "missing_version") == 0) return LRP_DNS_ERR_MISSING_VERSION;
    if (strcmp(name, "unsupported_version") == 0) return LRP_DNS_ERR_UNSUPPORTED_VERSION;
    if (strcmp(name, "missing_apis_endpoint") == 0) return LRP_DNS_ERR_MISSING_APIS_ENDPOINT;
    return LRP_DNS_ERR_NONE;
}

static void test_dns(void) {
    json_value *doc = load("dns.json");

    const json_value *port = json_get(doc, "default_tcp_port");
    T_CHECK(port != NULL && (int)port->num_val == LRP_DEFAULT_TCP_PORT,
             "dns: default_tcp_port matches LRP_DEFAULT_TCP_PORT");

    const json_value *lk = json_get(doc, "linkkeys_txt");
    const json_value *valid = json_get(lk, "valid_cases");
    for (size_t i = 0; i < json_len(valid); i++) {
        const json_value *c = json_at(valid, i);
        const char *txt = json_str(json_get(c, "txt"));
        lrp_linkkeys_record rec;
        lrp_dns_parse_error e = lrp_parse_linkkeys_txt(txt, &rec);
        T_CHECK(e == LRP_DNS_ERR_NONE, "dns: linkkeys_txt valid case parses");
        const json_value *expected_fps = json_get(c, "expected_fingerprints");
        T_CHECK(rec.fingerprints_count == json_len(expected_fps),
                 "dns: linkkeys_txt fingerprint count matches");
        for (size_t k = 0; k < rec.fingerprints_count && k < json_len(expected_fps); k++) {
            T_CHECK(strcmp(rec.fingerprints[k], json_str(json_at(expected_fps, k))) == 0,
                     "dns: linkkeys_txt fingerprint order/value matches");
        }
        lrp_linkkeys_record_free(&rec);
    }
    const json_value *invalid = json_get(lk, "invalid_cases");
    for (size_t i = 0; i < json_len(invalid); i++) {
        const json_value *c = json_at(invalid, i);
        const char *txt = json_str(json_get(c, "txt"));
        const char *expected_err = json_str(json_get(c, "expected_error"));
        lrp_linkkeys_record rec;
        lrp_dns_parse_error e = lrp_parse_linkkeys_txt(txt, &rec);
        T_CHECK(e == error_from_name(expected_err), "dns: linkkeys_txt invalid case error matches");
        lrp_linkkeys_record_free(&rec);
    }

    const json_value *apis = json_get(doc, "linkkeys_apis_txt");
    const json_value *avalid = json_get(apis, "valid_cases");
    for (size_t i = 0; i < json_len(avalid); i++) {
        const json_value *c = json_at(avalid, i);
        const char *txt = json_str(json_get(c, "txt"));
        lrp_linkkeys_apis a;
        lrp_dns_parse_error e = lrp_parse_linkkeys_apis_txt(txt, &a);
        T_CHECK(e == LRP_DNS_ERR_NONE, "dns: linkkeys_apis_txt valid case parses");
        const char *expected_tcp = json_str(json_get(c, "expected_tcp"));
        const char *expected_https = json_str(json_get(c, "expected_https_base"));
        if (expected_tcp == NULL) {
            T_CHECK(a.tcp.data == NULL, "dns: linkkeys_apis_txt expected null tcp");
        } else {
            T_CHECK(a.tcp.data != NULL && strcmp(a.tcp.data, expected_tcp) == 0,
                     "dns: linkkeys_apis_txt tcp matches");
        }
        if (expected_https == NULL) {
            T_CHECK(a.https_base.data == NULL, "dns: linkkeys_apis_txt expected null https_base");
        } else {
            T_CHECK(a.https_base.data != NULL && strcmp(a.https_base.data, expected_https) == 0,
                     "dns: linkkeys_apis_txt https_base matches");
        }
        lrp_linkkeys_apis_free(&a);
    }
    const json_value *ainvalid = json_get(apis, "invalid_cases");
    for (size_t i = 0; i < json_len(ainvalid); i++) {
        const json_value *c = json_at(ainvalid, i);
        const char *txt = json_str(json_get(c, "txt"));
        const char *expected_err = json_str(json_get(c, "expected_error"));
        lrp_linkkeys_apis a;
        lrp_dns_parse_error e = lrp_parse_linkkeys_apis_txt(txt, &a);
        T_CHECK(e == error_from_name(expected_err), "dns: linkkeys_apis_txt invalid case error matches");
        lrp_linkkeys_apis_free(&a);
    }

    json_free(doc);
}

/* ======================================================================= */
/* expirations.json                                                        */
/* ======================================================================= */

static const char *level_name(lrp_expiration_level level) { return lrp_expiration_level_name(level); }

static void test_expirations(void) {
    json_value *doc = load("expirations.json");

    const json_value *ce = json_get(doc, "check_expirations");
    const char *expires_at = json_str(json_get(ce, "expires_at"));
    const json_value *cases = json_get(ce, "cases");
    for (size_t i = 0; i < json_len(cases); i++) {
        const json_value *c = json_at(cases, i);
        const char *now_str = json_str(json_get(c, "now"));
        const char *expected_level = json_str(json_get(c, "expected_level"));
        int64_t now_unix;
        lrp_error err = {0};
        T_CHECK(lrp_parse_rfc3339(now_str, &now_unix, &err) == 0, "expirations: now parses");
        lrp_expiration_status status;
        T_CHECK(lrp_check_expirations_impl(expires_at, now_unix, &status, &err) == 0,
                 "expirations: check_expirations succeeds");
        T_CHECK(strcmp(level_name(status.level), expected_level) == 0,
                 "expirations: level matches expected_level");
    }

    const json_value *ct = json_get(doc, "check_timestamps");
    const char *issued_at = json_str(json_get(ct, "issued_at"));
    const char *ct_expires_at = json_str(json_get(ct, "expires_at"));
    int64_t skew = (int64_t)json_get(ct, "skew_seconds")->num_val;
    const json_value *ct_cases = json_get(ct, "cases");
    for (size_t i = 0; i < json_len(ct_cases); i++) {
        const json_value *c = json_at(ct_cases, i);
        const char *now_str = json_str(json_get(c, "now"));
        int expected_valid = json_bool(json_get(c, "expected_valid"));
        int64_t now_unix;
        lrp_error err = {0};
        lrp_parse_rfc3339(now_str, &now_unix, &err);
        lrp_error terr = {0};
        int rc = lrp_check_timestamps(issued_at, ct_expires_at, now_unix, skew, &terr);
        T_CHECK((rc == 0) == expected_valid, "expirations: check_timestamps outcome matches");
    }

    json_free(doc);
}

/* ======================================================================= */
/* revocations.json                                                        */
/* ======================================================================= */

static lrp_domain_public_key load_domain_key(const json_value *j) {
    lrp_domain_public_key k;
    memset(&k, 0, sizeof(k));
    k.key_id.data = strdup(json_str(json_get(j, "key_id")));
    k.public_key = t_hex_field(j, "public_key_hex");
    k.fingerprint.data = strdup(json_str(json_get(j, "fingerprint_hex")));
    k.algorithm.data = strdup(json_str(json_get(j, "algorithm")));
    k.key_usage.data = strdup(json_str(json_get(j, "key_usage")));
    k.created_at.data = strdup(json_str(json_get(j, "created_at")));
    k.expires_at.data = strdup(json_str(json_get(j, "expires_at")));
    const char *revoked = json_str(json_get(j, "revoked_at"));
    if (revoked != NULL) k.revoked_at.data = strdup(revoked);
    return k;
}

static void load_domain_keys(const json_value *arr, lrp_domain_public_key **out, size_t *out_count) {
    size_t n = json_len(arr);
    lrp_domain_public_key *keys = (lrp_domain_public_key *)calloc(n, sizeof(lrp_domain_public_key));
    for (size_t i = 0; i < n; i++) keys[i] = load_domain_key(json_at(arr, i));
    *out = keys;
    *out_count = n;
}

static void test_revocations(void) {
    json_value *doc = load("revocations.json");
    const char *domain = json_str(json_get(doc, "domain"));
    const json_value *dk_json = json_get(doc, "domain_keys");

    const json_value *cases = json_get(doc, "certificate_cases");
    for (size_t i = 0; i < json_len(cases); i++) {
        const json_value *c = json_at(cases, i);
        const char *verify_domain = json_str(json_get(c, "verify_domain"));
        int expected_valid = json_bool(json_get(c, "expected_valid"));
        int64_t expected_counted = (int64_t)json_get(c, "expected_counted_signers")->num_val;

        lrp_bytes cert_cbor = t_hex_field(c, "certificate_cbor_hex");
        lrp_w_revocation_certificate cert = {0};
        lrp_error err = {0};
        T_CHECK(lrp_decode_revocation_certificate(cert_cbor.data, cert_cbor.len, &cert, &err) == 0,
                 "revocations: certificate CBOR decodes");

        lrp_domain_public_key *keys;
        size_t keys_count;
        load_domain_keys(dk_json, &keys, &keys_count);

        size_t got = lrp_count_revocation_signers(&cert, keys, keys_count, verify_domain);
        T_CHECK((int64_t)got == expected_counted, "revocations: counted signers matches");

        lrp_error verr = {0};
        int vrc = lrp_verify_revocation_certificate(&cert, keys, keys_count, verify_domain, &verr);
        T_CHECK((vrc == 0) == expected_valid, "revocations: certificate verify outcome matches");

        lrp_domain_public_keys_array_free(keys, keys_count);
        lrp_w_revocation_certificate_free(&cert);
        lrp_bytes_free(&cert_cbor);
    }
    T_CHECK(json_len(cases) == 9, "revocations: 9 certificate cases present");

    /* application_case: complete_local_login's own usage pattern. */
    const json_value *app = json_get(doc, "application_case");
    const json_value *env = json_get(app, "envelope");
    lrp_w_signed_callback_payload sp;
    memset(&sp, 0, sizeof(sp));
    sp.payload = t_hex_field(env, "payload_cbor_hex");
    sp.signing_key_id.data = strdup(json_str(json_get(env, "signing_key_id")));
    sp.signature = t_hex_field(env, "signature_hex");

    int64_t verify_now;
    lrp_error perr = {0};
    lrp_parse_rfc3339(json_str(json_get(app, "verify_now")), &verify_now, &perr);
    int64_t skew = (int64_t)json_get(app, "clock_skew_seconds")->num_val;

    lrp_domain_public_key *keys;
    size_t keys_count;
    load_domain_keys(dk_json, &keys, &keys_count);

    lrp_w_callback_payload payload = {0};
    lrp_error verr1 = {0};
    int rc1 =
        lrp_verify_local_rp_callback_payload(&sp, keys, keys_count, verify_now, skew, &payload, &verr1);
    int expected_before = json_bool(json_get(app, "expected_valid_before_revocation"));
    T_CHECK((rc1 == 0) == expected_before, "revocations application_case: before-revocation outcome");
    if (rc1 == 0) lrp_w_callback_payload_free(&payload);

    /* Apply the referenced certificate's revocation to the target key. */
    const char *cert_ref_name = "valid_quorum_two_siblings";
    for (size_t i = 0; i < json_len(cases); i++) {
        const json_value *c = json_at(cases, i);
        if (strcmp(json_str(json_get(c, "name")), cert_ref_name) == 0) {
            const char *revoked_at = json_str(json_get(json_get(c, "certificate"), "revoked_at"));
            const char *target_key_id =
                json_str(json_get(json_get(c, "certificate"), "target_key_id"));
            for (size_t k = 0; k < keys_count; k++) {
                if (strcmp(keys[k].key_id.data, target_key_id) == 0) {
                    lrp_str_free(&keys[k].revoked_at);
                    keys[k].revoked_at.data = strdup(revoked_at);
                }
            }
            break;
        }
    }

    lrp_w_callback_payload payload2 = {0};
    lrp_error verr2 = {0};
    int rc2 = lrp_verify_local_rp_callback_payload(&sp, keys, keys_count, verify_now, skew, &payload2,
                                                    &verr2);
    int expected_after = json_bool(json_get(app, "expected_valid_after_revocation"));
    T_CHECK((rc2 == 0) == expected_after, "revocations application_case: after-revocation outcome");
    if (rc2 == 0) lrp_w_callback_payload_free(&payload2);

    (void)domain;
    lrp_domain_public_keys_array_free(keys, keys_count);
    lrp_w_signed_callback_payload_free(&sp);
    json_free(doc);
}

/* ======================================================================= */
/* claims.json                                                             */
/* ======================================================================= */

/* Independent Ed25519 verification via raw OpenSSL EVP calls — deliberately
 * NOT going through this SDK's own crypto.c (lrp_ed25519_verify) or
 * claims.c (claim_sign_payload). The background for this vector file is
 * that a sign-wrong/verify-wrong bug in one SDK's own code was perfectly
 * self-consistent and only cross-implementation vectors caught it; this
 * check gives claims.json's signed_payload_cbor_hex/signature_hex pairs a
 * verification path that shares no code with the SDK under test. */
static int evp_ed25519_verify_raw(const uint8_t pub[32], const uint8_t *msg, size_t msg_len,
                                   const uint8_t *sig, size_t sig_len) {
    if (sig_len != 64) return -1;
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    if (pkey == NULL) return -1;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int rc = -1;
    if (mdctx != NULL && EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len) == 1) {
        rc = 0;
    }
    if (mdctx != NULL) EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return rc;
}

static lrp_bytes find_signer_pubkey(const json_value *signer_keys, const char *key_id) {
    for (size_t i = 0; i < json_len(signer_keys); i++) {
        const json_value *sk = json_at(signer_keys, i);
        if (strcmp(json_str(json_get(sk, "key_id")), key_id) == 0) {
            return t_hex_field(sk, "public_key_hex");
        }
    }
    fprintf(stderr, "fixture error: claims.json signer_keys missing key_id '%s'\n", key_id);
    exit(2);
}

static const char *domain_keys_domain(const json_value *dk_json) {
    if (json_len(dk_json) == 0) return "";
    return json_str(json_get(json_at(dk_json, 0), "domain"));
}

static void run_claims_positive_case(const json_value *c, const json_value *signer_keys,
                                      const lrp_domain_key_set *default_sets,
                                      size_t default_sets_count) {
    lrp_bytes claim_cbor = t_hex_field(c, "claim_cbor_hex");
    const char *subject_domain = json_str(json_get(c, "subject_domain"));

    lrp_claim claim;
    lrp_error derr = {0};
    int drc = lrp_decode_claim(claim_cbor.data, claim_cbor.len, &claim, &derr);
    T_CHECK(drc == 0, "claims: positive case claim decodes");
    if (drc != 0) {
        lrp_bytes_free(&claim_cbor);
        return;
    }

    lrp_bytes reencoded = {0};
    lrp_error eerr = {0};
    T_CHECK(lrp_encode_claim(&claim, &reencoded, &eerr) == 0, "claims: positive case re-encodes");
    T_CHECK(reencoded.len == claim_cbor.len &&
                 memcmp(reencoded.data, claim_cbor.data, reencoded.len) == 0,
             "claims: positive case re-encode is byte-exact with claim_cbor_hex");

    /* Through the SDK's own claim verification path (src/claims.c), the
     * same path lrp_complete_login uses. */
    lrp_error verr = {0};
    int vrc = lrp_verify_claim(&claim, subject_domain, default_sets, default_sets_count, &verr);
    T_CHECK(vrc == 0, "claims: positive case verifies through lrp_verify_claim");

    /* Independent EVP verification of every signature's exact
     * signed_payload_cbor_hex/signature_hex pair from the vector, bypassing
     * claims.c and crypto.c entirely. */
    const json_value *sigs = json_get(json_get(c, "claim"), "signatures");
    for (size_t i = 0; i < json_len(sigs); i++) {
        const json_value *sc = json_at(sigs, i);
        const char *key_id = json_str(json_get(sc, "signed_by_key_id"));
        lrp_bytes pub = find_signer_pubkey(signer_keys, key_id);
        lrp_bytes payload = t_hex_field(sc, "signed_payload_cbor_hex");
        lrp_bytes sig = t_hex_field(sc, "signature_hex");
        T_CHECK(pub.len == 32, "claims: signer public key is 32 bytes");
        T_CHECK(evp_ed25519_verify_raw(pub.data, payload.data, payload.len, sig.data, sig.len) == 0,
                 "claims: independent raw-EVP verification of signed_payload_cbor_hex/signature_hex");
        lrp_bytes_free(&pub);
        lrp_bytes_free(&payload);
        lrp_bytes_free(&sig);
    }

    lrp_claim_free_fields(&claim);
    lrp_bytes_free(&claim_cbor);
    lrp_bytes_free(&reencoded);
}

static int claims_expected_error_matches(const char *expected, const lrp_error *err) {
    /* claims.c reports both failure kinds under one lrp_error_code
     * (LRP_ERR_CLAIM — see README's note that exact error TYPES are not
     * part of the portable contract); the fixture's expected_error is
     * still checked here via the distinct diagnostic messages claims.c
     * produces for each ("signing key not found: ..." vs "ed25519:
     * signature verification failed"), matching what lrp_verify_claim
     * actually reports for each of the two distinguishable failure kinds
     * this file exercises. */
    if (strcmp(expected, "signature_invalid") == 0) {
        return strstr(err->message, "signature verification failed") != NULL;
    }
    if (strcmp(expected, "key_not_found") == 0) {
        return strstr(err->message, "signing key not found") != NULL;
    }
    return 0;
}

static void run_claims_negative_case(const json_value *c, const json_value *default_domain_keys_json) {
    lrp_bytes claim_cbor = t_hex_field(c, "claim_cbor_hex");
    const char *subject_domain = json_str(json_get(c, "subject_domain"));
    const char *expected_error = json_str(json_get(c, "expected_error"));

    lrp_claim claim;
    lrp_error derr = {0};
    int drc = lrp_decode_claim(claim_cbor.data, claim_cbor.len, &claim, &derr);
    T_CHECK(drc == 0, "claims: negative case claim decodes (semantic failure, not a wire failure)");
    if (drc != 0) {
        lrp_bytes_free(&claim_cbor);
        return;
    }

    const json_value *override = json_get(c, "domain_keys");
    const json_value *dk_json = override != NULL ? override : default_domain_keys_json;
    lrp_domain_public_key *keys;
    size_t keys_count;
    load_domain_keys(dk_json, &keys, &keys_count);
    lrp_domain_key_set set = {domain_keys_domain(dk_json), keys, keys_count};

    lrp_error verr = {0};
    int vrc = lrp_verify_claim(&claim, subject_domain, &set, 1, &verr);
    T_CHECK(vrc != 0, "claims: negative case correctly rejected by lrp_verify_claim");
    T_CHECK(claims_expected_error_matches(expected_error, &verr),
             "claims: negative case error kind matches expected_error");

    lrp_domain_public_keys_array_free(keys, keys_count);
    lrp_claim_free_fields(&claim);
    lrp_bytes_free(&claim_cbor);
}

static void test_claims(void) {
    json_value *doc = load("claims.json");
    const json_value *signer_keys = json_get(doc, "signer_keys");
    const json_value *domain_keys_json = json_get(doc, "domain_keys");

    lrp_domain_public_key *default_keys;
    size_t default_keys_count;
    load_domain_keys(domain_keys_json, &default_keys, &default_keys_count);
    lrp_domain_key_set default_set = {domain_keys_domain(domain_keys_json), default_keys,
                                       default_keys_count};

    const json_value *cases = json_get(doc, "cases");
    for (size_t i = 0; i < json_len(cases); i++) {
        run_claims_positive_case(json_at(cases, i), signer_keys, &default_set, 1);
    }
    T_CHECK(json_len(cases) == 3, "claims: 3 positive cases present");

    /* The tstr-decode-rejection case: Claim.claim_value is CBOR bytes
     * (bstr) on the wire, never text (tstr) — a strict decoder must REJECT
     * this input outright. */
    const json_value *decode_neg = json_get(doc, "decode_negative_cases");
    for (size_t i = 0; i < json_len(decode_neg); i++) {
        const json_value *c = json_at(decode_neg, i);
        lrp_bytes claim_cbor = t_hex_field(c, "claim_cbor_hex");
        lrp_claim claim;
        lrp_error err = {0};
        int rc = lrp_decode_claim(claim_cbor.data, claim_cbor.len, &claim, &err);
        int expected_ok = json_bool(json_get(c, "expected_decode_ok"));
        T_CHECK((rc == 0) == expected_ok,
                 "claims: decode_negative_cases outcome matches expected_decode_ok");
        if (rc == 0) lrp_claim_free_fields(&claim);
        lrp_bytes_free(&claim_cbor);
    }
    T_CHECK(json_len(decode_neg) == 1,
             "claims: 1 decode_negative_case present (tstr claim_value rejection)");

    const json_value *neg = json_get(doc, "negative_cases");
    for (size_t i = 0; i < json_len(neg); i++) {
        run_claims_negative_case(json_at(neg, i), domain_keys_json);
    }
    T_CHECK(json_len(neg) == 4, "claims: 4 verification negative cases present");

    /* LocalRpTicketRedemptionResponse: the wire message
     * complete_local_login actually consumes Claims from. Round-trip it
     * byte-exactly AND verify the embedded claims' signatures. */
    const json_value *trr = json_get(doc, "ticket_redemption_response");
    lrp_bytes resp_cbor = t_hex_field(trr, "response_cbor_hex");
    lrp_w_ticket_redemption_response resp;
    lrp_error rerr = {0};
    T_CHECK(lrp_decode_ticket_redemption_response(resp_cbor.data, resp_cbor.len, &resp, &rerr) == 0,
             "claims: ticket_redemption_response decodes");
    T_CHECK(resp.claims_count == 3, "claims: ticket_redemption_response carries 3 claims");

    lrp_bytes resp_reencoded = {0};
    lrp_error rerr2 = {0};
    T_CHECK(lrp_encode_ticket_redemption_response(&resp, &resp_reencoded, &rerr2) == 0,
             "claims: ticket_redemption_response re-encodes");
    T_CHECK(resp_reencoded.len == resp_cbor.len &&
                 memcmp(resp_reencoded.data, resp_cbor.data, resp_reencoded.len) == 0,
             "claims: ticket_redemption_response re-encode is byte-exact with response_cbor_hex");

    for (size_t i = 0; i < resp.claims_count; i++) {
        lrp_error cverr = {0};
        int crc = lrp_verify_claim(&resp.claims[i], resp.user_domain.data, &default_set, 1, &cverr);
        T_CHECK(crc == 0, "claims: ticket_redemption_response embedded claim verifies");
    }

    lrp_bytes_free(&resp_cbor);
    lrp_bytes_free(&resp_reencoded);
    lrp_w_ticket_redemption_response_free(&resp);

    lrp_domain_public_keys_array_free(default_keys, default_keys_count);
    json_free(doc);
}

/* ======================================================================= */
/* CBOR decoder hardening (SEC fix: DoS/SF-5, and the M2 OOM-path leak)     */
/* ======================================================================= */

/* A definite-length array/map header can declare an element COUNT up to
 * 2^64-1 while the buffer backing it is only a handful of bytes. Before the
 * fix, that declared count was used directly to size a
 * `calloc(n, sizeof(cbor_value))` — under ASan (this test binary's build),
 * a request that large aborts the whole process outright (allocation-size-
 * too-big) rather than merely failing a decode, so this test's very ability
 * to run to completion is itself part of what it's checking. */
static void test_cbor_oversized_count_rejected(void) {
    /* Array header (major type 4), 8-byte length form (info=27), declaring
     * 0xFFFFFFFFFFFFFFFF items, with no item bytes following at all. */
    uint8_t huge_array[] = {0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    {
        cbor_value *v = NULL;
        lrp_error err = {0};
        int rc = cbor_decode(huge_array, sizeof(huge_array), &v, &err);
        T_CHECK(rc != 0, "cbor: array declaring 2^64-1 items is rejected, not OOM-attempted");
        T_CHECK(rc != 0 && err.code == LRP_ERR_DECODE, "cbor: oversized array count is a decode error");
        if (rc == 0) {
            cbor_value_free(v);
            free(v);
        }
    }

    /* Map header (major type 5), 8-byte length form, same oversized count. */
    uint8_t huge_map[] = {0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    {
        cbor_value *v = NULL;
        lrp_error err = {0};
        int rc = cbor_decode(huge_map, sizeof(huge_map), &v, &err);
        T_CHECK(rc != 0, "cbor: map declaring 2^64-1 entries is rejected, not OOM-attempted");
        T_CHECK(rc != 0 && err.code == LRP_ERR_DECODE, "cbor: oversized map count is a decode error");
        if (rc == 0) {
            cbor_value_free(v);
            free(v);
        }
    }

    /* A moderate-but-still-impossible count: declares 1000 array items
     * (2-byte length form, info=25) with only 2 bytes of buffer left after
     * the header — cannot possibly hold 1000 items at >=1 byte each.
     * Exercises the "reject if it can't possibly fit" bound directly, not
     * just the extreme 2^64 case (which a naive `n * sizeof(item) overflows
     * size_t` check alone would not catch). */
    uint8_t small_buf_big_count[] = {0x99, 0x03, 0xe8, 0x00, 0x00}; /* array(1000), 2 bytes follow */
    {
        cbor_value *v = NULL;
        lrp_error err = {0};
        int rc = cbor_decode(small_buf_big_count, sizeof(small_buf_big_count), &v, &err);
        T_CHECK(rc != 0,
                 "cbor: array count exceeding what the remaining buffer could hold is rejected");
        if (rc == 0) {
            cbor_value_free(v);
            free(v);
        }
    }

    /* Sanity: a small, legitimately-sized array still decodes fine — the
     * bound must not be overzealous. */
    uint8_t small_ok[] = {0x82, 0x01, 0x02}; /* array(2): [1, 2] */
    {
        cbor_value *v = NULL;
        lrp_error err = {0};
        int rc = cbor_decode(small_ok, sizeof(small_ok), &v, &err);
        T_CHECK(rc == 0, "cbor: a small legitimately-sized array still decodes");
        if (rc == 0) {
            T_CHECK(v->type == CBOR_T_ARRAY && v->items_len == 2,
                     "cbor: decoded array shape is correct");
            cbor_value_free(v);
            free(v);
        }
    }
}

/* ======================================================================= */

int run_conformance_tests(void) {
    test_keys();
    test_envelopes();
    test_callback_box();
    test_tickets();
    test_url_params();
    test_dns();
    test_expirations();
    test_revocations();
    test_claims();
    test_cbor_oversized_count_rejected();
    return 0;
}
