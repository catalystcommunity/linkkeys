/* linkkeys_local_rp.h
 *
 * Public C API for LinkKeys' DNS-less local RP identity SDK
 * (`dns-less-local-rp-design.md` at the repo root — read it first; this
 * header implements its "SDK API Shape" section, C-idiomatically adapted:
 * big-config input structs, explicit out-parameters, explicit ownership).
 *
 * This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
 * self-hosted service with no public DNS) use LinkKeys for login without
 * running its own DNS-pinned relying party. The app's identity is the
 * fingerprint of a locally-generated Ed25519 signing key (SSH-host-key
 * style), not a domain.
 *
 * ## Ownership rules (read this before calling anything)
 *
 * - Every `lrp_*_free` function releases exactly what the matching
 *   allocating call returned. Passing a partially-initialized or
 *   already-freed struct to a `_free` function is undefined behavior aside
 *   from the explicit "safe to call on a zeroed struct" guarantee below.
 * - Every struct in this header is safe to `_free` when it has been
 *   zero-initialized (e.g. `lrp_identity id = {0};`) and never populated —
 *   every `_free` function checks its heap-owned fields for NULL first.
 * - Structs containing private key material (`lrp_identity`) are zeroized
 *   with `OPENSSL_cleanse` before their backing memory is released.
 * - Output parameters of allocating functions are only written on success
 *   (return value `LRP_OK`); on failure they are left zeroed and owe the
 *   caller nothing.
 * - This library performs no logging. Callers that log `lrp_error` must
 *   heed AGENTS.md: never log key material, nonces, tokens, tickets, or
 *   claim values; `lrp_error.message` is written to avoid including any of
 *   those (see error.c).
 *
 * ## Quickstart
 *
 * ```c
 * lrp_error err = {0};
 * lrp_identity id = {0};
 * lrp_generate_identity_config gen_cfg = {
 *     .app_name = "My LAN Jukebox",
 *     .now_unix = time(NULL),
 * };
 * if (lrp_generate_local_rp_identity(&gen_cfg, &id, &err) != LRP_OK) { ... }
 *
 * lrp_bytes stored = {0};
 * lrp_local_rp_identity_to_bytes(&id, &stored, &err);
 * // ... persist stored.data/stored.len with application-secret care ...
 * lrp_bytes_free(&stored);
 *
 * lrp_login_redirect redirect = {0};
 * lrp_pending_login pending = {0};
 * lrp_begin_login_config begin_cfg = {
 *     .identity = &id,
 *     .callback_url = "http://jukebox.lan:8080/auth/callback",
 *     .user_domain = "example.com",
 *     .now_unix = time(NULL),
 * };
 * lrp_begin_local_login(&begin_cfg, &redirect, &pending, &err);
 * // ... app: persist `pending`, redirect the browser to redirect.redirect_url ...
 *
 * lrp_verified_login verified = {0};
 * lrp_complete_login_config complete_cfg = {
 *     .identity = &id,
 *     .pending = &pending,
 *     .encrypted_token = encrypted_token_from_query_string,
 *     .arrived_url = full_request_url,
 *     .now_unix = time(NULL),
 * };
 * lrp_complete_local_login(&complete_cfg, &verified, &err);
 * // verified carries user id/domain, claims, domain keys used, fingerprint,
 * // and expirations. Session creation, local user records, and
 * // authorization are entirely the app's responsibility.
 * ```
 *
 * See README.md for build/link instructions and further security notes.
 */

#ifndef LINKKEYS_LOCAL_RP_H
#define LINKKEYS_LOCAL_RP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------- */
/* Errors                                                                 */
/* --------------------------------------------------------------------- */

typedef enum lrp_error_code {
    LRP_OK = 0,
    LRP_ERR_INVALID_INPUT,
    LRP_ERR_DECODE,
    LRP_ERR_DNS,
    LRP_ERR_TRANSPORT,
    LRP_ERR_TLS,
    LRP_ERR_PROTOCOL,
    LRP_ERR_SERVER,
    LRP_ERR_VERIFICATION,
    LRP_ERR_CLAIM,
    LRP_ERR_NO_TRUSTED_KEYS,
    LRP_ERR_REVOCATION,
    LRP_ERR_CRYPTO,
    LRP_ERR_OUT_OF_MEMORY,
} lrp_error_code;

#define LRP_ERROR_MESSAGE_LEN 256

/* Caller-allocated (typically on the stack, zero-initialized). Every
 * fallible function in this header takes `lrp_error *err` and, on failure,
 * fills it in and returns a non-LRP_OK code (mirroring the return value).
 * `err` may be NULL if the caller only cares about the return code. */
typedef struct lrp_error {
    lrp_error_code code;
    char message[LRP_ERROR_MESSAGE_LEN];
} lrp_error;

/* Human-readable name of an error code (static string, do not free). */
const char *lrp_error_code_name(lrp_error_code code);

/* --------------------------------------------------------------------- */
/* Byte buffers                                                          */
/* --------------------------------------------------------------------- */

/* An owned, heap-allocated byte buffer. `data` is NULL and `len` is 0 for
 * an empty/unset buffer. Free with `lrp_bytes_free`. */
typedef struct lrp_bytes {
    uint8_t *data;
    size_t len;
} lrp_bytes;

void lrp_bytes_free(lrp_bytes *b);
/* Like lrp_bytes_free, but zeroizes the buffer (OPENSSL_cleanse) before
 * releasing it. Use for anything that held key material. */
void lrp_bytes_free_sensitive(lrp_bytes *b);

/* A NUL-terminated, heap-allocated C string. Free with lrp_str_free. */
typedef struct lrp_str {
    char *data; /* NULL for unset */
} lrp_str;

void lrp_str_free(lrp_str *s);

/* --------------------------------------------------------------------- */
/* Hex helpers (Byte Storage Helpers)                                    */
/* --------------------------------------------------------------------- */

/* Lowercase hex, no separators, no "0x" prefix. `out` is NUL-terminated. */
int lrp_bytes_to_hex(const uint8_t *data, size_t len, lrp_str *out, lrp_error *err);
int lrp_hex_to_bytes(const char *hex, lrp_bytes *out, lrp_error *err);

/* --------------------------------------------------------------------- */
/* Local RP identity                                                     */
/* --------------------------------------------------------------------- */

#define LRP_FINGERPRINT_HEX_LEN 64

/* A local RP's full key material: an Ed25519 signing keypair, a *separate*
 * X25519 encryption keypair (never algebraically derived from the signing
 * key), and the self-signed descriptor envelope binding them together
 * (design doc: "Encryption Key Is Separate, Not Derived").
 *
 * Security note: `signing_private_key`/`encryption_private_key` control
 * this app's entire local RP identity. Store the bytes from
 * `lrp_local_rp_identity_to_bytes` with ordinary application-secret care
 * (same tier as a database credential or API key), not merely as
 * configuration. `lrp_identity_free` zeroizes both private keys before
 * releasing this struct. */
typedef struct lrp_identity {
    uint8_t signing_private_key[32];   /* Ed25519 seed */
    uint8_t signing_public_key[32];
    uint8_t encryption_private_key[32]; /* X25519 */
    uint8_t encryption_public_key[32];
    /* Exact CBOR bytes of the LocalRpDescriptor payload, and its envelope
     * signature (context "linkkeys-local-rp-descriptor"). Reused as-is in
     * every begin_local_login call (no per-login descriptor churn). */
    lrp_bytes descriptor_cbor;
    lrp_bytes descriptor_signature;
    /* sha256(signing_public_key) hex, NUL-terminated, 64 hex chars + NUL. */
    char fingerprint[LRP_FINGERPRINT_HEX_LEN + 1];
} lrp_identity;

void lrp_identity_free(lrp_identity *id);

typedef struct lrp_generate_identity_config {
    const char *app_name;               /* required, non-empty */
    const char *local_domain_hint;      /* optional, may be NULL */
    /* AEAD suites this app can decrypt callbacks with, preference order.
     * NULL/count 0 => default: both registry suites, aes-256-gcm first. */
    const char *const *supported_suites;
    size_t supported_suites_count;
    /* Key/descriptor lifetime in seconds from now_unix. 0 => default 10y. */
    int64_t lifetime_seconds;
    int64_t now_unix;
} lrp_generate_identity_config;

/* generate_local_rp_identity(config) -> LocalRpKeyMaterial */
int lrp_generate_local_rp_identity(const lrp_generate_identity_config *config,
                                    lrp_identity *out, lrp_error *err);

/* Byte Storage Helpers: local_rp_identity_to_bytes / _from_bytes. The
 * packed format is an SDK-local storage convenience (magic "LKI1"), not a
 * protocol wire format. */
int lrp_local_rp_identity_to_bytes(const lrp_identity *id, lrp_bytes *out, lrp_error *err);
int lrp_local_rp_identity_from_bytes(const uint8_t *data, size_t len,
                                      lrp_identity *out, lrp_error *err);

/* --------------------------------------------------------------------- */
/* Expiration helper                                                     */
/* --------------------------------------------------------------------- */

typedef enum lrp_expiration_level {
    LRP_EXPIRATION_OK = 0,
    LRP_EXPIRATION_NOTICE,
    LRP_EXPIRATION_WARNING,
    LRP_EXPIRATION_CRITICAL,
    LRP_EXPIRATION_EXPIRED,
} lrp_expiration_level;

const char *lrp_expiration_level_name(lrp_expiration_level level);

typedef struct lrp_expiration_status {
    lrp_expiration_level level;
    int64_t expires_at_unix;
    int64_t now_unix;
} lrp_expiration_status;

/* check_expirations(identity, now) -> ExpirationStatus. Thresholds:
 * notice <= 180 days remaining, warning <= 90, critical <= 30,
 * expired when now >= expires_at (boundaries inclusive). */
int lrp_check_expirations(const lrp_identity *id, int64_t now_unix,
                           lrp_expiration_status *out, lrp_error *err);

/* --------------------------------------------------------------------- */
/* begin_local_login                                                     */
/* --------------------------------------------------------------------- */

typedef struct lrp_login_redirect {
    lrp_str redirect_url;
} lrp_login_redirect;

void lrp_login_redirect_free(lrp_login_redirect *r);

/* The state begin_local_login returns for the app to persist (e.g. in a
 * server-side session tied to the browser) and pass unchanged to
 * complete_local_login. Single-use: the app must discard it after one
 * completion attempt; this library owns no storage and cannot enforce
 * that itself. */
typedef struct lrp_pending_login {
    lrp_bytes nonce;
    lrp_bytes state;
    lrp_str user_domain;
    lrp_str callback_url;
    /* The claim types this login required (SEC fix: identity binding —
     * complete_local_login re-checks this set against the redemption's
     * VERIFIED claims; a claim type that never survives signature
     * verification can never satisfy a requirement). Must round-trip
     * through whatever storage the app persists lrp_pending_login in — a
     * login that began requiring e.g. "handle" can't complete without it
     * just because the requirement was forgotten between begin and
     * complete. NULL/0 for a login that required no claims. */
    char **required_claims;
    size_t required_claims_count;
} lrp_pending_login;

void lrp_pending_login_free(lrp_pending_login *p);

/* Serialize/deserialize a pending login for app-side session storage.
 * Format is an SDK-local convenience (magic "LKP1"), not a protocol wire
 * format. */
int lrp_pending_login_to_bytes(const lrp_pending_login *p, lrp_bytes *out, lrp_error *err);
int lrp_pending_login_from_bytes(const uint8_t *data, size_t len,
                                  lrp_pending_login *out, lrp_error *err);

typedef struct lrp_begin_login_config {
    const lrp_identity *identity;  /* required */
    const char *callback_url;      /* required, http:// or https:// */
    const char *user_domain;       /* required */
    /* Optional claim lists. NULL/count 0 => defaults (display_name, email,
     * handle requested; handle required). */
    const char *const *requested_claims;
    size_t requested_claims_count;
    const char *const *required_claims;
    size_t required_claims_count;
    /* Login-request lifetime in seconds. 0 => default 300 (5 minutes). */
    int64_t request_lifetime_seconds;
    int64_t now_unix;
} lrp_begin_login_config;

int lrp_begin_local_login(const lrp_begin_login_config *config,
                           lrp_login_redirect *out_redirect,
                           lrp_pending_login *out_pending,
                           lrp_error *err);

/* --------------------------------------------------------------------- */
/* Network seams: Transport (TCP dial) + DnsResolver (TXT lookup)        */
/* --------------------------------------------------------------------- */

/* A dialed connection. Implementations are function-pointer vtables so
 * tests can inject fakes without a real socket. */
typedef struct lrp_conn {
    void *ctx;
    /* Returns bytes read (>0), 0 at EOF, or -1 on error. */
    long (*read)(struct lrp_conn *self, uint8_t *buf, size_t len);
    /* Returns bytes written (>0) or -1 on error. */
    long (*write)(struct lrp_conn *self, const uint8_t *buf, size_t len);
    void (*close)(struct lrp_conn *self);
} lrp_conn;

typedef enum lrp_address_policy {
    LRP_ADDRESS_PERMISSIVE = 0, /* default: dial anything the OS resolves */
    LRP_ADDRESS_PUBLIC_ONLY,    /* refuse loopback/private/link-local/etc */
} lrp_address_policy;

/* Transport dials host:port and returns a byte stream. Deliberately narrow
 * (connects a byte stream only); TLS + certificate pinning are layered on
 * top in rpc.c. */
typedef struct lrp_transport {
    void *ctx;
    int (*dial)(struct lrp_transport *self, const char *host_port,
                lrp_conn *out_conn, lrp_error *err);
} lrp_transport;

/* Default Transport: a plain blocking TCP dialer. Wire Precision is
 * explicit that SDKs must default to permissive addressing (a LAN/loopback
 * local RP talking to its LinkKeys domain's published endpoint is
 * routinely a private address) — PublicOnly is opt-in. */
lrp_transport lrp_default_transport(lrp_address_policy policy);

/* DnsResolver: TXT lookup seam. Each returned string is one TXT record's
 * full content (concatenation of its character-strings). */
typedef struct lrp_txt_records {
    char **entries;
    size_t count;
} lrp_txt_records;

void lrp_txt_records_free(lrp_txt_records *r);

typedef struct lrp_dns_resolver {
    void *ctx;
    int (*txt_lookup)(struct lrp_dns_resolver *self, const char *name,
                       lrp_txt_records *out, lrp_error *err);
} lrp_dns_resolver;

/* Default DnsResolver: libresolv res_query, mirroring the design doc's
 * "Decided" section (system resolver default; LAN spoofing is an accepted,
 * documented tradeoff for this mode). */
lrp_dns_resolver lrp_default_dns_resolver(void);

/* --------------------------------------------------------------------- */
/* complete_local_login                                                  */
/* --------------------------------------------------------------------- */

typedef struct lrp_claim_signature {
    lrp_str domain;
    lrp_str signed_by_key_id;
    lrp_bytes signature;
} lrp_claim_signature;

typedef struct lrp_claim {
    lrp_str claim_id;
    lrp_str user_id;
    lrp_str claim_type;
    lrp_bytes claim_value;
    lrp_claim_signature *signatures;
    size_t signatures_count;
    lrp_str attested_at;
    lrp_str created_at;
    lrp_str expires_at;   /* .data == NULL if absent */
    lrp_str revoked_at;   /* .data == NULL if absent */
} lrp_claim;

typedef struct lrp_domain_public_key {
    lrp_str key_id;
    lrp_bytes public_key;
    lrp_str fingerprint;
    lrp_str algorithm;
    lrp_str key_usage;
    lrp_str created_at;
    lrp_str expires_at;
    lrp_str revoked_at;       /* .data == NULL if absent */
    lrp_str signed_by_key_id; /* .data == NULL if absent */
    lrp_bytes key_signature;  /* .len == 0 if absent */
} lrp_domain_public_key;

typedef struct lrp_verified_login {
    lrp_str user_id;
    lrp_str user_domain;
    lrp_claim *claims;
    size_t claims_count;
    lrp_domain_public_key *domain_public_keys;
    size_t domain_public_keys_count;
    char local_rp_fingerprint[LRP_FINGERPRINT_HEX_LEN + 1];
    int64_t issued_at_unix;
    int64_t expires_at_unix;
    int64_t ticket_expires_at_unix;
} lrp_verified_login;

void lrp_verified_login_free(lrp_verified_login *v);

typedef struct lrp_complete_login_config {
    const lrp_identity *identity;      /* required, same as begin used */
    const lrp_pending_login *pending;  /* required, from begin */
    const char *encrypted_token;       /* required: encrypted_token= value */
    const char *arrived_url;           /* required: full URL callback arrived at */
    int64_t now_unix;
    /* Clock-skew tolerance in seconds. 0 => default 300. */
    int64_t clock_skew_seconds;
    /* Network seams. NULL => library defaults (real TCP + system resolver). */
    lrp_transport *transport;
    lrp_dns_resolver *dns;
} lrp_complete_login_config;

int lrp_complete_local_login(const lrp_complete_login_config *config,
                              lrp_verified_login *out, lrp_error *err);

#ifdef __cplusplus
}
#endif

#endif /* LINKKEYS_LOCAL_RP_H */
