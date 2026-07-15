/* CSIL-RPC over the injected Transport, TLS-pinned to a domain's DNS
 * `fp=` records — this SDK's only network surface, per the design doc's
 * "Required Network Access": domain public keys, revocations, and
 * claim-ticket redemption, all unauthenticated-TLS TCP CSIL-RPC calls
 * pinned the same way `crates/linkkeys/src/tcp/tls.rs` pins the S2S path.
 *
 * No csilgen `c` target exists (a request for one has been filed — see
 * ~/repos/catalystcommunity/csilgen/docs/csilgen-requests/); this module
 * hand-writes the minimal CSIL-RPC v1 wire codec (`csil-rpc-transport.md`
 * / `crates/csilgen-transport/src/{rpc,conventions,carrier}.rs`): the
 * canonical-map request/response envelope (tag-24 payload, keys sorted by
 * encoded-key bytes) and the 4-byte-big-endian length-prefixed stream
 * framing.
 *
 * TLS pin-extraction route: `SSL_CTX_set_verify(SSL_VERIFY_NONE)` (WebPKI
 * chain validity is NOT the trust anchor here — the pin is) plus a
 * MANDATORY manual check after the handshake: `SSL_get1_peer_certificate`
 * -> `X509_get0_pubkey` -> `EVP_PKEY_get_raw_public_key` to recover the
 * raw 32-byte Ed25519 SPKI content directly (no manual ASN.1/DER framing
 * needed — OpenSSL's EVP layer already unwraps it), then
 * `sha256(...)`-hex compared case-insensitively against the domain's
 * `fp=` set. The TLS byte stream itself is carried over the injected
 * `lrp_transport`/`lrp_conn` seam via a custom BIO (`BIO_meth_new`) that
 * forwards to `conn->read`/`conn->write`, so this works over both the
 * real TCP transport and an in-memory fake used by tests. */
#ifndef LRP_INTERNAL_RPC_H
#define LRP_INTERNAL_RPC_H

#include "dns.h"
#include "linkkeys_local_rp.h"
#include "types.h"

/* Mirrors the reference SDKs' own cap so a malicious/compromised peer
 * cannot drive this client to an unbounded allocation via a forged length
 * prefix. */
#define LRP_MAX_RPC_FRAME_SIZE (1024 * 1024)

typedef struct lrp_domain_endpoint {
    char **fingerprints;
    size_t fingerprints_count;
    char *tcp_addr;
} lrp_domain_endpoint;
void lrp_domain_endpoint_free(lrp_domain_endpoint *e);

/* Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails
 * closed: this SDK never proceeds without a fingerprint set to pin to. */
int lrp_discover_domain_endpoint(lrp_dns_resolver *dns, const char *domain,
                                  lrp_domain_endpoint *out, lrp_error *err);

/* One CSIL-RPC call over a fresh TLS connection to `endpoint`: dial ->
 * TLS-connect-and-pin -> send request frame -> read response frame ->
 * decode. Returns the decoded response's payload bytes on a transport
 * status of Ok; a non-Ok status becomes LRP_ERR_SERVER. */
int lrp_rpc_call(lrp_transport *transport, const lrp_domain_endpoint *endpoint, const char *service,
                  const char *op, const uint8_t *payload, size_t payload_len, lrp_bytes *out_payload,
                  lrp_error *err);

/* Fetch `domain`'s currently-trusted public keys (DomainKeys/get-domain-keys),
 * pinned to the domain's DNS `fp=` set, with signing keys pinned directly
 * and encryption keys trusted only via a pinned signing key's vouch. When
 * the response signals recent_revocations_available, also best-effort
 * fetches DomainKeys/get-revocations and drops any key a quorum-verified
 * sibling revocation certificate targets. An empty trusted result is
 * LRP_ERR_NO_TRUSTED_KEYS — fail closed. */
int lrp_fetch_domain_keys(lrp_transport *transport, lrp_dns_resolver *dns, const char *domain,
                           lrp_domain_public_key **out_keys, size_t *out_count, lrp_error *err);

/* Redeem a claim ticket with `domain`'s IDP (LocalRp/redeem-claim-ticket),
 * pinned via the domain's DNS `fp=` set. Unauthenticated at the transport
 * layer (no client cert) — the redemption request itself is signed with
 * the local RP's signing key, which is the possession proof the server
 * checks. */
int lrp_redeem_claim_ticket(lrp_transport *transport, lrp_dns_resolver *dns, const char *domain,
                             const uint8_t *signed_request, size_t signed_request_len,
                             lrp_w_ticket_redemption_response *out, lrp_error *err);

#endif
