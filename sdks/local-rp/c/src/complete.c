/* complete_local_login (design doc: "SDK API Shape", "Flow" steps 12-13).
 * See the module docs in `sdks/local-rp/rust/src/complete.rs` for the
 * full rationale of this exact verification order; this file follows it
 * step for step. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"
#include "claims.h"
#include "encoding.h"
#include "error.h"
#include "local_rp.h"
#include "rpc.h"
#include "time_util.h"

/* Bound on the number of distinct claim-signer domains this call will
 * fetch keys for, mirroring the reference SDKs: an unbounded list would
 * let a malicious/compromised home IDP drive this process into many
 * outbound DNS/TCP calls to attacker-chosen targets (SSRF/DoS
 * amplification) before any signature is even checked. */
#define MAX_CLAIM_SIGNER_DOMAINS 8

void lrp_verified_login_free(lrp_verified_login *v) {
    if (v == NULL) return;
    lrp_str_free(&v->user_id);
    lrp_str_free(&v->user_domain);
    lrp_claims_array_free(v->claims, v->claims_count);
    lrp_domain_public_keys_array_free(v->domain_public_keys, v->domain_public_keys_count);
    memset(v, 0, sizeof(*v));
}

/* Undo the `?`/`&` + `encrypted_token=` suffix the IDP appends to deliver
 * the callback, so the recovered value can be compared against the signed
 * payload's callback_url. If the arrived URL doesn't end with that exact
 * suffix, returns a copy unchanged — the subsequent verify_callback_url
 * equality check then correctly fails closed rather than this function
 * guessing. Caller frees the result. */
static char *strip_encrypted_token_param(const char *arrived_url) {
    const char *markers[2] = {"?encrypted_token=", "&encrypted_token="};
    for (int i = 0; i < 2; i++) {
        const char *found = NULL;
        const char *scan = arrived_url;
        while ((scan = strstr(scan, markers[i])) != NULL) {
            found = scan;
            scan += 1;
        }
        if (found != NULL) {
            size_t len = (size_t)(found - arrived_url);
            char *out = (char *)malloc(len + 1);
            memcpy(out, arrived_url, len);
            out[len] = '\0';
            return out;
        }
    }
    return strdup(arrived_url);
}

static int get_own_allowed_suites(const lrp_identity *identity, char ***out_suites,
                                   size_t *out_count, lrp_error *err) {
    cbor_value *root = NULL;
    if (cbor_decode(identity->descriptor_cbor.data, identity->descriptor_cbor.len, &root, err) !=
        0) {
        return -1;
    }
    const cbor_value *arr = cbor_map_get(root, "supported_suites");
    if (arr == NULL || arr->type != CBOR_T_ARRAY) {
        cbor_value_free(root);
        free(root);
        return lrp_fail(err, LRP_ERR_DECODE, "own descriptor: missing supported_suites");
    }
    char **suites = (char **)calloc(arr->items_len > 0 ? arr->items_len : 1, sizeof(char *));
    size_t n = 0;
    for (size_t i = 0; i < arr->items_len; i++) {
        if (arr->items[i].type == CBOR_T_TEXT) {
            suites[n++] = strdup((const char *)arr->items[i].bytes);
        }
    }
    cbor_value_free(root);
    free(root);
    *out_suites = suites;
    *out_count = n;
    return 0;
}

static void free_string_array(char **arr, size_t n) {
    for (size_t i = 0; i < n; i++) free(arr[i]);
    free(arr);
}

int lrp_complete_local_login(const lrp_complete_login_config *config, lrp_verified_login *out,
                              lrp_error *err) {
    memset(out, 0, sizeof(*out));
    if (config->identity == NULL || config->pending == NULL || config->encrypted_token == NULL ||
        config->arrived_url == NULL) {
        return lrp_fail(err, LRP_ERR_INVALID_INPUT,
                         "identity, pending, encrypted_token, and arrived_url are all required");
    }
    int64_t skew =
        config->clock_skew_seconds > 0 ? config->clock_skew_seconds : LRP_DEFAULT_CLOCK_SKEW_SECONDS;

    lrp_transport default_transport_storage = lrp_default_transport(LRP_ADDRESS_PERMISSIVE);
    lrp_dns_resolver default_dns_storage = lrp_default_dns_resolver();
    lrp_transport *transport = config->transport != NULL ? config->transport : &default_transport_storage;
    lrp_dns_resolver *dns = config->dns != NULL ? config->dns : &default_dns_storage;

    /* 1. Decode the callback's URL-param encoding. */
    lrp_bytes encrypted_cbor = {0};
    if (lrp_base64url_decode(config->encrypted_token, &encrypted_cbor, err) != 0) return -1;
    lrp_w_encrypted_callback encrypted = {0};
    int rc = lrp_decode_encrypted_callback(encrypted_cbor.data, encrypted_cbor.len, &encrypted, err);
    lrp_bytes_free(&encrypted_cbor);
    if (rc != 0) return -1;

    /* 2. Open it, restricted to THIS identity's own advertised suites. */
    char **allowed_suites = NULL;
    size_t allowed_suites_count = 0;
    if (get_own_allowed_suites(config->identity, &allowed_suites, &allowed_suites_count, err) != 0) {
        lrp_w_encrypted_callback_free(&encrypted);
        return -1;
    }
    lrp_w_callback_header header = {0};
    lrp_w_signed_callback_payload signed_payload = {0};
    rc = lrp_open_local_rp_callback(encrypted.header.data, encrypted.header.len,
                                     encrypted.ciphertext.data, encrypted.ciphertext.len,
                                     config->identity->encryption_private_key,
                                     config->identity->encryption_public_key,
                                     (const char *const *)allowed_suites, allowed_suites_count,
                                     &header, &signed_payload, err);
    free_string_array(allowed_suites, allowed_suites_count);
    lrp_w_encrypted_callback_free(&encrypted);
    if (rc != 0) return -1;

    /* 3. Fetch the PENDING state's domain's keys + revocations, DNS-pinned. */
    lrp_domain_public_key *user_domain_keys = NULL;
    size_t user_domain_keys_count = 0;
    rc = lrp_fetch_domain_keys(transport, dns, config->pending->user_domain.data, &user_domain_keys,
                                &user_domain_keys_count, err);
    if (rc != 0) {
        lrp_w_callback_header_free(&header);
        lrp_w_signed_callback_payload_free(&signed_payload);
        return -1;
    }

    /* 4. Verify the domain-signed envelope. Nothing inside `payload` is
     * trusted before this succeeds. */
    lrp_w_callback_payload payload = {0};
    rc = lrp_verify_local_rp_callback_payload(&signed_payload, user_domain_keys,
                                               user_domain_keys_count, config->now_unix, skew,
                                               &payload, err);
    lrp_w_signed_callback_payload_free(&signed_payload);
    if (rc != 0) {
        lrp_w_callback_header_free(&header);
        goto fail_after_domain_keys;
    }

    /* 5. Cross-check the cleartext header's routing twins. */
    {
        int match_rc = lrp_check_callback_header_matches_payload(&header, &payload, err);
        lrp_w_callback_header_free(&header);
        if (match_rc != 0) goto fail_payload;
    }

    /* 6a. Audience. */
    if (lrp_verify_audience(payload.audience_fingerprint.data, config->identity->fingerprint, err) !=
        0) {
        goto fail_payload;
    }
    /* 6b. Issuer binding. */
    if (lrp_verify_issuer(payload.user_domain.data, config->pending->user_domain.data, err) != 0) {
        goto fail_payload;
    }
    /* 6c. Callback URL binding against the URL the callback actually arrived at. */
    {
        char *arrived_base_url = strip_encrypted_token_param(config->arrived_url);
        int vrc = lrp_verify_callback_url(payload.callback_url.data, arrived_base_url, err);
        free(arrived_base_url);
        if (vrc != 0) goto fail_payload;
    }
    /* 6d. Nonce/state equality against the pending state. */
    if (lrp_verify_nonce_state(config->pending->nonce.data, config->pending->nonce.len,
                                config->pending->state.data, config->pending->state.len,
                                payload.nonce.data, payload.nonce.len, payload.state.data,
                                payload.state.len, err) != 0) {
        goto fail_payload;
    }

    /* 7. Redeem the claim ticket, signed with the local RP's own key. */
    char redeem_issued_at[32];
    lrp_format_rfc3339(config->now_unix, redeem_issued_at);
    lrp_bytes redemption_req = {0};
    rc = lrp_encode_ticket_redemption_request(payload.claim_ticket.data, payload.claim_ticket.len,
                                               config->identity->fingerprint, redeem_issued_at,
                                               &redemption_req, err);
    if (rc != 0) goto fail_payload;
    lrp_bytes redemption_sig = {0};
    rc = lrp_sign_envelope(LRP_CTX_TICKET_REDEMPTION, redemption_req.data, redemption_req.len,
                            config->identity->signing_private_key, &redemption_sig, err);
    if (rc != 0) {
        lrp_bytes_free(&redemption_req);
        goto fail_payload;
    }
    lrp_bytes signed_redemption = {0};
    {
        cbor_buf sb;
        cbor_buf_init(&sb);
        int wrc = 0;
        wrc |= cbor_write_map_header(&sb, 2);
        wrc |= cbor_write_text_cstr(&sb, "request");
        wrc |= cbor_write_bytes(&sb, redemption_req.data, redemption_req.len);
        wrc |= cbor_write_text_cstr(&sb, "signature");
        wrc |= cbor_write_bytes(&sb, redemption_sig.data, redemption_sig.len);
        lrp_bytes_free(&redemption_req);
        lrp_bytes_free(&redemption_sig);
        if (wrc != 0) {
            cbor_buf_free(&sb);
            lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "encode signed ticket redemption: out of memory");
            goto fail_payload;
        }
        signed_redemption = cbor_buf_release(&sb);
    }
    lrp_w_ticket_redemption_response redemption = {0};
    rc = lrp_redeem_claim_ticket(transport, dns, config->pending->user_domain.data,
                                  signed_redemption.data, signed_redemption.len, &redemption, err);
    lrp_bytes_free(&signed_redemption);
    if (rc != 0) goto fail_payload;

    /* 7a. Identity binding (SEC fix): the ticket redemption response
     * carries no signature of its own — it is trusted only because it was
     * fetched over the DNS-pinned TLS channel for the domain the SIGNED
     * callback payload named. That is not the same as the redemption
     * response actually agreeing with the payload: a compromised/malicious
     * IDP could hand back claims for a different user than the one it
     * cryptographically vouched for in the signed callback (e.g. to
     * launder consent given to user A onto user B's claims). Cross-check
     * unconditionally; any mismatch is FATAL — never fall back to either
     * identity alone. */
    if (strcmp(redemption.user_id.data, payload.user_id.data) != 0 ||
        strcmp(redemption.user_domain.data, payload.user_domain.data) != 0) {
        lrp_fail(err, LRP_ERR_VERIFICATION,
                 "ticket redemption identity does not match the signed callback payload's identity");
        goto fail_redemption;
    }

    /* 8. Verify every returned claim's signatures against ITS signer
     * domain's keys, capped to avoid unbounded outbound fetches driven by
     * an untrusted claim set. */
    {
        lrp_domain_key_set sets[MAX_CLAIM_SIGNER_DOMAINS];
        int owns_keys[MAX_CLAIM_SIGNER_DOMAINS] = {0};
        lrp_domain_public_key *owned_arrays[MAX_CLAIM_SIGNER_DOMAINS] = {0};
        size_t owned_counts[MAX_CLAIM_SIGNER_DOMAINS] = {0};
        size_t sets_n = 1;
        sets[0].domain = config->pending->user_domain.data;
        sets[0].keys = user_domain_keys;
        sets[0].keys_count = user_domain_keys_count;

        int fetch_failed = 0;
        for (size_t c = 0; c < redemption.claims_count && !fetch_failed; c++) {
            for (size_t s = 0; s < redemption.claims[c].signatures_count && !fetch_failed; s++) {
                const char *sig_domain = redemption.claims[c].signatures[s].domain.data;
                int found = 0;
                for (size_t i = 0; i < sets_n; i++) {
                    if (strcmp(sets[i].domain, sig_domain) == 0) {
                        found = 1;
                        break;
                    }
                }
                if (found) continue;
                if (sets_n >= MAX_CLAIM_SIGNER_DOMAINS) {
                    lrp_fail(err, LRP_ERR_INVALID_INPUT,
                             "claim set names more than %d distinct signer domains; refusing to "
                             "fetch further keys",
                             MAX_CLAIM_SIGNER_DOMAINS);
                    fetch_failed = 1;
                    break;
                }
                lrp_domain_public_key *fetched = NULL;
                size_t fetched_count = 0;
                if (lrp_fetch_domain_keys(transport, dns, sig_domain, &fetched, &fetched_count,
                                           err) != 0) {
                    fetch_failed = 1;
                    break;
                }
                owned_arrays[sets_n] = fetched;
                owned_counts[sets_n] = fetched_count;
                owns_keys[sets_n] = 1;
                sets[sets_n].domain = sig_domain;
                sets[sets_n].keys = fetched;
                sets[sets_n].keys_count = fetched_count;
                sets_n++;
            }
        }

        int verify_failed = 0;
        if (!fetch_failed) {
            for (size_t c = 0; c < redemption.claims_count; c++) {
                /* Each claim must also name the SAME user the signed
                 * payload vouched for — checked BEFORE signature
                 * verification (SEC fix): without this, a malicious IDP
                 * could splice in a claim belonging to a different user_id
                 * inside an otherwise-valid, correctly-signed redemption
                 * response (the claim's own signature only proves the
                 * issuing domain signed *that* claim, not that it's the
                 * claim for *this* login). Checked against
                 * `payload.user_id` — the SIGNED source of truth (equal to
                 * `redemption.user_id` at this point per the 7a check
                 * above, but the payload is what was actually
                 * cryptographically attested). */
                if (strcmp(redemption.claims[c].user_id.data, payload.user_id.data) != 0) {
                    lrp_fail(err, LRP_ERR_VERIFICATION,
                             "claim %s names a user_id that does not match the signed callback "
                             "payload's subject",
                             redemption.claims[c].claim_id.data);
                    verify_failed = 1;
                    break;
                }
                /* Subject domain is the VERIFIED payload's user_domain, not
                 * the unverified redemption response's copy (SEC fix — the
                 * two are known-equal per the 7a check above, but the
                 * payload is the authoritative, signed source). */
                if (lrp_verify_claim(&redemption.claims[c], payload.user_domain.data, sets, sets_n,
                                      err) != 0) {
                    verify_failed = 1;
                    break;
                }
            }
        }

        for (size_t i = 1; i < sets_n; i++) {
            if (owns_keys[i]) lrp_domain_public_keys_array_free(owned_arrays[i], owned_counts[i]);
        }

        if (fetch_failed || verify_failed) {
            lrp_w_ticket_redemption_response_free(&redemption);
            lrp_w_callback_payload_free(&payload);
            lrp_domain_public_keys_array_free(user_domain_keys, user_domain_keys_count);
            return -1;
        }
    }

    /* Enforce the required_claims the login was BEGUN with (SEC fix: the
     * app-declared required claims are actually enforced). Only claim
     * types that survived the full verification above (identity match +
     * signature quorum + not revoked/expired) count — an
     * unsigned/unverifiable claim can never satisfy a requirement. An
     * empty or insufficient claim set against a non-empty requirement is
     * FATAL. */
    for (size_t i = 0; i < config->pending->required_claims_count; i++) {
        const char *want = config->pending->required_claims[i];
        int have = 0;
        for (size_t c = 0; c < redemption.claims_count; c++) {
            if (strcmp(redemption.claims[c].claim_type.data, want) == 0) {
                have = 1;
                break;
            }
        }
        if (!have) {
            lrp_fail(err, LRP_ERR_VERIFICATION,
                     "required claim type not satisfied by any verified claim: %s", want);
            goto fail_redemption;
        }
    }

    /* Success: populate the output, transferring ownership. user_id/
     * user_domain are sourced from the VERIFIED, SIGNED payload (SEC fix)
     * — not the redemption response — even though the two are now known to
     * agree (checked in 7a above). The payload is the thing actually
     * cryptographically attested by the domain; the redemption response is
     * merely corroborating data fetched over a channel that is pinned but
     * otherwise unsigned. */
    out->user_id = payload.user_id;
    payload.user_id.data = NULL;
    out->user_domain = payload.user_domain;
    payload.user_domain.data = NULL;
    out->claims = redemption.claims;
    out->claims_count = redemption.claims_count;
    redemption.claims = NULL;
    redemption.claims_count = 0;
    out->domain_public_keys = user_domain_keys;
    out->domain_public_keys_count = user_domain_keys_count;
    snprintf(out->local_rp_fingerprint, sizeof(out->local_rp_fingerprint), "%s",
             config->identity->fingerprint);

    lrp_parse_rfc3339(payload.issued_at.data, &out->issued_at_unix, NULL);
    lrp_parse_rfc3339(payload.expires_at.data, &out->expires_at_unix, NULL);
    lrp_parse_rfc3339(redemption.ticket_expires_at.data, &out->ticket_expires_at_unix, NULL);

    lrp_str_free(&redemption.ticket_expires_at);
    lrp_str_free(&redemption.user_id);
    lrp_str_free(&redemption.user_domain);
    lrp_w_callback_payload_free(&payload);
    return 0;

fail_redemption:
    lrp_w_ticket_redemption_response_free(&redemption);
fail_payload:
    lrp_w_callback_payload_free(&payload);
fail_after_domain_keys:
    lrp_domain_public_keys_array_free(user_domain_keys, user_domain_keys_count);
    return -1;
}
