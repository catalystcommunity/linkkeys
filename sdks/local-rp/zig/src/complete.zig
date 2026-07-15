//! `completeLocalLogin` (design doc: "SDK API Shape", "Flow" steps 12-13).
//! Mirrors `sdks/local-rp/rust/src/complete.rs` / `sdks/local-rp/go/complete.go`.
//!
//! This is the SDK's full verification chain, run in the exact order the
//! pure protocol helpers require:
//!
//!  1. decode the callback ciphertext from its URL-param encoding
//!  2. open it (decrypt) — only with a suite this identity's own descriptor
//!     advertises
//!  3. fetch the pending domain's public keys + revocations, DNS-fp-pinned,
//!     over TCP CSIL-RPC
//!  4. verify the domain-signed envelope (key lookup, revocation/expiry,
//!     signature, payload timestamp bounds) — only now is anything inside
//!     the payload trusted
//!  5. cross-check the cleartext header's routing fields against the
//!     now-verified payload
//!  6. audience / issuer / callback-URL / nonce-state checks
//!  7. redeem the claim ticket over TCP CSIL-RPC (signed with the local RP's
//!     own key — the possession proof)
//!  8. verify every returned claim's signatures against ITS signer domain's
//!     keys (fetched the same pinned way), which also checks the claim's
//!     own revocation/expiry

const std = @import("std");
const types = @import("types.zig");
const identity = @import("identity.zig");
const begin = @import("begin.zig");
const local_rp = @import("local_rp.zig");
const encoding = @import("encoding.zig");
const xcrypto = @import("crypto.zig");
const dnsmod = @import("dns.zig");
const rpc = @import("rpc.zig");
const claims = @import("claims.zig");
const transportmod = @import("transport.zig");

/// Bounds the number of distinct claim-signer domains `completeLocalLogin`
/// will fetch keys for per completion. The redemption response's claim
/// signatures name their signing domains as plain, not-yet-verified
/// strings — a malicious/compromised home IDP could otherwise list an
/// unbounded number of distinct "signer domains" purely to make this SDK
/// perform many outbound DNS/TCP calls to attacker-chosen targets before any
/// signature is actually checked (an SSRF/DoS amplification vector against
/// the app's own process). A legitimate claim set names very few (typically
/// one: the home domain).
pub const max_claim_signer_domains: usize = 8;

/// Input to `completeLocalLogin`. Every field is load-bearing (design doc:
/// "complete_local_login inputs, spelled out because every one is
/// load-bearing").
pub const CompleteLocalLoginConfig = struct {
    /// The same identity `beginLocalLogin` used.
    key_material: identity.LocalRpKeyMaterial,
    /// The pending-login state `beginLocalLogin` returned, exactly as the
    /// app persisted it. The app must treat this as single-use; this
    /// package owns no storage and cannot enforce that itself.
    pending: begin.PendingLogin,
    /// The raw callback data — the `encrypted_token` query-parameter value
    /// (base64url CBOR `LocalRpEncryptedCallback`).
    encrypted_token: []const u8,
    /// The URL the callback actually arrived at (the app's own HTTP
    /// handler's request URL, including the `encrypted_token` query
    /// parameter this package strips before comparing against the signed
    /// payload's `callback_url`).
    arrived_url: []const u8,
    now: i64,
    /// Clock-skew tolerance for timestamp checks. Defaults to
    /// `local_rp.default_clock_skew_seconds` (±300s) when zero.
    clock_skew_seconds: i64 = 0,
    /// The TCP dial seam.
    transport: transportmod.Transport,
    /// The pinned-TLS dial seam. Defaults to `rpc.defaultSecureDial`, which
    /// always fails closed (see `rpc.zig`'s and `tls_pin.zig`'s module
    /// docs, and this SDK's README, for why).
    secure_dial: rpc.SecureDial = rpc.defaultSecureDial,
    /// The DNS TXT lookup seam.
    dns: dnsmod.DnsResolver,
};

/// What `completeLocalLogin` returns to app code (design doc: "SDKs ...
/// should either return verified results or call registered callbacks
/// with:" — this package returns rather than calling back).
pub const VerifiedLocalLogin = struct {
    user_id: []const u8,
    user_domain: []const u8,
    /// Verified claim values, current as of ticket redemption (design doc:
    /// "Ticket semantics" — the claim *set* is frozen at consent, but each
    /// redemption returns current *values*).
    claims: []const types.Claim,
    /// The user's home domain's public keys used to verify the callback
    /// envelope (audit/logging context — never the whole trusted set for
    /// every claim signer domain).
    domain_public_keys: []const types.DomainPublicKey,
    local_rp_fingerprint: []const u8,
    issued_at: i64,
    expires_at: i64,
    /// The ticket's own expiry (design doc: "Valid for a bounded window,
    /// default 1 hour. Multi-use within the window").
    ticket_expires_at: i64,
};

/// Undoes the exact `?`/`&` + `encrypted_token=` suffix construction the
/// server uses to deliver the callback, so the recovered value can be
/// compared against the signed payload's `callback_url`. If `arrived_url`
/// doesn't end with that exact suffix, returns it unchanged — the
/// subsequent `verifyCallbackUrl` equality check will then correctly fail
/// closed rather than this function guessing.
fn stripEncryptedTokenParam(arrived_url: []const u8) []const u8 {
    inline for (.{ "?", "&" }) |sep| {
        const marker = sep ++ "encrypted_token=";
        if (std.mem.lastIndexOf(u8, arrived_url, marker)) |idx| return arrived_url[0..idx];
    }
    return arrived_url;
}

/// Implements `complete_local_login(config) -> VerifiedLocalLogin` (design
/// doc, "SDK API Shape"). See this module's docs for the exact verification
/// order.
pub fn completeLocalLogin(allocator: std.mem.Allocator, config: CompleteLocalLoginConfig) !VerifiedLocalLogin {
    const skew = if (config.clock_skew_seconds == 0) local_rp.default_clock_skew_seconds else config.clock_skew_seconds;

    // 1. Decode the callback's URL-param encoding.
    const encrypted = try encoding.localRpEncryptedCallbackFromUrlParam(allocator, config.encrypted_token);

    // 2. Open it, restricted to suites THIS identity's own descriptor
    // advertises (Wire Precision: "The SDK must decrypt only with a suite
    // listed in its own descriptor").
    const own_descriptor = try types.decodeLocalRpDescriptor(allocator, config.key_material.descriptor.descriptor);
    var allowed_suites = std.ArrayList(xcrypto.AeadSuite).init(allocator);
    for (own_descriptor.supported_suites) |s| {
        if (xcrypto.parseAeadSuite(s)) |suite| try allowed_suites.append(suite);
    }

    const opened = try local_rp.openLocalRpCallback(allocator, encrypted, config.key_material.encryption_private_key, allowed_suites.items);

    // 3. Fetch the PENDING state's domain's keys + revocations, DNS-pinned,
    // over TCP CSIL-RPC (design doc: "fetches domain public keys and
    // revocations for the domain the login was begun with").
    const user_domain_keys = try rpc.fetchDomainKeys(allocator, config.transport, config.secure_dial, config.dns, config.pending.user_domain);

    // 4. Verify the domain-signed envelope against those keys. Nothing
    // inside the payload is trusted before this succeeds.
    const payload = try local_rp.verifyLocalRpCallbackPayload(allocator, opened.signed_payload, user_domain_keys, config.now, skew);

    // 5. Cross-check the cleartext header's routing twins against the
    // now-verified payload.
    try local_rp.checkCallbackHeaderMatchesPayload(opened.header, payload);

    // 6a. Audience: the callback names THIS local RP.
    try local_rp.verifyAudience(payload.audience_fingerprint, config.key_material.fingerprint);

    // 6b. Issuer binding: the payload's user_domain must be the domain the
    // login was BEGUN with, not merely whichever domain's keys happened to
    // verify.
    try local_rp.verifyIssuer(payload.user_domain, config.pending.user_domain);

    // 6c. Callback URL binding against the URL the callback actually
    // arrived at.
    const arrived_base_url = stripEncryptedTokenParam(config.arrived_url);
    try local_rp.verifyCallbackUrl(payload.callback_url, arrived_base_url);

    // 6d. Nonce/state equality against the pending state.
    try local_rp.verifyNonceState(config.pending.nonce, config.pending.state, payload.nonce, payload.state);

    // 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the local
    // RP's own key (the possession proof a stolen ticket can't satisfy).
    var now_buf: [32]u8 = undefined;
    const now_str = try local_rp.formatTimestamp(&now_buf, config.now);
    const redemption_request = local_rp.buildLocalRpTicketRedemptionRequest(payload.claim_ticket, config.key_material.fingerprint, now_str);
    const signed_redemption = try local_rp.signLocalRpTicketRedemptionRequest(allocator, redemption_request, config.key_material.signing_private_key);

    const redemption = try rpc.redeemClaimTicket(allocator, config.transport, config.secure_dial, config.dns, config.pending.user_domain, signed_redemption);

    // 7a. Identity binding (SEC fix): the ticket redemption response carries
    // no signature of its own — it is trusted only because it was fetched
    // over the DNS-pinned channel for the domain the SIGNED callback payload
    // named. That is not the same as the redemption response actually
    // agreeing with the payload: a compromised/malicious IDP could hand back
    // claims for a different user than the one it cryptographically vouched
    // for in the signed callback (e.g. to launder an approval given to user
    // A onto user B's claims). Cross-check unconditionally, and treat any
    // mismatch as fatal — never fall back to either identity alone.
    if (!std.mem.eql(u8, redemption.user_id, payload.user_id) or !std.mem.eql(u8, redemption.user_domain, payload.user_domain)) {
        return error.IdentityMismatch;
    }

    // 8. Verify every returned claim's signatures against ITS signer
    // domain's keys, fetched the same pinned way (a claim may be attested
    // by a domain other than the user's home domain). Reuse the home
    // domain's already-fetched keys; fetch any additional signer domains
    // on demand, capped.
    var domain_key_sets = std.ArrayList(claims.DomainKeySet).init(allocator);
    try domain_key_sets.append(.{ .domain = config.pending.user_domain, .keys = user_domain_keys });

    for (redemption.claims) |claim| {
        for (claim.signatures) |sig| {
            var found = false;
            for (domain_key_sets.items) |s| {
                if (std.mem.eql(u8, s.domain, sig.domain)) {
                    found = true;
                    break;
                }
            }
            if (found) continue;
            if (domain_key_sets.items.len >= max_claim_signer_domains) return error.TooManyClaimSignerDomains;
            const keys = try rpc.fetchDomainKeys(allocator, config.transport, config.secure_dial, config.dns, sig.domain);
            try domain_key_sets.append(.{ .domain = sig.domain, .keys = keys });
        }
    }
    // Each claim must also name the SAME user the signed payload vouched
    // for — without this, a malicious IDP could splice in a claim belonging
    // to a different user_id inside an otherwise-valid, correctly-signed
    // redemption response (the claim's own signature only proves the
    // issuing domain signed *that* claim, not that it's the claim for *this*
    // login). Checked BEFORE signature verification, and against
    // `payload.user_id`/`payload.user_domain` — the VERIFIED, SIGNED source
    // of truth, never `redemption.user_id`/`user_domain` (equal at this
    // point, but the payload is what was actually cryptographically
    // attested).
    for (redemption.claims) |claim| {
        if (!std.mem.eql(u8, claim.user_id, payload.user_id)) return error.IdentityMismatch;
        try claims.verifyClaim(allocator, claim, payload.user_domain, domain_key_sets.items);
    }

    // Enforce the required_claims the login was BEGUN with (SEC checklist:
    // "the app-declared required claims are actually enforced"). Only claim
    // types that survived the loop above count — an unsigned/unverifiable
    // claim can never satisfy a requirement (if any claim above had failed
    // verification, this function would already have returned an error
    // before reaching here). An empty or insufficient claim set against a
    // non-empty requirement is fatal.
    var verified_claim_types = std.StringHashMap(void).init(allocator);
    defer verified_claim_types.deinit();
    for (redemption.claims) |claim| try verified_claim_types.put(claim.claim_type, {});
    for (config.pending.required_claims) |required| {
        if (!verified_claim_types.contains(required)) return error.RequiredClaimsNotSatisfied;
    }

    return .{
        // Sourced from the VERIFIED, SIGNED payload — not the redemption
        // response — even though the two are now known to agree (checked
        // above). The payload is the thing that was actually
        // cryptographically attested by the domain; the redemption response
        // is merely corroborating data fetched over a channel that is
        // pinned but otherwise unsigned.
        .user_id = payload.user_id,
        .user_domain = payload.user_domain,
        .claims = redemption.claims,
        .domain_public_keys = user_domain_keys,
        .local_rp_fingerprint = config.key_material.fingerprint,
        .issued_at = try local_rp.parseTimestamp(payload.issued_at),
        .expires_at = try local_rp.parseTimestamp(payload.expires_at),
        .ticket_expires_at = try local_rp.parseTimestamp(redemption.ticket_expires_at),
    };
}

test "stripEncryptedTokenParam strips the exact suffix, leaves other URLs unchanged" {
    try std.testing.expectEqualStrings("http://x/callback", stripEncryptedTokenParam("http://x/callback?encrypted_token=abc"));
    try std.testing.expectEqualStrings("http://x/callback?foo=bar", stripEncryptedTokenParam("http://x/callback?foo=bar&encrypted_token=abc"));
    try std.testing.expectEqualStrings("http://x/callback", stripEncryptedTokenParam("http://x/callback"));
}
