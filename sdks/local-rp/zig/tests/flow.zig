//! Flow tests: `completeLocalLogin`'s full verification chain, end to end,
//! against a fake IDP spun up as a real local TCP server. Mirrors
//! `sdks/local-rp/go/flow_test.go` / `sdks/local-rp/rust/tests/flow.rs> with
//! one deliberate difference: **no TLS**. `rpc.zig`'s and `tls_pin.zig`'s
//! module docs (and this SDK's README) explain why pinned TLS cannot be
//! implemented on `std.crypto.tls.Client` in Zig 0.14.1 (it never exposes
//! the peer certificate needed for the mandatory SPKI pin check). This is
//! exactly the design doc's sanctioned fallback for a toolchain that can't
//! do pinned TLS: exercise the full CSIL-RPC + protocol verification chain
//! over a fake **plaintext** transport injected at the `Transport`/
//! `SecureDial` seam, while `tls_pin.zig`'s own tests cover the SPKI
//! pin-extraction logic in isolation against a real openssl-minted fixture.
//!
//! What IS real here: DNS TXT parsing/pinning, the CSIL-RPC request/response
//! envelope + 4-byte length-prefix stream framing, and the entire local-RP
//! protocol verification chain (envelope signatures, sealed-box open,
//! header/payload cross-check, audience/issuer/callback-url/nonce-state,
//! claim signature verification). Only "how do I get a secure byte stream
//! to the peer" is faked (skipped straight to plaintext), and the DNS
//! answers are canned rather than real lookups.
//!
//! Canned callback/ticket-redemption/domain-keys responses are built with
//! this package directly (the same package app code uses), using the same
//! fixed, publicly-known test key seeds as
//! `sdks/local-rp/conformance/keys.json` (local_rp.signing = 0x01 repeated,
//! local_rp.encryption = 0x02 repeated, domain_signing_key = 0x03 repeated)
//! so this test suite and the conformance vectors describe the same
//! identities.

const std = @import("std");
const lrp = @import("linkkeys_local_rp");

const local_rp_signing_seed = [_]u8{1} ** 32;
const local_rp_encryption_private = [_]u8{2} ** 32;
const domain_signing_seed = [_]u8{3} ** 32;

const domain_key_id = "test-domain-key-1";
const user_domain = "example.test";
const callback_url = "http://localhost/callback";

/// Bypasses pinned TLS entirely: just dials the raw transport and hands
/// back the plaintext stream. See this file's module docs for why.
fn plaintextSecureDial(transport: lrp.Transport, allocator: std.mem.Allocator, endpoint: lrp.rpc.DomainEndpoint) anyerror!std.net.Stream {
    _ = allocator;
    return transport.dial(endpoint.tcp_addr);
}

/// Canned DNS answers for exactly one domain.
const FakeDnsResolver = struct {
    linkkeys_txt: []const u8,
    apis_txt: []const u8,

    fn resolver(self: *FakeDnsResolver) lrp.DnsResolver {
        return .{ .ptr = self, .txtLookupFn = txtLookupImpl };
    }

    fn txtLookupImpl(ptr: *anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const []const u8 {
        const self: *FakeDnsResolver = @ptrCast(@alignCast(ptr));
        var out = std.ArrayList([]const u8).init(allocator);
        if (std.mem.eql(u8, name, "_linkkeys." ++ user_domain)) {
            try out.append(self.linkkeys_txt);
        } else if (std.mem.eql(u8, name, "_linkkeys_apis." ++ user_domain)) {
            try out.append(self.apis_txt);
        } else {
            return error.NoFakeRecordForName;
        }
        return out.toOwnedSlice();
    }
};

fn fixedKeyMaterial(a: std.mem.Allocator, now: i64) !lrp.LocalRpKeyMaterial {
    const signing_kp = try lrp.crypto.Ed25519.KeyPair.generateDeterministic(local_rp_signing_seed);
    const signing_pub = signing_kp.public_key.toBytes();
    const enc_pub = try lrp.crypto.X25519.recoverPublicKey(local_rp_encryption_private);

    var created_buf: [32]u8 = undefined;
    var expires_buf: [32]u8 = undefined;
    const created_at = try a.dupe(u8, try lrp.local_rp.formatTimestamp(&created_buf, now - 24 * 3600));
    const expires_at = try a.dupe(u8, try lrp.local_rp.formatTimestamp(&expires_buf, now + 3650 * 24 * 3600));

    const suites = [_][]const u8{ "aes-256-gcm", "chacha20-poly1305" };
    const descriptor = try lrp.local_rp.buildLocalRpDescriptor(a, "Flow Test App", null, signing_pub, enc_pub, &suites, created_at, expires_at);
    const fingerprint = descriptor.fingerprint;
    const signed_descriptor = try lrp.local_rp.signLocalRpDescriptor(a, descriptor, local_rp_signing_seed);

    return .{
        .signing_private_key = local_rp_signing_seed,
        .signing_public_key = signing_pub,
        .encryption_private_key = local_rp_encryption_private,
        .encryption_public_key = enc_pub,
        .descriptor = signed_descriptor,
        .fingerprint = fingerprint,
    };
}

fn domainPublicKeyFlowTest(a: std.mem.Allocator, now: i64) !lrp.types.DomainPublicKey {
    const kp = try lrp.crypto.Ed25519.KeyPair.generateDeterministic(domain_signing_seed);
    const pub_bytes = kp.public_key.toBytes();
    const fp = lrp.crypto.fingerprintHex(&pub_bytes);
    var created_buf: [32]u8 = undefined;
    var expires_buf: [32]u8 = undefined;
    return .{
        .key_id = domain_key_id,
        .public_key = try a.dupe(u8, &pub_bytes),
        .fingerprint = try a.dupe(u8, &fp),
        .algorithm = "ed25519",
        .key_usage = "sign",
        .created_at = try a.dupe(u8, try lrp.local_rp.formatTimestamp(&created_buf, now - 30 * 24 * 3600)),
        .expires_at = try a.dupe(u8, try lrp.local_rp.formatTimestamp(&expires_buf, now + 365 * 24 * 3600)),
    };
}

// ---------------------------------------------------------------------
// Fake IDP: a real plaintext TCP server for exactly N requests.
// ---------------------------------------------------------------------

const FakeIdpCtx = struct {
    server: std.net.Server,
    allocator: std.mem.Allocator,
    expected_requests: usize,
    domain_keys: []const lrp.types.DomainPublicKey,
    redemption: lrp.types.LocalRpTicketRedemptionResponse,
    /// Revocation certificates `DomainKeys/get-revocations` hands back.
    /// Empty by default (a well-behaved IDP with nothing to report).
    revocations: []const lrp.types.RevocationCertificate = &.{},
    /// When set, `DomainKeys/get-revocations` responds with an RPC-level
    /// error instead of a payload — simulates a hostile/broken IDP so tests
    /// can prove the fetch is FATAL (fail closed), never silently swallowed.
    fail_get_revocations: bool = false,
};

fn serveFakeIdp(ctx: *FakeIdpCtx) void {
    var i: usize = 0;
    while (i < ctx.expected_requests) : (i += 1) {
        const conn = ctx.server.accept() catch return;
        defer conn.stream.close();

        var arena = std.heap.ArenaAllocator.init(ctx.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const frame = lrp.rpc.readLengthPrefixed(a, conn.stream, lrp.rpc.max_frame_size) catch continue orelse continue;
        const req = lrp.rpc.decodeRpcRequest(a, frame) catch continue;

        var resp_bytes: []const u8 = undefined;
        if (std.mem.eql(u8, req.service, "DomainKeys") and std.mem.eql(u8, req.op, "get-domain-keys")) {
            const resp = lrp.types.GetDomainKeysResponse{ .domain = user_domain, .keys = ctx.domain_keys };
            const payload = a.dupe(u8, encodeGetDomainKeysResponseForTest(a, resp) catch continue) catch continue;
            resp_bytes = lrp.rpc.encodeRpcResponseOk(a, "GetDomainKeysResponse", payload) catch continue;
        } else if (std.mem.eql(u8, req.service, "DomainKeys") and std.mem.eql(u8, req.op, "get-revocations")) {
            if (ctx.fail_get_revocations) {
                resp_bytes = lrp.rpc.encodeRpcResponseError(a, 6, "simulated get-revocations failure") catch continue;
            } else {
                const payload = a.dupe(u8, encodeGetRevocationsResponseForTest(a, ctx.revocations) catch continue) catch continue;
                resp_bytes = lrp.rpc.encodeRpcResponseOk(a, "GetRevocationsResponse", payload) catch continue;
            }
        } else if (std.mem.eql(u8, req.service, "LocalRp") and std.mem.eql(u8, req.op, "redeem-claim-ticket")) {
            const payload = lrp.types.encodeLocalRpTicketRedemptionResponse(a, ctx.redemption) catch continue;
            resp_bytes = lrp.rpc.encodeRpcResponseOk(a, "LocalRpTicketRedemptionResponse", payload) catch continue;
        } else {
            resp_bytes = lrp.rpc.encodeRpcResponseError(a, 2, "fake IDP has no handler for this service/op") catch continue;
        }
        lrp.rpc.writeLengthPrefixed(conn.stream, resp_bytes) catch continue;
    }
}

fn encodeGetDomainKeysResponseForTest(a: std.mem.Allocator, resp: lrp.types.GetDomainKeysResponse) ![]u8 {
    // types.zig doesn't export an encoder for GetDomainKeysResponse (this
    // SDK only ever decodes it as a client) — build the CBOR map directly.
    const cbor = lrp.cbor;
    var keys_vals = try a.alloc(cbor.Value, resp.keys.len);
    for (resp.keys, 0..) |k, idx| {
        keys_vals[idx] = try lrp.types.domainPublicKeyToValue(a, k);
    }
    const entries = try a.alloc(cbor.Entry, 2);
    entries[0] = .{ .key = cbor.text("domain"), .value = cbor.text(resp.domain) };
    entries[1] = .{ .key = cbor.text("keys"), .value = cbor.arrayVal(keys_vals) };
    return cbor.encodeAlloc(a, cbor.mapVal(entries));
}

fn encodeGetRevocationsResponseForTest(a: std.mem.Allocator, revocations: []const lrp.types.RevocationCertificate) ![]u8 {
    // Same rationale as encodeGetDomainKeysResponseForTest: no client-side
    // encoder exists for a response type this SDK only ever decodes.
    const cbor = lrp.cbor;
    var certs_vals = try a.alloc(cbor.Value, revocations.len);
    for (revocations, 0..) |c, idx| {
        certs_vals[idx] = try lrp.types.revocationCertificateToValue(a, c);
    }
    const entries = try a.alloc(cbor.Entry, 1);
    entries[0] = .{ .key = cbor.text("revocations"), .value = cbor.arrayVal(certs_vals) };
    return cbor.encodeAlloc(a, cbor.mapVal(entries));
}

// ---------------------------------------------------------------------
// Scenario construction
// ---------------------------------------------------------------------

const Mutators = struct {
    mutate_payload: *const fn (payload: *lrp.types.LocalRpCallbackPayload) void = noOpPayload,
    mutate_domain_key: *const fn (key: *lrp.types.DomainPublicKey) void = noOpKey,
    mutate_claim: *const fn (claim: *lrp.types.Claim) void = noOpClaim,
    /// Applied to the fake IDP's ticket-redemption response after it's
    /// built, but BEFORE the signed callback payload is constructed — lets
    /// hostile-IDP tests make the redemption disagree with what the payload
    /// cryptographically vouched for.
    mutate_redemption: *const fn (redemption: *lrp.types.LocalRpTicketRedemptionResponse) void = noOpRedemption,
    dns_fingerprint_override: ?[]const u8 = null,
    /// Total RPC requests the fake IDP will accept before its listener
    /// closes. Default covers the full happy path: get-domain-keys +
    /// get-revocations (always fetched — SEC fix) + redeem-claim-ticket.
    expected_requests: usize = 3,
    /// The `user_id` the redemption's single claim is signed for. Defaults
    /// to the same user the payload names; hostile-IDP tests override this
    /// to a different value to prove the claim/payload identity-binding
    /// check is enforced.
    claim_user_id: []const u8 = "user-1",
    /// Overrides `beginLocalLogin`'s `required_claims`; `null` keeps the
    /// SDK default (`["handle"]`).
    required_claims: ?[]const []const u8 = null,
    /// Additional domain signing keys the fake IDP advertises (and that get
    /// DNS-pinned) alongside the primary one — used to build a quorum-valid
    /// revocation certificate against a sibling-signed key set.
    extra_domain_keys: []const lrp.types.DomainPublicKey = &.{},
    /// Revocation certificates the fake IDP's `get-revocations` hands back.
    revocations: []const lrp.types.RevocationCertificate = &.{},
    /// Makes the fake IDP's `get-revocations` respond with an RPC error.
    fail_get_revocations: bool = false,
};

fn noOpPayload(_: *lrp.types.LocalRpCallbackPayload) void {}
fn noOpKey(_: *lrp.types.DomainPublicKey) void {}
fn noOpClaim(_: *lrp.types.Claim) void {}
fn noOpRedemption(_: *lrp.types.LocalRpTicketRedemptionResponse) void {}

/// Comptime-evaluated, so these live in static read-only memory for the
/// whole program — safe to take `&` of from any mutator, at any time,
/// unlike a locally-constructed array literal (whose storage would be
/// scoped to the mutator function's own stack frame and dangle once it
/// returns).
fn repeatCharArray(comptime c: u8, comptime n: usize) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out) |*x| x.* = c;
    return out;
}
const bad_fingerprint_b: [64]u8 = repeatCharArray('b', 64);
const bad_fingerprint_c: [64]u8 = repeatCharArray('c', 64);
const bad_nonce_ee: [32]u8 = repeatCharArray(0xEE, 32);

fn runScenario(a: std.mem.Allocator, sc: Mutators) !lrp.VerifiedLocalLogin {
    const now: i64 = try lrp.local_rp.parseTimestamp("2026-06-01T00:00:00Z");
    const key_material = try fixedKeyMaterial(a, now);

    const begin_result = try lrp.beginLocalLogin(a, .{
        .key_material = key_material,
        .callback_url = callback_url,
        .user_domain = user_domain,
        .required_claims = sc.required_claims,
        .now = now,
    });
    const pending = begin_result.pending;

    var domain_key = try domainPublicKeyFlowTest(a, now);
    sc.mutate_domain_key(&domain_key);

    const claim_ticket = [_]u8{7} ** 32;
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;
    var payload = lrp.local_rp.buildLocalRpCallbackPayload(
        "user-1",
        user_domain,
        &claim_ticket,
        key_material.fingerprint,
        callback_url,
        pending.nonce,
        pending.state,
        try a.dupe(u8, try lrp.local_rp.formatTimestamp(&buf1, now)),
        try a.dupe(u8, try lrp.local_rp.formatTimestamp(&buf2, now + 5 * 60)),
    );
    sc.mutate_payload(&payload);

    const signed_payload = try lrp.local_rp.signLocalRpCallbackPayload(a, payload, domain_key_id, domain_signing_seed);

    const encrypted = try lrp.local_rp.sealLocalRpCallback(a, signed_payload, .aes_256_gcm, key_material.encryption_public_key, payload.audience_fingerprint, payload.nonce, payload.state, payload.issued_at, payload.expires_at);
    const encrypted_token = try lrp.encoding.localRpEncryptedCallbackToUrlParam(a, encrypted);
    const arrived_url = try std.fmt.allocPrint(a, "{s}?encrypted_token={s}", .{ callback_url, encrypted_token });

    var attested_buf: [32]u8 = undefined;
    var claim = try lrp.claims.signClaim(a, .{
        .claim_id = "claim-1",
        .claim_type = "handle",
        .claim_value = "flowtestuser",
        .user_id = sc.claim_user_id,
        .subject_domain = user_domain,
        .attested_at = try a.dupe(u8, try lrp.local_rp.formatTimestamp(&attested_buf, now)),
    }, &[_]lrp.claims.ClaimSigner{.{ .domain = user_domain, .key_id = domain_key_id, .private_key_seed = domain_signing_seed }}, try a.dupe(u8, try lrp.local_rp.formatTimestamp(&attested_buf, now)));
    sc.mutate_claim(&claim);

    var ticket_expires_buf: [32]u8 = undefined;
    var redemption = lrp.types.LocalRpTicketRedemptionResponse{
        .user_id = "user-1",
        .user_domain = user_domain,
        .claims = &[_]lrp.types.Claim{claim},
        .ticket_expires_at = try a.dupe(u8, try lrp.local_rp.formatTimestamp(&ticket_expires_buf, now + 3600)),
    };
    sc.mutate_redemption(&redemption);

    var domain_keys_list = std.ArrayList(lrp.types.DomainPublicKey).init(a);
    try domain_keys_list.append(domain_key);
    try domain_keys_list.appendSlice(sc.extra_domain_keys);

    const bind_addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try bind_addr.listen(.{ .reuse_address = true });
    var ctx = FakeIdpCtx{
        .server = server,
        .allocator = std.heap.page_allocator,
        .expected_requests = sc.expected_requests,
        .domain_keys = domain_keys_list.items,
        .redemption = redemption,
        .revocations = sc.revocations,
        .fail_get_revocations = sc.fail_get_revocations,
    };
    const thread = try std.Thread.spawn(.{}, serveFakeIdp, .{&ctx});
    defer thread.join();
    defer server.deinit();

    var addr_buf: [64]u8 = undefined;
    const addr_str = try std.fmt.bufPrint(&addr_buf, "{}", .{server.listen_address});
    const tcp_addr = try a.dupe(u8, addr_str);

    const real_fingerprint_arr = lrp.crypto.fingerprintHex(domain_key.public_key);

    var pinned_fingerprints_txt = std.ArrayList(u8).init(a);
    try pinned_fingerprints_txt.appendSlice("v=lk1");
    if (sc.dns_fingerprint_override) |ov| {
        try pinned_fingerprints_txt.appendSlice(" fp=");
        try pinned_fingerprints_txt.appendSlice(ov);
    } else {
        try pinned_fingerprints_txt.appendSlice(" fp=");
        try pinned_fingerprints_txt.appendSlice(&real_fingerprint_arr);
        for (sc.extra_domain_keys) |k| {
            const fp = lrp.crypto.fingerprintHex(k.public_key);
            try pinned_fingerprints_txt.appendSlice(" fp=");
            try pinned_fingerprints_txt.appendSlice(&fp);
        }
    }

    var dns_resolver = FakeDnsResolver{
        .linkkeys_txt = pinned_fingerprints_txt.items,
        .apis_txt = try std.fmt.allocPrint(a, "v=lk1 tcp={s}", .{tcp_addr}),
    };

    var std_transport = lrp.StdTransport{};

    return lrp.completeLocalLogin(a, .{
        .key_material = key_material,
        .pending = pending,
        .encrypted_token = encrypted_token,
        .arrived_url = arrived_url,
        .now = now,
        .transport = std_transport.transport(),
        .secure_dial = plaintextSecureDial,
        .dns = dns_resolver.resolver(),
    });
}

fn defaultScenario() Mutators {
    return .{};
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

test "happy path returns a verified login" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const verified = try runScenario(a, defaultScenario());
    try std.testing.expectEqualStrings("user-1", verified.user_id);
    try std.testing.expectEqualStrings(user_domain, verified.user_domain);
    try std.testing.expectEqual(@as(usize, 1), verified.claims.len);
    try std.testing.expectEqualStrings("handle", verified.claims[0].claim_type);
    try std.testing.expectEqual(@as(usize, 64), verified.local_rp_fingerprint.len);
    try std.testing.expectEqual(@as(usize, 1), verified.domain_public_keys.len);
}

test "wrong audience fingerprint is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    sc.mutate_payload = struct {
        fn f(p: *lrp.types.LocalRpCallbackPayload) void {
            p.audience_fingerprint = &bad_fingerprint_b;
        }
    }.f;
    // Fails during envelope verification (step 4/6a), which only happens
    // after fetchDomainKeys' now-mandatory get-domain-keys + get-revocations
    // pair (SEC fix B) both succeed.
    sc.expected_requests = 2;
    try std.testing.expectError(error.AudienceMismatch, runScenario(a, sc));
}

test "wrong issuer domain is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    sc.mutate_payload = struct {
        fn f(p: *lrp.types.LocalRpCallbackPayload) void {
            p.user_domain = "attacker.test";
        }
    }.f;
    sc.expected_requests = 2;
    try std.testing.expectError(error.IssuerMismatch, runScenario(a, sc));
}

test "nonce mismatch is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    sc.mutate_payload = struct {
        fn f(p: *lrp.types.LocalRpCallbackPayload) void {
            p.nonce = &bad_nonce_ee;
        }
    }.f;
    sc.expected_requests = 2;
    try std.testing.expectError(error.NonceMismatch, runScenario(a, sc));
}

test "expired callback payload is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    sc.mutate_payload = struct {
        fn f(p: *lrp.types.LocalRpCallbackPayload) void {
            p.issued_at = "2000-01-01T00:00:00Z";
            p.expires_at = "2000-01-01T00:05:00Z";
        }
    }.f;
    sc.expected_requests = 2;
    try std.testing.expectError(error.Expired, runScenario(a, sc));
}

test "DNS fingerprint pin mismatch is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    sc.dns_fingerprint_override = &bad_fingerprint_c;
    sc.expected_requests = 1;
    // Fails during trust establishment (the fake IDP's real key fingerprint
    // no longer matches the pinned set) — must never reach a verified
    // result.
    try std.testing.expectError(error.NoTrustedDomainKeys, runScenario(a, sc));
}

test "revoked signing key is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    sc.mutate_domain_key = struct {
        fn f(k: *lrp.types.DomainPublicKey) void {
            k.revoked_at = "2026-01-01T00:00:00Z";
        }
    }.f;
    sc.expected_requests = 2;
    try std.testing.expectError(error.KeyRevoked, runScenario(a, sc));
}

test "tampered claim signature is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    sc.mutate_claim = struct {
        fn f(c: *lrp.types.Claim) void {
            if (c.signatures.len > 0 and c.signatures[0].signature.len > 0) {
                const mutable_sig = @constCast(c.signatures[0].signature);
                mutable_sig[0] ^= 0xff;
            }
        }
    }.f;
    sc.expected_requests = 3;
    try std.testing.expectError(error.ClaimSignatureInvalid, runScenario(a, sc));
}

// ---------------------------------------------------------------------
// Hostile-IDP tests (FIX A / FIX B): a malicious or compromised home IDP
// that returns cryptographically well-formed but semantically hostile
// responses. Every one of these must be a FATAL rejection — never a
// downgrade to success.
// ---------------------------------------------------------------------

test "hostile IDP: ticket redemption identity mismatched from the signed callback payload is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    // The signed callback payload (checked cryptographically) says
    // "user-1"/example.test; the (unsigned, merely pinned-channel-trusted)
    // redemption response claims a different user entirely.
    sc.mutate_redemption = struct {
        fn f(r: *lrp.types.LocalRpTicketRedemptionResponse) void {
            r.user_id = "attacker-controlled-user";
        }
    }.f;
    sc.expected_requests = 3;
    try std.testing.expectError(error.IdentityMismatch, runScenario(a, sc));
}

test "hostile IDP: ticket redemption naming a different user_domain than the signed payload is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    sc.mutate_redemption = struct {
        fn f(r: *lrp.types.LocalRpTicketRedemptionResponse) void {
            r.user_domain = "attacker.test";
        }
    }.f;
    sc.expected_requests = 3;
    try std.testing.expectError(error.IdentityMismatch, runScenario(a, sc));
}

test "hostile IDP: a claim naming a different user_id than the signed payload is rejected even with a valid signature" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    // The claim is legitimately signed (for "user-2") — its own signature
    // verifies fine — but it does not belong to the user the signed
    // callback payload vouched for ("user-1"). A malicious IDP could
    // otherwise splice another user's claim into this login.
    sc.claim_user_id = "user-2";
    sc.expected_requests = 3;
    try std.testing.expectError(error.IdentityMismatch, runScenario(a, sc));
}

test "hostile IDP: an unsatisfied required claim is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    // The login was begun requiring "email", but the redemption only ever
    // returns a "handle" claim.
    sc.required_claims = &[_][]const u8{"email"};
    sc.expected_requests = 3;
    try std.testing.expectError(error.RequiredClaimsNotSatisfied, runScenario(a, sc));
}

test "hostile IDP: an empty claim set against a non-empty requirement is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    sc.mutate_redemption = struct {
        fn f(r: *lrp.types.LocalRpTicketRedemptionResponse) void {
            r.claims = &[_]lrp.types.Claim{};
        }
    }.f;
    // Default required_claims is ["handle"]; redemption now returns none.
    sc.expected_requests = 3;
    try std.testing.expectError(error.RequiredClaimsNotSatisfied, runScenario(a, sc));
}

test "hostile IDP: get-revocations failure fails the login closed rather than proceeding unfiltered" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var sc = defaultScenario();
    sc.fail_get_revocations = true;
    // get-domain-keys succeeds, then get-revocations fails — the login must
    // never reach redeem-claim-ticket.
    sc.expected_requests = 2;
    try std.testing.expectError(error.RpcInternal, runScenario(a, sc));
}

test "hostile IDP: a quorum-revoked signing key is rejected even though it originally signed the callback" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sibling_seed_1 = [_]u8{20} ** 32;
    const sibling_seed_2 = [_]u8{21} ** 32;
    const sib_kp1 = try lrp.crypto.Ed25519.KeyPair.generateDeterministic(sibling_seed_1);
    const sib_kp2 = try lrp.crypto.Ed25519.KeyPair.generateDeterministic(sibling_seed_2);
    const sib_pub1 = sib_kp1.public_key.toBytes();
    const sib_pub2 = sib_kp2.public_key.toBytes();
    const sib_fp1 = lrp.crypto.fingerprintHex(&sib_pub1);
    const sib_fp2 = lrp.crypto.fingerprintHex(&sib_pub2);

    const sibling1 = lrp.types.DomainPublicKey{
        .key_id = "sibling-1",
        .public_key = &sib_pub1,
        .fingerprint = &sib_fp1,
        .algorithm = "ed25519",
        .key_usage = "sign",
        .created_at = "2020-01-01T00:00:00Z",
        .expires_at = "2099-01-01T00:00:00Z",
    };
    const sibling2 = lrp.types.DomainPublicKey{
        .key_id = "sibling-2",
        .public_key = &sib_pub2,
        .fingerprint = &sib_fp2,
        .algorithm = "ed25519",
        .key_usage = "sign",
        .created_at = "2020-01-01T00:00:00Z",
        .expires_at = "2099-01-01T00:00:00Z",
    };

    const now: i64 = try lrp.local_rp.parseTimestamp("2026-06-01T00:00:00Z");
    var buf: [32]u8 = undefined;
    const revoked_at = try a.dupe(u8, try lrp.local_rp.formatTimestamp(&buf, now));

    // Recompute the primary domain signing key's real fingerprint the same
    // way domainPublicKeyFlowTest does, to target it precisely.
    const target_kp = try lrp.crypto.Ed25519.KeyPair.generateDeterministic(domain_signing_seed);
    const target_pub = target_kp.public_key.toBytes();
    const target_fp = lrp.crypto.fingerprintHex(&target_pub);

    const payload = try lrp.revocation.revocationPayload(a, domain_key_id, &target_fp, revoked_at, user_domain);
    const sig1 = try lrp.crypto.signEd25519(sibling_seed_1, payload);
    const sig2 = try lrp.crypto.signEd25519(sibling_seed_2, payload);

    const cert = lrp.types.RevocationCertificate{
        .target_key_id = domain_key_id,
        .target_fingerprint = &target_fp,
        .revoked_at = revoked_at,
        .signatures = &[_]lrp.types.ClaimSignature{
            .{ .domain = user_domain, .signed_by_key_id = "sibling-1", .signature = &sig1 },
            .{ .domain = user_domain, .signed_by_key_id = "sibling-2", .signature = &sig2 },
        },
    };

    var sc = defaultScenario();
    sc.extra_domain_keys = &[_]lrp.types.DomainPublicKey{ sibling1, sibling2 };
    sc.revocations = &[_]lrp.types.RevocationCertificate{cert};
    // get-domain-keys + get-revocations succeed, but the signing key the
    // callback was actually signed with gets filtered out by the verified
    // revocation certificate before envelope verification — the login must
    // never reach redeem-claim-ticket.
    sc.expected_requests = 2;
    try std.testing.expectError(error.KeyNotFound, runScenario(a, sc));
}
