//! Act-as grantee tests for the Zig local-RP SDK. No live network: DNS
//! answers are canned, and the refresh call goes to a fake IDP on loopback
//! through the plaintext `SecureDial` seam that `tests/flow.zig` uses (see
//! that file's module docs for why pinned TLS is not available here).
//!
//! The byte-exact vectors come from
//! `sdks/regular-rp/conformance/act_as_grantee_signing.json`, case
//! `local_rp_grantee` (the same vectors that
//! `crates/liblinkkeys/tests/act_as_conformance.rs` consumes).

const std = @import("std");
const lrp = @import("linkkeys_local_rp");
const build_options = @import("build_options");
const act_as = lrp.act_as;

const user_domain = "example.test";
/// The home domain of the vector's local-RP grant.
const grant_domain = "home.conformance.example";

// ---------------------------------------------------------------------
// Vector loading
// ---------------------------------------------------------------------

fn parseVectors(a: std.mem.Allocator) !std.json.Value {
    const path = try std.fs.path.join(a, &.{ build_options.regular_rp_conformance_dir, "act_as_grantee_signing.json" });
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const text = try file.readToEndAlloc(a, 8 * 1024 * 1024);
    return std.json.parseFromSliceLeaky(std.json.Value, a, text, .{});
}

fn get(v: std.json.Value, key: []const u8) std.json.Value {
    return v.object.get(key).?;
}
fn str(v: std.json.Value, key: []const u8) []const u8 {
    return get(v, key).string;
}
fn optInt(v: std.json.Value, key: []const u8) ?i64 {
    return switch (get(v, key)) {
        .integer => |n| n,
        else => null,
    };
}
fn hex(a: std.mem.Allocator, v: std.json.Value, key: []const u8) ![]u8 {
    return lrp.crypto.hexDecodeAlloc(a, str(v, key));
}

fn localRpCase(root: std.json.Value) !std.json.Value {
    for (get(root, "cases").array.items) |c| {
        if (std.mem.eql(u8, str(c, "name"), "local_rp_grantee")) return c;
    }
    return error.MissingVectorCase;
}

/// Key material for the vector's local RP. Only the signing seed, the
/// signed descriptor, and the fingerprint take part in grantee signing.
fn vectorKeyMaterial(a: std.mem.Allocator, root: std.json.Value) !lrp.LocalRpKeyMaterial {
    const local = get(root, "local_rp_grantee");
    const seed = try lrp.crypto.hexDecodeFixed(32, str(local, "signing_private_key_hex"));
    const kp = try lrp.crypto.Ed25519.KeyPair.generateDeterministic(seed);
    return .{
        .signing_private_key = seed,
        .signing_public_key = kp.public_key.toBytes(),
        .encryption_private_key = [_]u8{0} ** 32,
        .encryption_public_key = [_]u8{0} ** 32,
        .descriptor = try lrp.types.decodeSignedLocalRpDescriptor(a, try hex(a, local, "signed_descriptor_cbor_hex")),
        .fingerprint = str(local, "fingerprint"),
    };
}

// ---------------------------------------------------------------------
// Byte-exact vectors
// ---------------------------------------------------------------------

test "act_as_grantee_signing.json local_rp_grantee: grant request, refresh request, credential" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseVectors(a);
    const case = try localRpCase(root);
    const km = try vectorKeyMaterial(a, root);
    try std.testing.expectEqualStrings(str(get(case, "grantee"), "local_rp_descriptor_fingerprint"), km.fingerprint);

    // Grant request.
    const g = get(case, "grant_request");
    const gi = get(g, "inputs");
    const scope_set_cbor = try hex(a, gi, "scope_set_signed_cbor_hex");
    const scope_set = try act_as.decodeSignedActAsScopeSet(a, scope_set_cbor);
    // The scope set re-encodes to the received bytes: it is embedded unchanged.
    try std.testing.expectEqualSlices(u8, scope_set_cbor, try act_as.encodeSignedActAsScopeSet(a, scope_set));

    const signed = try act_as.signActAsGrantRequest(a, .{
        .grantee_fingerprint = km.fingerprint,
        .scope_set = scope_set,
        .requested_lifetime_seconds = optInt(gi, "requested_lifetime_seconds"),
        .requested_renewal_window_seconds = optInt(gi, "requested_renewal_window_seconds"),
        .callback_url = str(gi, "callback_url"),
        .nonce = str(gi, "nonce"),
        .requested_at = str(gi, "requested_at"),
        .expires_at = str(gi, "expires_at"),
    }, km);
    try std.testing.expectEqualSlices(u8, try hex(a, g, "request_cbor_hex"), signed.request);
    try std.testing.expectEqualSlices(u8, try hex(a, g, "signature_input_cbor_hex"), try lrp.local_rp.envelopeSignatureInput(a, act_as.tag_grant_request, signed.request));
    try std.testing.expectEqualSlices(u8, try hex(a, g, "signed_cbor_hex"), try act_as.encodeSignedActAsGrantRequest(a, signed));
    try std.testing.expectEqualStrings(str(g, "url_param"), try act_as.signedActAsGrantRequestToUrlParam(a, signed));

    // Refresh request.
    const r = get(case, "refresh_request");
    const ri = get(r, "inputs");
    const refresh = try act_as.signActAsRefreshRequest(a, .{
        .grant_id = str(ri, "grant_id"),
        .grantee_fingerprint = km.fingerprint,
        .requested_at = str(ri, "requested_at"),
        .expires_at = str(ri, "expires_at"),
        .nonce = str(ri, "nonce"),
    }, km);
    try std.testing.expectEqualSlices(u8, try hex(a, r, "request_cbor_hex"), refresh.request);
    try std.testing.expectEqualSlices(u8, try hex(a, r, "signed_cbor_hex"), try act_as.encodeSignedActAsRefreshRequest(a, refresh));

    // Presentation / credential.
    const p = get(case, "presentation");
    const pi = get(p, "inputs");
    const grant_cbor = try hex(a, pi, "grant_signed_cbor_hex");
    const grant = try act_as.decodeSignedActAsGrant(a, grant_cbor);
    try std.testing.expectEqualSlices(u8, grant_cbor, try act_as.encodeSignedActAsGrant(a, grant));
    const aud = get(pi, "audience");
    const presented = try lrp.presentActAs(a, .{
        .key_material = km,
        .grant = grant,
        .audience = .{
            .subject_user_id = str(aud, "subject_user_id"),
            .subject_domain = str(aud, "subject_domain"),
            .application_id = str(aud, "application_id"),
        },
        .request_digest = try hex(a, pi, "request_digest_hex"),
        .nonce = try hex(a, pi, "nonce_hex"),
        .now = try lrp.local_rp.parseTimestamp(str(pi, "presented_at")),
    });
    const presentation = try act_as.decodeActAsPresentation(a, presented.credential.presentation.presentation);
    try std.testing.expectEqualSlices(u8, try hex(a, p, "grant_hash_hex"), presentation.grant_hash);
    try std.testing.expectEqualStrings(str(pi, "presented_at"), presentation.presented_at);
    try std.testing.expectEqualSlices(u8, try hex(a, p, "presentation_cbor_hex"), presented.credential.presentation.presentation);
    try std.testing.expectEqualSlices(u8, try hex(a, p, "credential_cbor_hex"), presented.credential_cbor);
}

// ---------------------------------------------------------------------
// Begin + callback
// ---------------------------------------------------------------------

const BeginFixture = struct {
    km: lrp.LocalRpKeyMaterial,
    scope_set_cbor: []const u8,
    now: i64,
};

fn beginFixture(a: std.mem.Allocator) !BeginFixture {
    const root = try parseVectors(a);
    const gi = get(get(try localRpCase(root), "grant_request"), "inputs");
    return .{
        .km = try vectorKeyMaterial(a, root),
        .scope_set_cbor = try hex(a, gi, "scope_set_signed_cbor_hex"),
        .now = try lrp.local_rp.parseTimestamp(str(gi, "requested_at")),
    };
}

fn signedRequestParam(url: []const u8) []const u8 {
    const marker = "?signed_request=";
    const at = std.mem.indexOf(u8, url, marker).?;
    return url[at + marker.len ..];
}

test "beginActAs uses the discovered https host and signs a verifiable request" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fx = try beginFixture(a);

    var dns = lrp.browser.FakeDnsResolver{ .apis_txts = &.{"v=lk1 tcp=linkkeys.example.test https=linkkeys.example.test/lk"} };
    const result = try lrp.beginActAs(a, .{
        .key_material = fx.km,
        .user_domain = "Alice@Example.TEST",
        .scope_set_cbor = fx.scope_set_cbor,
        .requested_lifetime_seconds = 1800,
        .requested_renewal_window_seconds = 600,
        .callback_url = "http://app.lan:8080/act-as/callback",
        .now = fx.now,
        .dns = dns.resolver(),
    });
    const url = result.redirect.redirect_url;
    try std.testing.expect(std.mem.startsWith(u8, url, "https://linkkeys.example.test/lk/auth/act-as?signed_request="));
    try std.testing.expect(std.mem.indexOf(u8, url, "username=") == null);
    try std.testing.expectEqualStrings(user_domain, result.pending.user_domain);
    try std.testing.expectEqualStrings("http://app.lan:8080/act-as/callback", result.pending.callback_url);
    try std.testing.expectEqual(@as(usize, 43), result.pending.nonce.len); // 32 bytes, base64url no pad

    const signed = try act_as.signedActAsGrantRequestFromUrlParam(a, signedRequestParam(url));
    try act_as.verifyLocalRpProof(a, signed.proof, act_as.tag_grant_request, signed.request, fx.km.fingerprint, fx.now);
    // The proof does not verify under another tag.
    try std.testing.expectError(error.BadSignature, act_as.verifyLocalRpProof(a, signed.proof, act_as.tag_refresh_request, signed.request, fx.km.fingerprint, fx.now));

    const request = try act_as.decodeActAsGrantRequest(a, signed.request);
    try std.testing.expectEqualStrings(fx.km.fingerprint, request.grantee_fingerprint);
    try std.testing.expectEqualStrings(result.pending.nonce, request.nonce);
    try std.testing.expectEqual(@as(?i64, 1800), request.requested_lifetime_seconds);
    try std.testing.expectEqual(@as(?i64, 600), request.requested_renewal_window_seconds);
    try std.testing.expectEqual(fx.now, try lrp.local_rp.parseTimestamp(request.requested_at));
    try std.testing.expectEqual(fx.now + 300, try lrp.local_rp.parseTimestamp(request.expires_at));
    try std.testing.expectEqualSlices(u8, fx.scope_set_cbor, try act_as.encodeSignedActAsScopeSet(a, request.scope_set));
}

test "beginActAs falls back to the identity domain and omits absent optional fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fx = try beginFixture(a);

    var failing = lrp.browser.FakeDnsResolver.failing();
    const result = try lrp.beginActAs(a, .{
        .key_material = fx.km,
        .user_domain = user_domain,
        .scope_set_cbor = fx.scope_set_cbor,
        .callback_url = "https://app.example/cb",
        .now = fx.now,
        .dns = failing.resolver(),
        .request_window_seconds = 900,
    });
    try std.testing.expect(std.mem.startsWith(u8, result.redirect.redirect_url, "https://" ++ user_domain ++ "/auth/act-as?signed_request="));
    const signed = try act_as.signedActAsGrantRequestFromUrlParam(a, signedRequestParam(result.redirect.redirect_url));
    const root = try lrp.cbor.decode(a, signed.request);
    try std.testing.expect(lrp.cbor.mapGet(root, "requested_lifetime_seconds") == null);
    try std.testing.expect(lrp.cbor.mapGet(root, "requested_renewal_window_seconds") == null);
    const request = try act_as.decodeActAsGrantRequest(a, signed.request);
    try std.testing.expectEqual(fx.now + 900, try lrp.local_rp.parseTimestamp(request.expires_at));

    // Two begins never share a nonce.
    const again = try lrp.beginActAs(a, .{ .key_material = fx.km, .user_domain = user_domain, .scope_set_cbor = fx.scope_set_cbor, .callback_url = "https://app.example/cb", .now = fx.now, .dns = failing.resolver() });
    try std.testing.expect(!std.mem.eql(u8, result.pending.nonce, again.pending.nonce));
}

test "beginActAs rejects bad inputs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fx = try beginFixture(a);
    var failing = lrp.browser.FakeDnsResolver.failing();
    const base = lrp.BeginActAsConfig{ .key_material = fx.km, .user_domain = user_domain, .scope_set_cbor = fx.scope_set_cbor, .callback_url = "http://app.lan/cb", .now = fx.now, .dns = failing.resolver() };

    var c = base;
    c.request_window_seconds = 901;
    try std.testing.expectError(error.InvalidRequestWindow, lrp.beginActAs(a, c));
    c = base;
    c.request_window_seconds = 0;
    try std.testing.expectError(error.InvalidRequestWindow, lrp.beginActAs(a, c));
    c = base;
    c.requested_lifetime_seconds = 0;
    try std.testing.expectError(error.InvalidRequestedLifetime, lrp.beginActAs(a, c));
    c = base;
    c.requested_renewal_window_seconds = -1;
    try std.testing.expectError(error.InvalidRequestedRenewalWindow, lrp.beginActAs(a, c));
    c = base;
    c.callback_url = "myapp://cb";
    try std.testing.expectError(error.InvalidCallbackScheme, lrp.beginActAs(a, c));
    c = base;
    c.user_domain = "not a domain";
    try std.testing.expectError(error.InvalidInput, lrp.beginActAs(a, c));
    c = base;
    c.scope_set_cbor = "\xa0";
    try std.testing.expectError(error.MissingField, lrp.beginActAs(a, c));
}

test "completeActAsCallback accepts the pending nonce and rejects another" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fx = try beginFixture(a);
    var failing = lrp.browser.FakeDnsResolver.failing();
    const result = try lrp.beginActAs(a, .{ .key_material = fx.km, .user_domain = user_domain, .scope_set_cbor = fx.scope_set_cbor, .callback_url = "http://app.lan/cb", .now = fx.now, .dns = failing.resolver() });

    const ok_url = try std.fmt.allocPrint(a, "http://app.lan/cb?act_as_grant_id=0199aaaa-1111&nonce={s}", .{result.pending.nonce});
    try std.testing.expectEqualStrings("0199aaaa-1111", try lrp.completeActAsCallback(a, result.pending, ok_url));

    const other = try lrp.beginActAs(a, .{ .key_material = fx.km, .user_domain = user_domain, .scope_set_cbor = fx.scope_set_cbor, .callback_url = "http://app.lan/cb", .now = fx.now, .dns = failing.resolver() });
    const bad_url = try std.fmt.allocPrint(a, "http://app.lan/cb?act_as_grant_id=0199aaaa-1111&nonce={s}", .{other.pending.nonce});
    try std.testing.expectError(error.NonceMismatch, lrp.completeActAsCallback(a, result.pending, bad_url));
}

// ---------------------------------------------------------------------
// Refresh against a fake IDP
// ---------------------------------------------------------------------

fn plaintextSecureDial(transport: lrp.Transport, allocator: std.mem.Allocator, endpoint: lrp.rpc.DomainEndpoint) anyerror!std.net.Stream {
    _ = allocator;
    return transport.dial(endpoint.tcp_addr);
}

const RefreshDns = struct {
    apis_txt: []const u8,

    fn resolver(self: *RefreshDns) lrp.DnsResolver {
        return .{ .ptr = self, .txtLookupFn = txtLookupImpl };
    }

    fn txtLookupImpl(ptr: *anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const []const u8 {
        const self: *RefreshDns = @ptrCast(@alignCast(ptr));
        const out = try allocator.alloc([]const u8, 1);
        if (std.ascii.eqlIgnoreCase(name, "_linkkeys." ++ grant_domain)) {
            out[0] = "v=lk1 fp=" ++ ("ab" ** 32);
        } else if (std.ascii.eqlIgnoreCase(name, "_linkkeys_apis." ++ grant_domain)) {
            out[0] = self.apis_txt;
        } else {
            return error.NoFakeRecordForName;
        }
        return out;
    }
};

const RefreshIdp = struct {
    server: std.net.Server,
    fingerprint: []const u8,
    grant_id: []const u8,
    now: i64,
    response_grant: []const u8,
    /// When set, the IDP returns a grant for another grant id.
    wrong_grant_id: bool = false,
    /// When set, the IDP answers with this RPC status and no payload.
    error_status: ?u64 = null,
    // What the IDP saw (written by the server thread, read after join).
    saw_refresh_op: bool = false,
    proof_verified: bool = false,
    request_matches: bool = false,
};

fn serveRefresh(ctx: *RefreshIdp) void {
    const conn = ctx.server.accept() catch return;
    defer conn.stream.close();
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const frame = (lrp.rpc.readLengthPrefixed(a, conn.stream, lrp.rpc.max_frame_size) catch return) orelse return;
    const req = lrp.rpc.decodeRpcRequest(a, frame) catch return;
    ctx.saw_refresh_op = std.mem.eql(u8, req.service, "ActAs") and std.mem.eql(u8, req.op, "refresh-grant");
    if (lrp.act_as.decodeRefreshActAsGrantRequest(a, req.payload)) |signed| {
        if (lrp.act_as.verifyLocalRpProof(a, signed.proof, lrp.act_as.tag_refresh_request, signed.request, ctx.fingerprint, ctx.now)) |_| {
            ctx.proof_verified = true;
        } else |_| {}
        if (lrp.act_as.decodeActAsRefreshRequest(a, signed.request)) |r| {
            const requested_at = lrp.local_rp.parseTimestamp(r.requested_at) catch 0;
            const expires_at = lrp.local_rp.parseTimestamp(r.expires_at) catch 0;
            ctx.request_matches = std.mem.eql(u8, r.grant_id, ctx.grant_id) and
                std.mem.eql(u8, r.grantee_fingerprint, ctx.fingerprint) and
                requested_at == ctx.now and expires_at == ctx.now + 300 and r.nonce.len == 43;
        } else |_| {}
    } else |_| {}

    const resp_bytes = blk: {
        if (ctx.error_status) |status| break :blk lrp.rpc.encodeRpcResponseError(a, status, "simulated refresh failure") catch return;
        var grant = lrp.act_as.decodeSignedActAsGrant(a, ctx.response_grant) catch return;
        if (ctx.wrong_grant_id) grant.grant = replaceGrantId(a, grant.grant) catch return;
        const payload = lrp.act_as.encodeRefreshActAsGrantResponse(a, .{ .grant = grant, .signed = true }) catch return;
        break :blk lrp.rpc.encodeRpcResponseOk(a, "RefreshActAsGrantResponse", payload) catch return;
    };
    lrp.rpc.writeLengthPrefixed(conn.stream, resp_bytes) catch return;
}

/// Re-encodes CBOR(ActAsGrant) with another `grant_id`. The domain
/// signature then no longer matches, but the client does not check it.
fn replaceGrantId(a: std.mem.Allocator, grant_bytes: []const u8) ![]u8 {
    const root = try lrp.cbor.decode(a, grant_bytes);
    const entries = try a.dupe(lrp.cbor.Entry, root.map);
    for (entries) |*e| {
        if (std.mem.eql(u8, e.key.text, "grant_id")) e.value = lrp.cbor.text("grant-2");
    }
    return lrp.cbor.encodeAlloc(a, lrp.cbor.mapVal(entries));
}

const RefreshOutcome = struct {
    ctx: RefreshIdp,
    result: anyerror!lrp.RefreshActAsGrantResponse,
};

fn runRefresh(a: std.mem.Allocator, error_status: ?u64, wrong_grant_id: bool) !RefreshOutcome {
    const root = try parseVectors(a);
    const case = try localRpCase(root);
    const km = try vectorKeyMaterial(a, root);
    const ri = get(get(case, "refresh_request"), "inputs");
    const grant_cbor = try hex(a, get(get(case, "presentation"), "inputs"), "grant_signed_cbor_hex");
    const now = try lrp.local_rp.parseTimestamp(str(ri, "requested_at"));

    const bind_addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var ctx = RefreshIdp{
        .server = try bind_addr.listen(.{ .reuse_address = true }),
        .fingerprint = km.fingerprint,
        .grant_id = str(ri, "grant_id"),
        .now = now,
        .response_grant = grant_cbor,
        .error_status = error_status,
        .wrong_grant_id = wrong_grant_id,
    };
    defer ctx.server.deinit();
    const thread = try std.Thread.spawn(.{}, serveRefresh, .{&ctx});

    var dns = RefreshDns{ .apis_txt = try std.fmt.allocPrint(a, "v=lk1 tcp={}", .{ctx.server.listen_address}) };
    var std_transport = lrp.StdTransport{};
    const result = lrp.refreshActAsGrant(a, .{
        .key_material = km,
        .user_domain = "Home.Conformance.Example",
        .grant_id = str(ri, "grant_id"),
        .now = now,
        .transport = std_transport.transport(),
        .secure_dial = plaintextSecureDial,
        .dns = dns.resolver(),
    });
    // If the client failed before it connected, the server still waits in
    // accept. One empty connection releases it; otherwise it is harmless.
    if (std.net.tcpConnectToAddress(ctx.server.listen_address)) |unblock| unblock.close() else |_| {}
    thread.join();
    return .{ .ctx = ctx, .result = result };
}

test "refreshActAsGrant calls ActAs/refresh-grant with a verifiable request and decodes the grant" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const outcome = try runRefresh(a, null, false);
    const refreshed = try outcome.result;
    try std.testing.expect(outcome.ctx.saw_refresh_op);
    try std.testing.expect(outcome.ctx.proof_verified);
    try std.testing.expect(outcome.ctx.request_matches);
    try std.testing.expect(refreshed.signed);
    try std.testing.expectEqualSlices(u8, outcome.ctx.response_grant, try act_as.encodeSignedActAsGrant(a, refreshed.grant));
}

test "refreshActAsGrant surfaces an RPC transport error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const outcome = try runRefresh(a, 3, false);
    try std.testing.expect(outcome.ctx.saw_refresh_op);
    try std.testing.expectError(error.RpcUnauthenticated, outcome.result);
}

test "refreshActAsGrant rejects a grant for another grant id" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const outcome = try runRefresh(a, null, true);
    try std.testing.expect(outcome.ctx.proof_verified);
    try std.testing.expectError(error.GrantMismatch, outcome.result);
}

test "refreshActAsGrant fails closed without a pinned-TLS dialer" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try parseVectors(a);
    var dns = RefreshDns{ .apis_txt = "v=lk1 tcp=127.0.0.1:1" };
    var std_transport = lrp.StdTransport{};
    try std.testing.expectError(error.PinnedTlsUnavailable, lrp.refreshActAsGrant(a, .{
        .key_material = try vectorKeyMaterial(a, root),
        .user_domain = grant_domain,
        .grant_id = "grant-1",
        .now = 0,
        .transport = std_transport.transport(),
        .dns = dns.resolver(),
    }));
}
