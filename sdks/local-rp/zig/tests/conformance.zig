//! Conformance-vector tests for the Zig local-RP SDK. Consumes every file
//! under `sdks/local-rp/conformance/` (see that directory's README for the
//! schema) — the same fixed, checked-in vectors every other SDK's test
//! suite uses. Read at runtime from an absolute path `build.zig` resolves
//! and passes in via `build_options` (that directory lives outside this
//! package's root, so `@embedFile` cannot reach it — robust regardless of
//! the cwd `zig build test` happens to run with).
//!
//! Covers: keys.json, envelopes.json, callback_box.json, url_params.json,
//! dns.json, tickets.json, expirations.json, revocations.json, claims.json —
//! every file in the conformance directory, positive and negative cases.

const std = @import("std");
const lrp = @import("linkkeys_local_rp");
const build_options = @import("build_options");

/// The conformance vectors live one level up, outside this package's root
/// (`sdks/local-rp/conformance/`, shared by every SDK's test suite) —
/// `@embedFile` cannot reach outside the package, so these are read at
/// runtime from the absolute path `build.zig` resolves (robust regardless
/// of the cwd `zig build test` happens to run with).
fn loadFixture(a: std.mem.Allocator, name: []const u8) ![]const u8 {
    const path = try std.fs.path.join(a, &.{ build_options.conformance_dir, name });
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return file.readToEndAlloc(a, 8 * 1024 * 1024);
}

fn parseFixture(a: std.mem.Allocator, name: []const u8) !std.json.Value {
    const text = try loadFixture(a, name);
    return std.json.parseFromSliceLeaky(std.json.Value, a, text, .{});
}

fn str(v: std.json.Value, key: []const u8) []const u8 {
    return v.object.get(key).?.string;
}
fn strOpt(v: std.json.Value, key: []const u8) ?[]const u8 {
    const got = v.object.get(key) orelse return null;
    return switch (got) {
        .string => |s| s,
        else => null,
    };
}
fn boolean(v: std.json.Value, key: []const u8) bool {
    return v.object.get(key).?.bool;
}
fn arr(v: std.json.Value, key: []const u8) []std.json.Value {
    return v.object.get(key).?.array.items;
}
fn integer(v: std.json.Value, key: []const u8) i64 {
    return v.object.get(key).?.integer;
}

fn mustHex(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    return lrp.crypto.hexDecodeAlloc(a, hex);
}
fn mustHex32(hex: []const u8) ![32]u8 {
    return lrp.crypto.hexDecodeFixed(32, hex);
}

// ---------------------------------------------------------------------
// keys.json
// ---------------------------------------------------------------------

test "keys.json: fingerprint matches and round-trips through SDK helpers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "keys.json");
    const local_rp_obj = root.object.get("local_rp").?;
    const signing = local_rp_obj.object.get("signing").?;
    const domain_signing = root.object.get("domain_signing_key").?;

    for ([_]std.json.Value{ signing, domain_signing }) |entry| {
        const pub_bytes = try mustHex(a, str(entry, "public_key_hex"));
        const expected_fp = str(entry, "fingerprint_hex");

        const fp = lrp.crypto.fingerprintHex(pub_bytes);
        try std.testing.expectEqualStrings(expected_fp, &fp);

        const s = lrp.fingerprintToString(expected_fp);
        const round_tripped = try lrp.fingerprintFromString(a, s);
        try std.testing.expectEqualStrings(expected_fp, round_tripped);
    }

    try std.testing.expectError(error.InvalidInput, lrp.fingerprintFromString(a, "deadbeef"));
}

// ---------------------------------------------------------------------
// envelopes.json
// ---------------------------------------------------------------------

fn checkEnvelopeCase(a: std.mem.Allocator, c: std.json.Value) !void {
    const context = str(c, "context");
    const payload = try mustHex(a, str(c, "payload_cbor_hex"));
    const expected_sig_input = try mustHex(a, str(c, "signature_input_cbor_hex"));
    const signature = try mustHex(a, str(c, "signature_hex"));
    const verify_key = try mustHex(a, str(c, "verify_key_hex"));
    const expected_valid = boolean(c, "expected_valid");

    const computed = try lrp.local_rp.envelopeSignatureInput(a, context, payload);
    try std.testing.expectEqualSlices(u8, expected_sig_input, computed);

    const valid = lrp.crypto.verifyEd25519(verify_key, computed, signature);
    try std.testing.expectEqual(expected_valid, valid);
}

test "envelopes.json: 4 positive cases verify" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "envelopes.json");
    const cases = arr(root, "cases");
    try std.testing.expectEqual(@as(usize, 4), cases.len);
    for (cases) |c| {
        try std.testing.expect(boolean(c, "expected_valid"));
        try checkEnvelopeCase(a, c);
    }
}

test "envelopes.json: 20 negative cases fail" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "envelopes.json");
    const negs = arr(root, "negative_cases");
    try std.testing.expectEqual(@as(usize, 20), negs.len);
    for (negs) |c| {
        try std.testing.expect(!boolean(c, "expected_valid"));
        try checkEnvelopeCase(a, c);
    }
}

// ---------------------------------------------------------------------
// callback_box.json
// ---------------------------------------------------------------------

fn parseAllowedSuites(a: std.mem.Allocator, ids: []std.json.Value) ![]lrp.crypto.AeadSuite {
    var out = std.ArrayList(lrp.crypto.AeadSuite).init(a);
    for (ids) |id| {
        const suite = lrp.crypto.parseAeadSuite(id.string) orelse return error.UnregisteredSuiteId;
        try out.append(suite);
    }
    return out.toOwnedSlice();
}

test "callback_box.json: 2 positive cases open" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "callback_box.json");
    const cases = arr(root, "positive_cases");
    try std.testing.expectEqual(@as(usize, 2), cases.len);

    for (cases) |c| {
        const header_bytes = try mustHex(a, str(c, "header_cbor_hex"));
        const ciphertext = try mustHex(a, str(c, "ciphertext_hex"));
        const decrypt_key = try mustHex32(str(c, "decrypt_private_key_hex"));
        const allowed = try parseAllowedSuites(a, arr(c, "allowed_suites"));

        const encrypted = lrp.types.LocalRpEncryptedCallback{ .header = header_bytes, .ciphertext = ciphertext };
        const opened = try lrp.local_rp.openLocalRpCallback(a, encrypted, decrypt_key, allowed);

        try std.testing.expectEqualStrings(str(c, "suite"), opened.header.suite);
        try std.testing.expectEqualStrings(str(c, "fingerprint"), opened.header.fingerprint);
        try std.testing.expectEqualStrings(str(c, "nonce_hex"), try lrp.crypto.hexEncode(a, opened.header.nonce));
        try std.testing.expectEqualStrings(str(c, "state_hex"), try lrp.crypto.hexEncode(a, opened.header.state));
        try std.testing.expectEqualStrings(str(c, "issued_at"), opened.header.issued_at);
        try std.testing.expectEqualStrings(str(c, "expires_at"), opened.header.expires_at);

        const plaintext = try lrp.types.encodeSignedLocalRpCallbackPayload(a, opened.signed_payload);
        try std.testing.expectEqualStrings(str(c, "plaintext_cbor_hex"), try lrp.crypto.hexEncode(a, plaintext));
    }
}

test "callback_box.json: 13 negative cases fail" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "callback_box.json");
    const cases = arr(root, "negative_cases");
    try std.testing.expectEqual(@as(usize, 13), cases.len);

    for (cases) |c| {
        const header_bytes = try mustHex(a, str(c, "header_cbor_hex"));
        const ciphertext = try mustHex(a, str(c, "ciphertext_hex"));
        const decrypt_key = try mustHex32(str(c, "decrypt_private_key_hex"));
        const allowed = try parseAllowedSuites(a, arr(c, "allowed_suites"));

        const encrypted = lrp.types.LocalRpEncryptedCallback{ .header = header_bytes, .ciphertext = ciphertext };
        try expectAnyError(lrp.local_rp.openLocalRpCallback(a, encrypted, decrypt_key, allowed));
    }
}

// std.testing.expectError requires a concrete expected error; for negative
// cases we only care that SOME error occurred (the conformance README:
// "Exact error types are intentionally not part of the contract"), so this
// helper just asserts failure.
fn expectAnyError(result: anytype) !void {
    if (result) |_| {
        return error.TestUnexpectedSuccess;
    } else |_| {
        return;
    }
}

// ---------------------------------------------------------------------
// url_params.json
// ---------------------------------------------------------------------

test "url_params.json: cases round trip both directions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "url_params.json");
    const cases = arr(root, "cases");

    for (cases) |c| {
        const name = str(c, "name");
        const cbor_bytes = try mustHex(a, str(c, "cbor_hex"));
        const expected_b64 = str(c, "base64url_unpadded");

        if (std.mem.eql(u8, name, "signed_local_rp_login_request")) {
            const typed = try lrp.types.decodeSignedLocalRpLoginRequest(a, cbor_bytes);
            const encoded = try lrp.encoding.signedLocalRpLoginRequestToUrlParam(a, typed);
            try std.testing.expectEqualStrings(expected_b64, encoded);

            const round_tripped = try lrp.encoding.signedLocalRpLoginRequestFromUrlParam(a, expected_b64);
            try std.testing.expectEqualSlices(u8, typed.request, round_tripped.request);
            try std.testing.expectEqualSlices(u8, typed.signature, round_tripped.signature);
        } else if (std.mem.eql(u8, name, "local_rp_encrypted_callback")) {
            const typed = try lrp.types.decodeLocalRpEncryptedCallback(a, cbor_bytes);
            const encoded = try lrp.encoding.localRpEncryptedCallbackToUrlParam(a, typed);
            try std.testing.expectEqualStrings(expected_b64, encoded);

            const round_tripped = try lrp.encoding.localRpEncryptedCallbackFromUrlParam(a, expected_b64);
            try std.testing.expectEqualSlices(u8, typed.header, round_tripped.header);
            try std.testing.expectEqualSlices(u8, typed.ciphertext, round_tripped.ciphertext);
        } else {
            return error.UnrecognizedUrlParamsCaseName;
        }
    }
}

test "url_params.json: 2 negative cases rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "url_params.json");
    const negs = arr(root, "negative_cases");
    try std.testing.expectEqual(@as(usize, 2), negs.len);
    for (negs) |c| {
        try std.testing.expect(!boolean(c, "expected_valid"));
        const input = str(c, "input");
        try expectAnyError(lrp.encoding.localRpEncryptedCallbackFromUrlParam(a, input));
    }
}

// ---------------------------------------------------------------------
// dns.json
// ---------------------------------------------------------------------

fn expectDnsError(expected: []const u8, result: anytype) !void {
    if (std.mem.eql(u8, expected, "missing_version")) return std.testing.expectError(error.MissingVersion, result);
    if (std.mem.eql(u8, expected, "unsupported_version")) return std.testing.expectError(error.UnsupportedVersion, result);
    if (std.mem.eql(u8, expected, "missing_apis_endpoint")) return std.testing.expectError(error.MissingApisEndpoint, result);
    return error.UnhandledExpectedDnsErrorKind;
}

test "dns.json: _linkkeys TXT valid/invalid cases" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "dns.json");
    const linkkeys_txt = root.object.get("linkkeys_txt").?;

    for (arr(linkkeys_txt, "valid_cases")) |c| {
        const rec = try lrp.dns.parseLinkKeysTxt(a, str(c, "txt"));
        const expected_fps = arr(c, "expected_fingerprints");
        try std.testing.expectEqual(expected_fps.len, rec.fingerprints.len);
        for (expected_fps, 0..) |fp, i| try std.testing.expectEqualStrings(fp.string, rec.fingerprints[i]);
    }

    for (arr(linkkeys_txt, "invalid_cases")) |c| {
        const result = lrp.dns.parseLinkKeysTxt(a, str(c, "txt"));
        try expectDnsError(str(c, "expected_error"), result);
    }

    try std.testing.expectEqual(@as(i64, integer(root, "default_tcp_port")), @as(i64, lrp.dns.default_tcp_port));
}

test "dns.json: _linkkeys_apis TXT valid/invalid cases" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "dns.json");
    const apis_txt = root.object.get("linkkeys_apis_txt").?;

    for (arr(apis_txt, "valid_cases")) |c| {
        const apis = try lrp.dns.parseLinkKeysApisTxt(a, str(c, "txt"));
        const expected_tcp = strOpt(c, "expected_tcp");
        const expected_https = strOpt(c, "expected_https_base");

        if (expected_tcp) |e| {
            try std.testing.expectEqualStrings(e, apis.tcp.?);
        } else {
            try std.testing.expect(apis.tcp == null);
        }
        if (expected_https) |e| {
            try std.testing.expectEqualStrings(e, apis.https_base.?);
        } else {
            try std.testing.expect(apis.https_base == null);
        }
    }

    for (arr(apis_txt, "invalid_cases")) |c| {
        const result = lrp.dns.parseLinkKeysApisTxt(a, str(c, "txt"));
        try expectDnsError(str(c, "expected_error"), result);
    }
}

// ---------------------------------------------------------------------
// tickets.json
// ---------------------------------------------------------------------

test "tickets.json: sha256 hash pairs match the fingerprint routine" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "tickets.json");
    const cases = arr(root, "cases");
    try std.testing.expect(cases.len > 0);

    for (cases) |c| {
        const ticket = try mustHex(a, str(c, "ticket_hex"));
        try std.testing.expectEqual(@as(usize, 32), ticket.len);
        const fp = lrp.crypto.fingerprintHex(ticket);
        try std.testing.expectEqualStrings(str(c, "sha256_hex"), &fp);
    }
}

// ---------------------------------------------------------------------
// expirations.json
// ---------------------------------------------------------------------

test "expirations.json: check_expirations thresholds are exact" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "expirations.json");
    const ce = root.object.get("check_expirations").?;
    const expires_at = str(ce, "expires_at");
    const cases = arr(ce, "cases");
    try std.testing.expectEqual(@as(usize, 11), cases.len);

    for (cases) |c| {
        const now = try lrp.local_rp.parseTimestamp(str(c, "now"));
        const status = try lrp.local_rp.checkExpirationsAt(expires_at, now);
        try std.testing.expectEqualStrings(str(c, "expected_level"), @tagName(status.level));
    }
}

test "expirations.json: check_timestamps skew boundaries are exact" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "expirations.json");
    const ct = root.object.get("check_timestamps").?;
    const issued_at = str(ct, "issued_at");
    const expires_at = str(ct, "expires_at");
    const skew = integer(ct, "skew_seconds");
    const cases = arr(ct, "cases");
    try std.testing.expectEqual(@as(usize, 4), cases.len);

    for (cases) |c| {
        const now = try lrp.local_rp.parseTimestamp(str(c, "now"));
        const result = lrp.local_rp.checkTimestamps(issued_at, expires_at, now, skew);
        const valid = if (result) true else |_| false;
        try std.testing.expectEqual(boolean(c, "expected_valid"), valid);
    }
}

// ---------------------------------------------------------------------
// revocations.json
// ---------------------------------------------------------------------

fn revocationFixtureKeys(a: std.mem.Allocator, domain_keys: []std.json.Value) ![]lrp.types.DomainPublicKey {
    var out = std.ArrayList(lrp.types.DomainPublicKey).init(a);
    for (domain_keys) |k| {
        try out.append(.{
            .key_id = str(k, "key_id"),
            .public_key = try mustHex(a, str(k, "public_key_hex")),
            .fingerprint = str(k, "fingerprint_hex"),
            .algorithm = str(k, "algorithm"),
            .key_usage = str(k, "key_usage"),
            .created_at = str(k, "created_at"),
            .expires_at = str(k, "expires_at"),
            .revoked_at = strOpt(k, "revoked_at"),
        });
    }
    return out.toOwnedSlice();
}

test "revocations.json: 9 certificate cases" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "revocations.json");
    try std.testing.expectEqual(@as(i64, integer(root, "quorum")), @as(i64, lrp.revocation.revocation_quorum));

    const keys = try revocationFixtureKeys(a, arr(root, "domain_keys"));
    const cases = arr(root, "certificate_cases");
    try std.testing.expectEqual(@as(usize, 9), cases.len);

    for (cases) |c| {
        const cert_bytes = try mustHex(a, str(c, "certificate_cbor_hex"));
        const cert = try lrp.types.decodeRevocationCertificate(a, cert_bytes);

        const expanded = c.object.get("certificate").?;
        try std.testing.expectEqualStrings(str(expanded, "target_key_id"), cert.target_key_id);
        try std.testing.expectEqualStrings(str(expanded, "target_fingerprint"), cert.target_fingerprint);
        try std.testing.expectEqualStrings(str(expanded, "revoked_at"), cert.revoked_at);
        const expanded_sigs = arr(expanded, "signatures");
        try std.testing.expectEqual(expanded_sigs.len, cert.signatures.len);
        for (expanded_sigs, 0..) |es, i| {
            try std.testing.expectEqualStrings(str(es, "domain"), cert.signatures[i].domain);
            try std.testing.expectEqualStrings(str(es, "signed_by_key_id"), cert.signatures[i].signed_by_key_id);
            try std.testing.expectEqualStrings(str(es, "signature_hex"), try lrp.crypto.hexEncode(a, cert.signatures[i].signature));
        }

        const verify_domain = str(c, "verify_domain");
        const expected_counted: i64 = integer(c, "expected_counted_signers");
        const counted = lrp.revocation.countRevocationSigners(a, cert, keys, verify_domain);
        try std.testing.expectEqual(expected_counted, @as(i64, @intCast(counted)));

        const result = lrp.revocation.verifyRevocationCertificate(a, cert, keys, verify_domain);
        const valid = if (result) true else |_| false;
        try std.testing.expectEqual(boolean(c, "expected_valid"), valid);
    }
}

test "revocations.json: application case — certificate application flips verification" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "revocations.json");
    const domain = str(root, "domain");
    const keys = try revocationFixtureKeys(a, arr(root, "domain_keys"));
    const ac = root.object.get("application_case").?;
    const envelope = ac.object.get("envelope").?;

    try std.testing.expectEqualStrings("linkkeys-local-rp-callback", str(envelope, "context"));

    const signed = lrp.types.SignedLocalRpCallbackPayload{
        .payload = try mustHex(a, str(envelope, "payload_cbor_hex")),
        .signing_key_id = str(envelope, "signing_key_id"),
        .signature = try mustHex(a, str(envelope, "signature_hex")),
    };
    const now = try lrp.local_rp.parseTimestamp(str(ac, "verify_now"));
    const skew = integer(ac, "clock_skew_seconds");

    // Before revocation: the fetched key list shows the target key with no
    // revoked_at, so the envelope verifies.
    const before_result = lrp.local_rp.verifyLocalRpCallbackPayload(a, signed, keys, now, skew);
    const before_valid = if (before_result) |_| true else |_| false;
    try std.testing.expectEqual(boolean(ac, "expected_valid_before_revocation"), before_valid);

    // The referenced certificate (valid_quorum_two_siblings) must verify
    // against the same key set.
    var cert_case: ?std.json.Value = null;
    for (arr(root, "certificate_cases")) |c| {
        if (std.mem.eql(u8, str(c, "name"), "valid_quorum_two_siblings")) {
            cert_case = c;
            break;
        }
    }
    const found_case = cert_case orelse return error.CertificateCaseNotFound;
    const cert = try lrp.types.decodeRevocationCertificate(a, try mustHex(a, str(found_case, "certificate_cbor_hex")));
    try lrp.revocation.verifyRevocationCertificate(a, cert, keys, domain);

    // Apply the revocation: mark the target as revoked from cert.revoked_at
    // onward. The same envelope must now fail even though the fetched key
    // entry looked valid on its own.
    const marked_keys = try a.dupe(lrp.types.DomainPublicKey, keys);
    for (marked_keys) |*k| {
        if (std.mem.eql(u8, k.key_id, cert.target_key_id)) k.revoked_at = cert.revoked_at;
    }
    const after_marked_result = lrp.local_rp.verifyLocalRpCallbackPayload(a, signed, marked_keys, now, skew);
    const after_marked_valid = if (after_marked_result) |_| true else |_| false;
    try std.testing.expectEqual(boolean(ac, "expected_valid_after_revocation"), after_marked_valid);

    // This SDK's production apply path (rpc.fetchDomainKeys) removes the
    // targeted key from the trusted set entirely rather than marking it —
    // verify that stricter application also flips the envelope to failing.
    var removed_keys = std.ArrayList(lrp.types.DomainPublicKey).init(a);
    for (keys) |k| {
        if (!std.mem.eql(u8, k.key_id, cert.target_key_id)) try removed_keys.append(k);
    }
    try expectAnyError(lrp.local_rp.verifyLocalRpCallbackPayload(a, signed, removed_keys.items, now, skew));
}

// ---------------------------------------------------------------------
// claims.json
// ---------------------------------------------------------------------
//
// The trap this file exists to catch: Claim.claim_value is CBOR bytes
// (bstr), never text (tstr), both on the wire and inside the eight-element
// signed payload tuple. Self-consistent sign-wrong/verify-wrong testing
// hides a tstr bug; only cross-implementation vectors expose it (see the
// conformance README's claims.json section and the non-UTF-8 positive
// case below, which a tstr codec cannot even represent).

fn claimSignatureFromExpanded(a: std.mem.Allocator, v: std.json.Value) !lrp.types.ClaimSignature {
    return .{
        .domain = str(v, "domain"),
        .signed_by_key_id = str(v, "signed_by_key_id"),
        .signature = try mustHex(a, str(v, "signature_hex")),
    };
}

fn claimDomainKeySets(a: std.mem.Allocator, domain: []const u8, domain_keys_json: []std.json.Value) ![]lrp.claims.DomainKeySet {
    const keys = try revocationFixtureKeys(a, domain_keys_json);
    const sets = try a.alloc(lrp.claims.DomainKeySet, 1);
    sets[0] = .{ .domain = domain, .keys = keys };
    return sets;
}

fn claimVerifyError(expected: []const u8) anyerror {
    if (std.mem.eql(u8, expected, "signature_invalid")) return error.ClaimSignatureInvalid;
    if (std.mem.eql(u8, expected, "key_not_found")) return error.ClaimKeyNotFound;
    unreachable;
}

test "claims.json: 3 positive cases — decode, sign-payload recompute, independent Ed25519 verify, SDK verify, byte-exact round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "claims.json");
    const cases = arr(root, "cases");
    try std.testing.expectEqual(@as(usize, 3), cases.len);

    // All fixture domain_keys entries belong to this one domain regardless
    // of the (possibly attacker-controlled) subject_domain a given case
    // verifies under — see the subject_domain_replay negative case below.
    const keys_domain = str(root, "subject_domain");
    const default_key_sets = try claimDomainKeySets(a, keys_domain, arr(root, "domain_keys"));

    for (cases) |c| {
        try std.testing.expect(boolean(c, "expected_valid"));
        const subject_domain = str(c, "subject_domain");
        const claim_bytes = try mustHex(a, str(c, "claim_cbor_hex"));

        // Decode the wire bytes through the SDK's own Claim codec (claim_value
        // must decode as bytes, never text).
        const decoded_value = try lrp.cbor.decode(a, claim_bytes);
        const decoded = try lrp.types.claimFromValue(a, decoded_value);

        const expanded = c.object.get("claim").?;
        try std.testing.expectEqualStrings(str(expanded, "claim_id"), decoded.claim_id);
        try std.testing.expectEqualStrings(str(expanded, "user_id"), decoded.user_id);
        try std.testing.expectEqualStrings(str(expanded, "claim_type"), decoded.claim_type);
        try std.testing.expectEqualSlices(u8, try mustHex(a, str(expanded, "claim_value_hex")), decoded.claim_value);
        try std.testing.expectEqualStrings(str(expanded, "attested_at"), decoded.attested_at);
        try std.testing.expectEqualStrings(str(expanded, "created_at"), decoded.created_at);

        if (strOpt(expanded, "expires_at")) |e| {
            try std.testing.expectEqualStrings(e, decoded.expires_at.?);
        } else {
            try std.testing.expect(decoded.expires_at == null);
        }
        try std.testing.expect(decoded.revoked_at == null);

        const expanded_sigs = arr(expanded, "signatures");
        try std.testing.expectEqual(expanded_sigs.len, decoded.signatures.len);

        for (expanded_sigs, 0..) |es, i| {
            const sig = decoded.signatures[i];
            try std.testing.expectEqualStrings(str(es, "domain"), sig.domain);
            try std.testing.expectEqualStrings(str(es, "signed_by_key_id"), sig.signed_by_key_id);
            const expected_sig_bytes = try mustHex(a, str(es, "signature_hex"));
            try std.testing.expectEqualSlices(u8, expected_sig_bytes, sig.signature);

            // Recompute the exact bytes a signature covers via the SDK's own
            // claimSignPayload (8-element tag-first array, claim_value as
            // bstr, subject as one '@'-joined string, expires_at CBOR null
            // when absent) and confirm it matches the vector byte-for-byte.
            const recomputed_payload = try lrp.claims.claimSignPayload(a, decoded.claim_id, decoded.claim_type, decoded.claim_value, decoded.user_id, subject_domain, sig.domain, decoded.expires_at, decoded.attested_at);
            const expected_payload = try mustHex(a, str(es, "signed_payload_cbor_hex"));
            try std.testing.expectEqualSlices(u8, expected_payload, recomputed_payload);

            // Independent Ed25519 verification via std.crypto (not routed
            // through verifyClaim) of the exact wire signature over the
            // exact wire payload bytes, against the fixture's signer key.
            var signer_pub: ?[]const u8 = null;
            for (arr(root, "signer_keys")) |sk| {
                if (std.mem.eql(u8, str(sk, "key_id"), sig.signed_by_key_id)) {
                    signer_pub = try mustHex(a, str(sk, "public_key_hex"));
                    break;
                }
            }
            const pub_key = signer_pub orelse return error.SignerKeyNotFoundInFixture;
            try std.testing.expect(lrp.crypto.verifyEd25519(pub_key, expected_payload, expected_sig_bytes));
        }

        // Byte-exact re-encode through the SDK's own codec.
        const reencoded = try lrp.cbor.encodeAlloc(a, try lrp.types.claimToValue(a, decoded));
        try std.testing.expectEqualSlices(u8, claim_bytes, reencoded);

        // Full claim verification through the SDK's own path — the same one
        // completeLocalLogin uses to verify claims from a ticket redemption.
        try lrp.claims.verifyClaim(a, decoded, subject_domain, default_key_sets);
    }
}

test "claims.json: decode-negative — CBOR-text claim_value must be rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "claims.json");
    const negs = arr(root, "decode_negative_cases");
    try std.testing.expectEqual(@as(usize, 1), negs.len);

    for (negs) |c| {
        try std.testing.expect(!boolean(c, "expected_decode_ok"));
        const claim_bytes = try mustHex(a, str(c, "claim_cbor_hex"));
        // The outer CBOR item itself is well-formed (only the claim_value
        // entry's major type differs from claim_utf8_text_value), so generic
        // decode succeeds; the strict bstr-typed Claim codec must reject it.
        const decoded_value = try lrp.cbor.decode(a, claim_bytes);
        try expectAnyError(lrp.types.claimFromValue(a, decoded_value));
    }
}

test "claims.json: 4 verification negatives fail with expected error kinds" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "claims.json");
    const negs = arr(root, "negative_cases");
    try std.testing.expectEqual(@as(usize, 4), negs.len);

    const keys_domain = str(root, "subject_domain");
    const default_key_sets = try claimDomainKeySets(a, keys_domain, arr(root, "domain_keys"));

    for (negs) |c| {
        const claim_bytes = try mustHex(a, str(c, "claim_cbor_hex"));
        const decoded_value = try lrp.cbor.decode(a, claim_bytes);
        const decoded = try lrp.types.claimFromValue(a, decoded_value);
        const subject_domain = str(c, "subject_domain");

        const key_sets = if (c.object.get("domain_keys")) |dk|
            try claimDomainKeySets(a, keys_domain, dk.array.items)
        else
            default_key_sets;

        const expected_err = claimVerifyError(str(c, "expected_error"));
        try std.testing.expectError(expected_err, lrp.claims.verifyClaimSignatures(a, decoded, subject_domain, key_sets));
    }
}

test "claims.json: LocalRpTicketRedemptionResponse round trip + embedded claim verification" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parseFixture(a, "claims.json");
    const trr = root.object.get("ticket_redemption_response").?;
    const response_bytes = try mustHex(a, str(trr, "response_cbor_hex"));

    // Decode through the same wire message completeLocalLogin actually
    // consumes Claims from.
    const decoded = try lrp.types.decodeLocalRpTicketRedemptionResponse(a, response_bytes);
    try std.testing.expectEqualStrings(str(trr, "user_id"), decoded.user_id);
    try std.testing.expectEqualStrings(str(trr, "user_domain"), decoded.user_domain);
    try std.testing.expectEqualStrings(str(trr, "ticket_expires_at"), decoded.ticket_expires_at);
    try std.testing.expectEqual(@as(usize, 3), decoded.claims.len);

    const key_sets = try claimDomainKeySets(a, str(root, "subject_domain"), arr(root, "domain_keys"));
    for (decoded.claims) |claim| {
        try lrp.claims.verifyClaim(a, claim, decoded.user_domain, key_sets);
    }

    // Re-encoding must reproduce response_cbor_hex byte-exactly.
    const reencoded = try lrp.types.encodeLocalRpTicketRedemptionResponse(a, decoded);
    try std.testing.expectEqualSlices(u8, response_bytes, reencoded);
}
