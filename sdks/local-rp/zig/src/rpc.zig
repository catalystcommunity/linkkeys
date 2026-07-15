//! CSIL-RPC over the injected `Transport`, meant to be TLS-pinned to a
//! domain's DNS `fp=` records — this SDK's only network surface, per the
//! design doc's "Required Network Access": domain public keys, revocations,
//! and claim-ticket redemption, all unauthenticated-TLS TCP CSIL-RPC calls
//! pinned the same way `crates/linkkeys/src/tcp/tls.rs` pins the S2S path.
//!
//! No csilgen Zig target exists (this SDK files that request alongside
//! itself), so the request/response envelope and stream framing here are
//! hand-written directly against `~/repos/catalystcommunity/csilgen/docs/csil-rpc-transport.md`
//! (byte-stream carrier: 4-byte big-endian length prefix + one canonical
//! CBOR envelope; `payload` is CBOR tag-24-wrapped) and
//! `csil-transport-conventions.md` (map keys sorted bytewise — our
//! `cbor.zig` encoder is already canonical by construction).
//!
//! **Pinned TLS is not implemented** — see `tls_pin.zig`'s module docs for
//! the full evaluation of why (`std.crypto.tls.Client` cannot expose the
//! peer certificate after a handshake). `defaultSecureDial` always returns
//! `error.PinnedTlsUnavailable` rather than silently connecting unpinned;
//! callers (including this SDK's own flow tests) inject an alternate
//! `SecureDial` — see this SDK's README.

const std = @import("std");
const cbor = @import("cbor.zig");
const types = @import("types.zig");
const dnsmod = @import("dns.zig");
const transportmod = @import("transport.zig");
const revocation = @import("revocation.zig");

pub const rpc_version: u64 = 1;

/// Mirrors the reference SDKs' own cap, so a malicious/compromised peer
/// cannot drive this client to an unbounded allocation via a forged length
/// prefix.
pub const max_frame_size: usize = 1024 * 1024;

// ---------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------

fn untag24(v: cbor.Value) ![]const u8 {
    if (v != .tag or v.tag.number != 24) return error.ExpectedTag24Payload;
    return cbor.asBytes(v.tag.value.*);
}

pub fn encodeRpcRequest(allocator: std.mem.Allocator, service: []const u8, op: []const u8, payload: []const u8) ![]u8 {
    var payload_bytes_val = cbor.bytesVal(payload);
    const entries = [_]cbor.Entry{
        .{ .key = cbor.text("v"), .value = cbor.uint(rpc_version) },
        .{ .key = cbor.text("service"), .value = cbor.text(service) },
        .{ .key = cbor.text("op"), .value = cbor.text(op) },
        .{ .key = cbor.text("payload"), .value = cbor.tagVal(24, &payload_bytes_val) },
    };
    return cbor.encodeAlloc(allocator, cbor.mapVal(&entries));
}

pub const RpcRequestDecoded = struct {
    service: []const u8,
    op: []const u8,
    payload: []const u8,
};

/// Decodes a `CsilRpcRequest` envelope. Only used by this SDK's own test
/// fixtures (fake IDPs) — production code only ever sends requests
/// (`encodeRpcRequest`), never decodes them.
pub fn decodeRpcRequest(allocator: std.mem.Allocator, bytes: []const u8) !RpcRequestDecoded {
    const root = try cbor.decode(allocator, bytes);
    const v = try cbor.asU64(try cbor.require(root, "v"));
    if (v != rpc_version) return error.RpcVersionUnsupported;
    const payload = try untag24(try cbor.require(root, "payload"));
    const service = try cbor.asText(try cbor.require(root, "service"));
    const op = try cbor.asText(try cbor.require(root, "op"));
    return .{ .service = service, .op = op, .payload = payload };
}

/// Encodes a successful (status-Ok) `CsilRpcResponse`. Only used by this
/// SDK's own test fixtures (fake IDPs) — production code only ever decodes
/// responses (`decodeRpcResponse`).
pub fn encodeRpcResponseOk(allocator: std.mem.Allocator, variant: []const u8, payload: []const u8) ![]u8 {
    var payload_val = cbor.bytesVal(payload);
    const entries = [_]cbor.Entry{
        .{ .key = cbor.text("v"), .value = cbor.uint(rpc_version) },
        .{ .key = cbor.text("status"), .value = cbor.uint(0) },
        .{ .key = cbor.text("variant"), .value = cbor.text(variant) },
        .{ .key = cbor.text("payload"), .value = cbor.tagVal(24, &payload_val) },
    };
    return cbor.encodeAlloc(allocator, cbor.mapVal(&entries));
}

/// Encodes a transport-level-failure `CsilRpcResponse` (non-zero status, no
/// typed payload). Only used by this SDK's own test fixtures.
pub fn encodeRpcResponseError(allocator: std.mem.Allocator, status_code: u64, message: []const u8) ![]u8 {
    var empty_payload_val = cbor.bytesVal(&.{});
    const entries = [_]cbor.Entry{
        .{ .key = cbor.text("v"), .value = cbor.uint(rpc_version) },
        .{ .key = cbor.text("status"), .value = cbor.uint(status_code) },
        .{ .key = cbor.text("error"), .value = cbor.text(message) },
        .{ .key = cbor.text("payload"), .value = cbor.tagVal(24, &empty_payload_val) },
    };
    return cbor.encodeAlloc(allocator, cbor.mapVal(&entries));
}

pub const RpcResponse = struct {
    status: i64,
    variant: ?[]const u8 = null,
    error_message: ?[]const u8 = null,
    payload: []const u8 = &.{},
};

pub fn decodeRpcResponse(allocator: std.mem.Allocator, bytes: []const u8) !RpcResponse {
    const root = try cbor.decode(allocator, bytes);
    const v = try cbor.asU64(try cbor.require(root, "v"));
    if (v != rpc_version) return error.RpcVersionUnsupported;

    var payload: []const u8 = &.{};
    if (cbor.mapGet(root, "payload")) |p| payload = try untag24(p);

    const status_val = try cbor.require(root, "status");
    const status: i64 = switch (status_val) {
        .uint => |n| @intCast(n),
        .nint => |n| n,
        else => return error.WrongType,
    };

    return .{
        .status = status,
        .variant = if (cbor.mapGet(root, "variant")) |x| try cbor.asText(x) else null,
        .error_message = if (cbor.mapGet(root, "error")) |x| try cbor.asText(x) else null,
        .payload = payload,
    };
}

fn statusToError(code: i64) anyerror {
    return switch (code) {
        0 => unreachable, // Ok is not an error
        1 => error.RpcMalformedEnvelope,
        2 => error.RpcUnknownServiceOrOp,
        3 => error.RpcUnauthenticated,
        4 => error.RpcForbidden,
        5 => error.RpcVersionUnsupported,
        6 => error.RpcInternal,
        7 => error.RpcUnavailable,
        8 => error.RpcDeadlineExceeded,
        else => error.RpcServerError,
    };
}

// ---------------------------------------------------------------------
// Stream framing (4-byte big-endian length prefix)
// ---------------------------------------------------------------------

pub fn writeLengthPrefixed(stream: std.net.Stream, bytes: []const u8) !void {
    if (bytes.len > max_frame_size) return error.FrameTooLarge;
    var prefix: [4]u8 = undefined;
    std.mem.writeInt(u32, &prefix, @intCast(bytes.len), .big);
    try stream.writeAll(&prefix);
    try stream.writeAll(bytes);
}

/// Reads one length-prefixed frame, enforcing the max-frame guard before
/// allocating. Returns `null` at a clean EOF before any byte of a frame.
pub fn readLengthPrefixed(allocator: std.mem.Allocator, stream: std.net.Stream, max_frame: usize) !?[]u8 {
    var prefix: [4]u8 = undefined;
    const n = try stream.readAll(&prefix);
    if (n == 0) return null;
    if (n != 4) return error.ConnectionClosed;
    const len = std.mem.readInt(u32, &prefix, .big);
    if (len > max_frame) return error.FrameTooLarge;
    const buf = try allocator.alloc(u8, len);
    const got = try stream.readAll(buf);
    if (got != len) return error.ConnectionClosed;
    return buf;
}

// ---------------------------------------------------------------------
// Domain endpoint discovery (DNS fp= pinning + tcp= endpoint)
// ---------------------------------------------------------------------

pub const DomainEndpoint = struct {
    fingerprints: []const []const u8,
    tcp_addr: []const u8,
};

/// Looks up a domain's trust anchor + TCP endpoint over DNS TXT. Fails
/// closed: a missing/unparseable record, or a `_linkkeys` record with no
/// `fp=` entries, or a `_linkkeys_apis` record with no `tcp=` entry, is an
/// error — this SDK never proceeds without a fingerprint set to pin to.
pub fn discoverDomainEndpoint(allocator: std.mem.Allocator, dns: dnsmod.DnsResolver, domain: []const u8) !DomainEndpoint {
    const anchor_name = try dnsmod.linkKeysDnsName(allocator, domain);
    const anchor_txts = try dns.txtLookup(allocator, anchor_name);
    var fingerprints: ?[]const []const u8 = null;
    for (anchor_txts) |txt| {
        const rec = dnsmod.parseLinkKeysTxt(allocator, txt) catch continue;
        if (rec.fingerprints.len > 0) {
            fingerprints = rec.fingerprints;
            break;
        }
    }
    const fps = fingerprints orelse return error.NoTrustAnchorRecord;

    const apis_name = try dnsmod.linkKeysApisDnsName(allocator, domain);
    const apis_txts = try dns.txtLookup(allocator, apis_name);
    var tcp_addr: ?[]const u8 = null;
    for (apis_txts) |txt| {
        const apis = dnsmod.parseLinkKeysApisTxt(allocator, txt) catch continue;
        if (apis.tcp) |t| {
            tcp_addr = t;
            break;
        }
    }
    const addr = tcp_addr orelse return error.NoApisEndpointRecord;

    return .{ .fingerprints = fps, .tcp_addr = addr };
}

// ---------------------------------------------------------------------
// Secure dial seam (see module docs: pinned TLS is not implemented)
// ---------------------------------------------------------------------

pub const SecureDial = *const fn (transport: transportmod.Transport, allocator: std.mem.Allocator, endpoint: DomainEndpoint) anyerror!std.net.Stream;

/// Always fails closed. See this module's docs and `tls_pin.zig` for why:
/// `std.crypto.tls.Client` cannot expose the peer certificate needed for
/// the MANDATORY SPKI pin check, so there is no safe default pinned-TLS
/// implementation to fall back to — connecting *unpinned* would silently
/// defeat the entire trust model (design doc: "an unauthenticated, unpinned
/// fetch would let a LAN MITM substitute domain keys and defeat every
/// downstream signature check").
pub fn defaultSecureDial(transport: transportmod.Transport, allocator: std.mem.Allocator, endpoint: DomainEndpoint) anyerror!std.net.Stream {
    _ = transport;
    _ = allocator;
    _ = endpoint;
    return error.PinnedTlsUnavailable;
}

fn call(allocator: std.mem.Allocator, transport: transportmod.Transport, secure_dial: SecureDial, endpoint: DomainEndpoint, service: []const u8, op: []const u8, payload: []const u8) ![]const u8 {
    const stream = try secure_dial(transport, allocator, endpoint);
    defer stream.close();

    const req_bytes = try encodeRpcRequest(allocator, service, op, payload);
    try writeLengthPrefixed(stream, req_bytes);

    const resp_bytes = try readLengthPrefixed(allocator, stream, max_frame_size) orelse return error.ConnectionClosed;
    const resp = try decodeRpcResponse(allocator, resp_bytes);
    if (resp.status != 0) return statusToError(resp.status);
    return resp.payload;
}

// ---------------------------------------------------------------------
// Domain-key + revocation fetch, ticket redemption
// ---------------------------------------------------------------------

/// Fetches `domain`'s currently-trusted public keys: `DomainKeys/get-domain-keys`
/// over TCP CSIL-RPC, pinned to the domain's DNS `fp=` set, with signing keys
/// pinned directly and encryption keys trusted only via a pinned signing
/// key's vouch (`dns.trustKeys`). Always also fetches
/// `DomainKeys/get-revocations` for the same domain — regardless of what the
/// `get-domain-keys` response's `recent_revocations_available` flag says —
/// and drops any key a quorum-verified sibling revocation certificate
/// targets.
///
/// SEC fix (fail-open -> fail-closed): `recent_revocations_available` is an
/// optional performance hint a well-behaved IDP may use to signal "you don't
/// even need to ask"; a compromised/malicious or merely buggy IDP could
/// otherwise use its absence to suppress this SDK from ever learning about a
/// revocation, which is exactly the scenario revocation exists to guard
/// against — so this SDK never uses it to skip the check. A
/// `get-revocations` RPC error (connection failure, non-Ok status, or
/// response decode failure) is FATAL and propagated: this SDK must fail
/// closed rather than silently proceed with a possibly-stale key set an
/// attacker could have engineered by making the endpoint fail. An empty
/// revocation list is normal success (nothing to apply). An empty trusted
/// result (after applying revocations) is `error.NoTrustedDomainKeys` — fail
/// closed, matching the server's own posture.
pub fn fetchDomainKeys(allocator: std.mem.Allocator, transport: transportmod.Transport, secure_dial: SecureDial, dns: dnsmod.DnsResolver, domain: []const u8) ![]types.DomainPublicKey {
    const endpoint = try discoverDomainEndpoint(allocator, dns, domain);

    const req_payload = try types.encodeEmptyRequest(allocator);
    const resp_bytes = try call(allocator, transport, secure_dial, endpoint, "DomainKeys", "get-domain-keys", req_payload);
    const resp = try types.decodeGetDomainKeysResponse(allocator, resp_bytes);

    var trusted = try dnsmod.trustKeys(allocator, resp.keys, endpoint.fingerprints);
    if (trusted.len == 0) return error.NoTrustedDomainKeys;

    // Always fetch revocations — never gated on `recent_revocations_available`
    // (see this function's doc comment). Any failure here propagates via
    // `try`, i.e. is FATAL: it must never be swallowed to "just proceed
    // unfiltered".
    var since_buf: [32]u8 = undefined;
    const local_rp = @import("local_rp.zig");
    const since = try local_rp.formatTimestamp(&since_buf, std.time.timestamp() - 30 * 24 * 60 * 60);
    const rev_req_payload = try types.encodeGetRevocationsRequest(allocator, since);
    const rev_resp_bytes = try call(allocator, transport, secure_dial, endpoint, "DomainKeys", "get-revocations", rev_req_payload);
    const rev_resp = try types.decodeGetRevocationsResponse(allocator, rev_resp_bytes);
    for (rev_resp.revocations) |cert| {
        if (revocation.verifyRevocationCertificate(allocator, cert, trusted, domain)) |_| {
            trusted = removeKeyById(trusted, cert.target_key_id);
        } else |_| {}
    }

    if (trusted.len == 0) return error.NoTrustedDomainKeys;
    return trusted;
}

fn removeKeyById(keys: []types.DomainPublicKey, key_id: []const u8) []types.DomainPublicKey {
    var write: usize = 0;
    for (keys) |k| {
        if (!std.mem.eql(u8, k.key_id, key_id)) {
            keys[write] = k;
            write += 1;
        }
    }
    return keys[0..write];
}

/// Redeems a claim ticket with `domain`'s IDP: `LocalRp/redeem-claim-ticket`
/// over TCP CSIL-RPC, pinned via the domain's DNS `fp=` set. Unauthenticated
/// at the transport layer (no client cert) — the redemption request itself
/// is signed with the local RP's signing key, which is the possession proof
/// the server checks.
pub fn redeemClaimTicket(allocator: std.mem.Allocator, transport: transportmod.Transport, secure_dial: SecureDial, dns: dnsmod.DnsResolver, domain: []const u8, signed_request: types.SignedLocalRpTicketRedemptionRequest) !types.LocalRpTicketRedemptionResponse {
    const endpoint = try discoverDomainEndpoint(allocator, dns, domain);
    const payload = try types.encodeSignedLocalRpTicketRedemptionRequest(allocator, signed_request);
    const resp_bytes = try call(allocator, transport, secure_dial, endpoint, "LocalRp", "redeem-claim-ticket", payload);
    return types.decodeLocalRpTicketRedemptionResponse(allocator, resp_bytes);
}

test "RpcRequest/RpcResponse envelope round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const req_bytes = try encodeRpcRequest(a, "DomainKeys", "get-domain-keys", "hello-payload");
    const decoded_root = try cbor.decode(a, req_bytes);
    try std.testing.expectEqualStrings("DomainKeys", try cbor.asText(try cbor.require(decoded_root, "service")));
    try std.testing.expectEqualStrings("get-domain-keys", try cbor.asText(try cbor.require(decoded_root, "op")));
    const payload_val = try cbor.require(decoded_root, "payload");
    try std.testing.expectEqualStrings("hello-payload", try untag24(payload_val));

    // Build a response the way a server would and decode it back.
    var payload_bytes_val = cbor.bytesVal("resp-payload");
    const resp_entries = [_]cbor.Entry{
        .{ .key = cbor.text("v"), .value = cbor.uint(1) },
        .{ .key = cbor.text("status"), .value = cbor.uint(0) },
        .{ .key = cbor.text("variant"), .value = cbor.text("GetDomainKeysResponse") },
        .{ .key = cbor.text("payload"), .value = cbor.tagVal(24, &payload_bytes_val) },
    };
    const resp_bytes = try cbor.encodeAlloc(a, cbor.mapVal(&resp_entries));
    const resp = try decodeRpcResponse(a, resp_bytes);
    try std.testing.expectEqual(@as(i64, 0), resp.status);
    try std.testing.expectEqualStrings("GetDomainKeysResponse", resp.variant.?);
    try std.testing.expectEqualStrings("resp-payload", resp.payload);
}

test "length-prefix framing is byte-exact" {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, 5, .big);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 5 }, &buf);
}

test "defaultSecureDial always fails closed" {
    var st = transportmod.StdTransport{};
    const endpoint = DomainEndpoint{ .fingerprints = &.{}, .tcp_addr = "127.0.0.1:1" };
    try std.testing.expectError(error.PinnedTlsUnavailable, defaultSecureDial(st.transport(), std.testing.allocator, endpoint));
}
