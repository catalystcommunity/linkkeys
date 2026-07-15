//! DNS TXT record parsing, pinning, and vouch verification — mirrors
//! `crates/liblinkkeys/src/dns.rs` / `sdks/local-rp/go/dns.go`. Also hosts
//! the `DnsResolver` seam (design doc "Required Network Access": every SDK
//! needs a DNS TXT lookup capability, configurable, defaulting to the system
//! resolver) and a hand-rolled, bounded UDP DNS TXT client — no stdlib TXT
//! lookup API exists in Zig 0.14 (`std.net` has no DNS resolver at all
//! beyond what the OS `getaddrinfo` gives for A/AAAA records), so this SDK
//! implements the minimal single-question/TXT-answer wire subset of RFC 1035
//! itself, plus `/etc/resolv.conf` nameserver discovery.

const std = @import("std");
const types = @import("types.zig");
const xcrypto = @import("crypto.zig");
const local_rp = @import("local_rp.zig");

/// Default TCP port for the LinkKeys protocol service. Advertised `tcp=`
/// values omit the port when it equals this.
pub const default_tcp_port: u16 = 4987;

pub const LinkKeysRecord = struct {
    fingerprints: []const []const u8,
};

pub const LinkKeysApis = struct {
    tcp: ?[]const u8 = null,
    https_base: ?[]const u8 = null,
};

pub fn linkKeysDnsName(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "_linkkeys.{s}", .{domain});
}

pub fn linkKeysApisDnsName(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "_linkkeys_apis.{s}", .{domain});
}

fn requireLk1Version(it: *std.mem.TokenIterator(u8, .any)) !void {
    var saved = it.*;
    while (saved.next()) |part| {
        if (std.mem.startsWith(u8, part, "v=")) {
            const version = part[2..];
            if (!std.mem.eql(u8, version, "lk1")) return error.UnsupportedVersion;
            return;
        }
    }
    return error.MissingVersion;
}

/// Parses a single `_linkkeys` TXT record string. Errors if it isn't a
/// LinkKeys v1 record (no `v=lk1` tag).
pub fn parseLinkKeysTxt(allocator: std.mem.Allocator, txt: []const u8) !LinkKeysRecord {
    var it = std.mem.tokenizeAny(u8, txt, " \t\r\n");
    try requireLk1Version(&it);

    var fps = std.ArrayList([]const u8).init(allocator);
    it.reset();
    while (it.next()) |part| {
        if (std.mem.startsWith(u8, part, "fp=")) try fps.append(part[3..]);
    }
    return .{ .fingerprints = try fps.toOwnedSlice() };
}

fn normalizeTcpEndpoint(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    if (value.len == 0 or std.mem.indexOfScalar(u8, value, ':') != null) return value;
    return std.fmt.allocPrint(allocator, "{s}:{d}", .{ value, default_tcp_port });
}

/// Parses a single `_linkkeys_apis` TXT record string. Errors if it isn't a
/// LinkKeys v1 record or carries no endpoint.
pub fn parseLinkKeysApisTxt(allocator: std.mem.Allocator, txt: []const u8) !LinkKeysApis {
    var it = std.mem.tokenizeAny(u8, txt, " \t\r\n");
    try requireLk1Version(&it);

    var tcp: ?[]const u8 = null;
    var https_base: ?[]const u8 = null;
    it.reset();
    while (it.next()) |part| {
        if (tcp == null and std.mem.startsWith(u8, part, "tcp=")) {
            const v = try normalizeTcpEndpoint(allocator, part[4..]);
            if (v.len > 0) tcp = v;
        }
        if (https_base == null and std.mem.startsWith(u8, part, "https=")) {
            const v = part[6..];
            if (v.len > 0) https_base = try std.fmt.allocPrint(allocator, "https://{s}", .{v});
        }
    }
    if (tcp == null and https_base == null) return error.MissingApisEndpoint;
    return .{ .tcp = tcp, .https_base = https_base };
}

/// Reports whether `fp` is a syntactically valid key fingerprint: 64 hex
/// chars (a SHA-256 digest), case-insensitive.
pub fn isValidFingerprint(fp: []const u8) bool {
    if (fp.len != 64) return false;
    for (fp) |b| {
        const ok = (b >= '0' and b <= '9') or (b >= 'a' and b <= 'f') or (b >= 'A' and b <= 'F');
        if (!ok) return false;
    }
    return true;
}

fn eqlIgnoreCaseHex(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

/// Pins fetched keys to the DNS-published fingerprint set: for each
/// candidate key it RECOMPUTES `Fingerprint(public_key)` (never trusting the
/// wire `fingerprint` field, which is attacker-controlled) and keeps only
/// keys whose recomputed fingerprint is a member of `pinned`. An empty
/// result means "no trustworthy keys" — callers must fail closed.
pub fn pinKeysToFingerprints(allocator: std.mem.Allocator, keys: []const types.DomainPublicKey, pinned: []const []const u8) ![]types.DomainPublicKey {
    var out = std.ArrayList(types.DomainPublicKey).init(allocator);
    for (keys) |k| {
        const fp = xcrypto.fingerprintHex(k.public_key);
        for (pinned) |p| {
            if (isValidFingerprint(p) and eqlIgnoreCaseHex(&fp, p)) {
                try out.append(k);
                break;
            }
        }
    }
    return out.toOwnedSlice();
}

/// Domain-separation tag for a signing key's vouch over an encryption key.
pub const key_vouch_tag = "linkkeys-key-vouch-v1";

pub fn keyVouchPayload(allocator: std.mem.Allocator, enc_fingerprint: []const u8, enc_expires_at: []const u8) ![]u8 {
    const cbor = @import("cbor.zig");
    const items = [_]cbor.Value{ cbor.text(key_vouch_tag), cbor.text(enc_fingerprint), cbor.text(enc_expires_at) };
    return cbor.encodeTuple(allocator, &items);
}

/// Verifies that `signing_key` vouches for `enc_key`: the encryption key
/// names this signing key, the signing key is itself valid (not
/// revoked/expired), and its signature covers the recomputed encrypt-key
/// fingerprint + expiry.
pub fn verifyKeyVouch(allocator: std.mem.Allocator, enc_key: types.DomainPublicKey, signing_key: types.DomainPublicKey) bool {
    const signed_by = enc_key.signed_by_key_id orelse return false;
    if (!std.mem.eql(u8, signed_by, signing_key.key_id)) return false;
    local_rp.checkSigningKeyValid(signing_key) catch return false;
    const key_sig = enc_key.key_signature orelse return false;
    const fp = xcrypto.fingerprintHex(enc_key.public_key);
    const payload = keyVouchPayload(allocator, &fp, enc_key.expires_at) catch return false;
    xcrypto.resolveAndVerify(signing_key.algorithm, payload, key_sig, signing_key.public_key) catch return false;
    return true;
}

/// Establishes the trusted key set from a fetched key list and the
/// DNS-pinned fingerprint set: signing keys (`key_usage == "sign"`) are
/// pinned directly; encryption keys (`key_usage == "encrypt"`) are trusted
/// only when a DNS-pinned signing key vouches for them. Anything not pinned
/// or not vouched is dropped.
pub fn trustKeys(allocator: std.mem.Allocator, keys: []const types.DomainPublicKey, pinned: []const []const u8) ![]types.DomainPublicKey {
    var signing = std.ArrayList(types.DomainPublicKey).init(allocator);
    for (keys) |k| {
        if (std.mem.eql(u8, k.key_usage, "sign")) try signing.append(k);
    }
    const pinned_signing = try pinKeysToFingerprints(allocator, signing.items, pinned);

    var trusted = std.ArrayList(types.DomainPublicKey).init(allocator);
    try trusted.appendSlice(pinned_signing);
    for (keys) |k| {
        if (!std.mem.eql(u8, k.key_usage, "encrypt")) continue;
        for (pinned_signing) |sk| {
            if (verifyKeyVouch(allocator, k, sk)) {
                try trusted.append(k);
                break;
            }
        }
    }
    return trusted.toOwnedSlice();
}

// ---------------------------------------------------------------------
// DnsResolver seam
// ---------------------------------------------------------------------

/// DNS TXT lookup seam (design doc: "Required Network Access" — the SDK
/// needs a DNS TXT lookup capability; injectable so tests can supply canned
/// answers and operators can supply a hardened resolver, e.g. a DoH client).
/// Vtable-style interface, the idiomatic Zig dynamic-dispatch pattern.
pub const DnsResolver = struct {
    ptr: *anyopaque,
    txtLookupFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const []const u8,

    /// Resolves TXT records for a fully-qualified name (e.g.
    /// `_linkkeys.example.com`). Each returned string is one TXT record's
    /// content — the concatenation of its character-strings.
    pub fn txtLookup(self: DnsResolver, allocator: std.mem.Allocator, name: []const u8) ![]const []const u8 {
        return self.txtLookupFn(self.ptr, allocator, name);
    }
};

// ---------------------------------------------------------------------
// Hand-rolled UDP DNS TXT client (RFC 1035 subset: one question, TXT
// answers, multi-string record concatenation, basic name-compression
// support for skipping answer names).
// ---------------------------------------------------------------------

const dns_type_txt: u16 = 16;
const dns_class_in: u16 = 1;

fn appendQname(list: *std.ArrayList(u8), name: []const u8) !void {
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue;
        if (label.len > 63) return error.DnsLabelTooLong;
        try list.append(@intCast(label.len));
        try list.appendSlice(label);
    }
    try list.append(0);
}

fn buildQuery(allocator: std.mem.Allocator, id: u16, name: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    try out.appendSlice(&[_]u8{
        @intCast(id >> 8), @intCast(id & 0xff),
        0x01, 0x00, // flags: standard query, recursion desired
        0x00, 0x01, // qdcount=1
        0x00, 0x00, // ancount=0
        0x00, 0x00, // nscount=0
        0x00, 0x00, // arcount=0
    });
    try appendQname(&out, name);
    try out.appendSlice(&[_]u8{
        @intCast(dns_type_txt >> 8), @intCast(dns_type_txt & 0xff),
        @intCast(dns_class_in >> 8), @intCast(dns_class_in & 0xff),
    });
    return out.toOwnedSlice();
}

/// Skips a (possibly compressed) DNS name starting at `pos`, advancing
/// `pos` past it. Names in questions/answers are not otherwise inspected —
/// this resolver trusts response ordering (single question, then its
/// answers), matching the scope of a minimal bounded client.
fn skipName(msg: []const u8, pos: *usize) !void {
    var cur = pos.*;
    var guard: usize = 0;
    while (true) {
        guard += 1;
        if (guard > 128) return error.DnsMessageMalformed;
        if (cur >= msg.len) return error.DnsMessageMalformed;
        const len = msg[cur];
        if (len == 0) {
            cur += 1;
            break;
        } else if ((len & 0xC0) == 0xC0) {
            if (cur + 1 >= msg.len) return error.DnsMessageMalformed;
            cur += 2;
            break; // a pointer always terminates the name at this level
        } else {
            cur += 1 + len;
            if (cur > msg.len) return error.DnsMessageMalformed;
        }
    }
    pos.* = cur;
}

fn readU16(msg: []const u8, pos: usize) !u16 {
    if (pos + 2 > msg.len) return error.DnsMessageMalformed;
    return std.mem.readInt(u16, msg[pos..][0..2], .big);
}
fn readU32(msg: []const u8, pos: usize) !u32 {
    if (pos + 4 > msg.len) return error.DnsMessageMalformed;
    return std.mem.readInt(u32, msg[pos..][0..4], .big);
}

/// Parses a DNS response for TXT answers, returning each answer's
/// concatenated character-strings.
pub fn parseTxtResponse(allocator: std.mem.Allocator, msg: []const u8) ![]const []const u8 {
    if (msg.len < 12) return error.DnsMessageMalformed;
    const qdcount = try readU16(msg, 4);
    const ancount = try readU16(msg, 6);

    var pos: usize = 12;
    var i: u16 = 0;
    while (i < qdcount) : (i += 1) {
        try skipName(msg, &pos);
        pos += 4; // qtype + qclass
    }

    var results = std.ArrayList([]const u8).init(allocator);
    i = 0;
    while (i < ancount) : (i += 1) {
        try skipName(msg, &pos);
        const rtype = try readU16(msg, pos);
        pos += 2;
        _ = try readU16(msg, pos); // class
        pos += 2;
        _ = try readU32(msg, pos); // ttl
        pos += 4;
        const rdlength = try readU16(msg, pos);
        pos += 2;
        if (pos + rdlength > msg.len) return error.DnsMessageMalformed;
        const rdata = msg[pos .. pos + rdlength];
        pos += rdlength;

        if (rtype == dns_type_txt) {
            var record = std.ArrayList(u8).init(allocator);
            var rp: usize = 0;
            while (rp < rdata.len) {
                const slen = rdata[rp];
                rp += 1;
                if (rp + slen > rdata.len) return error.DnsMessageMalformed;
                try record.appendSlice(rdata[rp .. rp + slen]);
                rp += slen;
            }
            try results.append(try record.toOwnedSlice());
        }
    }
    return results.toOwnedSlice();
}

/// Reads the first `nameserver` line from `/etc/resolv.conf`. Linux/POSIX
/// only (matches this environment); callers on other platforms should
/// inject their own `DnsResolver`.
pub fn discoverSystemNameserver(allocator: std.mem.Allocator) !std.net.Address {
    const file = std.fs.openFileAbsolute("/etc/resolv.conf", .{}) catch return error.NoNameserverConfigured;
    defer file.close();
    const contents = try file.readToEndAlloc(allocator, 64 * 1024);

    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "nameserver")) continue;
        var it = std.mem.tokenizeAny(u8, trimmed, " \t");
        _ = it.next(); // "nameserver"
        const ip = it.next() orelse continue;
        const addr = std.net.Address.parseIp(ip, 53) catch continue;
        return addr;
    }
    return error.NoNameserverConfigured;
}

pub const SystemDnsResolverError = error{
    NoNameserverConfigured,
    DnsTimeout,
    DnsMessageMalformed,
    DnsLabelTooLong,
};

/// The default `DnsResolver`: the OS-configured system resolver (raw UDP,
/// `/etc/resolv.conf`-discovered nameserver by default, or an explicit
/// override). Per the design doc's "Decided" section: resolver spoofing on
/// a LAN is an accepted, documented tradeoff for this mode; operators
/// wanting hardening can inject their own `DnsResolver` (e.g. a DoH client).
pub const SystemDnsResolver = struct {
    nameserver: std.net.Address,
    timeout_ms: i32 = 5000,

    pub fn init() !SystemDnsResolver {
        const gpa = std.heap.page_allocator;
        const ns = try discoverSystemNameserver(gpa);
        return .{ .nameserver = ns };
    }

    pub fn initWithNameserver(addr: std.net.Address) SystemDnsResolver {
        return .{ .nameserver = addr };
    }

    pub fn resolver(self: *SystemDnsResolver) DnsResolver {
        return .{ .ptr = self, .txtLookupFn = txtLookupImpl };
    }

    fn txtLookupImpl(ptr: *anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const []const u8 {
        const self: *SystemDnsResolver = @ptrCast(@alignCast(ptr));
        return self.txtLookup(allocator, name);
    }

    pub fn txtLookup(self: *SystemDnsResolver, allocator: std.mem.Allocator, name: []const u8) ![]const []const u8 {
        const posix = std.posix;
        var rand_bytes: [2]u8 = undefined;
        xcrypto.randomBytes(&rand_bytes);
        const id: u16 = (@as(u16, rand_bytes[0]) << 8) | rand_bytes[1];

        const query = try buildQuery(allocator, id, name);

        const sock = try posix.socket(self.nameserver.any.family, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        defer posix.close(sock);

        const dest_addr: *const posix.sockaddr = @ptrCast(&self.nameserver.any);
        _ = try posix.sendto(sock, query, 0, dest_addr, self.nameserver.getOsSockLen());

        var pfd = [_]posix.pollfd{.{ .fd = sock, .events = posix.POLL.IN, .revents = 0 }};
        const n_ready = try posix.poll(&pfd, self.timeout_ms);
        if (n_ready == 0) return error.DnsTimeout;

        var buf: [4096]u8 = undefined;
        const n = try posix.recvfrom(sock, &buf, 0, null, null);
        return parseTxtResponse(allocator, buf[0..n]);
    }
};

test "parseLinkKeysTxt: valid multi-fingerprint record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rec = try parseLinkKeysTxt(a, "v=lk1 fp=aa fp=bb fp=cc");
    try std.testing.expectEqual(@as(usize, 3), rec.fingerprints.len);
    try std.testing.expectEqualStrings("aa", rec.fingerprints[0]);
    try std.testing.expectEqualStrings("cc", rec.fingerprints[2]);
}

test "parseLinkKeysTxt: missing version rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.MissingVersion, parseLinkKeysTxt(arena.allocator(), "fp=abc"));
}

test "parseLinkKeysTxt: unsupported version rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.UnsupportedVersion, parseLinkKeysTxt(arena.allocator(), "v=lk99 fp=abc"));
}

test "parseLinkKeysApisTxt: tcp port defaulted" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const apis = try parseLinkKeysApisTxt(a, "v=lk1 tcp=idp.example.com");
    try std.testing.expectEqualStrings("idp.example.com:4987", apis.tcp.?);
    try std.testing.expect(apis.https_base == null);
}

test "parseLinkKeysApisTxt: missing endpoint rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.MissingApisEndpoint, parseLinkKeysApisTxt(arena.allocator(), "v=lk1"));
}

test "DNS wire round trip: build query, synthesize a response, parse TXT" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const query = try buildQuery(a, 0x1234, "_linkkeys.example.com");
    try std.testing.expect(query.len > 12);

    // Synthesize a minimal response: header + the same question + one TXT
    // answer (as a compressed-name pointer to offset 12) with two
    // character-strings that must concatenate.
    var resp = std.ArrayList(u8).init(a);
    try resp.appendSlice(&[_]u8{ 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
    try resp.appendSlice(query[12..]); // echo the question section
    // Answer: pointer to offset 12 (0xC0 0x0C), type=TXT, class=IN, ttl=0, rdlength, rdata
    try resp.appendSlice(&[_]u8{ 0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
    const part1 = "v=lk1 fp=";
    const part2 = "aabbcc";
    var rdata = std.ArrayList(u8).init(a);
    try rdata.append(@intCast(part1.len));
    try rdata.appendSlice(part1);
    try rdata.append(@intCast(part2.len));
    try rdata.appendSlice(part2);
    try resp.appendSlice(&[_]u8{ 0x00, @intCast(rdata.items.len) });
    try resp.appendSlice(rdata.items);

    const txts = try parseTxtResponse(a, resp.items);
    try std.testing.expectEqual(@as(usize, 1), txts.len);
    try std.testing.expectEqualStrings("v=lk1 fp=aabbcc", txts[0]);
}
