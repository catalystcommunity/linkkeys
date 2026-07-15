//! Minimal hand-written canonical CBOR codec.
//!
//! No csilgen Zig target exists (see the csilgen request filed alongside this
//! SDK), so this module is the Zig replacement for what other SDKs get from
//! generated `codec.gen.go` / `liblinkkeys::generated` code: a value-tree
//! encoder/decoder covering exactly the shapes the local-RP protocol needs —
//! unsigned/negative integers, bool, null, text strings, byte strings,
//! definite-length arrays, definite-length maps, and tag-24 (for CSIL-RPC
//! envelope payloads). No floats, no indefinite-length items: the protocol
//! never uses them (mirrors the Go SDK's `cbor.go` doc comment making the
//! same scoping call).
//!
//! Canonical encoding (RFC 8949 §4.2.1): map entries are sorted by their
//! *encoded key bytes*, bytewise lexicographic. Decoding is always by
//! key-name lookup (`mapGet`), so it is order-independent — this is what
//! makes wire interop with the Go/Rust reference codecs work even though
//! their generated encoders emit a fixed declaration order rather than a
//! truly sorted one (both are valid CBOR; only OUR encoder needs to be
//! canonical for this SDK's own conformance-vector byte-exact checks, e.g.
//! `EnvelopeSignatureInput` against `envelopes.json`'s
//! `signature_input_cbor_hex`).

const std = @import("std");

pub const Entry = struct { key: Value, value: Value };
pub const Tag = struct { number: u64, value: *const Value };

pub const Value = union(enum) {
    uint: u64,
    /// A negative integer, stored as its actual (negative) value.
    nint: i64,
    bool: bool,
    null,
    text: []const u8,
    bytes: []const u8,
    array: []const Value,
    map: []const Entry,
    tag: Tag,
};

pub fn text(s: []const u8) Value {
    return .{ .text = s };
}
pub fn bytesVal(b: []const u8) Value {
    return .{ .bytes = b };
}
pub fn uint(n: u64) Value {
    return .{ .uint = n };
}
pub fn boolVal(b: bool) Value {
    return .{ .bool = b };
}
pub const nullVal: Value = .null;
pub fn arrayVal(items: []const Value) Value {
    return .{ .array = items };
}
pub fn mapVal(entries: []const Entry) Value {
    return .{ .map = entries };
}
pub fn tagVal(number: u64, inner: *const Value) Value {
    return .{ .tag = .{ .number = number, .value = inner } };
}
/// `Option<&str>`: `Some(s)` as a text string, `None` as CBOR null — matches
/// how serde/ciborium serialize an `Option` field inside a signed tuple (see
/// the Go SDK's `cborOptText`).
pub fn optText(s: ?[]const u8) Value {
    return if (s) |x| text(x) else nullVal;
}

// ---------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------

fn encodeHead(out: *std.ArrayList(u8), major: u3, n: u64) !void {
    const m: u8 = @as(u8, major) << 5;
    if (n < 24) {
        try out.append(m | @as(u8, @intCast(n)));
    } else if (n <= 0xff) {
        try out.appendSlice(&[_]u8{ m | 24, @intCast(n) });
    } else if (n <= 0xffff) {
        var buf: [3]u8 = undefined;
        buf[0] = m | 25;
        std.mem.writeInt(u16, buf[1..3], @intCast(n), .big);
        try out.appendSlice(&buf);
    } else if (n <= 0xffffffff) {
        var buf: [5]u8 = undefined;
        buf[0] = m | 26;
        std.mem.writeInt(u32, buf[1..5], @intCast(n), .big);
        try out.appendSlice(&buf);
    } else {
        var buf: [9]u8 = undefined;
        buf[0] = m | 27;
        std.mem.writeInt(u64, buf[1..9], n, .big);
        try out.appendSlice(&buf);
    }
}

fn lessByKeyBytes(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn encodeInto(allocator: std.mem.Allocator, out: *std.ArrayList(u8), v: Value) anyerror!void {
    switch (v) {
        .uint => |n| try encodeHead(out, 0, n),
        .nint => |n| {
            std.debug.assert(n < 0);
            const arg: u64 = @intCast(-(n + 1));
            try encodeHead(out, 1, arg);
        },
        .bool => |b| try out.append(if (b) 0xf5 else 0xf4),
        .null => try out.append(0xf6),
        .text => |s| {
            try encodeHead(out, 3, s.len);
            try out.appendSlice(s);
        },
        .bytes => |b| {
            try encodeHead(out, 2, b.len);
            try out.appendSlice(b);
        },
        .array => |items| {
            try encodeHead(out, 4, items.len);
            for (items) |it| try encodeInto(allocator, out, it);
        },
        .map => |entries| {
            try encodeHead(out, 5, entries.len);
            if (entries.len == 0) return;
            const KeyedBytes = struct { key: []u8, val: []u8 };
            const pairs = try allocator.alloc(KeyedBytes, entries.len);
            for (entries, 0..) |e, i| {
                pairs[i] = .{
                    .key = try encodeAlloc(allocator, e.key),
                    .val = try encodeAlloc(allocator, e.value),
                };
            }
            const Ctx = struct {
                fn lessThan(_: void, a: KeyedBytes, b: KeyedBytes) bool {
                    return lessByKeyBytes({}, a.key, b.key);
                }
            };
            std.mem.sort(KeyedBytes, pairs, {}, Ctx.lessThan);
            for (pairs) |p| {
                try out.appendSlice(p.key);
                try out.appendSlice(p.val);
            }
        },
        .tag => |t| {
            try encodeHead(out, 6, t.number);
            try encodeInto(allocator, out, t.value.*);
        },
    }
}

/// Encodes `v` to canonical CBOR bytes owned by `allocator`.
pub fn encodeAlloc(allocator: std.mem.Allocator, v: Value) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try encodeInto(allocator, &out, v);
    return out.toOwnedSlice();
}

/// Encodes a definite-length CBOR array (major type 4) of the given
/// pre-built items, in order — the shape every signed "tuple" (envelope
/// signature input, revocation payload, claim payload, key-vouch payload)
/// needs.
pub fn encodeTuple(allocator: std.mem.Allocator, items: []const Value) ![]u8 {
    return encodeAlloc(allocator, arrayVal(items));
}

// ---------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------

pub const DecodeError = error{
    UnexpectedEndOfInput,
    TrailingBytes,
    ReservedAdditionalInfo,
    NegativeIntegerOutOfRange,
    UnsupportedSimpleValue,
    UnsupportedMajorType,
    TruncatedByteString,
    TruncatedTextString,
    NotValidUtf8,
    /// SEC fix (memory-exhaustion DoS, pre-auth reachable via the
    /// `encrypted_token` callback parameter): an array/map header declared
    /// more items than the remaining input could possibly hold. Every
    /// definite-length item needs at least one wire byte, so this is
    /// rejected before allocating for the declared count.
    DeclaredCountExceedsInput,
    /// SEC fix (stack-exhaustion DoS, same pre-auth entry point): nesting
    /// (array/map/tag) deeper than `max_decode_depth`.
    NestingTooDeep,
};

/// Bounds CBOR decode recursion (array/map/tag nesting). No shape this
/// protocol actually uses nests anywhere near this deep — this exists purely
/// to cap a hostile input's recursion depth before it can exhaust the stack.
pub const max_decode_depth: usize = 32;

fn readArg(bytes: []const u8, pos: *usize, low: u5) !u64 {
    if (low < 24) {
        pos.* += 1;
        return low;
    }
    switch (low) {
        24 => {
            if (pos.* + 2 > bytes.len) return error.UnexpectedEndOfInput;
            const v = bytes[pos.* + 1];
            pos.* += 2;
            return v;
        },
        25 => {
            if (pos.* + 3 > bytes.len) return error.UnexpectedEndOfInput;
            const v = std.mem.readInt(u16, bytes[pos.* + 1 ..][0..2], .big);
            pos.* += 3;
            return v;
        },
        26 => {
            if (pos.* + 5 > bytes.len) return error.UnexpectedEndOfInput;
            const v = std.mem.readInt(u32, bytes[pos.* + 1 ..][0..4], .big);
            pos.* += 5;
            return v;
        },
        27 => {
            if (pos.* + 9 > bytes.len) return error.UnexpectedEndOfInput;
            const v = std.mem.readInt(u64, bytes[pos.* + 1 ..][0..8], .big);
            pos.* += 9;
            return v;
        },
        else => return error.ReservedAdditionalInfo,
    }
}

fn decodeOne(allocator: std.mem.Allocator, bytes: []const u8, pos: *usize, depth: usize) anyerror!Value {
    if (depth > max_decode_depth) return error.NestingTooDeep;
    if (pos.* >= bytes.len) return error.UnexpectedEndOfInput;
    const ib = bytes[pos.*];
    const major: u3 = @intCast(ib >> 5);
    const low: u5 = @intCast(ib & 0x1f);

    if (major == 7) {
        switch (low) {
            20 => {
                pos.* += 1;
                return .{ .bool = false };
            },
            21 => {
                pos.* += 1;
                return .{ .bool = true };
            },
            22, 23 => {
                pos.* += 1;
                return .null;
            },
            else => return error.UnsupportedSimpleValue,
        }
    }

    const arg = try readArg(bytes, pos, low);
    switch (major) {
        0 => return .{ .uint = arg },
        1 => {
            if (arg > @as(u64, @intCast(std.math.maxInt(i64)))) return error.NegativeIntegerOutOfRange;
            return .{ .nint = -1 - @as(i64, @intCast(arg)) };
        },
        2 => {
            const n: usize = @intCast(arg);
            if (pos.* + n > bytes.len) return error.TruncatedByteString;
            const slice = try allocator.dupe(u8, bytes[pos.* .. pos.* + n]);
            pos.* += n;
            return .{ .bytes = slice };
        },
        3 => {
            const n: usize = @intCast(arg);
            if (pos.* + n > bytes.len) return error.TruncatedTextString;
            const slice = bytes[pos.* .. pos.* + n];
            if (!std.unicode.utf8ValidateSlice(slice)) return error.NotValidUtf8;
            const owned = try allocator.dupe(u8, slice);
            pos.* += n;
            return .{ .text = owned };
        },
        4 => {
            const n: usize = @intCast(arg);
            // SEC fix: bound the declared item count against the remaining
            // input before allocating. Every definite-length array item
            // needs at least one byte on the wire, so a declared count
            // exceeding the remaining bytes can never be satisfied and is
            // rejected up front rather than driving an unbounded allocation
            // (pre-auth reachable via the encrypted_token callback
            // parameter).
            if (n > bytes.len - pos.*) return error.DeclaredCountExceedsInput;
            const items = try allocator.alloc(Value, n);
            for (0..n) |i| items[i] = try decodeOne(allocator, bytes, pos, depth + 1);
            return .{ .array = items };
        },
        5 => {
            const n: usize = @intCast(arg);
            // Same bound as arrays, doubled: each map entry needs a key AND
            // a value, so at least two wire bytes.
            if (n > (bytes.len - pos.*) / 2) return error.DeclaredCountExceedsInput;
            const entries = try allocator.alloc(Entry, n);
            for (0..n) |i| {
                const k = try decodeOne(allocator, bytes, pos, depth + 1);
                const val = try decodeOne(allocator, bytes, pos, depth + 1);
                entries[i] = .{ .key = k, .value = val };
            }
            return .{ .map = entries };
        },
        6 => {
            const inner = try allocator.create(Value);
            inner.* = try decodeOne(allocator, bytes, pos, depth + 1);
            return .{ .tag = .{ .number = arg, .value = inner } };
        },
        else => return error.UnsupportedMajorType,
    }
}

/// Decodes exactly one CBOR item from `bytes`, rejecting trailing bytes.
/// Allocated sub-values (text/bytes copies, arrays, maps) are owned by
/// `allocator` — callers typically pass an arena allocator scoped to one
/// decode+verify operation.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Value {
    var pos: usize = 0;
    const v = try decodeOne(allocator, bytes, &pos, 0);
    if (pos != bytes.len) return error.TrailingBytes;
    return v;
}

// ---------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------

pub const AccessError = error{ MissingField, WrongType, NegativeWhereUnsignedExpected, IntegerOverflow };

pub fn mapGet(v: Value, key: []const u8) ?Value {
    if (v != .map) return null;
    for (v.map) |e| {
        if (e.key == .text and std.mem.eql(u8, e.key.text, key)) return e.value;
    }
    return null;
}

pub fn require(v: Value, key: []const u8) AccessError!Value {
    return mapGet(v, key) orelse error.MissingField;
}

pub fn asText(v: Value) AccessError![]const u8 {
    return if (v == .text) v.text else error.WrongType;
}

pub fn asBytes(v: Value) AccessError![]const u8 {
    return if (v == .bytes) v.bytes else error.WrongType;
}

pub fn asBool(v: Value) AccessError!bool {
    return if (v == .bool) v.bool else error.WrongType;
}

pub fn asU64(v: Value) AccessError!u64 {
    return switch (v) {
        .uint => |n| n,
        .nint => error.NegativeWhereUnsignedExpected,
        else => error.WrongType,
    };
}

pub fn asArray(v: Value) AccessError![]const Value {
    return if (v == .array) v.array else error.WrongType;
}

test "canonical map key ordering: shorter/lexicographically-earlier keys first" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const entries = [_]Entry{
        .{ .key = text("zebra"), .value = uint(1) },
        .{ .key = text("a"), .value = uint(2) },
        .{ .key = text("ab"), .value = uint(3) },
    };
    const encoded = try encodeAlloc(a, mapVal(&entries));

    // Expect key order: "a" (1 byte text head+char), "ab" (2 bytes), "zebra".
    // Head bytes: text major=3 -> 0x61 'a', then 0x62 "ab", then 0x65 "zebra".
    const decoded = try decode(a, encoded);
    try std.testing.expect(decoded == .map);
    try std.testing.expectEqualStrings("a", decoded.map[0].key.text);
    try std.testing.expectEqualStrings("ab", decoded.map[1].key.text);
    try std.testing.expectEqualStrings("zebra", decoded.map[2].key.text);
}

test "tuple encode/decode round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const items = [_]Value{ text("linkkeys-local-rp-descriptor"), bytesVal("payload-bytes") };
    const encoded = try encodeTuple(a, &items);
    const decoded = try decode(a, encoded);
    const arr = try asArray(decoded);
    try std.testing.expectEqual(@as(usize, 2), arr.len);
    try std.testing.expectEqualStrings("linkkeys-local-rp-descriptor", try asText(arr[0]));
    try std.testing.expectEqualStrings("payload-bytes", try asBytes(arr[1]));
}

test "tag-24 wrap/unwrap" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const inner = bytesVal("hello");
    const encoded = try encodeAlloc(a, tagVal(24, &inner));
    const decoded = try decode(a, encoded);
    try std.testing.expect(decoded == .tag);
    try std.testing.expectEqual(@as(u64, 24), decoded.tag.number);
    try std.testing.expectEqualStrings("hello", try asBytes(decoded.tag.value.*));
}

test "SEC: array header declaring a count far beyond the remaining input is rejected before allocating" {
    // Major type 4 (array), additional info 26 (4-byte length follows),
    // declaring 0xFFFFFFFF (~4.3 billion) items, then NO item bytes at all.
    // A naive decoder would `allocator.alloc(Value, 0xFFFFFFFF)` here.
    const bytes = [_]u8{ 0x9A, 0xFF, 0xFF, 0xFF, 0xFF };
    try std.testing.expectError(error.DeclaredCountExceedsInput, decode(std.testing.allocator, &bytes));
}

test "SEC: map header declaring a count far beyond the remaining input is rejected before allocating" {
    // Major type 5 (map), additional info 26 (4-byte length follows),
    // declaring 0xFFFFFFFF entries, then no key/value bytes at all.
    const bytes = [_]u8{ 0xBA, 0xFF, 0xFF, 0xFF, 0xFF };
    try std.testing.expectError(error.DeclaredCountExceedsInput, decode(std.testing.allocator, &bytes));
}

test "SEC: an array count that just barely fits the remaining input still decodes" {
    // 3 single-byte items (uint 0,1,2) declared and present: legitimate,
    // must not be rejected by the new bound.
    const bytes = [_]u8{ 0x83, 0x00, 0x01, 0x02 };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const decoded = try decode(arena.allocator(), &bytes);
    const arr = try asArray(decoded);
    try std.testing.expectEqual(@as(usize, 3), arr.len);
}

test "SEC: array nesting beyond max_decode_depth is rejected rather than exhausting the stack" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // A chain of single-element arrays (header 0x81 each), nested well past
    // max_decode_depth, terminated by one scalar (uint 0).
    const depth = max_decode_depth + 5;
    const bytes = try a.alloc(u8, depth + 1);
    for (0..depth) |i| bytes[i] = 0x81;
    bytes[depth] = 0x00;

    try std.testing.expectError(error.NestingTooDeep, decode(a, bytes));
}

test "SEC: array nesting within max_decode_depth still decodes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const depth = max_decode_depth - 1;
    const bytes = try a.alloc(u8, depth + 1);
    for (0..depth) |i| bytes[i] = 0x81;
    bytes[depth] = 0x00;

    const decoded = try decode(a, bytes);
    try std.testing.expect(decoded == .array);
}
