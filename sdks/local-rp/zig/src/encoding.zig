//! URL parameter encoding helpers — mirrors `crates/liblinkkeys/src/encoding.rs`
//! / `sdks/local-rp/go/encoding.go`. All CBOR-in-URL values are
//! base64url-encoded, **unpadded** (RFC 4648 §5, "URL and Filename Safe
//! Alphabet", no `=` padding) — matching `base64ct::Base64UrlUnpadded`
//! exactly. A standard-alphabet or padded string must be rejected, not
//! silently accepted (see `url_params.json`'s negative cases).

const std = @import("std");
const types = @import("types.zig");

const codec = std.base64.url_safe_no_pad;

pub fn encodeUrlParam(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, codec.Encoder.calcSize(bytes.len));
    _ = codec.Encoder.encode(out, bytes);
    return out;
}

/// Decodes a base64url-unpadded string. Rejects standard-alphabet input and
/// padded input by construction: `std.base64.url_safe_no_pad`'s decoder
/// only accepts `-`/`_` (not `+`/`/`) and treats a trailing `=` as an
/// invalid character rather than padding.
pub fn decodeUrlParam(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const size = codec.Decoder.calcSizeForSlice(s) catch return error.Base64DecodeFailed;
    const out = try allocator.alloc(u8, size);
    codec.Decoder.decode(out, s) catch return error.Base64DecodeFailed;
    return out;
}

/// Encodes a `SignedLocalRpLoginRequest` for the begin route's
/// `?signed_request=<...>` query parameter (Wire Precision: "URL and
/// parameter conventions").
pub fn signedLocalRpLoginRequestToUrlParam(allocator: std.mem.Allocator, signed: types.SignedLocalRpLoginRequest) ![]u8 {
    const cbor_bytes = try types.encodeSignedLocalRpLoginRequest(allocator, signed);
    return encodeUrlParam(allocator, cbor_bytes);
}

pub fn signedLocalRpLoginRequestFromUrlParam(allocator: std.mem.Allocator, param: []const u8) !types.SignedLocalRpLoginRequest {
    const cbor_bytes = try decodeUrlParam(allocator, param);
    return types.decodeSignedLocalRpLoginRequest(allocator, cbor_bytes);
}

/// Encodes a `LocalRpEncryptedCallback` for the callback redirect's
/// `&encrypted_token=<...>` query parameter (same name/mechanics as the
/// existing DNS-pinned flow's `encrypted_token` parameter).
pub fn localRpEncryptedCallbackToUrlParam(allocator: std.mem.Allocator, cb: types.LocalRpEncryptedCallback) ![]u8 {
    const cbor_bytes = try types.encodeLocalRpEncryptedCallback(allocator, cb);
    return encodeUrlParam(allocator, cbor_bytes);
}

/// Bounds the `encrypted_token` callback query parameter's encoded size.
/// SEC note: this is the SDK's only pre-authentication network-adjacent
/// input — `completeLocalLogin` decodes it before any DNS/RPC trust has been
/// established (see `complete.zig`'s module docs, step 1-2) — so it gets an
/// explicit cap here on top of `cbor.zig`'s own declared-count/nesting-depth
/// bounds, rather than relying solely on whatever limit the app's own HTTP
/// layer happens to impose on query-string length. A real encrypted callback
/// (signed payload + AEAD ciphertext + header) is on the order of a few
/// hundred bytes; this is generous headroom, well under
/// `rpc.max_frame_size`.
pub const max_encrypted_callback_param_bytes: usize = 64 * 1024;

pub fn localRpEncryptedCallbackFromUrlParam(allocator: std.mem.Allocator, param: []const u8) !types.LocalRpEncryptedCallback {
    if (param.len > max_encrypted_callback_param_bytes) return error.EncryptedCallbackTooLarge;
    const cbor_bytes = try decodeUrlParam(allocator, param);
    return types.decodeLocalRpEncryptedCallback(allocator, cbor_bytes);
}

test "base64url unpadded round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const original = "hello, local RP world!";
    const encoded = try encodeUrlParam(a, original);
    try std.testing.expect(std.mem.indexOfScalar(u8, encoded, '=') == null);
    const decoded = try decodeUrlParam(a, encoded);
    try std.testing.expectEqualStrings(original, decoded);
}

test "padded base64 is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const encoded = try encodeUrlParam(a, "some bytes");
    const padded = try std.fmt.allocPrint(a, "{s}=", .{encoded});
    try std.testing.expectError(error.Base64DecodeFailed, decodeUrlParam(a, padded));
}

test "SEC: oversized encrypted_token callback parameter is rejected before decoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const oversized = try a.alloc(u8, max_encrypted_callback_param_bytes + 1);
    @memset(oversized, 'A');
    try std.testing.expectError(error.EncryptedCallbackTooLarge, localRpEncryptedCallbackFromUrlParam(a, oversized));
}

test "standard alphabet is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Bytes chosen so the standard encoder emits a '+' or '/'.
    const bytes = [_]u8{ 0xff, 0xff, 0xfe };
    var std_buf: [8]u8 = undefined;
    const std_encoded = std.base64.standard_no_pad.Encoder.encode(&std_buf, &bytes);
    if (std.mem.indexOfAny(u8, std_encoded, "+/")) |_| {
        try std.testing.expectError(error.Base64DecodeFailed, decodeUrlParam(a, std_encoded));
    }
}
