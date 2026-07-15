//! Crypto primitive mappings for the DNS-less local RP protocol, per
//! dns-less-local-rp-design.md's Language Crypto Matrix (Zig row): "Ed25519,
//! X25519, AES-256-GCM, HKDF, SHA-256 are all in the Zig stdlib." Exact
//! std.crypto API used (verified against Zig 0.14.1's stdlib source, since
//! these names move between Zig versions — see this SDK's README):
//!
//!   - Ed25519:            `std.crypto.sign.Ed25519` — `KeyPair.generateDeterministic(seed)`
//!                          takes the 32-byte seed directly (Ed25519's "private
//!                          key" IS its 32-byte seed, matching keys.json's
//!                          `seed_hex == private_key_hex` convention).
//!   - X25519:              `std.crypto.dh.X25519` — `scalarmult`/`recoverPublicKey`
//!                          return `error.IdentityElement` for an all-zero/
//!                          low-order result; mapped to `error.NonContributoryKey`
//!                          below (Wire Precision's "reject an all-zero shared
//!                          secret").
//!   - AES-256-GCM:         `std.crypto.aead.aes_gcm.Aes256Gcm` (IETF 12-byte
//!                          nonce, 16-byte tag).
//!   - ChaCha20-Poly1305:   `std.crypto.aead.chacha_poly.ChaCha20Poly1305`
//!                          (IETF 12-byte nonce, 16-byte tag — confirmed by
//!                          `nonce_length = 12` in stdlib source, the
//!                          non-extended variant, not XChaCha20's 24-byte one).
//!   - HKDF-SHA256:         `std.crypto.kdf.hkdf.HkdfSha256`.
//!   - SHA-256:             `std.crypto.hash.sha2.Sha256`.

const std = @import("std");
const crypto = std.crypto;

pub const Ed25519 = crypto.sign.Ed25519;
pub const X25519 = crypto.dh.X25519;
pub const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
pub const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
pub const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
pub const Sha256 = crypto.hash.sha2.Sha256;

pub fn randomBytes(buf: []u8) void {
    crypto.random.bytes(buf);
}

/// `sha256(public_key_bytes)`, lowercase hex — the canonical LinkKeys
/// fingerprint format used everywhere (DNS `fp=` records, TLS SPKI pinning,
/// local RP identity). Matches `liblinkkeys::crypto::fingerprint` exactly.
pub fn fingerprintHex(public_key_bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    Sha256.hash(public_key_bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn hexEncode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = alphabet[b >> 4];
        out[i * 2 + 1] = alphabet[b & 0x0f];
    }
    return out;
}

pub fn hexDecodeFixed(comptime n: usize, hex: []const u8) ![n]u8 {
    if (hex.len != n * 2) return error.InvalidKeyLength;
    var out: [n]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

pub fn hexDecodeAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

// ---------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------

pub const Ed25519KeyPair = struct {
    public_key: [32]u8,
    seed: [32]u8,
};

pub fn generateEd25519Keypair() Ed25519KeyPair {
    const kp = Ed25519.KeyPair.generate();
    return .{ .public_key = kp.public_key.toBytes(), .seed = kp.secret_key.seed() };
}

/// Signs `message` with the Ed25519 key derived from `seed`. Deterministic
/// (no extra noise), matching Go's `ed25519.Sign` / Rust's `ed25519-dalek`
/// default signing behavior.
pub fn signEd25519(seed: [32]u8, message: []const u8) ![64]u8 {
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const sig = try kp.sign(message, null);
    return sig.toBytes();
}

/// Verifies an Ed25519 signature. Returns `false` (never an error) for a
/// malformed public key or signature — callers get a plain boolean, matching
/// the Go SDK's `verifyEd25519`.
pub fn verifyEd25519(pub_key: []const u8, message: []const u8, sig: []const u8) bool {
    if (pub_key.len != 32 or sig.len != 64) return false;
    const pk = Ed25519.PublicKey.fromBytes(pub_key[0..32].*) catch return false;
    const signature = Ed25519.Signature.fromBytes(sig[0..64].*);
    signature.verify(message, pk) catch return false;
    return true;
}

/// Resolves a wire algorithm string and verifies a signature. Only
/// "ed25519" is supported today (mirrors `liblinkkeys::crypto::SigningAlgorithm`
/// having exactly one variant); a new signing algorithm would be a new
/// protocol mode with new context strings, never a version bump of this one.
pub fn resolveAndVerify(algorithm: []const u8, message: []const u8, sig: []const u8, pub_key: []const u8) !void {
    if (!std.mem.eql(u8, algorithm, "ed25519")) return error.UnsupportedAlgorithm;
    if (!verifyEd25519(pub_key, message, sig)) return error.SignatureInvalid;
}

// ---------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------

pub const X25519KeyPair = struct {
    private_key: [32]u8,
    public_key: [32]u8,
};

/// Generates a fresh X25519 encryption keypair — a *separate* key from any
/// signing key, never algebraically derived (design doc: "Encryption Key Is
/// Separate, Not Derived").
pub fn generateX25519Keypair() X25519KeyPair {
    const kp = X25519.KeyPair.generate();
    return .{ .private_key = kp.secret_key, .public_key = kp.public_key };
}

/// X25519 Diffie-Hellman. Rejects an all-zero/low-order (non-contributory)
/// result via `error.NonContributoryKey` (Wire Precision: "reject an
/// all-zero shared secret").
pub fn x25519Ecdh(priv: [32]u8, pub_key: [32]u8) ![32]u8 {
    return X25519.scalarmult(priv, pub_key) catch error.NonContributoryKey;
}

pub fn x25519PublicFromPrivate(priv: [32]u8) ![32]u8 {
    return X25519.recoverPublicKey(priv) catch error.NonContributoryKey;
}

// ---------------------------------------------------------------------
// AEAD suite registry (Wire Precision: "AEAD suite registry")
// ---------------------------------------------------------------------

/// Exact, case-sensitive strings from a closed registry — never "close
/// enough", never case-folded. Mirrors `liblinkkeys::crypto::AeadSuite`.
pub const AeadSuite = enum {
    aes_256_gcm,
    chacha20_poly1305,

    pub fn wireId(self: AeadSuite) []const u8 {
        return switch (self) {
            .aes_256_gcm => "aes-256-gcm",
            .chacha20_poly1305 => "chacha20-poly1305",
        };
    }
};

pub fn parseAeadSuite(s: []const u8) ?AeadSuite {
    if (std.mem.eql(u8, s, "aes-256-gcm")) return .aes_256_gcm;
    if (std.mem.eql(u8, s, "chacha20-poly1305")) return .chacha20_poly1305;
    return null;
}

/// Every registry suite id, in preference order (baseline first).
pub const all_supported_suites = [_]AeadSuite{ .aes_256_gcm, .chacha20_poly1305 };

/// Picks the first suite in `advertised` (preference order) that this
/// implementation supports. Never returns a suite outside `advertised`, even
/// if this implementation also supports it.
pub fn selectSupportedSuite(advertised: []const []const u8) ?AeadSuite {
    for (advertised) |s| {
        if (parseAeadSuite(s)) |suite| return suite;
    }
    return null;
}

pub fn containsSuite(suites: []const AeadSuite, target: AeadSuite) bool {
    for (suites) |s| {
        if (s == target) return true;
    }
    return false;
}

// ---------------------------------------------------------------------
// AEAD encrypt/decrypt dispatch
// ---------------------------------------------------------------------

pub const tag_length = 16;
pub const nonce_length = 12;

/// Encrypts under `suite`, returning `ciphertext || tag` (the combined form
/// every conformance vector's `ciphertext_hex` uses, matching Go's
/// `cipher.AEAD.Seal` / Rust's `aes-gcm`/`chacha20poly1305` crate output).
pub fn aeadEncrypt(allocator: std.mem.Allocator, suite: AeadSuite, key: [32]u8, nonce: [nonce_length]u8, aad: []const u8, plaintext: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, plaintext.len + tag_length);
    var tag: [tag_length]u8 = undefined;
    switch (suite) {
        .aes_256_gcm => Aes256Gcm.encrypt(out[0..plaintext.len], &tag, plaintext, aad, nonce, key),
        .chacha20_poly1305 => ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, aad, nonce, key),
    }
    @memcpy(out[plaintext.len..], &tag);
    return out;
}

/// Decrypts `ciphertext` (`ciphertext || tag` combined form) under `suite`.
pub fn aeadDecrypt(allocator: std.mem.Allocator, suite: AeadSuite, key: [32]u8, nonce: [nonce_length]u8, aad: []const u8, ciphertext: []const u8) ![]u8 {
    if (ciphertext.len < tag_length) return error.DecryptFailed;
    const body_len = ciphertext.len - tag_length;
    const tag: [tag_length]u8 = ciphertext[body_len..][0..tag_length].*;
    const out = try allocator.alloc(u8, body_len);
    errdefer allocator.free(out);
    switch (suite) {
        .aes_256_gcm => Aes256Gcm.decrypt(out, ciphertext[0..body_len], tag, aad, nonce, key) catch return error.DecryptFailed,
        .chacha20_poly1305 => ChaCha20Poly1305.decrypt(out, ciphertext[0..body_len], tag, aad, nonce, key) catch return error.DecryptFailed,
    }
    return out;
}

// ---------------------------------------------------------------------
// Local-RP callback sealed-box KDF (Wire Precision: "Callback sealed box")
// ---------------------------------------------------------------------

/// Domain-separation tag for the local-RP callback sealed box, distinct from
/// liblinkkeys' generic sealed-box tag: this construction additionally binds
/// the negotiated suite id into the KDF context.
pub const local_rp_callback_box_tag = "linkkeys-local-rp-callback-box";

/// Derives the AEAD key for the local-RP callback sealed box via
/// HKDF-SHA256, and returns the context bytes (owned by `allocator`) that
/// double as the AEAD associated-data prefix. Layout: `tag || suite_id_utf8
/// || ephemeral_public(32) || recipient_public(32)`.
pub fn localRpCallbackKdf(allocator: std.mem.Allocator, suite: AeadSuite, ephemeral_public: [32]u8, recipient_public: [32]u8, shared_secret: [32]u8) !struct { key: [32]u8, context: []u8 } {
    const suite_id = suite.wireId();
    var context = try std.ArrayList(u8).initCapacity(allocator, local_rp_callback_box_tag.len + suite_id.len + 64);
    try context.appendSlice(local_rp_callback_box_tag);
    try context.appendSlice(suite_id);
    try context.appendSlice(&ephemeral_public);
    try context.appendSlice(&recipient_public);
    const context_bytes = try context.toOwnedSlice();

    // HKDF-SHA256(salt=none, ikm=shared_secret).expand(info=context, 32
    // bytes). An empty salt slice and RFC 5869's "no salt" default (HashLen
    // zero bytes) produce an identical HMAC key after zero-padding to the
    // hash's block size, so passing `&.{}` here matches Go's
    // `hkdf.Key(..., nil, ...)` / Rust's `Hkdf::new(None, ...)` exactly.
    const prk = HkdfSha256.extract(&.{}, &shared_secret);
    var key: [32]u8 = undefined;
    HkdfSha256.expand(&key, context_bytes, prk);

    return .{ .key = key, .context = context_bytes };
}

test "fingerprint matches a known sha256 hex vector" {
    // local_rp.signing public key from conformance/keys.json.
    const pub_hex = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    const expected_fp = "34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e";
    const pub_key = try hexDecodeFixed(32, pub_hex[0..64]);
    const fp = fingerprintHex(&pub_key);
    try std.testing.expectEqualStrings(expected_fp, &fp);
}

test "ed25519 sign/verify round trip" {
    const seed = [_]u8{1} ** 32;
    const msg = "hello world";
    const sig = try signEd25519(seed, msg);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pub_bytes = kp.public_key.toBytes();
    try std.testing.expect(verifyEd25519(&pub_bytes, msg, &sig));
    try std.testing.expect(!verifyEd25519(&pub_bytes, "tampered", &sig));
}

test "x25519 all-zero ephemeral key is rejected as non-contributory" {
    const zero_pub = [_]u8{0} ** 32;
    const some_priv = [_]u8{2} ** 32;
    try std.testing.expectError(error.NonContributoryKey, x25519Ecdh(some_priv, zero_pub));
}

test "aead round trip both suites" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const key = [_]u8{9} ** 32;
    const nonce = [_]u8{3} ** 12;
    const aad = "associated-data";
    const plaintext = "the quick brown fox";

    inline for (.{ AeadSuite.aes_256_gcm, AeadSuite.chacha20_poly1305 }) |suite| {
        const ct = try aeadEncrypt(a, suite, key, nonce, aad, plaintext);
        const pt = try aeadDecrypt(a, suite, key, nonce, aad, ct);
        try std.testing.expectEqualStrings(plaintext, pt);

        // Tampered AAD must fail.
        try std.testing.expectError(error.DecryptFailed, aeadDecrypt(a, suite, key, nonce, "wrong-aad", ct));
    }
}
