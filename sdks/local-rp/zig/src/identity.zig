//! `generate_local_rp_identity` and the raw-byte storage helpers (design
//! doc: "SDK API Shape", "Byte Storage Helpers"). Mirrors
//! `sdks/local-rp/rust/src/identity.rs` / `sdks/local-rp/go/identity.go`.
//!
//! A local RP identity is exactly one Ed25519 signing keypair, one X25519
//! encryption keypair, and a self-signed `SignedLocalRpDescriptor` binding
//! them together. There is no continuity story across rotation — generating
//! a new identity means a new fingerprint, full stop.
//!
//! Security note (design doc, "Byte Storage Helpers"): the private key
//! fields in `LocalRpKeyMaterial` do not directly identify a user, but they
//! control this app's entire local RP identity — anyone holding them can
//! sign login requests and redeem claim tickets as this app. Store them with
//! ordinary application-secret care (the same care as a database credential
//! or API key), not merely as configuration.

const std = @import("std");
const types = @import("types.zig");
const xcrypto = @import("crypto.zig");
const local_rp = @import("local_rp.zig");

/// Default local RP key lifetime: 10 years (design doc, "One Signing Key
/// and One Encryption Key" — "Default lifetime: 10 years. Rotation is a
/// deliberate operator event.").
pub const default_lifetime_seconds: i64 = 3650 * 24 * 60 * 60;

pub const GenerateLocalRpIdentityConfig = struct {
    /// Display name shown on the IDP's consent screen. NOT identity — the
    /// design doc is explicit that approval keys on the fingerprint alone;
    /// this is audit/display metadata only.
    app_name: []const u8,
    /// Optional local domain/origin hint (e.g. "jukebox.lan"), also
    /// display/audit metadata, never an identity input.
    local_domain_hint: ?[]const u8 = null,
    /// AEAD suites this app can decrypt callbacks with, in preference
    /// order. Defaults to both registry suites (aes-256-gcm first,
    /// mandatory baseline; chacha20-poly1305 second, optional) when null.
    supported_suites: ?[]const []const u8 = null,
    /// Key/descriptor lifetime from `now`. Defaults to
    /// `default_lifetime_seconds` (10 years) when zero.
    lifetime_seconds: i64 = 0,
    /// Current time (Unix seconds) — never read from the system clock
    /// inside this package's pure logic, so callers control determinism.
    now: i64,
};

/// A local RP's full key material: signing keypair, encryption keypair, the
/// self-signed descriptor binding them (which also carries app_name,
/// local_domain_hint, supported_suites, and the created/expires
/// timestamps), and the identity fingerprint.
pub const LocalRpKeyMaterial = struct {
    signing_private_key: [32]u8, // Ed25519 seed
    signing_public_key: [32]u8,
    encryption_private_key: [32]u8,
    encryption_public_key: [32]u8,
    /// The self-signed envelope, reused as-is in every `beginLocalLogin`
    /// call rather than re-signed per login, so the identity's descriptor
    /// stays a single stable object for the key's whole lifetime.
    descriptor: types.SignedLocalRpDescriptor,
    /// `sha256(signing_public_key)` hex — the canonical identity anchor.
    fingerprint: []const u8,
};

const default_suite_ids = [_][]const u8{ "aes-256-gcm", "chacha20-poly1305" };

/// Implements `generate_local_rp_identity(config) -> LocalRpKeyMaterial`
/// (design doc, "SDK API Shape"). Generates a fresh Ed25519 signing keypair
/// and a *separate* X25519 encryption keypair (never algebraically
/// derived), builds and self-signs the `SignedLocalRpDescriptor` binding
/// them, and returns everything the app needs to persist.
pub fn generateLocalRpIdentity(allocator: std.mem.Allocator, config: GenerateLocalRpIdentityConfig) !LocalRpKeyMaterial {
    if (std.mem.trim(u8, config.app_name, " \t\r\n").len == 0) return error.InvalidInput;

    const signing = xcrypto.generateEd25519Keypair();
    const encryption = xcrypto.generateX25519Keypair();

    const suites = config.supported_suites orelse &default_suite_ids;
    if (suites.len == 0) return error.InvalidInput;

    const lifetime = if (config.lifetime_seconds == 0) default_lifetime_seconds else config.lifetime_seconds;

    var created_buf: [32]u8 = undefined;
    var expires_buf: [32]u8 = undefined;
    const created_at = try allocator.dupe(u8, try local_rp.formatTimestamp(&created_buf, config.now));
    const expires_at = try allocator.dupe(u8, try local_rp.formatTimestamp(&expires_buf, config.now + lifetime));

    const descriptor = try local_rp.buildLocalRpDescriptor(
        allocator,
        config.app_name,
        config.local_domain_hint,
        signing.public_key,
        encryption.public_key,
        suites,
        created_at,
        expires_at,
    );
    const fingerprint = try allocator.dupe(u8, descriptor.fingerprint);
    const signed_descriptor = try local_rp.signLocalRpDescriptor(allocator, descriptor, signing.seed);

    return .{
        .signing_private_key = signing.seed,
        .signing_public_key = signing.public_key,
        .encryption_private_key = encryption.private_key,
        .encryption_public_key = encryption.public_key,
        .descriptor = signed_descriptor,
        .fingerprint = fingerprint,
    };
}

// ---------------------------------------------------------------------
// Byte storage helpers (design doc: "Byte Storage Helpers")
// ---------------------------------------------------------------------

pub fn signingKeyToBytes(key: [32]u8) [32]u8 {
    return key;
}
pub fn signingKeyFromBytes(b: []const u8) ![32]u8 {
    if (b.len != 32) return error.InvalidKeyLength;
    return b[0..32].*;
}
pub fn encryptionKeyToBytes(key: [32]u8) [32]u8 {
    return key;
}
pub fn encryptionKeyFromBytes(b: []const u8) ![32]u8 {
    if (b.len != 32) return error.InvalidKeyLength;
    return b[0..32].*;
}

/// The canonical fingerprint string form — a pass-through, since in this
/// SDK the fingerprint IS a hex string (design doc: "fingerprint: hex
/// string ... the existing LinkKeys fingerprint format, everywhere, with no
/// bytes variant").
pub fn fingerprintToString(fingerprint: []const u8) []const u8 {
    return fingerprint;
}

/// Parses/validates a fingerprint string: exactly 64 lowercase-normalized
/// hex characters (a SHA-256 digest). Rejects anything else so a malformed
/// value can never silently pass as a pin or an identity.
pub fn fingerprintFromString(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const dns = @import("dns.zig");
    if (!dns.isValidFingerprint(s)) return error.InvalidInput;
    return std.ascii.allocLowerString(allocator, s);
}

/// Magic prefix for the identity-bundle byte format below. This is an
/// SDK-local storage convenience, NOT a protocol wire format — nothing in
/// dns-less-local-rp-design.md's Wire Precision governs it, and no
/// conformance vector covers it. Versioned so a future incompatible layout
/// change fails loudly instead of silently misparsing.
const identity_bundle_magic = "LKI1";

/// Implements `local_rp_identity_to_bytes(identity) -> bytes` (design doc,
/// "SDK API Shape" + "Byte Storage Helpers": "identity bundle"). Packs both
/// private keys and the signed descriptor (which already carries both
/// public keys, app_name, local_domain_hint, supported_suites, and the
/// created/expires timestamps) into one opaque blob an app can store as a
/// single secret/config value. Layout: `MAGIC(4) ||
/// signing_private_key(32) || encryption_private_key(32) ||
/// descriptor_len(4, BE) || descriptor_cbor`.
pub fn localRpIdentityToBytes(allocator: std.mem.Allocator, identity: LocalRpKeyMaterial) ![]u8 {
    const descriptor_bytes = try types.encodeSignedLocalRpDescriptor(allocator, identity.descriptor);
    var out = try std.ArrayList(u8).initCapacity(allocator, 4 + 32 + 32 + 4 + descriptor_bytes.len);
    try out.appendSlice(identity_bundle_magic);
    try out.appendSlice(&identity.signing_private_key);
    try out.appendSlice(&identity.encryption_private_key);
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(descriptor_bytes.len), .big);
    try out.appendSlice(&len_buf);
    try out.appendSlice(descriptor_bytes);
    return out.toOwnedSlice();
}

/// Inverse of `localRpIdentityToBytes`. Public keys and the fingerprint are
/// read back out of the embedded descriptor rather than re-derived from the
/// private keys, exactly mirroring what was stored; this function does no
/// signature/expiry verification (that is `checkExpirations`'s and the
/// protocol verification chain's job).
pub fn localRpIdentityFromBytes(allocator: std.mem.Allocator, b: []const u8) !LocalRpKeyMaterial {
    const header_len = 4 + 32 + 32 + 4;
    if (b.len < header_len) return error.InvalidInput;
    if (!std.mem.eql(u8, b[0..4], identity_bundle_magic)) return error.InvalidInput;

    const signing_priv: [32]u8 = b[4..36].*;
    const enc_priv: [32]u8 = b[36..68].*;
    const desc_len = std.mem.readInt(u32, b[68..72], .big);

    if (@as(u64, header_len) + @as(u64, desc_len) > b.len) return error.InvalidInput;
    const descriptor_bytes = b[header_len .. header_len + desc_len];

    const signed_descriptor = try types.decodeSignedLocalRpDescriptor(allocator, descriptor_bytes);
    const descriptor = try types.decodeLocalRpDescriptor(allocator, signed_descriptor.descriptor);

    if (descriptor.signing_public_key.len != 32) return error.InvalidInput;
    if (descriptor.encryption_public_key.len != 32) return error.InvalidInput;

    return .{
        .signing_private_key = signing_priv,
        .signing_public_key = descriptor.signing_public_key[0..32].*,
        .encryption_private_key = enc_priv,
        .encryption_public_key = descriptor.encryption_public_key[0..32].*,
        .descriptor = signed_descriptor,
        .fingerprint = descriptor.fingerprint,
    };
}

/// Implements `check_expirations(identity, now) -> ExpirationStatus`
/// (design doc, "SDK API Shape" / "Expiration Helper"). Thin wrapper over
/// `local_rp.checkExpirationsAt`, taking the identity's descriptor
/// `expires_at` directly. The SDK reports facts; the app decides whether to
/// warn admins, warn users, block login, renew, or ignore.
pub fn checkExpirations(allocator: std.mem.Allocator, identity: LocalRpKeyMaterial, now: i64) !local_rp.ExpirationStatus {
    const descriptor = try types.decodeLocalRpDescriptor(allocator, identity.descriptor.descriptor);
    return local_rp.checkExpirationsAt(descriptor.expires_at, now);
}

test "generateLocalRpIdentity then identity bundle round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const now: i64 = try local_rp.parseTimestamp("2026-01-01T00:00:00Z");
    const identity = try generateLocalRpIdentity(a, .{ .app_name = "Round Trip App", .now = now });

    const bundle = try localRpIdentityToBytes(a, identity);
    const restored = try localRpIdentityFromBytes(a, bundle);

    try std.testing.expectEqualSlices(u8, &identity.signing_private_key, &restored.signing_private_key);
    try std.testing.expectEqualSlices(u8, &identity.encryption_private_key, &restored.encryption_private_key);
    try std.testing.expectEqualSlices(u8, &identity.signing_public_key, &restored.signing_public_key);
    try std.testing.expectEqualStrings(identity.fingerprint, restored.fingerprint);

    const status = try checkExpirations(a, restored, now);
    try std.testing.expectEqual(local_rp.ExpirationLevel.ok, status.level);
}

test "generateLocalRpIdentity rejects empty app_name" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidInput, generateLocalRpIdentity(arena.allocator(), .{ .app_name = "   ", .now = 0 }));
}

test "fingerprintFromString rejects non-fingerprint strings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidInput, fingerprintFromString(arena.allocator(), "deadbeef"));
}
