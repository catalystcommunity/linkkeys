//! Sibling-signed key revocation certificate verification — mirrors
//! `crates/liblinkkeys/src/revocation.rs` / `sdks/local-rp/go/revocation.go`.
//! Only verification is ported here (building/signing a revocation
//! certificate is a domain-admin/server-side operation, out of scope for a
//! local-RP SDK); this SDK verifies revocation certificates fetched
//! alongside domain keys (`rpc.fetchDomainKeys`) so it can drop a key a
//! quorum-verified sibling revocation targets.

const std = @import("std");
const cbor = @import("cbor.zig");
const types = @import("types.zig");
const xcrypto = @import("crypto.zig");
const local_rp = @import("local_rp.zig");

/// Minimum number of distinct sibling signatures required to revoke a key.
pub const revocation_quorum: usize = 2;

/// Domain-separation tag / version for the signed revocation payload.
pub const revocation_tag = "linkkeys-key-revocation-v1alpha";

/// Builds the canonical signed bytes: the tag, the target key id +
/// fingerprint, the revocation instant, and the signing sibling's domain
/// (bound per-signature to stop cross-domain reuse of a signature).
pub fn revocationPayload(allocator: std.mem.Allocator, target_key_id: []const u8, target_fingerprint: []const u8, revoked_at: []const u8, signing_domain: []const u8) ![]u8 {
    const items = [_]cbor.Value{
        cbor.text(revocation_tag),
        cbor.text(target_key_id),
        cbor.text(target_fingerprint),
        cbor.text(revoked_at),
        cbor.text(signing_domain),
    };
    return cbor.encodeTuple(allocator, &items);
}

/// Walks a revocation certificate's signatures against a domain's public key
/// set and returns how many DISTINCT signer key ids survive the full
/// filtering rules (conformance README, "Verification rules"):
///
///  1. Skip any signature whose `signed_by_key_id` equals the certificate's
///     `target_key_id` (a key never authorizes its own revocation), any
///     whose `domain` field differs from the domain being verified (the
///     `domain` parameter only FILTERS — see rule 2), and any whose signer
///     key is absent from `domain_keys` or is not a currently-valid signing
///     key (wrong key_usage, expired, or itself revoked — wall-clock
///     validity, like `checkSigningKeyValid` everywhere else).
///  2. For the rest, recompute the payload from the signature's WIRE
///     `domain` field (never from the `domain` parameter — this is what
///     makes a signature computed over another domain's payload fail even
///     when its wire domain claims this one) and Ed25519-verify.
///  3. Count distinct `signed_by_key_id` values that verified.
pub fn countRevocationSigners(allocator: std.mem.Allocator, cert: types.RevocationCertificate, domain_keys: []const types.DomainPublicKey, domain: []const u8) usize {
    var valid_signers = std.StringHashMap(void).init(allocator);
    defer valid_signers.deinit();

    for (cert.signatures) |sig| {
        if (std.mem.eql(u8, sig.signed_by_key_id, cert.target_key_id)) continue;
        if (!std.mem.eql(u8, sig.domain, domain)) continue;

        var key: ?types.DomainPublicKey = null;
        for (domain_keys) |k| {
            if (std.mem.eql(u8, k.key_id, sig.signed_by_key_id)) {
                key = k;
                break;
            }
        }
        const resolved = key orelse continue;
        local_rp.checkSigningKeyValid(resolved) catch continue;

        const payload = revocationPayload(allocator, cert.target_key_id, cert.target_fingerprint, cert.revoked_at, sig.domain) catch continue;
        if (std.mem.eql(u8, resolved.algorithm, "ed25519") and xcrypto.verifyEd25519(resolved.public_key, payload, sig.signature)) {
            valid_signers.put(sig.signed_by_key_id, {}) catch continue;
        }
    }
    return valid_signers.count();
}

/// Verifies a revocation certificate against a domain's public key set.
/// Requires at least `revocation_quorum` DISTINCT signing keys of `domain`,
/// each currently valid and NOT the target key, to have signed the
/// canonical payload (see `countRevocationSigners` for the exact
/// per-signature filtering rules).
pub fn verifyRevocationCertificate(allocator: std.mem.Allocator, cert: types.RevocationCertificate, domain_keys: []const types.DomainPublicKey, domain: []const u8) !void {
    const got = countRevocationSigners(allocator, cert, domain_keys, domain);
    if (got >= revocation_quorum) return;
    return error.InsufficientRevocationSigners;
}

test "revocation quorum: two valid siblings pass, one is insufficient" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed1 = [_]u8{10} ** 32;
    const seed2 = [_]u8{11} ** 32;
    const kp1 = try xcrypto.Ed25519.KeyPair.generateDeterministic(seed1);
    const kp2 = try xcrypto.Ed25519.KeyPair.generateDeterministic(seed2);
    const pub1 = kp1.public_key.toBytes();
    const pub2 = kp2.public_key.toBytes();

    const domain = "example.test";
    const target_key_id = "target-key";
    const target_fp = "deadbeef";
    const revoked_at = "2026-01-01T00:00:00Z";

    const payload = try revocationPayload(a, target_key_id, target_fp, revoked_at, domain);
    const sig1 = try xcrypto.signEd25519(seed1, payload);
    const sig2 = try xcrypto.signEd25519(seed2, payload);

    const domain_keys = [_]types.DomainPublicKey{
        .{ .key_id = "sibling-1", .public_key = &pub1, .fingerprint = "x1", .algorithm = "ed25519", .key_usage = "sign", .created_at = "2020-01-01T00:00:00Z", .expires_at = "2099-01-01T00:00:00Z" },
        .{ .key_id = "sibling-2", .public_key = &pub2, .fingerprint = "x2", .algorithm = "ed25519", .key_usage = "sign", .created_at = "2020-01-01T00:00:00Z", .expires_at = "2099-01-01T00:00:00Z" },
    };

    const cert_both = types.RevocationCertificate{
        .target_key_id = target_key_id,
        .target_fingerprint = target_fp,
        .revoked_at = revoked_at,
        .signatures = &[_]types.ClaimSignature{
            .{ .domain = domain, .signed_by_key_id = "sibling-1", .signature = &sig1 },
            .{ .domain = domain, .signed_by_key_id = "sibling-2", .signature = &sig2 },
        },
    };
    try std.testing.expectEqual(@as(usize, 2), countRevocationSigners(a, cert_both, &domain_keys, domain));
    try verifyRevocationCertificate(a, cert_both, &domain_keys, domain);

    const cert_one = types.RevocationCertificate{
        .target_key_id = target_key_id,
        .target_fingerprint = target_fp,
        .revoked_at = revoked_at,
        .signatures = &[_]types.ClaimSignature{
            .{ .domain = domain, .signed_by_key_id = "sibling-1", .signature = &sig1 },
        },
    };
    try std.testing.expectEqual(@as(usize, 1), countRevocationSigners(a, cert_one, &domain_keys, domain));
    try std.testing.expectError(error.InsufficientRevocationSigners, verifyRevocationCertificate(a, cert_one, &domain_keys, domain));
}

test "cross-domain signature reuse fails: wire domain lies but payload recompute catches it" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed1 = [_]u8{10} ** 32;
    const kp1 = try xcrypto.Ed25519.KeyPair.generateDeterministic(seed1);
    const pub1 = kp1.public_key.toBytes();

    const domain_keys = [_]types.DomainPublicKey{
        .{ .key_id = "sibling-1", .public_key = &pub1, .fingerprint = "x1", .algorithm = "ed25519", .key_usage = "sign", .created_at = "2020-01-01T00:00:00Z", .expires_at = "2099-01-01T00:00:00Z" },
    };

    // Signature computed over evil.example's payload, but wire `domain`
    // field claims the real domain.
    const evil_payload = try revocationPayload(a, "target-key", "fp", "2026-01-01T00:00:00Z", "evil.example");
    const sig = try xcrypto.signEd25519(seed1, evil_payload);

    const cert = types.RevocationCertificate{
        .target_key_id = "target-key",
        .target_fingerprint = "fp",
        .revoked_at = "2026-01-01T00:00:00Z",
        .signatures = &[_]types.ClaimSignature{
            .{ .domain = "example.test", .signed_by_key_id = "sibling-1", .signature = &sig },
        },
    };
    try std.testing.expectEqual(@as(usize, 0), countRevocationSigners(a, cert, &domain_keys, "example.test"));
}
