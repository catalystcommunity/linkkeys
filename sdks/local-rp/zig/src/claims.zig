//! Claim signature verification — mirrors `crates/liblinkkeys/src/claims.rs`
//! / `sdks/local-rp/go/claims.go`. Only the verification half matters in
//! production (claims are always signed by an IDP server-side); `signClaim`
//! is reproduced exactly (same tag, same tuple field order/CBOR shape) only
//! so this SDK's own test fixtures (fake IDPs) can build realistic claims —
//! this SDK itself only ever verifies claims returned from a ticket
//! redemption.

const std = @import("std");
const cbor = @import("cbor.zig");
const types = @import("types.zig");
const xcrypto = @import("crypto.zig");
const local_rp = @import("local_rp.zig");

/// Domain-separation tag + version for the claim signature payload.
pub const claim_payload_tag = "linkkeys-claim-v1alpha";

/// Builds the canonical bytes a single signature covers for a claim. The
/// subject is the single full identity `user_id@subject_domain` (not the
/// bare user_id), so a claim about a user_id at one domain can't be replayed
/// as the same user_id at another. `signing_domain` is bound per-signature so
/// a signature from domain A cannot satisfy a claim presented as signed by
/// B.
pub fn claimSignPayload(allocator: std.mem.Allocator, claim_id: []const u8, claim_type: []const u8, claim_value: []const u8, user_id: []const u8, subject_domain: []const u8, signing_domain: []const u8, expires_at: ?[]const u8, attested_at: []const u8) ![]u8 {
    const subject = try std.fmt.allocPrint(allocator, "{s}@{s}", .{ user_id, subject_domain });
    const items = [_]cbor.Value{
        cbor.text(claim_payload_tag),
        cbor.text(claim_id),
        cbor.text(claim_type),
        cbor.bytesVal(claim_value),
        cbor.text(subject),
        cbor.text(signing_domain),
        cbor.optText(expires_at),
        cbor.text(attested_at),
    };
    return cbor.encodeTuple(allocator, &items);
}

pub const ClaimSpec = struct {
    claim_id: []const u8,
    claim_type: []const u8,
    claim_value: []const u8,
    user_id: []const u8,
    subject_domain: []const u8,
    expires_at: ?[]const u8 = null,
    attested_at: []const u8,
};

pub const ClaimSigner = struct {
    domain: []const u8,
    key_id: []const u8,
    private_key_seed: [32]u8,
};

/// Signs a claim with one or more keys, producing a `Claim` carrying one
/// `ClaimSignature` per signer. Server-side (IDP) operation exposed here as
/// a pure protocol helper so test fixtures (fake IDPs) reproduce the exact
/// wire bytes a real IDP would.
pub fn signClaim(allocator: std.mem.Allocator, spec: ClaimSpec, signers: []const ClaimSigner, created_at: []const u8) !types.Claim {
    const signatures = try allocator.alloc(types.ClaimSignature, signers.len);
    for (signers, 0..) |signer, i| {
        const payload = try claimSignPayload(allocator, spec.claim_id, spec.claim_type, spec.claim_value, spec.user_id, spec.subject_domain, signer.domain, spec.expires_at, spec.attested_at);
        const sig = try xcrypto.signEd25519(signer.private_key_seed, payload);
        signatures[i] = .{ .domain = signer.domain, .signed_by_key_id = signer.key_id, .signature = try allocator.dupe(u8, &sig) };
    }
    return .{
        .claim_id = spec.claim_id,
        .user_id = spec.user_id,
        .claim_type = spec.claim_type,
        .claim_value = spec.claim_value,
        .signatures = signatures,
        .attested_at = spec.attested_at,
        .created_at = created_at,
        .expires_at = spec.expires_at,
        .revoked_at = null,
    };
}

/// A domain and the set of its currently-known public keys, as supplied to
/// `verifyClaim`. The caller resolves these before verifying (via
/// `rpc.fetchDomainKeys`) so verification stays pure and performs no I/O.
pub const DomainKeySet = struct {
    domain: []const u8,
    keys: []const types.DomainPublicKey,
};

fn verifyOneClaimSignature(sig: types.ClaimSignature, payload: []const u8, keys: []const types.DomainPublicKey) !void {
    var key: ?types.DomainPublicKey = null;
    for (keys) |k| {
        if (std.mem.eql(u8, k.key_id, sig.signed_by_key_id)) {
            key = k;
            break;
        }
    }
    const resolved = key orelse return error.ClaimKeyNotFound;

    // A claim signature must come from a signing key, never an encryption
    // key sharing the same id.
    if (!std.mem.eql(u8, resolved.key_usage, "sign")) return error.ClaimSignatureInvalid;

    try local_rp.checkSigningKeyValid(resolved);

    if (!std.mem.eql(u8, resolved.algorithm, "ed25519")) return error.ClaimUnsupportedAlgorithm;
    if (!xcrypto.verifyEd25519(resolved.public_key, payload, sig.signature)) return error.ClaimSignatureInvalid;
}

/// Verifies only the cryptographic per-domain quorum for `claim`;
/// `subject_domain` is the subject's home domain, supplied from
/// authoritative context (never attacker-controlled input), binding a claim
/// about user@A from being replayed as one about user@B. Every domain that
/// signed must contribute at least one signature from a currently-valid key
/// of that domain. Does NOT check the claim's own revocation/expiry (see
/// `verifyClaim`).
pub fn verifyClaimSignatures(allocator: std.mem.Allocator, claim: types.Claim, subject_domain: []const u8, domain_keys: []const DomainKeySet) !void {
    const signatures = claim.signatures;
    if (signatures.len == 0) return error.ClaimUnsigned;

    var domains = std.ArrayList([]const u8).init(allocator);
    for (signatures) |s| {
        var seen = false;
        for (domains.items) |d| {
            if (std.mem.eql(u8, d, s.domain)) {
                seen = true;
                break;
            }
        }
        if (!seen) try domains.append(s.domain);
    }
    std.mem.sort([]const u8, domains.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    for (domains.items) |signing_domain| {
        var set: ?DomainKeySet = null;
        for (domain_keys) |dk| {
            if (std.mem.eql(u8, dk.domain, signing_domain)) {
                set = dk;
                break;
            }
        }
        const resolved_set = set orelse return error.ClaimDomainKeysUnavailable;

        const payload = try claimSignPayload(allocator, claim.claim_id, claim.claim_type, claim.claim_value, claim.user_id, subject_domain, signing_domain, claim.expires_at, claim.attested_at);

        var satisfied = false;
        var last_err: anyerror = error.ClaimDomainUnverified;
        for (signatures) |sig| {
            if (!std.mem.eql(u8, sig.domain, signing_domain)) continue;
            verifyOneClaimSignature(sig, payload, resolved_set.keys) catch |err| {
                last_err = err;
                continue;
            };
            satisfied = true;
            break;
        }
        if (!satisfied) return last_err;
    }
}

/// Full claim verification: the cryptographic per-domain quorum plus the
/// claim's own revocation and expiry (both tamper-evident, being bound into
/// each signed payload).
pub fn verifyClaim(allocator: std.mem.Allocator, claim: types.Claim, subject_domain: []const u8, domain_keys: []const DomainKeySet) !void {
    try verifyClaimSignatures(allocator, claim, subject_domain, domain_keys);

    if (claim.revoked_at != null) return error.ClaimRevoked;
    if (claim.expires_at) |expires_at_str| {
        const expires = local_rp.parseTimestamp(expires_at_str) catch return error.ClaimBadExpiry;
        if (std.time.timestamp() > expires) return error.ClaimExpired;
    }
}

test "claim sign/verify round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const domain_seed = [_]u8{3} ** 32;
    const kp = try xcrypto.Ed25519.KeyPair.generateDeterministic(domain_seed);
    const domain_pub = kp.public_key.toBytes();

    const claim = try signClaim(a, .{
        .claim_id = "claim-1",
        .claim_type = "handle",
        .claim_value = "flowtestuser",
        .user_id = "user-1",
        .subject_domain = "example.test",
        .attested_at = "2026-01-01T00:00:00Z",
    }, &[_]ClaimSigner{.{ .domain = "example.test", .key_id = "key-1", .private_key_seed = domain_seed }}, "2026-01-01T00:00:00Z");

    const domain_key = types.DomainPublicKey{
        .key_id = "key-1",
        .public_key = &domain_pub,
        .fingerprint = "unused",
        .algorithm = "ed25519",
        .key_usage = "sign",
        .created_at = "2020-01-01T00:00:00Z",
        .expires_at = "2099-01-01T00:00:00Z",
    };
    const key_sets = [_]DomainKeySet{.{ .domain = "example.test", .keys = &[_]types.DomainPublicKey{domain_key} }};

    try verifyClaim(a, claim, "example.test", &key_sets);

    // Tampered signature must fail.
    var tampered = claim;
    var sigs = try a.dupe(types.ClaimSignature, claim.signatures);
    var sig_bytes = try a.dupe(u8, sigs[0].signature);
    sig_bytes[0] ^= 0xff;
    sigs[0].signature = sig_bytes;
    tampered.signatures = sigs;
    try std.testing.expectError(error.ClaimSignatureInvalid, verifyClaim(a, tampered, "example.test", &key_sets));
}
