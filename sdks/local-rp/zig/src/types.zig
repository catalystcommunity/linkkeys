//! CSIL wire types for the local-RP protocol (design doc "CSIL Work") plus
//! the handful of existing CSIL types this SDK consumes over CSIL-RPC
//! (`DomainPublicKey`, `Claim`, `ClaimSignature`, `RevocationCertificate`,
//! and their request/response wrappers). No csilgen Zig target exists (see
//! this SDK's filed csilgen request), so these are hand-written struct +
//! encode/decode pairs over `cbor.zig`'s value tree, mirroring the shape of
//! `sdks/local-rp/go/generated/{types,codec}.gen.go` field-for-field.
//!
//! All owned slices returned by `decode*` are allocated from the
//! `allocator` passed in — callers typically use an arena scoped to one
//! verify/build operation (see `root.zig`'s `Owned(T)`).

const std = @import("std");
const cbor = @import("cbor.zig");

fn textVal(v: cbor.Value, key: []const u8) !?[]const u8 {
    return if (cbor.mapGet(v, key)) |x| try cbor.asText(x) else null;
}
fn bytesValOpt(v: cbor.Value, key: []const u8) !?[]const u8 {
    return if (cbor.mapGet(v, key)) |x| try cbor.asBytes(x) else null;
}

fn encodeArena(allocator: std.mem.Allocator, v: cbor.Value) ![]u8 {
    return cbor.encodeAlloc(allocator, v);
}

fn textArrayToValue(allocator: std.mem.Allocator, items: []const []const u8) !cbor.Value {
    const vals = try allocator.alloc(cbor.Value, items.len);
    for (items, 0..) |it, i| vals[i] = cbor.text(it);
    return cbor.arrayVal(vals);
}

fn textArrayFromValue(allocator: std.mem.Allocator, v: cbor.Value) ![][]const u8 {
    const arr = try cbor.asArray(v);
    const out = try allocator.alloc([]const u8, arr.len);
    for (arr, 0..) |it, i| out[i] = try cbor.asText(it);
    return out;
}

// ---------------------------------------------------------------------
// ClaimSignature
// ---------------------------------------------------------------------

pub const ClaimSignature = struct {
    domain: []const u8,
    signed_by_key_id: []const u8,
    signature: []const u8,
};

pub fn claimSignatureToValue(allocator: std.mem.Allocator, v: ClaimSignature) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 3);
    entries[0] = .{ .key = cbor.text("domain"), .value = cbor.text(v.domain) };
    entries[1] = .{ .key = cbor.text("signed_by_key_id"), .value = cbor.text(v.signed_by_key_id) };
    entries[2] = .{ .key = cbor.text("signature"), .value = cbor.bytesVal(v.signature) };
    return cbor.mapVal(entries);
}

pub fn claimSignatureFromValue(v: cbor.Value) !ClaimSignature {
    return .{
        .domain = try cbor.asText(try cbor.require(v, "domain")),
        .signed_by_key_id = try cbor.asText(try cbor.require(v, "signed_by_key_id")),
        .signature = try cbor.asBytes(try cbor.require(v, "signature")),
    };
}

fn claimSignatureArrayToValue(allocator: std.mem.Allocator, items: []const ClaimSignature) !cbor.Value {
    const vals = try allocator.alloc(cbor.Value, items.len);
    for (items, 0..) |it, i| vals[i] = try claimSignatureToValue(allocator, it);
    return cbor.arrayVal(vals);
}

fn claimSignatureArrayFromValue(allocator: std.mem.Allocator, v: cbor.Value) ![]ClaimSignature {
    const arr = try cbor.asArray(v);
    const out = try allocator.alloc(ClaimSignature, arr.len);
    for (arr, 0..) |it, i| out[i] = try claimSignatureFromValue(it);
    return out;
}

// ---------------------------------------------------------------------
// DomainPublicKey
// ---------------------------------------------------------------------

pub const DomainPublicKey = struct {
    key_id: []const u8,
    public_key: []const u8,
    fingerprint: []const u8,
    algorithm: []const u8,
    key_usage: []const u8,
    created_at: []const u8,
    expires_at: []const u8,
    revoked_at: ?[]const u8 = null,
    signed_by_key_id: ?[]const u8 = null,
    key_signature: ?[]const u8 = null,
};

pub fn domainPublicKeyToValue(allocator: std.mem.Allocator, v: DomainPublicKey) !cbor.Value {
    var entries = std.ArrayList(cbor.Entry).init(allocator);
    try entries.append(.{ .key = cbor.text("key_id"), .value = cbor.text(v.key_id) });
    try entries.append(.{ .key = cbor.text("public_key"), .value = cbor.bytesVal(v.public_key) });
    try entries.append(.{ .key = cbor.text("fingerprint"), .value = cbor.text(v.fingerprint) });
    try entries.append(.{ .key = cbor.text("algorithm"), .value = cbor.text(v.algorithm) });
    try entries.append(.{ .key = cbor.text("key_usage"), .value = cbor.text(v.key_usage) });
    try entries.append(.{ .key = cbor.text("created_at"), .value = cbor.text(v.created_at) });
    try entries.append(.{ .key = cbor.text("expires_at"), .value = cbor.text(v.expires_at) });
    if (v.revoked_at) |x| try entries.append(.{ .key = cbor.text("revoked_at"), .value = cbor.text(x) });
    if (v.signed_by_key_id) |x| try entries.append(.{ .key = cbor.text("signed_by_key_id"), .value = cbor.text(x) });
    if (v.key_signature) |x| try entries.append(.{ .key = cbor.text("key_signature"), .value = cbor.bytesVal(x) });
    return cbor.mapVal(try entries.toOwnedSlice());
}

pub fn domainPublicKeyFromValue(v: cbor.Value) !DomainPublicKey {
    return .{
        .key_id = try cbor.asText(try cbor.require(v, "key_id")),
        .public_key = try cbor.asBytes(try cbor.require(v, "public_key")),
        .fingerprint = try cbor.asText(try cbor.require(v, "fingerprint")),
        .algorithm = try cbor.asText(try cbor.require(v, "algorithm")),
        .key_usage = try cbor.asText(try cbor.require(v, "key_usage")),
        .created_at = try cbor.asText(try cbor.require(v, "created_at")),
        .expires_at = try cbor.asText(try cbor.require(v, "expires_at")),
        .revoked_at = try textVal(v, "revoked_at"),
        .signed_by_key_id = try textVal(v, "signed_by_key_id"),
        .key_signature = try bytesValOpt(v, "key_signature"),
    };
}

fn domainPublicKeyArrayToValue(allocator: std.mem.Allocator, items: []const DomainPublicKey) !cbor.Value {
    const vals = try allocator.alloc(cbor.Value, items.len);
    for (items, 0..) |it, i| vals[i] = try domainPublicKeyToValue(allocator, it);
    return cbor.arrayVal(vals);
}

pub fn domainPublicKeyArrayFromValue(allocator: std.mem.Allocator, v: cbor.Value) ![]DomainPublicKey {
    const arr = try cbor.asArray(v);
    const out = try allocator.alloc(DomainPublicKey, arr.len);
    for (arr, 0..) |it, i| out[i] = try domainPublicKeyFromValue(it);
    return out;
}

pub fn encodeDomainPublicKey(allocator: std.mem.Allocator, v: DomainPublicKey) ![]u8 {
    return encodeArena(allocator, try domainPublicKeyToValue(allocator, v));
}
pub fn decodeDomainPublicKey(allocator: std.mem.Allocator, bytes: []const u8) !DomainPublicKey {
    return domainPublicKeyFromValue(try cbor.decode(allocator, bytes));
}

// ---------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------

pub const Claim = struct {
    claim_id: []const u8,
    user_id: []const u8,
    claim_type: []const u8,
    claim_value: []const u8,
    signatures: []const ClaimSignature,
    attested_at: []const u8,
    created_at: []const u8,
    expires_at: ?[]const u8 = null,
    revoked_at: ?[]const u8 = null,
};

pub fn claimToValue(allocator: std.mem.Allocator, v: Claim) !cbor.Value {
    var entries = std.ArrayList(cbor.Entry).init(allocator);
    try entries.append(.{ .key = cbor.text("claim_id"), .value = cbor.text(v.claim_id) });
    try entries.append(.{ .key = cbor.text("user_id"), .value = cbor.text(v.user_id) });
    try entries.append(.{ .key = cbor.text("claim_type"), .value = cbor.text(v.claim_type) });
    try entries.append(.{ .key = cbor.text("claim_value"), .value = cbor.bytesVal(v.claim_value) });
    try entries.append(.{ .key = cbor.text("signatures"), .value = try claimSignatureArrayToValue(allocator, v.signatures) });
    try entries.append(.{ .key = cbor.text("attested_at"), .value = cbor.text(v.attested_at) });
    try entries.append(.{ .key = cbor.text("created_at"), .value = cbor.text(v.created_at) });
    if (v.expires_at) |x| try entries.append(.{ .key = cbor.text("expires_at"), .value = cbor.text(x) });
    if (v.revoked_at) |x| try entries.append(.{ .key = cbor.text("revoked_at"), .value = cbor.text(x) });
    return cbor.mapVal(try entries.toOwnedSlice());
}

pub fn claimFromValue(allocator: std.mem.Allocator, v: cbor.Value) !Claim {
    return .{
        .claim_id = try cbor.asText(try cbor.require(v, "claim_id")),
        .user_id = try cbor.asText(try cbor.require(v, "user_id")),
        .claim_type = try cbor.asText(try cbor.require(v, "claim_type")),
        .claim_value = try cbor.asBytes(try cbor.require(v, "claim_value")),
        .signatures = try claimSignatureArrayFromValue(allocator, try cbor.require(v, "signatures")),
        .attested_at = try cbor.asText(try cbor.require(v, "attested_at")),
        .created_at = try cbor.asText(try cbor.require(v, "created_at")),
        .expires_at = try textVal(v, "expires_at"),
        .revoked_at = try textVal(v, "revoked_at"),
    };
}

fn claimArrayToValue(allocator: std.mem.Allocator, items: []const Claim) !cbor.Value {
    const vals = try allocator.alloc(cbor.Value, items.len);
    for (items, 0..) |it, i| vals[i] = try claimToValue(allocator, it);
    return cbor.arrayVal(vals);
}

pub fn claimArrayFromValue(allocator: std.mem.Allocator, v: cbor.Value) ![]Claim {
    const arr = try cbor.asArray(v);
    const out = try allocator.alloc(Claim, arr.len);
    for (arr, 0..) |it, i| out[i] = try claimFromValue(allocator, it);
    return out;
}

// ---------------------------------------------------------------------
// RevocationCertificate
// ---------------------------------------------------------------------

pub const RevocationCertificate = struct {
    target_key_id: []const u8,
    target_fingerprint: []const u8,
    revoked_at: []const u8,
    signatures: []const ClaimSignature,
};

pub fn revocationCertificateToValue(allocator: std.mem.Allocator, v: RevocationCertificate) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 4);
    entries[0] = .{ .key = cbor.text("target_key_id"), .value = cbor.text(v.target_key_id) };
    entries[1] = .{ .key = cbor.text("target_fingerprint"), .value = cbor.text(v.target_fingerprint) };
    entries[2] = .{ .key = cbor.text("revoked_at"), .value = cbor.text(v.revoked_at) };
    entries[3] = .{ .key = cbor.text("signatures"), .value = try claimSignatureArrayToValue(allocator, v.signatures) };
    return cbor.mapVal(entries);
}

pub fn revocationCertificateFromValue(allocator: std.mem.Allocator, v: cbor.Value) !RevocationCertificate {
    return .{
        .target_key_id = try cbor.asText(try cbor.require(v, "target_key_id")),
        .target_fingerprint = try cbor.asText(try cbor.require(v, "target_fingerprint")),
        .revoked_at = try cbor.asText(try cbor.require(v, "revoked_at")),
        .signatures = try claimSignatureArrayFromValue(allocator, try cbor.require(v, "signatures")),
    };
}

pub fn decodeRevocationCertificate(allocator: std.mem.Allocator, bytes: []const u8) !RevocationCertificate {
    return revocationCertificateFromValue(allocator, try cbor.decode(allocator, bytes));
}

fn revocationCertificateArrayFromValue(allocator: std.mem.Allocator, v: cbor.Value) ![]RevocationCertificate {
    const arr = try cbor.asArray(v);
    const out = try allocator.alloc(RevocationCertificate, arr.len);
    for (arr, 0..) |it, i| out[i] = try revocationCertificateFromValue(allocator, it);
    return out;
}

// ---------------------------------------------------------------------
// EmptyRequest / GetDomainKeysResponse / GetRevocationsRequest/Response /
// LocalRpTicketRedemptionResponse
// ---------------------------------------------------------------------

pub const EmptyRequest = struct {};

pub fn encodeEmptyRequest(allocator: std.mem.Allocator) ![]u8 {
    return encodeArena(allocator, cbor.mapVal(&.{}));
}

pub const GetDomainKeysResponse = struct {
    domain: []const u8,
    keys: []const DomainPublicKey,
    recent_revocations_available: ?bool = null,
};

pub fn decodeGetDomainKeysResponse(allocator: std.mem.Allocator, bytes: []const u8) !GetDomainKeysResponse {
    const root = try cbor.decode(allocator, bytes);
    return .{
        .domain = try cbor.asText(try cbor.require(root, "domain")),
        .keys = try domainPublicKeyArrayFromValue(allocator, try cbor.require(root, "keys")),
        .recent_revocations_available = if (cbor.mapGet(root, "recent_revocations_available")) |v| try cbor.asBool(v) else null,
    };
}

pub fn encodeGetRevocationsRequest(allocator: std.mem.Allocator, since: ?[]const u8) ![]u8 {
    var entries = std.ArrayList(cbor.Entry).init(allocator);
    if (since) |s| try entries.append(.{ .key = cbor.text("since"), .value = cbor.text(s) });
    return encodeArena(allocator, cbor.mapVal(try entries.toOwnedSlice()));
}

pub const GetRevocationsResponse = struct {
    revocations: []const RevocationCertificate,
};

pub fn decodeGetRevocationsResponse(allocator: std.mem.Allocator, bytes: []const u8) !GetRevocationsResponse {
    const root = try cbor.decode(allocator, bytes);
    return .{ .revocations = try revocationCertificateArrayFromValue(allocator, try cbor.require(root, "revocations")) };
}

pub const LocalRpTicketRedemptionResponse = struct {
    user_id: []const u8,
    user_domain: []const u8,
    claims: []const Claim,
    ticket_expires_at: []const u8,
};

pub fn decodeLocalRpTicketRedemptionResponse(allocator: std.mem.Allocator, bytes: []const u8) !LocalRpTicketRedemptionResponse {
    const root = try cbor.decode(allocator, bytes);
    return .{
        .user_id = try cbor.asText(try cbor.require(root, "user_id")),
        .user_domain = try cbor.asText(try cbor.require(root, "user_domain")),
        .claims = try claimArrayFromValue(allocator, try cbor.require(root, "claims")),
        .ticket_expires_at = try cbor.asText(try cbor.require(root, "ticket_expires_at")),
    };
}

pub fn encodeLocalRpTicketRedemptionResponse(allocator: std.mem.Allocator, v: LocalRpTicketRedemptionResponse) ![]u8 {
    const entries = try allocator.alloc(cbor.Entry, 4);
    entries[0] = .{ .key = cbor.text("user_id"), .value = cbor.text(v.user_id) };
    entries[1] = .{ .key = cbor.text("user_domain"), .value = cbor.text(v.user_domain) };
    entries[2] = .{ .key = cbor.text("claims"), .value = try claimArrayToValue(allocator, v.claims) };
    entries[3] = .{ .key = cbor.text("ticket_expires_at"), .value = cbor.text(v.ticket_expires_at) };
    return encodeArena(allocator, cbor.mapVal(entries));
}

// ---------------------------------------------------------------------
// LocalRpDescriptor / SignedLocalRpDescriptor
// ---------------------------------------------------------------------

pub const LocalRpDescriptor = struct {
    app_name: []const u8,
    local_domain_hint: ?[]const u8 = null,
    signing_public_key: []const u8,
    encryption_public_key: []const u8,
    fingerprint: []const u8,
    supported_suites: []const []const u8,
    created_at: []const u8,
    expires_at: []const u8,
};

pub fn localRpDescriptorToValue(allocator: std.mem.Allocator, v: LocalRpDescriptor) !cbor.Value {
    var entries = std.ArrayList(cbor.Entry).init(allocator);
    try entries.append(.{ .key = cbor.text("app_name"), .value = cbor.text(v.app_name) });
    if (v.local_domain_hint) |x| try entries.append(.{ .key = cbor.text("local_domain_hint"), .value = cbor.text(x) });
    try entries.append(.{ .key = cbor.text("signing_public_key"), .value = cbor.bytesVal(v.signing_public_key) });
    try entries.append(.{ .key = cbor.text("encryption_public_key"), .value = cbor.bytesVal(v.encryption_public_key) });
    try entries.append(.{ .key = cbor.text("fingerprint"), .value = cbor.text(v.fingerprint) });
    try entries.append(.{ .key = cbor.text("supported_suites"), .value = try textArrayToValue(allocator, v.supported_suites) });
    try entries.append(.{ .key = cbor.text("created_at"), .value = cbor.text(v.created_at) });
    try entries.append(.{ .key = cbor.text("expires_at"), .value = cbor.text(v.expires_at) });
    return cbor.mapVal(try entries.toOwnedSlice());
}

pub fn localRpDescriptorFromValue(allocator: std.mem.Allocator, v: cbor.Value) !LocalRpDescriptor {
    return .{
        .app_name = try cbor.asText(try cbor.require(v, "app_name")),
        .local_domain_hint = try textVal(v, "local_domain_hint"),
        .signing_public_key = try cbor.asBytes(try cbor.require(v, "signing_public_key")),
        .encryption_public_key = try cbor.asBytes(try cbor.require(v, "encryption_public_key")),
        .fingerprint = try cbor.asText(try cbor.require(v, "fingerprint")),
        .supported_suites = try textArrayFromValue(allocator, try cbor.require(v, "supported_suites")),
        .created_at = try cbor.asText(try cbor.require(v, "created_at")),
        .expires_at = try cbor.asText(try cbor.require(v, "expires_at")),
    };
}

pub fn encodeLocalRpDescriptor(allocator: std.mem.Allocator, v: LocalRpDescriptor) ![]u8 {
    return encodeArena(allocator, try localRpDescriptorToValue(allocator, v));
}
pub fn decodeLocalRpDescriptor(allocator: std.mem.Allocator, bytes: []const u8) !LocalRpDescriptor {
    return localRpDescriptorFromValue(allocator, try cbor.decode(allocator, bytes));
}

pub const SignedLocalRpDescriptor = struct {
    descriptor: []const u8,
    signature: []const u8,
};

pub fn signedLocalRpDescriptorToValue(allocator: std.mem.Allocator, v: SignedLocalRpDescriptor) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 2);
    entries[0] = .{ .key = cbor.text("descriptor"), .value = cbor.bytesVal(v.descriptor) };
    entries[1] = .{ .key = cbor.text("signature"), .value = cbor.bytesVal(v.signature) };
    return cbor.mapVal(entries);
}
pub fn signedLocalRpDescriptorFromValue(v: cbor.Value) !SignedLocalRpDescriptor {
    return .{
        .descriptor = try cbor.asBytes(try cbor.require(v, "descriptor")),
        .signature = try cbor.asBytes(try cbor.require(v, "signature")),
    };
}
pub fn encodeSignedLocalRpDescriptor(allocator: std.mem.Allocator, v: SignedLocalRpDescriptor) ![]u8 {
    return encodeArena(allocator, try signedLocalRpDescriptorToValue(allocator, v));
}
pub fn decodeSignedLocalRpDescriptor(allocator: std.mem.Allocator, bytes: []const u8) !SignedLocalRpDescriptor {
    return signedLocalRpDescriptorFromValue(try cbor.decode(allocator, bytes));
}

// ---------------------------------------------------------------------
// LocalRpLoginRequest / SignedLocalRpLoginRequest
// ---------------------------------------------------------------------

pub const LocalRpLoginRequest = struct {
    descriptor: SignedLocalRpDescriptor,
    callback_url: []const u8,
    nonce: []const u8,
    state: []const u8,
    requested_claims: []const []const u8,
    required_claims: []const []const u8,
    issued_at: []const u8,
    expires_at: []const u8,
};

pub fn localRpLoginRequestToValue(allocator: std.mem.Allocator, v: LocalRpLoginRequest) !cbor.Value {
    var entries = std.ArrayList(cbor.Entry).init(allocator);
    try entries.append(.{ .key = cbor.text("descriptor"), .value = try signedLocalRpDescriptorToValue(allocator, v.descriptor) });
    try entries.append(.{ .key = cbor.text("callback_url"), .value = cbor.text(v.callback_url) });
    try entries.append(.{ .key = cbor.text("nonce"), .value = cbor.bytesVal(v.nonce) });
    try entries.append(.{ .key = cbor.text("state"), .value = cbor.bytesVal(v.state) });
    try entries.append(.{ .key = cbor.text("requested_claims"), .value = try textArrayToValue(allocator, v.requested_claims) });
    try entries.append(.{ .key = cbor.text("required_claims"), .value = try textArrayToValue(allocator, v.required_claims) });
    try entries.append(.{ .key = cbor.text("issued_at"), .value = cbor.text(v.issued_at) });
    try entries.append(.{ .key = cbor.text("expires_at"), .value = cbor.text(v.expires_at) });
    return cbor.mapVal(try entries.toOwnedSlice());
}

pub fn localRpLoginRequestFromValue(allocator: std.mem.Allocator, v: cbor.Value) !LocalRpLoginRequest {
    return .{
        .descriptor = try signedLocalRpDescriptorFromValue(try cbor.require(v, "descriptor")),
        .callback_url = try cbor.asText(try cbor.require(v, "callback_url")),
        .nonce = try cbor.asBytes(try cbor.require(v, "nonce")),
        .state = try cbor.asBytes(try cbor.require(v, "state")),
        .requested_claims = try textArrayFromValue(allocator, try cbor.require(v, "requested_claims")),
        .required_claims = try textArrayFromValue(allocator, try cbor.require(v, "required_claims")),
        .issued_at = try cbor.asText(try cbor.require(v, "issued_at")),
        .expires_at = try cbor.asText(try cbor.require(v, "expires_at")),
    };
}

pub fn encodeLocalRpLoginRequest(allocator: std.mem.Allocator, v: LocalRpLoginRequest) ![]u8 {
    return encodeArena(allocator, try localRpLoginRequestToValue(allocator, v));
}
pub fn decodeLocalRpLoginRequest(allocator: std.mem.Allocator, bytes: []const u8) !LocalRpLoginRequest {
    return localRpLoginRequestFromValue(allocator, try cbor.decode(allocator, bytes));
}

pub const SignedLocalRpLoginRequest = struct {
    request: []const u8,
    signature: []const u8,
};

pub fn signedLocalRpLoginRequestToValue(allocator: std.mem.Allocator, v: SignedLocalRpLoginRequest) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 2);
    entries[0] = .{ .key = cbor.text("request"), .value = cbor.bytesVal(v.request) };
    entries[1] = .{ .key = cbor.text("signature"), .value = cbor.bytesVal(v.signature) };
    return cbor.mapVal(entries);
}
pub fn signedLocalRpLoginRequestFromValue(v: cbor.Value) !SignedLocalRpLoginRequest {
    return .{
        .request = try cbor.asBytes(try cbor.require(v, "request")),
        .signature = try cbor.asBytes(try cbor.require(v, "signature")),
    };
}
pub fn encodeSignedLocalRpLoginRequest(allocator: std.mem.Allocator, v: SignedLocalRpLoginRequest) ![]u8 {
    return encodeArena(allocator, try signedLocalRpLoginRequestToValue(allocator, v));
}
pub fn decodeSignedLocalRpLoginRequest(allocator: std.mem.Allocator, bytes: []const u8) !SignedLocalRpLoginRequest {
    return signedLocalRpLoginRequestFromValue(try cbor.decode(allocator, bytes));
}

// ---------------------------------------------------------------------
// LocalRpCallbackHeader / LocalRpEncryptedCallback
// ---------------------------------------------------------------------

pub const LocalRpCallbackHeader = struct {
    fingerprint: []const u8,
    nonce: []const u8,
    state: []const u8,
    suite: []const u8,
    ephemeral_public_key: []const u8,
    aead_nonce: []const u8,
    issued_at: []const u8,
    expires_at: []const u8,
};

pub fn localRpCallbackHeaderToValue(allocator: std.mem.Allocator, v: LocalRpCallbackHeader) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 8);
    entries[0] = .{ .key = cbor.text("fingerprint"), .value = cbor.text(v.fingerprint) };
    entries[1] = .{ .key = cbor.text("nonce"), .value = cbor.bytesVal(v.nonce) };
    entries[2] = .{ .key = cbor.text("state"), .value = cbor.bytesVal(v.state) };
    entries[3] = .{ .key = cbor.text("suite"), .value = cbor.text(v.suite) };
    entries[4] = .{ .key = cbor.text("ephemeral_public_key"), .value = cbor.bytesVal(v.ephemeral_public_key) };
    entries[5] = .{ .key = cbor.text("aead_nonce"), .value = cbor.bytesVal(v.aead_nonce) };
    entries[6] = .{ .key = cbor.text("issued_at"), .value = cbor.text(v.issued_at) };
    entries[7] = .{ .key = cbor.text("expires_at"), .value = cbor.text(v.expires_at) };
    return cbor.mapVal(entries);
}

pub fn localRpCallbackHeaderFromValue(v: cbor.Value) !LocalRpCallbackHeader {
    return .{
        .fingerprint = try cbor.asText(try cbor.require(v, "fingerprint")),
        .nonce = try cbor.asBytes(try cbor.require(v, "nonce")),
        .state = try cbor.asBytes(try cbor.require(v, "state")),
        .suite = try cbor.asText(try cbor.require(v, "suite")),
        .ephemeral_public_key = try cbor.asBytes(try cbor.require(v, "ephemeral_public_key")),
        .aead_nonce = try cbor.asBytes(try cbor.require(v, "aead_nonce")),
        .issued_at = try cbor.asText(try cbor.require(v, "issued_at")),
        .expires_at = try cbor.asText(try cbor.require(v, "expires_at")),
    };
}

pub fn encodeLocalRpCallbackHeader(allocator: std.mem.Allocator, v: LocalRpCallbackHeader) ![]u8 {
    return encodeArena(allocator, try localRpCallbackHeaderToValue(allocator, v));
}
pub fn decodeLocalRpCallbackHeader(allocator: std.mem.Allocator, bytes: []const u8) !LocalRpCallbackHeader {
    return localRpCallbackHeaderFromValue(try cbor.decode(allocator, bytes));
}

pub const LocalRpEncryptedCallback = struct {
    header: []const u8,
    ciphertext: []const u8,
};

pub fn localRpEncryptedCallbackToValue(allocator: std.mem.Allocator, v: LocalRpEncryptedCallback) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 2);
    entries[0] = .{ .key = cbor.text("header"), .value = cbor.bytesVal(v.header) };
    entries[1] = .{ .key = cbor.text("ciphertext"), .value = cbor.bytesVal(v.ciphertext) };
    return cbor.mapVal(entries);
}
pub fn localRpEncryptedCallbackFromValue(v: cbor.Value) !LocalRpEncryptedCallback {
    return .{
        .header = try cbor.asBytes(try cbor.require(v, "header")),
        .ciphertext = try cbor.asBytes(try cbor.require(v, "ciphertext")),
    };
}
pub fn encodeLocalRpEncryptedCallback(allocator: std.mem.Allocator, v: LocalRpEncryptedCallback) ![]u8 {
    return encodeArena(allocator, try localRpEncryptedCallbackToValue(allocator, v));
}
pub fn decodeLocalRpEncryptedCallback(allocator: std.mem.Allocator, bytes: []const u8) !LocalRpEncryptedCallback {
    return localRpEncryptedCallbackFromValue(try cbor.decode(allocator, bytes));
}

// ---------------------------------------------------------------------
// LocalRpCallbackPayload / SignedLocalRpCallbackPayload
// ---------------------------------------------------------------------

pub const LocalRpCallbackPayload = struct {
    user_id: []const u8,
    user_domain: []const u8,
    claim_ticket: []const u8,
    audience_fingerprint: []const u8,
    callback_url: []const u8,
    nonce: []const u8,
    state: []const u8,
    issued_at: []const u8,
    expires_at: []const u8,
};

pub fn localRpCallbackPayloadToValue(allocator: std.mem.Allocator, v: LocalRpCallbackPayload) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 9);
    entries[0] = .{ .key = cbor.text("user_id"), .value = cbor.text(v.user_id) };
    entries[1] = .{ .key = cbor.text("user_domain"), .value = cbor.text(v.user_domain) };
    entries[2] = .{ .key = cbor.text("claim_ticket"), .value = cbor.bytesVal(v.claim_ticket) };
    entries[3] = .{ .key = cbor.text("audience_fingerprint"), .value = cbor.text(v.audience_fingerprint) };
    entries[4] = .{ .key = cbor.text("callback_url"), .value = cbor.text(v.callback_url) };
    entries[5] = .{ .key = cbor.text("nonce"), .value = cbor.bytesVal(v.nonce) };
    entries[6] = .{ .key = cbor.text("state"), .value = cbor.bytesVal(v.state) };
    entries[7] = .{ .key = cbor.text("issued_at"), .value = cbor.text(v.issued_at) };
    entries[8] = .{ .key = cbor.text("expires_at"), .value = cbor.text(v.expires_at) };
    return cbor.mapVal(entries);
}

pub fn localRpCallbackPayloadFromValue(v: cbor.Value) !LocalRpCallbackPayload {
    return .{
        .user_id = try cbor.asText(try cbor.require(v, "user_id")),
        .user_domain = try cbor.asText(try cbor.require(v, "user_domain")),
        .claim_ticket = try cbor.asBytes(try cbor.require(v, "claim_ticket")),
        .audience_fingerprint = try cbor.asText(try cbor.require(v, "audience_fingerprint")),
        .callback_url = try cbor.asText(try cbor.require(v, "callback_url")),
        .nonce = try cbor.asBytes(try cbor.require(v, "nonce")),
        .state = try cbor.asBytes(try cbor.require(v, "state")),
        .issued_at = try cbor.asText(try cbor.require(v, "issued_at")),
        .expires_at = try cbor.asText(try cbor.require(v, "expires_at")),
    };
}

pub fn encodeLocalRpCallbackPayload(allocator: std.mem.Allocator, v: LocalRpCallbackPayload) ![]u8 {
    return encodeArena(allocator, try localRpCallbackPayloadToValue(allocator, v));
}
pub fn decodeLocalRpCallbackPayload(allocator: std.mem.Allocator, bytes: []const u8) !LocalRpCallbackPayload {
    return localRpCallbackPayloadFromValue(try cbor.decode(allocator, bytes));
}

pub const SignedLocalRpCallbackPayload = struct {
    payload: []const u8,
    signing_key_id: []const u8,
    signature: []const u8,
};

pub fn signedLocalRpCallbackPayloadToValue(allocator: std.mem.Allocator, v: SignedLocalRpCallbackPayload) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 3);
    entries[0] = .{ .key = cbor.text("payload"), .value = cbor.bytesVal(v.payload) };
    entries[1] = .{ .key = cbor.text("signing_key_id"), .value = cbor.text(v.signing_key_id) };
    entries[2] = .{ .key = cbor.text("signature"), .value = cbor.bytesVal(v.signature) };
    return cbor.mapVal(entries);
}
pub fn signedLocalRpCallbackPayloadFromValue(v: cbor.Value) !SignedLocalRpCallbackPayload {
    return .{
        .payload = try cbor.asBytes(try cbor.require(v, "payload")),
        .signing_key_id = try cbor.asText(try cbor.require(v, "signing_key_id")),
        .signature = try cbor.asBytes(try cbor.require(v, "signature")),
    };
}
pub fn encodeSignedLocalRpCallbackPayload(allocator: std.mem.Allocator, v: SignedLocalRpCallbackPayload) ![]u8 {
    return encodeArena(allocator, try signedLocalRpCallbackPayloadToValue(allocator, v));
}
pub fn decodeSignedLocalRpCallbackPayload(allocator: std.mem.Allocator, bytes: []const u8) !SignedLocalRpCallbackPayload {
    return signedLocalRpCallbackPayloadFromValue(try cbor.decode(allocator, bytes));
}

// ---------------------------------------------------------------------
// LocalRpTicketRedemptionRequest / SignedLocalRpTicketRedemptionRequest
// ---------------------------------------------------------------------

pub const LocalRpTicketRedemptionRequest = struct {
    claim_ticket: []const u8,
    fingerprint: []const u8,
    issued_at: []const u8,
};

pub fn localRpTicketRedemptionRequestToValue(allocator: std.mem.Allocator, v: LocalRpTicketRedemptionRequest) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 3);
    entries[0] = .{ .key = cbor.text("claim_ticket"), .value = cbor.bytesVal(v.claim_ticket) };
    entries[1] = .{ .key = cbor.text("fingerprint"), .value = cbor.text(v.fingerprint) };
    entries[2] = .{ .key = cbor.text("issued_at"), .value = cbor.text(v.issued_at) };
    return cbor.mapVal(entries);
}
pub fn localRpTicketRedemptionRequestFromValue(v: cbor.Value) !LocalRpTicketRedemptionRequest {
    return .{
        .claim_ticket = try cbor.asBytes(try cbor.require(v, "claim_ticket")),
        .fingerprint = try cbor.asText(try cbor.require(v, "fingerprint")),
        .issued_at = try cbor.asText(try cbor.require(v, "issued_at")),
    };
}
pub fn encodeLocalRpTicketRedemptionRequest(allocator: std.mem.Allocator, v: LocalRpTicketRedemptionRequest) ![]u8 {
    return encodeArena(allocator, try localRpTicketRedemptionRequestToValue(allocator, v));
}
pub fn decodeLocalRpTicketRedemptionRequest(allocator: std.mem.Allocator, bytes: []const u8) !LocalRpTicketRedemptionRequest {
    return localRpTicketRedemptionRequestFromValue(try cbor.decode(allocator, bytes));
}

pub const SignedLocalRpTicketRedemptionRequest = struct {
    request: []const u8,
    signature: []const u8,
};

pub fn signedLocalRpTicketRedemptionRequestToValue(allocator: std.mem.Allocator, v: SignedLocalRpTicketRedemptionRequest) !cbor.Value {
    const entries = try allocator.alloc(cbor.Entry, 2);
    entries[0] = .{ .key = cbor.text("request"), .value = cbor.bytesVal(v.request) };
    entries[1] = .{ .key = cbor.text("signature"), .value = cbor.bytesVal(v.signature) };
    return cbor.mapVal(entries);
}
pub fn signedLocalRpTicketRedemptionRequestFromValue(v: cbor.Value) !SignedLocalRpTicketRedemptionRequest {
    return .{
        .request = try cbor.asBytes(try cbor.require(v, "request")),
        .signature = try cbor.asBytes(try cbor.require(v, "signature")),
    };
}
pub fn encodeSignedLocalRpTicketRedemptionRequest(allocator: std.mem.Allocator, v: SignedLocalRpTicketRedemptionRequest) ![]u8 {
    return encodeArena(allocator, try signedLocalRpTicketRedemptionRequestToValue(allocator, v));
}
pub fn decodeSignedLocalRpTicketRedemptionRequest(allocator: std.mem.Allocator, bytes: []const u8) !SignedLocalRpTicketRedemptionRequest {
    return signedLocalRpTicketRedemptionRequestFromValue(try cbor.decode(allocator, bytes));
}

test "LocalRpDescriptor encode/decode round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const suites = [_][]const u8{ "aes-256-gcm", "chacha20-poly1305" };
    const d = LocalRpDescriptor{
        .app_name = "Test App",
        .local_domain_hint = "jukebox.lan",
        .signing_public_key = "01234567890123456789012345678901",
        .encryption_public_key = "01234567890123456789012345678902",
        .fingerprint = "deadbeef",
        .supported_suites = &suites,
        .created_at = "2026-01-01T00:00:00Z",
        .expires_at = "2036-01-01T00:00:00Z",
    };
    const encoded = try encodeLocalRpDescriptor(a, d);
    const decoded = try decodeLocalRpDescriptor(a, encoded);
    try std.testing.expectEqualStrings(d.app_name, decoded.app_name);
    try std.testing.expectEqualStrings(d.local_domain_hint.?, decoded.local_domain_hint.?);
    try std.testing.expectEqual(@as(usize, 2), decoded.supported_suites.len);
    try std.testing.expectEqualStrings("aes-256-gcm", decoded.supported_suites[0]);
}

test "optional fields absent on the wire decode back to null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const suites = [_][]const u8{"aes-256-gcm"};
    const d = LocalRpDescriptor{
        .app_name = "No Hint App",
        .local_domain_hint = null,
        .signing_public_key = "x",
        .encryption_public_key = "y",
        .fingerprint = "fp",
        .supported_suites = &suites,
        .created_at = "a",
        .expires_at = "b",
    };
    const encoded = try encodeLocalRpDescriptor(a, d);
    const decoded = try decodeLocalRpDescriptor(a, encoded);
    try std.testing.expect(decoded.local_domain_hint == null);
}
