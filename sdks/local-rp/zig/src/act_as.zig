//! Act-as grants, grantee side (`docs/spec/reserved/act-as-grants.md`).
//!
//! A user lets this local RP (the grantee) act as the user at an enrolled
//! application (the audience). A local RP is identified by the fingerprint
//! of its descriptor signing key, and that key signs every grantee message.
//! A local RP can never be an audience (a peer cannot resolve its keys
//! through DNS), so this module implements the grantee side only:
//!
//! 1. `beginActAs` signs an `ActAsGrantRequest` and builds the browser URL
//!    `<browser base>/auth/act-as?signed_request=...` for the user's home
//!    domain.
//! 2. `completeActAsCallback` reads `act_as_grant_id` and `nonce` from the
//!    callback and checks the nonce against the pending state.
//! 3. `refreshActAsGrant` fetches (or renews) the grant with
//!    `ActAs/refresh-grant` over the same pinned TCP CSIL-RPC path as
//!    claim-ticket redemption.
//! 4. `presentActAs` signs one presentation for one call to the audience.
//!
//! Every signature covers `CBOR([tag, payload_bytes])`, the same
//! construction as the descriptor and redemption signatures
//! (`local_rp.envelopeSignatureInput`). The hand-written encoders below
//! produce the same bytes as the CSIL codec: `cbor.zig` sorts map keys
//! canonically, and absent optional fields are omitted. The reference is
//! `crates/liblinkkeys/src/act_as.rs`; the arbiter is
//! `sdks/regular-rp/conformance/act_as_grantee_signing.json`.
//!
//! Memory: like the rest of this package, every function allocates from the
//! caller's allocator and never frees intermediates. Pass an arena.

const std = @import("std");
const cbor = @import("cbor.zig");
const types = @import("types.zig");
const identity = @import("identity.zig");
const local_rp = @import("local_rp.zig");
const encoding = @import("encoding.zig");
const xcrypto = @import("crypto.zig");
const dnsmod = @import("dns.zig");
const browser = @import("browser.zig");
const begin = @import("begin.zig");
const rpc = @import("rpc.zig");
const transportmod = @import("transport.zig");

// ---------------------------------------------------------------------
// Tags, routes, and bounds
// ---------------------------------------------------------------------

pub const tag_grant_request = "linkkeys-act-as-grant-request-v1alpha";
pub const tag_refresh_request = "linkkeys-act-as-refresh-request-v1alpha";
pub const tag_presentation = "linkkeys-act-as-presentation-v1alpha";

/// Default grant-request window (`expires_at - requested_at`).
pub const default_request_window_seconds: i64 = 300;
/// Longest grant-request window. The reference home domain refuses longer
/// windows, because it keeps request nonces only that long.
pub const max_request_window_seconds: i64 = 900;
/// Window of a refresh request.
pub const refresh_request_window_seconds: i64 = 300;

// ---------------------------------------------------------------------
// Wire types (CSIL "Act-as grants")
// ---------------------------------------------------------------------

/// An enrolled application, as an application-key attestation binds it.
pub const ApplicationRef = struct {
    subject_user_id: []const u8,
    subject_domain: []const u8,
    application_id: []const u8,
};

pub const ApplicationKeySignature = struct {
    signed_by_key_id: []const u8,
    signature: []const u8,
};

/// A local-RP `GranteeProof`: the signed descriptor and the signature of
/// its signing key. The application form (`application_instance_id`) is
/// not supported here, because this SDK is always a local RP.
pub const GranteeProof = struct {
    local_rp_descriptor: types.SignedLocalRpDescriptor,
    signature: ApplicationKeySignature,
};

/// The audience's signed scope set, as the grantee received it. The
/// grantee does not verify it; it embeds it unchanged in its request.
/// `signatures` has at least one entry.
pub const SignedActAsScopeSet = struct {
    scope_set: []const u8,
    signer_instance_id: []const u8,
    signatures: []const ApplicationKeySignature,
};

/// A grant, signed by the user's home domain. `grant` is CBOR(ActAsGrant);
/// a presentation binds SHA-256 of these bytes.
pub const SignedActAsGrant = struct {
    grant: []const u8,
    signatures: []const types.ClaimSignature,
};

/// `ActAsGrantRequest` with a local-RP grantee
/// (`grantee = {local_rp_descriptor_fingerprint}`). A local RP has no
/// enrolling account, so it never sends `grantee_handle_claim`.
pub const ActAsGrantRequest = struct {
    grantee_fingerprint: []const u8,
    scope_set: SignedActAsScopeSet,
    requested_lifetime_seconds: ?i64 = null,
    requested_renewal_window_seconds: ?i64 = null,
    callback_url: []const u8,
    nonce: []const u8,
    requested_at: []const u8,
    expires_at: []const u8,
};

pub const SignedActAsGrantRequest = struct {
    request: []const u8,
    proof: GranteeProof,
};

/// `ActAsRefreshRequest` with a local-RP grantee.
pub const ActAsRefreshRequest = struct {
    grant_id: []const u8,
    grantee_fingerprint: []const u8,
    requested_at: []const u8,
    expires_at: []const u8,
    nonce: []const u8,
};

pub const SignedActAsRefreshRequest = struct {
    request: []const u8,
    proof: GranteeProof,
};

pub const RefreshActAsGrantResponse = struct {
    grant: SignedActAsGrant,
    /// True when the home domain made a new signature for this call.
    signed: bool,
};

pub const ActAsPresentation = struct {
    grant_hash: []const u8,
    audience: ApplicationRef,
    request_digest: []const u8,
    presented_at: []const u8,
    nonce: []const u8,
};

pub const SignedActAsPresentation = struct {
    presentation: []const u8,
    proof: GranteeProof,
};

/// What the grantee sends with each call to the audience.
pub const ActAsCredential = struct {
    grant: SignedActAsGrant,
    presentation: SignedActAsPresentation,
};

// ---------------------------------------------------------------------
// Value-tree conversion
// ---------------------------------------------------------------------

fn mapOf(allocator: std.mem.Allocator, entries: []const cbor.Entry) !cbor.Value {
    return cbor.mapVal(try allocator.dupe(cbor.Entry, entries));
}

fn intVal(n: i64) cbor.Value {
    return if (n >= 0) cbor.uint(@intCast(n)) else .{ .nint = n };
}

fn asI64(v: cbor.Value) !i64 {
    return switch (v) {
        .uint => |n| std.math.cast(i64, n) orelse error.IntegerOverflow,
        .nint => |n| n,
        else => error.WrongType,
    };
}

fn optI64(v: cbor.Value, key: []const u8) !?i64 {
    return if (cbor.mapGet(v, key)) |x| try asI64(x) else null;
}

fn requireText(v: cbor.Value, key: []const u8) ![]const u8 {
    return cbor.asText(try cbor.require(v, key));
}

fn requireBytes(v: cbor.Value, key: []const u8) ![]const u8 {
    return cbor.asBytes(try cbor.require(v, key));
}

pub fn applicationRefToValue(allocator: std.mem.Allocator, v: ApplicationRef) !cbor.Value {
    return mapOf(allocator, &.{
        .{ .key = cbor.text("subject_user_id"), .value = cbor.text(v.subject_user_id) },
        .{ .key = cbor.text("subject_domain"), .value = cbor.text(v.subject_domain) },
        .{ .key = cbor.text("application_id"), .value = cbor.text(v.application_id) },
    });
}

pub fn applicationRefFromValue(v: cbor.Value) !ApplicationRef {
    return .{
        .subject_user_id = try requireText(v, "subject_user_id"),
        .subject_domain = try requireText(v, "subject_domain"),
        .application_id = try requireText(v, "application_id"),
    };
}

/// `GranteeRef` with only `local_rp_descriptor_fingerprint`.
fn localGranteeRefToValue(allocator: std.mem.Allocator, fingerprint: []const u8) !cbor.Value {
    return mapOf(allocator, &.{
        .{ .key = cbor.text("local_rp_descriptor_fingerprint"), .value = cbor.text(fingerprint) },
    });
}

/// Reads a `GranteeRef` that must be the local-RP form.
fn localGranteeRefFromValue(v: cbor.Value) ![]const u8 {
    if (cbor.mapGet(v, "application") != null) return error.UnsupportedGranteeForm;
    return requireText(v, "local_rp_descriptor_fingerprint");
}

fn applicationKeySignatureToValue(allocator: std.mem.Allocator, v: ApplicationKeySignature) !cbor.Value {
    return mapOf(allocator, &.{
        .{ .key = cbor.text("signed_by_key_id"), .value = cbor.text(v.signed_by_key_id) },
        .{ .key = cbor.text("signature"), .value = cbor.bytesVal(v.signature) },
    });
}

fn applicationKeySignatureFromValue(v: cbor.Value) !ApplicationKeySignature {
    return .{
        .signed_by_key_id = try requireText(v, "signed_by_key_id"),
        .signature = try requireBytes(v, "signature"),
    };
}

fn granteeProofToValue(allocator: std.mem.Allocator, v: GranteeProof) !cbor.Value {
    return mapOf(allocator, &.{
        .{ .key = cbor.text("local_rp_descriptor"), .value = try types.signedLocalRpDescriptorToValue(allocator, v.local_rp_descriptor) },
        .{ .key = cbor.text("signature"), .value = try applicationKeySignatureToValue(allocator, v.signature) },
    });
}

fn granteeProofFromValue(v: cbor.Value) !GranteeProof {
    if (cbor.mapGet(v, "application_instance_id") != null) return error.UnsupportedGranteeForm;
    return .{
        .local_rp_descriptor = try types.signedLocalRpDescriptorFromValue(try cbor.require(v, "local_rp_descriptor")),
        .signature = try applicationKeySignatureFromValue(try cbor.require(v, "signature")),
    };
}

fn signedScopeSetToValue(allocator: std.mem.Allocator, v: SignedActAsScopeSet) !cbor.Value {
    return mapOf(allocator, &.{
        .{ .key = cbor.text("scope_set"), .value = cbor.bytesVal(v.scope_set) },
        .{ .key = cbor.text("signer_instance_id"), .value = cbor.text(v.signer_instance_id) },
        .{ .key = cbor.text("signatures"), .value = try applicationKeySignatureArrayToValue(allocator, v.signatures) },
    });
}

fn applicationKeySignatureArrayToValue(allocator: std.mem.Allocator, items: []const ApplicationKeySignature) !cbor.Value {
    const vals = try allocator.alloc(cbor.Value, items.len);
    for (items, 0..) |it, i| vals[i] = try applicationKeySignatureToValue(allocator, it);
    return cbor.arrayVal(vals);
}

/// `[+ ApplicationKeySignature]`: an empty array is a decode error.
fn applicationKeySignatureArrayFromValue(allocator: std.mem.Allocator, v: cbor.Value) ![]ApplicationKeySignature {
    const arr = try cbor.asArray(v);
    if (arr.len == 0) return error.EmptySignatures;
    const out = try allocator.alloc(ApplicationKeySignature, arr.len);
    for (arr, 0..) |it, i| out[i] = try applicationKeySignatureFromValue(it);
    return out;
}

fn signedScopeSetFromValue(allocator: std.mem.Allocator, v: cbor.Value) !SignedActAsScopeSet {
    return .{
        .scope_set = try requireBytes(v, "scope_set"),
        .signer_instance_id = try requireText(v, "signer_instance_id"),
        .signatures = try applicationKeySignatureArrayFromValue(allocator, try cbor.require(v, "signatures")),
    };
}

fn signedGrantToValue(allocator: std.mem.Allocator, v: SignedActAsGrant) !cbor.Value {
    return mapOf(allocator, &.{
        .{ .key = cbor.text("grant"), .value = cbor.bytesVal(v.grant) },
        .{ .key = cbor.text("signatures"), .value = try types.claimSignatureArrayToValue(allocator, v.signatures) },
    });
}

fn signedGrantFromValue(allocator: std.mem.Allocator, v: cbor.Value) !SignedActAsGrant {
    return .{
        .grant = try requireBytes(v, "grant"),
        .signatures = try types.claimSignatureArrayFromValue(allocator, try cbor.require(v, "signatures")),
    };
}

fn grantRequestToValue(allocator: std.mem.Allocator, v: ActAsGrantRequest) !cbor.Value {
    var entries = std.ArrayList(cbor.Entry).init(allocator);
    try entries.appendSlice(&.{
        .{ .key = cbor.text("grantee"), .value = try localGranteeRefToValue(allocator, v.grantee_fingerprint) },
        .{ .key = cbor.text("scope_set"), .value = try signedScopeSetToValue(allocator, v.scope_set) },
        .{ .key = cbor.text("callback_url"), .value = cbor.text(v.callback_url) },
        .{ .key = cbor.text("nonce"), .value = cbor.text(v.nonce) },
        .{ .key = cbor.text("requested_at"), .value = cbor.text(v.requested_at) },
        .{ .key = cbor.text("expires_at"), .value = cbor.text(v.expires_at) },
    });
    if (v.requested_lifetime_seconds) |n| try entries.append(.{ .key = cbor.text("requested_lifetime_seconds"), .value = intVal(n) });
    if (v.requested_renewal_window_seconds) |n| try entries.append(.{ .key = cbor.text("requested_renewal_window_seconds"), .value = intVal(n) });
    return cbor.mapVal(try entries.toOwnedSlice());
}

fn grantRequestFromValue(allocator: std.mem.Allocator, v: cbor.Value) !ActAsGrantRequest {
    return .{
        .grantee_fingerprint = try localGranteeRefFromValue(try cbor.require(v, "grantee")),
        .scope_set = try signedScopeSetFromValue(allocator, try cbor.require(v, "scope_set")),
        .requested_lifetime_seconds = try optI64(v, "requested_lifetime_seconds"),
        .requested_renewal_window_seconds = try optI64(v, "requested_renewal_window_seconds"),
        .callback_url = try requireText(v, "callback_url"),
        .nonce = try requireText(v, "nonce"),
        .requested_at = try requireText(v, "requested_at"),
        .expires_at = try requireText(v, "expires_at"),
    };
}

fn refreshRequestToValue(allocator: std.mem.Allocator, v: ActAsRefreshRequest) !cbor.Value {
    return mapOf(allocator, &.{
        .{ .key = cbor.text("grant_id"), .value = cbor.text(v.grant_id) },
        .{ .key = cbor.text("grantee"), .value = try localGranteeRefToValue(allocator, v.grantee_fingerprint) },
        .{ .key = cbor.text("requested_at"), .value = cbor.text(v.requested_at) },
        .{ .key = cbor.text("expires_at"), .value = cbor.text(v.expires_at) },
        .{ .key = cbor.text("nonce"), .value = cbor.text(v.nonce) },
    });
}

fn refreshRequestFromValue(v: cbor.Value) !ActAsRefreshRequest {
    return .{
        .grant_id = try requireText(v, "grant_id"),
        .grantee_fingerprint = try localGranteeRefFromValue(try cbor.require(v, "grantee")),
        .requested_at = try requireText(v, "requested_at"),
        .expires_at = try requireText(v, "expires_at"),
        .nonce = try requireText(v, "nonce"),
    };
}

/// The `{request: bytes, proof: GranteeProof}` shape shared by
/// `SignedActAsGrantRequest` and `SignedActAsRefreshRequest`.
fn signedRequestToValue(allocator: std.mem.Allocator, request: []const u8, proof: GranteeProof) !cbor.Value {
    return mapOf(allocator, &.{
        .{ .key = cbor.text("request"), .value = cbor.bytesVal(request) },
        .{ .key = cbor.text("proof"), .value = try granteeProofToValue(allocator, proof) },
    });
}

fn presentationToValue(allocator: std.mem.Allocator, v: ActAsPresentation) !cbor.Value {
    return mapOf(allocator, &.{
        .{ .key = cbor.text("grant_hash"), .value = cbor.bytesVal(v.grant_hash) },
        .{ .key = cbor.text("audience"), .value = try applicationRefToValue(allocator, v.audience) },
        .{ .key = cbor.text("request_digest"), .value = cbor.bytesVal(v.request_digest) },
        .{ .key = cbor.text("presented_at"), .value = cbor.text(v.presented_at) },
        .{ .key = cbor.text("nonce"), .value = cbor.bytesVal(v.nonce) },
    });
}

fn credentialToValue(allocator: std.mem.Allocator, v: ActAsCredential) !cbor.Value {
    return mapOf(allocator, &.{
        .{ .key = cbor.text("grant"), .value = try signedGrantToValue(allocator, v.grant) },
        .{ .key = cbor.text("presentation"), .value = try mapOf(allocator, &.{
            .{ .key = cbor.text("presentation"), .value = cbor.bytesVal(v.presentation.presentation) },
            .{ .key = cbor.text("proof"), .value = try granteeProofToValue(allocator, v.presentation.proof) },
        }) },
    });
}

// ---------------------------------------------------------------------
// Encode / decode
// ---------------------------------------------------------------------

pub fn encodeSignedActAsScopeSet(allocator: std.mem.Allocator, v: SignedActAsScopeSet) ![]u8 {
    return cbor.encodeAlloc(allocator, try signedScopeSetToValue(allocator, v));
}
pub fn decodeSignedActAsScopeSet(allocator: std.mem.Allocator, bytes: []const u8) !SignedActAsScopeSet {
    return signedScopeSetFromValue(allocator, try cbor.decode(allocator, bytes));
}

pub fn encodeSignedActAsGrant(allocator: std.mem.Allocator, v: SignedActAsGrant) ![]u8 {
    return cbor.encodeAlloc(allocator, try signedGrantToValue(allocator, v));
}
pub fn decodeSignedActAsGrant(allocator: std.mem.Allocator, bytes: []const u8) !SignedActAsGrant {
    return signedGrantFromValue(allocator, try cbor.decode(allocator, bytes));
}

pub fn encodeActAsGrantRequest(allocator: std.mem.Allocator, v: ActAsGrantRequest) ![]u8 {
    return cbor.encodeAlloc(allocator, try grantRequestToValue(allocator, v));
}
pub fn decodeActAsGrantRequest(allocator: std.mem.Allocator, bytes: []const u8) !ActAsGrantRequest {
    return grantRequestFromValue(allocator, try cbor.decode(allocator, bytes));
}

pub fn encodeSignedActAsGrantRequest(allocator: std.mem.Allocator, v: SignedActAsGrantRequest) ![]u8 {
    return cbor.encodeAlloc(allocator, try signedRequestToValue(allocator, v.request, v.proof));
}
pub fn decodeSignedActAsGrantRequest(allocator: std.mem.Allocator, bytes: []const u8) !SignedActAsGrantRequest {
    const root = try cbor.decode(allocator, bytes);
    return .{ .request = try requireBytes(root, "request"), .proof = try granteeProofFromValue(try cbor.require(root, "proof")) };
}

/// The `signed_request` query value: base64url-no-pad CBOR.
pub fn signedActAsGrantRequestToUrlParam(allocator: std.mem.Allocator, v: SignedActAsGrantRequest) ![]u8 {
    return encoding.encodeUrlParam(allocator, try encodeSignedActAsGrantRequest(allocator, v));
}
pub fn signedActAsGrantRequestFromUrlParam(allocator: std.mem.Allocator, param: []const u8) !SignedActAsGrantRequest {
    return decodeSignedActAsGrantRequest(allocator, try encoding.decodeUrlParam(allocator, param));
}

pub fn encodeActAsRefreshRequest(allocator: std.mem.Allocator, v: ActAsRefreshRequest) ![]u8 {
    return cbor.encodeAlloc(allocator, try refreshRequestToValue(allocator, v));
}
pub fn decodeActAsRefreshRequest(allocator: std.mem.Allocator, bytes: []const u8) !ActAsRefreshRequest {
    return refreshRequestFromValue(try cbor.decode(allocator, bytes));
}

pub fn encodeSignedActAsRefreshRequest(allocator: std.mem.Allocator, v: SignedActAsRefreshRequest) ![]u8 {
    return cbor.encodeAlloc(allocator, try signedRequestToValue(allocator, v.request, v.proof));
}

fn signedRefreshRequestFromValue(v: cbor.Value) !SignedActAsRefreshRequest {
    return .{ .request = try requireBytes(v, "request"), .proof = try granteeProofFromValue(try cbor.require(v, "proof")) };
}

/// `RefreshActAsGrantRequest {request}`: the `ActAs/refresh-grant` payload.
pub fn encodeRefreshActAsGrantRequest(allocator: std.mem.Allocator, signed: SignedActAsRefreshRequest) ![]u8 {
    return cbor.encodeAlloc(allocator, try mapOf(allocator, &.{
        .{ .key = cbor.text("request"), .value = try signedRequestToValue(allocator, signed.request, signed.proof) },
    }));
}
pub fn decodeRefreshActAsGrantRequest(allocator: std.mem.Allocator, bytes: []const u8) !SignedActAsRefreshRequest {
    return signedRefreshRequestFromValue(try cbor.require(try cbor.decode(allocator, bytes), "request"));
}

pub fn encodeRefreshActAsGrantResponse(allocator: std.mem.Allocator, v: RefreshActAsGrantResponse) ![]u8 {
    return cbor.encodeAlloc(allocator, try mapOf(allocator, &.{
        .{ .key = cbor.text("grant"), .value = try signedGrantToValue(allocator, v.grant) },
        .{ .key = cbor.text("signed"), .value = cbor.boolVal(v.signed) },
    }));
}
pub fn decodeRefreshActAsGrantResponse(allocator: std.mem.Allocator, bytes: []const u8) !RefreshActAsGrantResponse {
    const root = try cbor.decode(allocator, bytes);
    return .{
        .grant = try signedGrantFromValue(allocator, try cbor.require(root, "grant")),
        .signed = try cbor.asBool(try cbor.require(root, "signed")),
    };
}

pub fn encodeActAsPresentation(allocator: std.mem.Allocator, v: ActAsPresentation) ![]u8 {
    return cbor.encodeAlloc(allocator, try presentationToValue(allocator, v));
}
pub fn decodeActAsPresentation(allocator: std.mem.Allocator, bytes: []const u8) !ActAsPresentation {
    const root = try cbor.decode(allocator, bytes);
    return .{
        .grant_hash = try requireBytes(root, "grant_hash"),
        .audience = try applicationRefFromValue(try cbor.require(root, "audience")),
        .request_digest = try requireBytes(root, "request_digest"),
        .presented_at = try requireText(root, "presented_at"),
        .nonce = try requireBytes(root, "nonce"),
    };
}

pub fn encodeActAsCredential(allocator: std.mem.Allocator, v: ActAsCredential) ![]u8 {
    return cbor.encodeAlloc(allocator, try credentialToValue(allocator, v));
}

// ---------------------------------------------------------------------
// Signing and proof verification
// ---------------------------------------------------------------------

/// Signs `CBOR([tag, payload])` with the descriptor signing key and wraps
/// the signature in a local-RP `GranteeProof`.
pub fn proveLocalRp(allocator: std.mem.Allocator, key_material: identity.LocalRpKeyMaterial, tag: []const u8, payload: []const u8) !GranteeProof {
    const input = try local_rp.envelopeSignatureInput(allocator, tag, payload);
    const sig = try xcrypto.signEd25519(key_material.signing_private_key, input);
    return .{
        .local_rp_descriptor = key_material.descriptor,
        .signature = .{ .signed_by_key_id = key_material.fingerprint, .signature = try allocator.dupe(u8, &sig) },
    };
}

/// Encodes and signs a grant request under `tag_grant_request`.
pub fn signActAsGrantRequest(allocator: std.mem.Allocator, request: ActAsGrantRequest, key_material: identity.LocalRpKeyMaterial) !SignedActAsGrantRequest {
    const bytes = try encodeActAsGrantRequest(allocator, request);
    return .{ .request = bytes, .proof = try proveLocalRp(allocator, key_material, tag_grant_request, bytes) };
}

/// Encodes and signs a refresh request under `tag_refresh_request`.
pub fn signActAsRefreshRequest(allocator: std.mem.Allocator, request: ActAsRefreshRequest, key_material: identity.LocalRpKeyMaterial) !SignedActAsRefreshRequest {
    const bytes = try encodeActAsRefreshRequest(allocator, request);
    return .{ .request = bytes, .proof = try proveLocalRp(allocator, key_material, tag_refresh_request, bytes) };
}

/// Verifies a local-RP proof as a home domain or audience does: the
/// descriptor verifies and is valid at `now`, its fingerprint equals
/// `expected_fingerprint` and `signed_by_key_id`, and its signing key
/// signed `CBOR([tag, payload])`. This SDK's own tests use it; an app can
/// use it to check what it built.
pub fn verifyLocalRpProof(allocator: std.mem.Allocator, proof: GranteeProof, tag: []const u8, payload: []const u8, expected_fingerprint: []const u8, now: i64) !void {
    const descriptor = try local_rp.verifyLocalRpDescriptor(allocator, proof.local_rp_descriptor, now, local_rp.default_clock_skew_seconds);
    if (!std.mem.eql(u8, descriptor.fingerprint, expected_fingerprint) or
        !std.mem.eql(u8, proof.signature.signed_by_key_id, descriptor.fingerprint))
    {
        return error.FingerprintMismatch;
    }
    const input = try local_rp.envelopeSignatureInput(allocator, tag, payload);
    if (!xcrypto.verifyEd25519(descriptor.signing_public_key, input, proof.signature.signature)) return error.BadSignature;
}

fn freshNonce(allocator: std.mem.Allocator) ![]u8 {
    var raw: [32]u8 = undefined;
    xcrypto.randomBytes(&raw);
    return encoding.encodeUrlParam(allocator, &raw);
}

fn timestamp(allocator: std.mem.Allocator, unix_seconds: i64) ![]u8 {
    var buf: [32]u8 = undefined;
    return allocator.dupe(u8, try local_rp.formatTimestamp(&buf, unix_seconds));
}

// ---------------------------------------------------------------------
// 1. Begin
// ---------------------------------------------------------------------

pub const BeginActAsConfig = struct {
    /// This local RP's identity. Its descriptor signing key signs.
    key_material: identity.LocalRpKeyMaterial,
    /// The LinkKeys login (`user@domain`) or domain the user entered,
    /// parsed like `beginLocalLogin`. Only the domain is used: the home
    /// domain authenticates the user itself.
    user_domain: []const u8,
    /// CBOR of the `SignedActAsScopeSet` exactly as the audience sent it.
    /// It is embedded unchanged.
    scope_set_cbor: []const u8,
    /// Requested grant lifetime. Must be positive when set.
    requested_lifetime_seconds: ?i64 = null,
    /// Requested renewal window. Must not be negative when set.
    requested_renewal_window_seconds: ?i64 = null,
    /// Where the home domain sends the browser back, with
    /// `act_as_grant_id` and `nonce`. Must be `http://` or `https://`.
    callback_url: []const u8,
    now: i64,
    /// DNS seam for browser endpoint discovery. Defaults to the system
    /// resolver when null.
    dns: ?dnsmod.DnsResolver = null,
    /// `expires_at - requested_at`. Defaults to
    /// `default_request_window_seconds`; at most `max_request_window_seconds`.
    request_window_seconds: ?i64 = null,
};

pub const ActAsRedirect = struct {
    redirect_url: []const u8,
};

/// State the app keeps between `beginActAs` and `completeActAsCallback`.
/// Single-use: discard it after one callback.
pub const PendingActAs = struct {
    /// The request nonce (base64url text). The callback must echo it.
    nonce: []const u8,
    /// The user's identity domain (lowercase). `refreshActAsGrant` calls
    /// this domain, never the discovered browser host.
    user_domain: []const u8,
    callback_url: []const u8,
};

pub const BeginActAsResult = struct {
    redirect: ActAsRedirect,
    pending: PendingActAs,
};

/// Signs an `ActAsGrantRequest` and builds the browser redirect to the
/// user's home domain: `<browser base>/auth/act-as?signed_request=...`.
/// The browser base comes from `_linkkeys_apis.<domain>` (`https=`), with a
/// fallback to `https://<domain>`, as in `beginLocalLogin`.
pub fn beginActAs(allocator: std.mem.Allocator, config: BeginActAsConfig) !BeginActAsResult {
    try begin.validateCallbackScheme(config.callback_url);
    const identity_input = try begin.parseIdentityInput(allocator, config.user_domain);

    const window = config.request_window_seconds orelse default_request_window_seconds;
    if (window <= 0 or window > max_request_window_seconds) return error.InvalidRequestWindow;
    if (config.requested_lifetime_seconds) |n| if (n <= 0) return error.InvalidRequestedLifetime;
    if (config.requested_renewal_window_seconds) |n| if (n < 0) return error.InvalidRequestedRenewalWindow;

    const scope_set = try decodeSignedActAsScopeSet(allocator, config.scope_set_cbor);
    const nonce = try freshNonce(allocator);
    const request = ActAsGrantRequest{
        .grantee_fingerprint = config.key_material.fingerprint,
        .scope_set = scope_set,
        .requested_lifetime_seconds = config.requested_lifetime_seconds,
        .requested_renewal_window_seconds = config.requested_renewal_window_seconds,
        .callback_url = config.callback_url,
        .nonce = nonce,
        .requested_at = try timestamp(allocator, config.now),
        .expires_at = try timestamp(allocator, config.now + window),
    };
    const signed = try signActAsGrantRequest(allocator, request, config.key_material);
    const param = try signedActAsGrantRequestToUrlParam(allocator, signed);

    var system_resolver: dnsmod.SystemDnsResolver = undefined;
    const resolver: ?dnsmod.DnsResolver = config.dns orelse blk: {
        system_resolver = dnsmod.SystemDnsResolver.init() catch break :blk null;
        break :blk system_resolver.resolver();
    };
    const redirect_url = try browser.resolveBrowserEndpoint(allocator, resolver, identity_input.domain, browser.browser_route_act_as, param);

    return .{
        .redirect = .{ .redirect_url = redirect_url },
        .pending = .{ .nonce = nonce, .user_domain = identity_input.domain, .callback_url = config.callback_url },
    };
}

// ---------------------------------------------------------------------
// 2. Callback
// ---------------------------------------------------------------------

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn percentDecode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try std.ArrayList(u8).initCapacity(allocator, s.len);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] != '%') {
            out.appendAssumeCapacity(s[i]);
            continue;
        }
        if (i + 2 >= s.len) return error.InvalidPercentEncoding;
        const hi = hexValue(s[i + 1]) orelse return error.InvalidPercentEncoding;
        const lo = hexValue(s[i + 2]) orelse return error.InvalidPercentEncoding;
        out.appendAssumeCapacity(hi * 16 + lo);
        i += 2;
    }
    return out.toOwnedSlice();
}

/// Reads `act_as_grant_id` and `nonce` from the callback (a full URL or
/// only its query string). The nonce must equal `pending.nonce`; the
/// compare is constant-time. Returns the grant id. A parameter that occurs
/// more than once is an error, so the value is never ambiguous.
pub fn completeActAsCallback(allocator: std.mem.Allocator, pending: PendingActAs, callback: []const u8) ![]const u8 {
    var query = callback;
    if (std.mem.indexOfScalar(u8, query, '?')) |q| query = query[q + 1 ..];
    if (std.mem.indexOfScalar(u8, query, '#')) |h| query = query[0..h];

    var grant_id: ?[]const u8 = null;
    var nonce: ?[]const u8 = null;
    var pairs = std.mem.splitScalar(u8, query, '&');
    while (pairs.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const name = pair[0..eq];
        const slot: *?[]const u8 = if (std.mem.eql(u8, name, "act_as_grant_id"))
            &grant_id
        else if (std.mem.eql(u8, name, "nonce"))
            &nonce
        else
            continue;
        if (slot.* != null) return error.DuplicateQueryParameter;
        slot.* = try percentDecode(allocator, pair[eq + 1 ..]);
    }

    const got_nonce = nonce orelse return error.MissingNonce;
    if (!local_rp.timingSafeEqlBytes(pending.nonce, got_nonce)) return error.NonceMismatch;
    const id = grant_id orelse return error.MissingActAsGrantId;
    if (id.len == 0) return error.MissingActAsGrantId;
    return id;
}

// ---------------------------------------------------------------------
// 3. Refresh
// ---------------------------------------------------------------------

pub const RefreshActAsGrantConfig = struct {
    key_material: identity.LocalRpKeyMaterial,
    /// The user's identity domain (`PendingActAs.user_domain`).
    user_domain: []const u8,
    grant_id: []const u8,
    now: i64,
    /// The TCP dial seam.
    transport: transportmod.Transport,
    /// The pinned-TLS dial seam, as in `CompleteLocalLoginConfig`. Defaults
    /// to `rpc.defaultSecureDial`, which always fails closed.
    secure_dial: rpc.SecureDial = rpc.defaultSecureDial,
    /// The DNS TXT lookup seam (`fp=` pins and `tcp=` endpoint).
    dns: dnsmod.DnsResolver,
};

/// Fetches the current grant, or a renewed one, with `ActAs/refresh-grant`
/// on the user's home domain. Use it once after the callback to get the
/// grant, and again when less than half of its life remains. The returned
/// grant must name the requested grant id, this local RP as grantee, and
/// `user_domain` as its subject domain, or the call fails with
/// `error.GrantMismatch`.
pub fn refreshActAsGrant(allocator: std.mem.Allocator, config: RefreshActAsGrantConfig) !RefreshActAsGrantResponse {
    if (config.grant_id.len == 0) return error.MissingActAsGrantId;
    const request = ActAsRefreshRequest{
        .grant_id = config.grant_id,
        .grantee_fingerprint = config.key_material.fingerprint,
        .requested_at = try timestamp(allocator, config.now),
        .expires_at = try timestamp(allocator, config.now + refresh_request_window_seconds),
        .nonce = try freshNonce(allocator),
    };
    const signed = try signActAsRefreshRequest(allocator, request, config.key_material);
    const payload = try encodeRefreshActAsGrantRequest(allocator, signed);
    const resp = try rpc.callDomain(allocator, config.transport, config.secure_dial, config.dns, config.user_domain, "ActAs", "refresh-grant", payload);
    const decoded = try decodeRefreshActAsGrantResponse(allocator, resp);
    try checkRefreshedGrant(allocator, decoded.grant, config.grant_id, config.key_material.fingerprint, config.user_domain);
    return decoded;
}

/// Binds the returned grant to this refresh: the grant id, the local-RP
/// grantee (this fingerprint, no application form), and the user's domain
/// must match. This does not verify the home domain's signature; the
/// audience does that.
fn checkRefreshedGrant(allocator: std.mem.Allocator, grant: SignedActAsGrant, grant_id: []const u8, fingerprint: []const u8, user_domain: []const u8) !void {
    const root = try cbor.decode(allocator, grant.grant);
    if (!std.mem.eql(u8, try requireText(root, "grant_id"), grant_id)) return error.GrantMismatch;
    if (!std.ascii.eqlIgnoreCase(try requireText(root, "subject_domain"), user_domain)) return error.GrantMismatch;
    const grantee = try cbor.require(root, "grantee");
    if (cbor.mapGet(grantee, "application") != null) return error.GrantMismatch;
    if (!std.mem.eql(u8, try requireText(grantee, "local_rp_descriptor_fingerprint"), fingerprint)) return error.GrantMismatch;
}

// ---------------------------------------------------------------------
// 4. Present
// ---------------------------------------------------------------------

pub const PresentActAsConfig = struct {
    key_material: identity.LocalRpKeyMaterial,
    grant: SignedActAsGrant,
    /// The audience this call goes to.
    audience: ApplicationRef,
    /// The digest of this request, as the audience's protocol defines it.
    request_digest: []const u8,
    /// A fresh nonce for this presentation. The audience owns replay checks.
    nonce: []const u8,
    now: i64,
};

pub const PresentedActAs = struct {
    credential: ActAsCredential,
    /// CBOR(ActAsCredential), ready to send to the audience.
    credential_cbor: []const u8,
};

/// Signs one presentation of `grant` to `audience` and returns the
/// credential to send with the call.
pub fn presentActAs(allocator: std.mem.Allocator, config: PresentActAsConfig) !PresentedActAs {
    var hash: [xcrypto.Sha256.digest_length]u8 = undefined;
    xcrypto.Sha256.hash(config.grant.grant, &hash, .{});
    const presentation = ActAsPresentation{
        .grant_hash = try allocator.dupe(u8, &hash),
        .audience = config.audience,
        .request_digest = config.request_digest,
        .presented_at = try timestamp(allocator, config.now),
        .nonce = config.nonce,
    };
    const bytes = try encodeActAsPresentation(allocator, presentation);
    const credential = ActAsCredential{
        .grant = config.grant,
        .presentation = .{ .presentation = bytes, .proof = try proveLocalRp(allocator, config.key_material, tag_presentation, bytes) },
    };
    return .{ .credential = credential, .credential_cbor = try encodeActAsCredential(allocator, credential) };
}

// ---------------------------------------------------------------------
// Unit tests (no network). Vector and fake-server tests are in
// tests/act_as.zig.
// ---------------------------------------------------------------------

test "completeActAsCallback reads the grant id and checks the nonce" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const pending = PendingActAs{ .nonce = "n0nce_-A", .user_domain = "example.test", .callback_url = "http://app.lan/cb" };

    const id = try completeActAsCallback(a, pending, "http://app.lan/cb?x=1&act_as_grant_id=grant%2D1&nonce=n0nce_-A");
    try std.testing.expectEqualStrings("grant-1", id);
    try std.testing.expectEqualStrings("g", try completeActAsCallback(a, pending, "nonce=n0nce_-A&act_as_grant_id=g"));

    try std.testing.expectError(error.NonceMismatch, completeActAsCallback(a, pending, "?act_as_grant_id=g&nonce=other"));
    try std.testing.expectError(error.NonceMismatch, completeActAsCallback(a, pending, "?act_as_grant_id=g&nonce=n0nce_-"));
    try std.testing.expectError(error.MissingNonce, completeActAsCallback(a, pending, "?act_as_grant_id=g"));
    try std.testing.expectError(error.MissingActAsGrantId, completeActAsCallback(a, pending, "?nonce=n0nce_-A"));
    try std.testing.expectError(error.MissingActAsGrantId, completeActAsCallback(a, pending, "?act_as_grant_id=&nonce=n0nce_-A"));
    try std.testing.expectError(error.DuplicateQueryParameter, completeActAsCallback(a, pending, "?act_as_grant_id=g&nonce=n0nce_-A&nonce=n0nce_-A"));
    try std.testing.expectError(error.InvalidPercentEncoding, completeActAsCallback(a, pending, "?act_as_grant_id=%zz&nonce=n0nce_-A"));
}

test "negative CBOR integers round-trip through the grant request codec" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const req = ActAsGrantRequest{
        .grantee_fingerprint = "fp",
        .scope_set = .{ .scope_set = "s", .signer_instance_id = "i", .signatures = &.{.{ .signed_by_key_id = "k", .signature = "sig" }} },
        .requested_lifetime_seconds = 60,
        .requested_renewal_window_seconds = -1,
        .callback_url = "http://cb",
        .nonce = "n",
        .requested_at = "2026-01-01T00:00:00Z",
        .expires_at = "2026-01-01T00:05:00Z",
    };
    const back = try decodeActAsGrantRequest(a, try encodeActAsGrantRequest(a, req));
    try std.testing.expectEqual(@as(?i64, 60), back.requested_lifetime_seconds);
    try std.testing.expectEqual(@as(?i64, -1), back.requested_renewal_window_seconds);
    try std.testing.expectEqualStrings("fp", back.grantee_fingerprint);
}
