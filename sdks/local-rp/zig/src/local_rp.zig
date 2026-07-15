//! Local RP protocol core: envelope sign/verify with the four mandatory
//! context strings, the callback sealed box (Wire Precision: "Callback
//! sealed box"), timestamp/expiration helpers, and nonce/state/audience/
//! issuer verification. Mirrors `crates/liblinkkeys/src/local_rp.rs` /
//! `sdks/local-rp/go/localrp.go` field-for-field; read
//! `dns-less-local-rp-design.md`'s "Wire Precision (Normative)" section
//! first — it is the source of truth these functions implement.
//!
//! This module performs no I/O: every "current time" is an explicit `now`
//! parameter, with one narrow, deliberate exception (`signingKeyValidity`)
//! that mirrors `liblinkkeys::crypto::signing_key_validity` exactly, wall
//! clock and all.

const std = @import("std");
const cbor = @import("cbor.zig");
const types = @import("types.zig");
const xcrypto = @import("crypto.zig");

pub const ctx_local_rp_descriptor = "linkkeys-local-rp-descriptor";
pub const ctx_local_rp_login_request = "linkkeys-local-rp-login-request";
pub const ctx_local_rp_callback = "linkkeys-local-rp-callback";
pub const ctx_local_rp_ticket_redemption = "linkkeys-local-rp-ticket-redemption";

/// Design doc: "±300 seconds" default bounded clock-skew tolerance.
pub const default_clock_skew_seconds: i64 = 300;

/// Signature input for every local-RP signed structure:
/// `CBOR([context, payload_bytes])` — a two-element array with the
/// domain-separation context string first and the exact payload bytes second
/// (encoded as a CBOR byte string, never re-serialized). Deliberately NOT a
/// bare `context || payload` concatenation — see the design doc's
/// "Signature input bytes".
pub fn envelopeSignatureInput(allocator: std.mem.Allocator, context: []const u8, payload_bytes: []const u8) ![]u8 {
    const items = [_]cbor.Value{ cbor.text(context), cbor.bytesVal(payload_bytes) };
    return cbor.encodeTuple(allocator, &items);
}

// ---------------------------------------------------------------------
// RFC3339 timestamps (UTC only; fractional seconds accepted but discarded —
// every check in this protocol operates at whole-second granularity).
// ---------------------------------------------------------------------

/// Days-since-epoch for a proleptic Gregorian civil date (Howard Hinnant's
/// `days_from_civil` algorithm — well-tested, handles the full i64 year
/// range this protocol's far-future fixture timestamps (e.g. 2126) need).
fn daysFromCivil(y_in: i64, m_in: u32, d_in: u32) i64 {
    const y: i64 = y_in - @as(i64, if (m_in <= 2) 1 else 0);
    const era: i64 = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe: i64 = y - era * 400;
    const mp: i64 = if (m_in > 2) @as(i64, m_in) - 3 else @as(i64, m_in) + 9;
    const doy: i64 = @divFloor(153 * mp + 2, 5) + @as(i64, d_in) - 1;
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

const CivilDate = struct { y: i64, m: u32, d: u32 };

fn civilFromDays(z_in: i64) CivilDate {
    const z = z_in + 719468;
    const era: i64 = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe: i64 = z - era * 146097;
    const yoe: i64 = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y: i64 = yoe + era * 400;
    const doy: i64 = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp: i64 = @divFloor(5 * doy + 2, 153);
    const d: i64 = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m: i64 = if (mp < 10) mp + 3 else mp - 9;
    return .{ .y = y + @as(i64, if (m <= 2) 1 else 0), .m = @intCast(m), .d = @intCast(d) };
}

/// Parses an RFC3339 timestamp (`Z` or a numeric `+HH:MM`/`-HH:MM` offset;
/// fractional seconds accepted and discarded) into Unix seconds (UTC).
pub fn parseTimestamp(s: []const u8) !i64 {
    if (s.len < 20) return error.BadTimestamp;
    const year = std.fmt.parseInt(i64, s[0..4], 10) catch return error.BadTimestamp;
    if (s[4] != '-') return error.BadTimestamp;
    const month = std.fmt.parseInt(u32, s[5..7], 10) catch return error.BadTimestamp;
    if (s[7] != '-') return error.BadTimestamp;
    const day = std.fmt.parseInt(u32, s[8..10], 10) catch return error.BadTimestamp;
    if (s[10] != 'T' and s[10] != 't') return error.BadTimestamp;
    const hour = std.fmt.parseInt(i64, s[11..13], 10) catch return error.BadTimestamp;
    if (s[13] != ':') return error.BadTimestamp;
    const minute = std.fmt.parseInt(i64, s[14..16], 10) catch return error.BadTimestamp;
    if (s[16] != ':') return error.BadTimestamp;
    const second = std.fmt.parseInt(i64, s[17..19], 10) catch return error.BadTimestamp;

    var idx: usize = 19;
    if (idx < s.len and s[idx] == '.') {
        idx += 1;
        while (idx < s.len and s[idx] >= '0' and s[idx] <= '9') idx += 1;
    }
    if (idx >= s.len) return error.BadTimestamp;

    var offset_seconds: i64 = 0;
    if (s[idx] == 'Z' or s[idx] == 'z') {
        idx += 1;
    } else if (s[idx] == '+' or s[idx] == '-') {
        const sign: i64 = if (s[idx] == '-') -1 else 1;
        idx += 1;
        if (idx + 5 > s.len) return error.BadTimestamp;
        const oh = std.fmt.parseInt(i64, s[idx .. idx + 2], 10) catch return error.BadTimestamp;
        if (s[idx + 2] != ':') return error.BadTimestamp;
        const om = std.fmt.parseInt(i64, s[idx + 3 .. idx + 5], 10) catch return error.BadTimestamp;
        offset_seconds = sign * (oh * 3600 + om * 60);
        idx += 5;
    } else {
        return error.BadTimestamp;
    }
    if (idx != s.len) return error.BadTimestamp;

    const days = daysFromCivil(year, month, day);
    const local_seconds = days * 86400 + hour * 3600 + minute * 60 + second;
    return local_seconds - offset_seconds;
}

/// Formats Unix seconds (UTC) as `YYYY-MM-DDTHH:MM:SSZ` into `buf` (must be
/// at least 20 bytes), returning the written slice.
pub fn formatTimestamp(buf: []u8, unix_seconds: i64) ![]const u8 {
    if (buf.len < 20) return error.BufferTooSmall;
    const days = @divFloor(unix_seconds, 86400);
    var remainder = unix_seconds - days * 86400;
    if (remainder < 0) remainder += 86400;
    const date = civilFromDays(days);
    // Cast the year to unsigned before formatting: Zig's `{d:0>4}` zero-pad
    // specifier prints an explicit `+` sign for a *signed* integer type
    // (e.g. "+2026"), which would silently shift every fixed-offset index
    // this parser and every other SDK's byte-exact comparisons rely on.
    // This protocol never needs a negative/BCE year.
    if (date.y < 0 or date.y > std.math.maxInt(u32)) return error.BadTimestamp;
    const year: u32 = @intCast(date.y);
    const hour: u32 = @intCast(@divFloor(remainder, 3600));
    const minute: u32 = @intCast(@divFloor(@mod(remainder, 3600), 60));
    const second: u32 = @intCast(@mod(remainder, 60));
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year, date.m, date.d, hour, minute, second,
    });
}

/// Checks an (issued_at, expires_at) pair against `now`, tolerant of
/// `skew_seconds` of clock skew in either direction. Boundaries are
/// inclusive: exactly `now - skew == expires_at` still passes, and exactly
/// one second past either boundary fails.
pub fn checkTimestamps(issued_at: []const u8, expires_at: []const u8, now: i64, skew_seconds: i64) !void {
    const issued = try parseTimestamp(issued_at);
    const expires = try parseTimestamp(expires_at);
    if (now + skew_seconds < issued) return error.NotYetValid;
    if (now - skew_seconds > expires) return error.Expired;
}

pub const ExpirationLevel = enum { ok, notice, warning, critical, expired };

pub const ExpirationStatus = struct {
    level: ExpirationLevel,
    expires_at: i64,
    now: i64,
};

const seconds_per_day: i64 = 86400;

/// Per-timestamp expiry check (design doc: "Expiration Helper"). Does NOT
/// apply clock-skew tolerance (unlike `checkTimestamps`): expiry warnings
/// are advisory, day-scale facts, not a replay/freshness security boundary.
pub fn checkExpirationsAt(expires_at: []const u8, now: i64) !ExpirationStatus {
    const expires = try parseTimestamp(expires_at);
    const remaining = expires - now;
    const level: ExpirationLevel = if (now >= expires)
        .expired
    else if (remaining <= 30 * seconds_per_day)
        .critical
    else if (remaining <= 90 * seconds_per_day)
        .warning
    else if (remaining <= 180 * seconds_per_day)
        .notice
    else
        .ok;
    return .{ .level = level, .expires_at = expires, .now = now };
}

/// Constant-time byte-slice equality (SEC fix: nonce/state are compared
/// against attacker-influenced input from the callback payload, so a
/// short-circuiting `std.mem.eql` byte-by-byte compare is a timing side
/// channel). `std.crypto.utils.timingSafeEql` only accepts a comptime-known
/// array type, not an arbitrary-length slice, so the fixed 32-byte case this
/// protocol always uses is dispatched straight to it; the length check
/// itself is not secret (an attacker already knows this protocol's nonce/
/// state are 32 bytes), and any other length falls back to a manual
/// constant-time accumulator rather than ever branching on byte content.
fn timingSafeEqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    if (a.len == 32) {
        return std.crypto.utils.timingSafeEql([32]u8, a[0..32].*, b[0..32].*);
    }
    var acc: u8 = 0;
    for (a, b) |x, y| acc |= x ^ y;
    return acc == 0;
}

pub fn verifyNonceState(expected_nonce: []const u8, expected_state: []const u8, actual_nonce: []const u8, actual_state: []const u8) !void {
    if (!timingSafeEqlBytes(expected_nonce, actual_nonce)) return error.NonceMismatch;
    if (!timingSafeEqlBytes(expected_state, actual_state)) return error.StateMismatch;
}

pub fn verifyAudience(payload_audience_fingerprint: []const u8, local_rp_fingerprint: []const u8) !void {
    if (!std.mem.eql(u8, payload_audience_fingerprint, local_rp_fingerprint)) return error.AudienceMismatch;
}

pub fn verifyIssuer(payload_user_domain: []const u8, expected_domain: []const u8) !void {
    if (!std.mem.eql(u8, payload_user_domain, expected_domain)) return error.IssuerMismatch;
}

pub fn verifyCallbackUrl(payload_callback_url: []const u8, arrived_url: []const u8) !void {
    if (!std.mem.eql(u8, payload_callback_url, arrived_url)) return error.CallbackUrlMismatch;
}

// ---------------------------------------------------------------------
// Signing-key validity (mirrors liblinkkeys::crypto::signing_key_validity /
// check_signing_key_valid exactly, including its use of the real wall clock
// rather than an explicit `now` parameter).
// ---------------------------------------------------------------------

const KeyValidity = enum { valid, revoked, expired, bad_expiry };

fn signingKeyValidity(expires_at: []const u8, revoked_at: ?[]const u8) KeyValidity {
    if (revoked_at != null) return .revoked;
    const expires = parseTimestamp(expires_at) catch return .bad_expiry;
    const now = std.time.timestamp();
    if (now > expires) return .expired;
    return .valid;
}

/// Rejects a signing key that is not usable as a signer: wrong key_usage,
/// revoked, or expired. Shared by every verify path that resolves a key by
/// id.
pub fn checkSigningKeyValid(key: types.DomainPublicKey) !void {
    if (!std.mem.eql(u8, key.key_usage, "sign")) return error.SignatureInvalid;
    switch (signingKeyValidity(key.expires_at, key.revoked_at)) {
        .valid => return,
        .revoked => return error.KeyRevoked,
        else => return error.KeyExpired,
    }
}

// ---------------------------------------------------------------------
// Descriptor
// ---------------------------------------------------------------------

/// Builds an unsigned `LocalRpDescriptor`. `fingerprint` is always derived
/// from `signing_public_key` — callers cannot set it directly, so it can
/// never drift from the key it names. Note this takes an allocator: the key
/// bytes and fingerprint must be copied into memory that outlives this call
/// (the `[32]u8` parameters are by-value stack copies; a returned slice
/// pointing at them would dangle the instant this function returns).
pub fn buildLocalRpDescriptor(
    allocator: std.mem.Allocator,
    app_name: []const u8,
    local_domain_hint: ?[]const u8,
    signing_public_key: [32]u8,
    encryption_public_key: [32]u8,
    supported_suites: []const []const u8,
    created_at: []const u8,
    expires_at: []const u8,
) !types.LocalRpDescriptor {
    const fp = xcrypto.fingerprintHex(&signing_public_key);
    return .{
        .app_name = app_name,
        .local_domain_hint = local_domain_hint,
        .signing_public_key = try allocator.dupe(u8, &signing_public_key),
        .encryption_public_key = try allocator.dupe(u8, &encryption_public_key),
        .fingerprint = try allocator.dupe(u8, &fp),
        .supported_suites = supported_suites,
        .created_at = created_at,
        .expires_at = expires_at,
    };
}

pub fn signLocalRpDescriptor(allocator: std.mem.Allocator, descriptor: types.LocalRpDescriptor, signing_seed: [32]u8) !types.SignedLocalRpDescriptor {
    const descriptor_bytes = try types.encodeLocalRpDescriptor(allocator, descriptor);
    const sig_input = try envelopeSignatureInput(allocator, ctx_local_rp_descriptor, descriptor_bytes);
    const sig = try xcrypto.signEd25519(signing_seed, sig_input);
    return .{ .descriptor = descriptor_bytes, .signature = try allocator.dupe(u8, &sig) };
}

/// Verifies a signed local RP descriptor: decode it, check its fingerprint
/// field truly is `Fingerprint(signing_public_key)`, verify the envelope
/// signature against its own embedded signing key (a local RP descriptor is
/// self-asserted identity, SSH-host style), and check `created_at`/
/// `expires_at` bounds.
pub fn verifyLocalRpDescriptor(allocator: std.mem.Allocator, signed: types.SignedLocalRpDescriptor, now: i64, skew_seconds: i64) !types.LocalRpDescriptor {
    const descriptor = try types.decodeLocalRpDescriptor(allocator, signed.descriptor);

    if (descriptor.signing_public_key.len != 32) return error.InvalidKeyLength;
    const expected_fp = xcrypto.fingerprintHex(descriptor.signing_public_key);
    if (!std.mem.eql(u8, descriptor.fingerprint, &expected_fp)) return error.FingerprintMismatch;

    const sig_input = try envelopeSignatureInput(allocator, ctx_local_rp_descriptor, signed.descriptor);
    try xcrypto.resolveAndVerify("ed25519", sig_input, signed.signature, descriptor.signing_public_key);

    try checkTimestamps(descriptor.created_at, descriptor.expires_at, now, skew_seconds);
    return descriptor;
}

// ---------------------------------------------------------------------
// Login request
// ---------------------------------------------------------------------

pub fn buildLocalRpLoginRequest(
    descriptor: types.SignedLocalRpDescriptor,
    callback_url: []const u8,
    nonce: []const u8,
    state: []const u8,
    requested_claims: []const []const u8,
    required_claims: []const []const u8,
    issued_at: []const u8,
    expires_at: []const u8,
) types.LocalRpLoginRequest {
    return .{
        .descriptor = descriptor,
        .callback_url = callback_url,
        .nonce = nonce,
        .state = state,
        .requested_claims = requested_claims,
        .required_claims = required_claims,
        .issued_at = issued_at,
        .expires_at = expires_at,
    };
}

pub fn signLocalRpLoginRequest(allocator: std.mem.Allocator, request: types.LocalRpLoginRequest, signing_seed: [32]u8) !types.SignedLocalRpLoginRequest {
    const request_bytes = try types.encodeLocalRpLoginRequest(allocator, request);
    const sig_input = try envelopeSignatureInput(allocator, ctx_local_rp_login_request, request_bytes);
    const sig = try xcrypto.signEd25519(signing_seed, sig_input);
    return .{ .request = request_bytes, .signature = try allocator.dupe(u8, &sig) };
}

/// Verifies a signed local RP login request end to end: decode it, fully
/// verify the nested descriptor (envelope signature, fingerprint binding,
/// timestamp bounds), then verify the outer envelope signature against the
/// descriptor's signing key, then check the request's own timestamp bounds.
pub fn verifyLocalRpLoginRequest(allocator: std.mem.Allocator, signed: types.SignedLocalRpLoginRequest, now: i64, skew_seconds: i64) !types.LocalRpLoginRequest {
    const request = try types.decodeLocalRpLoginRequest(allocator, signed.request);
    const descriptor = try verifyLocalRpDescriptor(allocator, request.descriptor, now, skew_seconds);

    const sig_input = try envelopeSignatureInput(allocator, ctx_local_rp_login_request, signed.request);
    try xcrypto.resolveAndVerify("ed25519", sig_input, signed.signature, descriptor.signing_public_key);

    try checkTimestamps(request.issued_at, request.expires_at, now, skew_seconds);
    return request;
}

// ---------------------------------------------------------------------
// Ticket redemption
// ---------------------------------------------------------------------

pub fn buildLocalRpTicketRedemptionRequest(claim_ticket: []const u8, fingerprint: []const u8, issued_at: []const u8) types.LocalRpTicketRedemptionRequest {
    return .{ .claim_ticket = claim_ticket, .fingerprint = fingerprint, .issued_at = issued_at };
}

pub fn signLocalRpTicketRedemptionRequest(allocator: std.mem.Allocator, request: types.LocalRpTicketRedemptionRequest, signing_seed: [32]u8) !types.SignedLocalRpTicketRedemptionRequest {
    const request_bytes = try types.encodeLocalRpTicketRedemptionRequest(allocator, request);
    const sig_input = try envelopeSignatureInput(allocator, ctx_local_rp_ticket_redemption, request_bytes);
    const sig = try xcrypto.signEd25519(signing_seed, sig_input);
    return .{ .request = request_bytes, .signature = try allocator.dupe(u8, &sig) };
}

/// Verifies a ticket-redemption request's possession proof: `signing_public_key`
/// is the key the caller resolved for `expected_fingerprint` — the signature
/// must verify against it, AND that key's own fingerprint plus the request's
/// embedded fingerprint field must both equal `expected_fingerprint`.
pub fn verifyLocalRpTicketRedemptionRequest(allocator: std.mem.Allocator, signed: types.SignedLocalRpTicketRedemptionRequest, signing_public_key: []const u8, expected_fingerprint: []const u8) !types.LocalRpTicketRedemptionRequest {
    const sig_input = try envelopeSignatureInput(allocator, ctx_local_rp_ticket_redemption, signed.request);
    try xcrypto.resolveAndVerify("ed25519", sig_input, signed.signature, signing_public_key);

    const request = try types.decodeLocalRpTicketRedemptionRequest(allocator, signed.request);

    if (signing_public_key.len != 32) return error.InvalidKeyLength;
    const key_fp = xcrypto.fingerprintHex(signing_public_key);
    if (!std.mem.eql(u8, &key_fp, expected_fingerprint) or !std.mem.eql(u8, request.fingerprint, expected_fingerprint)) {
        return error.FingerprintMismatch;
    }
    return request;
}

// ---------------------------------------------------------------------
// Callback payload (domain-signed envelope)
// ---------------------------------------------------------------------

pub fn buildLocalRpCallbackPayload(
    user_id: []const u8,
    user_domain: []const u8,
    claim_ticket: []const u8,
    audience_fingerprint: []const u8,
    callback_url: []const u8,
    nonce: []const u8,
    state: []const u8,
    issued_at: []const u8,
    expires_at: []const u8,
) types.LocalRpCallbackPayload {
    return .{
        .user_id = user_id,
        .user_domain = user_domain,
        .claim_ticket = claim_ticket,
        .audience_fingerprint = audience_fingerprint,
        .callback_url = callback_url,
        .nonce = nonce,
        .state = state,
        .issued_at = issued_at,
        .expires_at = expires_at,
    };
}

/// Signs a `LocalRpCallbackPayload` with one of the issuing domain's signing
/// keys (`key_id` identifies which one — a domain holds several signing
/// keys). This is a server-side (IDP) operation exposed here only because it
/// is a pure protocol helper; the local-RP SDK itself never calls it in
/// production — only test fixtures (fake IDPs) do.
pub fn signLocalRpCallbackPayload(allocator: std.mem.Allocator, payload: types.LocalRpCallbackPayload, key_id: []const u8, signing_seed: [32]u8) !types.SignedLocalRpCallbackPayload {
    const payload_bytes = try types.encodeLocalRpCallbackPayload(allocator, payload);
    const sig_input = try envelopeSignatureInput(allocator, ctx_local_rp_callback, payload_bytes);
    const sig = try xcrypto.signEd25519(signing_seed, sig_input);
    return .{ .payload = payload_bytes, .signing_key_id = key_id, .signature = try allocator.dupe(u8, &sig) };
}

/// Verifies a domain-signed callback payload envelope against a set of
/// domain public keys: resolve `signing_key_id`, reject a
/// revoked/expired/non-signing key, verify the envelope signature, decode,
/// then check `issued_at`/`expires_at` bounds.
pub fn verifyLocalRpCallbackPayload(allocator: std.mem.Allocator, signed: types.SignedLocalRpCallbackPayload, domain_public_keys: []const types.DomainPublicKey, now: i64, skew_seconds: i64) !types.LocalRpCallbackPayload {
    var key: ?types.DomainPublicKey = null;
    for (domain_public_keys) |k| {
        if (std.mem.eql(u8, k.key_id, signed.signing_key_id)) {
            key = k;
            break;
        }
    }
    const resolved_key = key orelse return error.KeyNotFound;
    try checkSigningKeyValid(resolved_key);

    const sig_input = try envelopeSignatureInput(allocator, ctx_local_rp_callback, signed.payload);
    try xcrypto.resolveAndVerify(resolved_key.algorithm, sig_input, signed.signature, resolved_key.public_key);

    const payload = try types.decodeLocalRpCallbackPayload(allocator, signed.payload);
    try checkTimestamps(payload.issued_at, payload.expires_at, now, skew_seconds);
    return payload;
}

/// Cross-checks the cleartext callback header's routing fields against the
/// authoritative copies inside the decrypted, domain-signature-verified
/// payload. The header is already bound as AEAD associated data (so it
/// cannot be tampered independently of the ciphertext it accompanies), but a
/// verifier must still consult the signed copies rather than trusting the
/// header alone.
pub fn checkCallbackHeaderMatchesPayload(header: types.LocalRpCallbackHeader, payload: types.LocalRpCallbackPayload) !void {
    if (!std.mem.eql(u8, header.fingerprint, payload.audience_fingerprint)) return error.HeaderPayloadMismatch;
    if (!std.mem.eql(u8, header.nonce, payload.nonce)) return error.HeaderPayloadMismatch;
    if (!std.mem.eql(u8, header.state, payload.state)) return error.HeaderPayloadMismatch;
    if (!std.mem.eql(u8, header.issued_at, payload.issued_at)) return error.HeaderPayloadMismatch;
    if (!std.mem.eql(u8, header.expires_at, payload.expires_at)) return error.HeaderPayloadMismatch;
}

// ---------------------------------------------------------------------
// Callback sealed box (Wire Precision: "Callback sealed box")
// ---------------------------------------------------------------------

/// Seals a `SignedLocalRpCallbackPayload` into a `LocalRpEncryptedCallback`
/// for `recipient_encryption_public_key`, using `suite`. This is a
/// server-side (IDP) operation exposed here as a pure protocol helper; the
/// local-RP SDK itself never calls it in production, only test fixtures.
pub fn sealLocalRpCallback(
    allocator: std.mem.Allocator,
    signed_payload: types.SignedLocalRpCallbackPayload,
    suite: xcrypto.AeadSuite,
    recipient_encryption_public_key: [32]u8,
    fingerprint: []const u8,
    nonce: []const u8,
    state: []const u8,
    issued_at: []const u8,
    expires_at: []const u8,
) !types.LocalRpEncryptedCallback {
    const ephemeral = xcrypto.generateX25519Keypair();
    var aead_nonce: [xcrypto.nonce_length]u8 = undefined;
    xcrypto.randomBytes(&aead_nonce);
    return sealLocalRpCallbackInner(allocator, signed_payload, suite, recipient_encryption_public_key, fingerprint, nonce, state, issued_at, expires_at, ephemeral.private_key, ephemeral.public_key, aead_nonce);
}

fn sealLocalRpCallbackInner(
    allocator: std.mem.Allocator,
    signed_payload: types.SignedLocalRpCallbackPayload,
    suite: xcrypto.AeadSuite,
    recipient_pub: [32]u8,
    fingerprint: []const u8,
    nonce: []const u8,
    state: []const u8,
    issued_at: []const u8,
    expires_at: []const u8,
    ephemeral_priv: [32]u8,
    ephemeral_pub: [32]u8,
    aead_nonce: [xcrypto.nonce_length]u8,
) !types.LocalRpEncryptedCallback {
    const plaintext = try types.encodeSignedLocalRpCallbackPayload(allocator, signed_payload);

    const shared_secret = try xcrypto.x25519Ecdh(ephemeral_priv, recipient_pub);

    const header = types.LocalRpCallbackHeader{
        .fingerprint = fingerprint,
        .nonce = nonce,
        .state = state,
        .suite = suite.wireId(),
        .ephemeral_public_key = &ephemeral_pub,
        .aead_nonce = &aead_nonce,
        .issued_at = issued_at,
        .expires_at = expires_at,
    };
    const header_bytes = try types.encodeLocalRpCallbackHeader(allocator, header);

    const kdf = try xcrypto.localRpCallbackKdf(allocator, suite, ephemeral_pub, recipient_pub, shared_secret);

    var aad = std.ArrayList(u8).init(allocator);
    try aad.appendSlice(kdf.context);
    try aad.appendSlice(header_bytes);

    const ciphertext = try xcrypto.aeadEncrypt(allocator, suite, kdf.key, aead_nonce, aad.items, plaintext);

    return .{ .header = header_bytes, .ciphertext = ciphertext };
}

pub const OpenedCallback = struct {
    header: types.LocalRpCallbackHeader,
    signed_payload: types.SignedLocalRpCallbackPayload,
};

/// Opens a `LocalRpEncryptedCallback` with the local RP's encryption private
/// key. `allowed_suites` is the local RP's own supported-suite list (from
/// its descriptor): a header advertising a suite NOT in that list is
/// rejected even if it is otherwise a valid registry id.
///
/// Returns the decoded header (cleartext routing metadata) and the still
/// domain-signature-unverified `SignedLocalRpCallbackPayload` — callers must
/// still call `verifyLocalRpCallbackPayload` against fetched domain keys,
/// and then `checkCallbackHeaderMatchesPayload`, before trusting the result.
pub fn openLocalRpCallback(allocator: std.mem.Allocator, encrypted: types.LocalRpEncryptedCallback, recipient_encryption_private_key: [32]u8, allowed_suites: []const xcrypto.AeadSuite) !OpenedCallback {
    const header = try types.decodeLocalRpCallbackHeader(allocator, encrypted.header);

    const suite = xcrypto.parseAeadSuite(header.suite) orelse return error.UnsupportedSuite;
    if (!xcrypto.containsSuite(allowed_suites, suite)) return error.SuiteNotAdvertised;

    if (header.ephemeral_public_key.len != 32) return error.InvalidKeyLength;
    const ephemeral_pub: [32]u8 = header.ephemeral_public_key[0..32].*;

    if (header.aead_nonce.len != xcrypto.nonce_length) return error.InvalidKeyLength;
    const aead_nonce: [xcrypto.nonce_length]u8 = header.aead_nonce[0..xcrypto.nonce_length].*;

    const recipient_pub = try xcrypto.x25519PublicFromPrivate(recipient_encryption_private_key);
    const shared_secret = try xcrypto.x25519Ecdh(recipient_encryption_private_key, ephemeral_pub);

    const kdf = try xcrypto.localRpCallbackKdf(allocator, suite, ephemeral_pub, recipient_pub, shared_secret);

    var aad = std.ArrayList(u8).init(allocator);
    try aad.appendSlice(kdf.context);
    try aad.appendSlice(encrypted.header);

    const plaintext = xcrypto.aeadDecrypt(allocator, suite, kdf.key, aead_nonce, aad.items, encrypted.ciphertext) catch return error.DecryptFailed;

    const signed_payload = try types.decodeSignedLocalRpCallbackPayload(allocator, plaintext);
    return .{ .header = header, .signed_payload = signed_payload };
}

test "verifyNonceState: equal nonce/state pass, any single differing byte fails" {
    const nonce = [_]u8{7} ** 32;
    const state = [_]u8{8} ** 32;
    try verifyNonceState(&nonce, &state, &nonce, &state);

    var bad_nonce = nonce;
    bad_nonce[31] ^= 1;
    try std.testing.expectError(error.NonceMismatch, verifyNonceState(&nonce, &state, &bad_nonce, &state));

    var bad_state = state;
    bad_state[0] ^= 1;
    try std.testing.expectError(error.StateMismatch, verifyNonceState(&nonce, &state, &nonce, &bad_state));
}

test "timingSafeEqlBytes handles non-32-byte lengths and length mismatches" {
    try std.testing.expect(timingSafeEqlBytes("abc", "abc"));
    try std.testing.expect(!timingSafeEqlBytes("abc", "abd"));
    try std.testing.expect(!timingSafeEqlBytes("abc", "abcd"));
    try std.testing.expect(timingSafeEqlBytes("", ""));
}

test "timestamp parse/format round trip" {
    const cases = [_][]const u8{
        "2035-07-02T00:00:00+00:00",
        "2026-01-01T00:10:01+00:00",
        "2126-01-01T00:00:00Z",
        "1970-01-01T00:00:00Z",
    };
    for (cases) |c| {
        const secs = try parseTimestamp(c);
        var buf: [32]u8 = undefined;
        const formatted = try formatTimestamp(&buf, secs);
        const reparsed = try parseTimestamp(formatted);
        try std.testing.expectEqual(secs, reparsed);
    }
}

test "checkTimestamps skew boundaries are exact" {
    // issued_at=2026-01-01T00:00:00Z, expires_at=2026-01-01T00:05:00Z, skew=300s
    const issued = "2026-01-01T00:00:00+00:00";
    const expires = "2026-01-01T00:05:00+00:00";
    const skew: i64 = 300;

    try checkTimestamps(issued, expires, try parseTimestamp("2026-01-01T00:10:00+00:00"), skew);
    try std.testing.expectError(error.Expired, checkTimestamps(issued, expires, try parseTimestamp("2026-01-01T00:10:01+00:00"), skew));
    try checkTimestamps(issued, expires, try parseTimestamp("2025-12-31T23:55:00+00:00"), skew);
    try std.testing.expectError(error.NotYetValid, checkTimestamps(issued, expires, try parseTimestamp("2025-12-31T23:54:59+00:00"), skew));
}

test "checkExpirationsAt thresholds inclusive at boundary" {
    const expires_at = "2035-12-30T00:00:00+00:00";
    const Case = struct { now: []const u8, level: ExpirationLevel };
    const cases = [_]Case{
        .{ .now = "2035-07-02T00:00:00+00:00", .level = .ok },
        .{ .now = "2035-07-03T00:00:00+00:00", .level = .notice },
        .{ .now = "2035-10-01T00:00:00+00:00", .level = .warning },
        .{ .now = "2035-11-30T00:00:00+00:00", .level = .critical },
        .{ .now = "2035-12-30T00:00:00+00:00", .level = .expired },
        .{ .now = "2035-12-31T00:00:00+00:00", .level = .expired },
    };
    for (cases) |c| {
        const now = try parseTimestamp(c.now);
        const status = try checkExpirationsAt(expires_at, now);
        try std.testing.expectEqual(c.level, status.level);
    }
}

test "descriptor sign/verify round trip and fingerprint binding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed = [_]u8{1} ** 32;
    const kp = try xcrypto.Ed25519.KeyPair.generateDeterministic(seed);
    const signing_pub = kp.public_key.toBytes();
    const enc_pub = [_]u8{2} ** 32;

    const now: i64 = try parseTimestamp("2026-01-01T00:00:00Z");
    var created_buf: [32]u8 = undefined;
    var expires_buf: [32]u8 = undefined;
    const created_at = try formatTimestamp(&created_buf, now);
    const expires_at = try formatTimestamp(&expires_buf, now + 3650 * seconds_per_day);

    const suites = [_][]const u8{"aes-256-gcm"};
    const descriptor = try buildLocalRpDescriptor(a, "Test App", null, signing_pub, enc_pub, &suites, created_at, expires_at);
    const signed = try signLocalRpDescriptor(a, descriptor, seed);

    const verified = try verifyLocalRpDescriptor(a, signed, now, default_clock_skew_seconds);
    try std.testing.expectEqualStrings("Test App", verified.app_name);

    // Tamper the descriptor bytes: fingerprint mismatch must be caught.
    var bad_signed = signed;
    const bad_bytes = try a.dupe(u8, signed.descriptor);
    bad_bytes[bad_bytes.len - 1] ^= 0xff;
    bad_signed.descriptor = bad_bytes;
    try std.testing.expectError(error.SignatureInvalid, verifyLocalRpDescriptor(a, bad_signed, now, default_clock_skew_seconds));
}
