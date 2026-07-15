//! TLS SPKI pin-extraction logic — the MANDATORY manual SPKI pin check
//! (design doc, "SDK endpoint discovery and pinning": "TLS to the TCP port:
//! verify the server certificate's SPKI public-key fingerprint is in the
//! `fp=` set, exactly as `crates/linkkeys/src/tcp/tls.rs` does. WebPKI
//! validity of the cert is not the anchor; the pin is.").
//!
//! ## TLS evaluation outcome (see README.md for the full writeup)
//!
//! Zig 0.14.1's `std.crypto.tls.Client`:
//!
//!   (a) CAN connect with certificate verification disabled or relaxed:
//!       `Options.ca = .self_signed` accepts any self-signed certificate,
//!       and `Options.host = .no_verification` skips hostname checking.
//!       It also correctly supports Ed25519 leaf certificates — both the
//!       TLS 1.3 handshake signature scheme (`tls.SignatureScheme.ed25519
//!       = 0x0807`, `SchemeEddsa`) and the X.509 signature-algorithm
//!       verification path (`Certificate.zig`'s `verifyEd25519`) are
//!       implemented.
//!
//!   (b) CANNOT expose the peer certificate (or its SubjectPublicKeyInfo)
//!       after the handshake. `Client.init()` parses and verifies the
//!       leaf certificate transiently during the handshake and discards it;
//!       nothing on the `Client` struct retains it, and there is no
//!       verification-callback hook (unlike, say, a `rustls::ClientConfig`
//!       or a Go `tls.Config.VerifyPeerCertificate`) to intercept it before
//!       it's dropped.
//!
//! Because (b) is missing, this SDK CANNOT implement the MANDATORY manual
//! SPKI pin check on top of `std.crypto.tls.Client` alone — doing pinned
//! TLS would require either forking/vendoring the certificate-handling
//! portion of the stdlib TLS client, or writing a TLS client from scratch.
//! Neither is in scope here. Consistent with this repo's error-handling
//! philosophy (fail closed at a security boundary rather than silently
//! degrade): `rpc.defaultSecureDial` always returns
//! `error.PinnedTlsUnavailable` rather than connecting unpinned. Flow tests
//! exercise the full CSIL-RPC + protocol verification chain over a fake
//! plaintext transport injected at the `Transport` seam (this mirrors the
//! design doc's sanctioned Dart-toolchain-style fallback). What would
//! unblock a real implementation: either (1) a fork of
//! `std.crypto.tls.Client` that exposes the parsed leaf certificate (or
//! calls out to a verification callback before discarding it), or (2) a
//! separate, from-scratch or vendored TLS implementation with that hook.
//!
//! This module supplies the one piece that IS fully implementable and
//! tested today: given a certificate's DER-encoded SubjectPublicKeyInfo (or
//! a full certificate DER, in which the fixed-prefix SPKI substring is
//! located), extract the raw 32-byte Ed25519 public key and compute its
//! fingerprint — ready to slot into a real pinned-TLS implementation's
//! verification callback once one exists.

const std = @import("std");
const xcrypto = @import("crypto.zig");

/// RFC 8410's fixed 12-byte DER prefix for an Ed25519 SubjectPublicKeyInfo:
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { 0x00, <32 raw
/// bytes> } }`. Constant because an Ed25519 SPKI has no algorithm
/// parameters, so its ASN.1 framing never varies in length.
pub const ed25519_spki_prefix = [_]u8{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
pub const ed25519_spki_der_len = ed25519_spki_prefix.len + 32;

/// Extracts the raw 32-byte Ed25519 public key from a DER-encoded
/// SubjectPublicKeyInfo of exactly `ed25519_spki_der_len` bytes.
pub fn extractEd25519PublicKeyFromSpkiDer(spki_der: []const u8) ![32]u8 {
    if (spki_der.len != ed25519_spki_der_len) return error.NotAnEd25519Spki;
    if (!std.mem.eql(u8, spki_der[0..ed25519_spki_prefix.len], &ed25519_spki_prefix)) return error.NotAnEd25519Spki;
    return spki_der[ed25519_spki_prefix.len..][0..32].*;
}

/// Locates and extracts an Ed25519 SubjectPublicKeyInfo from a full X.509
/// certificate's DER encoding, by searching for the fixed prefix. This is a
/// pragmatic substring search rather than a full ASN.1 parse (this SDK does
/// not otherwise need a general X.509 parser); it is safe because the
/// 12-byte Ed25519 SPKI prefix is fixed and distinctive, and a certificate
/// legitimately contains at most one SPKI field.
pub fn extractEd25519PublicKeyFromCertificateDer(cert_der: []const u8) ![32]u8 {
    const idx = std.mem.indexOf(u8, cert_der, &ed25519_spki_prefix) orelse return error.NotAnEd25519Spki;
    if (idx + ed25519_spki_der_len > cert_der.len) return error.NotAnEd25519Spki;
    return extractEd25519PublicKeyFromSpkiDer(cert_der[idx .. idx + ed25519_spki_der_len]);
}

/// Verifies that a certificate's (or SPKI's) Ed25519 public key fingerprint
/// is a member of `pinned_fingerprints_hex`. This is what a real pinned-TLS
/// verification callback would call once std.crypto.tls.Client (or a
/// replacement) exposes the peer certificate.
pub fn verifyPin(public_key: [32]u8, pinned_fingerprints_hex: []const []const u8) bool {
    const fp = xcrypto.fingerprintHex(&public_key);
    for (pinned_fingerprints_hex) |pinned| {
        if (std.ascii.eqlIgnoreCase(&fp, pinned)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------
// Fixture: a REAL openssl-CLI-minted Ed25519 self-signed certificate.
//
// Generated with:
//   openssl req -x509 -newkey ed25519 -keyout key.pem -out cert.pem \
//     -days 3650 -nodes -subj "/CN=test.local"
//   openssl x509 -in cert.pem -outform DER -out cert.der
//   openssl pkey -pubin -in <(openssl x509 -in cert.pem -pubkey -noout) \
//     -outform DER   # -> the 44-byte SPKI fixture below
// ---------------------------------------------------------------------

const fixture_cert_der_hex = "3082013e3081f1a003020102021414bb343f07d7ac09f1c3f00b197625d8fe17fd44300506032b657030153113301106035504030c0a746573742e6c6f63616c301e170d3236303731333037343833355a170d3336303731303037343833355a30153113301106035504030c0a746573742e6c6f63616c302a300506032b657003210076126b9aec543d3bfadb2d8168697df0d28bb7e902e9827c6814dac631016cd2a3533051301d0603551d0e04160414d9c5326e8f05773636ecb3212e2f5b1401881118301f0603551d23041830168014d9c5326e8f05773636ecb3212e2f5b1401881118300f0603551d130101ff040530030101ff300506032b65700341009e6c7d9f2a28525cba3ce88e8fee3e3d25fc520051497c241ee3940588ce418d7ae5d6e221de314bfe8c1e531104d1a4cbd7b77b4c76d8d8f1e4a8d4e4bd3d01";

const fixture_spki_der_hex = "302a300506032b657003210076126b9aec543d3bfadb2d8168697df0d28bb7e902e9827c6814dac631016cd2";
const fixture_raw_pubkey_hex = "76126b9aec543d3bfadb2d8168697df0d28bb7e902e9827c6814dac631016cd2";

fn hexDecodeComptimeLen(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "extractEd25519PublicKeyFromSpkiDer matches an openssl-minted fixture" {
    const spki = hexDecodeComptimeLen(fixture_spki_der_hex);
    const expected_pub = hexDecodeComptimeLen(fixture_raw_pubkey_hex);

    const extracted = try extractEd25519PublicKeyFromSpkiDer(&spki);
    try std.testing.expectEqualSlices(u8, &expected_pub, &extracted);
}

test "extractEd25519PublicKeyFromCertificateDer locates the SPKI inside a full cert" {
    const cert_der = hexDecodeComptimeLen(fixture_cert_der_hex);
    const expected_pub = hexDecodeComptimeLen(fixture_raw_pubkey_hex);
    const extracted = try extractEd25519PublicKeyFromCertificateDer(&cert_der);
    try std.testing.expectEqualSlices(u8, &expected_pub, &extracted);
}

test "verifyPin: fingerprint of the fixture key matches directly-computed fingerprint" {
    const pub_key = hexDecodeComptimeLen(fixture_raw_pubkey_hex);
    const fp = xcrypto.fingerprintHex(&pub_key);
    const pinned = [_][]const u8{&fp};
    try std.testing.expect(verifyPin(pub_key, &pinned));

    const wrong = [_][]const u8{"0000000000000000000000000000000000000000000000000000000000000000"};
    try std.testing.expect(!verifyPin(pub_key, &wrong));
}

test "extractEd25519PublicKeyFromSpkiDer rejects non-Ed25519 / malformed prefixes" {
    var bad = hexDecodeComptimeLen(fixture_spki_der_hex);
    bad[0] ^= 0xff;
    try std.testing.expectError(error.NotAnEd25519Spki, extractEd25519PublicKeyFromSpkiDer(&bad));

    try std.testing.expectError(error.NotAnEd25519Spki, extractEd25519PublicKeyFromSpkiDer("too short"));
}
