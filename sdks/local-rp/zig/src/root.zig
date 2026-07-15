//! # linkkeys_local_rp
//!
//! Zig SDK for LinkKeys' DNS-less local RP identity mode
//! (`dns-less-local-rp-design.md` at the repo root — read it first; this
//! module implements its "SDK API Shape" section verbatim, Zig-idiomatically
//! adapted: big-config structs, explicit allocators, error unions).
//!
//! This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
//! self-hosted service with no public DNS) use LinkKeys for login without
//! running its own DNS-pinned relying party. The app's identity is the
//! fingerprint of a locally-generated signing key (SSH-host-key style), not
//! a domain.
//!
//! ## Quickstart
//!
//! ```zig
//! const lrp = @import("linkkeys_local_rp");
//!
//! // Once, at install/setup time — persist the returned bytes with ordinary
//! // application-secret care (see `identity.zig` module docs).
//! const identity = try lrp.generateLocalRpIdentity(allocator, .{
//!     .app_name = "My LAN Jukebox",
//!     .now = std.time.timestamp(),
//! });
//! const stored_bytes = try lrp.localRpIdentityToBytes(allocator, identity);
//!
//! // Later, per login attempt:
//! const identity2 = try lrp.localRpIdentityFromBytes(allocator, stored_bytes);
//! const result = try lrp.beginLocalLogin(allocator, .{
//!     .key_material = identity2,
//!     .callback_url = "http://jukebox.lan:8080/auth/callback",
//!     .user_domain = "example.com",
//!     .now = std.time.timestamp(),
//! });
//! // App: persist `result.pending` (e.g. in a server-side session), then
//! // redirect the browser to `result.redirect.redirect_url`.
//!
//! // On callback (app's HTTP handler received `arrived_url` with an
//! // `encrypted_token=` query parameter whose value is `encrypted_token`):
//! const verified = try lrp.completeLocalLogin(allocator, .{
//!     .key_material = identity2,
//!     .pending = result.pending,
//!     .encrypted_token = encrypted_token,
//!     .arrived_url = arrived_url,
//!     .now = std.time.timestamp(),
//!     .transport = lrp.defaultTransport(),
//!     .dns = my_dns_resolver, // see README: pinned TLS is not implemented
//! });
//! // `verified` carries user id/domain, claims, domain keys used, the local
//! // RP fingerprint, and expirations — session creation, local user
//! // records, and authorization are all the app's own responsibility.
//! ```
//!
//! ## Storage and single-use responsibilities this SDK assigns to the app
//!
//! - **Key material**: persist the bytes from `localRpIdentityToBytes` with
//!   ordinary application-secret care (same tier as a database credential
//!   or API key) — see `identity.zig` module docs.
//! - **`PendingLogin`**: persist it between `beginLocalLogin` and
//!   `completeLocalLogin`, and discard it after one completion attempt.
//!   This module owns no storage and cannot enforce single-use itself.
//! - **Sessions, local user records, authorization**: entirely the app's.
//!   This module returns verified protocol facts; it never creates a
//!   session or writes to an app database (design doc: "SDKs must not own
//!   application storage, sessions, database writes, or local user
//!   authorization").
//!
//! ## Security notes — READ ME: pinned TLS is not implemented
//!
//! `rpc.defaultSecureDial` always fails with `error.PinnedTlsUnavailable`.
//! `std.crypto.tls.Client` (Zig 0.14.1) cannot expose the peer certificate
//! after a handshake, so this SDK cannot perform the MANDATORY manual SPKI
//! pin check the design doc requires for `fetchDomainKeys`/
//! `redeemClaimTicket`. See `tls_pin.zig` and `rpc.zig`'s module docs, and
//! this SDK's README, for the full evaluation and what would unblock a real
//! implementation. Until a real pinned-TLS `SecureDial` is supplied (via
//! `CompleteLocalLoginConfig.secure_dial`), `completeLocalLogin` cannot
//! reach a real network peer — this is a deliberate fail-closed default,
//! not an oversight.
//!
//! - Revoking this local RP identity at the IDP kills future logins AND any
//!   outstanding claim tickets immediately (redemption re-checks approval
//!   status every time) — but it does **not** reach into sessions the app
//!   already minted from a prior successful login. Session lifecycle is the
//!   app's to manage.
//! - Key rotation is not supported as a continuity operation: generating a
//!   new identity means a new fingerprint and re-approval at every LinkKeys
//!   domain. There is no "same app, new key" story in this protocol
//!   version.
//! - Domain keys and revocations fetched over the network are only ever
//!   trusted after DNS `fp=` pinning (`dns.trustKeys`) — an
//!   unpinned/unauthenticated key can never reach the verification chain.
//! - The default DNS resolver is the OS-configured system resolver; LAN
//!   resolver spoofing is an accepted, documented tradeoff for this mode
//!   (matching the design doc's "Decided" section). Inject a hardened
//!   `DnsResolver` if your deployment needs more.

const std = @import("std");

pub const cbor = @import("cbor.zig");
pub const types = @import("types.zig");
pub const crypto = @import("crypto.zig");
pub const local_rp = @import("local_rp.zig");
pub const claims = @import("claims.zig");
pub const revocation = @import("revocation.zig");
pub const dns = @import("dns.zig");
pub const encoding = @import("encoding.zig");
pub const identity = @import("identity.zig");
pub const begin = @import("begin.zig");
pub const complete = @import("complete.zig");
pub const rpc = @import("rpc.zig");
pub const transport = @import("transport.zig");
pub const tls_pin = @import("tls_pin.zig");

// ---------------------------------------------------------------------
// Flat re-exports of the "SDK API Shape" surface.
// ---------------------------------------------------------------------

pub const generateLocalRpIdentity = identity.generateLocalRpIdentity;
pub const GenerateLocalRpIdentityConfig = identity.GenerateLocalRpIdentityConfig;
pub const LocalRpKeyMaterial = identity.LocalRpKeyMaterial;

pub const localRpIdentityToBytes = identity.localRpIdentityToBytes;
pub const localRpIdentityFromBytes = identity.localRpIdentityFromBytes;
pub const signingKeyToBytes = identity.signingKeyToBytes;
pub const signingKeyFromBytes = identity.signingKeyFromBytes;
pub const encryptionKeyToBytes = identity.encryptionKeyToBytes;
pub const encryptionKeyFromBytes = identity.encryptionKeyFromBytes;
pub const fingerprintToString = identity.fingerprintToString;
pub const fingerprintFromString = identity.fingerprintFromString;

pub const beginLocalLogin = begin.beginLocalLogin;
pub const BeginLocalLoginConfig = begin.BeginLocalLoginConfig;
pub const LocalLoginRedirect = begin.LocalLoginRedirect;
pub const PendingLogin = begin.PendingLogin;

pub const completeLocalLogin = complete.completeLocalLogin;
pub const CompleteLocalLoginConfig = complete.CompleteLocalLoginConfig;
pub const VerifiedLocalLogin = complete.VerifiedLocalLogin;

pub const checkExpirations = identity.checkExpirations;
pub const ExpirationStatus = local_rp.ExpirationStatus;
pub const ExpirationLevel = local_rp.ExpirationLevel;

pub const defaultTransport = transport.defaultTransport;
pub const Transport = transport.Transport;
pub const StdTransport = transport.StdTransport;
pub const AddressPolicy = transport.AddressPolicy;

pub const DnsResolver = dns.DnsResolver;
pub const SystemDnsResolver = dns.SystemDnsResolver;

test {
    // Pull every module's tests into `zig build test`'s in-source test run.
    std.testing.refAllDecls(@This());
}
