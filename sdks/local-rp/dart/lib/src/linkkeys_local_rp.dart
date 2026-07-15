// Facade for the DNS-less local RP identity mode (`dns-less-local-rp-design.md`
// at the repo root -- read it first; this SDK implements its "SDK API
// Shape" section verbatim, Dart-idiomatically adapted).
//
// This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
// self-hosted service with no public DNS) use LinkKeys for login without
// running its own DNS-pinned relying party. The app's identity is the
// fingerprint of a locally-generated signing key (SSH-host-key style), not
// a domain.
//
// ## Quickstart
//
// ```dart
// // Once, at install/setup time -- persist the returned bytes with
// // ordinary application-secret care.
// final identity = await generateLocalRpIdentity(GenerateLocalRpIdentityConfig(
//     appName: 'My LAN Jukebox', now: DateTime.now().toUtc()));
// final storedBytes = localRpIdentityToBytes(identity);
//
// // Later, per login attempt:
// final reloaded = localRpIdentityFromBytes(storedBytes);
// final begun = await beginLocalLogin(BeginLocalLoginConfig(
//     keyMaterial: reloaded,
//     callbackUrl: 'http://jukebox.lan:8080/auth/callback',
//     userDomain: 'example.com',
//     now: DateTime.now().toUtc()));
// // App: persist begun.pending (e.g. in a server-side session), then
// // redirect the browser to begun.redirect.redirectUrl.
//
// // On callback (app's HTTP handler received `arrivedUrl` with an
// // `encrypted_token=` query parameter):
// final verified = await completeLocalLogin(CompleteLocalLoginConfig(
//     keyMaterial: reloaded,
//     pending: begun.pending,
//     encryptedToken: encryptedToken,
//     arrivedUrl: arrivedUrl,
//     now: DateTime.now().toUtc()));
// // `verified` carries user id/domain, claims, domain keys used, the local
// // RP fingerprint, and expirations -- session creation, local user
// // records, and authorization are all the app's own responsibility.
// ```
//
// ## Storage and single-use responsibilities this SDK assigns to the app
//
//   * **Key material**: persist the bytes from [localRpIdentityToBytes]
//     with ordinary application-secret care.
//   * **`PendingLogin`**: persist it between `beginLocalLogin` and
//     `completeLocalLogin`, and discard it after one completion attempt.
//     This SDK owns no storage and cannot enforce single-use itself.
//   * **Sessions, local user records, authorization**: entirely the app's.
//     This SDK returns verified protocol facts; it never creates a session
//     or writes to an app database.
//
// ## Security notes
//
//   * Revoking this local RP identity at the IDP kills future logins AND
//     any outstanding claim tickets immediately, but does NOT reach into
//     sessions the app already minted from a prior successful login.
//   * Key rotation is not supported as a continuity operation: generating a
//     new identity means a new fingerprint and re-approval at every
//     LinkKeys domain.
//   * Domain keys and revocations fetched over the network are only ever
//     trusted after DNS `fp=` pinning -- the SDK never trusts unpinned key
//     material.
//   * The default DNS resolver is a minimal hand-rolled UDP TXT client
//     reading `/etc/resolv.conf`; LAN resolver spoofing is an accepted,
//     documented tradeoff for this mode. Inject a hardened `DnsResolver` if
//     your deployment needs more.
library;

import 'identity.dart';
import 'local_rp.dart';
import 'wire/codec.dart';

export 'begin.dart';
export 'claims.dart'
    show
        ClaimSpec,
        ClaimSigner,
        DomainKeySet,
        signClaim,
        verifyClaim,
        verifyClaimSignatures,
        maxClaimSignerDomains;
export 'complete.dart' hide maxClaimSignerDomains, completeLocalLoginForTesting;
export 'crypto/aead_suite.dart';
export 'dns/dns.dart'
    show
        LinkKeysRecord,
        LinkKeysApis,
        defaultTcpPort,
        linkkeysDnsName,
        linkkeysApisDnsName,
        parseLinkKeysTxt,
        parseLinkKeysApisTxt,
        isValidFingerprint;
export 'dns/dns_resolver.dart';
export 'dns/system_dns_resolver.dart';
export 'encoding.dart';
export 'errors.dart';
export 'identity.dart';
export 'local_rp.dart' show ExpirationLevel, ExpirationStatus, LocalRp;
export 'revocation.dart';
export 'rpc/address_policy.dart';
// `fetchDomainKeys`/`redeemClaimTicket` are deliberately NOT re-exported
// here, even though they're the lowest-level pinned-RPC primitives
// `completeLocalLogin` itself uses. Both accept an optional `RpcCaller`
// override (see `rpc/rpc_client.dart`'s docs) that exists ONLY as an
// internal test seam -- `dart:io`'s TLS stack can't negotiate this
// protocol's Ed25519 server certificates, so this package's own flow tests
// dial through an override that skips the TLS handshake. That override
// bypasses certificate pinning entirely; nothing forces an external caller
// to only ever pass a safe one. No test or documented usage in this
// package calls these two functions by name (tests reach them via
// `import 'package:linkkeys_local_rp/src/rpc/rpc_client.dart'`, which is
// unaffected by this barrel), so keeping the pin-bypassing parameter out of
// the public, barrel-exported API surface is a cheap, non-breaking
// tightening: no legitimate caller loses anything, since `discoverDomainEndpoint`
// is still exported for apps that want to build their own pinned transport.
export 'rpc/rpc_client.dart' show DomainEndpoint, discoverDomainEndpoint;
export 'rpc/std_transport.dart';
export 'rpc/transport.dart';
export 'wire/types.dart';

/// `check_expirations(identity, now) -> ExpirationStatus` (design doc, "SDK
/// API Shape" / "Expiration Helper"). Thin wrapper over
/// `LocalRp.checkExpirations`, taking the identity's descriptor
/// `expires_at` directly. The SDK reports facts; the app decides whether to
/// warn admins, warn users, block login, renew, or ignore.
ExpirationStatus checkExpirations(LocalRpKeyMaterial identity, DateTime now) {
  final descriptor =
      Codec.decodeLocalRpDescriptor(identity.descriptor.descriptor);
  return LocalRp.checkExpirations(descriptor.expiresAt, now);
}
