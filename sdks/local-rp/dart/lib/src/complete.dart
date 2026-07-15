// `completeLocalLogin` (design doc: "SDK API Shape", "Flow" steps 12-13).
//
// This is the SDK's full verification chain, run in the exact order the
// pure [LocalRp] helpers require:
//
//   1. decode the callback ciphertext from its URL-param encoding
//   2. open it (decrypt) -- only with a suite this identity's own
//      descriptor advertises
//   3. fetch the pending domain's public keys + revocations,
//      DNS-`fp=`-pinned, over TCP CSIL-RPC
//   4. verify the domain-signed envelope (key lookup, revocation/expiry,
//      signature, payload timestamp bounds) -- only now is anything inside
//      the payload trusted
//   5. cross-check the cleartext header's routing fields against the
//      now-verified payload
//   6. audience / issuer / callback-URL / nonce-state checks
//   7. redeem the claim ticket over TCP CSIL-RPC (signed with the local
//      RP's own key -- the possession proof), then assert the
//      (unauthenticated) redemption response's user_id/user_domain match
//      the already-verified payload's -- fatal on mismatch
//   8. verify every returned claim's signatures against ITS signer domain's
//      keys (fetched the same pinned way), which also checks the claim's
//      own revocation/expiry, AND assert each claim's user_id matches the
//      verified payload's (fatal on mismatch), then enforce that every
//      `requiredClaims` entry from the pending login is covered by a claim
//      that passed all of the above (fatal if missing/insufficient)
library;

import 'begin.dart';
import 'claims.dart' as claims;
import 'crypto/aead_suite.dart';
import 'dns/dns_resolver.dart';
import 'dns/system_dns_resolver.dart';
import 'encoding.dart';
import 'errors.dart';
import 'identity.dart';
import 'local_rp.dart';
import 'rfc3339.dart';
import 'rpc/rpc_client.dart' as rpc;
import 'rpc/std_transport.dart';
import 'rpc/transport.dart';
import 'wire/codec.dart';
import 'wire/types.dart';

/// Bound on the number of distinct claim-signer domains
/// [completeLocalLogin] will fetch keys for per completion. The redemption
/// response's claim signatures name their signing domains as plain,
/// not-yet-verified strings -- a malicious/compromised home IDP could
/// otherwise list an unbounded number of distinct "signer domains" purely
/// to make this SDK perform many outbound DNS/TCP calls to attacker-chosen
/// targets before any signature is actually checked (an SSRF/DoS
/// amplification vector against the app's own process).
const int maxClaimSignerDomains = claims.maxClaimSignerDomains;

Transport? _defaultTransportInstance;
Transport defaultTransport() => _defaultTransportInstance ??= StdTransport();

DnsResolver? _defaultDnsResolverInstance;
DnsResolver defaultDnsResolver() =>
    _defaultDnsResolverInstance ??= SystemDnsResolver();

/// Input to [completeLocalLogin]. Every field is load-bearing.
class CompleteLocalLoginConfig {
  /// The same identity `beginLocalLogin` used.
  final LocalRpKeyMaterial keyMaterial;

  /// The pending-login state `beginLocalLogin` returned, exactly as the app
  /// persisted it.
  final PendingLogin pending;

  /// The raw callback data -- the `encrypted_token` query-parameter value.
  final String encryptedToken;

  /// The URL the callback actually arrived at (the app's own HTTP handler's
  /// request URL).
  final String arrivedUrl;

  final DateTime now;

  /// Clock-skew tolerance for timestamp checks. Defaults to
  /// [LocalRp.defaultClockSkewSeconds] when `null`.
  final int? clockSkewSeconds;

  /// The TCP dial seam. Defaults to [defaultTransport].
  final Transport? transport;

  /// The DNS TXT lookup seam. Defaults to [defaultDnsResolver].
  final DnsResolver? dns;

  const CompleteLocalLoginConfig({
    required this.keyMaterial,
    required this.pending,
    required this.encryptedToken,
    required this.arrivedUrl,
    required this.now,
    this.clockSkewSeconds,
    this.transport,
    this.dns,
  });
}

/// What `completeLocalLogin` returns to app code.
class VerifiedLocalLogin {
  final String userId;
  final String userDomain;
  final List<Claim> claims;
  final List<DomainPublicKey> domainPublicKeys;
  final String localRpFingerprint;
  final DateTime issuedAt;
  final DateTime expiresAt;
  final DateTime ticketExpiresAt;

  const VerifiedLocalLogin({
    required this.userId,
    required this.userDomain,
    required this.claims,
    required this.domainPublicKeys,
    required this.localRpFingerprint,
    required this.issuedAt,
    required this.expiresAt,
    required this.ticketExpiresAt,
  });
}

/// Undo the exact `?`/`&` + `encrypted_token=` suffix construction the IDP
/// uses to deliver the callback, so the recovered value can be compared
/// against the signed payload's `callback_url`. If the arrived URL doesn't
/// end with that exact suffix, returns it unchanged -- the subsequent
/// [LocalRp.verifyCallbackUrl] equality check then correctly fails closed
/// rather than this function guessing.
String stripEncryptedTokenParam(String arrivedUrl) {
  for (final sep in ['?', '&']) {
    final marker = '${sep}encrypted_token=';
    final idx = arrivedUrl.lastIndexOf(marker);
    if (idx >= 0) {
      return arrivedUrl.substring(0, idx);
    }
  }
  return arrivedUrl;
}

/// `complete_local_login(config) -> VerifiedLocalLogin` (design doc, "SDK
/// API Shape"). Always uses the real TLS-pinned RPC transport
/// (`rpc.RpcCaller`'s default) -- production code path, full stop.
Future<VerifiedLocalLogin> completeLocalLogin(
        CompleteLocalLoginConfig config) =>
    _completeLocalLoginImpl(config);

/// **Test-only.** Identical to [completeLocalLogin] except it accepts an
/// [rpc.RpcCaller] override for the TCP CSIL-RPC calls. Exists solely
/// because `dart:io`'s TLS stack cannot serve/negotiate the Ed25519
/// certificates this protocol's pinning requires (see
/// `rpc/rpc_client.dart`'s `RpcCaller` docs and the package README's
/// "Known limitations" section) -- so an in-process flow test cannot go
/// through real TLS the way the Rust/Go/Java/TypeScript reference SDKs'
/// flow tests do. Every other step of [completeLocalLogin]'s verification
/// chain runs unchanged.
Future<VerifiedLocalLogin> completeLocalLoginForTesting(
        CompleteLocalLoginConfig config,
        {required rpc.RpcCaller caller}) =>
    _completeLocalLoginImpl(config, caller: caller);

Future<VerifiedLocalLogin> _completeLocalLoginImpl(
    CompleteLocalLoginConfig config,
    {rpc.RpcCaller? caller}) async {
  final skew = config.clockSkewSeconds ?? LocalRp.defaultClockSkewSeconds;
  final transport = config.transport ?? defaultTransport();
  final dns = config.dns ?? defaultDnsResolver();

  // 1. Decode the callback's URL-param encoding.
  final encrypted = localRpEncryptedCallbackFromUrlParam(config.encryptedToken);

  // 2. Open it, restricted to suites THIS identity's own descriptor
  // advertises.
  final ownDescriptor =
      Codec.decodeLocalRpDescriptor(config.keyMaterial.descriptor.descriptor);
  final allowedSuites = <AeadSuite>[
    for (final s in ownDescriptor.supportedSuites)
      if (AeadSuite.parse(s) != null) AeadSuite.parse(s)!,
  ];
  final opened = await LocalRp.openLocalRpCallback(
      encrypted, config.keyMaterial.encryptionPrivateKey, allowedSuites);

  // 3. Fetch the PENDING state's domain's keys + revocations, DNS-pinned,
  // over TCP CSIL-RPC.
  final userDomainKeys = await rpc.fetchDomainKeys(
      transport, dns, config.pending.userDomain,
      caller: caller);

  // 4. Verify the domain-signed envelope against those keys. Nothing inside
  // `payload` is trusted before this succeeds.
  final payload = await LocalRp.verifyLocalRpCallbackPayload(
      opened.signedPayload, userDomainKeys, config.now, skew);

  // 5. Cross-check the cleartext header's routing twins against the
  // now-verified payload.
  LocalRp.checkCallbackHeaderMatchesPayload(opened.header, payload);

  // 6a. Audience: the callback names THIS local RP.
  LocalRp.verifyAudience(
      payload.audienceFingerprint, config.keyMaterial.fingerprint);

  // 6b. Issuer binding: the payload's user_domain must be the domain the
  // login was BEGUN with.
  LocalRp.verifyIssuer(payload.userDomain, config.pending.userDomain);

  // 6c. Callback URL binding against the URL the callback actually arrived
  // at.
  final arrivedBaseUrl = stripEncryptedTokenParam(config.arrivedUrl);
  LocalRp.verifyCallbackUrl(payload.callbackUrl, arrivedBaseUrl);

  // 6d. Nonce/state equality against the pending state.
  LocalRp.verifyNonceState(
      config.pending.nonce, config.pending.state, payload.nonce, payload.state);

  // 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the local
  // RP's own key.
  final redemptionRequest = LocalRp.buildLocalRpTicketRedemptionRequest(
      payload.claimTicket,
      config.keyMaterial.fingerprint,
      Rfc3339.format(config.now));
  final signedRedemption = await LocalRp.signLocalRpTicketRedemptionRequest(
      redemptionRequest, config.keyMaterial.signingPrivateKey);
  final redemption = await rpc.redeemClaimTicket(
      transport, dns, config.pending.userDomain, signedRedemption,
      caller: caller);

  // 7a. Redemption identity binding: the redemption response's userId and
  // userDomain must match the domain-signature-VERIFIED callback payload's
  // -- never merely trusted as-is. Everything up to this point in step 7 is
  // an unauthenticated server response; without this check a
  // compromised/malicious IDP (or a stolen/substituted ticket) could answer
  // a redemption for a different user than the one who actually completed
  // the signed callback, and that identity would otherwise flow straight
  // into VerifiedLocalLogin. Fatal, never a success return.
  if (redemption.userId != payload.userId ||
      redemption.userDomain != payload.userDomain) {
    throw LocalRpError(LocalRpErrorKind.redemptionIdentityMismatch, null);
  }

  // 8. Verify every returned claim's signatures against ITS signer domain's
  // keys, fetched the same pinned way. Reuse the home domain's
  // already-fetched keys; fetch any additional signer domains on demand,
  // capped at maxClaimSignerDomains. Keyed on the VERIFIED payload's
  // userDomain (not redemption.userDomain, even though the two are now
  // known to agree) -- the payload is the source of truth.
  final domainKeySets = <claims.DomainKeySet>[
    claims.DomainKeySet(payload.userDomain, userDomainKeys),
  ];
  for (final claim in redemption.claims) {
    for (final sig in claim.signatures) {
      final known = domainKeySets.any((s) => s.domain == sig.domain);
      if (!known) {
        if (domainKeySets.length >= maxClaimSignerDomains) {
          throw SdkException(
            SdkExceptionKind.invalidInput,
            'claim set names more than $maxClaimSignerDomains distinct signer domains; refusing to fetch further keys',
          );
        }
        final keys = await rpc.fetchDomainKeys(transport, dns, sig.domain,
            caller: caller);
        domainKeySets.add(claims.DomainKeySet(sig.domain, keys));
      }
    }
  }

  // verifiedClaimTypes tracks the claim types that passed EVERY check below
  // (subject binding, signature quorum, revocation, expiry) so
  // requiredClaims enforcement (8b below) can't be satisfied by a claim
  // that merely arrived in the response but never actually verified.
  final verifiedClaimTypes = <String>{};
  for (final claim in redemption.claims) {
    // Subject binding: a claim's userId must match the
    // signature-verified payload's userId -- a claim about a different
    // user must never be attributed to this login, regardless of whether
    // its own signature checks out. Checked BEFORE signature verification,
    // and fatal.
    if (claim.userId != payload.userId) {
      throw ClaimError(ClaimErrorKind.userIdMismatch, claim.claimId);
    }
    await claims.verifyClaim(claim, payload.userDomain, domainKeySets);
    verifiedClaimTypes.add(claim.claimType);
  }

  // 8b. requiredClaims enforcement: every claim type the login demanded
  // (persisted on PendingLogin at beginLocalLogin time) must appear among
  // the claims that passed full verification above. An empty or
  // insufficient claim set is fatal -- requiredClaims exists precisely so
  // the app can rely on these being present in a successful return.
  for (final required in config.pending.requiredClaims) {
    if (!verifiedClaimTypes.contains(required)) {
      throw ClaimError(ClaimErrorKind.requiredClaimMissing, required);
    }
  }

  return VerifiedLocalLogin(
    // Sourced from the VERIFIED, SIGNED payload -- not the redemption
    // response -- even though the two are now known to agree (checked
    // above). The payload is the thing that was actually cryptographically
    // attested by the domain; the redemption response is merely
    // corroborating data fetched over a channel that is pinned but
    // otherwise unsigned.
    userId: payload.userId,
    userDomain: payload.userDomain,
    claims: redemption.claims,
    domainPublicKeys: userDomainKeys,
    localRpFingerprint: config.keyMaterial.fingerprint,
    issuedAt: Rfc3339.parse('issued_at', payload.issuedAt),
    expiresAt: Rfc3339.parse('expires_at', payload.expiresAt),
    ticketExpiresAt:
        Rfc3339.parse('ticket_expires_at', redemption.ticketExpiresAt),
  );
}
