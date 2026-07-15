// Flow tests: `completeLocalLogin`'s full verification chain, end to end,
// against a real (but locally spun up, fake-identity) LinkKeys IDP -- real
// TCP sockets, real CSIL-RPC framing, and all. Two things are faked: the
// DNS TXT answers (`_FakeDnsResolver`, so no real network/DNS is touched)
// and, of necessity, the TLS layer.
//
// ## Known limitation: no real TLS handshake
//
// Unlike the Rust/Go/Java/TypeScript reference SDKs' flow tests, this file
// cannot present a real Ed25519 TLS server certificate from an in-process
// fake IDP: `dart:io`'s TLS stack (BoringSSL) rejects the handshake
// entirely when the server certificate is Ed25519-keyed
// (`HandshakeException: ... NO_COMMON_SIGNATURE_ALGORITHMS`), which was
// verified empirically against an `openssl`-minted Ed25519 certificate
// before writing this file. Since this protocol's TLS pinning is DEFINED
// in terms of a domain's Ed25519 signing key's fingerprint, there is no
// substitute certificate algorithm that would exercise the real
// production path here.
//
// This test suite therefore drives `completeLocalLoginForTesting` (an
// internal, non-exported test seam in `src/complete.dart`) with an
// `RpcCaller` override (`insecureCallForTesting` in
// `src/rpc/rpc_client.dart`) that dials a real TCP socket and speaks real
// CSIL-RPC stream framing to a real in-process fake IDP, but skips the TLS
// handshake step. Every other production code path this SDK owns is
// exercised for real: the CBOR wire codec, the full `LocalRp`/`Claims`
// verification chain (envelope signatures, sealed-box open, nonce/state/
// audience/issuer/callback-url checks, claim-ticket redemption, per-signer
// claim verification), and DNS TXT parsing. The one thing NOT covered
// end-to-end by this file is the TLS certificate pin check itself, which
// `test/tls_pinning_test.dart` unit-tests directly against real
// `openssl`-minted Ed25519 certificate bytes instead. See this package's
// README, "Known limitations", for the full writeup.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:linkkeys_local_rp/src/claims.dart' as claims_impl;
import 'package:linkkeys_local_rp/src/complete.dart'
    show completeLocalLoginForTesting;
import 'package:linkkeys_local_rp/src/crypto/crypto.dart';
import 'package:linkkeys_local_rp/src/revocation.dart' as revocation_impl;
import 'package:linkkeys_local_rp/src/rpc/rpc_client.dart' as rpc;
import 'package:linkkeys_local_rp/src/rpc/rpc_envelope.dart';
import 'package:linkkeys_local_rp/src/rpc/stream_framing.dart';
import 'package:linkkeys_local_rp/src/rfc3339.dart';
import 'package:linkkeys_local_rp/src/wire/codec.dart';
import 'package:test/test.dart';

const String _userDomain = 'example.test';
const String _callbackUrl = 'http://localhost/callback';
const String _domainKeyId = 'test-domain-key-1';

class _FakeDnsResolver implements DnsResolver {
  final String linkkeysTxt;
  final String apisTxt;
  _FakeDnsResolver(this.linkkeysTxt, this.apisTxt);

  @override
  Future<List<String>> txtLookup(String name) async {
    if (name == '_linkkeys.$_userDomain') return [linkkeysTxt];
    if (name == '_linkkeys_apis.$_userDomain') return [apisTxt];
    throw SdkException(SdkExceptionKind.dns, 'no fake record for $name');
  }
}

typedef _Dispatch = RpcResponse Function(
    String service, String op, Uint8List payload);

/// Spawns a background plain-TCP (no TLS) server for [expectedRequests]
/// connections on a fresh loopback port, answering each with
/// `dispatch(service, op, payload)`. Returns the bound `host:port` string.
Future<String> _spawnFakeIdp(int expectedRequests, _Dispatch dispatch) async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  var handled = 0;
  server.listen((socket) async {
    try {
      final reader = FrameReader(socket);
      final reqBytes = await reader.readFrame();
      RpcResponse resp;
      try {
        final req = RpcRequest.decode(reqBytes);
        resp = dispatch(req.service, req.op, req.payload);
      } catch (e) {
        resp = RpcResponse.transportError(RpcStatus.malformedEnvelope, '$e');
      }
      await sendFrame(socket, resp.encode());
    } catch (_) {
      // best-effort: a deliberately-bad test connection may drop early.
    } finally {
      socket.destroy();
      handled++;
      if (handled >= expectedRequests) {
        await server.close();
      }
    }
  });
  return '127.0.0.1:${server.port}';
}

Future<LocalRpKeyMaterial> _fixedKeyMaterial(DateTime now) {
  return generateLocalRpIdentity(GenerateLocalRpIdentityConfig(
    appName: 'Flow Test App',
    now: now.subtract(const Duration(days: 1)),
    lifetime: const Duration(days: 3651),
  ));
}

/// Every knob a failure-case test can turn, applied in this order: build
/// the correct objects, then mutate, then sign/seal/serve.
class _Scenario {
  LocalRpCallbackPayload Function(LocalRpCallbackPayload) mutatePayload =
      (p) => p;
  DomainPublicKey Function(DomainPublicKey) mutateDomainKey = (k) => k;
  Claim Function(Claim) mutateClaim = (c) => c;
  LocalRpTicketRedemptionResponse Function(LocalRpTicketRedemptionResponse)
      mutateRedemption = (r) => r;

  /// `null` means "use the default single `handle` claim"; non-null
  /// replaces the claims list wholesale (may be empty).
  List<Claim>? claimsOverride;

  /// `null` means "use `beginLocalLogin`'s defaults" (`['handle']`).
  List<String>? requiredClaimsOverride;

  /// Additional domain keys served (and DNS-pinned) alongside the
  /// callback-signing key -- e.g. revocation-quorum siblings.
  List<DomainPublicKey> extraDomainKeys = const [];

  /// Revocation certificates the fake IDP's `get-revocations` route
  /// returns. Ignored when [revocationsBuilder] is set.
  List<RevocationCertificate> revocations = const [];

  /// Async alternative to [revocations] for scenarios that need to SIGN a
  /// certificate against the domain key `_runScenario` just generated (only
  /// known once [mutateDomainKey] has run) -- `mutateDomainKey` itself is
  /// synchronous, so signing can't happen inside it.
  Future<List<RevocationCertificate>> Function(DomainPublicKey domainKey)?
      revocationsBuilder;

  /// When true, `get-revocations` answers with a transport error instead
  /// of a response (FIX B: this must fail the whole login closed, not be
  /// swallowed).
  bool dropRevocationsResponse = false;

  String? dnsFingerprintOverride;

  // get-domain-keys + get-revocations (FIX B: always fetched) +
  // redeem-claim-ticket.
  int expectedRequests = 3;
}

Future<VerifiedLocalLogin> _runScenario(_Scenario scenario) async {
  final now = DateTime.now().toUtc();
  final keyMaterial = await _fixedKeyMaterial(now);

  final begun = await beginLocalLogin(BeginLocalLoginConfig(
    keyMaterial: keyMaterial,
    callbackUrl: _callbackUrl,
    userDomain: _userDomain,
    requiredClaims: scenario.requiredClaimsOverride,
    now: now,
  ));
  final pending = begun.pending;

  final domainSigning = await Crypto.generateEd25519KeyPair();
  var domainKey = DomainPublicKey(
    keyId: _domainKeyId,
    publicKey: domainSigning.publicKey,
    fingerprint: await Crypto.fingerprint(domainSigning.publicKey),
    algorithm: 'ed25519',
    keyUsage: 'sign',
    createdAt: Rfc3339.format(now.subtract(const Duration(days: 30))),
    expiresAt: Rfc3339.format(now.add(const Duration(days: 365))),
  );
  domainKey = scenario.mutateDomainKey(domainKey);
  final revocationsForWire = scenario.revocationsBuilder != null
      ? await scenario.revocationsBuilder!(domainKey)
      : scenario.revocations;

  final claimTicket = Uint8List.fromList(List<int>.filled(32, 7));
  var payload = LocalRp.buildLocalRpCallbackPayload(
    'user-1',
    _userDomain,
    claimTicket,
    keyMaterial.fingerprint,
    _callbackUrl,
    pending.nonce,
    pending.state,
    Rfc3339.format(now),
    Rfc3339.format(now.add(const Duration(minutes: 5))),
  );
  payload = scenario.mutatePayload(payload);

  final signedPayload = await LocalRp.signLocalRpCallbackPayload(
      payload, _domainKeyId, domainSigning.privateKeySeed);

  final encrypted = await LocalRp.sealLocalRpCallback(
    signedPayload,
    AeadSuite.aes256Gcm,
    keyMaterial.encryptionPublicKey,
    payload.audienceFingerprint,
    payload.nonce,
    payload.state,
    payload.issuedAt,
    payload.expiresAt,
  );
  final encryptedToken = localRpEncryptedCallbackToUrlParam(encrypted);
  final arrivedUrl = '$_callbackUrl?encrypted_token=$encryptedToken';

  final claimSpec = claims_impl.ClaimSpec(
    claimId: 'claim-1',
    claimType: 'handle',
    claimValue: Uint8List.fromList(utf8.encode('flowtestuser')),
    userId: 'user-1',
    subjectDomain: _userDomain,
    attestedAt: Rfc3339.format(now),
  );
  var claim = await claims_impl.signClaim(claimSpec, [
    claims_impl.ClaimSigner(
        domain: _userDomain,
        keyId: _domainKeyId,
        privateKeySeed: domainSigning.privateKeySeed),
  ]);
  claim = scenario.mutateClaim(claim);
  final claimsForWire = scenario.claimsOverride ?? [claim];

  var redemptionResponse = LocalRpTicketRedemptionResponse(
    userId: 'user-1',
    userDomain: _userDomain,
    claims: claimsForWire,
    ticketExpiresAt: Rfc3339.format(now.add(const Duration(hours: 1))),
  );
  redemptionResponse = scenario.mutateRedemption(redemptionResponse);

  final servedDomainKeys = [domainKey, ...scenario.extraDomainKeys];
  final finalRedemptionResponse = redemptionResponse;
  final addr =
      await _spawnFakeIdp(scenario.expectedRequests, (service, op, reqPayload) {
    final route = '$service/$op';
    if (route == 'DomainKeys/get-domain-keys') {
      final resp =
          GetDomainKeysResponse(domain: _userDomain, keys: servedDomainKeys);
      return RpcResponse.ok(
          'GetDomainKeysResponse', Codec.encodeGetDomainKeysResponse(resp));
    }
    if (route == 'DomainKeys/get-revocations') {
      if (scenario.dropRevocationsResponse) {
        return RpcResponse.transportError(
            RpcStatus.internal, 'fake IDP deliberately fails get-revocations');
      }
      final resp = GetRevocationsResponse(revocations: revocationsForWire);
      return RpcResponse.ok(
          'GetRevocationsResponse', Codec.encodeGetRevocationsResponse(resp));
    }
    if (route == 'LocalRp/redeem-claim-ticket') {
      return RpcResponse.ok('LocalRpTicketRedemptionResponse',
          Codec.encodeLocalRpTicketRedemptionResponse(finalRedemptionResponse));
    }
    return RpcResponse.transportError(
        RpcStatus.unknownServiceOrOp, 'fake IDP has no handler for $route');
  });

  final realFingerprint = await Crypto.fingerprint(domainSigning.publicKey);
  final pinnedFingerprint = scenario.dnsFingerprintOverride ?? realFingerprint;
  final extraFingerprints =
      scenario.extraDomainKeys.map((k) => ' fp=${k.fingerprint}').join();
  final dns = _FakeDnsResolver(
      'v=lk1 fp=$pinnedFingerprint$extraFingerprints', 'v=lk1 tcp=$addr');
  final transport = StdTransport();

  final config = CompleteLocalLoginConfig(
    keyMaterial: keyMaterial,
    pending: pending,
    encryptedToken: encryptedToken,
    arrivedUrl: arrivedUrl,
    now: now,
    transport: transport,
    dns: dns,
  );
  return completeLocalLoginForTesting(config,
      caller: rpc.insecureCallForTesting);
}

void main() {
  group('Flow', () {
    test('happy path returns verified login', () async {
      final result = await _runScenario(_Scenario());
      expect(result.userId, equals('user-1'));
      expect(result.userDomain, equals(_userDomain));
      expect(result.claims.length, equals(1));
      expect(result.claims[0].claimType, equals('handle'));
      expect(result.localRpFingerprint.length, equals(64));
      expect(result.domainPublicKeys.length, equals(1));
    });

    test('wrong audience fingerprint is rejected', () async {
      final s = _Scenario();
      s.mutatePayload = (p) => LocalRpCallbackPayload(
            userId: p.userId,
            userDomain: p.userDomain,
            claimTicket: p.claimTicket,
            audienceFingerprint: 'b' * 64,
            callbackUrl: p.callbackUrl,
            nonce: p.nonce,
            state: p.state,
            issuedAt: p.issuedAt,
            expiresAt: p.expiresAt,
          );
      // get-domain-keys + get-revocations only -- fails before redemption
      // is ever attempted.
      s.expectedRequests = 2;
      await expectLater(_runScenario(s), throwsA(isA<LocalRpError>()));
    });

    test('wrong issuer domain is rejected', () async {
      final s = _Scenario();
      s.mutatePayload = (p) => LocalRpCallbackPayload(
            userId: p.userId,
            userDomain: 'attacker.test',
            claimTicket: p.claimTicket,
            audienceFingerprint: p.audienceFingerprint,
            callbackUrl: p.callbackUrl,
            nonce: p.nonce,
            state: p.state,
            issuedAt: p.issuedAt,
            expiresAt: p.expiresAt,
          );
      s.expectedRequests = 2;
      await expectLater(_runScenario(s), throwsA(isA<LocalRpError>()));
    });

    test('nonce mismatch is rejected', () async {
      final s = _Scenario();
      final wrongNonce = Uint8List.fromList(List<int>.filled(32, 0xEE));
      s.mutatePayload = (p) => LocalRpCallbackPayload(
            userId: p.userId,
            userDomain: p.userDomain,
            claimTicket: p.claimTicket,
            audienceFingerprint: p.audienceFingerprint,
            callbackUrl: p.callbackUrl,
            nonce: wrongNonce,
            state: p.state,
            issuedAt: p.issuedAt,
            expiresAt: p.expiresAt,
          );
      s.expectedRequests = 2;
      await expectLater(_runScenario(s), throwsA(isA<LocalRpError>()));
    });

    test('expired callback payload is rejected', () async {
      final s = _Scenario();
      s.mutatePayload = (p) {
        final n = DateTime.now().toUtc();
        return LocalRpCallbackPayload(
          userId: p.userId,
          userDomain: p.userDomain,
          claimTicket: p.claimTicket,
          audienceFingerprint: p.audienceFingerprint,
          callbackUrl: p.callbackUrl,
          nonce: p.nonce,
          state: p.state,
          issuedAt: Rfc3339.format(n.subtract(const Duration(hours: 2))),
          expiresAt: Rfc3339.format(n.subtract(const Duration(hours: 1))),
        );
      };
      s.expectedRequests = 2;
      await expectLater(_runScenario(s), throwsA(isA<LocalRpError>()));
    });

    test('dns fingerprint pin mismatch is rejected', () async {
      final s = _Scenario();
      s.dnsFingerprintOverride = 'c' * 64;
      s.expectedRequests = 1;
      // Fails during domain-key trust establishment (the fake IDP's real
      // domain key no longer matches the pinned DNS fingerprint set) --
      // either way it must never reach a verified result.
      await expectLater(_runScenario(s), throwsA(anything));
    });

    test('revoked signing key is rejected', () async {
      final s = _Scenario();
      s.mutateDomainKey = (k) => DomainPublicKey(
            keyId: k.keyId,
            publicKey: k.publicKey,
            fingerprint: k.fingerprint,
            algorithm: k.algorithm,
            keyUsage: k.keyUsage,
            createdAt: k.createdAt,
            expiresAt: k.expiresAt,
            revokedAt: Rfc3339.format(DateTime.now().toUtc()),
            signedByKeyId: k.signedByKeyId,
            keySignature: k.keySignature,
          );
      s.expectedRequests = 2;
      await expectLater(_runScenario(s), throwsA(isA<LocalRpError>()));
    });

    test('tampered claim signature is rejected', () async {
      final s = _Scenario();
      s.mutateClaim = (c) {
        final sigs = List<ClaimSignature>.from(c.signatures);
        if (sigs.isNotEmpty) {
          final sig = sigs[0];
          final flipped = Uint8List.fromList(sig.signature);
          flipped[0] ^= 0xff;
          sigs[0] = ClaimSignature(
              domain: sig.domain,
              signedByKeyId: sig.signedByKeyId,
              signature: flipped);
        }
        return c.copyWith(signatures: sigs);
      };
      await expectLater(_runScenario(s), throwsA(isA<ClaimError>()));
    });
  });

  group('Flow -- hostile-IDP rejections (security review fixes)', () {
    // FIX A.1: identity binding -- the ticket-redemption response carries
    // no signature of its own; it must never be trusted as-is against the
    // domain-signature-VERIFIED callback payload.
    test('redemption user_id mismatch with signed payload is rejected',
        () async {
      final s = _Scenario();
      s.mutateRedemption = (r) => LocalRpTicketRedemptionResponse(
            userId: 'attacker-user',
            userDomain: r.userDomain,
            claims: r.claims,
            ticketExpiresAt: r.ticketExpiresAt,
          );
      final err = await _expectFatal<LocalRpError>(_runScenario(s));
      expect(err.kind, equals(LocalRpErrorKind.redemptionIdentityMismatch));
    });

    test('redemption user_domain mismatch with signed payload is rejected',
        () async {
      final s = _Scenario();
      s.mutateRedemption = (r) => LocalRpTicketRedemptionResponse(
            userId: r.userId,
            userDomain: 'attacker.test',
            claims: r.claims,
            ticketExpiresAt: r.ticketExpiresAt,
          );
      final err = await _expectFatal<LocalRpError>(_runScenario(s));
      expect(err.kind, equals(LocalRpErrorKind.redemptionIdentityMismatch));
    });

    // FIX A.1.c: a validly-signed claim naming a DIFFERENT subject than the
    // domain-signed payload vouches for must never be attributed to this
    // login, even though its own signature verifies.
    test('claim user_id mismatch with signed payload is rejected', () async {
      final s = _Scenario();
      s.mutateClaim = (c) => c.copyWith(userId: 'attacker-user');
      final err = await _expectFatal<ClaimError>(_runScenario(s));
      expect(err.kind, equals(ClaimErrorKind.userIdMismatch));
    });

    // FIX A.1.d: required-claims enforcement -- empty and insufficient
    // claim sets must both be fatal, never a silent partial success.
    test('empty claims with non-empty required claims is rejected', () async {
      final s = _Scenario();
      s.claimsOverride = const [];
      final err = await _expectFatal<ClaimError>(_runScenario(s));
      expect(err.kind, equals(ClaimErrorKind.requiredClaimMissing));
    });

    test('insufficient claims missing a required type is rejected', () async {
      final s = _Scenario();
      // Two claim types are required, but the fake IDP only ever attests
      // one ('handle', built into `_runScenario`).
      s.requiredClaimsOverride = const ['handle', 'email'];
      final err = await _expectFatal<ClaimError>(_runScenario(s));
      expect(err.kind, equals(ClaimErrorKind.requiredClaimMissing));
      expect(err.detail, equals('email'));
    });

    // FIX B: revocation fetching must fail closed. A `get-revocations`
    // error must never be swallowed as "proceed unfiltered" -- the whole
    // login must fail.
    test('get-revocations RPC error fails the login closed', () async {
      final s = _Scenario();
      s.dropRevocationsResponse = true;
      // get-domain-keys succeeds, get-revocations errors -- redemption
      // must never be attempted on a "best effort" basis.
      s.expectedRequests = 2;
      await expectLater(_runScenario(s), throwsA(isA<SdkException>()));
    });

    // FIX B: a quorum-verified sibling revocation certificate targeting the
    // domain's callback-signing key must be applied BEFORE that key is
    // trusted for anything -- regardless of `recentRevocationsAvailable`.
    test('certificate-revoked signing key is rejected', () async {
      final now = DateTime.now().toUtc();
      final sibling1 = await Crypto.generateEd25519KeyPair();
      final sibling2 = await Crypto.generateEd25519KeyPair();
      const sibling1KeyId = 'sibling-key-1';
      const sibling2KeyId = 'sibling-key-2';
      final sibling1Key = DomainPublicKey(
        keyId: sibling1KeyId,
        publicKey: sibling1.publicKey,
        fingerprint: await Crypto.fingerprint(sibling1.publicKey),
        algorithm: 'ed25519',
        keyUsage: 'sign',
        createdAt: Rfc3339.format(now.subtract(const Duration(days: 30))),
        expiresAt: Rfc3339.format(now.add(const Duration(days: 365))),
      );
      final sibling2Key = DomainPublicKey(
        keyId: sibling2KeyId,
        publicKey: sibling2.publicKey,
        fingerprint: await Crypto.fingerprint(sibling2.publicKey),
        algorithm: 'ed25519',
        keyUsage: 'sign',
        createdAt: Rfc3339.format(now.subtract(const Duration(days: 30))),
        expiresAt: Rfc3339.format(now.add(const Duration(days: 365))),
      );

      final s = _Scenario();
      // Two sibling signing keys, both DNS-pinned alongside the real
      // callback-signing key (needed to satisfy revocation.revocationQuorum
      // == 2).
      s.extraDomainKeys = [sibling1Key, sibling2Key];
      // `revocationsBuilder` runs (inside `_runScenario`) right after the
      // real callback-signing key is built -- it's the only place this
      // test learns that key's actual key id/fingerprint, and unlike
      // `mutateDomainKey` it's allowed to be async, so the quorum-verified
      // revocation certificate targeting it can be signed here.
      s.revocationsBuilder = (domainKey) async {
        final revokedAt = Rfc3339.format(now);
        final payload = revocation_impl.revocationPayload(
            domainKey.keyId, domainKey.fingerprint, revokedAt, _userDomain);
        final sig1 = await Crypto.signEd25519(payload, sibling1.privateKeySeed);
        final sig2 = await Crypto.signEd25519(payload, sibling2.privateKeySeed);
        return [
          RevocationCertificate(
            targetKeyId: domainKey.keyId,
            targetFingerprint: domainKey.fingerprint,
            revokedAt: revokedAt,
            signatures: [
              ClaimSignature(
                  domain: _userDomain,
                  signedByKeyId: sibling1KeyId,
                  signature: sig1),
              ClaimSignature(
                  domain: _userDomain,
                  signedByKeyId: sibling2KeyId,
                  signature: sig2),
            ],
          ),
        ];
      };
      // Fails at envelope verification (the signing key was just revoked
      // out of the trusted set) -- redemption is never attempted.
      s.expectedRequests = 2;
      final err = await _expectFatal<LocalRpError>(_runScenario(s));
      expect(err.kind, equals(LocalRpErrorKind.keyNotFound));
    });
  });
}

/// Awaits [future], asserting it throws an instance of [T], and returns
/// that instance (so the test can assert on its specific `kind`/`detail`
/// rather than merely "some error was thrown").
Future<T> _expectFatal<T extends Object>(Future<Object?> future) async {
  try {
    await future;
  } catch (e) {
    expect(e, isA<T>());
    return e as T;
  }
  fail('expected $T to be thrown, but the future completed successfully');
}
