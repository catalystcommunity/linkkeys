// Act-as grantee support. Vector tests reproduce the exact bytes of
// `sdks/regular-rp/conformance/act_as_grantee_signing.json`'s
// `local_rp_grantee` case. Every resolver is a hermetic fake, and the
// refresh tests talk to an in-process loopback fake IDP through the same
// `insecureCallForTesting` seam `flow_test.dart` uses (see that file for why
// the TLS handshake is skipped). No test reaches a live network.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:linkkeys_local_rp/linkkeys_local_rp.dart';
import 'package:linkkeys_local_rp/src/act_as.dart'
    show refreshActAsGrantForTesting;
import 'package:linkkeys_local_rp/src/crypto/crypto.dart';
import 'package:linkkeys_local_rp/src/crypto/hex.dart';
import 'package:linkkeys_local_rp/src/rpc/rpc_client.dart' as rpc;
import 'package:linkkeys_local_rp/src/rpc/rpc_envelope.dart';
import 'package:linkkeys_local_rp/src/rpc/stream_framing.dart';
import 'package:linkkeys_local_rp/src/wire/cbor.dart'
    show Cbor, CborMap, CborMapEntry, CborText;
import 'package:linkkeys_local_rp/src/wire/codec.dart';
import 'package:test/test.dart';

import 'testutil/fixtures.dart';

const _domain = 'home.example.test';

/// The home domain of the grant in the act-as vectors.
const _vectorHomeDomain = 'home.conformance.example';
const _callbackUrl = 'http://app.lan:8080/act-as/callback';

Map<String, dynamic> _vectors() => jsonDecode(File(
        '${conformanceDir()}/../../regular-rp/conformance/act_as_grantee_signing.json')
    .readAsStringSync()) as Map<String, dynamic>;

Map<String, dynamic> _localCase(Map<String, dynamic> v) =>
    (v['cases'] as List).cast<Map<String, dynamic>>().firstWhere(
          (c) => c['name'] == 'local_rp_grantee',
        );

/// Key material built from the vector's published local-RP seed and signed
/// descriptor. The encryption keys are not used by act-as.
Future<LocalRpKeyMaterial> _vectorKeyMaterial(Map<String, dynamic> v) async {
  final g = v['local_rp_grantee'] as Map<String, dynamic>;
  final kp = await Crypto.ed25519KeyPairFromSeed(
      hex(g['signing_private_key_hex'] as String));
  return LocalRpKeyMaterial(
    signingPrivateKey: kp.privateKeySeed,
    signingPublicKey: kp.publicKey,
    encryptionPrivateKey: Uint8List(32),
    encryptionPublicKey: Uint8List(32),
    descriptor: Codec.decodeSignedLocalRpDescriptor(
        hex(g['signed_descriptor_cbor_hex'] as String)),
    fingerprint: g['fingerprint'] as String,
  );
}

class _MapDnsResolver implements DnsResolver {
  final Map<String, List<String>> records;
  _MapDnsResolver(this.records);

  @override
  Future<List<String>> txtLookup(String name) async {
    final txts = records[name];
    if (txts == null) {
      throw SdkException(SdkExceptionKind.dns, 'no fake record for $name');
    }
    return txts;
  }
}

typedef _Dispatch = RpcResponse Function(
    String service, String op, Uint8List payload);

/// A one-connection plain-TCP fake IDP on loopback (see `flow_test.dart`).
Future<String> _spawnFakeIdp(_Dispatch dispatch) async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((socket) async {
    try {
      final req = RpcRequest.decode(await FrameReader(socket).readFrame());
      await sendFrame(
          socket, dispatch(req.service, req.op, req.payload).encode());
    } catch (_) {
      // a failed test surfaces on the client side
    } finally {
      socket.destroy();
      await server.close();
    }
  });
  return '127.0.0.1:${server.port}';
}

Future<void> _verifyProof(LocalRpKeyMaterial km, GranteeProof proof, String tag,
    Uint8List payload) async {
  expect(proof.applicationInstanceId, isNull);
  expect(proof.signature.signedByKeyId, equals(km.fingerprint));
  final descriptor =
      Codec.decodeLocalRpDescriptor(proof.localRpDescriptor!.descriptor);
  expect(descriptor.fingerprint, equals(km.fingerprint));
  expect(
      await Crypto.verifyEd25519(LocalRp.envelopeSignatureInput(tag, payload),
          proof.signature.signature, descriptor.signingPublicKey),
      isTrue);
}

void main() {
  final v = _vectors();
  final c = _localCase(v);

  group('act_as_grantee_signing.json local_rp_grantee', () {
    test('tags match', () {
      final tags = v['tags'] as Map<String, dynamic>;
      expect(ActAs.tagGrantRequest, equals(tags['grant_request']));
      expect(ActAs.tagRefreshRequest, equals(tags['refresh_request']));
      expect(ActAs.tagPresentation, equals(tags['presentation']));
    });

    test('grant request bytes, signed CBOR, and url_param', () async {
      final km = await _vectorKeyMaterial(v);
      final gr = c['grant_request'] as Map<String, dynamic>;
      final inputs = gr['inputs'] as Map<String, dynamic>;
      final request = ActAsGrantRequest(
        grantee: ActAs.granteeFor(km),
        scopeSet: ActAsCodec.decodeSignedActAsScopeSet(
            hex(inputs['scope_set_signed_cbor_hex'] as String)),
        requestedLifetimeSeconds: inputs['requested_lifetime_seconds'] as int?,
        requestedRenewalWindowSeconds:
            inputs['requested_renewal_window_seconds'] as int?,
        callbackUrl: inputs['callback_url'] as String,
        nonce: inputs['nonce'] as String,
        requestedAt: inputs['requested_at'] as String,
        expiresAt: inputs['expires_at'] as String,
      );
      final signed = await ActAs.signGrantRequest(request, km);
      expect(Hex.encode(signed.request), equals(gr['request_cbor_hex']));
      expect(
          Hex.encode(LocalRp.envelopeSignatureInput(
              ActAs.tagGrantRequest, signed.request)),
          equals(gr['signature_input_cbor_hex']));
      final signedBytes = ActAsCodec.encodeSignedActAsGrantRequest(signed);
      expect(Hex.encode(signedBytes), equals(gr['signed_cbor_hex']));
      expect(encodeUrlParam(signedBytes), equals(gr['url_param']));
      // Round trip.
      final back = ActAsCodec.decodeSignedActAsGrantRequest(signedBytes);
      expect(Hex.encode(ActAsCodec.encodeSignedActAsGrantRequest(back)),
          equals(gr['signed_cbor_hex']));
    });

    test('refresh request signed CBOR', () async {
      final km = await _vectorKeyMaterial(v);
      final rr = c['refresh_request'] as Map<String, dynamic>;
      final inputs = rr['inputs'] as Map<String, dynamic>;
      final signed = await ActAs.signRefreshRequest(
          ActAsRefreshRequest(
            grantId: inputs['grant_id'] as String,
            grantee: ActAs.granteeFor(km),
            requestedAt: inputs['requested_at'] as String,
            expiresAt: inputs['expires_at'] as String,
            nonce: inputs['nonce'] as String,
          ),
          km);
      expect(Hex.encode(signed.request), equals(rr['request_cbor_hex']));
      expect(Hex.encode(ActAsCodec.encodeSignedActAsRefreshRequest(signed)),
          equals(rr['signed_cbor_hex']));
    });

    test('presentation and credential CBOR', () async {
      final km = await _vectorKeyMaterial(v);
      final p = c['presentation'] as Map<String, dynamic>;
      final inputs = p['inputs'] as Map<String, dynamic>;
      final aud = inputs['audience'] as Map<String, dynamic>;
      final grant = ActAsCodec.decodeSignedActAsGrant(
          hex(inputs['grant_signed_cbor_hex'] as String));
      expect(Hex.encode(await ActAs.grantHash(grant.grant)),
          equals(p['grant_hash_hex']));
      final presented = await presentActAsGrant(
        grant: grant,
        audience: ApplicationRef(
          subjectUserId: aud['subject_user_id'] as String,
          subjectDomain: aud['subject_domain'] as String,
          applicationId: aud['application_id'] as String,
        ),
        requestDigest: hex(inputs['request_digest_hex'] as String),
        now: DateTime.parse(inputs['presented_at'] as String),
        nonce: hex(inputs['nonce_hex'] as String),
        keyMaterial: km,
      );
      expect(Hex.encode(presented.credential.presentation.presentation),
          equals(p['presentation_cbor_hex']));
      expect(Hex.encode(presented.bytes), equals(p['credential_cbor_hex']));
      final back = ActAsCodec.decodeActAsCredential(presented.bytes);
      expect(Hex.encode(ActAsCodec.encodeActAsCredential(back)),
          equals(p['credential_cbor_hex']));
    });
  });

  group('beginActAs', () {
    final now = DateTime.utc(2026, 10, 6, 11, 59);
    Uint8List scopeSet() =>
        hex(((c['grant_request'] as Map<String, dynamic>)['inputs']
            as Map<String, dynamic>)['scope_set_signed_cbor_hex'] as String);

    Future<BeginActAsResult> begin(DnsResolver dns,
            {String identity = 'alice@$_domain', Duration? window}) async =>
        beginActAs(BeginActAsConfig(
          keyMaterial: await _vectorKeyMaterial(v),
          userIdentity: identity,
          signedScopeSet: scopeSet(),
          requestedLifetimeSeconds: 1800,
          callbackUrl: _callbackUrl,
          now: now,
          dns: dns,
          requestWindow: window,
        ));

    test('uses the discovered host and signs a verifiable request', () async {
      final km = await _vectorKeyMaterial(v);
      final r = await begin(_MapDnsResolver({
        '_linkkeys_apis.$_domain': ['v=lk1 https=login.example.test/lk'],
      }));
      final uri = Uri.parse(r.redirectUrl);
      expect(uri.scheme, equals('https'));
      expect(uri.host, equals('login.example.test'));
      expect(uri.path, equals('/lk/auth/act-as'));
      expect(uri.queryParameters.keys, equals(['signed_request']));
      expect(r.pending.userDomain, equals(_domain));
      expect(r.pending.callbackUrl, equals(_callbackUrl));

      final signed = ActAsCodec.decodeSignedActAsGrantRequest(
          decodeUrlParam(uri.queryParameters['signed_request']!));
      await _verifyProof(
          km, signed.proof, ActAs.tagGrantRequest, signed.request);
      final req = ActAsCodec.decodeActAsGrantRequest(signed.request);
      expect(req.grantee.localRpDescriptorFingerprint, equals(km.fingerprint));
      expect(req.grantee.application, isNull);
      expect(req.nonce, equals(r.pending.nonce));
      expect(decodeUrlParam(req.nonce).length, equals(32));
      expect(req.requestedAt, equals('2026-10-06T11:59:00Z'));
      expect(req.expiresAt, equals('2026-10-06T12:04:00Z'));
      expect(req.requestedLifetimeSeconds, equals(1800));
      expect(req.requestedRenewalWindowSeconds, isNull);
      expect(req.callbackUrl, equals(_callbackUrl));
      expect(ActAsCodec.encodeSignedActAsScopeSet(req.scopeSet),
          equals(scopeSet()));
    });

    test('falls back to the identity domain when discovery fails', () async {
      final r = await begin(_MapDnsResolver(const {}), identity: _domain);
      expect(r.redirectUrl,
          startsWith('https://$_domain/auth/act-as?signed_request='));
    });

    test('fresh nonce per call', () async {
      final a = await begin(_MapDnsResolver(const {}));
      final b = await begin(_MapDnsResolver(const {}));
      expect(a.pending.nonce, isNot(equals(b.pending.nonce)));
    });

    test('rejects a request window above 900 seconds', () async {
      await expectLater(
          begin(_MapDnsResolver(const {}),
              window: const Duration(seconds: 901)),
          throwsA(isA<SdkException>()));
    });

    test('rejects a scope set that does not decode', () async {
      await expectLater(
          beginActAs(BeginActAsConfig(
            keyMaterial: await _vectorKeyMaterial(v),
            userIdentity: _domain,
            signedScopeSet: Uint8List.fromList([0xa0]),
            callbackUrl: _callbackUrl,
            now: now,
            dns: _MapDnsResolver(const {}),
          )),
          throwsA(isA<SdkException>()));
    });
  });

  group('completeActAsCallback', () {
    const pending = PendingActAs(
        nonce: 'abc_DEF-123', userDomain: _domain, callbackUrl: _callbackUrl);

    test('matching nonce returns the grant id', () {
      expect(
          completeActAsCallback(pending,
              '$_callbackUrl?act_as_grant_id=grant-7&nonce=abc_DEF-123'),
          equals('grant-7'));
      expect(
          completeActAsCallback(
              pending, 'act_as_grant_id=grant-7&nonce=abc_DEF-123'),
          equals('grant-7'));
    });

    test('mismatched nonce is rejected', () {
      expect(
          () => completeActAsCallback(
              pending, '$_callbackUrl?act_as_grant_id=grant-7&nonce=wrong'),
          throwsA(isA<LocalRpError>()
              .having((e) => e.kind, 'kind', LocalRpErrorKind.nonceMismatch)));
    });

    test('missing or repeated parameters are rejected', () {
      for (final q in [
        '$_callbackUrl?nonce=abc_DEF-123',
        '$_callbackUrl?act_as_grant_id=g',
        '$_callbackUrl?act_as_grant_id=g&nonce=abc_DEF-123&nonce=abc_DEF-123',
      ]) {
        expect(() => completeActAsCallback(pending, q),
            throwsA(isA<LocalRpError>()));
      }
    });
  });

  group('refreshActAsGrant', () {
    final now = DateTime.utc(2026, 10, 6, 12, 40);
    final grantBytes = hex(
        ((c['presentation'] as Map<String, dynamic>)['inputs']
            as Map<String, dynamic>)['grant_signed_cbor_hex'] as String);

    Future<RefreshActAsGrantResponse> refresh(_Dispatch dispatch) async {
      final km = await _vectorKeyMaterial(v);
      final addr = await _spawnFakeIdp(dispatch);
      final dns = _MapDnsResolver({
        '_linkkeys.$_vectorHomeDomain': ['v=lk1 fp=${'a' * 64}'],
        '_linkkeys_apis.$_vectorHomeDomain': ['v=lk1 tcp=$addr'],
      });
      return refreshActAsGrantForTesting(
          RefreshActAsGrantConfig(
            keyMaterial: km,
            userDomain: _vectorHomeDomain,
            grantId: 'grant-1',
            now: now,
            transport: StdTransport(),
            dns: dns,
          ),
          caller: rpc.insecureCallForTesting);
    }

    test('calls ActAs/refresh-grant with a verifiable signed request',
        () async {
      final km = await _vectorKeyMaterial(v);
      String? route;
      Uint8List? seen;
      final resp = await refresh((service, op, payload) {
        route = '$service/$op';
        seen = payload;
        return RpcResponse.ok(
            'RefreshActAsGrantResponse',
            ActAsCodec.encodeRefreshActAsGrantResponse(
                RefreshActAsGrantResponse(
                    grant: ActAsCodec.decodeSignedActAsGrant(grantBytes),
                    signed: true)));
      });
      expect(route, equals('ActAs/refresh-grant'));
      final signed = ActAsCodec.decodeRefreshActAsGrantRequest(seen!).request;
      await _verifyProof(
          km, signed.proof, ActAs.tagRefreshRequest, signed.request);
      final req = ActAsCodec.decodeActAsRefreshRequest(signed.request);
      expect(req.grantId, equals('grant-1'));
      expect(req.grantee.localRpDescriptorFingerprint, equals(km.fingerprint));
      expect(req.requestedAt, equals('2026-10-06T12:40:00Z'));
      expect(req.expiresAt, equals('2026-10-06T12:45:00Z'));
      expect(decodeUrlParam(req.nonce).length, equals(32));

      expect(resp.signed, isTrue);
      expect(ActAsCodec.encodeSignedActAsGrant(resp.grant), equals(grantBytes));
    });

    test('a grant for another grant id, grantee, or domain is refused',
        () async {
      final good = ActAsCodec.decodeSignedActAsGrant(grantBytes);
      final identity = ActAsCodec.decodeGrantIdentity(good.grant);
      Uint8List reencoded(String grantId, String fingerprint, String domain) {
        final m = Cbor.decode(good.grant) as CborMap;
        final entries = m.entries.map((e) {
          final key = (e.key as CborText).value;
          if (key == 'grant_id') return CborMapEntry(e.key, CborText(grantId));
          if (key == 'subject_domain') {
            return CborMapEntry(e.key, CborText(domain));
          }
          if (key == 'grantee') {
            return CborMapEntry(
                e.key,
                Cbor.vmap([
                  Cbor.entry(
                      'local_rp_descriptor_fingerprint', CborText(fingerprint))
                ]));
          }
          return e;
        }).toList();
        return Cbor.encode(Cbor.vmap(entries));
      }

      final fp = identity.grantee.localRpDescriptorFingerprint!;
      for (final served in [
        reencoded('grant-2', fp, _vectorHomeDomain),
        reencoded('grant-1', 'another-local-rp', _vectorHomeDomain),
        reencoded('grant-1', fp, 'other.example'),
      ]) {
        await expectLater(
            refresh((service, op, payload) => RpcResponse.ok(
                'RefreshActAsGrantResponse',
                ActAsCodec.encodeRefreshActAsGrantResponse(
                    RefreshActAsGrantResponse(
                        grant: SignedActAsGrant(
                            grant: served, signatures: good.signatures),
                        signed: false)))),
            throwsA(isA<LocalRpError>().having(
                (e) => e.kind, 'kind', LocalRpErrorKind.grantMismatch)));
      }
    });

    test('a transport error surfaces', () async {
      await expectLater(
          refresh((service, op, payload) =>
              RpcResponse.transportError(RpcStatus.forbidden, 'refused')),
          throwsA(isA<SdkException>()
              .having((e) => e.kind, 'kind', SdkExceptionKind.server)));
    });

    test('a response that does not decode is a protocol error', () async {
      await expectLater(
          refresh((service, op, payload) =>
              RpcResponse.ok(null, Uint8List.fromList([0xa0]))),
          throwsA(isA<SdkException>()
              .having((e) => e.kind, 'kind', SdkExceptionKind.protocol)));
    });
  });
}
