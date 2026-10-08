// Act-as grants, grantee side (`docs/spec/reserved/act-as-grants.md`).
//
// A user can let this local RP (the grantee) act as the user at an enrolled
// application (the audience). A local RP is identified by its descriptor
// signing-key fingerprint, and that key signs every grantee message. A local
// RP can never be an audience: a peer cannot resolve its keys through DNS.
//
// The flow:
//
//   1. [beginActAs] signs an `ActAsGrantRequest` around the audience's
//      signed scope set and returns the browser redirect to the user's home
//      domain (`GET /auth/act-as?signed_request=...`) plus a [PendingActAs].
//   2. The home domain shows the consent page, then sends the browser to the
//      callback URL with `act_as_grant_id` and `nonce`.
//      [completeActAsCallback] checks the nonce and returns the grant id.
//   3. [refreshActAsGrant] fetches (or renews) the signed grant over the
//      DNS-pinned TCP CSIL-RPC path (`ActAs/refresh-grant`).
//   4. [presentActAsGrant] signs one presentation for one call to the
//      audience and returns the `ActAsCredential` to send with it.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'begin.dart' show parseIdentityInput, validateCallbackScheme;
import 'browser.dart';
import 'complete.dart' show defaultDnsResolver, defaultTransport;
import 'crypto/crypto.dart';
import 'dns/dns_resolver.dart';
import 'encoding.dart';
import 'errors.dart';
import 'identity.dart';
import 'local_rp.dart';
import 'rfc3339.dart';
import 'rpc/rpc_client.dart' as rpc;
import 'rpc/transport.dart';
import 'wire/act_as_wire.dart';

/// The browser route that starts an act-as grant at the home domain.
const String browserRouteActAs = '/auth/act-as';

/// Default grant-request window (`requested_at` to `expires_at`).
const Duration defaultActAsRequestWindow = Duration(seconds: 300);

/// Longest grant-request window. The reference home domain refuses longer
/// windows, because it keeps request nonces only that long.
const Duration maxActAsRequestWindow = Duration(seconds: 900);

/// Window of a refresh request.
const Duration actAsRefreshRequestWindow = Duration(seconds: 300);

/// Pure act-as signing helpers: domain-separation tags and the signed
/// structures. No I/O.
class ActAs {
  ActAs._();

  static const String tagGrantRequest = 'linkkeys-act-as-grant-request-v1alpha';
  static const String tagRefreshRequest =
      'linkkeys-act-as-refresh-request-v1alpha';
  static const String tagPresentation = 'linkkeys-act-as-presentation-v1alpha';

  /// This local RP as a grantee: `{local_rp_descriptor_fingerprint}`.
  static GranteeRef granteeFor(LocalRpKeyMaterial keyMaterial) =>
      GranteeRef(localRpDescriptorFingerprint: keyMaterial.fingerprint);

  /// Sign `CBOR([tag, payload])` with the descriptor signing key and wrap
  /// the signature in a local-RP [GranteeProof].
  static Future<GranteeProof> prove(
      String tag, Uint8List payload, LocalRpKeyMaterial keyMaterial) async {
    final signature = await Crypto.signEd25519(
        LocalRp.envelopeSignatureInput(tag, payload),
        keyMaterial.signingPrivateKey);
    return GranteeProof(
      localRpDescriptor: keyMaterial.descriptor,
      signature: ApplicationKeySignature(
          signedByKeyId: keyMaterial.fingerprint, signature: signature),
    );
  }

  static Future<SignedActAsGrantRequest> signGrantRequest(
      ActAsGrantRequest request, LocalRpKeyMaterial keyMaterial) async {
    final bytes = ActAsCodec.encodeActAsGrantRequest(request);
    return SignedActAsGrantRequest(
        request: bytes,
        proof: await prove(tagGrantRequest, bytes, keyMaterial));
  }

  static Future<SignedActAsRefreshRequest> signRefreshRequest(
      ActAsRefreshRequest request, LocalRpKeyMaterial keyMaterial) async {
    final bytes = ActAsCodec.encodeActAsRefreshRequest(request);
    return SignedActAsRefreshRequest(
        request: bytes,
        proof: await prove(tagRefreshRequest, bytes, keyMaterial));
  }

  /// SHA-256 of a grant's signed bytes (`SignedActAsGrant.grant`).
  static Future<Uint8List> grantHash(Uint8List grantBytes) =>
      Crypto.sha256(grantBytes);
}

/// A fresh request nonce: 32 random bytes, unpadded base64url.
String _freshNonce() => encodeUrlParam(Crypto.randomBytes(32));

// ---------------------------------------------------------------------
// Begin
// ---------------------------------------------------------------------

/// Input to [beginActAs].
class BeginActAsConfig {
  final LocalRpKeyMaterial keyMaterial;

  /// The user's LinkKeys login (`user@domain`) or home domain. Only the
  /// domain is used: the act-as route takes no username hint.
  final String userIdentity;

  /// The audience's `SignedActAsScopeSet`, as the CBOR bytes the audience
  /// sent. The SDK embeds it unchanged.
  final Uint8List signedScopeSet;

  final int? requestedLifetimeSeconds;
  final int? requestedRenewalWindowSeconds;
  final String callbackUrl;
  final DateTime now;

  /// The DNS TXT lookup seam for browser endpoint discovery. Defaults to
  /// the system resolver.
  final DnsResolver? dns;

  /// The request window. Defaults to [defaultActAsRequestWindow]; at most
  /// [maxActAsRequestWindow].
  final Duration? requestWindow;

  const BeginActAsConfig({
    required this.keyMaterial,
    required this.userIdentity,
    required this.signedScopeSet,
    this.requestedLifetimeSeconds,
    this.requestedRenewalWindowSeconds,
    required this.callbackUrl,
    required this.now,
    this.dns,
    this.requestWindow,
  });
}

/// The state [beginActAs] returns. Persist it and pass it to
/// [completeActAsCallback]. Single-use: discard it after one attempt.
class PendingActAs {
  final String nonce;

  /// The user's home domain. Use it for [refreshActAsGrant].
  final String userDomain;
  final String callbackUrl;

  const PendingActAs({
    required this.nonce,
    required this.userDomain,
    required this.callbackUrl,
  });
}

class BeginActAsResult {
  /// The URL to send the user's browser to.
  final String redirectUrl;
  final PendingActAs pending;
  const BeginActAsResult(this.redirectUrl, this.pending);
}

/// Build and sign an act-as grant request, and return the browser redirect
/// to the user's home domain plus the pending state.
///
/// The redirect host comes from `_linkkeys_apis.<domain>` discovery, with
/// the same fallback to `https://<domain>` that [beginLocalLogin] uses.
Future<BeginActAsResult> beginActAs(BeginActAsConfig config) async {
  validateCallbackScheme(config.callbackUrl);
  final identity = parseIdentityInput(config.userIdentity);
  final window = config.requestWindow ?? defaultActAsRequestWindow;
  if (window <= Duration.zero || window > maxActAsRequestWindow) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'request window must be 1 to ${maxActAsRequestWindow.inSeconds} seconds');
  }
  final lifetime = config.requestedLifetimeSeconds;
  if (lifetime != null && lifetime <= 0) {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'requested lifetime must be positive');
  }
  final renewal = config.requestedRenewalWindowSeconds;
  if (renewal != null && renewal < 0) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'requested renewal window must not be negative');
  }
  final SignedActAsScopeSet scopeSet;
  try {
    scopeSet = ActAsCodec.decodeSignedActAsScopeSet(config.signedScopeSet);
  } catch (e) {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'signed scope set does not decode',
        cause: e);
  }

  final nonce = _freshNonce();
  final request = ActAsGrantRequest(
    grantee: ActAs.granteeFor(config.keyMaterial),
    scopeSet: scopeSet,
    requestedLifetimeSeconds: lifetime,
    requestedRenewalWindowSeconds: renewal,
    callbackUrl: config.callbackUrl,
    nonce: nonce,
    requestedAt: Rfc3339.format(config.now),
    expiresAt: Rfc3339.format(config.now.add(window)),
  );
  final signed = await ActAs.signGrantRequest(request, config.keyMaterial);
  final encoded =
      encodeUrlParam(ActAsCodec.encodeSignedActAsGrantRequest(signed));

  final dns = config.dns ?? defaultDnsResolver();
  final redirectUrl = await resolveBrowserEndpoint(
      dns, identity.domain, browserRouteActAs, encoded);

  return BeginActAsResult(
    redirectUrl,
    PendingActAs(
      nonce: nonce,
      userDomain: identity.domain,
      callbackUrl: config.callbackUrl,
    ),
  );
}

// ---------------------------------------------------------------------
// Callback
// ---------------------------------------------------------------------

/// Read the act-as callback. [callback] is the full URL the callback
/// arrived at, or only its query string. The `nonce` parameter must equal
/// [PendingActAs.nonce]. Returns the `act_as_grant_id`.
///
/// Throws [LocalRpError] ([LocalRpErrorKind.decode] when a parameter is
/// missing or repeated, [LocalRpErrorKind.nonceMismatch] when the nonce is
/// wrong).
String completeActAsCallback(PendingActAs pending, String callback) {
  final Map<String, List<String>> params;
  try {
    params = callback.contains('?')
        ? Uri.parse(callback).queryParametersAll
        : Uri.parse('?$callback').queryParametersAll;
  } on FormatException catch (e) {
    throw LocalRpError(LocalRpErrorKind.decode, 'callback URL does not parse',
        cause: e);
  }
  String single(String name) {
    final values = params[name];
    if (values == null || values.length != 1 || values.single.isEmpty) {
      throw LocalRpError(
          LocalRpErrorKind.decode, 'callback must carry exactly one $name');
    }
    return values.single;
  }

  final grantId = single('act_as_grant_id');
  final nonce = single('nonce');
  if (!Crypto.constantTimeEquals(
      utf8.encode(nonce), utf8.encode(pending.nonce))) {
    throw LocalRpError(LocalRpErrorKind.nonceMismatch,
        'callback nonce does not match the pending act-as request');
  }
  return grantId;
}

// ---------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------

/// Input to [refreshActAsGrant].
class RefreshActAsGrantConfig {
  final LocalRpKeyMaterial keyMaterial;

  /// The user's home domain ([PendingActAs.userDomain]).
  final String userDomain;
  final String grantId;
  final DateTime now;

  /// The TCP dial seam. Defaults to the standard transport.
  final Transport? transport;

  /// The DNS TXT lookup seam. Defaults to the system resolver.
  final DnsResolver? dns;

  const RefreshActAsGrantConfig({
    required this.keyMaterial,
    required this.userDomain,
    required this.grantId,
    required this.now,
    this.transport,
    this.dns,
  });
}

/// Fetch the current signed grant, or a renewed one, from the user's home
/// domain: `ActAs/refresh-grant` over TCP CSIL-RPC, pinned to the domain's
/// DNS `fp=` set (the same path as claim-ticket redemption).
/// [RefreshActAsGrantResponse.signed] is true when the home domain signed
/// a new grant for this call.
Future<RefreshActAsGrantResponse> refreshActAsGrant(
        RefreshActAsGrantConfig config) =>
    _refreshActAsGrantImpl(config, rpc.call);

/// Test seam: [refreshActAsGrant] with an [rpc.RpcCaller] override. Not
/// exported from the package (see `rpc_client.dart`'s `call` docs).
Future<RefreshActAsGrantResponse> refreshActAsGrantForTesting(
        RefreshActAsGrantConfig config,
        {required rpc.RpcCaller caller}) =>
    _refreshActAsGrantImpl(config, caller);

Future<RefreshActAsGrantResponse> _refreshActAsGrantImpl(
    RefreshActAsGrantConfig config, rpc.RpcCaller caller) async {
  if (config.grantId.isEmpty) {
    throw SdkException(SdkExceptionKind.invalidInput, 'grant id is empty');
  }
  final domain = parseIdentityInput(config.userDomain).domain;
  final request = ActAsRefreshRequest(
    grantId: config.grantId,
    grantee: ActAs.granteeFor(config.keyMaterial),
    requestedAt: Rfc3339.format(config.now),
    expiresAt: Rfc3339.format(config.now.add(actAsRefreshRequestWindow)),
    nonce: _freshNonce(),
  );
  final signed = await ActAs.signRefreshRequest(request, config.keyMaterial);
  final payload = ActAsCodec.encodeRefreshActAsGrantRequest(
      RefreshActAsGrantRequest(signed));

  final transport = config.transport ?? defaultTransport();
  final dns = config.dns ?? defaultDnsResolver();
  final endpoint = await rpc.discoverDomainEndpoint(dns, domain);
  final respBytes =
      await caller(transport, endpoint, 'ActAs', 'refresh-grant', payload);
  final RefreshActAsGrantResponse response;
  final ({String grantId, GranteeRef grantee, String subjectDomain}) grant;
  try {
    response = ActAsCodec.decodeRefreshActAsGrantResponse(respBytes);
    grant = ActAsCodec.decodeGrantIdentity(response.grant.grant);
  } catch (e) {
    throw SdkException(SdkExceptionKind.protocol,
        'ActAs/refresh-grant response does not decode',
        cause: e);
  }
  // The audience checks the grant signature. This only checks that the home
  // domain returned the grant this call asked for, so a confused or hostile
  // server cannot hand this grantee another grant.
  if (grant.grantId != config.grantId) {
    throw LocalRpError(LocalRpErrorKind.grantMismatch,
        'refresh-grant returned another grant id');
  }
  if (grant.grantee.application != null ||
      grant.grantee.localRpDescriptorFingerprint !=
          config.keyMaterial.fingerprint) {
    throw LocalRpError(LocalRpErrorKind.grantMismatch,
        'refresh-grant returned a grant for another grantee');
  }
  if (_asciiLower(grant.subjectDomain) != _asciiLower(domain)) {
    throw LocalRpError(LocalRpErrorKind.grantMismatch,
        'refresh-grant returned a grant from another subject domain');
  }
  return response;
}

/// ASCII-only lower case, for domain comparison.
String _asciiLower(String value) =>
    value.replaceAllMapped(RegExp('[A-Z]'), (m) => m[0]!.toLowerCase());

// ---------------------------------------------------------------------
// Present
// ---------------------------------------------------------------------

/// A credential for one call to the audience, as a value and as the CBOR
/// bytes to send.
class PresentedActAsCredential {
  final ActAsCredential credential;
  final Uint8List bytes;
  const PresentedActAsCredential(this.credential, this.bytes);
}

/// Sign one presentation of [grant] to [audience] for one request.
///
/// [requestDigest] is defined by the audience's application protocol.
/// [nonce] must be fresh for each call; the audience owns replay checks.
/// `presented_at` is [now] as whole-second RFC3339 UTC.
Future<PresentedActAsCredential> presentActAsGrant({
  required SignedActAsGrant grant,
  required ApplicationRef audience,
  required Uint8List requestDigest,
  required DateTime now,
  required Uint8List nonce,
  required LocalRpKeyMaterial keyMaterial,
}) async {
  final presentation = ActAsPresentation(
    grantHash: await ActAs.grantHash(grant.grant),
    audience: audience,
    requestDigest: requestDigest,
    presentedAt: Rfc3339.format(now),
    nonce: nonce,
  );
  final bytes = ActAsCodec.encodeActAsPresentation(presentation);
  final credential = ActAsCredential(
    grant: grant,
    presentation: SignedActAsPresentation(
      presentation: bytes,
      proof: await ActAs.prove(ActAs.tagPresentation, bytes, keyMaterial),
    ),
  );
  return PresentedActAsCredential(
      credential, ActAsCodec.encodeActAsCredential(credential));
}
