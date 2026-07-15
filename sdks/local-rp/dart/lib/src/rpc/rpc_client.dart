// CSIL-RPC over the injected [Transport], TLS-pinned to a domain's DNS
// `fp=` records -- this SDK's only network surface, per the design doc's
// "Required Network Access": domain public keys, revocations, and
// claim-ticket redemption, all unauthenticated-TLS TCP CSIL-RPC calls.
library;

import 'dart:io';
import 'dart:typed_data';

import '../dns/dns.dart' as dnsproto;
import '../dns/dns_resolver.dart';
import '../errors.dart';
import '../revocation.dart' as revocation;
import '../wire/codec.dart';
import '../wire/types.dart';
import 'rpc_envelope.dart';
import 'stream_framing.dart';
import 'tls_pinning.dart' as tls;
import 'transport.dart';

/// A discovered endpoint for a domain: its pinned trust-anchor fingerprints
/// and its CSIL-RPC TCP address.
class DomainEndpoint {
  final List<String> fingerprints;
  final String tcpAddr;
  const DomainEndpoint(this.fingerprints, this.tcpAddr);
}

/// Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails
/// closed: a missing/unparseable record, or a `_linkkeys` record with no
/// `fp=` entries, or a `_linkkeys_apis` record with no `tcp=` entry, is an
/// error.
Future<DomainEndpoint> discoverDomainEndpoint(
    DnsResolver dns, String domain) async {
  final anchorName = dnsproto.linkkeysDnsName(domain);
  final anchorTxts = await dns.txtLookup(anchorName);
  List<String>? fingerprints;
  for (final txt in anchorTxts) {
    try {
      final rec = dnsproto.parseLinkKeysTxt(txt);
      if (rec.fingerprints.isNotEmpty) {
        fingerprints = rec.fingerprints;
        break;
      }
    } on DnsParseError {
      // try the next TXT record
    }
  }
  if (fingerprints == null) {
    throw SdkException(SdkExceptionKind.dns,
        'no usable $anchorName TXT record with fp= entries');
  }

  final apisName = dnsproto.linkkeysApisDnsName(domain);
  final apisTxts = await dns.txtLookup(apisName);
  String? tcpAddr;
  for (final txt in apisTxts) {
    try {
      final apis = dnsproto.parseLinkKeysApisTxt(txt);
      if (apis.tcp != null) {
        tcpAddr = apis.tcp;
        break;
      }
    } on DnsParseError {
      // try the next TXT record
    }
  }
  if (tcpAddr == null) {
    throw SdkException(
        SdkExceptionKind.dns, 'no usable $apisName TXT record with tcp= entry');
  }

  return DomainEndpoint(fingerprints, tcpAddr);
}

String _extractHostname(String hostPort) {
  if (hostPort.startsWith('[')) {
    final end = hostPort.indexOf(']');
    if (end != -1) return hostPort.substring(1, end);
  }
  final idx = hostPort.lastIndexOf(':');
  return idx == -1 ? hostPort : hostPort.substring(0, idx);
}

/// The shape of [call]: dial + speak one CSIL-RPC request/response over
/// [endpoint]. Exposed as a typedef solely so tests can override HOW a call
/// is transported -- see [call]'s docs for why this exists and its (tight)
/// bounds.
typedef RpcCaller = Future<Uint8List> Function(Transport transport,
    DomainEndpoint endpoint, String service, String op, Uint8List payload);

/// Send one CSIL-RPC request over a fresh TLS connection to [endpoint] and
/// return the decoded success payload. This is the ONLY call path
/// production code (`complete.dart`) uses; [fetchDomainKeys] and
/// [redeemClaimTicket] accept an optional [RpcCaller] override purely as a
/// **test seam**.
///
/// That override exists for one documented reason: `dart:io`'s TLS stack
/// (BoringSSL) refuses to negotiate a TLS handshake at all when the server
/// presents an Ed25519 certificate (`NO_COMMON_SIGNATURE_ALGORITHMS`,
/// verified empirically against an `openssl`-minted Ed25519 cert before
/// writing this comment) -- unlike the JDK, which the Java reference SDK's
/// flow test relies on to serve a real Ed25519-certificate TLS server in
/// the same process. Since this protocol's TLS pinning REQUIRES an Ed25519
/// server certificate by construction (the pinned fingerprint is a
/// domain's Ed25519 signing key), no in-process flow test can exercise the
/// real TLS handshake path in Dart today. Flow tests therefore use an
/// [RpcCaller] that dials a real TCP socket and speaks real CSIL-RPC
/// framing to a real in-process fake IDP, skipping only the TLS handshake
/// step -- every other production code path (CBOR wire codec, the full
/// `LocalRp`/`Claims`/`Revocation` verification chain, DNS TXT parsing) is
/// exercised unchanged. The TLS pin-check logic itself
/// (`tls_pinning.dart`'s certificate DER parsing and fingerprint
/// comparison) is unit-tested separately, directly against
/// `openssl`-minted Ed25519 certificate bytes, since it cannot be
/// exercised through a live handshake. See the package README's "Known
/// limitations" section.
Future<Uint8List> call(Transport transport, DomainEndpoint endpoint,
    String service, String op, Uint8List payload) async {
  final raw = await transport.dial(endpoint.tcpAddr);
  final hostname = _extractHostname(endpoint.tcpAddr);
  SecureSocket? secure;
  try {
    secure = await tls.connectPinned(raw, hostname, endpoint.fingerprints);
    final request = RpcRequest(service: service, op: op, payload: payload);
    await sendFrame(secure, request.encode());
    final reader = FrameReader(secure);
    final respBytes = await reader.readFrame();
    final resp = RpcResponse.decode(respBytes);

    if (!resp.isOk) {
      throw SdkException.server(resp.status, resp.error ?? 'unknown error');
    }
    return resp.payload;
  } on SdkException {
    rethrow;
  } catch (e) {
    throw SdkException(SdkExceptionKind.transport, '$e', cause: e);
  } finally {
    secure?.destroy();
  }
}

/// Fetch [domain]'s currently-trusted public keys:
/// `DomainKeys/get-domain-keys` over TCP CSIL-RPC, pinned to the domain's
/// DNS `fp=` set, with signing keys pinned directly and encryption keys
/// trusted only via a pinned signing key's vouch. Always also fetches
/// `DomainKeys/get-revocations` for the same domain -- regardless of what
/// the `get-domain-keys` response's `recentRevocationsAvailable` flag says
/// -- and drops any key a quorum-verified sibling revocation certificate
/// targets. `recentRevocationsAvailable` is an optional performance hint a
/// well-behaved IDP may use to signal "you don't even need to ask"; a
/// compromised/malicious or merely buggy IDP could otherwise use its
/// absence to suppress this SDK from ever learning about a revocation,
/// which is exactly the scenario revocation exists to guard against -- so
/// this SDK never uses it to skip the check. A `get-revocations` RPC error
/// (connection failure or response decode failure) is FATAL: this SDK must
/// fail closed rather than silently proceed with a possibly-stale key set
/// an attacker could have engineered by making the endpoint fail. An empty
/// revocation list is normal success (nothing to apply). An empty trusted
/// result (before or after applying revocations) is a fail-closed
/// [SdkException].
Future<List<DomainPublicKey>> fetchDomainKeys(
    Transport transport, DnsResolver dns, String domain,
    {RpcCaller? caller}) async {
  final doCall = caller ?? call;
  final endpoint = await discoverDomainEndpoint(dns, domain);

  final payload = Codec.encodeEmptyRequest(const EmptyRequest());
  final respBytes = await doCall(
      transport, endpoint, 'DomainKeys', 'get-domain-keys', payload);
  final resp = Codec.decodeGetDomainKeysResponse(respBytes);

  var trusted = await dnsproto.trustKeys(resp.keys, endpoint.fingerprints);
  if (trusted.isEmpty) {
    throw SdkException(SdkExceptionKind.noTrustedDomainKeys, domain);
  }

  // Always fetch revocations -- never gated on `recentRevocationsAvailable`
  // (see this function's doc comment). A failure here propagates, i.e. is
  // FATAL: it must never be swallowed to "just proceed unfiltered".
  final since = DateTime.now()
      .toUtc()
      .subtract(const Duration(days: 30))
      .toIso8601String();
  final reqPayload =
      Codec.encodeGetRevocationsRequest(GetRevocationsRequest(since: since));
  final revRespBytes = await doCall(
      transport, endpoint, 'DomainKeys', 'get-revocations', reqPayload);
  final revResp = Codec.decodeGetRevocationsResponse(revRespBytes);
  for (final cert in revResp.revocations) {
    try {
      await revocation.verifyRevocationCertificate(cert, trusted, domain);
      trusted = trusted.where((k) => k.keyId != cert.targetKeyId).toList();
    } catch (_) {
      // certificate didn't meet quorum; key stays trusted
    }
  }

  if (trusted.isEmpty) {
    throw SdkException(SdkExceptionKind.noTrustedDomainKeys, domain);
  }
  return trusted;
}

/// Redeem a claim ticket with [domain]'s IDP:
/// `LocalRp/redeem-claim-ticket` over TCP CSIL-RPC, pinned via the domain's
/// DNS `fp=` set. Unauthenticated at the transport layer (no client cert)
/// -- the redemption request itself is signed with the local RP's signing
/// key, which is the possession proof the server checks.
Future<LocalRpTicketRedemptionResponse> redeemClaimTicket(
    Transport transport,
    DnsResolver dns,
    String domain,
    SignedLocalRpTicketRedemptionRequest signedRequest,
    {RpcCaller? caller}) async {
  final doCall = caller ?? call;
  final endpoint = await discoverDomainEndpoint(dns, domain);
  final payload =
      Codec.encodeSignedLocalRpTicketRedemptionRequest(signedRequest);
  final respBytes = await doCall(
      transport, endpoint, 'LocalRp', 'redeem-claim-ticket', payload);
  return Codec.decodeLocalRpTicketRedemptionResponse(respBytes);
}

/// A [RpcCaller] that dials a real TCP socket and speaks real CSIL-RPC
/// stream framing, but skips the TLS handshake entirely (no pinning, no
/// encryption). **Test-only.** See [call]'s docs for exactly why this
/// exists and what it does and does not cover.
Future<Uint8List> insecureCallForTesting(
    Transport transport,
    DomainEndpoint endpoint,
    String service,
    String op,
    Uint8List payload) async {
  final raw = await transport.dial(endpoint.tcpAddr);
  try {
    final request = RpcRequest(service: service, op: op, payload: payload);
    await sendFrame(raw, request.encode());
    final reader = FrameReader(raw);
    final respBytes = await reader.readFrame();
    final resp = RpcResponse.decode(respBytes);
    if (!resp.isOk) {
      throw SdkException.server(resp.status, resp.error ?? 'unknown error');
    }
    return resp.payload;
  } on SdkException {
    rethrow;
  } catch (e) {
    throw SdkException(SdkExceptionKind.transport, '$e', cause: e);
  } finally {
    raw.destroy();
  }
}
