// CSIL-RPC request/response envelopes
// (`~/repos/catalystcommunity/csilgen/docs/csil-rpc-transport.md`).
// Hand-written, pending a csilgen Dart target -- no generated CSIL-RPC
// client exists for Dart, so this SDK hand-implements exactly the envelope
// shape every other language's generated client also produces, verified
// against the same conventions the TypeScript/Java SDKs' vendored/hand-
// written RPC envelopes implement.
//
// Only the byte-stream (TCP/TLS) carrier framing is needed here: a 4-byte
// big-endian length prefix followed by the CBOR envelope (see
// `stream_framing.dart`).
library;

import 'dart:typed_data';

import '../errors.dart';
import '../wire/cbor.dart';

const int rpcVersion = 1;
const int _tagEncodedCbor = 24;

/// Transport status registry (subset this SDK observes). `0` = a typed
/// reply is present.
class RpcStatus {
  RpcStatus._();
  static const int ok = 0;
  static const int malformedEnvelope = 1;
  static const int unknownServiceOrOp = 2;
  static const int unauthenticated = 3;
  static const int forbidden = 4;
  static const int versionUnsupported = 5;
  static const int internal = 6;
  static const int unavailable = 7;
  static const int deadlineExceeded = 8;
}

CborValue _tag24(List<int> payload) =>
    Cbor.vtag(_tagEncodedCbor, Cbor.vbytes(payload));

Uint8List _untag24(CborValue v) {
  if (v is CborTag && v.tag == _tagEncodedCbor && v.value is CborBytes) {
    return (v.value as CborBytes).value;
  }
  throw SdkException(
      SdkExceptionKind.protocol, 'expected a tag-24 (encoded-cbor) payload');
}

void _checkVersion(int v) {
  if (v != rpcVersion) {
    throw SdkException(
        SdkExceptionKind.protocol, 'unsupported transport version $v');
  }
}

/// A CSIL-RPC request (client -> server).
class RpcRequest {
  final String service;
  final String op;
  final int? id;
  final Uint8List payload;
  final String? auth;

  const RpcRequest(
      {required this.service,
      required this.op,
      this.id,
      required this.payload,
      this.auth});

  Uint8List encode() {
    final entries = <CborMapEntry>[];
    Cbor.putText(entries, 'service', service);
    Cbor.putText(entries, 'op', op);
    entries.add(Cbor.entry('v', Cbor.vint(rpcVersion)));
    entries.add(Cbor.entry('payload', _tag24(payload)));
    if (id != null) entries.add(Cbor.entry('id', Cbor.vint(id!)));
    Cbor.putOptText(entries, 'auth', auth);
    return Cbor.encode(Cbor.vmap(entries));
  }

  static RpcRequest decode(Uint8List bytes) {
    final v = Cbor.decode(bytes);
    _checkVersion(Cbor.asInt(Cbor.require(v, 'v')));
    final payload = _untag24(Cbor.require(v, 'payload'));
    final service = Cbor.requireText(v, 'service');
    final op = Cbor.requireText(v, 'op');
    final idField = Cbor.mapGet(v, 'id');
    final id = idField == null ? null : Cbor.asInt(idField);
    final auth = Cbor.optText(v, 'auth');
    return RpcRequest(
        service: service, op: op, id: id, payload: payload, auth: auth);
  }
}

/// A CSIL-RPC response (server -> client).
class RpcResponse {
  final int? id;
  final int status;
  final String? variant;
  final String? error;
  final Uint8List payload;

  const RpcResponse(
      {this.id,
      required this.status,
      this.variant,
      this.error,
      required this.payload});

  factory RpcResponse.ok(String? variant, Uint8List payload) =>
      RpcResponse(status: RpcStatus.ok, variant: variant, payload: payload);

  factory RpcResponse.transportError(int status, String message) =>
      RpcResponse(status: status, error: message, payload: Uint8List(0));

  bool get isOk => status == RpcStatus.ok;

  Uint8List encode() {
    final entries = <CborMapEntry>[];
    entries.add(Cbor.entry('v', Cbor.vint(rpcVersion)));
    entries.add(Cbor.entry('status', Cbor.vint(status)));
    entries.add(Cbor.entry('payload', _tag24(payload)));
    if (id != null) entries.add(Cbor.entry('id', Cbor.vint(id!)));
    Cbor.putOptText(entries, 'variant', variant);
    Cbor.putOptText(entries, 'error', error);
    return Cbor.encode(Cbor.vmap(entries));
  }

  static RpcResponse decode(Uint8List bytes) {
    final v = Cbor.decode(bytes);
    _checkVersion(Cbor.asInt(Cbor.require(v, 'v')));
    final payloadField = Cbor.mapGet(v, 'payload');
    final payload =
        payloadField == null ? Uint8List(0) : _untag24(payloadField);
    final status = Cbor.asInt(Cbor.require(v, 'status'));
    final idField = Cbor.mapGet(v, 'id');
    final id = idField == null ? null : Cbor.asInt(idField);
    final variant = Cbor.optText(v, 'variant');
    final error = Cbor.optText(v, 'error');
    return RpcResponse(
        id: id,
        status: status,
        variant: variant,
        error: error,
        payload: payload);
  }
}
