// Default [Transport]: a plain [Socket] dialer, gated only by [AddressPolicy].
library;

import 'dart:io';

import '../errors.dart';
import 'address_policy.dart';
import 'transport.dart';

class StdTransport implements Transport {
  final AddressPolicy policy;
  final Duration connectTimeout;

  StdTransport({
    this.policy = AddressPolicy.permissive,
    this.connectTimeout = const Duration(seconds: 10),
  });

  @override
  Future<Socket> dial(String hostPort) async {
    final idx = hostPort.lastIndexOf(':');
    if (idx < 0) {
      throw SdkException(SdkExceptionKind.transport, '$hostPort: missing port');
    }
    final host = hostPort.substring(0, idx);
    final port = int.tryParse(hostPort.substring(idx + 1));
    if (port == null) {
      throw SdkException(SdkExceptionKind.transport, '$hostPort: invalid port');
    }

    List<InternetAddress> addrs;
    try {
      addrs = await InternetAddress.lookup(host);
    } on SocketException catch (e) {
      throw SdkException(
          SdkExceptionKind.transport, '$hostPort: resolve failed: ${e.message}',
          cause: e);
    }

    Object? lastError;
    for (final addr in addrs) {
      if (policy == AddressPolicy.publicOnly && _isNonPublic(addr)) {
        lastError = SdkException(SdkExceptionKind.transport,
            '${addr.address}: refusing non-public address under AddressPolicy.publicOnly');
        continue;
      }
      try {
        return await Socket.connect(addr, port, timeout: connectTimeout);
      } catch (e) {
        lastError =
            SdkException(SdkExceptionKind.transport, '$hostPort: $e', cause: e);
      }
    }
    if (lastError != null) {
      // ignore: only_throw_errors
      throw lastError;
    }
    throw SdkException(
        SdkExceptionKind.transport, '$hostPort: no address resolved');
  }

  /// True for loopback/private/link-local/CGNAT/documentation/unspecified
  /// addresses. Only consulted under [AddressPolicy.publicOnly], never by
  /// default.
  static bool _isNonPublic(InternetAddress addr) {
    if (addr.isLoopback) return true;
    final a = addr.rawAddress;
    if (a.length == 4) {
      final o0 = a[0], o1 = a[1], o2 = a[2], o3 = a[3];
      if (o0 == 0) return true; // "this network" / unspecified
      if (o0 == 10) return true; // RFC 1918
      if (o0 == 172 && (o1 & 0xf0) == 16) return true; // RFC 1918
      if (o0 == 192 && o1 == 168) return true; // RFC 1918
      if (o0 == 169 && o1 == 254) return true; // link-local
      if (o0 == 100 && (o1 & 0xc0) == 0x40) return true; // CGNAT 100.64/10
      if (o0 == 192 && o1 == 0 && o2 == 2) return true; // documentation
      if (o0 == 198 && o1 == 51 && o2 == 100) return true; // documentation
      if (o0 == 203 && o1 == 0 && o2 == 113) return true; // documentation
      if (o0 == 224) return true; // multicast (224.0.0.0/8, coarse check)
      if (o0 == 255 && o1 == 255 && o2 == 255 && o3 == 255) return true;
    } else if (a.length == 16) {
      final allZero = a.every((b) => b == 0);
      if (allZero) return true; // ::
      if ((a[0] & 0xfe) == 0xfc) return true; // ULA fc00::/7
      if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) {
        return true; // link-local fe80::/10
      }
      if (a[0] == 0xff) return true; // multicast
    }
    return false;
  }
}
