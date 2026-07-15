// Default [DnsResolver]: a minimal hand-rolled DNS TXT client speaking raw
// UDP (with TCP fallback on a truncated response), reading nameservers from
// `/etc/resolv.conf`.
//
// ## Why hand-rolled instead of a pub package
//
// `dart:io` has no DNS TXT lookup at all (`InternetAddress.lookup` only
// returns A/AAAA records) -- unlike Java (JNDI's built-in DNS provider) or
// Node (`dns.resolveTxt`), Dart's stdlib gives this SDK nothing to build on
// for the design doc's mandatory `_linkkeys`/`_linkkeys_apis` TXT lookups.
// The design doc allows two paths: (a) a minimal hand-rolled UDP DNS TXT
// query, bounded in scope, or (b) a pub DNS package IF it is genuinely
// well-maintained (health-checked the same way as the `cryptography_plus`
// crypto choice; see the package README).
//
// Every pub.dev DNS-lookup candidate surveyed failed that health check:
//   * `dns_client` -- its listed GitHub repository no longer resolves at all
//     (a 404 on the GitHub API), and its version history is a 5+ year silent
//     gap (2021 to 2026) followed by a one-day release burst with no
//     activity since. A README's homepage link that has gone dead is a hard
//     stop for a security-relevant dependency.
//   * `dnsolve` -- resolves via native FFI (`res_query`/platform resolver
//     bindings) rather than a portable DNS client, and is a much narrower
//     dependency surface than this SDK's ~150-line bounded need justifies.
//   * `basic_utils` -- DNS lookup is one small corner of a large,
//     general-purpose "kitchen sink" utility package; pulling in the whole
//     package for TXT lookups violates AGENTS.md's "every dependency is a
//     liability."
//   * `multicast_dns` -- mDNS (`.local` LAN discovery), not unicast DNS;
//     wrong protocol entirely.
//
// A single-question, TXT-only DNS client with optional TCP fallback on
// truncation is bounded, auditable, and small enough that hand-rolling it is
// less risk than taking on any of the above. This mirrors the same
// calculus Go/Rust/Java made for their own gaps in this protocol (Go/Rust
// hand-write CBOR before a generated client exists; Java hand-rolls HKDF).
//
// Per the design doc's "Decided" section: resolver spoofing on a LAN is an
// accepted, documented tradeoff for this mode; operators wanting hardening
// can inject their own [DnsResolver] (e.g. a DoH client) instead of this
// one -- the seam is injectable specifically so that choice is the
// integrating app's, not this SDK's.
library;

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import '../errors.dart';
import 'dns_resolver.dart';

class SystemDnsResolver implements DnsResolver {
  final List<String> _servers;
  final Duration _timeout;
  final int _port;

  /// [servers] entries are plain IP addresses (IPv4 or IPv6). If omitted,
  /// nameservers are read from `/etc/resolv.conf`.
  SystemDnsResolver({List<String>? servers, Duration? timeout, int port = 53})
      : _servers = servers ?? _readResolvConf(),
        _timeout = timeout ?? const Duration(seconds: 5),
        _port = port;

  static List<String> _readResolvConf() {
    const path = '/etc/resolv.conf';
    try {
      final lines = File(path).readAsLinesSync();
      final servers = <String>[];
      for (final raw in lines) {
        final line = raw.trim();
        if (line.startsWith('#') || line.startsWith(';')) continue;
        if (!line.startsWith('nameserver')) continue;
        final parts = line.split(RegExp(r'\s+'));
        if (parts.length >= 2) servers.add(parts[1]);
      }
      return servers;
    } catch (_) {
      return const [];
    }
  }

  @override
  Future<List<String>> txtLookup(String name) async {
    if (_servers.isEmpty) {
      throw SdkException(SdkExceptionKind.dns,
          '$name: no DNS servers configured (checked /etc/resolv.conf)');
    }

    final id = Random.secure().nextInt(0x10000);
    final query = _buildTxtQuery(id, name);

    Object? lastError;
    for (final server in _servers) {
      try {
        final response = await _queryUdp(server, _port, query, _timeout);
        final parsed = _parseResponse(response, id);
        if (parsed.truncated) {
          final tcpResponse = await _queryTcp(server, _port, query, _timeout);
          return _parseResponse(tcpResponse, id).txtRecords;
        }
        return parsed.txtRecords;
      } catch (e) {
        lastError = e;
        continue;
      }
    }
    throw SdkException(
        SdkExceptionKind.dns, '$name: all DNS servers failed: $lastError',
        cause: lastError);
  }

  // -----------------------------------------------------------------
  // Wire query construction (RFC 1035 section 4.1)
  // -----------------------------------------------------------------

  static Uint8List _buildTxtQuery(int id, String name) {
    final out = BytesBuilder();
    out.addByte((id >> 8) & 0xff);
    out.addByte(id & 0xff);
    // Flags: standard query, recursion desired.
    out.addByte(0x01);
    out.addByte(0x00);
    // QDCOUNT = 1, ANCOUNT/NSCOUNT/ARCOUNT = 0.
    out.addByte(0x00);
    out.addByte(0x01);
    out.addByte(0x00);
    out.addByte(0x00);
    out.addByte(0x00);
    out.addByte(0x00);
    out.addByte(0x00);
    out.addByte(0x00);

    for (final label in name.split('.')) {
      if (label.isEmpty) continue;
      final bytes = _asciiBytes(label);
      if (bytes.length > 63) {
        throw SdkException(
            SdkExceptionKind.invalidInput, 'DNS label too long: $label');
      }
      out.addByte(bytes.length);
      out.add(bytes);
    }
    out.addByte(0x00); // root label

    // QTYPE = 16 (TXT)
    out.addByte(0x00);
    out.addByte(0x10);
    // QCLASS = 1 (IN)
    out.addByte(0x00);
    out.addByte(0x01);

    return out.toBytes();
  }

  static Uint8List _asciiBytes(String s) => Uint8List.fromList(s.codeUnits);

  // -----------------------------------------------------------------
  // Transport: UDP with a TCP fallback on truncation
  // -----------------------------------------------------------------

  static Future<Uint8List> _queryUdp(
      String server, int port, Uint8List query, Duration timeout) async {
    final serverAddr = InternetAddress(server);
    final bindAddr = serverAddr.type == InternetAddressType.IPv6
        ? InternetAddress.anyIPv6
        : InternetAddress.anyIPv4;
    final socket = await RawDatagramSocket.bind(bindAddr, 0);
    try {
      socket.send(query, InternetAddress(server), port);
      final completer = Completer<Uint8List>();
      late StreamSubscription sub;
      sub = socket.listen((event) {
        if (event == RawSocketEvent.read) {
          final datagram = socket.receive();
          if (datagram != null && !completer.isCompleted) {
            completer.complete(datagram.data);
          }
        }
      });
      try {
        return await completer.future.timeout(timeout);
      } finally {
        await sub.cancel();
      }
    } finally {
      socket.close();
    }
  }

  static Future<Uint8List> _queryTcp(
      String server, int port, Uint8List query, Duration timeout) async {
    final socket = await Socket.connect(server, port, timeout: timeout);
    try {
      final framed = Uint8List(2 + query.length);
      framed[0] = (query.length >> 8) & 0xff;
      framed[1] = query.length & 0xff;
      framed.setAll(2, query);
      socket.add(framed);
      await socket.flush();

      final buffer = BytesBuilder();
      final completer = Completer<Uint8List>();
      late StreamSubscription sub;
      sub = socket.listen(
        (data) {
          buffer.add(data);
          final have = buffer.toBytes();
          if (have.length >= 2) {
            final len = (have[0] << 8) | have[1];
            if (have.length >= 2 + len) {
              if (!completer.isCompleted) {
                completer.complete(Uint8List.sublistView(have, 2, 2 + len));
              }
            }
          }
        },
        onError: (Object e) {
          if (!completer.isCompleted) completer.completeError(e);
        },
        onDone: () {
          if (!completer.isCompleted) {
            completer.completeError(SdkException(
                SdkExceptionKind.dns, 'TCP DNS connection closed early'));
          }
        },
      );
      try {
        return await completer.future.timeout(timeout);
      } finally {
        await sub.cancel();
      }
    } finally {
      socket.destroy();
    }
  }

  // -----------------------------------------------------------------
  // Wire response parsing (RFC 1035 sections 4.1, 3.3.14)
  // -----------------------------------------------------------------

  static _ParsedResponse _parseResponse(Uint8List data, int expectedId) {
    if (data.length < 12) {
      throw SdkException(SdkExceptionKind.protocol, 'DNS response too short');
    }
    final id = (data[0] << 8) | data[1];
    if (id != expectedId) {
      throw SdkException(SdkExceptionKind.protocol, 'DNS response id mismatch');
    }
    final flags = (data[2] << 8) | data[3];
    final truncated = (flags & 0x0200) != 0;
    final rcode = flags & 0x000f;

    final qdcount = (data[4] << 8) | data[5];
    final ancount = (data[6] << 8) | data[7];

    var pos = 12;
    for (var i = 0; i < qdcount; i++) {
      pos = _skipName(data, pos);
      pos += 4; // QTYPE + QCLASS
    }

    if (rcode != 0) {
      // NXDOMAIN (3) or any other failure rcode: no records for this name.
      // Fail-closed callers (RpcClient) treat an empty TXT list the same as
      // "no usable record" -- absence is not itself an error at this layer.
      return _ParsedResponse(const [], truncated);
    }

    final txtRecords = <String>[];
    for (var i = 0; i < ancount; i++) {
      if (pos >= data.length) break;
      pos = _skipName(data, pos);
      if (pos + 10 > data.length) break;
      final type = (data[pos] << 8) | data[pos + 1];
      pos += 2;
      pos += 2; // CLASS
      pos += 4; // TTL
      final rdlength = (data[pos] << 8) | data[pos + 1];
      pos += 2;
      final rdataStart = pos;
      if (type == 16) {
        // TXT: one or more length-prefixed character-strings; concatenate.
        final sb = StringBuffer();
        var rp = rdataStart;
        final rdataEnd = rdataStart + rdlength;
        while (rp < rdataEnd) {
          final len = data[rp];
          rp += 1;
          if (rp + len > data.length) break;
          sb.write(String.fromCharCodes(data.sublist(rp, rp + len)));
          rp += len;
        }
        txtRecords.add(sb.toString());
      }
      pos = rdataStart + rdlength;
    }

    return _ParsedResponse(txtRecords, truncated);
  }

  /// Skip a DNS NAME field (a sequence of length-prefixed labels terminated
  /// by a zero-length label, or a compression pointer, or labels followed
  /// by a pointer) and return the position just past it. Does not resolve
  /// pointer targets -- this SDK never needs the owner name's contents,
  /// only correct alignment for the fields that follow.
  static int _skipName(Uint8List data, int pos) {
    var p = pos;
    while (p < data.length) {
      final len = data[p];
      if ((len & 0xc0) == 0xc0) {
        // Compression pointer: 2 bytes total, terminates the name field.
        return p + 2;
      }
      if (len == 0) {
        return p + 1;
      }
      p += 1 + len;
    }
    throw SdkException(
        SdkExceptionKind.protocol, 'DNS name field ran past end of message');
  }
}

class _ParsedResponse {
  final List<String> txtRecords;
  final bool truncated;
  const _ParsedResponse(this.txtRecords, this.truncated);
}
