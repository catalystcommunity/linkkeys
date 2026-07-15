// CSIL-RPC byte-stream (TCP/TLS) carrier framing: a 4-byte big-endian
// unsigned length prefix, then that many bytes of CBOR envelope
// (`csil-rpc-transport.md` section 2.3).
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../errors.dart';

/// Mirrors the Rust/Go/Java reference clients' own cap, so a forged length
/// prefix cannot drive an unbounded allocation.
const int maxFrameSize = 1024 * 1024;

Future<void> sendFrame(Socket out, List<int> data) async {
  final len = data.length;
  final header = Uint8List(4);
  header[0] = (len >> 24) & 0xff;
  header[1] = (len >> 16) & 0xff;
  header[2] = (len >> 8) & 0xff;
  header[3] = len & 0xff;
  out.add(header);
  out.add(data);
  await out.flush();
}

/// A small buffering reader over a byte [Stream], used so [readFrame] can
/// read an exact number of bytes without racing multiple listeners on the
/// same socket stream.
class FrameReader {
  final Stream<List<int>> _stream;
  StreamIterator<List<int>>? _iter;
  Uint8List _buffer = Uint8List(0);

  FrameReader(this._stream);

  Future<Uint8List> _readExact(int n) async {
    _iter ??= StreamIterator(_stream);
    while (_buffer.length < n) {
      if (!await _iter!.moveNext()) {
        throw SdkException(SdkExceptionKind.transport,
            'connection closed before expected bytes arrived');
      }
      final chunk = _iter!.current;
      final combined = Uint8List(_buffer.length + chunk.length);
      combined.setAll(0, _buffer);
      combined.setAll(_buffer.length, chunk);
      _buffer = combined;
    }
    final out = Uint8List.sublistView(_buffer, 0, n);
    _buffer = Uint8List.sublistView(_buffer, n);
    return out;
  }

  Future<Uint8List> readFrame() async {
    final lenBuf = await _readExact(4);
    final len =
        (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
    if (len < 0 || len > maxFrameSize) {
      throw SdkException(SdkExceptionKind.protocol,
          'peer frame too large ($len bytes, max $maxFrameSize)');
    }
    return _readExact(len);
  }
}
