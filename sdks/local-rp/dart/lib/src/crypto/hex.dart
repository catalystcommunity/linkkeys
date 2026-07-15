// Lowercase hex encode/decode helpers -- no dependency needed, this is a
// handful of lines over dart:typed_data.
library;

import 'dart:typed_data';

class Hex {
  Hex._();

  static const _digits = '0123456789abcdef';

  static String encode(List<int> bytes) {
    final out = StringBuffer();
    for (final b in bytes) {
      out.write(_digits[(b >> 4) & 0xf]);
      out.write(_digits[b & 0xf]);
    }
    return out.toString();
  }

  static Uint8List decode(String hex) {
    final s = hex.trim();
    if (s.length % 2 != 0) {
      throw FormatException('hex string must have an even length: $s');
    }
    final out = Uint8List(s.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      final hi = _digit(s.codeUnitAt(i * 2));
      final lo = _digit(s.codeUnitAt(i * 2 + 1));
      out[i] = (hi << 4) | lo;
    }
    return out;
  }

  static int _digit(int codeUnit) {
    if (codeUnit >= 0x30 && codeUnit <= 0x39) return codeUnit - 0x30;
    if (codeUnit >= 0x61 && codeUnit <= 0x66) return codeUnit - 0x61 + 10;
    if (codeUnit >= 0x41 && codeUnit <= 0x46) return codeUnit - 0x41 + 10;
    throw FormatException(
        'invalid hex digit: ${String.fromCharCode(codeUnit)}');
  }
}
