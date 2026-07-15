// Hand-written minimal canonical CBOR (RFC 8949) codec.
//
// This library is hand-written, pending a csilgen Dart target (see the
// csilgen request filed alongside this SDK,
// `~/repos/catalystcommunity/csilgen/docs/csilgen-requests/`); everything in
// `lib/src/wire/` hand-reproduces exactly the wire structures the DNS-less
// local-RP protocol needs, verified byte-for-byte against
// `sdks/local-rp/conformance/` -- the same approach the Go/TypeScript/Java
// reference SDKs took before a generated client existed for them (see
// `sdks/local-rp/java/.../wire/Cbor.java`, this SDK's direct model).
//
// Only the subset CSIL-RPC and this protocol's structures need is
// implemented: unsigned/negative integers, byte strings, text strings,
// arrays, maps, and tags. Maps are emitted with RFC 8949 section 4.2.1 core
// deterministic encoding -- entries sorted by the bytewise lexicographic
// order of their *encoded* keys -- exactly mirroring the Rust reference's
// generated codec (which bakes this same order in at codegen time) and the
// Java SDK's `Cbor.writeCanonicalMap`.
//
// Indefinite-length items are rejected on decode (this protocol never uses
// them); decoding a value also rejects trailing bytes, since a wire envelope
// is always exactly one CBOR data item.
library;

import 'dart:convert';
import 'dart:typed_data';

/// The CBOR value model used by this codec.
sealed class CborValue {
  const CborValue();
}

class CborInt extends CborValue {
  final int value;
  const CborInt(this.value);
}

class CborBytes extends CborValue {
  final Uint8List value;
  const CborBytes(this.value);
}

class CborText extends CborValue {
  final String value;
  const CborText(this.value);
}

class CborArray extends CborValue {
  final List<CborValue> items;
  const CborArray(this.items);
}

/// A map entry. Order in the source list is irrelevant: [Cbor.encode] always
/// sorts by encoded-key bytes.
class CborMapEntry {
  final CborValue key;
  final CborValue value;
  const CborMapEntry(this.key, this.value);
}

class CborMap extends CborValue {
  final List<CborMapEntry> entries;
  const CborMap(this.entries);
}

class CborTag extends CborValue {
  final int tag;
  final CborValue value;
  const CborTag(this.tag, this.value);
}

class CborBool extends CborValue {
  final bool value;
  const CborBool(this.value);
}

class CborNull extends CborValue {
  const CborNull();
}

/// Thrown when decoding fails: malformed input, unsupported major type,
/// indefinite lengths, or trailing bytes after the top-level item.
class CborDecodeException implements Exception {
  final String message;
  CborDecodeException(this.message);

  @override
  String toString() => 'CborDecodeException: $message';
}

/// Hand-written minimal canonical CBOR (RFC 8949) encode/decode.
class Cbor {
  Cbor._();

  static CborValue vint(int v) => CborInt(v);
  static CborValue vbytes(List<int> v) => CborBytes(Uint8List.fromList(v));
  static CborValue vtext(String v) => CborText(v);
  static CborValue varray(List<CborValue> v) => CborArray(v);
  static CborValue vmap(List<CborMapEntry> v) => CborMap(v);
  static CborValue vtag(int tag, CborValue v) => CborTag(tag, v);
  static CborValue vbool(bool v) => CborBool(v);
  static CborValue vnull() => const CborNull();

  /// A map entry keyed by a CBOR text string -- the only key shape this
  /// protocol uses.
  static CborMapEntry entry(String key, CborValue value) =>
      CborMapEntry(vtext(key), value);

  /// Build a definite-length CBOR array (major type 4) of pre-built items, in
  /// order -- the wire shape of every domain-separated "tuple" this SDK needs
  /// to reproduce for house constructions that predate CSIL's envelope
  /// pattern (revocation certificates, claim signatures): a fixed-arity array
  /// built from a Rust tuple via `ciborium::ser::into_writer`, never a map.
  /// Order is significant here (unlike [vmap], which always sorts) because
  /// these are positional tuples, not maps.
  static CborValue tuple(List<CborValue> items) => varray(items);

  /// `Option<&str>` encoded positionally within a [tuple]: `Some(s)` as a
  /// text string, `None` (Dart `null`) as CBOR null -- matching how
  /// serde/ciborium serializes an `Option` field inside a tuple.
  static CborValue optTextItem(String? s) => s == null ? vnull() : vtext(s);

  static void putText(List<CborMapEntry> entries, String key, String value) {
    entries.add(entry(key, vtext(value)));
  }

  static void putOptText(
      List<CborMapEntry> entries, String key, String? value) {
    if (value != null) entries.add(entry(key, vtext(value)));
  }

  static void putBytes(
      List<CborMapEntry> entries, String key, List<int> value) {
    entries.add(entry(key, vbytes(value)));
  }

  static void putOptBytes(
      List<CborMapEntry> entries, String key, List<int>? value) {
    if (value != null) entries.add(entry(key, vbytes(value)));
  }

  static void putBool(List<CborMapEntry> entries, String key, bool value) {
    entries.add(entry(key, vbool(value)));
  }

  static void putOptBool(List<CborMapEntry> entries, String key, bool? value) {
    if (value != null) entries.add(entry(key, vbool(value)));
  }

  // -----------------------------------------------------------------
  // Encoding
  // -----------------------------------------------------------------

  static Uint8List encode(CborValue v) {
    final out = BytesBuilder(copy: false);
    _writeValue(v, out);
    return out.toBytes();
  }

  static void _writeHead(BytesBuilder out, int major, int n) {
    final mt = (major & 0x7) << 5;
    if (n < 0) {
      throw ArgumentError('negative CBOR length/argument: $n');
    }
    if (n < 24) {
      out.addByte(mt | n);
    } else if (n <= 0xff) {
      out.addByte(mt | 24);
      out.addByte(n);
    } else if (n <= 0xffff) {
      out.addByte(mt | 25);
      out.addByte((n >> 8) & 0xff);
      out.addByte(n & 0xff);
    } else if (n <= 0xffffffff) {
      out.addByte(mt | 26);
      out.addByte((n >> 24) & 0xff);
      out.addByte((n >> 16) & 0xff);
      out.addByte((n >> 8) & 0xff);
      out.addByte(n & 0xff);
    } else {
      out.addByte(mt | 27);
      for (var shift = 56; shift >= 0; shift -= 8) {
        out.addByte((n >> shift) & 0xff);
      }
    }
  }

  static void _writeValue(CborValue v, BytesBuilder out) {
    switch (v) {
      case CborInt i:
        if (i.value >= 0) {
          _writeHead(out, 0, i.value);
        } else {
          _writeHead(out, 1, -1 - i.value);
        }
      case CborBytes b:
        _writeHead(out, 2, b.value.length);
        out.add(b.value);
      case CborText t:
        final utf8Bytes = utf8.encode(t.value);
        _writeHead(out, 3, utf8Bytes.length);
        out.add(utf8Bytes);
      case CborArray a:
        _writeHead(out, 4, a.items.length);
        for (final item in a.items) {
          _writeValue(item, out);
        }
      case CborMap m:
        _writeCanonicalMap(m, out);
      case CborTag tg:
        _writeHead(out, 6, tg.tag);
        _writeValue(tg.value, out);
      case CborBool bo:
        out.addByte(bo.value ? 0xf5 : 0xf4);
      case CborNull _:
        out.addByte(0xf6);
    }
  }

  static void _writeCanonicalMap(CborMap m, BytesBuilder out) {
    final keyBytes = <Uint8List>[];
    final valBytes = <Uint8List>[];
    for (final e in m.entries) {
      keyBytes.add(encode(e.key));
      valBytes.add(encode(e.value));
    }
    final order = List<int>.generate(m.entries.length, (i) => i);
    order.sort((x, y) => _compareBytes(keyBytes[x], keyBytes[y]));

    _writeHead(out, 5, m.entries.length);
    for (final idx in order) {
      out.add(keyBytes[idx]);
      out.add(valBytes[idx]);
    }
  }

  /// Bytewise unsigned lexicographic comparison; a shorter run that is a
  /// prefix of the longer sorts first -- RFC 8949 section 4.2.1's rule.
  static int _compareBytes(Uint8List a, Uint8List b) {
    final n = a.length < b.length ? a.length : b.length;
    for (var i = 0; i < n; i++) {
      final diff = a[i] - b[i];
      if (diff != 0) return diff;
    }
    return a.length - b.length;
  }

  // -----------------------------------------------------------------
  // Decoding
  // -----------------------------------------------------------------

  /// Decode a single CBOR data item from [data]. An envelope is always
  /// exactly one self-contained CBOR item, so trailing bytes are rejected
  /// rather than silently ignored.
  static CborValue decode(Uint8List data) {
    final r = _Reader(data);
    final v = r.readValue();
    if (r.pos != data.length) {
      throw CborDecodeException(
          'trailing bytes after CBOR item: ${data.length - r.pos} byte(s)');
    }
    return v;
  }

  // -----------------------------------------------------------------
  // Map navigation helpers (decode side)
  // -----------------------------------------------------------------

  static CborValue? mapGet(CborValue map, String key) {
    if (map is! CborMap) return null;
    for (final e in map.entries) {
      if (e.key is CborText && (e.key as CborText).value == key) {
        return e.value;
      }
    }
    return null;
  }

  static CborValue require(CborValue map, String key) {
    final v = mapGet(map, key);
    if (v == null) {
      throw CborDecodeException("missing required field '$key'");
    }
    return v;
  }

  static String asText(CborValue v) {
    if (v is CborText) return v.value;
    throw CborDecodeException('expected a CBOR text string, got $v');
  }

  static Uint8List asBytes(CborValue v) {
    if (v is CborBytes) return v.value;
    throw CborDecodeException('expected a CBOR byte string, got $v');
  }

  static bool asBool(CborValue v) {
    if (v is CborBool) return v.value;
    throw CborDecodeException('expected a CBOR bool, got $v');
  }

  static int asInt(CborValue v) {
    if (v is CborInt) return v.value;
    throw CborDecodeException('expected a CBOR integer, got $v');
  }

  static List<CborValue> asArray(CborValue v) {
    if (v is CborArray) return v.items;
    throw CborDecodeException('expected a CBOR array, got $v');
  }

  static String requireText(CborValue map, String key) =>
      asText(require(map, key));

  static Uint8List requireBytes(CborValue map, String key) =>
      asBytes(require(map, key));

  static String? optText(CborValue map, String key) {
    final v = mapGet(map, key);
    return v == null ? null : asText(v);
  }

  static Uint8List? optBytes(CborValue map, String key) {
    final v = mapGet(map, key);
    return v == null ? null : asBytes(v);
  }

  static bool? optBool(CborValue map, String key) {
    final v = mapGet(map, key);
    return v == null ? null : asBool(v);
  }
}

class _Reader {
  final Uint8List data;
  int pos = 0;

  _Reader(this.data);

  int _readByteUnsigned() {
    if (pos >= data.length) {
      throw CborDecodeException('unexpected end of CBOR input');
    }
    return data[pos++];
  }

  Uint8List _take(int n) {
    if (n < 0) {
      throw CborDecodeException('CBOR length out of range: $n');
    }
    if (pos + n > data.length) {
      throw CborDecodeException('unexpected end of CBOR input');
    }
    final out = Uint8List.sublistView(data, pos, pos + n);
    pos += n;
    return out;
  }

  int _readArgument(int ai) {
    if (ai < 24) return ai;
    switch (ai) {
      case 24:
        return _readByteUnsigned();
      case 25:
        return (_readByteUnsigned() << 8) | _readByteUnsigned();
      case 26:
        var v = 0;
        for (var i = 0; i < 4; i++) {
          v = (v << 8) | _readByteUnsigned();
        }
        return v;
      case 27:
        var v = 0;
        for (var i = 0; i < 8; i++) {
          v = (v << 8) | _readByteUnsigned();
        }
        return v;
      default:
        throw CborDecodeException(
            'unsupported CBOR additional info $ai (indefinite lengths are not allowed)');
    }
  }

  CborValue readValue() {
    final head = _readByteUnsigned();
    final major = head >> 5;
    final ai = head & 0x1f;
    switch (major) {
      case 0:
        return Cbor.vint(_readArgument(ai));
      case 1:
        return Cbor.vint(-1 - _readArgument(ai));
      case 2:
        return Cbor.vbytes(_take(_readArgument(ai)));
      case 3:
        return Cbor.vtext(utf8.decode(_take(_readArgument(ai))));
      case 4:
        final n = _readArgument(ai);
        final items = <CborValue>[];
        for (var i = 0; i < n; i++) {
          items.add(readValue());
        }
        return Cbor.varray(items);
      case 5:
        final n = _readArgument(ai);
        final entries = <CborMapEntry>[];
        for (var i = 0; i < n; i++) {
          final k = readValue();
          final v = readValue();
          entries.add(CborMapEntry(k, v));
        }
        return Cbor.vmap(entries);
      case 6:
        return Cbor.vtag(_readArgument(ai), readValue());
      case 7:
        if (ai == 20) return Cbor.vbool(false);
        if (ai == 21) return Cbor.vbool(true);
        if (ai == 22) return Cbor.vnull();
        throw CborDecodeException('unsupported CBOR simple value with ai=$ai');
      default:
        throw CborDecodeException('unsupported CBOR major type $major');
    }
  }
}
