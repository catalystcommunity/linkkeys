// Timestamp helpers. Wire timestamps are CSIL `timestamp` values (CBOR tag 0
// around RFC 3339 UTC text, see `wire/cbor.dart`); in memory they are UTC
// [DateTime] values. A signed tuple payload carries a timestamp as whole
// Unix seconds (a CBOR integer), see [Rfc3339.signedSeconds].
library;

import 'errors.dart';
import 'wire/cbor.dart';

class Rfc3339 {
  Rfc3339._();

  /// Parse strict RFC 3339 text (with an explicit offset) into a UTC
  /// [DateTime]. Throws a [LocalRpError] of kind `badTimestamp`.
  static DateTime parse(String field, String s) {
    try {
      return Cbor.parseTimestamp(s);
    } on CborDecodeException catch (e) {
      throw LocalRpError(LocalRpErrorKind.badTimestamp, '$field: ${e.message}');
    }
  }

  /// Formats an instant as `yyyy-MM-ddTHH:mm:ssZ` (UTC, fraction dropped).
  static String format(DateTime instant) =>
      Cbor.formatTimestamp(wholeSeconds(instant));

  /// [instant] in UTC with its fraction of a second dropped (rounded down).
  /// Use it for a timestamp that will be signed.
  static DateTime wholeSeconds(DateTime instant) {
    final u = instant.toUtc();
    return u.subtract(
        Duration(milliseconds: u.millisecond, microseconds: u.microsecond));
  }

  /// The signed form of [instant]: whole Unix seconds. Returns `null` when
  /// [instant] has a fraction of a second; such a timestamp was never signed
  /// (do not round it).
  static int? signedSeconds(DateTime instant) {
    final us = instant.microsecondsSinceEpoch;
    if (us % 1000000 != 0) return null;
    return us ~/ 1000000;
  }
}
