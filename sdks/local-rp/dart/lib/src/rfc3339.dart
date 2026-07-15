// RFC3339 timestamp parse/format helpers. Parsing accepts both the `Z` and
// `+00:00` UTC-offset spellings (conformance vectors use the latter; this
// SDK's own output uses the former) -- both are valid RFC3339 and Dart's
// `DateTime.parse` accepts either.
library;

import 'errors.dart';

class Rfc3339 {
  Rfc3339._();

  static DateTime parse(String field, String s) {
    try {
      final dt = DateTime.parse(s);
      return dt.isUtc ? dt : dt.toUtc();
    } on FormatException catch (e) {
      throw LocalRpError(LocalRpErrorKind.badTimestamp, '$field: ${e.message}');
    }
  }

  /// Formats an instant as `yyyy-MM-ddTHH:mm:ssZ` (UTC, no fractional
  /// seconds -- this protocol's timestamps are second-precision).
  static String format(DateTime instant) {
    final u = instant.toUtc();
    String pad(int n, int width) => n.toString().padLeft(width, '0');
    return '${pad(u.year, 4)}-${pad(u.month, 2)}-${pad(u.day, 2)}'
        'T${pad(u.hour, 2)}:${pad(u.minute, 2)}:${pad(u.second, 2)}Z';
  }
}
