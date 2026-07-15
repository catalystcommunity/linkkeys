// The negotiated AEAD suite registry (design doc, Wire Precision "AEAD suite
// registry"). Exact, case-sensitive strings from a closed registry -- never
// "close enough", never case-folded. Mirrors `liblinkkeys::crypto::AeadSuite`.
library;

enum AeadSuite {
  /// Mandatory-to-implement baseline.
  aes256Gcm('aes-256-gcm'),

  /// Optional second suite.
  chacha20Poly1305('chacha20-poly1305');

  final String wireId;
  const AeadSuite(this.wireId);

  /// Parse a wire-format suite id string. Returns `null` for an id outside
  /// the registry.
  static AeadSuite? parse(String s) {
    for (final suite in AeadSuite.values) {
      if (suite.wireId == s) return suite;
    }
    return null;
  }

  /// Every registry suite id, in preference order (baseline first).
  static List<String> allSupported() =>
      const ['aes-256-gcm', 'chacha20-poly1305'];

  /// Pick the first suite in [advertised] (preference order) that this
  /// implementation supports. Never returns a suite outside [advertised],
  /// even if this implementation also supports it.
  static AeadSuite? selectSupported(List<String> advertised) {
    for (final s in advertised) {
      final suite = parse(s);
      if (suite != null) return suite;
    }
    return null;
  }
}
