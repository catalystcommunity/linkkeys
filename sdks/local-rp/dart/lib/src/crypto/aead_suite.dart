// The negotiated AEAD suite registry (design doc, Wire Precision "AEAD suite
// registry"). Mirrors `liblinkkeys::crypto::AeadSuite`.
//
// On the wire a suite is a CSIL named-number enum: a CBOR unsigned integer
// ([number]). The callback-box KDF context still binds the text id
// ([wireId]): exact, case-sensitive, never case-folded.
library;

enum AeadSuite {
  /// Mandatory-to-implement baseline.
  aes256Gcm('aes-256-gcm', 1),

  /// Optional second suite.
  chacha20Poly1305('chacha20-poly1305', 2);

  /// The text id. The callback-box KDF context binds it.
  final String wireId;

  /// The CSIL enum number. CBOR fields carry it.
  final int number;
  const AeadSuite(this.wireId, this.number);

  /// Parse a text suite id. Returns `null` for an id outside the registry.
  static AeadSuite? parse(String s) {
    for (final suite in AeadSuite.values) {
      if (suite.wireId == s) return suite;
    }
    return null;
  }

  /// The suite with CSIL enum number [n]. Returns `null` for a number
  /// outside the registry.
  static AeadSuite? fromNumber(int n) {
    for (final suite in AeadSuite.values) {
      if (suite.number == n) return suite;
    }
    return null;
  }

  /// Every registry suite, in preference order (baseline first).
  static List<AeadSuite> allSupported() =>
      const [AeadSuite.aes256Gcm, AeadSuite.chacha20Poly1305];
}
