package community.catalyst.linkkeys.localrp.crypto;

import java.util.List;

/**
 * The negotiated AEAD suite registry (design doc, Wire Precision "AEAD suite
 * registry"). Exact, case-sensitive strings from a closed registry &mdash;
 * never "close enough", never case-folded. Mirrors
 * {@code liblinkkeys::crypto::AeadSuite}.
 */
public enum AeadSuite {
    /** Mandatory-to-implement baseline. */
    AES_256_GCM("aes-256-gcm"),
    /** Optional second suite. */
    CHACHA20_POLY1305("chacha20-poly1305");

    private final String wireId;

    AeadSuite(String wireId) {
        this.wireId = wireId;
    }

    public String wireId() {
        return wireId;
    }

    /** Parse a wire-format suite id string. Returns {@code null} for an id outside the registry. */
    public static AeadSuite parse(String s) {
        for (AeadSuite suite : values()) {
            if (suite.wireId.equals(s)) {
                return suite;
            }
        }
        return null;
    }

    /** Every registry suite id, in preference order (baseline first). */
    public static List<String> allSupported() {
        return List.of(AES_256_GCM.wireId, CHACHA20_POLY1305.wireId);
    }

    /**
     * Pick the first suite in {@code advertised} (preference order) that
     * this implementation supports. Never returns a suite outside
     * {@code advertised}, even if this implementation also supports it.
     */
    public static AeadSuite selectSupported(List<String> advertised) {
        for (String s : advertised) {
            AeadSuite suite = parse(s);
            if (suite != null) {
                return suite;
            }
        }
        return null;
    }
}
