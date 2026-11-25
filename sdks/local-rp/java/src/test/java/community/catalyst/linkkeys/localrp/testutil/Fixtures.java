package community.catalyst.linkkeys.localrp.testutil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.OffsetDateTime;

import community.catalyst.linkkeys.localrp.crypto.Hex;

/** Loads {@code sdks/local-rp/conformance/*.json} fixture files for tests. */
public final class Fixtures {
    private Fixtures() {}

    public static MiniJson.JsonValue load(String name) {
        return loadFrom("linkkeys.conformanceDir", name);
    }

    /** Loads {@code sdks/regular-rp/conformance/*.json} (the act-as grantee vectors live there). */
    public static MiniJson.JsonValue loadRegularRp(String name) {
        return loadFrom("linkkeys.regularRpConformanceDir", name);
    }

    private static MiniJson.JsonValue loadFrom(String property, String name) {
        String dir = System.getProperty(property);
        if (dir == null) {
            throw new IllegalStateException("system property " + property + " is not set (run via gradle test)");
        }
        Path path = Path.of(dir, name);
        try {
            String text = Files.readString(path);
            return MiniJson.parse(text);
        } catch (IOException e) {
            throw new RuntimeException("read " + path + ": " + e.getMessage() + " (run the generator?)", e);
        }
    }

    /** An RFC 3339 vector time as an {@link Instant}. */
    public static Instant time(String s) {
        return OffsetDateTime.parse(s).toInstant();
    }

    /** {@link #time}, or {@code null} for a JSON null. */
    public static Instant timeOrNull(String s) {
        return s == null ? null : time(s);
    }

    public static byte[] hex(String s) {
        return Hex.decode(s);
    }
}
