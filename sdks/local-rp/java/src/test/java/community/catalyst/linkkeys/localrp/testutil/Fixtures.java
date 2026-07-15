package community.catalyst.linkkeys.localrp.testutil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import community.catalyst.linkkeys.localrp.crypto.Hex;

/** Loads {@code sdks/local-rp/conformance/*.json} fixture files for tests. */
public final class Fixtures {
    private Fixtures() {}

    public static MiniJson.JsonValue load(String name) {
        String dir = System.getProperty("linkkeys.conformanceDir");
        if (dir == null) {
            throw new IllegalStateException("system property linkkeys.conformanceDir is not set (run via gradle test)");
        }
        Path path = Path.of(dir, name);
        try {
            String text = Files.readString(path);
            return MiniJson.parse(text);
        } catch (IOException e) {
            throw new RuntimeException("read " + path + ": " + e.getMessage() + " (run the generator?)", e);
        }
    }

    public static byte[] hex(String s) {
        return Hex.decode(s);
    }
}
