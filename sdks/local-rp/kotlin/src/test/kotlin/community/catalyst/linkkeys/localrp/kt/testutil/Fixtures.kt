package community.catalyst.linkkeys.localrp.kt.testutil

import java.nio.file.Files
import java.nio.file.Path

/** Loads the JSON vector files under `sdks/local-rp/conformance` for tests. */
object Fixtures {
    fun load(name: String): MiniJson.JsonValue {
        val dir = System.getProperty("linkkeys.conformanceDir")
            ?: error("system property linkkeys.conformanceDir is not set (run via gradle test)")
        val path = Path.of(dir, name)
        val text = try {
            Files.readString(path)
        } catch (e: java.io.IOException) {
            throw RuntimeException("read $path: ${e.message} (run the generator?)", e)
        }
        return MiniJson.parse(text)
    }

    fun hex(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd-length hex string: $s" }
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(s[i * 2], 16)
            val lo = Character.digit(s[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "invalid hex byte at index $i in $s" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}
