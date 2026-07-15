package community.catalyst.linkkeys.localrp.kt

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.CallbackBox
import community.catalyst.linkkeys.localrp.kt.testutil.Fixtures
import community.catalyst.linkkeys.localrp.kt.testutil.MiniJson.JsonValue

/** Conformance vectors: `callback_box.json`, exercised through this package's own [CallbackBox.open]. */
class CallbackBoxConformanceTest {

    private fun allowedSuites(c: JsonValue): List<String> = c.get("allowed_suites").asArray().map { it.asString() }

    @Test
    fun positiveCasesOpen() {
        val d = Fixtures.load("callback_box.json")
        val cases = d.get("positive_cases").asArray()
        assertEquals(2, cases.size)

        for (c in cases) {
            val headerBytes = Fixtures.hex(c.get("header_cbor_hex").asString())
            val ciphertext = Fixtures.hex(c.get("ciphertext_hex").asString())
            val decryptKey = Fixtures.hex(c.get("decrypt_private_key_hex").asString())
            val allowed = allowedSuites(c)

            val opened = CallbackBox.open(headerBytes, ciphertext, decryptKey, allowed)

            assertEquals(c.get("suite").asString(), opened.header.suite)
            assertEquals(c.get("fingerprint").asString(), opened.header.fingerprint)
            assertArrayEquals(Fixtures.hex(c.get("nonce_hex").asString()), opened.header.nonce)
            assertArrayEquals(Fixtures.hex(c.get("state_hex").asString()), opened.header.state)
            assertEquals(c.get("issued_at").asString(), opened.header.issuedAt)
            assertEquals(c.get("expires_at").asString(), opened.header.expiresAt)

            assertArrayEquals(Fixtures.hex(c.get("plaintext_cbor_hex").asString()), opened.signedPayloadCbor)
        }
    }

    @Test
    fun negativeCasesFail() {
        val d = Fixtures.load("callback_box.json")
        val cases = d.get("negative_cases").asArray()
        assertEquals(13, cases.size)

        for (c in cases) {
            val headerBytes = Fixtures.hex(c.get("header_cbor_hex").asString())
            val ciphertext = Fixtures.hex(c.get("ciphertext_hex").asString())
            val decryptKey = Fixtures.hex(c.get("decrypt_private_key_hex").asString())
            val allowed = allowedSuites(c)

            assertThrows(RuntimeException::class.java, {
                CallbackBox.open(headerBytes, ciphertext, decryptKey, allowed)
            }, "negative case unexpectedly opened: ${c.getOrNull("name")}")
        }
    }
}
