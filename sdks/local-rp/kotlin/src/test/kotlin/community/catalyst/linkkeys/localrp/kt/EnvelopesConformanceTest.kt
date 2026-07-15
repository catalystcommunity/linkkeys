package community.catalyst.linkkeys.localrp.kt

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.Crypto
import community.catalyst.linkkeys.localrp.kt.protocol.SignatureContexts
import community.catalyst.linkkeys.localrp.kt.protocol.envelopeSignatureInput
import community.catalyst.linkkeys.localrp.kt.testutil.Fixtures
import community.catalyst.linkkeys.localrp.kt.testutil.MiniJson.JsonValue

/** Conformance vectors: `envelopes.json` -- the four signature contexts, exercised through this package's own [envelopeSignatureInput]/[Crypto.verifyEd25519]. */
class EnvelopesConformanceTest {

    private fun checkCase(c: JsonValue, expectValid: Boolean) {
        val context = c.get("context").asString()
        val payload = Fixtures.hex(c.get("payload_cbor_hex").asString())
        val expectedSigInput = Fixtures.hex(c.get("signature_input_cbor_hex").asString())
        val signature = Fixtures.hex(c.get("signature_hex").asString())
        val verifyKey = Fixtures.hex(c.get("verify_key_hex").asString())

        val computedSigInput = envelopeSignatureInput(context, payload)
        assertArrayEquals(expectedSigInput, computedSigInput, "signature_input_cbor_hex mismatch")

        val valid = Crypto.verifyEd25519(computedSigInput, signature, verifyKey)
        assertEquals(expectValid, valid, "verify result mismatch")
    }

    @Test
    fun positiveCasesVerify() {
        val d = Fixtures.load("envelopes.json")
        val cases = d.get("cases").asArray()
        assertEquals(4, cases.size)
        for (c in cases) {
            assertTrue(c.get("expected_valid").asBoolean())
            checkCase(c, true)
        }
    }

    @Test
    fun negativeCasesFail() {
        val d = Fixtures.load("envelopes.json")
        val cases = d.get("negative_cases").asArray()
        assertEquals(20, cases.size)
        for (c in cases) {
            assertFalse(c.get("expected_valid").asBoolean())
            checkCase(c, false)
        }
    }

    @Test
    fun contextStringsMatchTheFourConstants() {
        val d = Fixtures.load("envelopes.json").get("context_strings")
        assertEquals(SignatureContexts.DESCRIPTOR, d.get("descriptor").asString())
        assertEquals(SignatureContexts.LOGIN_REQUEST, d.get("login_request").asString())
        assertEquals(SignatureContexts.CALLBACK, d.get("callback_payload").asString())
        assertEquals(SignatureContexts.TICKET_REDEMPTION, d.get("ticket_redemption").asString())
    }
}
