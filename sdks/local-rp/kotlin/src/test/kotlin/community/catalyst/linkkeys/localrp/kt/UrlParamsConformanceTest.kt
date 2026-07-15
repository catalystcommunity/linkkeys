package community.catalyst.linkkeys.localrp.kt

import java.util.Base64
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.UrlParams
import community.catalyst.linkkeys.localrp.kt.testutil.Fixtures

/** Conformance vectors: `url_params.json`, exercised through this package's own [UrlParams]. */
class UrlParamsConformanceTest {

    @Test
    fun casesRoundTripBothDirections() {
        val d = Fixtures.load("url_params.json")
        val cases = d.get("cases").asArray()
        assertEquals(2, cases.size)

        for (c in cases) {
            val cbor = Fixtures.hex(c.get("cbor_hex").asString())
            val b64 = c.get("base64url_unpadded").asString()

            assertEquals(b64, Base64.getUrlEncoder().withoutPadding().encodeToString(cbor))
            assertArrayEquals(cbor, Base64.getUrlDecoder().decode(b64))

            when (val name = c.get("name").asString()) {
                "signed_local_rp_login_request" -> {
                    val typed = UrlParams.decodeSignedLoginRequestFromCbor(cbor)
                    assertEquals(b64, UrlParams.encodeSignedLoginRequest(typed))
                    val roundTripped = UrlParams.decodeSignedLoginRequest(b64)
                    assertArrayEquals(roundTripped.request, typed.request)
                    assertArrayEquals(roundTripped.signature, typed.signature)
                }
                "local_rp_encrypted_callback" -> {
                    val typed = UrlParams.decodeEncryptedCallbackFromCbor(cbor)
                    assertEquals(b64, UrlParams.encodeEncryptedCallback(typed))
                    val roundTripped = UrlParams.decodeEncryptedCallback(b64)
                    assertArrayEquals(roundTripped.header, typed.header)
                    assertArrayEquals(roundTripped.ciphertext, typed.ciphertext)
                }
                else -> error("unrecognized url_params.json case name: $name")
            }
        }
    }

    @Test
    fun negativeCasesRejected() {
        val d = Fixtures.load("url_params.json")
        val cases = d.get("negative_cases").asArray()
        assertEquals(2, cases.size)
        for (c in cases) {
            val input = c.get("input").asString()
            assertThrows(RuntimeException::class.java) { UrlParams.decodeEncryptedCallback(input) }
        }
    }
}
