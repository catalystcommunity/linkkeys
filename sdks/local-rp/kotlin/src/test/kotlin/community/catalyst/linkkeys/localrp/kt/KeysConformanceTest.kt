package community.catalyst.linkkeys.localrp.kt

import java.nio.charset.StandardCharsets
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.Crypto
import community.catalyst.linkkeys.localrp.kt.testutil.Fixtures

/** Conformance vectors: `keys.json`, exercised through this package's own [Crypto] and [LocalRpIdentity] fingerprint helpers. */
class KeysConformanceTest {

    @Test
    fun fingerprintsRoundTripThroughSdkFingerprintHelpers() {
        val d = Fixtures.load("keys.json")

        for (node in listOf(d.get("local_rp").get("signing"), d.get("domain_signing_key"))) {
            val seed = Fixtures.hex(node.get("seed_hex").asString())
            val expectedPublic = Fixtures.hex(node.get("public_key_hex").asString())
            val expectedFp = node.get("fingerprint_hex").asString()

            // Confirm seed and public key correspond to the same Ed25519
            // keypair: signing with the seed and verifying against the
            // fixture's public key must succeed.
            val message = "conformance-check".toByteArray(StandardCharsets.UTF_8)
            val sig = Crypto.signEd25519(message, seed)
            assertTrue(Crypto.verifyEd25519(message, sig, expectedPublic))

            val computed = Crypto.fingerprint(expectedPublic)
            assertEquals(expectedFp, computed)

            // Round-trip through the SDK's own fingerprint string helpers.
            val s = fingerprintToString(computed)
            assertEquals(expectedFp, fingerprintFromString(s))

            assertEquals(32, seed.size)
        }

        // fingerprintFromString must reject non-fingerprint strings even
        // when they happen to be valid hex of the wrong length.
        assertThrows(LocalRpException.InvalidInput::class.java) { fingerprintFromString("deadbeef") }
    }

    @Test
    fun x25519PublicKeysDeriveFromPrivateKeys() {
        val d = Fixtures.load("keys.json")
        for (node in listOf(d.get("local_rp").get("encryption"), d.get("domain_encryption_recipient"))) {
            val priv = Fixtures.hex(node.get("private_key_hex").asString())
            val expectedPublic = Fixtures.hex(node.get("public_key_hex").asString())
            assertArrayEquals(expectedPublic, Crypto.derivePublicFromX25519Private(priv))
        }
    }
}
