package community.catalyst.linkkeys.localrp.kt

import java.time.Duration
import java.time.Instant
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.Crypto

/** Unit tests for [generateLocalRpIdentity] and the byte-storage helpers (mirrors the Java/Rust/Go SDKs' own identity module tests). */
class IdentityTest {

    private fun material(): LocalRpIdentity = generateLocalRpIdentity(appName = "Test App", now = Instant.now())

    @Test
    fun generateIdentityDefaultsBothSuitesAndTenYearLifetime() {
        val identity = material()
        assertEquals(64, identity.fingerprint.length)
        assertEquals(Crypto.fingerprint(identity.signingPublicKey), identity.fingerprint)
        assertEquals(Duration.ofDays(3650), LocalRpIdentity.DEFAULT_LIFETIME)
    }

    @Test
    fun generateIdentityRejectsEmptyAppName() {
        assertThrows(LocalRpException.InvalidInput::class.java) { generateLocalRpIdentity(appName = "", now = Instant.now()) }
    }

    @Test
    fun generateIdentityRejectsEmptySuiteList() {
        assertThrows(LocalRpException.InvalidInput::class.java) {
            generateLocalRpIdentity(appName = "Test App", now = Instant.now(), supportedSuites = emptyList())
        }
    }

    @Test
    fun signingAndEncryptionKeyByteRoundTrips() {
        val key = ByteArray(32) { 7 }
        assertArrayEquals(key, signingKeyFromBytes(signingKeyToBytes(key)))
        assertArrayEquals(key, encryptionKeyFromBytes(encryptionKeyToBytes(key)))
        assertThrows(LocalRpException.InvalidInput::class.java) { signingKeyFromBytes(ByteArray(31)) }
        assertThrows(LocalRpException.InvalidInput::class.java) { encryptionKeyFromBytes(ByteArray(33)) }
    }

    @Test
    fun fingerprintStringRoundTripValidatesHex() {
        val identity = material()
        val s = fingerprintToString(identity.fingerprint)
        assertEquals(identity.fingerprint, fingerprintFromString(s))
        assertThrows(LocalRpException.InvalidInput::class.java) { fingerprintFromString("not-hex") }
        assertThrows(LocalRpException.InvalidInput::class.java) { fingerprintFromString("a".repeat(63)) }
    }

    @Test
    fun identityBundleByteRoundTrip() {
        val identity = material()
        val bytes = identity.toBytes()
        val roundTripped = localRpIdentityFromBytes(bytes)

        assertArrayEquals(identity.signingPrivateKey, roundTripped.signingPrivateKey)
        assertArrayEquals(identity.signingPublicKey, roundTripped.signingPublicKey)
        assertArrayEquals(identity.encryptionPrivateKey, roundTripped.encryptionPrivateKey)
        assertArrayEquals(identity.encryptionPublicKey, roundTripped.encryptionPublicKey)
        assertEquals(identity.fingerprint, roundTripped.fingerprint)
        assertEquals(identity, roundTripped)
    }

    @Test
    fun identityBundleRejectsBadMagicAndTruncation() {
        val identity = material()
        val bytes = identity.toBytes()
        val badMagic = bytes.clone()
        badMagic[0] = (badMagic[0].toInt() xor 0xff).toByte()
        assertThrows(LocalRpException.InvalidInput::class.java) { localRpIdentityFromBytes(badMagic) }

        val truncated = bytes.copyOfRange(0, 10)
        assertThrows(LocalRpException.InvalidInput::class.java) { localRpIdentityFromBytes(truncated) }
    }

    @Test
    fun checkExpirationsWrapsThresholds() {
        val identity = generateLocalRpIdentity(appName = "Test App", now = Instant.now(), lifetime = Duration.ofDays(100))

        val status = checkExpirations(identity, Instant.now())
        assertEquals(ExpirationLevel.NOTICE, status.level)

        val farFuture = Instant.now().plus(Duration.ofDays(200))
        val expired = checkExpirations(identity, farFuture)
        assertEquals(ExpirationLevel.EXPIRED, expired.level)
    }
}
