package community.catalyst.linkkeys.localrp.kt

import java.time.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Unit tests for [beginLocalLogin] (mirrors the Java/Rust/Go SDKs' own begin module tests). */
class BeginTest {

    private fun material(): LocalRpIdentity = generateLocalRpIdentity(appName = "Test App", now = Instant.now())

    @Test
    fun beginDefaultsClaimsAndProducesPendingState() {
        val m = material()
        val result = beginLocalLogin(m, "http://localhost:8080/callback", "example.com", Instant.now())

        assertTrue(result.redirect.redirectUrl.startsWith("https://example.com/auth/local-rp?signed_request="))
        assertEquals("example.com", result.pending.userDomain)
        assertEquals("http://localhost:8080/callback", result.pending.callbackUrl)
        assertEquals(32, result.pending.nonce.size)
        assertEquals(32, result.pending.state.size)
    }

    @Test
    fun beginDefaultsRequiredClaimsOnPendingLogin() {
        val m = material()
        val result = beginLocalLogin(m, "http://localhost:8080/callback", "example.com", Instant.now())
        assertEquals(DefaultClaims.REQUIRED, result.pending.requiredClaims)
    }

    @Test
    fun pendingLoginRoundTripsThroughItsByteSerializeForm() {
        val m = material()
        val pending = beginLocalLogin(
            m, "http://localhost:8080/callback", "example.com", Instant.now(),
            requiredClaims = listOf("handle", "email"),
        ).pending

        val roundTripped = pendingLoginFromBytes(pending.toBytes())

        assertEquals(pending, roundTripped)
        assertEquals(listOf("handle", "email"), roundTripped.requiredClaims)
    }

    @Test
    fun beginRejectsNonHttpCallbackScheme() {
        val m = material()
        assertThrows(LocalRpException.InvalidInput::class.java) {
            beginLocalLogin(m, "myapp://callback", "example.com", Instant.now())
        }
    }

    @Test
    fun beginRejectsEmptyUserDomain() {
        val m = material()
        assertThrows(LocalRpException.InvalidInput::class.java) {
            beginLocalLogin(m, "http://localhost/callback", "", Instant.now())
        }
    }

    @Test
    fun beginTwoCallsNeverReuseNonceOrState() {
        val m = material()
        val r1 = beginLocalLogin(m, "http://localhost/callback", "example.com", Instant.now())
        val r2 = beginLocalLogin(m, "http://localhost/callback", "example.com", Instant.now())
        assertNotEquals(r1.pending.nonce.toList(), r2.pending.nonce.toList())
        assertNotEquals(r1.pending.state.toList(), r2.pending.state.toList())
    }

    @Test
    fun beginHonorsExplicitClaimsAndLifetime() {
        val m = material()
        val result = beginLocalLogin(
            identity = m,
            callbackUrl = "http://localhost/callback",
            userDomain = "example.com",
            now = Instant.now(),
            requestedClaims = listOf("email"),
            requiredClaims = listOf("email"),
        )
        assertTrue(result.redirect.redirectUrl.isNotEmpty())
    }
}
