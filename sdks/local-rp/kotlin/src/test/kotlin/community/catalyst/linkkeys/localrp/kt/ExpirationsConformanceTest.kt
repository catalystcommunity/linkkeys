package community.catalyst.linkkeys.localrp.kt

import java.time.Duration
import java.time.Instant
import java.time.OffsetDateTime
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.checkTimestamps
import community.catalyst.linkkeys.localrp.kt.testutil.Fixtures

/** Conformance vectors: `expirations.json`, exercised through this package's own [checkExpirations] / [checkTimestamps]. */
class ExpirationsConformanceTest {

    @Test
    fun checkExpirationsThresholdsViaSdkWrapper() {
        val d = Fixtures.load("expirations.json").get("check_expirations")
        val expiresAtStr = d.get("expires_at").asString()
        val cases = d.get("cases").asArray()
        assertEquals(11, cases.size)

        // Build an identity whose descriptor expires at exactly `expiresAt`,
        // exercising checkExpirations end to end (identity -> descriptor ->
        // threshold logic), not a raw threshold function directly.
        val expires: Instant = OffsetDateTime.parse(expiresAtStr).toInstant()
        val createdAt = expires.minus(Duration.ofDays(3650))
        val identity = generateLocalRpIdentity(
            appName = "Conformance Test App",
            now = createdAt,
            lifetime = Duration.between(createdAt, expires),
        )

        for (c in cases) {
            val now = OffsetDateTime.parse(c.get("now").asString()).toInstant()
            val status = checkExpirations(identity, now)
            assertEquals(c.get("expected_level").asString(), status.level.name.lowercase(), "now=$now")
        }
    }

    @Test
    fun checkTimestampsSkewBoundariesAreExact() {
        val d = Fixtures.load("expirations.json").get("check_timestamps")
        val issuedAt: Instant = OffsetDateTime.parse(d.get("issued_at").asString()).toInstant()
        val expiresAt: Instant = OffsetDateTime.parse(d.get("expires_at").asString()).toInstant()
        val skew = d.get("skew_seconds").asLong()
        val cases = d.get("cases").asArray()
        assertEquals(4, cases.size)

        for (c in cases) {
            val now = OffsetDateTime.parse(c.get("now").asString()).toInstant()
            val expectedValid = c.get("expected_valid").asBoolean()
            val valid = try {
                checkTimestamps(issuedAt, expiresAt, now, skew)
                true
            } catch (e: LocalRpException.Protocol) {
                false
            }
            assertEquals(expectedValid, valid, "now=$now")
        }
    }
}
