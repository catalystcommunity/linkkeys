package community.catalyst.linkkeys.localrp.kt

import java.time.Instant
import community.catalyst.linkkeys.localrp.LinkKeysLocalRp as JFacade
import community.catalyst.linkkeys.localrp.LocalRp as JLocalRp

/**
 * A warning level for how close a local RP identity is to expiring (design
 * doc, "Expiration Helper"). Thresholds are inclusive at the boundary: exactly
 * 180 days remaining is already [NOTICE] (not [OK]), exactly 90 is already
 * [WARNING], exactly 30 is already [CRITICAL], and `now >= expiresAt` is
 * [EXPIRED].
 */
enum class ExpirationLevel {
    OK,
    NOTICE,
    WARNING,
    CRITICAL,
    EXPIRED,
}

private fun JLocalRp.ExpirationLevel.toKotlin(): ExpirationLevel = ExpirationLevel.valueOf(name)

/** The result of [checkExpirations]: exact datetimes plus a [ExpirationLevel]. The SDK reports facts; the app decides what to do with them. */
data class ExpirationStatus(val level: ExpirationLevel, val expiresAt: Instant, val now: Instant)

/**
 * `check_expirations(identity, now) -> ExpirationStatus` (design doc, "SDK
 * API Shape" / "Expiration Helper"). Does NOT apply clock-skew tolerance
 * (unlike the protocol's timestamp-bounds checks): expiry warnings are
 * advisory, day-scale facts, not a replay/freshness security boundary. The
 * SDK reports facts; the app decides whether to warn admins, warn users,
 * block login, renew, or ignore.
 */
fun checkExpirations(identity: LocalRpIdentity, now: Instant): ExpirationStatus {
    val status = JFacade.checkExpirations(identity.javaMaterial, now)
    return ExpirationStatus(status.level().toKotlin(), status.expiresAt(), status.now())
}
