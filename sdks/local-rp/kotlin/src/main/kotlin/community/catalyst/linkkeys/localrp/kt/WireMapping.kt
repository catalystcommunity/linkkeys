package community.catalyst.linkkeys.localrp.kt

import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeParseException
import community.catalyst.linkkeys.localrp.wire.Types as JTypes

/**
 * RFC3339 timestamp parse/format, and the mapping between this package's
 * idiomatic Kotlin data classes (using [Instant]) and the underlying Java
 * SDK's wire records (using RFC3339 `String`s -- see
 * `community.catalyst.linkkeys.localrp.wire.Types`). This is presentation
 * mapping only: no protocol logic is duplicated here, only
 * `Instant<->String` conversion at the Kotlin API boundary.
 *
 * Parsing accepts both the `Z` and `+00:00` UTC-offset spellings (matching
 * the underlying SDK's own `Rfc3339` helper), since [OffsetDateTime]'s ISO
 * offset parser accepts either.
 */
internal fun parseRfc3339(field: String, s: String): Instant =
    try {
        OffsetDateTime.parse(s).toInstant()
    } catch (e: DateTimeParseException) {
        throw LocalRpException.Protocol(ProtocolErrorKind.BAD_TIMESTAMP, "$field: ${e.message}", e)
    }

internal fun parseRfc3339OrNull(field: String, s: String?): Instant? = s?.let { parseRfc3339(field, it) }

internal fun formatRfc3339(instant: Instant): String = instant.atOffset(ZoneOffset.UTC).toString()

/** Nullable-`ByteArray`-aware content equality, since `ByteArray?.equals` is reference equality by default. */
private fun nullableContentEquals(a: ByteArray?, b: ByteArray?): Boolean =
    if (a == null || b == null) a === b else a.contentEquals(b)

/** One signer's signature over a claim or revocation payload -- domain-bound, per the protocol's per-signature domain binding. */
data class ClaimSignature(val domain: String, val signedByKeyId: String, val signature: ByteArray) {
    override fun equals(other: Any?): Boolean =
        other is ClaimSignature && domain == other.domain && signedByKeyId == other.signedByKeyId &&
            signature.contentEquals(other.signature)

    override fun hashCode(): Int = java.util.Objects.hash(domain, signedByKeyId, signature.contentHashCode())
}

/** A single verified identity claim, as returned inside [VerifiedLocalLogin.claims]. */
data class Claim(
    val claimId: String,
    val userId: String,
    val claimType: String,
    val claimValue: ByteArray,
    val signatures: List<ClaimSignature>,
    val attestedAt: Instant,
    val createdAt: Instant,
    val expiresAt: Instant?,
    val revokedAt: Instant?,
) {
    override fun equals(other: Any?): Boolean =
        other is Claim && claimId == other.claimId && userId == other.userId && claimType == other.claimType &&
            claimValue.contentEquals(other.claimValue) && signatures == other.signatures &&
            attestedAt == other.attestedAt && createdAt == other.createdAt && expiresAt == other.expiresAt &&
            revokedAt == other.revokedAt

    override fun hashCode(): Int =
        java.util.Objects.hash(claimId, userId, claimType, claimValue.contentHashCode(), signatures, attestedAt, createdAt, expiresAt, revokedAt)
}

/** A domain's published signing or encryption public key, as returned inside [VerifiedLocalLogin.domainPublicKeys]. */
data class DomainPublicKey(
    val keyId: String,
    val publicKey: ByteArray,
    val fingerprint: String,
    val algorithm: String,
    val keyUsage: String,
    val createdAt: Instant,
    val expiresAt: Instant,
    val revokedAt: Instant?,
    val signedByKeyId: String?,
    val keySignature: ByteArray?,
) {
    override fun equals(other: Any?): Boolean =
        other is DomainPublicKey && keyId == other.keyId && publicKey.contentEquals(other.publicKey) &&
            fingerprint == other.fingerprint && algorithm == other.algorithm && keyUsage == other.keyUsage &&
            createdAt == other.createdAt && expiresAt == other.expiresAt && revokedAt == other.revokedAt &&
            signedByKeyId == other.signedByKeyId && nullableContentEquals(keySignature, other.keySignature)

    override fun hashCode(): Int =
        java.util.Objects.hash(
            keyId, publicKey.contentHashCode(), fingerprint, algorithm, keyUsage, createdAt, expiresAt, revokedAt,
            signedByKeyId, keySignature?.contentHashCode(),
        )
}

internal fun JTypes.ClaimSignature.toKotlin(): ClaimSignature = ClaimSignature(domain(), signedByKeyId(), signature())

internal fun ClaimSignature.toJava(): JTypes.ClaimSignature = JTypes.ClaimSignature(domain, signedByKeyId, signature)

internal fun JTypes.Claim.toKotlin(): Claim = Claim(
    claimId(),
    userId(),
    claimType(),
    claimValue(),
    signatures().map { it.toKotlin() },
    parseRfc3339("attested_at", attestedAt()),
    parseRfc3339("created_at", createdAt()),
    parseRfc3339OrNull("expires_at", expiresAt()),
    parseRfc3339OrNull("revoked_at", revokedAt()),
)

internal fun JTypes.DomainPublicKey.toKotlin(): DomainPublicKey = DomainPublicKey(
    keyId(),
    publicKey(),
    fingerprint(),
    algorithm(),
    keyUsage(),
    parseRfc3339("created_at", createdAt()),
    parseRfc3339("expires_at", expiresAt()),
    parseRfc3339OrNull("revoked_at", revokedAt()),
    signedByKeyId(),
    keySignature(),
)

internal fun DomainPublicKey.toJava(): JTypes.DomainPublicKey = JTypes.DomainPublicKey(
    keyId,
    publicKey,
    fingerprint,
    algorithm,
    keyUsage,
    formatRfc3339(createdAt),
    formatRfc3339(expiresAt),
    revokedAt?.let { formatRfc3339(it) },
    signedByKeyId,
    keySignature,
)
