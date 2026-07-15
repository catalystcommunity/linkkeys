package community.catalyst.linkkeys.localrp.kt

import java.time.Duration
import java.time.Instant
import community.catalyst.linkkeys.localrp.Identity as JIdentity
import community.catalyst.linkkeys.localrp.crypto.AeadSuite as JAeadSuite

/**
 * A local RP's full key material: an Ed25519 signing keypair, a *separate*
 * X25519 encryption keypair (never algebraically derived -- design doc, "Encryption
 * Key Is Separate, Not Derived"), the self-signed descriptor binding them, and
 * the identity fingerprint (`sha256(signing_public_key)`, hex).
 *
 * Construct one with [generateLocalRpIdentity]; reload one from storage with
 * [localRpIdentityFromBytes]. There is no public constructor: this type's
 * invariant (the four key fields and [fingerprint] must all agree with the
 * embedded, signature-verified descriptor) is only established by those two
 * entry points.
 *
 * **Security note** (design doc, "Byte Storage Helpers"): [signingPrivateKey]
 * and [encryptionPrivateKey] do not directly identify a user, but they
 * control this app's entire local RP identity -- anyone holding them can sign
 * login requests and redeem claim tickets as this app. Persist the bytes from
 * [toBytes] with ordinary application-secret care (the same tier as a
 * database credential or API key), not merely as configuration.
 */
@ConsistentCopyVisibility
data class LocalRpIdentity internal constructor(
    val signingPrivateKey: ByteArray,
    val signingPublicKey: ByteArray,
    val encryptionPrivateKey: ByteArray,
    val encryptionPublicKey: ByteArray,
    val fingerprint: String,
    internal val javaMaterial: JIdentity.LocalRpKeyMaterial,
) {
    override fun equals(other: Any?): Boolean =
        other is LocalRpIdentity && fingerprint == other.fingerprint &&
            signingPrivateKey.contentEquals(other.signingPrivateKey) &&
            signingPublicKey.contentEquals(other.signingPublicKey) &&
            encryptionPrivateKey.contentEquals(other.encryptionPrivateKey) &&
            encryptionPublicKey.contentEquals(other.encryptionPublicKey)

    override fun hashCode(): Int =
        java.util.Objects.hash(
            fingerprint, signingPrivateKey.contentHashCode(), signingPublicKey.contentHashCode(),
            encryptionPrivateKey.contentHashCode(), encryptionPublicKey.contentHashCode(),
        )

    companion object {
        /** Default local RP key lifetime: 10 years (design doc: "Default lifetime: 10 years"). */
        val DEFAULT_LIFETIME: Duration = JIdentity.DEFAULT_LIFETIME
    }
}

private fun wrap(material: JIdentity.LocalRpKeyMaterial): LocalRpIdentity = LocalRpIdentity(
    material.signingPrivateKey(),
    material.signingPublicKey(),
    material.encryptionPrivateKey(),
    material.encryptionPublicKey(),
    material.fingerprint(),
    material,
)

/**
 * `generate_local_rp_identity(config) -> LocalRpKeyMaterial` (design doc,
 * "SDK API Shape"). Generates a fresh Ed25519 signing keypair and a separate
 * X25519 encryption keypair, builds and self-signs the descriptor binding
 * them.
 *
 * @param now the current time -- never read from the system clock internally;
 *   the caller supplies it, matching every other timestamp-consuming
 *   function in this package.
 * @param supportedSuites AEAD suites this app can decrypt callbacks with, in
 *   preference order. Defaults to every registry suite
 *   (`aes-256-gcm`, `chacha20-poly1305`).
 * @param lifetime key/descriptor lifetime from [now]. Defaults to
 *   [LocalRpIdentity.DEFAULT_LIFETIME].
 * @throws LocalRpException.InvalidInput if [appName] is blank or
 *   [supportedSuites] is empty.
 */
fun generateLocalRpIdentity(
    appName: String,
    now: Instant,
    localDomainHint: String? = null,
    supportedSuites: List<String> = JAeadSuite.allSupported(),
    lifetime: Duration = LocalRpIdentity.DEFAULT_LIFETIME,
): LocalRpIdentity {
    val config = JIdentity.GenerateLocalRpIdentityConfig(appName, now)
    config.localDomainHint = localDomainHint
    config.supportedSuites = supportedSuites
    config.lifetime = lifetime
    return wrap(runCatchingSdk { JIdentity.generateLocalRpIdentity(config) })
}

/** `local_rp_identity_to_bytes(identity) -> bytes` (design doc, "SDK API Shape" / "Byte Storage Helpers"). */
fun LocalRpIdentity.toBytes(): ByteArray = runCatchingSdk { JIdentity.localRpIdentityToBytes(javaMaterial) }

/**
 * `local_rp_identity_from_bytes(bytes) -> LocalRpIdentity` -- the inverse of
 * [LocalRpIdentity.toBytes]. Does no signature/expiry verification beyond
 * decoding the embedded descriptor (that is [checkExpirations]'s and the full
 * `completeLocalLogin` verification chain's job).
 */
fun localRpIdentityFromBytes(bytes: ByteArray): LocalRpIdentity = wrap(runCatchingSdk { JIdentity.localRpIdentityFromBytes(bytes) })

/** `signing_key_to_bytes(key) -> bytes` (design doc, "Byte Storage Helpers"): the canonical 32-byte form, unchanged. */
fun signingKeyToBytes(key: ByteArray): ByteArray = JIdentity.signingKeyToBytes(key)

/** `signing_key_from_bytes(bytes) -> SigningKey`. @throws LocalRpException.InvalidInput if [bytes] is not 32 bytes. */
fun signingKeyFromBytes(bytes: ByteArray): ByteArray = runCatchingSdk { JIdentity.signingKeyFromBytes(bytes) }

/** `encryption_key_to_bytes(key) -> bytes` (design doc, "Byte Storage Helpers"): the canonical 32-byte form, unchanged. */
fun encryptionKeyToBytes(key: ByteArray): ByteArray = JIdentity.encryptionKeyToBytes(key)

/** `encryption_key_from_bytes(bytes) -> EncryptionKey`. @throws LocalRpException.InvalidInput if [bytes] is not 32 bytes. */
fun encryptionKeyFromBytes(bytes: ByteArray): ByteArray = runCatchingSdk { JIdentity.encryptionKeyFromBytes(bytes) }

/** `fingerprint_to_string(fingerprint) -> text` -- a pass-through, since the fingerprint IS a hex string already. */
fun fingerprintToString(fingerprint: String): String = JIdentity.fingerprintToString(fingerprint)

/**
 * `fingerprint_from_string(text) -> Fingerprint` -- parse/validate a
 * fingerprint string: exactly 64 lowercase-normalized hex characters (a
 * SHA-256 digest). @throws LocalRpException.InvalidInput otherwise.
 */
fun fingerprintFromString(s: String): String = runCatchingSdk { JIdentity.fingerprintFromString(s) }
