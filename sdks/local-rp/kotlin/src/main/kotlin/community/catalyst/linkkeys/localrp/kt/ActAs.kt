package community.catalyst.linkkeys.localrp.kt

import java.time.Duration
import java.time.Instant
import community.catalyst.linkkeys.localrp.ActAs as JActAs
import community.catalyst.linkkeys.localrp.wire.Codec as JCodec
import community.catalyst.linkkeys.localrp.wire.Types as JTypes

// -----------------------------------------------------------------------
// Act-as grants, grantee side (docs/spec/reserved/act-as-grants.md).
//
// A user lets this local RP (the grantee) act as the user at an enrolled
// application (the audience). The user's home domain signs that decision. A
// local RP can be a grantee only after its home domain approved it, and it
// can never be an audience. This file wraps the Java SDK's `ActAs` class.
// -----------------------------------------------------------------------

/** Domain-separation tags and request windows for act-as grants. */
object ActAsDefaults {
    /** The grantee's signature over a grant request. */
    const val GRANT_REQUEST_TAG: String = JActAs.GRANT_REQUEST_TAG
    /** The grantee's signature over a refresh request. */
    const val REFRESH_REQUEST_TAG: String = JActAs.REFRESH_REQUEST_TAG
    /** The grantee's signature over one presentation to the audience. */
    const val PRESENTATION_TAG: String = JActAs.PRESENTATION_TAG
    /** The browser route on the home domain: `/auth/act-as`. */
    const val BROWSER_ROUTE: String = community.catalyst.linkkeys.localrp.Browser.BROWSER_ROUTE_ACT_AS
    /** Default grant-request window: 300 seconds. */
    val REQUEST_WINDOW: Duration = JActAs.DEFAULT_REQUEST_WINDOW
    /** Longest grant-request window: 900 seconds. */
    val MAX_REQUEST_WINDOW: Duration = JActAs.MAX_REQUEST_WINDOW
}

/** An enrolled application, as an application-key attestation binds it. The audience of a grant. */
data class ApplicationRef(val subjectUserId: String, val subjectDomain: String, val applicationId: String) {
    internal fun toJava(): JTypes.ApplicationRef = JTypes.ApplicationRef(subjectUserId, subjectDomain, applicationId)
}

/**
 * A grant as the user's home domain signed it. [grant] is the signed CBOR of
 * the grant; [toBytes] gives the CBOR of the whole signed grant.
 */
class SignedActAsGrant internal constructor(internal val java: JTypes.SignedActAsGrant) {
    /** The signed CBOR of the grant. A presentation binds its SHA-256. */
    val grant: ByteArray get() = java.grant().clone()

    /** The CBOR of this signed grant. */
    fun toBytes(): ByteArray = JCodec.encodeSignedActAsGrant(java)

    /**
     * Decode the grant WITHOUT verifying the home domain's signature, for
     * example to schedule a refresh from [ActAsGrantInfo.expiresAt]. The
     * audience verifies the grant.
     */
    fun decodeUnverified(): ActAsGrantInfo {
        val g = runCatchingSdk { JActAs.decodeGrantUnverified(java) }
        return ActAsGrantInfo(
            grantId = g.grantId(),
            userId = g.userId(),
            subjectDomain = g.subjectDomain(),
            audience = ApplicationRef(g.audience().subjectUserId(), g.audience().subjectDomain(), g.audience().applicationId()),
            approvedScope = g.approvedScope(),
            issuedAt = parseRfc3339("issued_at", g.issuedAt()),
            expiresAt = parseRfc3339("expires_at", g.expiresAt()),
            seriesIssuedAt = parseRfc3339("series_issued_at", g.seriesIssuedAt()),
            renewableUntil = parseRfc3339("renewable_until", g.renewableUntil()),
        )
    }

    override fun equals(other: Any?): Boolean = other is SignedActAsGrant && toBytes().contentEquals(other.toBytes())

    override fun hashCode(): Int = toBytes().contentHashCode()

    companion object {
        /** Decode the CBOR of a signed grant. @throws LocalRpException.InvalidInput if [bytes] is malformed. */
        fun fromBytes(bytes: ByteArray): SignedActAsGrant =
            try {
                SignedActAsGrant(JCodec.decodeSignedActAsGrant(bytes))
            } catch (e: RuntimeException) {
                throw LocalRpException.InvalidInput("signed act-as grant did not decode: ${e.message}", e)
            }
    }
}

/** The unverified contents of a grant. See [SignedActAsGrant.decodeUnverified]. */
data class ActAsGrantInfo(
    val grantId: String,
    val userId: String,
    val subjectDomain: String,
    val audience: ApplicationRef,
    val approvedScope: List<String>,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val seriesIssuedAt: Instant,
    val renewableUntil: Instant,
)

/**
 * The state [beginActAs] returns. The app persists it and passes it
 * unchanged to [completeActAsCallback]. Single-use.
 */
data class PendingActAs(val nonce: String, val userDomain: String, val callbackUrl: String) {
    internal fun toJava(): JActAs.PendingActAs = JActAs.PendingActAs(nonce, userDomain, callbackUrl)

    /** CBOR storage form. An SDK-local convenience, not a protocol wire format. */
    fun toBytes(): ByteArray = toJava().toBytes()

    companion object {
        /** The inverse of [toBytes]. @throws LocalRpException.InvalidInput if [bytes] is malformed. */
        fun fromBytes(bytes: ByteArray): PendingActAs {
            val p = runCatchingSdk { JActAs.PendingActAs.fromBytes(bytes) }
            return PendingActAs(p.nonce(), p.userDomain(), p.callbackUrl())
        }
    }
}

/** What [beginActAs] returns: the browser redirect and the state to persist. */
data class BeginActAsResult(val redirectUrl: String, val pending: PendingActAs)

/**
 * Build and sign an `ActAsGrantRequest`, and return the browser redirect to
 * the home domain's `/auth/act-as` route plus the pending state.
 *
 * The redirect host comes from `_linkkeys_apis.<userDomain>` discovery, with
 * the same fallback to `https://<userDomain>` as [beginLocalLogin].
 *
 * @param userDomain the user's LinkKeys login or domain. Only the domain is used.
 * @param scopeSetCbor the CBOR of the `SignedActAsScopeSet`, exactly as the audience sent it. It is embedded unchanged.
 * @param requestedLifetimeSeconds optional. Absent sets no limit from the grantee.
 * @param requestedRenewalWindowSeconds optional. Absent means 0 (no renewal).
 * @param requestWindow how long the home domain accepts the request. 1 to 900 seconds.
 * @throws LocalRpException.InvalidInput for a bad callback URL, identity, scope set, window, or requested value.
 */
fun beginActAs(
    identity: LocalRpIdentity,
    userDomain: String,
    scopeSetCbor: ByteArray,
    callbackUrl: String,
    now: Instant,
    requestedLifetimeSeconds: Long? = null,
    requestedRenewalWindowSeconds: Long? = null,
    requestWindow: Duration = ActAsDefaults.REQUEST_WINDOW,
    dns: DnsResolver = defaultDnsResolver(),
): BeginActAsResult {
    val config = JActAs.BeginActAsConfig(identity.javaMaterial, userDomain, scopeSetCbor, callbackUrl, now)
    config.requestedLifetimeSeconds = requestedLifetimeSeconds
    config.requestedRenewalWindowSeconds = requestedRenewalWindowSeconds
    config.requestWindow = requestWindow
    config.dns = dns
    val result = runCatchingSdk { JActAs.beginActAs(config) }
    val p = result.pending()
    return BeginActAsResult(result.redirectUrl(), PendingActAs(p.nonce(), p.userDomain(), p.callbackUrl()))
}

/**
 * Read the home domain's callback and return the `act_as_grant_id`.
 * [callback] is the URL the callback arrived at, or only its query string.
 * The `nonce` parameter must equal [PendingActAs.nonce] (constant-time
 * compare). Fetch the grant itself with [refreshActAsGrant].
 *
 * @throws LocalRpException.Protocol (kind [ProtocolErrorKind.NONCE_MISMATCH]) when the nonce differs.
 * @throws LocalRpException.InvalidInput when a parameter is missing, repeated, or malformed.
 */
fun completeActAsCallback(pending: PendingActAs, callback: String): String =
    runCatchingSdk { JActAs.completeActAsCallback(pending.toJava(), callback) }

/** What [refreshActAsGrant] returns. [signed] is true when the home domain signed a new grant for this call. */
data class RefreshedActAsGrant(val grant: SignedActAsGrant, val signed: Boolean)

/**
 * Fetch the current grant, or a renewed one, from the user's home domain:
 * `ActAs/refresh-grant` over TCP CSIL-RPC, DNS-`fp=`-pinned, the same path as
 * claim-ticket redemption. Call it first after the callback, and again when
 * less than half of the grant's life remains. This does not verify the grant;
 * the audience does.
 *
 * @param userDomain the user's home domain: [PendingActAs.userDomain].
 */
fun refreshActAsGrant(
    identity: LocalRpIdentity,
    userDomain: String,
    grantId: String,
    now: Instant,
    transport: Transport = defaultTransport(),
    dns: DnsResolver = defaultDnsResolver(),
): RefreshedActAsGrant {
    val config = JActAs.RefreshActAsGrantConfig(identity.javaMaterial, userDomain, grantId, now)
    config.transport = transport
    config.dns = dns
    val result = runCatchingSdk { JActAs.refreshActAsGrant(config) }
    return RefreshedActAsGrant(SignedActAsGrant(result.grant()), result.signed())
}

/** What the grantee sends the audience with one call: [bytes] is the CBOR of the `ActAsCredential`. */
class ActAsCredential internal constructor(val grant: SignedActAsGrant, val presentation: ByteArray, val bytes: ByteArray) {
    override fun equals(other: Any?): Boolean = other is ActAsCredential && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
}

/**
 * Sign one call to the audience. [requestDigest] is defined by the
 * audience's application protocol. [nonce] must be fresh for each call; the
 * audience owns replay protection. [now] is written as whole-second RFC3339 UTC.
 */
fun presentActAs(
    grant: SignedActAsGrant,
    audience: ApplicationRef,
    requestDigest: ByteArray,
    now: Instant,
    nonce: ByteArray,
    identity: LocalRpIdentity,
): ActAsCredential {
    val credential = runCatchingSdk {
        JActAs.present(grant.java, audience.toJava(), requestDigest, now, nonce, identity.javaMaterial)
    }
    return ActAsCredential(grant, credential.presentation().presentation(), JActAs.encodeCredential(credential))
}

/** SHA-256 of a grant's signed bytes ([SignedActAsGrant.grant]). */
fun actAsGrantHash(grantBytes: ByteArray): ByteArray = JActAs.grantHash(grantBytes)

/**
 * Low-level: sign an `ActAsGrantRequest` with explicit values and return the
 * CBOR of the `SignedActAsGrantRequest`. [beginActAs] calls the same code
 * with a fresh nonce and the current time. Use this for conformance checks.
 */
fun signActAsGrantRequest(
    identity: LocalRpIdentity,
    scopeSetCbor: ByteArray,
    callbackUrl: String,
    nonce: String,
    requestedAt: String,
    expiresAt: String,
    requestedLifetimeSeconds: Long? = null,
    requestedRenewalWindowSeconds: Long? = null,
): ByteArray {
    val scopeSet = try {
        JCodec.decodeSignedActAsScopeSet(scopeSetCbor)
    } catch (e: RuntimeException) {
        throw LocalRpException.InvalidInput("scope set did not decode: ${e.message}", e)
    }
    val request = JTypes.ActAsGrantRequest(
        JActAs.localRpGrantee(identity.javaMaterial), scopeSet, requestedLifetimeSeconds,
        requestedRenewalWindowSeconds, callbackUrl, nonce, requestedAt, expiresAt,
    )
    return JCodec.encodeSignedActAsGrantRequest(runCatchingSdk { JActAs.signGrantRequest(request, identity.javaMaterial) })
}

/**
 * Low-level: sign an `ActAsRefreshRequest` with explicit values and return
 * the CBOR of the `SignedActAsRefreshRequest`. [refreshActAsGrant] calls the
 * same code with a fresh nonce and the current time.
 */
fun signActAsRefreshRequest(
    identity: LocalRpIdentity,
    grantId: String,
    requestedAt: String,
    expiresAt: String,
    nonce: String,
): ByteArray {
    val request = JTypes.ActAsRefreshRequest(grantId, JActAs.localRpGrantee(identity.javaMaterial), requestedAt, expiresAt, nonce)
    return JCodec.encodeSignedActAsRefreshRequest(runCatchingSdk { JActAs.signRefreshRequest(request, identity.javaMaterial) })
}
