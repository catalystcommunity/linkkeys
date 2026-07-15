package community.catalyst.linkkeys.localrp.kt

import java.time.Duration
import java.time.Instant
import community.catalyst.linkkeys.localrp.Begin as JBegin

/** The redirect URL the app should send the user's browser to. This SDK never performs the redirect itself. */
data class LocalLoginRedirect(val redirectUrl: String)

/**
 * The state [beginLocalLogin] returns for the app to persist (e.g. in a
 * server-side session tied to the browser) and pass unchanged to
 * [completeLocalLogin]. **Single-use**: the app must discard it after one
 * completion attempt -- this SDK owns no storage and cannot enforce
 * single-use itself.
 *
 * [requiredClaims] is retained here (not just used transiently while
 * building the login request) because [completeLocalLogin] must enforce it
 * against the redeemed claims (SEC fix: an IDP that drops or fails to
 * attest a required claim must fail the login, not silently return less
 * than the app required).
 */
@ConsistentCopyVisibility
data class PendingLogin internal constructor(
    val nonce: ByteArray,
    val state: ByteArray,
    val userDomain: String,
    val callbackUrl: String,
    val requiredClaims: List<String>,
    internal val javaPending: JBegin.PendingLogin,
) {
    override fun equals(other: Any?): Boolean =
        other is PendingLogin && userDomain == other.userDomain && callbackUrl == other.callbackUrl &&
            requiredClaims == other.requiredClaims &&
            nonce.contentEquals(other.nonce) && state.contentEquals(other.state)

    override fun hashCode(): Int =
        java.util.Objects.hash(userDomain, callbackUrl, requiredClaims, nonce.contentHashCode(), state.contentHashCode())
}

private fun wrap(pending: JBegin.PendingLogin): PendingLogin =
    PendingLogin(pending.nonce(), pending.state(), pending.userDomain(), pending.callbackUrl(), pending.requiredClaims(), pending)

/** What [beginLocalLogin] returns: the redirect URL plus the pending-login state the app must persist. */
data class BeginLoginResult(val redirect: LocalLoginRedirect, val pending: PendingLogin)

/** Default claim sets when the caller doesn't specify any (design doc, "Default Claim Set"). */
object DefaultClaims {
    /** `display_name`, `email`, `handle`. */
    val REQUESTED: List<String> = JBegin.DEFAULT_REQUESTED_CLAIMS
    /** `handle`. */
    val REQUIRED: List<String> = JBegin.DEFAULT_REQUIRED_CLAIMS
}

/** Default login-request lifetime: short-lived, matching the callback's own short default lifetime. */
val DEFAULT_LOGIN_REQUEST_LIFETIME: Duration = JBegin.DEFAULT_LOGIN_REQUEST_LIFETIME

/**
 * `begin_local_login(config) -> (LocalLoginRedirect, PendingLogin)` (design
 * doc, "SDK API Shape", "Flow" steps 4-6). Pure/offline: no network access
 * happens here. Generates a fresh nonce/state, builds and signs a login
 * request around [identity]'s already-signed descriptor, and returns the full
 * redirect URL plus the pending-login state.
 *
 * @param requestedClaims defaults to [DefaultClaims.REQUESTED].
 * @param requiredClaims defaults to [DefaultClaims.REQUIRED].
 * @throws LocalRpException.InvalidInput if [callbackUrl] is not `http://`/`https://`, or [userDomain] is blank.
 */
fun beginLocalLogin(
    identity: LocalRpIdentity,
    callbackUrl: String,
    userDomain: String,
    now: Instant,
    requestedClaims: List<String> = DefaultClaims.REQUESTED,
    requiredClaims: List<String> = DefaultClaims.REQUIRED,
    requestLifetime: Duration = DEFAULT_LOGIN_REQUEST_LIFETIME,
): BeginLoginResult {
    val config = JBegin.BeginLocalLoginConfig(identity.javaMaterial, callbackUrl, userDomain, now)
    config.requestedClaims = requestedClaims
    config.requiredClaims = requiredClaims
    config.requestLifetime = requestLifetime

    val result = runCatchingSdk { JBegin.beginLocalLogin(config) }
    return BeginLoginResult(
        LocalLoginRedirect(result.redirect().redirectUrl()),
        wrap(result.pending()),
    )
}

/**
 * Serialize form for app-side persistence (e.g. a server-side session
 * store), CBOR-encoded so it round-trips exactly, including
 * [PendingLogin.requiredClaims]. An SDK-local storage convenience, not a
 * protocol wire format.
 */
fun PendingLogin.toBytes(): ByteArray = runCatchingSdk { javaPending.toBytes() }

/** The inverse of [PendingLogin.toBytes]. @throws LocalRpException.InvalidInput if [bytes] is malformed. */
fun pendingLoginFromBytes(bytes: ByteArray): PendingLogin = wrap(runCatchingSdk { JBegin.PendingLogin.fromBytes(bytes) })
