package community.catalyst.linkkeys.localrp.kt

import java.time.Duration
import java.time.Instant
import community.catalyst.linkkeys.localrp.Begin as JBegin
import community.catalyst.linkkeys.localrp.Browser as JBrowser

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
 * doc, "SDK API Shape", "Flow" steps 4-6). Generates a fresh nonce/state,
 * builds and signs a login request around [identity]'s already-signed
 * descriptor, and returns the full redirect URL plus the pending-login state.
 *
 * The signing work is pure/offline. The one network touch is a DNS TXT
 * lookup of `_linkkeys_apis.<userDomain>` to discover the browser-facing
 * HTTPS endpoint: the identity domain is a trust domain, not necessarily the
 * host that serves the login routes (see [resolveBrowserBase]). The redirect
 * uses the first valid `https=` endpoint. When the lookup fails, no valid
 * record carries `https=`, or the discovered base is invalid, the redirect
 * falls back to `https://<userDomain>`. [PendingLogin.userDomain] stays the
 * identity domain either way -- verification is bound to it, never to the
 * discovered service host.
 *
 * @param requestedClaims defaults to [DefaultClaims.REQUESTED].
 * @param requiredClaims defaults to [DefaultClaims.REQUIRED].
 * @param dns the DNS TXT lookup seam for browser endpoint discovery. Defaults to [defaultDnsResolver].
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
    dns: DnsResolver = defaultDnsResolver(),
): BeginLoginResult {
    val config = JBegin.BeginLocalLoginConfig(identity.javaMaterial, callbackUrl, userDomain, now)
    config.requestedClaims = requestedClaims
    config.requiredClaims = requiredClaims
    config.requestLifetime = requestLifetime
    config.dns = dns

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

// -----------------------------------------------------------------------
// Browser endpoint discovery
// -----------------------------------------------------------------------

/**
 * Browser routes under a discovered browser base. The identity domain (what
 * the user typed, what [PendingLogin.userDomain] stores) is a trust and
 * discovery domain; the browser base (`https://host[:port][/path]`, from the
 * `https=` endpoint of `_linkkeys_apis.<identity-domain>`) is a service
 * location only; the route is the path under that base for one flow.
 */
object BrowserRoutes {
    /** The browser route for the DNS-less local-RP login flow: `/auth/local-rp`. */
    const val LOCAL_RP: String = JBrowser.BROWSER_ROUTE_LOCAL_RP
    /** The browser route for the regular (domain-keyed) RP login flow: `/auth/authorize`. */
    const val AUTHORIZE: String = JBrowser.BROWSER_ROUTE_AUTHORIZE
}

/**
 * Resolve [identityDomain]'s browser-facing HTTPS base URL (e.g.
 * `https://linkkeys.todandlorna.com` or `https://login.example.com/linkkeys`)
 * from its `_linkkeys_apis.<identityDomain>` TXT record.
 *
 * Selects the first LinkKeys v1 record whose `https=` endpoint is a valid
 * browser base (https only, a host, an optional path prefix, no userinfo /
 * query / fragment); invalid TXT records and records without `https=` are
 * skipped. [beginLocalLogin] calls this itself; it is exposed for
 * regular-RP application glue that builds `/auth/authorize` URLs.
 *
 * The resolved base is a service location only. Identity verification stays
 * bound to the identity domain -- never bind trust decisions to the host
 * this returns.
 *
 * @throws LocalRpException.Network (kind [NetworkErrorKind.DNS]) when the lookup fails or no record yields a valid base.
 */
fun resolveBrowserBase(identityDomain: String, dns: DnsResolver = defaultDnsResolver()): String =
    runCatchingSdk { JBrowser.resolveBrowserBase(dns, identityDomain) }

/**
 * Build the full browser URL for [route] (e.g. [BrowserRoutes.LOCAL_RP])
 * under [browserBase], carrying [signedRequest] as the `signed_request`
 * query parameter. A path prefix in the base is preserved: base
 * `https://login.example.com/linkkeys` and route `/auth/local-rp` produce
 * `https://login.example.com/linkkeys/auth/local-rp?...`. The URL is
 * assembled with `java.net.URI`; an unpadded-base64url `signed_request`
 * value passes through byte-identically.
 *
 * @throws LocalRpException.InvalidInput if [browserBase] is not a valid https base or [route] does not start with `/`.
 */
fun buildBrowserEndpoint(browserBase: String, route: String, signedRequest: String): String =
    runCatchingSdk { JBrowser.buildBrowserEndpoint(browserBase, route, signedRequest) }
