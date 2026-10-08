package community.catalyst.linkkeys.localrp.kt

import java.net.URI
import java.time.Instant
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.UrlParams
import community.catalyst.linkkeys.localrp.wire.Codec as JCodec

/**
 * Browser endpoint discovery through this package's [beginLocalLogin]
 * wrapper and its [resolveBrowserBase] / [buildBrowserEndpoint] helpers
 * (mirrors `sdks/local-rp/go/browser_test.go`). Every resolver here is a
 * hermetic Kotlin lambda with canned TXT answers; no test in this file
 * performs a live DNS request.
 */
class BrowserTest {

    private val identityDomain = "ident.example.test"

    /** Canned TXT answers per name; every other name is a lookup failure. */
    private fun mapResolver(records: Map<String, List<String>>): DnsResolver = DnsResolver { name ->
        records[name] ?: throw LocalRpException.Network(NetworkErrorKind.DNS, "no fake record for $name")
    }

    private fun apisResolver(vararg txts: String): DnsResolver =
        mapResolver(mapOf("_linkkeys_apis.$identityDomain" to txts.toList()))

    private fun failingResolver(): DnsResolver =
        DnsResolver { throw LocalRpException.Network(NetworkErrorKind.DNS, "SERVFAIL") }

    private val now: Instant = Instant.parse("2026-08-17T12:00:00Z")
    private val callbackUrl = "http://app.lan:8080/cb"

    private fun beginWith(dns: DnsResolver, userDomain: String = identityDomain): BeginLoginResult =
        beginLocalLogin(generateLocalRpIdentity(appName = "browser-test", now = now), callbackUrl, userDomain, now, dns = dns)

    // Case 1: a valid https= host is used for the redirect instead of the
    // identity domain. Case 8: PendingLogin.userDomain stays the identity
    // domain -- verification stays bound to it, not to the service host.
    @Test
    fun beginUsesDiscoveredHttpsHost() {
        val result = beginWith(apisResolver("v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test"))
        val url = result.redirect.redirectUrl
        assertTrue(url.startsWith("https://linkkeys.ident.example.test/auth/local-rp?signed_request="), url)
        assertFalse(url.startsWith("https://$identityDomain/"), url)
        assertEquals(identityDomain, result.pending.userDomain)
    }

    // Case 2: an https= value with a path prefix preserves that prefix.
    @Test
    fun beginPreservesHttpsPathPrefix() {
        val url = beginWith(apisResolver("v=lk1 https=login.example.test/linkkeys")).redirect.redirectUrl
        assertTrue(url.startsWith("https://login.example.test/linkkeys/auth/local-rp?signed_request="), url)
    }

    // Case 3: a record with only tcp= falls back to the identity domain.
    @Test
    fun beginTcpOnlyRecordFallsBackToIdentityDomain() {
        val url = beginWith(apisResolver("v=lk1 tcp=linkkeys.ident.example.test")).redirect.redirectUrl
        assertTrue(url.startsWith("https://$identityDomain/auth/local-rp?signed_request="), url)
    }

    // Case 4: a DNS lookup error falls back to the identity domain.
    @Test
    fun beginDnsErrorFallsBackToIdentityDomain() {
        val url = beginWith(failingResolver()).redirect.redirectUrl
        assertTrue(url.startsWith("https://$identityDomain/auth/local-rp?signed_request="), url)
    }

    // Cases 5 + 6: invalid TXT records are ignored, and across several
    // records the FIRST valid record with https= is selected.
    @Test
    fun beginSelectsFirstValidHttpsAcrossRecords() {
        val url = beginWith(
            apisResolver(
                "not a linkkeys record",
                "v=lk2 https=wrong-version.example.test",
                "v=lk1 tcp=tcp-only.example.test",
                "v=lk1 https=first.example.test",
                "v=lk1 https=second.example.test",
            ),
        ).redirect.redirectUrl
        assertTrue(url.startsWith("https://first.example.test/auth/local-rp?signed_request="), url)
    }

    // Case 7: signed_request rides the discovered URL unchanged -- it decodes
    // to the signed login request whose fields match this login.
    @Test
    fun beginSignedRequestSurvivesDiscoveredUrl() {
        val result = beginWith(apisResolver("v=lk1 https=login.example.test/linkkeys"))
        val query = URI(result.redirect.redirectUrl).rawQuery
        val param = query.split("&").firstOrNull { it.startsWith("signed_request=") }?.removePrefix("signed_request=")
        assertNotNull(param, "signed_request query parameter missing")

        val envelope = UrlParams.decodeSignedLoginRequest(param!!)
        val request = JCodec.decodeLocalRpLoginRequest(envelope.request)
        assertEquals(callbackUrl, request.callbackUrl())
        assertArrayEquals(result.pending.nonce, request.nonce())
    }

    // The username hint still rides along after discovery, encoded, and the
    // pending domain is still the parsed identity domain.
    @Test
    fun beginKeepsUsernameHintOnDiscoveredUrl() {
        val dns = mapResolver(mapOf("_linkkeys_apis.id.example.test" to listOf("v=lk1 https=login.example.test/pfx")))
        val result = beginWith(dns, userDomain = "Alice+work@ID.Example.TEST")
        val url = result.redirect.redirectUrl
        assertTrue(url.startsWith("https://login.example.test/pfx/auth/local-rp?signed_request="), url)
        assertTrue(url.endsWith("&username=Alice%2Bwork"), url)
        assertEquals("id.example.test", result.pending.userDomain)
    }

    // Case 9: a call without a dns argument compiles unchanged (this test is
    // that caller) and the default is the memoized system resolver. The
    // default path is not executed here -- that would be a live DNS request.
    @Test
    fun beginCallWithoutResolverStillCompiles() {
        val identity = generateLocalRpIdentity(appName = "browser-test", now = now)
        val call: () -> BeginLoginResult = { beginLocalLogin(identity, callbackUrl, identityDomain, now) }
        assertNotNull(call)
        assertNotNull(defaultDnsResolver())
    }

    // -----------------------------------------------------------------
    // Direct tests for the exported helpers
    // -----------------------------------------------------------------

    @Test
    fun resolveBrowserBaseSelectsValidHttpsRecord() {
        val base = resolveBrowserBase(
            identityDomain,
            dns = apisResolver("v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys"),
        )
        assertEquals("https://login.example.test:8443/linkkeys", base)

        // A record whose https= value smuggles URL structure is skipped; with
        // no other candidate, resolution errors so the caller can fall back.
        for (hostile in listOf(
            "v=lk1 https=user@evil.example.test",
            "v=lk1 https=evil.example.test/x?y=1",
            "v=lk1 https=evil.example.test/x#frag",
        )) {
            val e = assertThrows(LocalRpException.Network::class.java, { resolveBrowserBase(identityDomain, apisResolver(hostile)) }, hostile)
            assertEquals(NetworkErrorKind.DNS, e.kind)
        }

        val noHttps = assertThrows(LocalRpException.Network::class.java) {
            resolveBrowserBase(identityDomain, apisResolver("v=lk1 tcp=only.example.test"))
        }
        assertEquals(NetworkErrorKind.DNS, noHttps.kind)

        val lookupFailed = assertThrows(LocalRpException.Network::class.java) {
            resolveBrowserBase(identityDomain, failingResolver())
        }
        assertEquals(NetworkErrorKind.DNS, lookupFailed.kind)
    }

    @Test
    fun buildBrowserEndpointJoinsBaseRouteAndQuery() {
        assertEquals(
            "https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc",
            buildBrowserEndpoint("https://h.example.test", BrowserRoutes.LOCAL_RP, "PAYLOAD-123_abc"),
        )

        // Path prefix, with and without a trailing slash, and the regular-RP
        // route -- the same helper serves /auth/authorize glue.
        for ((base, want) in mapOf(
            "https://h.example.test/pfx" to "https://h.example.test/pfx/auth/authorize?signed_request=s",
            "https://h.example.test/pfx/" to "https://h.example.test/pfx/auth/authorize?signed_request=s",
            "https://h.example.test:8443/" to "https://h.example.test:8443/auth/authorize?signed_request=s",
        )) {
            assertEquals(want, buildBrowserEndpoint(base, BrowserRoutes.AUTHORIZE, "s"), base)
        }

        // A non-HTTPS scheme must never be selectable.
        for (bad in listOf(
            "http://h.example.test",
            "ftp://h.example.test",
            "https://",
            "https:opaque",
            "https://u:p@h.example.test",
            "https://h.example.test/x?y=1",
            "https://h.example.test/x#f",
        )) {
            assertThrows(LocalRpException.InvalidInput::class.java, { buildBrowserEndpoint(bad, BrowserRoutes.LOCAL_RP, "s") }, bad)
        }
        assertThrows(LocalRpException.InvalidInput::class.java) {
            buildBrowserEndpoint("https://h.example.test", "auth/no-leading-slash", "s")
        }
    }
}
