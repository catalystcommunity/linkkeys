package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.dns.DnsResolver;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpLoginRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpLoginRequest;

/**
 * Browser endpoint discovery in {@link Begin#beginLocalLogin} and the
 * exported {@link Browser} helpers (mirrors {@code sdks/local-rp/go/browser_test.go}).
 * Every resolver here is a hermetic fake with canned TXT answers; no test in
 * this file performs a live DNS request.
 */
class BrowserTest {

    private static final String IDENTITY_DOMAIN = "ident.example.test";

    /** Canned TXT answers per name; every other name is a lookup failure. */
    private static DnsResolver mapResolver(Map<String, List<String>> records) {
        return name -> {
            List<String> txts = records.get(name);
            if (txts == null) {
                throw new SdkException(SdkException.Kind.DNS, "no fake record for " + name);
            }
            return txts;
        };
    }

    private static DnsResolver apisResolver(String... txts) {
        return mapResolver(Map.of("_linkkeys_apis." + IDENTITY_DOMAIN, List.of(txts)));
    }

    private static DnsResolver failingResolver() {
        return name -> {
            throw new SdkException(SdkException.Kind.DNS, "SERVFAIL");
        };
    }

    private static Begin.BeginLocalLoginConfig config(DnsResolver dns) {
        Instant now = Instant.parse("2026-08-17T12:00:00Z");
        Identity.LocalRpKeyMaterial identity =
                Identity.generateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("browser-test", now));
        Begin.BeginLocalLoginConfig config =
                new Begin.BeginLocalLoginConfig(identity, "http://app.lan:8080/cb", IDENTITY_DOMAIN, now);
        config.dns = dns;
        return config;
    }

    private static Begin.BeginResult beginWith(DnsResolver dns) {
        return Begin.beginLocalLogin(config(dns));
    }

    // Case 1: a valid https= host is used for the redirect instead of the
    // identity domain. Case 8: PendingLogin.userDomain stays the identity
    // domain -- verification stays bound to it, not to the service host.
    @Test
    void beginUsesDiscoveredHttpsHost() {
        Begin.BeginResult result = beginWith(apisResolver(
                "v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test"));
        String url = result.redirect().redirectUrl();
        assertTrue(url.startsWith("https://linkkeys.ident.example.test/auth/local-rp?signed_request="), url);
        assertFalse(url.startsWith("https://" + IDENTITY_DOMAIN + "/"), url);
        assertEquals(IDENTITY_DOMAIN, result.pending().userDomain());
    }

    // Case 2: an https= value with a path prefix preserves that prefix.
    @Test
    void beginPreservesHttpsPathPrefix() {
        Begin.BeginResult result = beginWith(apisResolver("v=lk1 https=login.example.test/linkkeys"));
        String url = result.redirect().redirectUrl();
        assertTrue(url.startsWith("https://login.example.test/linkkeys/auth/local-rp?signed_request="), url);
    }

    // Case 3: a record with only tcp= falls back to the identity domain.
    @Test
    void beginTcpOnlyRecordFallsBackToIdentityDomain() {
        Begin.BeginResult result = beginWith(apisResolver("v=lk1 tcp=linkkeys.ident.example.test"));
        String url = result.redirect().redirectUrl();
        assertTrue(url.startsWith("https://" + IDENTITY_DOMAIN + "/auth/local-rp?signed_request="), url);
    }

    // Case 4: a DNS lookup error falls back to the identity domain.
    @Test
    void beginDnsErrorFallsBackToIdentityDomain() {
        Begin.BeginResult result = beginWith(failingResolver());
        String url = result.redirect().redirectUrl();
        assertTrue(url.startsWith("https://" + IDENTITY_DOMAIN + "/auth/local-rp?signed_request="), url);
    }

    // A resolver that throws something other than SdkException still falls
    // back: any lookup failure is a discovery failure, never a begin failure.
    @Test
    void beginForeignResolverExceptionFallsBackToIdentityDomain() {
        DnsResolver broken = name -> {
            throw new IllegalStateException("resolver exploded");
        };
        Begin.BeginResult result = beginWith(broken);
        assertTrue(result.redirect().redirectUrl().startsWith("https://" + IDENTITY_DOMAIN + "/auth/local-rp?"));
    }

    // Cases 5 + 6: invalid TXT records are ignored, and across several
    // records the FIRST valid record with https= is selected.
    @Test
    void beginSelectsFirstValidHttpsAcrossRecords() {
        Begin.BeginResult result = beginWith(apisResolver(
                "not a linkkeys record",
                "v=lk2 https=wrong-version.example.test",
                "v=lk1 tcp=tcp-only.example.test",
                "v=lk1 https=first.example.test",
                "v=lk1 https=second.example.test"));
        String url = result.redirect().redirectUrl();
        assertTrue(url.startsWith("https://first.example.test/auth/local-rp?signed_request="), url);
    }

    // Case 7: signed_request rides the discovered URL unchanged -- it decodes
    // to the signed login request whose fields match this login.
    @Test
    void beginSignedRequestSurvivesDiscoveredUrl() {
        Begin.BeginLocalLoginConfig config = config(apisResolver("v=lk1 https=login.example.test/linkkeys"));
        Begin.BeginResult result = Begin.beginLocalLogin(config);

        URI u = URI.create(result.redirect().redirectUrl());
        String param = null;
        for (String pair : u.getRawQuery().split("&")) {
            if (pair.startsWith("signed_request=")) {
                param = pair.substring("signed_request=".length());
            }
        }
        assertNotNull(param, "signed_request query parameter missing");

        SignedLocalRpLoginRequest signed = Encoding.signedLocalRpLoginRequestFromUrlParam(param);
        LocalRpLoginRequest request = Codec.decodeLocalRpLoginRequest(signed.request());
        assertEquals(config.callbackUrl, request.callbackUrl());
        assertArrayEquals(result.pending().nonce(), request.nonce());
    }

    // The username hint still rides along after discovery, encoded, and the
    // pending domain is still the parsed identity domain.
    @Test
    void beginKeepsUsernameHintOnDiscoveredUrl() {
        Begin.BeginLocalLoginConfig config = config(mapResolver(Map.of(
                "_linkkeys_apis.id.example.test", List.of("v=lk1 https=login.example.test/pfx"))));
        Begin.BeginLocalLoginConfig withUser = new Begin.BeginLocalLoginConfig(
                config.keyMaterial, config.callbackUrl, "Alice+work@ID.Example.TEST", config.now);
        withUser.dns = config.dns;
        Begin.BeginResult result = Begin.beginLocalLogin(withUser);
        String url = result.redirect().redirectUrl();
        assertTrue(url.startsWith("https://login.example.test/pfx/auth/local-rp?signed_request="), url);
        assertTrue(url.endsWith("&username=Alice%2Bwork"), url);
        assertEquals("id.example.test", result.pending().userDomain());
    }

    // Case 9: a config without a dns field compiles unchanged (this test is
    // that caller) and the default is the memoized system resolver. The
    // default path is not executed here -- that would be a live DNS request.
    @Test
    void beginConfigWithoutResolverStillCompiles() {
        Begin.BeginLocalLoginConfig config = new Begin.BeginLocalLoginConfig(
                null, "http://app.lan:8080/cb", IDENTITY_DOMAIN, Instant.parse("2026-08-17T12:00:00Z"));
        assertEquals(null, config.dns);
        assertNotNull(LinkKeysLocalRp.defaultDnsResolver(), "defaultDnsResolver() must supply the default resolver");
    }

    // -----------------------------------------------------------------
    // Direct tests for the exported helpers
    // -----------------------------------------------------------------

    @Test
    void resolveBrowserBase() {
        String base = Browser.resolveBrowserBase(
                apisResolver("v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys"), IDENTITY_DOMAIN);
        assertEquals("https://login.example.test:8443/linkkeys", base);

        // A record whose https= value smuggles URL structure is skipped; with
        // no other candidate, resolution errors so the caller can fall back.
        for (String hostile : List.of(
                "v=lk1 https=user@evil.example.test",
                "v=lk1 https=evil.example.test/x?y=1",
                "v=lk1 https=evil.example.test/x#frag")) {
            SdkException e = assertThrows(SdkException.class,
                    () -> Browser.resolveBrowserBase(apisResolver(hostile), IDENTITY_DOMAIN), hostile);
            assertEquals(SdkException.Kind.DNS, e.kind());
        }

        SdkException noHttps = assertThrows(SdkException.class,
                () -> Browser.resolveBrowserBase(apisResolver("v=lk1 tcp=only.example.test"), IDENTITY_DOMAIN));
        assertEquals(SdkException.Kind.DNS, noHttps.kind());

        SdkException lookupFailed = assertThrows(SdkException.class,
                () -> Browser.resolveBrowserBase(failingResolver(), IDENTITY_DOMAIN));
        assertEquals(SdkException.Kind.DNS, lookupFailed.kind());
    }

    @Test
    void buildBrowserEndpoint() {
        assertEquals(
                "https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc",
                Browser.buildBrowserEndpoint("https://h.example.test", Browser.BROWSER_ROUTE_LOCAL_RP, "PAYLOAD-123_abc"));

        // Path prefix, with and without a trailing slash, and the regular-RP
        // route -- the same helper serves /auth/authorize glue.
        for (Map.Entry<String, String> c : Map.of(
                "https://h.example.test/pfx", "https://h.example.test/pfx/auth/authorize?signed_request=s",
                "https://h.example.test/pfx/", "https://h.example.test/pfx/auth/authorize?signed_request=s",
                "https://h.example.test:8443/", "https://h.example.test:8443/auth/authorize?signed_request=s",
                "https://h.example.test/p%20q", "https://h.example.test/p%20q/auth/authorize?signed_request=s")
                .entrySet()) {
            assertEquals(c.getValue(),
                    Browser.buildBrowserEndpoint(c.getKey(), Browser.BROWSER_ROUTE_AUTHORIZE, "s"), c.getKey());
        }

        // A non-HTTPS scheme must never be selectable.
        for (String bad : List.of(
                "http://h.example.test",
                "ftp://h.example.test",
                "https://",
                "https:opaque",
                "https://u:p@h.example.test",
                "https://h.example.test/x?y=1",
                "https://h.example.test/x#f")) {
            SdkException e = assertThrows(SdkException.class,
                    () -> Browser.buildBrowserEndpoint(bad, Browser.BROWSER_ROUTE_LOCAL_RP, "s"), bad);
            assertEquals(SdkException.Kind.INVALID_INPUT, e.kind());
        }
        assertThrows(SdkException.class,
                () -> Browser.buildBrowserEndpoint("https://h.example.test", "auth/no-leading-slash", "s"));
    }
}
