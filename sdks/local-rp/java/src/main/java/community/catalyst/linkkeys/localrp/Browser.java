package community.catalyst.linkkeys.localrp;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import community.catalyst.linkkeys.localrp.dns.Dns;
import community.catalyst.linkkeys.localrp.dns.DnsParseError;
import community.catalyst.linkkeys.localrp.dns.DnsResolver;

/**
 * Browser endpoint discovery: resolve an identity domain's browser-facing
 * HTTPS base from its {@code _linkkeys_apis} TXT record, and build browser
 * route URLs against it. Mirrors {@code sdks/local-rp/go/browser.go}.
 *
 * <p>The identity domain (the domain the user selected, e.g.
 * {@code todandlorna.com}) is a trust and discovery domain. It is not
 * necessarily the host that serves the browser login routes &mdash; the
 * {@code https=} endpoint of {@code _linkkeys_apis.<identity-domain>} is
 * ({@code docs/spec/trust-and-anchors.md}: "{@code https=} is the
 * browser-facing endpoint"). These helpers are shared by
 * {@link Begin#beginLocalLogin} (route {@link #BROWSER_ROUTE_LOCAL_RP}) and
 * by regular-RP application glue (route {@link #BROWSER_ROUTE_AUTHORIZE}),
 * so discovery is implemented once.
 *
 * <p>Three distinct things are in play, and must not be confused:
 * <ul>
 *   <li><b>identity domain</b> &mdash; what the user typed, what
 *       {@link Begin.PendingLogin#userDomain()} stores, and what
 *       verification is bound to;
 *   <li><b>browser base</b> &mdash; the {@code https://host[:port][/path]}
 *       service location this class discovers (a location only, never a
 *       trust decision);
 *   <li><b>route</b> &mdash; the path under that base for one flow.
 * </ul>
 */
public final class Browser {
    private Browser() {}

    /** The browser route for the DNS-less local-RP login flow. */
    public static final String BROWSER_ROUTE_LOCAL_RP = "/auth/local-rp";

    /** The browser route for the regular (domain-keyed) RP login flow. */
    public static final String BROWSER_ROUTE_AUTHORIZE = "/auth/authorize";

    /** The browser route for an act-as grant request ({@link ActAs#beginActAs}). */
    public static final String BROWSER_ROUTE_ACT_AS = "/auth/act-as";

    /**
     * Check that {@code base} is a usable https browser base URL: parseable,
     * https scheme, a host, an optional path prefix, and nothing else. A TXT
     * record value must never smuggle in userinfo, a query, a fragment, or
     * (via {@link Dns#parseLinkKeysApisTxt}'s unconditional {@code https://}
     * prefix plus this check) a non-HTTPS scheme.
     */
    private static URI validateBrowserBase(String base) {
        URI u;
        try {
            u = new URI(base);
        } catch (URISyntaxException e) {
            throw new SdkException(
                    SdkException.Kind.INVALID_INPUT, "browser base is not a valid URL: " + e.getMessage(), e);
        }
        if (u.isOpaque() || !"https".equals(u.getScheme())) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "browser base must use https");
        }
        if (u.getHost() == null || u.getHost().isEmpty()) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "browser base has no host");
        }
        if (u.getUserInfo() != null || u.getRawQuery() != null || u.getRawFragment() != null) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "browser base must be host[:port][/path] only");
        }
        return u;
    }

    /**
     * Resolve {@code identityDomain}'s browser-facing HTTPS base URL (e.g.
     * {@code https://linkkeys.todandlorna.com} or
     * {@code https://login.example.com/linkkeys}) from its
     * {@code _linkkeys_apis.<identityDomain>} TXT record.
     *
     * <p>Selects the first LinkKeys v1 record whose {@code https=} endpoint is
     * a valid browser base; invalid TXT records and records without
     * {@code https=} are skipped. Throws an {@link SdkException} of kind
     * {@link SdkException.Kind#DNS} when the lookup fails or no record yields
     * a valid base &mdash; the caller decides the fallback
     * ({@link Begin#beginLocalLogin} falls back to
     * {@code https://<identityDomain>}).
     *
     * <p>The resolved base is a service location only. Identity verification
     * stays bound to the identity domain &mdash; never bind trust decisions to
     * the host this returns.
     */
    public static String resolveBrowserBase(DnsResolver dns, String identityDomain) {
        String name = Dns.linkkeysApisDnsName(identityDomain);
        List<String> txts;
        try {
            txts = dns.txtLookup(name);
        } catch (SdkException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new SdkException(SdkException.Kind.DNS, name + ": " + e.getMessage(), e);
        }
        for (String txt : txts) {
            Dns.LinkKeysApis apis;
            try {
                apis = Dns.parseLinkKeysApisTxt(txt);
            } catch (DnsParseError ignored) {
                continue;
            }
            if (apis.httpsBase() == null) {
                continue;
            }
            try {
                validateBrowserBase(apis.httpsBase());
            } catch (SdkException ignored) {
                continue;
            }
            return apis.httpsBase();
        }
        throw new SdkException(SdkException.Kind.DNS, "no usable " + name + " TXT record with an https= endpoint");
    }

    /**
     * Build the full browser URL for {@code route} (e.g.
     * {@link #BROWSER_ROUTE_LOCAL_RP}) under {@code browserBase}, carrying
     * {@code signedRequest} as the {@code signed_request} query parameter. A
     * path prefix in the base is preserved: base
     * {@code https://login.example.com/linkkeys} and route
     * {@code /auth/local-rp} produce
     * {@code https://login.example.com/linkkeys/auth/local-rp?...}.
     *
     * <p>The URL is assembled from the validated {@link URI} components of
     * the base (raw, so a percent-encoded path prefix is preserved
     * byte-for-byte) and re-parsed by {@link URI#create}. {@code signed_request}
     * values are URL-param-encoded (unpadded base64url) by construction, so
     * query encoding passes them through byte-identically.
     *
     * @throws SdkException (kind {@link SdkException.Kind#INVALID_INPUT}) if
     *     {@code browserBase} is not a valid https base or {@code route} does
     *     not start with {@code /}.
     */
    public static String buildBrowserEndpoint(String browserBase, String route, String signedRequest) {
        URI base = validateBrowserBase(browserBase);
        if (!route.startsWith("/")) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "route must start with /");
        }
        String prefix = base.getRawPath() == null ? "" : base.getRawPath().replaceAll("/+$", "");
        return assemble(base, prefix + route, "signed_request=" + encodeQueryValue(signedRequest));
    }

    /**
     * The begin-flow composition: discover the identity domain's browser base
     * and build the route URL, falling back to {@code https://<identityDomain>}
     * when DNS lookup fails, no valid record carries {@code https=}, or the
     * discovered base is invalid. The fallback preserves the pre-discovery
     * behavior, so a domain that serves its browser routes at the apex keeps
     * working without a {@code _linkkeys_apis} record.
     */
    static String resolveBrowserEndpoint(DnsResolver dns, String identityDomain, String route, String signedRequest) {
        String base;
        try {
            base = resolveBrowserBase(dns, identityDomain);
        } catch (SdkException e) {
            base = "https://" + identityDomain;
        }
        return buildBrowserEndpoint(base, route, signedRequest);
    }

    /** Append one {@code name=value} query parameter to an already-built browser URL. */
    static String appendQueryParam(String url, String name, String value) {
        URI u;
        try {
            u = new URI(url);
        } catch (URISyntaxException e) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "browser endpoint produced an invalid URL", e);
        }
        String query = u.getRawQuery();
        String pair = encodeQueryValue(name) + "=" + encodeQueryValue(value);
        return assemble(u, u.getRawPath(), query == null || query.isEmpty() ? pair : query + "&" + pair);
    }

    /**
     * Join the scheme and raw authority of an already-validated hierarchical
     * URI with a raw path and raw query, then re-parse the result so an
     * illegal byte anywhere fails as {@link SdkException.Kind#INVALID_INPUT}
     * instead of leaking into a redirect.
     */
    private static String assemble(URI validated, String rawPath, String rawQuery) {
        String url = validated.getScheme() + "://" + validated.getRawAuthority() + rawPath + "?" + rawQuery;
        try {
            return new URI(url).toString();
        } catch (URISyntaxException e) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "browser endpoint produced an invalid URL", e);
        }
    }

    /** Percent-encode one query value; a space becomes {@code %20}, never {@code +}. */
    private static String encodeQueryValue(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
