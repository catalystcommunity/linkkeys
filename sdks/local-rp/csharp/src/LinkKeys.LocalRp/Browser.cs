using LinkKeys.LocalRp.Dns;

namespace LinkKeys.LocalRp;

/// <summary>
/// Browser endpoint discovery: resolve an identity domain's browser-facing HTTPS base
/// from its <c>_linkkeys_apis</c> TXT record, and build browser route URLs against it.
/// Mirrors <c>sdks/local-rp/go/browser.go</c>.
///
/// <para>The identity domain (the domain the user selected, e.g. <c>todandlorna.com</c>)
/// is a trust and discovery domain. It is not necessarily the host that serves the
/// browser login routes — the <c>https=</c> endpoint of
/// <c>_linkkeys_apis.&lt;identity-domain&gt;</c> is (<c>docs/spec/trust-and-anchors.md</c>:
/// "<c>https=</c> is the browser-facing endpoint"). These helpers are shared by
/// <see cref="Begin.BeginLocalLogin"/> (route <see cref="BrowserRouteLocalRp"/>) and by
/// regular-RP application glue (route <see cref="BrowserRouteAuthorize"/>), so discovery
/// is implemented once.</para>
///
/// <para>Three distinct things are in play, and must not be confused: the
/// <b>identity domain</b> (what the user typed, what
/// <see cref="Begin.PendingLogin.UserDomain"/> stores, and what verification is bound
/// to); the <b>browser base</b> (the <c>https://host[:port][/path]</c> service location
/// this class discovers — a location only, never a trust decision); and the
/// <b>route</b> (the path under that base for one flow).</para>
/// </summary>
public static class Browser
{
    /// <summary>The browser route for the DNS-less local-RP login flow.</summary>
    public const string BrowserRouteLocalRp = "/auth/local-rp";

    /// <summary>The browser route for the regular (domain-keyed) RP login flow.</summary>
    public const string BrowserRouteAuthorize = "/auth/authorize";

    /// <summary>The browser route for an act-as grant request (<see cref="ActAs.BeginActAs"/>).</summary>
    public const string BrowserRouteActAs = "/auth/act-as";

    /// <summary>
    /// Check that <paramref name="browserBase"/> is a usable https browser base URL:
    /// parseable, https scheme, a host, an optional path prefix, and nothing else. A TXT
    /// record value must never smuggle in userinfo, a query, a fragment, or (via
    /// <see cref="Dns.Dns.ParseLinkKeysApisTxt"/>'s unconditional <c>https://</c> prefix
    /// plus this check) a non-HTTPS scheme.
    /// </summary>
    private static Uri ValidateBrowserBase(string browserBase)
    {
        // Check the literal prefix first: System.Uri accepts lenient spellings such
        // as `https:host`, and the authority slice below assumes the `https://` form.
        if (!browserBase.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "browser base must use https");
        }

        if (!Uri.TryCreate(browserBase, UriKind.Absolute, out var u))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "browser base is not a valid URL");
        }

        if (u.Scheme != Uri.UriSchemeHttps)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "browser base must use https");
        }

        if (u.Host.Length == 0)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "browser base has no host");
        }

        // System.Uri reports an empty UserInfo for `https://@host`, and keeps a bare `?`
        // or `#` as a one-character Query/Fragment; check the authority text for `@`
        // and the whole string for `?`/`#` so none of those shapes slip through.
        var authorityEnd = browserBase.IndexOf('/', "https://".Length);
        var authority = authorityEnd < 0 ? browserBase["https://".Length..] : browserBase["https://".Length..authorityEnd];
        if (u.UserInfo.Length != 0 || authority.Contains('@') || u.Query.Length != 0 || u.Fragment.Length != 0
            || browserBase.Contains('?') || browserBase.Contains('#'))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "browser base must be host[:port][/path] only");
        }

        return u;
    }

    /// <summary>
    /// Resolve <paramref name="identityDomain"/>'s browser-facing HTTPS base URL (e.g.
    /// <c>https://linkkeys.todandlorna.com</c> or <c>https://login.example.com/linkkeys</c>)
    /// from its <c>_linkkeys_apis.&lt;identityDomain&gt;</c> TXT record.
    ///
    /// <para>Selects the first LinkKeys v1 record whose <c>https=</c> endpoint is a valid
    /// browser base; invalid TXT records and records without <c>https=</c> are skipped.
    /// Throws an <see cref="SdkException"/> of kind <see cref="SdkException.ErrorKind.Dns"/>
    /// when the lookup fails or no record yields a valid base — the caller decides the
    /// fallback (<see cref="Begin.BeginLocalLogin"/> falls back to
    /// <c>https://&lt;identityDomain&gt;</c>).</para>
    ///
    /// <para>The resolved base is a service location only. Identity verification stays
    /// bound to the identity domain — never bind trust decisions to the host this
    /// returns.</para>
    /// </summary>
    public static string ResolveBrowserBase(IDnsResolver dns, string identityDomain)
    {
        var name = LinkKeys.LocalRp.Dns.Dns.LinkKeysApisDnsName(identityDomain);
        IReadOnlyList<string> txts;
        try
        {
            txts = dns.TxtLookup(name);
        }
        catch (SdkException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw new SdkException(SdkException.ErrorKind.Dns, $"{name}: {e.Message}", e);
        }

        foreach (var txt in txts)
        {
            LinkKeys.LocalRp.Dns.Dns.LinkKeysApis apis;
            try
            {
                apis = LinkKeys.LocalRp.Dns.Dns.ParseLinkKeysApisTxt(txt);
            }
            catch (DnsParseError)
            {
                continue;
            }

            if (apis.HttpsBase is null)
            {
                continue;
            }

            try
            {
                ValidateBrowserBase(apis.HttpsBase);
            }
            catch (SdkException)
            {
                continue;
            }

            return apis.HttpsBase;
        }

        throw new SdkException(SdkException.ErrorKind.Dns, $"no usable {name} TXT record with an https= endpoint");
    }

    /// <summary>
    /// Build the full browser URL for <paramref name="route"/> (e.g.
    /// <see cref="BrowserRouteLocalRp"/>) under <paramref name="browserBase"/>, carrying
    /// <paramref name="signedRequest"/> as the <c>signed_request</c> query parameter. A
    /// path prefix in the base is preserved: base <c>https://login.example.com/linkkeys</c>
    /// and route <c>/auth/local-rp</c> produce
    /// <c>https://login.example.com/linkkeys/auth/local-rp?...</c>.
    ///
    /// <para>The URL is assembled with <see cref="Uri"/>/<see cref="UriBuilder"/>.
    /// <c>signed_request</c> values are URL-param-encoded (unpadded base64url) by
    /// construction, so query encoding passes them through byte-identically.</para>
    /// </summary>
    /// <exception cref="SdkException">
    /// Kind <see cref="SdkException.ErrorKind.InvalidInput"/> if <paramref name="browserBase"/>
    /// is not a valid https base or <paramref name="route"/> does not start with <c>/</c>.
    /// </exception>
    public static string BuildBrowserEndpoint(string browserBase, string route, string signedRequest)
    {
        var baseUri = ValidateBrowserBase(browserBase);
        if (!route.StartsWith('/'))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "route must start with /");
        }

        var builder = new UriBuilder(baseUri)
        {
            Path = baseUri.AbsolutePath.TrimEnd('/') + route,
            Query = "signed_request=" + Uri.EscapeDataString(signedRequest),
            Fragment = "",
        };
        return builder.Uri.AbsoluteUri;
    }

    /// <summary>
    /// The begin-flow composition: discover the identity domain's browser base and build
    /// the route URL, falling back to <c>https://&lt;identityDomain&gt;</c> when DNS lookup
    /// fails, no valid record carries <c>https=</c>, or the discovered base is invalid.
    /// The fallback preserves the pre-discovery behavior, so a domain that serves its
    /// browser routes at the apex keeps working without a <c>_linkkeys_apis</c> record.
    /// </summary>
    internal static string ResolveBrowserEndpoint(IDnsResolver dns, string identityDomain, string route, string signedRequest)
    {
        string browserBase;
        try
        {
            browserBase = ResolveBrowserBase(dns, identityDomain);
        }
        catch (SdkException)
        {
            browserBase = $"https://{identityDomain}";
        }

        return BuildBrowserEndpoint(browserBase, route, signedRequest);
    }

    /// <summary>Append one <c>name=value</c> query parameter to an already-built browser URL.</summary>
    internal static string AppendQueryParam(string url, string name, string value)
    {
        var builder = new UriBuilder(url);
        var pair = Uri.EscapeDataString(name) + "=" + Uri.EscapeDataString(value);
        var existing = builder.Query.TrimStart('?');
        builder.Query = existing.Length == 0 ? pair : existing + "&" + pair;
        return builder.Uri.AbsoluteUri;
    }
}
