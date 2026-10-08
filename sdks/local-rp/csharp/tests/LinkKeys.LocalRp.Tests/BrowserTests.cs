using LinkKeys.LocalRp.Dns;
using LinkKeys.LocalRp.Wire;

namespace LinkKeys.LocalRp.Tests;

/// <summary>
/// Browser endpoint discovery in <see cref="Begin.BeginLocalLogin"/> and the exported
/// <see cref="Browser"/> helpers (mirrors <c>sdks/local-rp/go/browser_test.go</c>). Every
/// resolver here is a hermetic fake with canned TXT answers; no test in this file
/// performs a live DNS request.
/// </summary>
public class BrowserTests
{
    private const string IdentityDomain = "ident.example.test";

    /// <summary>Canned TXT answers per name; every other name is a lookup failure.</summary>
    private sealed class MapDnsResolver(IReadOnlyDictionary<string, IReadOnlyList<string>> records) : IDnsResolver
    {
        public IReadOnlyList<string> TxtLookup(string name) =>
            records.TryGetValue(name, out var txts)
                ? txts
                : throw new SdkException(SdkException.ErrorKind.Dns, $"no fake record for {name}");
    }

    private sealed class ThrowingDnsResolver(Exception error) : IDnsResolver
    {
        public IReadOnlyList<string> TxtLookup(string name) => throw error;
    }

    private static IDnsResolver ApisResolver(params string[] txts) =>
        new MapDnsResolver(new Dictionary<string, IReadOnlyList<string>>
        {
            [$"_linkkeys_apis.{IdentityDomain}"] = txts,
        });

    private static IDnsResolver FailingResolver() =>
        new ThrowingDnsResolver(new SdkException(SdkException.ErrorKind.Dns, "SERVFAIL"));

    private static Begin.BeginLocalLoginConfig Config(IDnsResolver dns, string userDomain = IdentityDomain)
    {
        var now = new DateTimeOffset(2026, 8, 17, 12, 0, 0, TimeSpan.Zero);
        var identity = Identity.GenerateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("browser-test", now));
        return new Begin.BeginLocalLoginConfig(identity, "http://app.lan:8080/cb", userDomain, now, Dns: dns);
    }

    private static Begin.BeginResult BeginWith(IDnsResolver dns) => Begin.BeginLocalLogin(Config(dns));

    // Case 1: a valid https= host is used for the redirect instead of the identity
    // domain. Case 8: PendingLogin.UserDomain stays the identity domain -- verification
    // stays bound to it, not to the service host.
    [Fact]
    public void BeginUsesDiscoveredHttpsHost()
    {
        var result = BeginWith(ApisResolver("v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test"));
        Assert.StartsWith("https://linkkeys.ident.example.test/auth/local-rp?signed_request=", result.Redirect.RedirectUrl);
        Assert.DoesNotContain($"https://{IdentityDomain}/", result.Redirect.RedirectUrl);
        Assert.Equal(IdentityDomain, result.Pending.UserDomain);
    }

    // Case 2: an https= value with a path prefix preserves that prefix.
    [Fact]
    public void BeginPreservesHttpsPathPrefix()
    {
        var result = BeginWith(ApisResolver("v=lk1 https=login.example.test/linkkeys"));
        Assert.StartsWith("https://login.example.test/linkkeys/auth/local-rp?signed_request=", result.Redirect.RedirectUrl);
    }

    // Case 3: a record with only tcp= falls back to the identity domain.
    [Fact]
    public void BeginTcpOnlyRecordFallsBackToIdentityDomain()
    {
        var result = BeginWith(ApisResolver("v=lk1 tcp=linkkeys.ident.example.test"));
        Assert.StartsWith($"https://{IdentityDomain}/auth/local-rp?signed_request=", result.Redirect.RedirectUrl);
    }

    // Case 4: a DNS lookup error falls back to the identity domain.
    [Fact]
    public void BeginDnsErrorFallsBackToIdentityDomain()
    {
        var result = BeginWith(FailingResolver());
        Assert.StartsWith($"https://{IdentityDomain}/auth/local-rp?signed_request=", result.Redirect.RedirectUrl);
    }

    // A resolver that throws something other than SdkException still falls back: any
    // lookup failure is a discovery failure, never a begin failure.
    [Fact]
    public void BeginForeignResolverExceptionFallsBackToIdentityDomain()
    {
        var result = BeginWith(new ThrowingDnsResolver(new InvalidOperationException("resolver exploded")));
        Assert.StartsWith($"https://{IdentityDomain}/auth/local-rp?", result.Redirect.RedirectUrl);
    }

    // Cases 5 + 6: invalid TXT records are ignored, and across several records the
    // FIRST valid record with https= is selected.
    [Fact]
    public void BeginSelectsFirstValidHttpsAcrossRecords()
    {
        var result = BeginWith(ApisResolver(
            "not a linkkeys record",
            "v=lk2 https=wrong-version.example.test",
            "v=lk1 tcp=tcp-only.example.test",
            "v=lk1 https=first.example.test",
            "v=lk1 https=second.example.test"));
        Assert.StartsWith("https://first.example.test/auth/local-rp?signed_request=", result.Redirect.RedirectUrl);
    }

    // Case 7: signed_request rides the discovered URL unchanged -- it decodes to the
    // signed login request whose fields match this login.
    [Fact]
    public void BeginSignedRequestSurvivesDiscoveredUrl()
    {
        var config = Config(ApisResolver("v=lk1 https=login.example.test/linkkeys"));
        var result = Begin.BeginLocalLogin(config);

        var query = new Uri(result.Redirect.RedirectUrl).Query.TrimStart('?').Split('&');
        var param = query.Single(p => p.StartsWith("signed_request=", StringComparison.Ordinal))["signed_request=".Length..];
        Assert.NotEmpty(param);

        var signed = UrlEncoding.SignedLocalRpLoginRequestFromUrlParam(param);
        var request = Codec.DecodeLocalRpLoginRequest(signed.Request);
        Assert.Equal(config.CallbackUrl, request.CallbackUrl);
        Assert.Equal(result.Pending.Nonce, request.Nonce);
    }

    // The username hint still rides along after discovery, encoded, and the pending
    // domain is still the parsed identity domain.
    [Fact]
    public void BeginKeepsUsernameHintOnDiscoveredUrl()
    {
        var dns = new MapDnsResolver(new Dictionary<string, IReadOnlyList<string>>
        {
            ["_linkkeys_apis.id.example.test"] = ["v=lk1 https=login.example.test/pfx"],
        });
        var result = Begin.BeginLocalLogin(Config(dns, "Alice+work@ID.Example.TEST"));
        Assert.StartsWith("https://login.example.test/pfx/auth/local-rp?signed_request=", result.Redirect.RedirectUrl);
        Assert.EndsWith("&username=Alice%2Bwork", result.Redirect.RedirectUrl);
        Assert.Equal("id.example.test", result.Pending.UserDomain);
    }

    // Case 9: a config without a Dns argument compiles unchanged (this test is that
    // caller) and the default is the memoized system resolver. The default path is not
    // executed here -- that would be a live DNS request.
    [Fact]
    public void BeginConfigWithoutResolverStillCompiles()
    {
        var now = new DateTimeOffset(2026, 8, 17, 12, 0, 0, TimeSpan.Zero);
        var identity = Identity.GenerateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("browser-test", now));
        var config = new Begin.BeginLocalLoginConfig(identity, "http://app.lan:8080/cb", IdentityDomain, now);
        Assert.Null(config.Dns);
        Assert.NotNull(LinkKeysLocalRp.DefaultDnsResolver());
    }

    // -----------------------------------------------------------------
    // Direct tests for the exported helpers
    // -----------------------------------------------------------------

    [Fact]
    public void ResolveBrowserBase()
    {
        var browserBase = Browser.ResolveBrowserBase(
            ApisResolver("v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys"), IdentityDomain);
        Assert.Equal("https://login.example.test:8443/linkkeys", browserBase);

        // A record whose https= value smuggles URL structure is skipped; with no other
        // candidate, resolution errors so the caller can fall back.
        foreach (var hostile in new[]
                 {
                     "v=lk1 https=user@evil.example.test",
                     "v=lk1 https=@evil.example.test",
                     "v=lk1 https=evil.example.test/x?y=1",
                     "v=lk1 https=evil.example.test/x?",
                     "v=lk1 https=evil.example.test/x#frag",
                     "v=lk1 https=evil.example.test/x#",
                 })
        {
            var e = Assert.Throws<SdkException>(() => Browser.ResolveBrowserBase(ApisResolver(hostile), IdentityDomain));
            Assert.Equal(SdkException.ErrorKind.Dns, e.Kind);
        }

        var noHttps = Assert.Throws<SdkException>(
            () => Browser.ResolveBrowserBase(ApisResolver("v=lk1 tcp=only.example.test"), IdentityDomain));
        Assert.Equal(SdkException.ErrorKind.Dns, noHttps.Kind);

        var lookupFailed = Assert.Throws<SdkException>(() => Browser.ResolveBrowserBase(FailingResolver(), IdentityDomain));
        Assert.Equal(SdkException.ErrorKind.Dns, lookupFailed.Kind);
    }

    [Fact]
    public void BuildBrowserEndpoint()
    {
        Assert.Equal(
            "https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc",
            Browser.BuildBrowserEndpoint("https://h.example.test", Browser.BrowserRouteLocalRp, "PAYLOAD-123_abc"));

        // Path prefix, with and without a trailing slash, and the regular-RP route --
        // the same helper serves /auth/authorize glue.
        foreach (var (browserBase, want) in new Dictionary<string, string>
                 {
                     ["https://h.example.test/pfx"] = "https://h.example.test/pfx/auth/authorize?signed_request=s",
                     ["https://h.example.test/pfx/"] = "https://h.example.test/pfx/auth/authorize?signed_request=s",
                     ["https://h.example.test:8443/"] = "https://h.example.test:8443/auth/authorize?signed_request=s",
                     ["https://h.example.test/p%20q"] = "https://h.example.test/p%20q/auth/authorize?signed_request=s",
                 })
        {
            Assert.Equal(want, Browser.BuildBrowserEndpoint(browserBase, Browser.BrowserRouteAuthorize, "s"));
        }

        // A non-HTTPS scheme must never be selectable.
        foreach (var bad in new[]
                 {
                     "http://h.example.test",
                     "ftp://h.example.test",
                     "https://",
                     "https:opaque",
                     "https:h",
                     "https://u:p@h.example.test",
                     "https://h.example.test/x?y=1",
                     "https://h.example.test/x#f",
                 })
        {
            var e = Assert.Throws<SdkException>(() => Browser.BuildBrowserEndpoint(bad, Browser.BrowserRouteLocalRp, "s"));
            Assert.Equal(SdkException.ErrorKind.InvalidInput, e.Kind);
        }

        Assert.Throws<SdkException>(() => Browser.BuildBrowserEndpoint("https://h.example.test", "auth/no-leading-slash", "s"));
    }
}
