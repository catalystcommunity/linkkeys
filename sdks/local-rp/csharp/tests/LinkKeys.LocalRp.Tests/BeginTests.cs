namespace LinkKeys.LocalRp.Tests;

/// <summary>Unit tests for <see cref="Begin"/> (mirrors the Rust/Go/Java SDKs' own begin-module tests).</summary>
public class BeginTests
{
    private static Identity.LocalRpKeyMaterial Material() =>
        Identity.GenerateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("Test App", DateTimeOffset.UtcNow));

    [Fact]
    public void BeginDefaultsClaimsAndProducesPendingState()
    {
        var m = Material();
        var result = Begin.BeginLocalLogin(
            new Begin.BeginLocalLoginConfig(m, "http://localhost:8080/callback", "example.com", DateTimeOffset.UtcNow));

        Assert.StartsWith("https://example.com/auth/local-rp?signed_request=", result.Redirect.RedirectUrl);
        Assert.Equal("example.com", result.Pending.UserDomain);
        Assert.Equal("http://localhost:8080/callback", result.Pending.CallbackUrl);
        Assert.Equal(32, result.Pending.Nonce.Length);
        Assert.Equal(32, result.Pending.State.Length);
        Assert.Equal(Begin.DefaultRequiredClaims, result.Pending.RequiredClaims);
    }

    /// <summary>
    /// SEC fix: <see cref="Begin.PendingLogin.RequiredClaims"/> must retain whatever the
    /// caller supplied (not silently fall back to the default set) -- it is what
    /// <see cref="Complete.CompleteLocalLogin"/> later enforces the redeemed claims
    /// against.
    /// </summary>
    [Fact]
    public void BeginRetainsCallerSuppliedRequiredClaimsInPendingState()
    {
        var m = Material();
        var config = new Begin.BeginLocalLoginConfig(
            m, "http://localhost/callback", "example.com", DateTimeOffset.UtcNow, RequiredClaims: ["email", "handle"]);
        var result = Begin.BeginLocalLogin(config);
        Assert.Equal(["email", "handle"], result.Pending.RequiredClaims);
    }

    /// <summary>
    /// <see cref="Begin.PendingLogin"/> is what the app persists between
    /// <see cref="Begin.BeginLocalLogin"/> and <see cref="Complete.CompleteLocalLogin"/>
    /// (e.g. in a server-side session store) -- it must round-trip through an ordinary
    /// app-side serialize form, RequiredClaims included, or a login that began requiring
    /// e.g. <c>handle</c> could silently lose that requirement between begin and
    /// complete. Uses the BCL's <see cref="System.Text.Json"/> (no extra dependency,
    /// records serialize natively) as a representative serialize form.
    /// </summary>
    [Fact]
    public void PendingLoginRoundTripsThroughJsonSerialization()
    {
        var m = Material();
        var config = new Begin.BeginLocalLoginConfig(
            m, "http://localhost/callback", "example.com", DateTimeOffset.UtcNow, RequiredClaims: ["email", "handle"]);
        var result = Begin.BeginLocalLogin(config);

        var json = System.Text.Json.JsonSerializer.Serialize(result.Pending);
        var roundTripped = System.Text.Json.JsonSerializer.Deserialize<Begin.PendingLogin>(json);

        // Field-by-field, not record Equals: byte[]-typed record members compare by
        // reference (arrays don't override Equals), so a synthesized record equality
        // check would fail here even on a fully correct round-trip.
        Assert.NotNull(roundTripped);
        Assert.Equal(result.Pending.Nonce, roundTripped.Nonce);
        Assert.Equal(result.Pending.State, roundTripped.State);
        Assert.Equal(result.Pending.UserDomain, roundTripped.UserDomain);
        Assert.Equal(result.Pending.CallbackUrl, roundTripped.CallbackUrl);
        Assert.Equal(["email", "handle"], roundTripped.RequiredClaims);
    }

    [Fact]
    public void BeginRejectsNonHttpCallbackScheme()
    {
        var m = Material();
        Assert.Throws<SdkException>(() => Begin.BeginLocalLogin(
            new Begin.BeginLocalLoginConfig(m, "myapp://callback", "example.com", DateTimeOffset.UtcNow)));
    }

    [Fact]
    public void BeginRejectsEmptyUserDomain()
    {
        var m = Material();
        Assert.Throws<SdkException>(() => Begin.BeginLocalLogin(
            new Begin.BeginLocalLoginConfig(m, "http://localhost/callback", "", DateTimeOffset.UtcNow)));
    }

    [Fact]
    public void BeginTwoCallsNeverReuseNonceOrState()
    {
        var m = Material();
        var r1 = Begin.BeginLocalLogin(
            new Begin.BeginLocalLoginConfig(m, "http://localhost/callback", "example.com", DateTimeOffset.UtcNow));
        var r2 = Begin.BeginLocalLogin(
            new Begin.BeginLocalLoginConfig(m, "http://localhost/callback", "example.com", DateTimeOffset.UtcNow));
        Assert.NotEqual(r1.Pending.Nonce, r2.Pending.Nonce);
        Assert.NotEqual(r1.Pending.State, r2.Pending.State);
    }
}
