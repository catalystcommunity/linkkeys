using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp;

/// <summary>
/// <c>begin_local_login</c> (design doc: "SDK API Shape", "Flow" steps 4-6).
///
/// <para>Pure/offline: no network access happens here. It generates a fresh
/// nonce/state, builds and signs a <c>LocalRpLoginRequest</c> around the identity's
/// already-signed descriptor, and returns a redirect URL plus the pending-login state
/// the app must persist and treat as single-use.</para>
/// </summary>
public static class Begin
{
    /// <summary>Default requested claims when the caller doesn't specify any (design doc, "Default Claim Set").</summary>
    public static readonly IReadOnlyList<string> DefaultRequestedClaims = ["display_name", "email", "handle"];

    /// <summary>Default required claims (design doc, "Default Claim Set").</summary>
    public static readonly IReadOnlyList<string> DefaultRequiredClaims = ["handle"];

    /// <summary>Default login-request lifetime: short-lived, matching the callback's own short default lifetime.</summary>
    public static readonly TimeSpan DefaultLoginRequestLifetime = TimeSpan.FromMinutes(5);

    /// <summary>Input to <see cref="BeginLocalLogin"/>. Big-config, single record.</summary>
    public sealed record BeginLocalLoginConfig(
        Identity.LocalRpKeyMaterial KeyMaterial,
        string CallbackUrl,
        string UserDomain,
        DateTimeOffset Now,
        IReadOnlyList<string>? RequestedClaims = null,
        IReadOnlyList<string>? RequiredClaims = null,
        TimeSpan? RequestLifetime = null);

    /// <summary>The redirect URL the app should send the user's browser to. This SDK never performs the redirect itself.</summary>
    public sealed record LocalLoginRedirect(string RedirectUrl);

    /// <summary>
    /// The state <see cref="BeginLocalLogin"/> returns for the app to persist (e.g. in a
    /// server-side session tied to the browser) and pass unchanged to
    /// <see cref="Complete.CompleteLocalLogin"/>. <b>Single-use</b>: the app must discard
    /// it after one completion attempt.
    /// </summary>
    /// <param name="RequiredClaims">
    /// The claim types this login required (design doc, "Default Claim Set" / SEC
    /// checklist: "the app-declared required claims are actually enforced"). Must be
    /// retained (not just used transiently while building the login request), and must
    /// round-trip through whatever form the app persists <see cref="PendingLogin"/> in —
    /// <see cref="Complete.CompleteLocalLogin"/> re-checks this set against the
    /// redemption's verified claims, so a login that began requiring e.g. <c>handle</c>
    /// can't complete without it just because the requirement was forgotten between
    /// begin and complete.
    /// </param>
    public sealed record PendingLogin(
        byte[] Nonce, byte[] State, string UserDomain, string CallbackUrl, IReadOnlyList<string> RequiredClaims);

    public sealed record BeginResult(LocalLoginRedirect Redirect, PendingLogin Pending);

    private static void ValidateCallbackScheme(string url)
    {
        if (!url.StartsWith("http://", StringComparison.Ordinal) && !url.StartsWith("https://", StringComparison.Ordinal))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, $"callback_url must be http:// or https://, got: {url}");
        }
    }

    /// <summary>
    /// <c>begin_local_login(config) -&gt; (LocalLoginRedirect, PendingLogin)</c> (design
    /// doc, "SDK API Shape"). Generates a fresh nonce/state, builds and signs a
    /// <c>LocalRpLoginRequest</c> around the identity's descriptor, and returns the full
    /// redirect URL plus the pending-login state.
    /// </summary>
    public static BeginResult BeginLocalLogin(BeginLocalLoginConfig config)
    {
        ValidateCallbackScheme(config.CallbackUrl);
        if (string.IsNullOrWhiteSpace(config.UserDomain))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "user_domain must not be empty");
        }

        var nonce = Crypto.Crypto.RandomBytes(32);
        var state = Crypto.Crypto.RandomBytes(32);

        var requestedClaims = config.RequestedClaims ?? DefaultRequestedClaims;
        var requiredClaims = config.RequiredClaims ?? DefaultRequiredClaims;
        var lifetime = config.RequestLifetime ?? DefaultLoginRequestLifetime;
        var issuedAt = Rfc3339.Format(config.Now);
        var expiresAt = Rfc3339.Format(config.Now + lifetime);

        LocalRpLoginRequest request = LocalRp.BuildLocalRpLoginRequest(
            config.KeyMaterial.Descriptor, config.CallbackUrl, nonce, state, requestedClaims, requiredClaims, issuedAt, expiresAt);
        var signed = LocalRp.SignLocalRpLoginRequest(request, config.KeyMaterial.SigningPrivateKey);

        var encoded = UrlEncoding.SignedLocalRpLoginRequestToUrlParam(signed);

        // Wire Precision: "Begin route: GET /auth/local-rp?signed_request=<...>".
        var redirectUrl = $"https://{config.UserDomain}/auth/local-rp?signed_request={encoded}";

        return new BeginResult(
            new LocalLoginRedirect(redirectUrl),
            new PendingLogin(nonce, state, config.UserDomain, config.CallbackUrl, requiredClaims));
    }
}
