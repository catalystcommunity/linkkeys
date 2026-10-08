using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using LinkKeys.LocalRp.Dns;
using LinkKeys.LocalRp.Rpc;
using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp;

/// <summary>
/// Act-as grants, grantee side (<c>docs/spec/reserved/act-as-grants.md</c>).
///
/// <para>A user lets this local RP (the grantee) act as the user at an enrolled
/// application (the audience). The user's home domain signs that decision. A local RP is
/// identified by its descriptor fingerprint and signs with its descriptor signing key. A
/// local RP can be a grantee only after its home domain approved it, and it can never be
/// an audience, so this class has no audience-side verification.</para>
///
/// <para>Flow: <see cref="BeginActAs"/> sends the browser to the home domain's consent
/// page; <see cref="CompleteActAsCallback"/> reads the grant id from the callback;
/// <see cref="RefreshActAsGrant"/> fetches (and later renews) the signed grant over TCP
/// CSIL-RPC; <see cref="Present"/> signs one call to the audience.</para>
///
/// <para>Every signature covers <c>CBOR([tag, payload_bytes])</c>, the same construction
/// as <see cref="LocalRp.EnvelopeSignatureInput"/>.</para>
/// </summary>
public static class ActAs
{
    /// <summary>The grantee's signature over a grant request.</summary>
    public const string GrantRequestTag = "linkkeys-act-as-grant-request-v1alpha";

    /// <summary>The grantee's signature over a refresh request.</summary>
    public const string RefreshRequestTag = "linkkeys-act-as-refresh-request-v1alpha";

    /// <summary>The grantee's signature over one presentation to the audience.</summary>
    public const string PresentationTag = "linkkeys-act-as-presentation-v1alpha";

    /// <summary>Default grant-request window.</summary>
    public static readonly TimeSpan DefaultRequestWindow = TimeSpan.FromSeconds(300);

    /// <summary>Longest grant-request window. The reference home domain refuses longer windows.</summary>
    public static readonly TimeSpan MaxRequestWindow = TimeSpan.FromSeconds(900);

    /// <summary>The refresh-request window.</summary>
    public static readonly TimeSpan RefreshRequestWindow = TimeSpan.FromSeconds(300);

    // -----------------------------------------------------------------
    // Pure building blocks
    // -----------------------------------------------------------------

    /// <summary>Whole-second RFC3339 in UTC ending in <c>Z</c>, as the reference implementation formats act-as times.</summary>
    public static string FormatTime(DateTimeOffset t) =>
        t.ToUniversalTime().ToString("yyyy-MM-dd\\THH:mm:ss\\Z", CultureInfo.InvariantCulture);

    /// <summary>SHA-256 of a grant's signed bytes (<c>SignedActAsGrant.Grant</c>). A presentation binds this value.</summary>
    public static byte[] GrantHash(byte[] grantBytes) => SHA256.HashData(grantBytes);

    /// <summary>The grantee reference for this local RP: its descriptor fingerprint.</summary>
    public static GranteeRef LocalRpGrantee(Identity.LocalRpKeyMaterial keyMaterial) => new(null, keyMaterial.Fingerprint);

    private static GranteeProof Prove(string tag, byte[] payload, Identity.LocalRpKeyMaterial keyMaterial)
    {
        var signature = Crypto.Crypto.SignEd25519(LocalRp.EnvelopeSignatureInput(tag, payload), keyMaterial.SigningPrivateKey);
        return new GranteeProof(null, keyMaterial.Descriptor, new ApplicationKeySignature(keyMaterial.Fingerprint, signature));
    }

    /// <summary>Sign a grant request under <see cref="GrantRequestTag"/> with the descriptor signing key.</summary>
    public static SignedActAsGrantRequest SignGrantRequest(ActAsGrantRequest request, Identity.LocalRpKeyMaterial keyMaterial)
    {
        var bytes = Codec.EncodeActAsGrantRequest(request);
        return new SignedActAsGrantRequest(bytes, Prove(GrantRequestTag, bytes, keyMaterial));
    }

    /// <summary>Sign a refresh request under <see cref="RefreshRequestTag"/> with the descriptor signing key.</summary>
    public static SignedActAsRefreshRequest SignRefreshRequest(ActAsRefreshRequest request, Identity.LocalRpKeyMaterial keyMaterial)
    {
        var bytes = Codec.EncodeActAsRefreshRequest(request);
        return new SignedActAsRefreshRequest(bytes, Prove(RefreshRequestTag, bytes, keyMaterial));
    }

    /// <summary>Encode a signed grant request for the <c>signed_request</c> query parameter (unpadded base64url).</summary>
    public static string SignedGrantRequestToUrlParam(SignedActAsGrantRequest signed) =>
        UrlEncoding.EncodeUrlParam(Codec.EncodeSignedActAsGrantRequest(signed));

    /// <summary>
    /// Sign one call to the audience. <paramref name="requestDigest"/> is defined by the
    /// audience's application protocol. <paramref name="nonce"/> must be fresh for each
    /// call; the audience owns replay protection.
    /// </summary>
    public static ActAsCredential Present(
        SignedActAsGrant grant,
        ApplicationRef audience,
        byte[] requestDigest,
        DateTimeOffset now,
        byte[] nonce,
        Identity.LocalRpKeyMaterial keyMaterial)
    {
        var presentation = new ActAsPresentation(GrantHash(grant.Grant), audience, requestDigest, FormatTime(now), nonce);
        var bytes = Codec.EncodeActAsPresentation(presentation);
        return new ActAsCredential(grant, new SignedActAsPresentation(bytes, Prove(PresentationTag, bytes, keyMaterial)));
    }

    /// <summary>The CBOR bytes of a credential, as the grantee sends them to the audience.</summary>
    public static byte[] EncodeCredential(ActAsCredential credential) => Codec.EncodeActAsCredential(credential);

    /// <summary>
    /// Decode the grant inside a signed grant, WITHOUT verifying the home domain's
    /// signature. Use it to read <c>grant_id</c>, <c>expires_at</c>, and
    /// <c>approved_scope</c>, for example to schedule a refresh. The audience verifies
    /// the grant.
    /// </summary>
    public static ActAsGrant DecodeGrantUnverified(SignedActAsGrant grant)
    {
        try
        {
            return Codec.DecodeActAsGrant(grant.Grant);
        }
        catch (Cbor.CborDecodeException e)
        {
            throw new SdkException(SdkException.ErrorKind.Protocol, $"act-as grant did not decode: {e.Message}", e);
        }
    }

    // -----------------------------------------------------------------
    // Begin
    // -----------------------------------------------------------------

    /// <summary>Input to <see cref="BeginActAs"/>.</summary>
    /// <param name="UserDomain">The user's LinkKeys login or domain, parsed like <see cref="Begin.BeginLocalLogin"/>. Only the domain is used.</param>
    /// <param name="ScopeSetCbor">The CBOR of the <c>SignedActAsScopeSet</c>, exactly as the audience sent it.</param>
    /// <param name="RequestedLifetimeSeconds">Optional. An absent value sets no limit from the grantee.</param>
    /// <param name="RequestedRenewalWindowSeconds">Optional. An absent value means 0 (no renewal).</param>
    /// <param name="RequestWindow">Defaults to <see cref="DefaultRequestWindow"/>. At most <see cref="MaxRequestWindow"/>.</param>
    /// <param name="Dns">Browser endpoint discovery seam. <c>null</c> selects <see cref="LinkKeysLocalRp.DefaultDnsResolver"/>.</param>
    public sealed record BeginActAsConfig(
        Identity.LocalRpKeyMaterial KeyMaterial,
        string UserDomain,
        byte[] ScopeSetCbor,
        string CallbackUrl,
        DateTimeOffset Now,
        long? RequestedLifetimeSeconds = null,
        long? RequestedRenewalWindowSeconds = null,
        TimeSpan? RequestWindow = null,
        IDnsResolver? Dns = null);

    /// <summary>
    /// The state <see cref="BeginActAs"/> returns. The app persists it and passes it
    /// unchanged to <see cref="CompleteActAsCallback"/>. Single-use.
    /// </summary>
    public sealed record PendingActAs(string Nonce, string UserDomain, string CallbackUrl)
    {
        /// <summary>CBOR storage form. An SDK-local convenience, not a protocol wire format.</summary>
        public byte[] ToBytes()
        {
            var e = new List<Cbor.Entry>();
            Cbor.PutText(e, "nonce", Nonce);
            Cbor.PutText(e, "user_domain", UserDomain);
            Cbor.PutText(e, "callback_url", CallbackUrl);
            return Cbor.Encode(Cbor.VMapOf(e));
        }

        /// <summary>The inverse of <see cref="ToBytes"/>.</summary>
        public static PendingActAs FromBytes(byte[] bytes)
        {
            try
            {
                var v = Cbor.Decode(bytes);
                return new PendingActAs(Cbor.RequireText(v, "nonce"), Cbor.RequireText(v, "user_domain"), Cbor.RequireText(v, "callback_url"));
            }
            catch (Cbor.CborDecodeException e)
            {
                throw new SdkException(SdkException.ErrorKind.InvalidInput, $"malformed PendingActAs bytes: {e.Message}", e);
            }
        }
    }

    public sealed record BeginActAsResult(string RedirectUrl, PendingActAs Pending);

    /// <summary>
    /// Build and sign an <c>ActAsGrantRequest</c>, and return the browser redirect to the
    /// home domain's <c>/auth/act-as</c> route plus the pending state. The redirect host
    /// comes from <c>_linkkeys_apis.&lt;UserDomain&gt;</c> discovery, with the same
    /// fallback to <c>https://&lt;UserDomain&gt;</c> as <see cref="Begin.BeginLocalLogin"/>.
    /// </summary>
    public static BeginActAsResult BeginActAs(BeginActAsConfig config)
    {
        Begin.ValidateCallbackScheme(config.CallbackUrl);
        var identity = Begin.ParseIdentityInput(config.UserDomain);
        var window = config.RequestWindow ?? DefaultRequestWindow;
        if (window <= TimeSpan.Zero || window > MaxRequestWindow)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "request window must be 1 to 900 seconds");
        }

        if (config.RequestedLifetimeSeconds is <= 0)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "requested lifetime must be positive");
        }

        if (config.RequestedRenewalWindowSeconds is < 0)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "requested renewal window must not be negative");
        }

        SignedActAsScopeSet scopeSet;
        try
        {
            scopeSet = Codec.DecodeSignedActAsScopeSet(config.ScopeSetCbor);
        }
        catch (Cbor.CborDecodeException e)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, $"scope set did not decode: {e.Message}", e);
        }

        var nonce = UrlEncoding.EncodeUrlParam(Crypto.Crypto.RandomBytes(32));
        var request = new ActAsGrantRequest(
            LocalRpGrantee(config.KeyMaterial),
            scopeSet,
            config.RequestedLifetimeSeconds,
            config.RequestedRenewalWindowSeconds,
            config.CallbackUrl,
            nonce,
            FormatTime(config.Now),
            FormatTime(config.Now + window));
        var signed = SignGrantRequest(request, config.KeyMaterial);

        var dns = config.Dns ?? LinkKeysLocalRp.DefaultDnsResolver();
        var redirectUrl = Browser.ResolveBrowserEndpoint(dns, identity.Domain, Browser.BrowserRouteActAs, SignedGrantRequestToUrlParam(signed));
        return new BeginActAsResult(redirectUrl, new PendingActAs(nonce, identity.Domain, config.CallbackUrl));
    }

    // -----------------------------------------------------------------
    // Callback
    // -----------------------------------------------------------------

    /// <summary>
    /// Read the home domain's callback. <paramref name="callback"/> is the URL the
    /// callback arrived at, or only its query string. The <c>nonce</c> parameter must
    /// equal the pending nonce (constant-time compare). Returns the
    /// <c>act_as_grant_id</c>. The grant itself does not travel through the browser:
    /// fetch it with <see cref="RefreshActAsGrant"/>.
    /// </summary>
    /// <exception cref="LocalRpError">Kind <c>NonceMismatch</c> when the nonce differs.</exception>
    /// <exception cref="SdkException">Kind <c>InvalidInput</c> when a parameter is missing, repeated, or malformed.</exception>
    public static string CompleteActAsCallback(PendingActAs pending, string callback)
    {
        var query = callback ?? "";
        var q = query.IndexOf('?');
        if (q >= 0) query = query[(q + 1)..];
        var fragment = query.IndexOf('#');
        if (fragment >= 0) query = query[..fragment];

        string? grantId = null;
        string? nonce = null;
        foreach (var pair in query.Split('&'))
        {
            if (pair.Length == 0) continue;
            var eq = pair.IndexOf('=');
            var name = QueryDecode(eq >= 0 ? pair[..eq] : pair);
            var value = eq >= 0 ? QueryDecode(pair[(eq + 1)..]) : "";
            if (name == "act_as_grant_id")
            {
                if (grantId is not null) throw new SdkException(SdkException.ErrorKind.InvalidInput, "callback repeats act_as_grant_id");
                grantId = value;
            }
            else if (name == "nonce")
            {
                if (nonce is not null) throw new SdkException(SdkException.ErrorKind.InvalidInput, "callback repeats nonce");
                nonce = value;
            }
        }

        if (nonce is null) throw new SdkException(SdkException.ErrorKind.InvalidInput, "callback has no nonce");
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(pending.Nonce), Encoding.UTF8.GetBytes(nonce)))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.NonceMismatch, null);
        }

        if (string.IsNullOrEmpty(grantId)) throw new SdkException(SdkException.ErrorKind.InvalidInput, "callback has no act_as_grant_id");
        return grantId;
    }

    /// <summary>
    /// Decode one query component: <c>+</c> is a space, then percent-decoding. A
    /// malformed escape is an error, not silently passed through.
    /// </summary>
    private static string QueryDecode(string s)
    {
        var plus = s.Replace('+', ' ');
        for (var i = plus.IndexOf('%'); i >= 0; i = plus.IndexOf('%', i + 1))
        {
            if (i + 2 >= plus.Length || !Uri.IsHexDigit(plus[i + 1]) || !Uri.IsHexDigit(plus[i + 2]))
            {
                throw new SdkException(SdkException.ErrorKind.InvalidInput, "callback query is not valid percent-encoding");
            }
        }

        return Uri.UnescapeDataString(plus);
    }

    // -----------------------------------------------------------------
    // Refresh
    // -----------------------------------------------------------------

    /// <summary>Input to <see cref="RefreshActAsGrant"/>.</summary>
    /// <param name="UserDomain">The user's home domain: <see cref="PendingActAs.UserDomain"/>.</param>
    /// <param name="Transport">The TCP dial seam. <c>null</c> selects <see cref="LinkKeysLocalRp.DefaultTransport"/>.</param>
    /// <param name="Dns">The DNS TXT lookup seam. <c>null</c> selects <see cref="LinkKeysLocalRp.DefaultDnsResolver"/>.</param>
    public sealed record RefreshActAsGrantConfig(
        Identity.LocalRpKeyMaterial KeyMaterial,
        string UserDomain,
        string GrantId,
        DateTimeOffset Now,
        ITransport? Transport = null,
        IDnsResolver? Dns = null);

    /// <summary>What <see cref="RefreshActAsGrant"/> returns. <c>Signed</c> is true when the home domain signed a new grant for this call.</summary>
    public sealed record RefreshedActAsGrant(SignedActAsGrant Grant, bool Signed);

    /// <summary>
    /// Fetch the current grant, or a renewed one, from the user's home domain
    /// (<c>ActAs/refresh-grant</c> over TCP CSIL-RPC, DNS-<c>fp=</c>-pinned, the same path
    /// as claim-ticket redemption). Call it first after the callback, and again when less
    /// than half of the grant's life remains. This does not verify the grant
    /// signature; the audience does. It does check that the grant names the requested
    /// grant id, this local RP, and <c>UserDomain</c>.
    /// </summary>
    public static RefreshedActAsGrant RefreshActAsGrant(RefreshActAsGrantConfig config)
    {
        if (string.IsNullOrEmpty(config.GrantId))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "grant id must not be empty");
        }

        var request = new ActAsRefreshRequest(
            config.GrantId,
            LocalRpGrantee(config.KeyMaterial),
            FormatTime(config.Now),
            FormatTime(config.Now + RefreshRequestWindow),
            UrlEncoding.EncodeUrlParam(Crypto.Crypto.RandomBytes(32)));
        var signed = SignRefreshRequest(request, config.KeyMaterial);
        RefreshActAsGrantResponse response;
        ActAsGrant grant;
        try
        {
            response = RpcClient.RefreshActAsGrant(
                config.Transport ?? LinkKeysLocalRp.DefaultTransport(),
                config.Dns ?? LinkKeysLocalRp.DefaultDnsResolver(),
                config.UserDomain,
                signed);
            grant = Codec.DecodeActAsGrant(response.Grant.Grant);
        }
        catch (Cbor.CborDecodeException e)
        {
            throw new SdkException(SdkException.ErrorKind.Protocol, $"refresh-grant response did not decode: {e.Message}", e);
        }

        // The audience checks the grant signature. This only checks that the home
        // domain returned the grant this call asked for, so a confused or hostile
        // server cannot hand this grantee another grant.
        if (grant.GrantId != config.GrantId)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.GrantMismatch, "refresh-grant returned another grant id");
        }
        if (grant.Grantee.Application is not null
            || grant.Grantee.LocalRpDescriptorFingerprint != config.KeyMaterial.Fingerprint)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.GrantMismatch, "refresh-grant returned a grant for another grantee");
        }
        if (AsciiLower(grant.SubjectDomain) != AsciiLower(config.UserDomain))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.GrantMismatch, "refresh-grant returned a grant from another subject domain");
        }

        return new RefreshedActAsGrant(response.Grant, response.Signed);
    }

    /// <summary>ASCII-only lower case, for domain comparison.</summary>
    private static string AsciiLower(string value) =>
        string.Create(value.Length, value, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                var c = source[i];
                span[i] = c is >= 'A' and <= 'Z' ? (char)(c + ('a' - 'A')) : c;
            }
        });
}
