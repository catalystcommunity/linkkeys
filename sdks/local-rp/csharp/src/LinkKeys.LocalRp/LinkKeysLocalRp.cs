using LinkKeys.LocalRp.Dns;
using LinkKeys.LocalRp.Rpc;
using LinkKeys.LocalRp.Wire;

namespace LinkKeys.LocalRp;

/// <summary>
/// Facade for the DNS-less local RP identity mode (<c>dns-less-local-rp-design.md</c> at
/// the repo root — read it first; this SDK implements its "SDK API Shape" section
/// verbatim, C#-idiomatically adapted).
///
/// <para>This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
/// self-hosted service with no public DNS) use LinkKeys for login without running its
/// own DNS-pinned relying party. The app's identity is the fingerprint of a
/// locally-generated signing key (SSH-host-key style), not a domain.</para>
///
/// <h2>Quickstart</h2>
///
/// <code>
/// // Once, at install/setup time -- persist the returned bytes with ordinary
/// // application-secret care.
/// var identity = Identity.GenerateLocalRpIdentity(
///     new Identity.GenerateLocalRpIdentityConfig("My LAN Jukebox", DateTimeOffset.UtcNow));
/// byte[] storedBytes = Identity.LocalRpIdentityToBytes(identity);
///
/// // Later, per login attempt:
/// var reloaded = Identity.LocalRpIdentityFromBytes(storedBytes);
/// var begun = Begin.BeginLocalLogin(new Begin.BeginLocalLoginConfig(
///     reloaded, "http://jukebox.lan:8080/auth/callback", "example.com", DateTimeOffset.UtcNow));
/// // App: persist begun.Pending (e.g. in a server-side session), then redirect the
/// // browser to begun.Redirect.RedirectUrl.
///
/// // On callback (app's HTTP handler received `arrivedUrl` with an `encrypted_token=`
/// // query parameter):
/// var config = new Complete.CompleteLocalLoginConfig(
///     reloaded, begun.Pending, encryptedToken, arrivedUrl, DateTimeOffset.UtcNow);
/// var verified = Complete.CompleteLocalLogin(config);
/// // `verified` carries user id/domain, claims, domain keys used, the local RP
/// // fingerprint, and expirations -- session creation, local user records, and
/// // authorization are all the app's own responsibility.
/// </code>
///
/// <h2>Storage and single-use responsibilities this SDK assigns to the app</h2>
///
/// <list type="bullet">
/// <item><b>Key material</b>: persist the bytes from <see cref="Identity.LocalRpIdentityToBytes"/>
/// with ordinary application-secret care.</item>
/// <item><b><c>PendingLogin</c></b>: persist it between <c>BeginLocalLogin</c> and
/// <c>CompleteLocalLogin</c>, and discard it after one completion attempt. This SDK owns
/// no storage and cannot enforce single-use itself.</item>
/// <item><b>Sessions, local user records, authorization</b>: entirely the app's. This SDK
/// returns verified protocol facts; it never creates a session or writes to an app
/// database.</item>
/// </list>
///
/// <h2>Security notes</h2>
///
/// <list type="bullet">
/// <item>Revoking this local RP identity at the IDP kills future logins AND any
/// outstanding claim tickets immediately, but does NOT reach into sessions the app
/// already minted from a prior successful login.</item>
/// <item>Key rotation is not supported as a continuity operation: generating a new
/// identity means a new fingerprint and re-approval at every LinkKeys domain.</item>
/// <item>Domain keys and revocations fetched over the network are only ever trusted
/// after DNS <c>fp=</c> pinning — an unpinned/unauthenticated key can never reach the
/// verification chain.</item>
/// <item>The default DNS resolver is a hand-rolled resolver reading the OS-configured
/// <c>/etc/resolv.conf</c>; LAN resolver spoofing is an accepted, documented tradeoff
/// for this mode. Inject a hardened <see cref="IDnsResolver"/> if your deployment needs
/// more.</item>
/// </list>
/// </summary>
public static class LinkKeysLocalRp
{
    private static readonly Lazy<ITransport> LazyTransport = new(() => new StdTransport());
    private static readonly Lazy<IDnsResolver> LazyDnsResolver = new(() => new SystemDnsResolver());

    /// <summary>The default <see cref="ITransport"/>: a permissive-by-default blocking socket dialer. Memoized for the process lifetime.</summary>
    public static ITransport DefaultTransport() => LazyTransport.Value;

    /// <summary>The default <see cref="IDnsResolver"/>: the OS-configured system resolver. Memoized for the process lifetime.</summary>
    public static IDnsResolver DefaultDnsResolver() => LazyDnsResolver.Value;

    /// <summary>
    /// <c>check_expirations(identity, now) -&gt; ExpirationStatus</c> (design doc, "SDK API
    /// Shape" / "Expiration Helper"). Thin wrapper over <see cref="LocalRp.CheckExpirations"/>,
    /// taking the identity's descriptor <c>expires_at</c> directly. The SDK reports
    /// facts; the app decides whether to warn admins, warn users, block login, renew, or
    /// ignore.
    /// </summary>
    public static LocalRp.ExpirationStatus CheckExpirations(Identity.LocalRpKeyMaterial identity, DateTimeOffset now)
    {
        var descriptor = Codec.DecodeLocalRpDescriptor(identity.Descriptor.Descriptor);
        return LocalRp.CheckExpirations(descriptor.ExpiresAt, now);
    }
}
