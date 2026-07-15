package community.catalyst.linkkeys.localrp;

import java.time.Instant;

import community.catalyst.linkkeys.localrp.dns.DnsResolver;
import community.catalyst.linkkeys.localrp.dns.SystemDnsResolver;
import community.catalyst.linkkeys.localrp.rpc.StdTransport;
import community.catalyst.linkkeys.localrp.rpc.Transport;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpDescriptor;

/**
 * Facade for the DNS-less local RP identity mode
 * ({@code dns-less-local-rp-design.md} at the repo root &mdash; read it
 * first; this SDK implements its "SDK API Shape" section verbatim,
 * Java-idiomatically adapted).
 *
 * <p>This mode lets a locally-installed app (a LAN jukebox, a desktop tool,
 * a self-hosted service with no public DNS) use LinkKeys for login without
 * running its own DNS-pinned relying party. The app's identity is the
 * fingerprint of a locally-generated signing key (SSH-host-key style), not
 * a domain.
 *
 * <h2>Quickstart</h2>
 *
 * <pre>{@code
 * // Once, at install/setup time -- persist the returned bytes with ordinary
 * // application-secret care.
 * var identity = Identity.generateLocalRpIdentity(
 *     new Identity.GenerateLocalRpIdentityConfig("My LAN Jukebox", Instant.now()));
 * byte[] storedBytes = Identity.localRpIdentityToBytes(identity);
 *
 * // Later, per login attempt:
 * var reloaded = Identity.localRpIdentityFromBytes(storedBytes);
 * var begun = Begin.beginLocalLogin(new Begin.BeginLocalLoginConfig(
 *     reloaded, "http://jukebox.lan:8080/auth/callback", "example.com", Instant.now()));
 * // App: persist begun.pending() (e.g. in a server-side session), then
 * // redirect the browser to begun.redirect().redirectUrl().
 *
 * // On callback (app's HTTP handler received `arrivedUrl` with an
 * // `encrypted_token=` query parameter):
 * var config = new Complete.CompleteLocalLoginConfig(
 *     reloaded, begun.pending(), encryptedToken, arrivedUrl, Instant.now());
 * var verified = Complete.completeLocalLogin(config);
 * // `verified` carries user id/domain, claims, domain keys used, the local
 * // RP fingerprint, and expirations -- session creation, local user
 * // records, and authorization are all the app's own responsibility.
 * }</pre>
 *
 * <h2>Storage and single-use responsibilities this SDK assigns to the app</h2>
 *
 * <ul>
 *   <li><b>Key material</b>: persist the bytes from
 *       {@link Identity#localRpIdentityToBytes} with ordinary
 *       application-secret care.
 *   <li><b>{@code PendingLogin}</b>: persist it between
 *       {@code beginLocalLogin} and {@code completeLocalLogin}, and discard
 *       it after one completion attempt. This SDK owns no storage and
 *       cannot enforce single-use itself.
 *   <li><b>Sessions, local user records, authorization</b>: entirely the
 *       app's. This SDK returns verified protocol facts; it never creates a
 *       session or writes to an app database.
 * </ul>
 *
 * <h2>Security notes</h2>
 *
 * <ul>
 *   <li>Revoking this local RP identity at the IDP kills future logins AND
 *       any outstanding claim tickets immediately, but does NOT reach into
 *       sessions the app already minted from a prior successful login.
 *   <li>Key rotation is not supported as a continuity operation: generating
 *       a new identity means a new fingerprint and re-approval at every
 *       LinkKeys domain.
 *   <li>Domain keys and revocations fetched over the network are only ever
 *       trusted after DNS {@code fp=} pinning &mdash; an unpinned/unauthenticated
 *       key can never reach the verification chain.
 *   <li>The default DNS resolver is the OS-configured system resolver; LAN
 *       resolver spoofing is an accepted, documented tradeoff for this mode.
 *       Inject a hardened {@link DnsResolver} if your deployment needs more.
 * </ul>
 */
public final class LinkKeysLocalRp {
    private LinkKeysLocalRp() {}

    private static final class TransportHolder {
        static final Transport INSTANCE = new StdTransport();
    }

    private static final class DnsHolder {
        static final DnsResolver INSTANCE = new SystemDnsResolver();
    }

    /** The default {@link Transport}: a permissive-by-default blocking socket dialer. Memoized for the process lifetime. */
    public static Transport defaultTransport() {
        return TransportHolder.INSTANCE;
    }

    /** The default {@link DnsResolver}: the OS-configured system resolver. Memoized for the process lifetime. */
    public static DnsResolver defaultDnsResolver() {
        return DnsHolder.INSTANCE;
    }

    /**
     * {@code check_expirations(identity, now) -> ExpirationStatus} (design
     * doc, "SDK API Shape" / "Expiration Helper"). Thin wrapper over
     * {@link LocalRp#checkExpirations}, taking the identity's descriptor
     * {@code expires_at} directly. The SDK reports facts; the app decides
     * whether to warn admins, warn users, block login, renew, or ignore.
     */
    public static LocalRp.ExpirationStatus checkExpirations(Identity.LocalRpKeyMaterial identity, Instant now) {
        LocalRpDescriptor descriptor = Codec.decodeLocalRpDescriptor(identity.descriptor().descriptor());
        return LocalRp.checkExpirations(descriptor.expiresAt(), now);
    }
}
