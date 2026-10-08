package community.catalyst.linkkeys.localrp;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import community.catalyst.linkkeys.localrp.Identity.LocalRpKeyMaterial;
import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.dns.DnsResolver;
import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpLoginRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpLoginRequest;

/**
 * {@code begin_local_login} (design doc: "SDK API Shape", "Flow" steps 4-6).
 *
 * <p>It generates a fresh nonce/state, builds and signs a
 * {@code LocalRpLoginRequest} around the identity's already-signed
 * descriptor, and returns a redirect URL plus the pending-login state the
 * app must persist and treat as single-use.
 *
 * <p>The signing work is pure/offline. The one network touch is a DNS TXT
 * lookup of {@code _linkkeys_apis.<userDomain>} to discover the
 * browser-facing HTTPS endpoint (the identity domain is a trust domain, not
 * necessarily the host serving the login routes &mdash; see {@link Browser}).
 * The resolver is injectable via {@link BeginLocalLoginConfig#dns}; on any
 * discovery failure the redirect falls back to {@code https://<userDomain>}.
 */
public final class Begin {
    private Begin() {}

    /** Default requested claims when the caller doesn't specify any (design doc, "Default Claim Set"). */
    public static final List<String> DEFAULT_REQUESTED_CLAIMS = List.of("display_name", "email", "handle");

    /** Default required claims (design doc, "Default Claim Set"). */
    public static final List<String> DEFAULT_REQUIRED_CLAIMS = List.of("handle");

    /** Default login-request lifetime: short-lived, matching the callback's own short default lifetime. */
    public static final Duration DEFAULT_LOGIN_REQUEST_LIFETIME = Duration.ofMinutes(5);

    /** Input to {@link #beginLocalLogin}. Big-config, single class. */
    public static final class BeginLocalLoginConfig {
        public final LocalRpKeyMaterial keyMaterial;
        public final String callbackUrl;
        /** A LinkKeys login or domain. A full login adds a username hint. */
        public final String userDomain;
        public List<String> requestedClaims;
        public List<String> requiredClaims;
        public Duration requestLifetime;
        public final Instant now;
        /**
         * The DNS TXT lookup seam for browser endpoint discovery
         * ({@code _linkkeys_apis.<userDomain>}, its {@code https=} endpoint).
         * {@code null} (the default) selects
         * {@link LinkKeysLocalRp#defaultDnsResolver()}, the same default as
         * {@code Complete.CompleteLocalLoginConfig.dns}.
         */
        public DnsResolver dns;

        public BeginLocalLoginConfig(LocalRpKeyMaterial keyMaterial, String callbackUrl, String userDomain, Instant now) {
            this.keyMaterial = keyMaterial;
            this.callbackUrl = callbackUrl;
            this.userDomain = userDomain;
            this.now = now;
        }
    }

    /** The redirect URL the app should send the user's browser to. This SDK never performs the redirect itself. */
    public record LocalLoginRedirect(String redirectUrl) {}

    /**
     * The state {@link #beginLocalLogin} returns for the app to persist
     * (e.g. in a server-side session tied to the browser) and pass
     * unchanged to {@code Complete.completeLocalLogin}. <b>Single-use</b>:
     * the app must discard it after one completion attempt.
     *
     * <p>{@code requiredClaims} is retained here (not just used transiently
     * while building the login request) because {@code completeLocalLogin}
     * must enforce it against the redeemed claims (SEC fix: an IDP that
     * drops or fails to attest a required claim must fail the login, not
     * silently return less than the app required).
     */
    public record PendingLogin(byte[] nonce, byte[] state, String userDomain, String callbackUrl, List<String> requiredClaims) {

        /**
         * Serialize form for app-side persistence (e.g. a server-side
         * session store), CBOR-encoded so it round-trips exactly, including
         * {@link #requiredClaims}. An SDK-local storage convenience, not a
         * protocol wire format.
         */
        public byte[] toBytes() {
            List<Cbor.Entry> entries = new ArrayList<>();
            Cbor.putBytes(entries, "nonce", nonce);
            Cbor.putBytes(entries, "state", state);
            Cbor.putText(entries, "user_domain", userDomain);
            Cbor.putText(entries, "callback_url", callbackUrl);
            List<Cbor.Value> claimItems = new ArrayList<>();
            for (String c : requiredClaims) {
                claimItems.add(Cbor.vtext(c));
            }
            entries.add(Cbor.entry("required_claims", Cbor.varray(claimItems)));
            return Cbor.encode(Cbor.vmap(entries));
        }

        /** The inverse of {@link #toBytes()}. */
        public static PendingLogin fromBytes(byte[] bytes) {
            Cbor.Value v;
            try {
                v = Cbor.decode(bytes);
            } catch (RuntimeException e) {
                throw new SdkException(
                        SdkException.Kind.INVALID_INPUT, "malformed PendingLogin bytes: " + e.getMessage(), e);
            }
            byte[] nonce = Cbor.requireBytes(v, "nonce");
            byte[] state = Cbor.requireBytes(v, "state");
            String userDomain = Cbor.requireText(v, "user_domain");
            String callbackUrl = Cbor.requireText(v, "callback_url");
            List<String> requiredClaims = new ArrayList<>();
            for (Cbor.Value item : Cbor.asArray(Cbor.require(v, "required_claims"))) {
                requiredClaims.add(Cbor.asText(item));
            }
            return new PendingLogin(nonce, state, userDomain, callbackUrl, requiredClaims);
        }
    }

    public record BeginResult(LocalLoginRedirect redirect, PendingLogin pending) {}

    static void validateCallbackScheme(String url) {
        if (!(url.startsWith("http://") || url.startsWith("https://"))) {
            throw new SdkException(
                    SdkException.Kind.INVALID_INPUT, "callback_url must be http:// or https://, got: " + url);
        }
    }

    record IdentityInput(String username, String domain) {}

    static IdentityInput parseIdentityInput(String value) {
        String identity = value == null ? "" : value.trim();
        if (!identity.matches("[\\x00-\\x7F]+") || identity.chars().filter(c -> c == '@').count() > 1) invalidIdentity();
        int separator = identity.indexOf('@');
        String username = separator >= 0 ? identity.substring(0, separator) : null;
        String domain = separator >= 0 ? identity.substring(separator + 1) : identity;
        if (username != null && !username.matches("(?!\\.)(?!.*\\.\\.)[A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~.]{1,64}(?<!\\.)")) invalidIdentity();
        if (!validDomain(domain)) invalidIdentity();
        return new IdentityInput(username, domain.toLowerCase(java.util.Locale.ROOT));
    }

    private static boolean validDomain(String domain) {
        if (domain.length() > 259 || !domain.matches("[^:]+(?::[0-9]+)?")) return false;
        int separator = domain.lastIndexOf(':');
        String host = separator >= 0 ? domain.substring(0, separator) : domain;
        if (separator >= 0) {
            try {
                int port = Integer.parseInt(domain.substring(separator + 1));
                if (port < 1 || port > 65535) return false;
            } catch (NumberFormatException error) {
                return false;
            }
        }
        if (host.length() > 253 || (!host.contains(".") && separator < 0)) return false;
        for (String label : host.split("\\.", -1)) {
            if (label.length() < 1 || label.length() > 63 || !label.matches("(?!-)[A-Za-z0-9-]+(?<!-)")) return false;
        }
        return true;
    }

    private static void invalidIdentity() {
        throw new SdkException(SdkException.Kind.INVALID_INPUT, "identity must be a username@domain or a domain");
    }

    /**
     * {@code begin_local_login(config) -> (LocalLoginRedirect, PendingLogin)}
     * (design doc, "SDK API Shape"). Generates a fresh nonce/state, builds
     * and signs a {@code LocalRpLoginRequest} around the identity's
     * descriptor, and returns the full redirect URL plus the pending-login
     * state.
     *
     * <p>The redirect host comes from {@code _linkkeys_apis.<userDomain>}
     * discovery ({@link Browser#resolveBrowserBase}), with a fallback to the
     * identity domain itself. {@link PendingLogin#userDomain()} stays the
     * identity domain &mdash; verification is bound to it, never to the
     * discovered service host.
     */
    public static BeginResult beginLocalLogin(BeginLocalLoginConfig config) {
        validateCallbackScheme(config.callbackUrl);
        IdentityInput identity = parseIdentityInput(config.userDomain);

        byte[] nonce = Crypto.randomBytes(32);
        byte[] state = Crypto.randomBytes(32);

        List<String> requestedClaims = config.requestedClaims != null ? config.requestedClaims : DEFAULT_REQUESTED_CLAIMS;
        List<String> requiredClaims = config.requiredClaims != null ? config.requiredClaims : DEFAULT_REQUIRED_CLAIMS;
        Duration lifetime = config.requestLifetime != null ? config.requestLifetime : DEFAULT_LOGIN_REQUEST_LIFETIME;
        String issuedAt = Rfc3339.format(config.now);
        String expiresAt = Rfc3339.format(config.now.plus(lifetime));

        LocalRpLoginRequest request = LocalRp.buildLocalRpLoginRequest(
                config.keyMaterial.descriptor(),
                config.callbackUrl,
                nonce,
                state,
                requestedClaims,
                requiredClaims,
                issuedAt,
                expiresAt);
        SignedLocalRpLoginRequest signed = LocalRp.signLocalRpLoginRequest(request, config.keyMaterial.signingPrivateKey());

        String encoded = Encoding.signedLocalRpLoginRequestToUrlParam(signed);

        // Wire Precision: "Begin route: GET /auth/local-rp?signed_request=<...>"
        // -- mirrors the existing GET /auth/authorize?signed_request=... shape.
        // The host comes from `_linkkeys_apis.<userDomain>` discovery (with a
        // fallback to the identity domain itself); PendingLogin.userDomain
        // stays the identity domain -- verification is bound to it, never to
        // the discovered service host.
        DnsResolver dns = config.dns != null ? config.dns : LinkKeysLocalRp.defaultDnsResolver();
        String redirectUrl = Browser.resolveBrowserEndpoint(dns, identity.domain(), Browser.BROWSER_ROUTE_LOCAL_RP, encoded);
        if (identity.username() != null) {
            redirectUrl = Browser.appendQueryParam(redirectUrl, "username", identity.username());
        }

        return new BeginResult(
                new LocalLoginRedirect(redirectUrl),
                new PendingLogin(nonce, state, identity.domain(), config.callbackUrl, requiredClaims));
    }
}
