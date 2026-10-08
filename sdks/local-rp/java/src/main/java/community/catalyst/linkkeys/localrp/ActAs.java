package community.catalyst.linkkeys.localrp;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import community.catalyst.linkkeys.localrp.Identity.LocalRpKeyMaterial;
import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.dns.DnsResolver;
import community.catalyst.linkkeys.localrp.rpc.RpcClient;
import community.catalyst.linkkeys.localrp.rpc.Transport;
import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsCredential;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsGrant;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsGrantRequest;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsPresentation;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsRefreshRequest;
import community.catalyst.linkkeys.localrp.wire.Types.ApplicationKeySignature;
import community.catalyst.linkkeys.localrp.wire.Types.ApplicationRef;
import community.catalyst.linkkeys.localrp.wire.Types.GranteeProof;
import community.catalyst.linkkeys.localrp.wire.Types.GranteeRef;
import community.catalyst.linkkeys.localrp.wire.Types.RefreshActAsGrantResponse;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsGrant;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsGrantRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsPresentation;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsRefreshRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsScopeSet;

/**
 * Act-as grants, grantee side ({@code docs/spec/reserved/act-as-grants.md}).
 *
 * <p>A user lets this local RP (the grantee) act as the user at an enrolled
 * application (the audience). The user's home domain signs that decision. A
 * local RP is identified by its descriptor fingerprint and signs with its
 * descriptor signing key. A local RP can be a grantee only after its home
 * domain approved it, and it can never be an audience, so this class has no
 * audience-side verification.
 *
 * <p>Flow: {@link #beginActAs} sends the browser to the home domain's consent
 * page; {@link #completeActAsCallback} reads the grant id from the callback;
 * {@link #refreshActAsGrant} fetches (and later renews) the signed grant over
 * TCP CSIL-RPC; {@link #present} signs one call to the audience.
 *
 * <p>Every signature covers {@code CBOR([tag, payload_bytes])}, the same
 * construction as {@link LocalRp#envelopeSignatureInput}.
 */
public final class ActAs {
    private ActAs() {}

    /** The grantee's signature over a grant request. */
    public static final String GRANT_REQUEST_TAG = "linkkeys-act-as-grant-request-v1alpha";
    /** The grantee's signature over a refresh request. */
    public static final String REFRESH_REQUEST_TAG = "linkkeys-act-as-refresh-request-v1alpha";
    /** The grantee's signature over one presentation to the audience. */
    public static final String PRESENTATION_TAG = "linkkeys-act-as-presentation-v1alpha";

    /** Default grant-request window. */
    public static final Duration DEFAULT_REQUEST_WINDOW = Duration.ofSeconds(300);
    /** Longest grant-request window. The reference home domain refuses longer windows. */
    public static final Duration MAX_REQUEST_WINDOW = Duration.ofSeconds(900);
    /** The refresh-request window. */
    public static final Duration REFRESH_REQUEST_WINDOW = Duration.ofSeconds(300);

    // -----------------------------------------------------------------
    // Pure building blocks
    // -----------------------------------------------------------------

    /** Whole-second RFC3339 in UTC ending in {@code Z}, as the reference implementation formats act-as times. */
    public static String formatTime(Instant t) {
        return DateTimeFormatter.ISO_INSTANT.format(t.truncatedTo(ChronoUnit.SECONDS));
    }

    /** SHA-256 of a grant's signed bytes ({@code SignedActAsGrant.grant}). A presentation binds this value. */
    public static byte[] grantHash(byte[] grantBytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(grantBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /** The grantee reference for this local RP: its descriptor fingerprint. */
    public static GranteeRef localRpGrantee(LocalRpKeyMaterial keyMaterial) {
        return new GranteeRef(null, keyMaterial.fingerprint());
    }

    private static GranteeProof prove(String tag, byte[] payload, LocalRpKeyMaterial keyMaterial) {
        byte[] signature = Crypto.signEd25519(
                LocalRp.envelopeSignatureInput(tag, payload), keyMaterial.signingPrivateKey());
        return new GranteeProof(
                null, keyMaterial.descriptor(), new ApplicationKeySignature(keyMaterial.fingerprint(), signature));
    }

    /** Sign a grant request under {@link #GRANT_REQUEST_TAG} with the descriptor signing key. */
    public static SignedActAsGrantRequest signGrantRequest(ActAsGrantRequest request, LocalRpKeyMaterial keyMaterial) {
        byte[] bytes = Codec.encodeActAsGrantRequest(request);
        return new SignedActAsGrantRequest(bytes, prove(GRANT_REQUEST_TAG, bytes, keyMaterial));
    }

    /** Sign a refresh request under {@link #REFRESH_REQUEST_TAG} with the descriptor signing key. */
    public static SignedActAsRefreshRequest signRefreshRequest(
            ActAsRefreshRequest request, LocalRpKeyMaterial keyMaterial) {
        byte[] bytes = Codec.encodeActAsRefreshRequest(request);
        return new SignedActAsRefreshRequest(bytes, prove(REFRESH_REQUEST_TAG, bytes, keyMaterial));
    }

    /** Encode a signed grant request for the {@code signed_request} query parameter (unpadded base64url). */
    public static String signedGrantRequestToUrlParam(SignedActAsGrantRequest signed) {
        return Encoding.encodeUrlParam(Codec.encodeSignedActAsGrantRequest(signed));
    }

    /**
     * Sign one call to the audience. {@code requestDigest} is defined by the
     * audience's application protocol. {@code nonce} must be fresh for each
     * call; the audience owns replay protection.
     */
    public static ActAsCredential present(
            SignedActAsGrant grant,
            ApplicationRef audience,
            byte[] requestDigest,
            Instant now,
            byte[] nonce,
            LocalRpKeyMaterial keyMaterial) {
        ActAsPresentation presentation =
                new ActAsPresentation(grantHash(grant.grant()), audience, requestDigest, formatTime(now), nonce);
        byte[] bytes = Codec.encodeActAsPresentation(presentation);
        return new ActAsCredential(grant, new SignedActAsPresentation(bytes, prove(PRESENTATION_TAG, bytes, keyMaterial)));
    }

    /** The CBOR bytes of a credential, as the grantee sends them to the audience. */
    public static byte[] encodeCredential(ActAsCredential credential) {
        return Codec.encodeActAsCredential(credential);
    }

    /**
     * Decode the grant inside a signed grant, WITHOUT verifying the home
     * domain's signature. Use it to read {@code grant_id}, {@code expires_at},
     * and {@code approved_scope}, for example to schedule a refresh. The
     * audience verifies the grant.
     */
    public static ActAsGrant decodeGrantUnverified(SignedActAsGrant grant) {
        try {
            return Codec.decodeActAsGrant(grant.grant());
        } catch (Cbor.CborDecodeException e) {
            throw new SdkException(SdkException.Kind.PROTOCOL, "act-as grant did not decode: " + e.getMessage(), e);
        }
    }

    // -----------------------------------------------------------------
    // Begin
    // -----------------------------------------------------------------

    /** Input to {@link #beginActAs}. */
    public static final class BeginActAsConfig {
        public final LocalRpKeyMaterial keyMaterial;
        /** The user's LinkKeys login or domain, parsed like {@code Begin.beginLocalLogin}. Only the domain is used. */
        public final String userDomain;
        /** The CBOR of the {@code SignedActAsScopeSet}, exactly as the audience sent it. */
        public final byte[] scopeSetCbor;
        public final String callbackUrl;
        public final Instant now;
        /** Optional. An absent value sets no limit from the grantee. */
        public Long requestedLifetimeSeconds;
        /** Optional. An absent value means 0 (no renewal). */
        public Long requestedRenewalWindowSeconds;
        /** Defaults to {@link #DEFAULT_REQUEST_WINDOW}. At most {@link #MAX_REQUEST_WINDOW}. */
        public Duration requestWindow;
        /** Browser endpoint discovery seam. {@code null} selects {@link LinkKeysLocalRp#defaultDnsResolver()}. */
        public DnsResolver dns;

        public BeginActAsConfig(
                LocalRpKeyMaterial keyMaterial, String userDomain, byte[] scopeSetCbor, String callbackUrl, Instant now) {
            this.keyMaterial = keyMaterial;
            this.userDomain = userDomain;
            this.scopeSetCbor = scopeSetCbor;
            this.callbackUrl = callbackUrl;
            this.now = now;
        }
    }

    /**
     * The state {@link #beginActAs} returns. The app persists it and passes it
     * unchanged to {@link #completeActAsCallback}. Single-use.
     */
    public record PendingActAs(String nonce, String userDomain, String callbackUrl) {
        /** CBOR storage form. An SDK-local convenience, not a protocol wire format. */
        public byte[] toBytes() {
            List<Cbor.Entry> entries = new ArrayList<>();
            Cbor.putText(entries, "nonce", nonce);
            Cbor.putText(entries, "user_domain", userDomain);
            Cbor.putText(entries, "callback_url", callbackUrl);
            return Cbor.encode(Cbor.vmap(entries));
        }

        /** The inverse of {@link #toBytes()}. */
        public static PendingActAs fromBytes(byte[] bytes) {
            try {
                Cbor.Value v = Cbor.decode(bytes);
                return new PendingActAs(
                        Cbor.requireText(v, "nonce"), Cbor.requireText(v, "user_domain"), Cbor.requireText(v, "callback_url"));
            } catch (RuntimeException e) {
                throw new SdkException(
                        SdkException.Kind.INVALID_INPUT, "malformed PendingActAs bytes: " + e.getMessage(), e);
            }
        }
    }

    public record BeginActAsResult(String redirectUrl, PendingActAs pending) {}

    /**
     * Build and sign an {@code ActAsGrantRequest}, and return the browser
     * redirect to the home domain's {@code /auth/act-as} route plus the
     * pending state. The redirect host comes from
     * {@code _linkkeys_apis.<userDomain>} discovery, with the same fallback to
     * {@code https://<userDomain>} as {@link Begin#beginLocalLogin}.
     */
    public static BeginActAsResult beginActAs(BeginActAsConfig config) {
        Begin.validateCallbackScheme(config.callbackUrl);
        Begin.IdentityInput identity = Begin.parseIdentityInput(config.userDomain);
        Duration window = config.requestWindow != null ? config.requestWindow : DEFAULT_REQUEST_WINDOW;
        if (window.isNegative() || window.isZero() || window.compareTo(MAX_REQUEST_WINDOW) > 0) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "request window must be 1 to 900 seconds");
        }
        if (config.requestedLifetimeSeconds != null && config.requestedLifetimeSeconds <= 0) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "requested lifetime must be positive");
        }
        if (config.requestedRenewalWindowSeconds != null && config.requestedRenewalWindowSeconds < 0) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "requested renewal window must not be negative");
        }
        SignedActAsScopeSet scopeSet;
        try {
            scopeSet = Codec.decodeSignedActAsScopeSet(config.scopeSetCbor);
        } catch (Cbor.CborDecodeException e) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "scope set did not decode: " + e.getMessage(), e);
        }

        String nonce = Encoding.encodeUrlParam(Crypto.randomBytes(32));
        ActAsGrantRequest request = new ActAsGrantRequest(
                localRpGrantee(config.keyMaterial),
                scopeSet,
                config.requestedLifetimeSeconds,
                config.requestedRenewalWindowSeconds,
                config.callbackUrl,
                nonce,
                formatTime(config.now),
                formatTime(config.now.plus(window)));
        SignedActAsGrantRequest signed = signGrantRequest(request, config.keyMaterial);

        DnsResolver dns = config.dns != null ? config.dns : LinkKeysLocalRp.defaultDnsResolver();
        String redirectUrl = Browser.resolveBrowserEndpoint(
                dns, identity.domain(), Browser.BROWSER_ROUTE_ACT_AS, signedGrantRequestToUrlParam(signed));
        return new BeginActAsResult(redirectUrl, new PendingActAs(nonce, identity.domain(), config.callbackUrl));
    }

    // -----------------------------------------------------------------
    // Callback
    // -----------------------------------------------------------------

    /**
     * Read the home domain's callback. {@code callback} is the URL the
     * callback arrived at, or only its query string. The {@code nonce}
     * parameter must equal the pending nonce (constant-time compare).
     * Returns the {@code act_as_grant_id}. The grant itself does not travel
     * through the browser: fetch it with {@link #refreshActAsGrant}.
     *
     * @throws LocalRpError (kind {@code NONCE_MISMATCH}) when the nonce differs.
     * @throws SdkException (kind {@code INVALID_INPUT}) when a parameter is missing, repeated, or malformed.
     */
    public static String completeActAsCallback(PendingActAs pending, String callback) {
        String query = callback == null ? "" : callback;
        int q = query.indexOf('?');
        if (q >= 0) {
            query = query.substring(q + 1);
        }
        int fragment = query.indexOf('#');
        if (fragment >= 0) {
            query = query.substring(0, fragment);
        }
        String grantId = null;
        String nonce = null;
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String name = queryDecode(eq >= 0 ? pair.substring(0, eq) : pair);
            String value = eq >= 0 ? queryDecode(pair.substring(eq + 1)) : "";
            if (name.equals("act_as_grant_id")) {
                if (grantId != null) {
                    throw new SdkException(SdkException.Kind.INVALID_INPUT, "callback repeats act_as_grant_id");
                }
                grantId = value;
            } else if (name.equals("nonce")) {
                if (nonce != null) {
                    throw new SdkException(SdkException.Kind.INVALID_INPUT, "callback repeats nonce");
                }
                nonce = value;
            }
        }
        if (nonce == null) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "callback has no nonce");
        }
        if (!MessageDigest.isEqual(
                pending.nonce().getBytes(StandardCharsets.UTF_8), nonce.getBytes(StandardCharsets.UTF_8))) {
            throw new LocalRpError(LocalRpError.Kind.NONCE_MISMATCH, null);
        }
        if (grantId == null || grantId.isEmpty()) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "callback has no act_as_grant_id");
        }
        return grantId;
    }

    private static String queryDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "callback query is not valid percent-encoding", e);
        }
    }

    // -----------------------------------------------------------------
    // Refresh
    // -----------------------------------------------------------------

    /** Input to {@link #refreshActAsGrant}. */
    public static final class RefreshActAsGrantConfig {
        public final LocalRpKeyMaterial keyMaterial;
        /** The user's home domain: {@link PendingActAs#userDomain()}. */
        public final String userDomain;
        public final String grantId;
        public final Instant now;
        /** The TCP dial seam. Defaults to {@link LinkKeysLocalRp#defaultTransport()}. */
        public Transport transport;
        /** The DNS TXT lookup seam. Defaults to {@link LinkKeysLocalRp#defaultDnsResolver()}. */
        public DnsResolver dns;

        public RefreshActAsGrantConfig(LocalRpKeyMaterial keyMaterial, String userDomain, String grantId, Instant now) {
            this.keyMaterial = keyMaterial;
            this.userDomain = userDomain;
            this.grantId = grantId;
            this.now = now;
            this.transport = LinkKeysLocalRp.defaultTransport();
            this.dns = LinkKeysLocalRp.defaultDnsResolver();
        }
    }

    /** What {@link #refreshActAsGrant} returns. {@code signed} is true when the home domain signed a new grant for this call. */
    public record RefreshedActAsGrant(SignedActAsGrant grant, boolean signed) {}

    /**
     * Fetch the current grant, or a renewed one, from the user's home domain
     * ({@code ActAs/refresh-grant} over TCP CSIL-RPC, DNS-{@code fp=}-pinned,
     * the same path as claim-ticket redemption). Call it first after the
     * callback, and again when less than half of the grant's life remains.
     * This does not verify the grant; the audience does.
     */
    public static RefreshedActAsGrant refreshActAsGrant(RefreshActAsGrantConfig config) {
        if (config.grantId == null || config.grantId.isEmpty()) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "grant id must not be empty");
        }
        ActAsRefreshRequest request = new ActAsRefreshRequest(
                config.grantId,
                localRpGrantee(config.keyMaterial),
                formatTime(config.now),
                formatTime(config.now.plus(REFRESH_REQUEST_WINDOW)),
                Encoding.encodeUrlParam(Crypto.randomBytes(32)));
        SignedActAsRefreshRequest signed = signRefreshRequest(request, config.keyMaterial);
        RefreshActAsGrantResponse response;
        ActAsGrant grant;
        try {
            response = RpcClient.refreshActAsGrant(config.transport, config.dns, config.userDomain, signed);
            grant = Codec.decodeActAsGrant(response.grant().grant());
        } catch (Cbor.CborDecodeException e) {
            throw new SdkException(SdkException.Kind.PROTOCOL, "refresh-grant response did not decode: " + e.getMessage(), e);
        }
        // The audience checks the grant signature. This only checks that the
        // home domain returned the grant this call asked for, so a confused or
        // hostile server cannot hand this grantee another grant.
        if (!grant.grantId().equals(config.grantId)) {
            throw new LocalRpError(LocalRpError.Kind.GRANT_MISMATCH, "refresh-grant returned another grant id");
        }
        if (grant.grantee().application() != null
                || !config.keyMaterial.fingerprint().equals(grant.grantee().localRpDescriptorFingerprint())) {
            throw new LocalRpError(LocalRpError.Kind.GRANT_MISMATCH, "refresh-grant returned a grant for another grantee");
        }
        if (!asciiLower(grant.subjectDomain()).equals(asciiLower(config.userDomain))) {
            throw new LocalRpError(LocalRpError.Kind.GRANT_MISMATCH, "refresh-grant returned a grant from another subject domain");
        }
        return new RefreshedActAsGrant(response.grant(), response.signed());
    }

    /**
     * ASCII-only lower case, for domain comparison. {@code String.toLowerCase}
     * also folds non-ASCII letters (U+212A KELVIN SIGN becomes "k").
     */
    private static String asciiLower(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            out.append(c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c);
        }
        return out.toString();
    }
}
