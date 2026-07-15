package community.catalyst.linkkeys.localrp;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import community.catalyst.linkkeys.localrp.Begin.PendingLogin;
import community.catalyst.linkkeys.localrp.Identity.LocalRpKeyMaterial;
import community.catalyst.linkkeys.localrp.crypto.AeadSuite;
import community.catalyst.linkkeys.localrp.dns.DnsResolver;
import community.catalyst.linkkeys.localrp.rpc.RpcClient;
import community.catalyst.linkkeys.localrp.rpc.Transport;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.Claim;
import community.catalyst.linkkeys.localrp.wire.Types.ClaimSignature;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpCallbackPayload;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpDescriptor;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpEncryptedCallback;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpTicketRedemptionRequest;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpTicketRedemptionResponse;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpTicketRedemptionRequest;

/**
 * {@code complete_local_login} (design doc: "SDK API Shape", "Flow" steps
 * 12-13).
 *
 * <p>This is the SDK's full verification chain, run in the exact order the
 * pure {@link LocalRp} helpers require:
 *
 * <ol>
 *   <li>decode the callback ciphertext from its URL-param encoding
 *   <li>open it (decrypt) &mdash; only with a suite this identity's own
 *       descriptor advertises
 *   <li>fetch the pending domain's public keys + revocations, DNS-{@code fp=}-pinned,
 *       over TCP CSIL-RPC
 *   <li>verify the domain-signed envelope (key lookup, revocation/expiry,
 *       signature, payload timestamp bounds) &mdash; only now is anything
 *       inside the payload trusted
 *   <li>cross-check the cleartext header's routing fields against the
 *       now-verified payload
 *   <li>audience / issuer / callback-URL / nonce-state checks
 *   <li>redeem the claim ticket over TCP CSIL-RPC (signed with the local
 *       RP's own key &mdash; the possession proof)
 *   <li>cross-check the (unsigned) redemption response's identity against
 *       the SIGNED callback payload's identity &mdash; fatal on mismatch
 *   <li>verify every returned claim's signatures against ITS signer
 *       domain's keys (fetched the same pinned way), which also checks the
 *       claim's own revocation/expiry, AND that each claim's subject
 *       matches the verified payload's identity
 *   <li>enforce that every {@code requiredClaims} entry from the pending
 *       login is covered by a claim that passed the checks above
 * </ol>
 */
public final class Complete {
    private Complete() {}

    /**
     * Bound on the number of distinct claim-signer domains
     * {@link #completeLocalLogin} will fetch keys for per completion. The
     * redemption response's claim signatures name their signing domains as
     * plain, not-yet-verified strings &mdash; a malicious/compromised home
     * IDP could otherwise list an unbounded number of distinct "signer
     * domains" purely to make this SDK perform many outbound DNS/TCP calls
     * to attacker-chosen targets before any signature is actually checked
     * (an SSRF/DoS amplification vector against the app's own process).
     */
    public static final int MAX_CLAIM_SIGNER_DOMAINS = Claims.MAX_CLAIM_SIGNER_DOMAINS;

    /** Input to {@link #completeLocalLogin}. Every field is load-bearing. */
    public static final class CompleteLocalLoginConfig {
        /** The same identity {@code Begin.beginLocalLogin} used. */
        public final LocalRpKeyMaterial keyMaterial;
        /** The pending-login state {@code beginLocalLogin} returned, exactly as the app persisted it. */
        public final PendingLogin pending;
        /** The raw callback data &mdash; the {@code encrypted_token} query-parameter value. */
        public final String encryptedToken;
        /** The URL the callback actually arrived at (the app's own HTTP handler's request URL). */
        public final String arrivedUrl;
        public final Instant now;
        /** Clock-skew tolerance for timestamp checks. Defaults to {@link LocalRp#DEFAULT_CLOCK_SKEW_SECONDS} when {@code null}. */
        public Long clockSkewSeconds;
        /** The TCP dial seam. Defaults to {@link LinkKeysLocalRp#defaultTransport()}. */
        public Transport transport;
        /** The DNS TXT lookup seam. Defaults to {@link LinkKeysLocalRp#defaultDnsResolver()}. */
        public DnsResolver dns;

        public CompleteLocalLoginConfig(
                LocalRpKeyMaterial keyMaterial, PendingLogin pending, String encryptedToken, String arrivedUrl, Instant now) {
            this.keyMaterial = keyMaterial;
            this.pending = pending;
            this.encryptedToken = encryptedToken;
            this.arrivedUrl = arrivedUrl;
            this.now = now;
            this.transport = LinkKeysLocalRp.defaultTransport();
            this.dns = LinkKeysLocalRp.defaultDnsResolver();
        }
    }

    /** What {@code completeLocalLogin} returns to app code. */
    public record VerifiedLocalLogin(
            String userId,
            String userDomain,
            List<Claim> claims,
            List<DomainPublicKey> domainPublicKeys,
            String localRpFingerprint,
            Instant issuedAt,
            Instant expiresAt,
            Instant ticketExpiresAt) {}

    /**
     * Undo the exact {@code ?}/{@code &} + {@code encrypted_token=} suffix
     * construction the IDP uses to deliver the callback, so the recovered
     * value can be compared against the signed payload's
     * {@code callback_url}. If the arrived URL doesn't end with that exact
     * suffix, returns it unchanged &mdash; the subsequent
     * {@link LocalRp#verifyCallbackUrl} equality check then correctly fails
     * closed rather than this method guessing.
     */
    static String stripEncryptedTokenParam(String arrivedUrl) {
        for (char sep : new char[] {'?', '&'}) {
            String marker = sep + "encrypted_token=";
            int idx = arrivedUrl.lastIndexOf(marker);
            if (idx >= 0) {
                return arrivedUrl.substring(0, idx);
            }
        }
        return arrivedUrl;
    }

    /** {@code complete_local_login(config) -> VerifiedLocalLogin} (design doc, "SDK API Shape"). */
    public static VerifiedLocalLogin completeLocalLogin(CompleteLocalLoginConfig config) {
        long skew = config.clockSkewSeconds != null ? config.clockSkewSeconds : LocalRp.DEFAULT_CLOCK_SKEW_SECONDS;

        // 1. Decode the callback's URL-param encoding.
        LocalRpEncryptedCallback encrypted = Encoding.localRpEncryptedCallbackFromUrlParam(config.encryptedToken);

        // 2. Open it, restricted to suites THIS identity's own descriptor advertises.
        LocalRpDescriptor ownDescriptor = Codec.decodeLocalRpDescriptor(config.keyMaterial.descriptor().descriptor());
        List<AeadSuite> allowedSuites = new ArrayList<>();
        for (String s : ownDescriptor.supportedSuites()) {
            AeadSuite suite = AeadSuite.parse(s);
            if (suite != null) {
                allowedSuites.add(suite);
            }
        }
        LocalRp.OpenedCallback opened =
                LocalRp.openLocalRpCallback(encrypted, config.keyMaterial.encryptionPrivateKey(), allowedSuites);

        // 3. Fetch the PENDING state's domain's keys + revocations, DNS-pinned, over TCP CSIL-RPC.
        List<DomainPublicKey> userDomainKeys =
                RpcClient.fetchDomainKeys(config.transport, config.dns, config.pending.userDomain());

        // 4. Verify the domain-signed envelope against those keys. Nothing
        // inside `payload` is trusted before this succeeds.
        LocalRpCallbackPayload payload =
                LocalRp.verifyLocalRpCallbackPayload(opened.signedPayload(), userDomainKeys, config.now, skew);

        // 5. Cross-check the cleartext header's routing twins against the now-verified payload.
        LocalRp.checkCallbackHeaderMatchesPayload(opened.header(), payload);

        // 6a. Audience: the callback names THIS local RP.
        LocalRp.verifyAudience(payload.audienceFingerprint(), config.keyMaterial.fingerprint());

        // 6b. Issuer binding: the payload's user_domain must be the domain the login was BEGUN with.
        LocalRp.verifyIssuer(payload.userDomain(), config.pending.userDomain());

        // 6c. Callback URL binding against the URL the callback actually arrived at.
        String arrivedBaseUrl = stripEncryptedTokenParam(config.arrivedUrl);
        LocalRp.verifyCallbackUrl(payload.callbackUrl(), arrivedBaseUrl);

        // 6d. Nonce/state equality against the pending state.
        LocalRp.verifyNonceState(config.pending.nonce(), config.pending.state(), payload.nonce(), payload.state());

        // 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the local RP's own key.
        LocalRpTicketRedemptionRequest redemptionRequest = LocalRp.buildLocalRpTicketRedemptionRequest(
                payload.claimTicket(), config.keyMaterial.fingerprint(), Rfc3339.format(config.now));
        SignedLocalRpTicketRedemptionRequest signedRedemption =
                LocalRp.signLocalRpTicketRedemptionRequest(redemptionRequest, config.keyMaterial.signingPrivateKey());
        LocalRpTicketRedemptionResponse redemption = RpcClient.redeemClaimTicket(
                config.transport, config.dns, config.pending.userDomain(), signedRedemption);

        // 7a. The redemption response arrives over the same CSIL-RPC
        // connection as any other reply -- it is NOT itself domain-signed.
        // Bind it back to the identity the domain already vouched for in
        // the SIGNED callback payload before trusting anything about it.
        // Fatal on mismatch: never fall through to a "verified" result.
        LocalRp.verifyRedemptionIdentity(
                redemption.userId(), redemption.userDomain(), payload.userId(), payload.userDomain());

        // 8. Verify every returned claim's signatures against ITS signer
        // domain's keys, fetched the same pinned way. Reuse the home
        // domain's already-fetched keys; fetch any additional signer
        // domains on demand, capped at MAX_CLAIM_SIGNER_DOMAINS.
        List<Claims.DomainKeySet> domainKeySets = new ArrayList<>();
        domainKeySets.add(new Claims.DomainKeySet(config.pending.userDomain(), userDomainKeys));
        for (Claim claim : redemption.claims()) {
            for (ClaimSignature sig : claim.signatures()) {
                boolean known = domainKeySets.stream().anyMatch(s -> s.domain().equals(sig.domain()));
                if (!known) {
                    if (domainKeySets.size() >= MAX_CLAIM_SIGNER_DOMAINS) {
                        throw new SdkException(
                                SdkException.Kind.INVALID_INPUT,
                                "claim set names more than " + MAX_CLAIM_SIGNER_DOMAINS
                                        + " distinct signer domains; refusing to fetch further keys");
                    }
                    List<DomainPublicKey> keys = RpcClient.fetchDomainKeys(config.transport, config.dns, sig.domain());
                    domainKeySets.add(new Claims.DomainKeySet(sig.domain(), keys));
                }
            }
        }
        // Subject domain for signature verification is the VERIFIED
        // payload's user_domain, not the unsigned redemption response's
        // (which was already cross-checked against it above, but the
        // signed value is the authoritative one to feed into crypto
        // verification).
        Set<String> verifiedClaimTypes = new LinkedHashSet<>();
        for (Claim claim : redemption.claims()) {
            // 8a. A claim naming a different subject than the verified
            // payload must never be attributed to this login, even if its
            // own signature is otherwise valid.
            LocalRp.verifyClaimIdentity(claim.userId(), payload.userId());
            Claims.verifyClaim(claim, payload.userDomain(), domainKeySets);
            verifiedClaimTypes.add(claim.claimType());
        }

        // 8b. Enforce the pending login's requiredClaims against the claims
        // that actually passed verification above. Missing or insufficient
        // -- including an empty claim set -- is fatal.
        LocalRp.verifyRequiredClaimsSatisfied(config.pending.requiredClaims(), verifiedClaimTypes);

        return new VerifiedLocalLogin(
                payload.userId(),
                payload.userDomain(),
                redemption.claims(),
                userDomainKeys,
                config.keyMaterial.fingerprint(),
                Rfc3339.parse("issued_at", payload.issuedAt()),
                Rfc3339.parse("expires_at", payload.expiresAt()),
                Rfc3339.parse("ticket_expires_at", redemption.ticketExpiresAt()));
    }
}
