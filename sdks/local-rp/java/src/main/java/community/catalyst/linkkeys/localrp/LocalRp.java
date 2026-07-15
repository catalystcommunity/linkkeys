package community.catalyst.linkkeys.localrp;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import community.catalyst.linkkeys.localrp.crypto.AeadSuite;
import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpCallbackHeader;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpCallbackPayload;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpDescriptor;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpEncryptedCallback;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpLoginRequest;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpTicketRedemptionRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpCallbackPayload;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpDescriptor;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpLoginRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpTicketRedemptionRequest;

/**
 * DNS-less local RP identity: pure protocol helpers. Mirrors
 * {@code crates/liblinkkeys/src/local_rp.rs} / {@code sdks/local-rp/go/localrp.go}
 * byte-for-byte per {@code dns-less-local-rp-design.md}'s "Wire Precision
 * (Normative)" section &mdash; read that first. Summary of the shape:
 *
 * <ul>
 *   <li>Every signed structure uses the envelope pattern: the payload is
 *       CBOR-encoded once, and the signature covers
 *       {@code CBOR([context: tstr, payload: bstr])} &mdash; a two-element
 *       CBOR array, never a bare {@code context || payload} concatenation.
 *   <li>Four mandatory, structure-specific context strings stop a signature
 *       over one structure from ever verifying as another.
 *   <li>The descriptor, login request, and ticket-redemption envelopes
 *       verify against the local RP's own signing key (self-asserted
 *       identity, SSH-host style). The callback payload envelope verifies
 *       against DOMAIN public keys, keyed by {@code signing_key_id}.
 *   <li>The callback ciphertext is a variant of a sealed-box construction,
 *       extended with negotiated-suite selection and cleartext-header AAD
 *       binding.
 * </ul>
 *
 * <p>This class performs no I/O: every "current time" is an explicit
 * {@code now} parameter, never the system clock, with one narrow, deliberate
 * exception ({@link #checkSigningKeyValid}) that mirrors
 * {@code liblinkkeys::crypto::check_signing_key_valid} exactly &mdash; wall
 * clock and all.
 */
public final class LocalRp {
    private LocalRp() {}

    // Signature contexts for the four local-RP signed structures.
    public static final String CTX_LOCAL_RP_DESCRIPTOR = "linkkeys-local-rp-descriptor";
    public static final String CTX_LOCAL_RP_LOGIN_REQUEST = "linkkeys-local-rp-login-request";
    public static final String CTX_LOCAL_RP_CALLBACK = "linkkeys-local-rp-callback";
    public static final String CTX_LOCAL_RP_TICKET_REDEMPTION = "linkkeys-local-rp-ticket-redemption";

    /** Default bounded clock-skew tolerance (seconds), design doc: "&plusmn;300 seconds". */
    public static final long DEFAULT_CLOCK_SKEW_SECONDS = 300;

    private static final String LOCAL_RP_CALLBACK_BOX_TAG = "linkkeys-local-rp-callback-box";

    // -----------------------------------------------------------------
    // Envelope signature input
    // -----------------------------------------------------------------

    /**
     * The signature input for every local-RP signed structure:
     * {@code CBOR([context, payload_bytes])} &mdash; a two-element array
     * with the domain-separation context string first and the exact
     * payload bytes second (encoded as a CBOR byte string, never
     * re-serialized). Deliberately NOT a bare {@code context || payload}
     * concatenation.
     */
    public static byte[] envelopeSignatureInput(String context, byte[] payloadBytes) {
        return Cbor.encode(Cbor.tuple(Cbor.vtext(context), Cbor.vbytes(payloadBytes)));
    }

    // -----------------------------------------------------------------
    // Timestamps / expirations
    // -----------------------------------------------------------------

    public static void checkTimestamps(String issuedAt, String expiresAt, Instant now, long skewSeconds) {
        Instant issued = Rfc3339.parse("issued_at", issuedAt);
        Instant expires = Rfc3339.parse("expires_at", expiresAt);
        Duration skew = Duration.ofSeconds(skewSeconds);
        if (now.plus(skew).isBefore(issued)) {
            throw new LocalRpError(LocalRpError.Kind.NOT_YET_VALID, null);
        }
        if (now.minus(skew).isAfter(expires)) {
            throw new LocalRpError(LocalRpError.Kind.EXPIRED, null);
        }
    }

    public enum ExpirationLevel {
        OK,
        NOTICE,
        WARNING,
        CRITICAL,
        EXPIRED;

        public String wireName() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }
    }

    public record ExpirationStatus(ExpirationLevel level, Instant expiresAt, Instant now) {}

    /**
     * {@code check_expirations(identity, now) -> ExpirationStatus} (design
     * doc, "Expiration Helper"). Does NOT apply clock-skew tolerance (unlike
     * {@link #checkTimestamps}): expiry warnings are advisory, day-scale
     * facts, not a replay/freshness security boundary.
     */
    public static ExpirationStatus checkExpirations(String expiresAt, Instant now) {
        Instant expires = Rfc3339.parse("expires_at", expiresAt);
        Duration remaining = Duration.between(now, expires);
        ExpirationLevel level;
        if (!now.isBefore(expires)) {
            level = ExpirationLevel.EXPIRED;
        } else if (remaining.compareTo(Duration.ofDays(30)) <= 0) {
            level = ExpirationLevel.CRITICAL;
        } else if (remaining.compareTo(Duration.ofDays(90)) <= 0) {
            level = ExpirationLevel.WARNING;
        } else if (remaining.compareTo(Duration.ofDays(180)) <= 0) {
            level = ExpirationLevel.NOTICE;
        } else {
            level = ExpirationLevel.OK;
        }
        return new ExpirationStatus(level, expires, now);
    }

    // -----------------------------------------------------------------
    // Nonce/state/audience/issuer/callback-url checks
    // -----------------------------------------------------------------

    public static void verifyNonceState(
            byte[] expectedNonce, byte[] expectedState, byte[] actualNonce, byte[] actualState) {
        // Constant-time: nonce/state are unpredictable secrets bound to a
        // specific pending login (CSRF/replay protection), not merely
        // opaque routing fields -- compare them the same way a MAC or token
        // would be compared, not with a short-circuiting byte compare.
        if (!java.security.MessageDigest.isEqual(expectedNonce, actualNonce)) {
            throw new LocalRpError(LocalRpError.Kind.NONCE_MISMATCH, null);
        }
        if (!java.security.MessageDigest.isEqual(expectedState, actualState)) {
            throw new LocalRpError(LocalRpError.Kind.STATE_MISMATCH, null);
        }
    }

    public static void verifyAudience(String payloadAudienceFingerprint, String localRpFingerprint) {
        if (!payloadAudienceFingerprint.equals(localRpFingerprint)) {
            throw new LocalRpError(LocalRpError.Kind.AUDIENCE_MISMATCH, null);
        }
    }

    public static void verifyIssuer(String payloadUserDomain, String expectedDomain) {
        if (!payloadUserDomain.equals(expectedDomain)) {
            throw new LocalRpError(LocalRpError.Kind.ISSUER_MISMATCH, null);
        }
    }

    public static void verifyCallbackUrl(String payloadCallbackUrl, String arrivedUrl) {
        if (!payloadCallbackUrl.equals(arrivedUrl)) {
            throw new LocalRpError(LocalRpError.Kind.CALLBACK_URL_MISMATCH, null);
        }
    }

    // -----------------------------------------------------------------
    // Signing-key validity (mirrors liblinkkeys::crypto::signing_key_validity
    // / check_signing_key_valid exactly, including its use of the real wall
    // clock rather than an explicit `now` parameter)
    // -----------------------------------------------------------------

    /** Rejects a signing key that is not usable as a signer: wrong key_usage, revoked, or expired (wall clock). */
    public static void checkSigningKeyValid(DomainPublicKey key) {
        if (!"sign".equals(key.keyUsage())) {
            throw new LocalRpError(LocalRpError.Kind.SIGNATURE_INVALID, "key_usage is not 'sign'");
        }
        if (key.revokedAt() != null) {
            throw new LocalRpError(LocalRpError.Kind.KEY_REVOKED, key.keyId());
        }
        Instant expires;
        try {
            expires = Rfc3339.parse("expires_at", key.expiresAt());
        } catch (LocalRpError e) {
            throw new LocalRpError(LocalRpError.Kind.KEY_EXPIRED, key.keyId());
        }
        if (Instant.now().isAfter(expires)) {
            throw new LocalRpError(LocalRpError.Kind.KEY_EXPIRED, key.keyId());
        }
    }

    // -----------------------------------------------------------------
    // Descriptor
    // -----------------------------------------------------------------

    public static LocalRpDescriptor buildLocalRpDescriptor(
            String appName,
            String localDomainHint,
            byte[] signingPublicKey,
            byte[] encryptionPublicKey,
            List<String> supportedSuites,
            String createdAt,
            String expiresAt) {
        return new LocalRpDescriptor(
                appName,
                localDomainHint,
                signingPublicKey.clone(),
                encryptionPublicKey.clone(),
                Crypto.fingerprint(signingPublicKey),
                supportedSuites,
                createdAt,
                expiresAt);
    }

    public static SignedLocalRpDescriptor signLocalRpDescriptor(LocalRpDescriptor descriptor, byte[] privateKeySeed) {
        byte[] descriptorBytes = Codec.encodeLocalRpDescriptor(descriptor);
        byte[] sigInput = envelopeSignatureInput(CTX_LOCAL_RP_DESCRIPTOR, descriptorBytes);
        byte[] signature = Crypto.signEd25519(sigInput, privateKeySeed);
        return new SignedLocalRpDescriptor(descriptorBytes, signature);
    }

    public static LocalRpDescriptor verifyLocalRpDescriptor(
            SignedLocalRpDescriptor signed, Instant now, long skewSeconds) {
        LocalRpDescriptor descriptor;
        try {
            descriptor = Codec.decodeLocalRpDescriptor(signed.descriptor());
        } catch (RuntimeException e) {
            throw new LocalRpError(LocalRpError.Kind.DECODE, e.getMessage(), e);
        }
        if (descriptor.signingPublicKey().length != 32) {
            throw new LocalRpError(LocalRpError.Kind.INVALID_KEY_LENGTH, null);
        }
        String expectedFingerprint = Crypto.fingerprint(descriptor.signingPublicKey());
        if (!descriptor.fingerprint().equals(expectedFingerprint)) {
            throw new LocalRpError(LocalRpError.Kind.FINGERPRINT_MISMATCH, null);
        }
        byte[] sigInput = envelopeSignatureInput(CTX_LOCAL_RP_DESCRIPTOR, signed.descriptor());
        if (!Crypto.verifyEd25519(sigInput, signed.signature(), descriptor.signingPublicKey())) {
            throw new LocalRpError(LocalRpError.Kind.SIGNATURE_INVALID, null);
        }
        checkTimestamps(descriptor.createdAt(), descriptor.expiresAt(), now, skewSeconds);
        return descriptor;
    }

    // -----------------------------------------------------------------
    // Login request
    // -----------------------------------------------------------------

    public static LocalRpLoginRequest buildLocalRpLoginRequest(
            SignedLocalRpDescriptor descriptor,
            String callbackUrl,
            byte[] nonce,
            byte[] state,
            List<String> requestedClaims,
            List<String> requiredClaims,
            String issuedAt,
            String expiresAt) {
        return new LocalRpLoginRequest(
                descriptor, callbackUrl, nonce, state, requestedClaims, requiredClaims, issuedAt, expiresAt);
    }

    public static SignedLocalRpLoginRequest signLocalRpLoginRequest(
            LocalRpLoginRequest request, byte[] privateKeySeed) {
        byte[] requestBytes = Codec.encodeLocalRpLoginRequest(request);
        byte[] sigInput = envelopeSignatureInput(CTX_LOCAL_RP_LOGIN_REQUEST, requestBytes);
        byte[] signature = Crypto.signEd25519(sigInput, privateKeySeed);
        return new SignedLocalRpLoginRequest(requestBytes, signature);
    }

    public static LocalRpLoginRequest verifyLocalRpLoginRequest(
            SignedLocalRpLoginRequest signed, Instant now, long skewSeconds) {
        LocalRpLoginRequest request;
        try {
            request = Codec.decodeLocalRpLoginRequest(signed.request());
        } catch (RuntimeException e) {
            throw new LocalRpError(LocalRpError.Kind.DECODE, e.getMessage(), e);
        }
        LocalRpDescriptor descriptor = verifyLocalRpDescriptor(request.descriptor(), now, skewSeconds);

        byte[] sigInput = envelopeSignatureInput(CTX_LOCAL_RP_LOGIN_REQUEST, signed.request());
        if (!Crypto.verifyEd25519(sigInput, signed.signature(), descriptor.signingPublicKey())) {
            throw new LocalRpError(LocalRpError.Kind.SIGNATURE_INVALID, null);
        }
        checkTimestamps(request.issuedAt(), request.expiresAt(), now, skewSeconds);
        return request;
    }

    // -----------------------------------------------------------------
    // Ticket redemption
    // -----------------------------------------------------------------

    public static LocalRpTicketRedemptionRequest buildLocalRpTicketRedemptionRequest(
            byte[] claimTicket, String fingerprint, String issuedAt) {
        return new LocalRpTicketRedemptionRequest(claimTicket, fingerprint, issuedAt);
    }

    public static SignedLocalRpTicketRedemptionRequest signLocalRpTicketRedemptionRequest(
            LocalRpTicketRedemptionRequest request, byte[] privateKeySeed) {
        byte[] requestBytes = Codec.encodeLocalRpTicketRedemptionRequest(request);
        byte[] sigInput = envelopeSignatureInput(CTX_LOCAL_RP_TICKET_REDEMPTION, requestBytes);
        byte[] signature = Crypto.signEd25519(sigInput, privateKeySeed);
        return new SignedLocalRpTicketRedemptionRequest(requestBytes, signature);
    }

    /**
     * Verify a ticket-redemption request's possession proof: {@code signingPublicKey}
     * is the key the caller resolved for {@code expectedFingerprint} &mdash;
     * the signature must verify against it, AND that key's own fingerprint
     * plus the request's embedded fingerprint field must both equal
     * {@code expectedFingerprint}.
     */
    public static LocalRpTicketRedemptionRequest verifyLocalRpTicketRedemptionRequest(
            SignedLocalRpTicketRedemptionRequest signed, byte[] signingPublicKey, String expectedFingerprint) {
        byte[] sigInput = envelopeSignatureInput(CTX_LOCAL_RP_TICKET_REDEMPTION, signed.request());
        if (!Crypto.verifyEd25519(sigInput, signed.signature(), signingPublicKey)) {
            throw new LocalRpError(LocalRpError.Kind.SIGNATURE_INVALID, null);
        }
        LocalRpTicketRedemptionRequest request;
        try {
            request = Codec.decodeLocalRpTicketRedemptionRequest(signed.request());
        } catch (RuntimeException e) {
            throw new LocalRpError(LocalRpError.Kind.DECODE, e.getMessage(), e);
        }
        String keyFingerprint = Crypto.fingerprint(signingPublicKey);
        if (!keyFingerprint.equals(expectedFingerprint) || !request.fingerprint().equals(expectedFingerprint)) {
            throw new LocalRpError(LocalRpError.Kind.FINGERPRINT_MISMATCH, null);
        }
        return request;
    }

    // -----------------------------------------------------------------
    // Callback payload (domain-signed envelope)
    // -----------------------------------------------------------------

    public static LocalRpCallbackPayload buildLocalRpCallbackPayload(
            String userId,
            String userDomain,
            byte[] claimTicket,
            String audienceFingerprint,
            String callbackUrl,
            byte[] nonce,
            byte[] state,
            String issuedAt,
            String expiresAt) {
        return new LocalRpCallbackPayload(
                userId, userDomain, claimTicket, audienceFingerprint, callbackUrl, nonce, state, issuedAt, expiresAt);
    }

    /**
     * Sign a callback payload with one of the issuing domain's signing keys.
     * Server-side (IDP) operation, exposed here only because it is a pure
     * protocol helper &mdash; a local-RP SDK never calls this in production,
     * only test fixtures (fake IDPs) do.
     */
    public static SignedLocalRpCallbackPayload signLocalRpCallbackPayload(
            LocalRpCallbackPayload payload, String keyId, byte[] privateKeySeed) {
        byte[] payloadBytes = Codec.encodeLocalRpCallbackPayload(payload);
        byte[] sigInput = envelopeSignatureInput(CTX_LOCAL_RP_CALLBACK, payloadBytes);
        byte[] signature = Crypto.signEd25519(sigInput, privateKeySeed);
        return new SignedLocalRpCallbackPayload(payloadBytes, keyId, signature);
    }

    /**
     * Verify a domain-signed callback payload envelope against a set of
     * domain public keys: resolve {@code signing_key_id}, reject a
     * revoked/expired/non-signing key, verify the envelope signature,
     * decode, then check {@code issued_at}/{@code expires_at} bounds.
     */
    public static LocalRpCallbackPayload verifyLocalRpCallbackPayload(
            SignedLocalRpCallbackPayload signed, List<DomainPublicKey> domainPublicKeys, Instant now, long skewSeconds) {
        DomainPublicKey key = domainPublicKeys.stream()
                .filter(k -> k.keyId().equals(signed.signingKeyId()))
                .findFirst()
                .orElseThrow(() -> new LocalRpError(LocalRpError.Kind.KEY_NOT_FOUND, signed.signingKeyId()));

        checkSigningKeyValid(key);

        if (!"ed25519".equals(key.algorithm())) {
            throw new LocalRpError(LocalRpError.Kind.UNSUPPORTED_ALGORITHM, key.algorithm());
        }
        byte[] sigInput = envelopeSignatureInput(CTX_LOCAL_RP_CALLBACK, signed.payload());
        if (!Crypto.verifyEd25519(sigInput, signed.signature(), key.publicKey())) {
            throw new LocalRpError(LocalRpError.Kind.SIGNATURE_INVALID, null);
        }

        LocalRpCallbackPayload payload;
        try {
            payload = Codec.decodeLocalRpCallbackPayload(signed.payload());
        } catch (RuntimeException e) {
            throw new LocalRpError(LocalRpError.Kind.DECODE, e.getMessage(), e);
        }
        checkTimestamps(payload.issuedAt(), payload.expiresAt(), now, skewSeconds);
        return payload;
    }

    /**
     * Cross-check the cleartext callback header's routing fields against
     * the authoritative copies inside the decrypted, domain-signature-verified
     * payload. The header is already bound as AEAD associated data, but a
     * verifier must still consult the signed copies rather than trusting
     * the header alone.
     */
    public static void checkCallbackHeaderMatchesPayload(LocalRpCallbackHeader header, LocalRpCallbackPayload payload) {
        if (!header.fingerprint().equals(payload.audienceFingerprint())) {
            throw new LocalRpError(LocalRpError.Kind.HEADER_PAYLOAD_MISMATCH, "fingerprint");
        }
        if (!java.security.MessageDigest.isEqual(header.nonce(), payload.nonce())) {
            throw new LocalRpError(LocalRpError.Kind.HEADER_PAYLOAD_MISMATCH, "nonce");
        }
        if (!java.security.MessageDigest.isEqual(header.state(), payload.state())) {
            throw new LocalRpError(LocalRpError.Kind.HEADER_PAYLOAD_MISMATCH, "state");
        }
        if (!header.issuedAt().equals(payload.issuedAt())) {
            throw new LocalRpError(LocalRpError.Kind.HEADER_PAYLOAD_MISMATCH, "issued_at");
        }
        if (!header.expiresAt().equals(payload.expiresAt())) {
            throw new LocalRpError(LocalRpError.Kind.HEADER_PAYLOAD_MISMATCH, "expires_at");
        }
    }

    // -----------------------------------------------------------------
    // Post-redemption identity binding (SEC fix: the ticket-redemption
    // response and its claims are NOT themselves domain-signed -- they
    // arrive over the same CSIL-RPC connection as an ordinary response, so
    // they must always be bound back to the identity the domain already
    // vouched for in the SIGNED callback payload before anything in them is
    // trusted.)
    // -----------------------------------------------------------------

    /**
     * Cross-check the ticket-redemption response's identity against the
     * already-verified callback payload's identity. Mismatch is fatal: a
     * compromised/malicious IDP redeeming a valid ticket but returning a
     * different user must never be allowed to impersonate that other user.
     */
    public static void verifyRedemptionIdentity(
            String redemptionUserId, String redemptionUserDomain, String payloadUserId, String payloadUserDomain) {
        if (!redemptionUserId.equals(payloadUserId) || !redemptionUserDomain.equals(payloadUserDomain)) {
            throw new LocalRpError(LocalRpError.Kind.REDEMPTION_IDENTITY_MISMATCH, null);
        }
    }

    /**
     * Cross-check a single redeemed claim's {@code user_id} against the
     * already-verified callback payload's {@code user_id}. Mismatch is
     * fatal: a claim about a different subject must never be attributed to
     * this login, even if the claim's own signature verifies correctly
     * (that only proves the signer attested it about ITS named subject, not
     * about the user who is logging in).
     */
    public static void verifyClaimIdentity(String claimUserId, String payloadUserId) {
        if (!claimUserId.equals(payloadUserId)) {
            throw new LocalRpError(LocalRpError.Kind.CLAIM_IDENTITY_MISMATCH, null);
        }
    }

    /**
     * Enforce that every claim type in {@code requiredClaims} appears in
     * {@code verifiedClaimTypes} (the claim types that already passed full
     * verification, including the identity check above). Fatal if any
     * required claim type is missing -- including the case where
     * {@code verifiedClaimTypes} is empty because the redemption returned
     * no claims at all.
     */
    public static void verifyRequiredClaimsSatisfied(
            List<String> requiredClaims, java.util.Set<String> verifiedClaimTypes) {
        for (String required : requiredClaims) {
            if (!verifiedClaimTypes.contains(required)) {
                throw new LocalRpError(LocalRpError.Kind.REQUIRED_CLAIMS_NOT_SATISFIED, required);
            }
        }
    }

    // -----------------------------------------------------------------
    // Callback sealed box (Wire Precision: "Callback sealed box")
    // -----------------------------------------------------------------

    private record KdfResult(byte[] key, byte[] context) {}

    /**
     * Derive the AEAD key and construct the KDF {@code info}/AAD-prefix
     * context for the local-RP callback sealed box:
     * {@code tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)},
     * raw concatenation. HKDF-SHA256 with no salt, expanded to 32 bytes.
     */
    private static KdfResult localRpCallbackKdf(
            AeadSuite suite, byte[] ephemeralPublic, byte[] recipientPublic, byte[] sharedSecret) {
        byte[] tag = LOCAL_RP_CALLBACK_BOX_TAG.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] suiteId = suite.wireId().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] context = new byte[tag.length + suiteId.length + 32 + 32];
        int pos = 0;
        System.arraycopy(tag, 0, context, pos, tag.length);
        pos += tag.length;
        System.arraycopy(suiteId, 0, context, pos, suiteId.length);
        pos += suiteId.length;
        System.arraycopy(ephemeralPublic, 0, context, pos, 32);
        pos += 32;
        System.arraycopy(recipientPublic, 0, context, pos, 32);

        byte[] key = Crypto.hkdfSha256(sharedSecret, context, 32);
        return new KdfResult(key, context);
    }

    /**
     * Seal a {@link SignedLocalRpCallbackPayload} into a
     * {@link LocalRpEncryptedCallback} for {@code recipientEncryptionPublicKey},
     * using {@code suite}. Production path: fresh random ephemeral X25519
     * keypair and AEAD nonce.
     */
    public static LocalRpEncryptedCallback sealLocalRpCallback(
            SignedLocalRpCallbackPayload signedPayload,
            AeadSuite suite,
            byte[] recipientEncryptionPublicKey,
            String fingerprint,
            byte[] nonce,
            byte[] state,
            String issuedAt,
            String expiresAt) {
        Crypto.X25519KeyPair ephemeral = Crypto.generateX25519KeyPair();
        byte[] aeadNonce = Crypto.randomBytes(12);
        return sealLocalRpCallbackInner(
                signedPayload,
                suite,
                recipientEncryptionPublicKey,
                fingerprint,
                nonce,
                state,
                issuedAt,
                expiresAt,
                ephemeral.privateKey(),
                ephemeral.publicKey(),
                aeadNonce);
    }

    /**
     * Deterministic variant of {@link #sealLocalRpCallback}: the caller
     * supplies the ephemeral X25519 private key and AEAD nonce instead of
     * sourcing them from {@link SecureRandom}. Production code must always
     * use {@link #sealLocalRpCallback}; this variant exists solely so tests
     * can reproduce the checked-in conformance vectors' exact ciphertexts.
     */
    public static LocalRpEncryptedCallback sealLocalRpCallbackWithRandomness(
            SignedLocalRpCallbackPayload signedPayload,
            AeadSuite suite,
            byte[] recipientEncryptionPublicKey,
            String fingerprint,
            byte[] nonce,
            byte[] state,
            String issuedAt,
            String expiresAt,
            byte[] ephemeralPrivateKey,
            byte[] aeadNonce) {
        byte[] ephemeralPublic = Crypto.derivePublicFromX25519Private(ephemeralPrivateKey);
        return sealLocalRpCallbackInner(
                signedPayload,
                suite,
                recipientEncryptionPublicKey,
                fingerprint,
                nonce,
                state,
                issuedAt,
                expiresAt,
                ephemeralPrivateKey,
                ephemeralPublic,
                aeadNonce);
    }

    private static LocalRpEncryptedCallback sealLocalRpCallbackInner(
            SignedLocalRpCallbackPayload signedPayload,
            AeadSuite suite,
            byte[] recipientEncryptionPublicKey,
            String fingerprint,
            byte[] nonce,
            byte[] state,
            String issuedAt,
            String expiresAt,
            byte[] ephemeralPrivateKey,
            byte[] ephemeralPublicKey,
            byte[] aeadNonce) {
        byte[] plaintext = Codec.encodeSignedLocalRpCallbackPayload(signedPayload);

        byte[] sharedSecret = Crypto.x25519DiffieHellman(ephemeralPrivateKey, recipientEncryptionPublicKey);

        LocalRpCallbackHeader header = new LocalRpCallbackHeader(
                fingerprint, nonce, state, suite.wireId(), ephemeralPublicKey, aeadNonce, issuedAt, expiresAt);
        byte[] headerBytes = Codec.encodeLocalRpCallbackHeader(header);

        KdfResult kdf = localRpCallbackKdf(suite, ephemeralPublicKey, recipientEncryptionPublicKey, sharedSecret);

        byte[] aad = new byte[kdf.context().length + headerBytes.length];
        System.arraycopy(kdf.context(), 0, aad, 0, kdf.context().length);
        System.arraycopy(headerBytes, 0, aad, kdf.context().length, headerBytes.length);

        byte[] ciphertext = Crypto.aeadEncrypt(suite, kdf.key(), aeadNonce, aad, plaintext);
        return new LocalRpEncryptedCallback(headerBytes, ciphertext);
    }

    /**
     * Open a {@link LocalRpEncryptedCallback} with the local RP's encryption
     * private key. {@code allowedSuites} is the local RP's own
     * supported-suite list (from its descriptor): a header advertising a
     * suite NOT in that list is rejected even if it is otherwise a valid
     * registry id.
     *
     * <p>Returns the decoded header and the still domain-signature-unverified
     * {@link SignedLocalRpCallbackPayload} &mdash; callers must still call
     * {@link #verifyLocalRpCallbackPayload} against fetched domain keys, and
     * then {@link #checkCallbackHeaderMatchesPayload}, before trusting the
     * result.
     */
    public record OpenedCallback(LocalRpCallbackHeader header, SignedLocalRpCallbackPayload signedPayload) {}

    public static OpenedCallback openLocalRpCallback(
            LocalRpEncryptedCallback encrypted, byte[] recipientEncryptionPrivateKey, List<AeadSuite> allowedSuites) {
        LocalRpCallbackHeader header;
        try {
            header = Codec.decodeLocalRpCallbackHeader(encrypted.header());
        } catch (RuntimeException e) {
            throw new LocalRpError(LocalRpError.Kind.DECODE, e.getMessage(), e);
        }

        AeadSuite suite = AeadSuite.parse(header.suite());
        if (suite == null) {
            throw new LocalRpError(LocalRpError.Kind.UNSUPPORTED_SUITE, header.suite());
        }
        if (!allowedSuites.contains(suite)) {
            throw new LocalRpError(LocalRpError.Kind.SUITE_NOT_ADVERTISED, header.suite());
        }

        if (header.ephemeralPublicKey().length != 32) {
            throw new LocalRpError(LocalRpError.Kind.INVALID_KEY_LENGTH, null);
        }
        if (header.aeadNonce().length != 12) {
            throw new LocalRpError(LocalRpError.Kind.INVALID_KEY_LENGTH, null);
        }

        byte[] recipientPublic = Crypto.derivePublicFromX25519Private(recipientEncryptionPrivateKey);

        byte[] sharedSecret;
        try {
            sharedSecret = Crypto.x25519DiffieHellman(recipientEncryptionPrivateKey, header.ephemeralPublicKey());
        } catch (community.catalyst.linkkeys.localrp.crypto.CryptoException e) {
            throw new LocalRpError(LocalRpError.Kind.CRYPTO, "non-contributory ephemeral key", e);
        }

        KdfResult kdf = localRpCallbackKdf(suite, header.ephemeralPublicKey(), recipientPublic, sharedSecret);

        byte[] aad = new byte[kdf.context().length + encrypted.header().length];
        System.arraycopy(kdf.context(), 0, aad, 0, kdf.context().length);
        System.arraycopy(encrypted.header(), 0, aad, kdf.context().length, encrypted.header().length);

        byte[] plaintext;
        try {
            plaintext = Crypto.aeadDecrypt(suite, kdf.key(), header.aeadNonce(), aad, encrypted.ciphertext());
        } catch (community.catalyst.linkkeys.localrp.crypto.CryptoException e) {
            throw new LocalRpError(LocalRpError.Kind.CRYPTO, "decrypt failed", e);
        }

        SignedLocalRpCallbackPayload signedPayload;
        try {
            signedPayload = Codec.decodeSignedLocalRpCallbackPayload(plaintext);
        } catch (RuntimeException e) {
            throw new LocalRpError(LocalRpError.Kind.DECODE, e.getMessage(), e);
        }

        return new OpenedCallback(header, signedPayload);
    }
}
