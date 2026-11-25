package community.catalyst.linkkeys.localrp.wire;

import java.time.Instant;
import java.util.List;

/**
 * Hand-written wire types for exactly the CSIL structures the DNS-less
 * local-RP protocol needs. <b>Hand-written, pending a csilgen Java target</b>
 * (see this package's {@link Cbor} docs and the filed csilgen request) &mdash;
 * field names and shapes mirror {@code csil/linkkeys.csil} and the generated
 * Rust/Go types in {@code crates/liblinkkeys/src/generated/types.rs} /
 * {@code sdks/local-rp/go/generated/types.gen.go} exactly.
 *
 * <p>These are plain data carriers, not builders: optional fields are
 * {@code null} when absent (mirroring Rust {@code Option::None} / Go nil
 * pointers), and byte-array fields are raw, unencoded bytes. CSIL
 * {@code timestamp} fields are {@link Instant}s (tag 0 RFC 3339 text on the
 * wire). Closed vocabularies (key algorithm, key usage, AEAD suite) keep
 * their text labels here; {@link Codec} writes their CSIL numbers on the
 * wire. Encoding/decoding lives in {@link Codec}.
 */
public final class Types {
    private Types() {}

    /** The empty request type used by unauthenticated no-argument RPC calls. */
    public record EmptyRequest() {}

    public record DomainPublicKey(
            String keyId,
            byte[] publicKey,
            String fingerprint,
            String algorithm,
            String keyUsage,
            Instant createdAt,
            Instant expiresAt,
            Instant revokedAt,
            String signedByKeyId,
            byte[] keySignature) {}

    public record GetDomainKeysResponse(
            String domain, List<DomainPublicKey> keys, Boolean recentRevocationsAvailable) {}

    public record GetRevocationsRequest(Instant since) {}

    public record ClaimSignature(String domain, String signedByKeyId, byte[] signature) {}

    public record RevocationCertificate(
            String targetKeyId,
            String targetFingerprint,
            Instant revokedAt,
            List<ClaimSignature> signatures) {}

    public record GetRevocationsResponse(List<RevocationCertificate> revocations) {}

    public record Claim(
            String claimId,
            String userId,
            String claimType,
            byte[] claimValue,
            List<ClaimSignature> signatures,
            Instant attestedAt,
            Instant createdAt,
            Instant expiresAt,
            Instant revokedAt) {}

    public record LocalRpDescriptor(
            String appName,
            String localDomainHint,
            byte[] signingPublicKey,
            byte[] encryptionPublicKey,
            String fingerprint,
            List<String> supportedSuites,
            Instant createdAt,
            Instant expiresAt) {}

    public record SignedLocalRpDescriptor(byte[] descriptor, byte[] signature) {}

    public record LocalRpLoginRequest(
            SignedLocalRpDescriptor descriptor,
            String callbackUrl,
            byte[] nonce,
            byte[] state,
            List<String> requestedClaims,
            List<String> requiredClaims,
            Instant issuedAt,
            Instant expiresAt) {}

    public record SignedLocalRpLoginRequest(byte[] request, byte[] signature) {}

    public record LocalRpCallbackHeader(
            String fingerprint,
            byte[] nonce,
            byte[] state,
            String suite,
            byte[] ephemeralPublicKey,
            byte[] aeadNonce,
            Instant issuedAt,
            Instant expiresAt) {}

    public record LocalRpEncryptedCallback(byte[] header, byte[] ciphertext) {}

    public record LocalRpCallbackPayload(
            String userId,
            String userDomain,
            byte[] claimTicket,
            String audienceFingerprint,
            String callbackUrl,
            byte[] nonce,
            byte[] state,
            Instant issuedAt,
            Instant expiresAt) {}

    public record SignedLocalRpCallbackPayload(byte[] payload, String signingKeyId, byte[] signature) {}

    public record LocalRpTicketRedemptionRequest(byte[] claimTicket, String fingerprint, Instant issuedAt) {}

    public record SignedLocalRpTicketRedemptionRequest(byte[] request, byte[] signature) {}

    public record LocalRpTicketRedemptionResponse(
            String userId, String userDomain, List<Claim> claims, Instant ticketExpiresAt) {}

    // -----------------------------------------------------------------
    // Act-as grants (grantee side only). A local RP can be a grantee, never
    // an audience. See docs/spec/reserved/act-as-grants.md.
    // -----------------------------------------------------------------

    public record ApplicationRef(String subjectUserId, String subjectDomain, String applicationId) {}

    /** Exactly one field is non-null. This SDK always sets {@code localRpDescriptorFingerprint}. */
    public record GranteeRef(ApplicationRef application, String localRpDescriptorFingerprint) {}

    public record ApplicationKeySignature(String signedByKeyId, byte[] signature) {}

    /** Exactly one of the first two fields is non-null. This SDK always sets {@code localRpDescriptor}. */
    public record GranteeProof(
            String applicationInstanceId, SignedLocalRpDescriptor localRpDescriptor, ApplicationKeySignature signature) {}

    /**
     * The audience's signed scope set. {@code scopeSet} is the signed CBOR of an {@code ActAsScopeSet}, kept unchanged.
     * {@code signatures} has at least one entry (CSIL {@code [+ ApplicationKeySignature]}).
     */
    public record SignedActAsScopeSet(
            byte[] scopeSet, String signerInstanceId, List<ApplicationKeySignature> signatures) {}

    /** A grant as the home domain signed it. {@code grant} is the signed CBOR of an {@link ActAsGrant}. */
    public record SignedActAsGrant(byte[] grant, List<ClaimSignature> signatures) {}

    public record ActAsGrant(
            String grantId,
            String userId,
            String subjectDomain,
            GranteeRef grantee,
            ApplicationRef audience,
            SignedActAsScopeSet scopeSet,
            List<String> approvedScope,
            Instant issuedAt,
            Instant expiresAt,
            Instant seriesIssuedAt,
            Instant renewableUntil,
            String deviceFingerprint) {}

    public record ActAsGrantRequest(
            GranteeRef grantee,
            SignedActAsScopeSet scopeSet,
            Long requestedLifetimeSeconds,
            Long requestedRenewalWindowSeconds,
            String callbackUrl,
            String nonce,
            Instant requestedAt,
            Instant expiresAt) {}

    public record SignedActAsGrantRequest(byte[] request, GranteeProof proof) {}

    public record ActAsRefreshRequest(
            String grantId, GranteeRef grantee, Instant requestedAt, Instant expiresAt, String nonce) {}

    public record SignedActAsRefreshRequest(byte[] request, GranteeProof proof) {}

    public record RefreshActAsGrantRequest(SignedActAsRefreshRequest request) {}

    public record RefreshActAsGrantResponse(SignedActAsGrant grant, boolean signed) {}

    public record ActAsPresentation(
            byte[] grantHash, ApplicationRef audience, byte[] requestDigest, Instant presentedAt, byte[] nonce) {}

    public record SignedActAsPresentation(byte[] presentation, GranteeProof proof) {}

    public record ActAsCredential(SignedActAsGrant grant, SignedActAsPresentation presentation) {}
}
