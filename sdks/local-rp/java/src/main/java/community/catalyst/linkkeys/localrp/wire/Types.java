package community.catalyst.linkkeys.localrp.wire;

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
 * pointers), and byte-array fields are raw, unencoded bytes. Encoding/decoding
 * lives in {@link Codec}.
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
            String createdAt,
            String expiresAt,
            String revokedAt,
            String signedByKeyId,
            byte[] keySignature) {}

    public record GetDomainKeysResponse(
            String domain, List<DomainPublicKey> keys, Boolean recentRevocationsAvailable) {}

    public record GetRevocationsRequest(String since) {}

    public record ClaimSignature(String domain, String signedByKeyId, byte[] signature) {}

    public record RevocationCertificate(
            String targetKeyId,
            String targetFingerprint,
            String revokedAt,
            List<ClaimSignature> signatures) {}

    public record GetRevocationsResponse(List<RevocationCertificate> revocations) {}

    public record Claim(
            String claimId,
            String userId,
            String claimType,
            byte[] claimValue,
            List<ClaimSignature> signatures,
            String attestedAt,
            String createdAt,
            String expiresAt,
            String revokedAt) {}

    public record LocalRpDescriptor(
            String appName,
            String localDomainHint,
            byte[] signingPublicKey,
            byte[] encryptionPublicKey,
            String fingerprint,
            List<String> supportedSuites,
            String createdAt,
            String expiresAt) {}

    public record SignedLocalRpDescriptor(byte[] descriptor, byte[] signature) {}

    public record LocalRpLoginRequest(
            SignedLocalRpDescriptor descriptor,
            String callbackUrl,
            byte[] nonce,
            byte[] state,
            List<String> requestedClaims,
            List<String> requiredClaims,
            String issuedAt,
            String expiresAt) {}

    public record SignedLocalRpLoginRequest(byte[] request, byte[] signature) {}

    public record LocalRpCallbackHeader(
            String fingerprint,
            byte[] nonce,
            byte[] state,
            String suite,
            byte[] ephemeralPublicKey,
            byte[] aeadNonce,
            String issuedAt,
            String expiresAt) {}

    public record LocalRpEncryptedCallback(byte[] header, byte[] ciphertext) {}

    public record LocalRpCallbackPayload(
            String userId,
            String userDomain,
            byte[] claimTicket,
            String audienceFingerprint,
            String callbackUrl,
            byte[] nonce,
            byte[] state,
            String issuedAt,
            String expiresAt) {}

    public record SignedLocalRpCallbackPayload(byte[] payload, String signingKeyId, byte[] signature) {}

    public record LocalRpTicketRedemptionRequest(byte[] claimTicket, String fingerprint, String issuedAt) {}

    public record SignedLocalRpTicketRedemptionRequest(byte[] request, byte[] signature) {}

    public record LocalRpTicketRedemptionResponse(
            String userId, String userDomain, List<Claim> claims, String ticketExpiresAt) {}
}
