namespace LinkKeys.LocalRp.Wire;

/// <summary>
/// Hand-written wire types for exactly the CSIL structures the DNS-less local-RP
/// protocol needs. <b>Hand-written, pending a csilgen C# target</b> (see this
/// namespace's <see cref="Cbor"/> docs and the filed csilgen request) — field
/// names and shapes mirror <c>csil/linkkeys.csil</c> and the generated
/// Rust/Go/Java types exactly.
///
/// <para>These are plain data carriers, not builders: optional fields are
/// <c>null</c> when absent (mirroring Rust <c>Option::None</c>), and byte-array
/// fields are raw, unencoded bytes. Encoding/decoding lives in <see cref="Codec"/>.</para>
/// </summary>
public static class Types
{
    /// <summary>The empty request type used by unauthenticated no-argument RPC calls.</summary>
    public sealed record EmptyRequest;

    public sealed record DomainPublicKey(
        string KeyId,
        byte[] PublicKey,
        string Fingerprint,
        string Algorithm,
        string KeyUsage,
        string CreatedAt,
        string ExpiresAt,
        string? RevokedAt,
        string? SignedByKeyId,
        byte[]? KeySignature);

    public sealed record GetDomainKeysResponse(string Domain, IReadOnlyList<DomainPublicKey> Keys, bool? RecentRevocationsAvailable);

    public sealed record GetRevocationsRequest(string? Since);

    public sealed record ClaimSignature(string Domain, string SignedByKeyId, byte[] Signature);

    public sealed record RevocationCertificate(
        string TargetKeyId,
        string TargetFingerprint,
        string RevokedAt,
        IReadOnlyList<ClaimSignature> Signatures);

    public sealed record GetRevocationsResponse(IReadOnlyList<RevocationCertificate> Revocations);

    public sealed record Claim(
        string ClaimId,
        string UserId,
        string ClaimType,
        byte[] ClaimValue,
        IReadOnlyList<ClaimSignature> Signatures,
        string AttestedAt,
        string CreatedAt,
        string? ExpiresAt,
        string? RevokedAt);

    public sealed record LocalRpDescriptor(
        string AppName,
        string? LocalDomainHint,
        byte[] SigningPublicKey,
        byte[] EncryptionPublicKey,
        string Fingerprint,
        IReadOnlyList<string> SupportedSuites,
        string CreatedAt,
        string ExpiresAt);

    public sealed record SignedLocalRpDescriptor(byte[] Descriptor, byte[] Signature);

    public sealed record LocalRpLoginRequest(
        SignedLocalRpDescriptor Descriptor,
        string CallbackUrl,
        byte[] Nonce,
        byte[] State,
        IReadOnlyList<string> RequestedClaims,
        IReadOnlyList<string> RequiredClaims,
        string IssuedAt,
        string ExpiresAt);

    public sealed record SignedLocalRpLoginRequest(byte[] Request, byte[] Signature);

    public sealed record LocalRpCallbackHeader(
        string Fingerprint,
        byte[] Nonce,
        byte[] State,
        string Suite,
        byte[] EphemeralPublicKey,
        byte[] AeadNonce,
        string IssuedAt,
        string ExpiresAt);

    public sealed record LocalRpEncryptedCallback(byte[] Header, byte[] Ciphertext);

    public sealed record LocalRpCallbackPayload(
        string UserId,
        string UserDomain,
        byte[] ClaimTicket,
        string AudienceFingerprint,
        string CallbackUrl,
        byte[] Nonce,
        byte[] State,
        string IssuedAt,
        string ExpiresAt);

    public sealed record SignedLocalRpCallbackPayload(byte[] Payload, string SigningKeyId, byte[] Signature);

    public sealed record LocalRpTicketRedemptionRequest(byte[] ClaimTicket, string Fingerprint, string IssuedAt);

    public sealed record SignedLocalRpTicketRedemptionRequest(byte[] Request, byte[] Signature);

    public sealed record LocalRpTicketRedemptionResponse(
        string UserId, string UserDomain, IReadOnlyList<Claim> Claims, string TicketExpiresAt);
}
