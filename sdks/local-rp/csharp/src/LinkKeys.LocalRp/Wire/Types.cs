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

    // -----------------------------------------------------------------
    // Act-as grants (grantee side only). A local RP can be a grantee, never an
    // audience. See docs/spec/reserved/act-as-grants.md.
    // -----------------------------------------------------------------

    public sealed record ApplicationRef(string SubjectUserId, string SubjectDomain, string ApplicationId);

    /// <summary>Exactly one field is non-null. This SDK always sets <c>LocalRpDescriptorFingerprint</c>.</summary>
    public sealed record GranteeRef(ApplicationRef? Application, string? LocalRpDescriptorFingerprint);

    public sealed record ApplicationKeySignature(string SignedByKeyId, byte[] Signature);

    /// <summary>Exactly one of the first two fields is non-null. This SDK always sets <c>LocalRpDescriptor</c>.</summary>
    public sealed record GranteeProof(
        string? ApplicationInstanceId, SignedLocalRpDescriptor? LocalRpDescriptor, ApplicationKeySignature Signature);

    /// <summary>The audience's signed scope set. <c>ScopeSet</c> is the signed CBOR of an <c>ActAsScopeSet</c>, kept unchanged.</summary>
    public sealed record SignedActAsScopeSet(
        byte[] ScopeSet, string SignerInstanceId, IReadOnlyList<ApplicationKeySignature> Signatures);

    /// <summary>A grant as the home domain signed it. <c>Grant</c> is the signed CBOR of an <see cref="ActAsGrant"/>.</summary>
    public sealed record SignedActAsGrant(byte[] Grant, IReadOnlyList<ClaimSignature> Signatures);

    public sealed record ActAsGrant(
        string GrantId,
        string UserId,
        string SubjectDomain,
        GranteeRef Grantee,
        ApplicationRef Audience,
        SignedActAsScopeSet ScopeSet,
        IReadOnlyList<string> ApprovedScope,
        string IssuedAt,
        string ExpiresAt,
        string SeriesIssuedAt,
        string RenewableUntil,
        string? DeviceFingerprint);

    /// <summary>
    /// A local RP never sends the optional <c>grantee_handle_claim</c> (it has no enrolling
    /// account), so this record does not carry it and the encoder always omits it.
    /// </summary>
    public sealed record ActAsGrantRequest(
        GranteeRef Grantee,
        SignedActAsScopeSet ScopeSet,
        long? RequestedLifetimeSeconds,
        long? RequestedRenewalWindowSeconds,
        string CallbackUrl,
        string Nonce,
        string RequestedAt,
        string ExpiresAt);

    public sealed record SignedActAsGrantRequest(byte[] Request, GranteeProof Proof);

    public sealed record ActAsRefreshRequest(string GrantId, GranteeRef Grantee, string RequestedAt, string ExpiresAt, string Nonce);

    public sealed record SignedActAsRefreshRequest(byte[] Request, GranteeProof Proof);

    public sealed record RefreshActAsGrantRequest(SignedActAsRefreshRequest Request);

    public sealed record RefreshActAsGrantResponse(SignedActAsGrant Grant, bool Signed);

    public sealed record ActAsPresentation(
        byte[] GrantHash, ApplicationRef Audience, byte[] RequestDigest, string PresentedAt, byte[] Nonce);

    public sealed record SignedActAsPresentation(byte[] Presentation, GranteeProof Proof);

    public sealed record ActAsCredential(SignedActAsGrant Grant, SignedActAsPresentation Presentation);
}
