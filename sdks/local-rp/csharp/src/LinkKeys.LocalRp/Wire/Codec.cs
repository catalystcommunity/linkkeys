using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp.Wire;

/// <summary>
/// Canonical CSIL CBOR encode/decode for every <see cref="Types"/> wire structure this
/// SDK needs. <b>Hand-written, pending a csilgen C# target</b> — see <see cref="Cbor"/>'s
/// class docs. Field order within each map is irrelevant (the <see cref="Cbor"/> encoder
/// always sorts to RFC 8949 canonical order), so this file lists fields in natural
/// struct order rather than hand-tracking the canonical order the Go/Rust generators
/// bake in at codegen time.
/// </summary>
public static class Codec
{
    // -----------------------------------------------------------------
    // EmptyRequest
    // -----------------------------------------------------------------

    public static byte[] EncodeEmptyRequest(EmptyRequest v) => Cbor.Encode(Cbor.VMapOf([]));

    public static EmptyRequest DecodeEmptyRequest(byte[] data)
    {
        Cbor.Decode(data);
        return new EmptyRequest();
    }

    // -----------------------------------------------------------------
    // DomainPublicKey
    // -----------------------------------------------------------------

    private static Cbor.Value EncDomainPublicKey(DomainPublicKey v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "key_id", v.KeyId);
        Cbor.PutBytes(e, "public_key", v.PublicKey);
        Cbor.PutText(e, "fingerprint", v.Fingerprint);
        Cbor.PutText(e, "algorithm", v.Algorithm);
        Cbor.PutText(e, "key_usage", v.KeyUsage);
        Cbor.PutText(e, "created_at", v.CreatedAt);
        Cbor.PutText(e, "expires_at", v.ExpiresAt);
        Cbor.PutOptText(e, "revoked_at", v.RevokedAt);
        Cbor.PutOptText(e, "signed_by_key_id", v.SignedByKeyId);
        Cbor.PutOptBytes(e, "key_signature", v.KeySignature);
        return Cbor.VMapOf(e);
    }

    private static DomainPublicKey DecDomainPublicKey(Cbor.Value m) => new(
        Cbor.RequireText(m, "key_id"),
        Cbor.RequireBytes(m, "public_key"),
        Cbor.RequireText(m, "fingerprint"),
        Cbor.RequireText(m, "algorithm"),
        Cbor.RequireText(m, "key_usage"),
        Cbor.RequireText(m, "created_at"),
        Cbor.RequireText(m, "expires_at"),
        Cbor.OptText(m, "revoked_at"),
        Cbor.OptText(m, "signed_by_key_id"),
        Cbor.OptBytes(m, "key_signature"));

    public static byte[] EncodeDomainPublicKey(DomainPublicKey v) => Cbor.Encode(EncDomainPublicKey(v));

    public static DomainPublicKey DecodeDomainPublicKey(byte[] data) => DecDomainPublicKey(Cbor.Decode(data));

    // -----------------------------------------------------------------
    // GetDomainKeysResponse
    // -----------------------------------------------------------------

    public static byte[] EncodeGetDomainKeysResponse(GetDomainKeysResponse v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "domain", v.Domain);
        e.Add(Cbor.EntryOf("keys", EncArray(v.Keys, EncDomainPublicKey)));
        Cbor.PutOptBool(e, "recent_revocations_available", v.RecentRevocationsAvailable);
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    public static GetDomainKeysResponse DecodeGetDomainKeysResponse(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new GetDomainKeysResponse(
            Cbor.RequireText(m, "domain"),
            DecArray(Cbor.Require(m, "keys"), DecDomainPublicKey),
            Cbor.OptBool(m, "recent_revocations_available"));
    }

    // -----------------------------------------------------------------
    // GetRevocationsRequest / GetRevocationsResponse
    // -----------------------------------------------------------------

    public static byte[] EncodeGetRevocationsRequest(GetRevocationsRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutOptText(e, "since", v.Since);
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    public static GetRevocationsRequest DecodeGetRevocationsRequest(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new GetRevocationsRequest(Cbor.OptText(m, "since"));
    }

    private static Cbor.Value EncClaimSignature(ClaimSignature v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "domain", v.Domain);
        Cbor.PutText(e, "signed_by_key_id", v.SignedByKeyId);
        Cbor.PutBytes(e, "signature", v.Signature);
        return Cbor.VMapOf(e);
    }

    private static ClaimSignature DecClaimSignature(Cbor.Value m) => new(
        Cbor.RequireText(m, "domain"),
        Cbor.RequireText(m, "signed_by_key_id"),
        Cbor.RequireBytes(m, "signature"));

    private static Cbor.Value EncRevocationCertificate(RevocationCertificate v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "target_key_id", v.TargetKeyId);
        Cbor.PutText(e, "target_fingerprint", v.TargetFingerprint);
        Cbor.PutText(e, "revoked_at", v.RevokedAt);
        e.Add(Cbor.EntryOf("signatures", EncArray(v.Signatures, EncClaimSignature)));
        return Cbor.VMapOf(e);
    }

    private static RevocationCertificate DecRevocationCertificate(Cbor.Value m) => new(
        Cbor.RequireText(m, "target_key_id"),
        Cbor.RequireText(m, "target_fingerprint"),
        Cbor.RequireText(m, "revoked_at"),
        DecArray(Cbor.Require(m, "signatures"), DecClaimSignature));

    public static byte[] EncodeGetRevocationsResponse(GetRevocationsResponse v)
    {
        var e = new List<Cbor.Entry> { Cbor.EntryOf("revocations", EncArray(v.Revocations, EncRevocationCertificate)) };
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    public static GetRevocationsResponse DecodeGetRevocationsResponse(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new GetRevocationsResponse(DecArray(Cbor.Require(m, "revocations"), DecRevocationCertificate));
    }

    // -----------------------------------------------------------------
    // Claim
    // -----------------------------------------------------------------

    private static Cbor.Value EncClaim(Claim v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "claim_id", v.ClaimId);
        Cbor.PutText(e, "user_id", v.UserId);
        Cbor.PutText(e, "claim_type", v.ClaimType);
        Cbor.PutBytes(e, "claim_value", v.ClaimValue);
        e.Add(Cbor.EntryOf("signatures", EncArray(v.Signatures, EncClaimSignature)));
        Cbor.PutText(e, "attested_at", v.AttestedAt);
        Cbor.PutText(e, "created_at", v.CreatedAt);
        Cbor.PutOptText(e, "expires_at", v.ExpiresAt);
        Cbor.PutOptText(e, "revoked_at", v.RevokedAt);
        return Cbor.VMapOf(e);
    }

    private static Claim DecClaim(Cbor.Value m) => new(
        Cbor.RequireText(m, "claim_id"),
        Cbor.RequireText(m, "user_id"),
        Cbor.RequireText(m, "claim_type"),
        Cbor.RequireBytes(m, "claim_value"),
        DecArray(Cbor.Require(m, "signatures"), DecClaimSignature),
        Cbor.RequireText(m, "attested_at"),
        Cbor.RequireText(m, "created_at"),
        Cbor.OptText(m, "expires_at"),
        Cbor.OptText(m, "revoked_at"));

    public static byte[] EncodeClaim(Claim v) => Cbor.Encode(EncClaim(v));

    public static Claim DecodeClaim(byte[] data) => DecClaim(Cbor.Decode(data));

    // -----------------------------------------------------------------
    // LocalRpDescriptor / SignedLocalRpDescriptor
    // -----------------------------------------------------------------

    private static Cbor.Value EncLocalRpDescriptor(LocalRpDescriptor v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "app_name", v.AppName);
        Cbor.PutOptText(e, "local_domain_hint", v.LocalDomainHint);
        Cbor.PutBytes(e, "signing_public_key", v.SigningPublicKey);
        Cbor.PutBytes(e, "encryption_public_key", v.EncryptionPublicKey);
        Cbor.PutText(e, "fingerprint", v.Fingerprint);
        e.Add(Cbor.EntryOf("supported_suites", Cbor.VArrayOf(v.SupportedSuites.Select(Cbor.VTextOf).ToList())));
        Cbor.PutText(e, "created_at", v.CreatedAt);
        Cbor.PutText(e, "expires_at", v.ExpiresAt);
        return Cbor.VMapOf(e);
    }

    private static LocalRpDescriptor DecLocalRpDescriptor(Cbor.Value m)
    {
        var suites = Cbor.AsArray(Cbor.Require(m, "supported_suites"));
        return new LocalRpDescriptor(
            Cbor.RequireText(m, "app_name"),
            Cbor.OptText(m, "local_domain_hint"),
            Cbor.RequireBytes(m, "signing_public_key"),
            Cbor.RequireBytes(m, "encryption_public_key"),
            Cbor.RequireText(m, "fingerprint"),
            suites.Select(Cbor.AsText).ToList(),
            Cbor.RequireText(m, "created_at"),
            Cbor.RequireText(m, "expires_at"));
    }

    public static byte[] EncodeLocalRpDescriptor(LocalRpDescriptor v) => Cbor.Encode(EncLocalRpDescriptor(v));

    public static LocalRpDescriptor DecodeLocalRpDescriptor(byte[] data) => DecLocalRpDescriptor(Cbor.Decode(data));

    private static Cbor.Value EncSignedLocalRpDescriptor(SignedLocalRpDescriptor v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "descriptor", v.Descriptor);
        Cbor.PutBytes(e, "signature", v.Signature);
        return Cbor.VMapOf(e);
    }

    private static SignedLocalRpDescriptor DecSignedLocalRpDescriptor(Cbor.Value m) => new(
        Cbor.RequireBytes(m, "descriptor"), Cbor.RequireBytes(m, "signature"));

    public static byte[] EncodeSignedLocalRpDescriptor(SignedLocalRpDescriptor v) => Cbor.Encode(EncSignedLocalRpDescriptor(v));

    public static SignedLocalRpDescriptor DecodeSignedLocalRpDescriptor(byte[] data) =>
        DecSignedLocalRpDescriptor(Cbor.Decode(data));

    // -----------------------------------------------------------------
    // LocalRpLoginRequest / SignedLocalRpLoginRequest
    // -----------------------------------------------------------------

    private static Cbor.Value EncLocalRpLoginRequest(LocalRpLoginRequest v)
    {
        var e = new List<Cbor.Entry> { Cbor.EntryOf("descriptor", EncSignedLocalRpDescriptor(v.Descriptor)) };
        Cbor.PutText(e, "callback_url", v.CallbackUrl);
        Cbor.PutBytes(e, "nonce", v.Nonce);
        Cbor.PutBytes(e, "state", v.State);
        e.Add(Cbor.EntryOf("requested_claims", Cbor.VArrayOf(v.RequestedClaims.Select(Cbor.VTextOf).ToList())));
        e.Add(Cbor.EntryOf("required_claims", Cbor.VArrayOf(v.RequiredClaims.Select(Cbor.VTextOf).ToList())));
        Cbor.PutText(e, "issued_at", v.IssuedAt);
        Cbor.PutText(e, "expires_at", v.ExpiresAt);
        return Cbor.VMapOf(e);
    }

    private static LocalRpLoginRequest DecLocalRpLoginRequest(Cbor.Value m) => new(
        DecSignedLocalRpDescriptor(Cbor.Require(m, "descriptor")),
        Cbor.RequireText(m, "callback_url"),
        Cbor.RequireBytes(m, "nonce"),
        Cbor.RequireBytes(m, "state"),
        Cbor.AsArray(Cbor.Require(m, "requested_claims")).Select(Cbor.AsText).ToList(),
        Cbor.AsArray(Cbor.Require(m, "required_claims")).Select(Cbor.AsText).ToList(),
        Cbor.RequireText(m, "issued_at"),
        Cbor.RequireText(m, "expires_at"));

    public static byte[] EncodeLocalRpLoginRequest(LocalRpLoginRequest v) => Cbor.Encode(EncLocalRpLoginRequest(v));

    public static LocalRpLoginRequest DecodeLocalRpLoginRequest(byte[] data) => DecLocalRpLoginRequest(Cbor.Decode(data));

    private static Cbor.Value EncSignedLocalRpLoginRequest(SignedLocalRpLoginRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "request", v.Request);
        Cbor.PutBytes(e, "signature", v.Signature);
        return Cbor.VMapOf(e);
    }

    private static SignedLocalRpLoginRequest DecSignedLocalRpLoginRequest(Cbor.Value m) => new(
        Cbor.RequireBytes(m, "request"), Cbor.RequireBytes(m, "signature"));

    public static byte[] EncodeSignedLocalRpLoginRequest(SignedLocalRpLoginRequest v) => Cbor.Encode(EncSignedLocalRpLoginRequest(v));

    public static SignedLocalRpLoginRequest DecodeSignedLocalRpLoginRequest(byte[] data) =>
        DecSignedLocalRpLoginRequest(Cbor.Decode(data));

    // -----------------------------------------------------------------
    // LocalRpCallbackHeader / LocalRpEncryptedCallback
    // -----------------------------------------------------------------

    private static Cbor.Value EncLocalRpCallbackHeader(LocalRpCallbackHeader v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "fingerprint", v.Fingerprint);
        Cbor.PutBytes(e, "nonce", v.Nonce);
        Cbor.PutBytes(e, "state", v.State);
        Cbor.PutText(e, "suite", v.Suite);
        Cbor.PutBytes(e, "ephemeral_public_key", v.EphemeralPublicKey);
        Cbor.PutBytes(e, "aead_nonce", v.AeadNonce);
        Cbor.PutText(e, "issued_at", v.IssuedAt);
        Cbor.PutText(e, "expires_at", v.ExpiresAt);
        return Cbor.VMapOf(e);
    }

    private static LocalRpCallbackHeader DecLocalRpCallbackHeader(Cbor.Value m) => new(
        Cbor.RequireText(m, "fingerprint"),
        Cbor.RequireBytes(m, "nonce"),
        Cbor.RequireBytes(m, "state"),
        Cbor.RequireText(m, "suite"),
        Cbor.RequireBytes(m, "ephemeral_public_key"),
        Cbor.RequireBytes(m, "aead_nonce"),
        Cbor.RequireText(m, "issued_at"),
        Cbor.RequireText(m, "expires_at"));

    public static byte[] EncodeLocalRpCallbackHeader(LocalRpCallbackHeader v) => Cbor.Encode(EncLocalRpCallbackHeader(v));

    public static LocalRpCallbackHeader DecodeLocalRpCallbackHeader(byte[] data) => DecLocalRpCallbackHeader(Cbor.Decode(data));

    private static Cbor.Value EncLocalRpEncryptedCallback(LocalRpEncryptedCallback v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "header", v.Header);
        Cbor.PutBytes(e, "ciphertext", v.Ciphertext);
        return Cbor.VMapOf(e);
    }

    private static LocalRpEncryptedCallback DecLocalRpEncryptedCallback(Cbor.Value m) => new(
        Cbor.RequireBytes(m, "header"), Cbor.RequireBytes(m, "ciphertext"));

    public static byte[] EncodeLocalRpEncryptedCallback(LocalRpEncryptedCallback v) => Cbor.Encode(EncLocalRpEncryptedCallback(v));

    public static LocalRpEncryptedCallback DecodeLocalRpEncryptedCallback(byte[] data) =>
        DecLocalRpEncryptedCallback(Cbor.Decode(data));

    // -----------------------------------------------------------------
    // LocalRpCallbackPayload / SignedLocalRpCallbackPayload
    // -----------------------------------------------------------------

    private static Cbor.Value EncLocalRpCallbackPayload(LocalRpCallbackPayload v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "user_id", v.UserId);
        Cbor.PutText(e, "user_domain", v.UserDomain);
        Cbor.PutBytes(e, "claim_ticket", v.ClaimTicket);
        Cbor.PutText(e, "audience_fingerprint", v.AudienceFingerprint);
        Cbor.PutText(e, "callback_url", v.CallbackUrl);
        Cbor.PutBytes(e, "nonce", v.Nonce);
        Cbor.PutBytes(e, "state", v.State);
        Cbor.PutText(e, "issued_at", v.IssuedAt);
        Cbor.PutText(e, "expires_at", v.ExpiresAt);
        return Cbor.VMapOf(e);
    }

    private static LocalRpCallbackPayload DecLocalRpCallbackPayload(Cbor.Value m) => new(
        Cbor.RequireText(m, "user_id"),
        Cbor.RequireText(m, "user_domain"),
        Cbor.RequireBytes(m, "claim_ticket"),
        Cbor.RequireText(m, "audience_fingerprint"),
        Cbor.RequireText(m, "callback_url"),
        Cbor.RequireBytes(m, "nonce"),
        Cbor.RequireBytes(m, "state"),
        Cbor.RequireText(m, "issued_at"),
        Cbor.RequireText(m, "expires_at"));

    public static byte[] EncodeLocalRpCallbackPayload(LocalRpCallbackPayload v) => Cbor.Encode(EncLocalRpCallbackPayload(v));

    public static LocalRpCallbackPayload DecodeLocalRpCallbackPayload(byte[] data) => DecLocalRpCallbackPayload(Cbor.Decode(data));

    private static Cbor.Value EncSignedLocalRpCallbackPayload(SignedLocalRpCallbackPayload v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "payload", v.Payload);
        Cbor.PutText(e, "signing_key_id", v.SigningKeyId);
        Cbor.PutBytes(e, "signature", v.Signature);
        return Cbor.VMapOf(e);
    }

    private static SignedLocalRpCallbackPayload DecSignedLocalRpCallbackPayload(Cbor.Value m) => new(
        Cbor.RequireBytes(m, "payload"),
        Cbor.RequireText(m, "signing_key_id"),
        Cbor.RequireBytes(m, "signature"));

    public static byte[] EncodeSignedLocalRpCallbackPayload(SignedLocalRpCallbackPayload v) =>
        Cbor.Encode(EncSignedLocalRpCallbackPayload(v));

    public static SignedLocalRpCallbackPayload DecodeSignedLocalRpCallbackPayload(byte[] data) =>
        DecSignedLocalRpCallbackPayload(Cbor.Decode(data));

    // -----------------------------------------------------------------
    // LocalRpTicketRedemptionRequest / SignedLocalRpTicketRedemptionRequest
    // -----------------------------------------------------------------

    private static Cbor.Value EncLocalRpTicketRedemptionRequest(LocalRpTicketRedemptionRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "claim_ticket", v.ClaimTicket);
        Cbor.PutText(e, "fingerprint", v.Fingerprint);
        Cbor.PutText(e, "issued_at", v.IssuedAt);
        return Cbor.VMapOf(e);
    }

    private static LocalRpTicketRedemptionRequest DecLocalRpTicketRedemptionRequest(Cbor.Value m) => new(
        Cbor.RequireBytes(m, "claim_ticket"),
        Cbor.RequireText(m, "fingerprint"),
        Cbor.RequireText(m, "issued_at"));

    public static byte[] EncodeLocalRpTicketRedemptionRequest(LocalRpTicketRedemptionRequest v) =>
        Cbor.Encode(EncLocalRpTicketRedemptionRequest(v));

    public static LocalRpTicketRedemptionRequest DecodeLocalRpTicketRedemptionRequest(byte[] data) =>
        DecLocalRpTicketRedemptionRequest(Cbor.Decode(data));

    private static Cbor.Value EncSignedLocalRpTicketRedemptionRequest(SignedLocalRpTicketRedemptionRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "request", v.Request);
        Cbor.PutBytes(e, "signature", v.Signature);
        return Cbor.VMapOf(e);
    }

    private static SignedLocalRpTicketRedemptionRequest DecSignedLocalRpTicketRedemptionRequest(Cbor.Value m) => new(
        Cbor.RequireBytes(m, "request"), Cbor.RequireBytes(m, "signature"));

    public static byte[] EncodeSignedLocalRpTicketRedemptionRequest(SignedLocalRpTicketRedemptionRequest v) =>
        Cbor.Encode(EncSignedLocalRpTicketRedemptionRequest(v));

    public static SignedLocalRpTicketRedemptionRequest DecodeSignedLocalRpTicketRedemptionRequest(byte[] data) =>
        DecSignedLocalRpTicketRedemptionRequest(Cbor.Decode(data));

    // -----------------------------------------------------------------
    // LocalRpTicketRedemptionResponse
    // -----------------------------------------------------------------

    private static Cbor.Value EncLocalRpTicketRedemptionResponse(LocalRpTicketRedemptionResponse v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "user_id", v.UserId);
        Cbor.PutText(e, "user_domain", v.UserDomain);
        e.Add(Cbor.EntryOf("claims", EncArray(v.Claims, EncClaim)));
        Cbor.PutText(e, "ticket_expires_at", v.TicketExpiresAt);
        return Cbor.VMapOf(e);
    }

    private static LocalRpTicketRedemptionResponse DecLocalRpTicketRedemptionResponse(Cbor.Value m) => new(
        Cbor.RequireText(m, "user_id"),
        Cbor.RequireText(m, "user_domain"),
        DecArray(Cbor.Require(m, "claims"), DecClaim),
        Cbor.RequireText(m, "ticket_expires_at"));

    public static byte[] EncodeLocalRpTicketRedemptionResponse(LocalRpTicketRedemptionResponse v) =>
        Cbor.Encode(EncLocalRpTicketRedemptionResponse(v));

    public static LocalRpTicketRedemptionResponse DecodeLocalRpTicketRedemptionResponse(byte[] data) =>
        DecLocalRpTicketRedemptionResponse(Cbor.Decode(data));

    // -----------------------------------------------------------------
    // Act-as grants (grantee side). Shapes mirror csil/linkkeys.csil "Act-as
    // grants"; optional fields are omitted when null, exactly as the generated
    // Rust codec does.
    // -----------------------------------------------------------------

    private static Cbor.Value EncApplicationRef(ApplicationRef v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "subject_user_id", v.SubjectUserId);
        Cbor.PutText(e, "subject_domain", v.SubjectDomain);
        Cbor.PutText(e, "application_id", v.ApplicationId);
        return Cbor.VMapOf(e);
    }

    private static ApplicationRef DecApplicationRef(Cbor.Value m) => new(
        Cbor.RequireText(m, "subject_user_id"),
        Cbor.RequireText(m, "subject_domain"),
        Cbor.RequireText(m, "application_id"));

    private static Cbor.Value EncGranteeRef(GranteeRef v)
    {
        var e = new List<Cbor.Entry>();
        if (v.Application is not null) e.Add(Cbor.EntryOf("application", EncApplicationRef(v.Application)));
        Cbor.PutOptText(e, "local_rp_descriptor_fingerprint", v.LocalRpDescriptorFingerprint);
        return Cbor.VMapOf(e);
    }

    private static GranteeRef DecGranteeRef(Cbor.Value m)
    {
        var app = Cbor.MapGet(m, "application");
        return new GranteeRef(app is null ? null : DecApplicationRef(app), Cbor.OptText(m, "local_rp_descriptor_fingerprint"));
    }

    private static Cbor.Value EncApplicationKeySignature(ApplicationKeySignature v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "signed_by_key_id", v.SignedByKeyId);
        Cbor.PutBytes(e, "signature", v.Signature);
        return Cbor.VMapOf(e);
    }

    private static ApplicationKeySignature DecApplicationKeySignature(Cbor.Value m) =>
        new(Cbor.RequireText(m, "signed_by_key_id"), Cbor.RequireBytes(m, "signature"));

    private static Cbor.Value EncGranteeProof(GranteeProof v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutOptText(e, "application_instance_id", v.ApplicationInstanceId);
        if (v.LocalRpDescriptor is not null) e.Add(Cbor.EntryOf("local_rp_descriptor", EncSignedLocalRpDescriptor(v.LocalRpDescriptor)));
        e.Add(Cbor.EntryOf("signature", EncApplicationKeySignature(v.Signature)));
        return Cbor.VMapOf(e);
    }

    private static GranteeProof DecGranteeProof(Cbor.Value m)
    {
        var descriptor = Cbor.MapGet(m, "local_rp_descriptor");
        return new GranteeProof(
            Cbor.OptText(m, "application_instance_id"),
            descriptor is null ? null : DecSignedLocalRpDescriptor(descriptor),
            DecApplicationKeySignature(Cbor.Require(m, "signature")));
    }

    private static Cbor.Value EncSignedActAsScopeSet(SignedActAsScopeSet v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "scope_set", v.ScopeSet);
        Cbor.PutText(e, "signer_instance_id", v.SignerInstanceId);
        e.Add(Cbor.EntryOf("signatures", EncArray(v.Signatures, EncApplicationKeySignature)));
        return Cbor.VMapOf(e);
    }

    private static SignedActAsScopeSet DecSignedActAsScopeSet(Cbor.Value m)
    {
        var signatures = DecArray(Cbor.Require(m, "signatures"), DecApplicationKeySignature);
        if (signatures.Count == 0) throw new Cbor.CborDecodeException("SignedActAsScopeSet.signatures is empty");
        return new SignedActAsScopeSet(
            Cbor.RequireBytes(m, "scope_set"), Cbor.RequireText(m, "signer_instance_id"), signatures);
    }

    public static byte[] EncodeSignedActAsScopeSet(SignedActAsScopeSet v) => Cbor.Encode(EncSignedActAsScopeSet(v));

    public static SignedActAsScopeSet DecodeSignedActAsScopeSet(byte[] data) => DecSignedActAsScopeSet(Cbor.Decode(data));

    private static Cbor.Value EncSignedActAsGrant(SignedActAsGrant v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "grant", v.Grant);
        e.Add(Cbor.EntryOf("signatures", EncArray(v.Signatures, EncClaimSignature)));
        return Cbor.VMapOf(e);
    }

    private static SignedActAsGrant DecSignedActAsGrant(Cbor.Value m) =>
        new(Cbor.RequireBytes(m, "grant"), DecArray(Cbor.Require(m, "signatures"), DecClaimSignature));

    public static byte[] EncodeSignedActAsGrant(SignedActAsGrant v) => Cbor.Encode(EncSignedActAsGrant(v));

    public static SignedActAsGrant DecodeSignedActAsGrant(byte[] data) => DecSignedActAsGrant(Cbor.Decode(data));

    /// <summary>Decode only. A grantee never builds a grant; the home domain signs it.</summary>
    public static ActAsGrant DecodeActAsGrant(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new ActAsGrant(
            Cbor.RequireText(m, "grant_id"),
            Cbor.RequireText(m, "user_id"),
            Cbor.RequireText(m, "subject_domain"),
            DecGranteeRef(Cbor.Require(m, "grantee")),
            DecApplicationRef(Cbor.Require(m, "audience")),
            DecSignedActAsScopeSet(Cbor.Require(m, "scope_set")),
            Cbor.AsArray(Cbor.Require(m, "approved_scope")).Select(Cbor.AsText).ToList(),
            Cbor.RequireText(m, "issued_at"),
            Cbor.RequireText(m, "expires_at"),
            Cbor.RequireText(m, "series_issued_at"),
            Cbor.RequireText(m, "renewable_until"),
            Cbor.OptText(m, "device_fingerprint"));
    }

    private static long? OptInt(Cbor.Value m, string key)
    {
        var v = Cbor.MapGet(m, key);
        return v is null ? null : Cbor.AsInt(v);
    }

    public static byte[] EncodeActAsGrantRequest(ActAsGrantRequest v)
    {
        var e = new List<Cbor.Entry>
        {
            Cbor.EntryOf("grantee", EncGranteeRef(v.Grantee)),
            Cbor.EntryOf("scope_set", EncSignedActAsScopeSet(v.ScopeSet)),
        };
        if (v.RequestedLifetimeSeconds is long lifetime) e.Add(Cbor.EntryOf("requested_lifetime_seconds", Cbor.VInteger(lifetime)));
        if (v.RequestedRenewalWindowSeconds is long window) e.Add(Cbor.EntryOf("requested_renewal_window_seconds", Cbor.VInteger(window)));
        Cbor.PutText(e, "callback_url", v.CallbackUrl);
        Cbor.PutText(e, "nonce", v.Nonce);
        Cbor.PutText(e, "requested_at", v.RequestedAt);
        Cbor.PutText(e, "expires_at", v.ExpiresAt);
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    public static ActAsGrantRequest DecodeActAsGrantRequest(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new ActAsGrantRequest(
            DecGranteeRef(Cbor.Require(m, "grantee")),
            DecSignedActAsScopeSet(Cbor.Require(m, "scope_set")),
            OptInt(m, "requested_lifetime_seconds"),
            OptInt(m, "requested_renewal_window_seconds"),
            Cbor.RequireText(m, "callback_url"),
            Cbor.RequireText(m, "nonce"),
            Cbor.RequireText(m, "requested_at"),
            Cbor.RequireText(m, "expires_at"));
    }

    public static byte[] EncodeSignedActAsGrantRequest(SignedActAsGrantRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "request", v.Request);
        e.Add(Cbor.EntryOf("proof", EncGranteeProof(v.Proof)));
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    public static SignedActAsGrantRequest DecodeSignedActAsGrantRequest(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new SignedActAsGrantRequest(Cbor.RequireBytes(m, "request"), DecGranteeProof(Cbor.Require(m, "proof")));
    }

    public static byte[] EncodeActAsRefreshRequest(ActAsRefreshRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "grant_id", v.GrantId);
        e.Add(Cbor.EntryOf("grantee", EncGranteeRef(v.Grantee)));
        Cbor.PutText(e, "requested_at", v.RequestedAt);
        Cbor.PutText(e, "expires_at", v.ExpiresAt);
        Cbor.PutText(e, "nonce", v.Nonce);
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    public static ActAsRefreshRequest DecodeActAsRefreshRequest(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new ActAsRefreshRequest(
            Cbor.RequireText(m, "grant_id"),
            DecGranteeRef(Cbor.Require(m, "grantee")),
            Cbor.RequireText(m, "requested_at"),
            Cbor.RequireText(m, "expires_at"),
            Cbor.RequireText(m, "nonce"));
    }

    private static Cbor.Value EncSignedActAsRefreshRequest(SignedActAsRefreshRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "request", v.Request);
        e.Add(Cbor.EntryOf("proof", EncGranteeProof(v.Proof)));
        return Cbor.VMapOf(e);
    }

    private static SignedActAsRefreshRequest DecSignedActAsRefreshRequest(Cbor.Value m) =>
        new(Cbor.RequireBytes(m, "request"), DecGranteeProof(Cbor.Require(m, "proof")));

    public static byte[] EncodeSignedActAsRefreshRequest(SignedActAsRefreshRequest v) => Cbor.Encode(EncSignedActAsRefreshRequest(v));

    public static SignedActAsRefreshRequest DecodeSignedActAsRefreshRequest(byte[] data) =>
        DecSignedActAsRefreshRequest(Cbor.Decode(data));

    public static byte[] EncodeRefreshActAsGrantRequest(RefreshActAsGrantRequest v) =>
        Cbor.Encode(Cbor.VMapOf([Cbor.EntryOf("request", EncSignedActAsRefreshRequest(v.Request))]));

    public static RefreshActAsGrantRequest DecodeRefreshActAsGrantRequest(byte[] data) =>
        new(DecSignedActAsRefreshRequest(Cbor.Require(Cbor.Decode(data), "request")));

    public static byte[] EncodeRefreshActAsGrantResponse(RefreshActAsGrantResponse v)
    {
        var e = new List<Cbor.Entry> { Cbor.EntryOf("grant", EncSignedActAsGrant(v.Grant)) };
        Cbor.PutBool(e, "signed", v.Signed);
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    public static RefreshActAsGrantResponse DecodeRefreshActAsGrantResponse(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new RefreshActAsGrantResponse(DecSignedActAsGrant(Cbor.Require(m, "grant")), Cbor.AsBool(Cbor.Require(m, "signed")));
    }

    public static byte[] EncodeActAsPresentation(ActAsPresentation v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "grant_hash", v.GrantHash);
        e.Add(Cbor.EntryOf("audience", EncApplicationRef(v.Audience)));
        Cbor.PutBytes(e, "request_digest", v.RequestDigest);
        Cbor.PutText(e, "presented_at", v.PresentedAt);
        Cbor.PutBytes(e, "nonce", v.Nonce);
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    public static ActAsPresentation DecodeActAsPresentation(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new ActAsPresentation(
            Cbor.RequireBytes(m, "grant_hash"),
            DecApplicationRef(Cbor.Require(m, "audience")),
            Cbor.RequireBytes(m, "request_digest"),
            Cbor.RequireText(m, "presented_at"),
            Cbor.RequireBytes(m, "nonce"));
    }

    private static Cbor.Value EncSignedActAsPresentation(SignedActAsPresentation v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutBytes(e, "presentation", v.Presentation);
        e.Add(Cbor.EntryOf("proof", EncGranteeProof(v.Proof)));
        return Cbor.VMapOf(e);
    }

    private static SignedActAsPresentation DecSignedActAsPresentation(Cbor.Value m) =>
        new(Cbor.RequireBytes(m, "presentation"), DecGranteeProof(Cbor.Require(m, "proof")));

    public static byte[] EncodeActAsCredential(ActAsCredential v) =>
        Cbor.Encode(Cbor.VMapOf(
        [
            Cbor.EntryOf("grant", EncSignedActAsGrant(v.Grant)),
            Cbor.EntryOf("presentation", EncSignedActAsPresentation(v.Presentation)),
        ]));

    public static ActAsCredential DecodeActAsCredential(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new ActAsCredential(
            DecSignedActAsGrant(Cbor.Require(m, "grant")),
            DecSignedActAsPresentation(Cbor.Require(m, "presentation")));
    }

    // -----------------------------------------------------------------
    // Array helpers
    // -----------------------------------------------------------------

    private static Cbor.Value EncArray<T>(IReadOnlyList<T> items, Func<T, Cbor.Value> encOne) =>
        Cbor.VArrayOf(items.Select(encOne).ToList());

    private static List<T> DecArray<T>(Cbor.Value v, Func<Cbor.Value, T> decOne) =>
        Cbor.AsArray(v).Select(decOne).ToList();
}
