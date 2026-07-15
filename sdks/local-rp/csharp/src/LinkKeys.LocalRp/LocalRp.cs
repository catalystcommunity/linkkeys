using LinkKeys.LocalRp.Crypto;
using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp;

/// <summary>
/// DNS-less local RP identity: pure protocol helpers. Mirrors
/// <c>crates/liblinkkeys/src/local_rp.rs</c> byte-for-byte per
/// <c>dns-less-local-rp-design.md</c>'s "Wire Precision (Normative)" section — read that
/// first. Summary of the shape:
///
/// <list type="bullet">
/// <item>Every signed structure uses the envelope pattern: the payload is CBOR-encoded
/// once, and the signature covers <c>CBOR([context: tstr, payload: bstr])</c> — a
/// two-element CBOR array, never a bare <c>context || payload</c> concatenation.</item>
/// <item>Four mandatory, structure-specific context strings stop a signature over one
/// structure from ever verifying as another.</item>
/// <item>The descriptor, login request, and ticket-redemption envelopes verify against
/// the local RP's own signing key (self-asserted identity, SSH-host style). The
/// callback payload envelope verifies against DOMAIN public keys, keyed by
/// <c>signing_key_id</c>.</item>
/// <item>The callback ciphertext is a variant of a sealed-box construction, extended
/// with negotiated-suite selection and cleartext-header AAD binding.</item>
/// </list>
///
/// <para>This class performs no I/O: every "current time" is an explicit
/// <c>now</c> parameter, never the system clock, with one narrow, deliberate exception
/// (<see cref="CheckSigningKeyValid"/>) that mirrors
/// <c>liblinkkeys::crypto::check_signing_key_valid</c> exactly — wall clock and all.</para>
/// </summary>
public static class LocalRp
{
    // Signature contexts for the four local-RP signed structures.
    public const string CtxLocalRpDescriptor = "linkkeys-local-rp-descriptor";
    public const string CtxLocalRpLoginRequest = "linkkeys-local-rp-login-request";
    public const string CtxLocalRpCallback = "linkkeys-local-rp-callback";
    public const string CtxLocalRpTicketRedemption = "linkkeys-local-rp-ticket-redemption";

    /// <summary>Default bounded clock-skew tolerance (seconds), design doc: "±300 seconds".</summary>
    public const long DefaultClockSkewSeconds = 300;

    private const string LocalRpCallbackBoxTag = "linkkeys-local-rp-callback-box";

    // -----------------------------------------------------------------
    // Envelope signature input
    // -----------------------------------------------------------------

    /// <summary>
    /// The signature input for every local-RP signed structure:
    /// <c>CBOR([context, payload_bytes])</c> — a two-element array with the
    /// domain-separation context string first and the exact payload bytes second
    /// (encoded as a CBOR byte string, never re-serialized). Deliberately NOT a bare
    /// <c>context || payload</c> concatenation.
    /// </summary>
    public static byte[] EnvelopeSignatureInput(string context, byte[] payloadBytes) =>
        Cbor.Encode(Cbor.Tuple(Cbor.VTextOf(context), Cbor.VBytesOf(payloadBytes)));

    // -----------------------------------------------------------------
    // Timestamps / expirations
    // -----------------------------------------------------------------

    public static void CheckTimestamps(string issuedAt, string expiresAt, DateTimeOffset now, long skewSeconds)
    {
        var issued = Rfc3339.Parse("issued_at", issuedAt);
        var expires = Rfc3339.Parse("expires_at", expiresAt);
        var skew = TimeSpan.FromSeconds(skewSeconds);
        if (now + skew < issued)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.NotYetValid, null);
        }

        if (now - skew > expires)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.Expired, null);
        }
    }

    public enum ExpirationLevel
    {
        Ok,
        Notice,
        Warning,
        Critical,
        Expired,
    }

    public static string WireName(this ExpirationLevel level) => level.ToString().ToLowerInvariant();

    public sealed record ExpirationStatus(ExpirationLevel Level, DateTimeOffset ExpiresAt, DateTimeOffset Now);

    /// <summary>
    /// <c>check_expirations(identity, now) -&gt; ExpirationStatus</c> (design doc,
    /// "Expiration Helper"). Does NOT apply clock-skew tolerance (unlike
    /// <see cref="CheckTimestamps"/>): expiry warnings are advisory, day-scale facts,
    /// not a replay/freshness security boundary.
    /// </summary>
    public static ExpirationStatus CheckExpirations(string expiresAt, DateTimeOffset now)
    {
        var expires = Rfc3339.Parse("expires_at", expiresAt);
        var remaining = expires - now;
        ExpirationLevel level;
        if (now >= expires)
        {
            level = ExpirationLevel.Expired;
        }
        else if (remaining <= TimeSpan.FromDays(30))
        {
            level = ExpirationLevel.Critical;
        }
        else if (remaining <= TimeSpan.FromDays(90))
        {
            level = ExpirationLevel.Warning;
        }
        else if (remaining <= TimeSpan.FromDays(180))
        {
            level = ExpirationLevel.Notice;
        }
        else
        {
            level = ExpirationLevel.Ok;
        }

        return new ExpirationStatus(level, expires, now);
    }

    // -----------------------------------------------------------------
    // Nonce/state/audience/issuer/callback-url checks
    // -----------------------------------------------------------------

    /// <summary>
    /// Constant-time: nonce/state are unpredictable secrets bound to a specific pending
    /// login (CSRF/replay protection), not merely opaque routing fields — compare them
    /// the same way a MAC or token would be compared
    /// (<see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals"/>),
    /// not with a short-circuiting byte compare that could leak timing information about
    /// how many leading bytes matched.
    /// </summary>
    public static void VerifyNonceState(byte[] expectedNonce, byte[] expectedState, byte[] actualNonce, byte[] actualState)
    {
        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expectedNonce, actualNonce))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.NonceMismatch, null);
        }

        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expectedState, actualState))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.StateMismatch, null);
        }
    }

    public static void VerifyAudience(string payloadAudienceFingerprint, string localRpFingerprint)
    {
        if (payloadAudienceFingerprint != localRpFingerprint)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.AudienceMismatch, null);
        }
    }

    public static void VerifyIssuer(string payloadUserDomain, string expectedDomain)
    {
        if (payloadUserDomain != expectedDomain)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.IssuerMismatch, null);
        }
    }

    public static void VerifyCallbackUrl(string payloadCallbackUrl, string arrivedUrl)
    {
        if (payloadCallbackUrl != arrivedUrl)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.CallbackUrlMismatch, null);
        }
    }

    // -----------------------------------------------------------------
    // Post-redemption identity binding (SEC fix)
    // -----------------------------------------------------------------

    /// <summary>
    /// Cross-check the (unsigned) ticket-redemption response's identity against the
    /// SIGNED callback payload's identity. Fatal on mismatch, unconditionally: the
    /// redemption response is trusted only because it was fetched over the DNS-pinned TLS
    /// channel for the domain the signed callback payload named — that is not the same as
    /// the redemption response actually agreeing with the payload. A
    /// compromised/malicious IDP could otherwise hand back claims for a different user
    /// than the one it cryptographically vouched for in the signed callback (e.g. to
    /// launder an approval given to user A onto user B's claims).
    /// </summary>
    public static void VerifyRedemptionIdentity(
        string redemptionUserId, string redemptionUserDomain, string payloadUserId, string payloadUserDomain)
    {
        if (redemptionUserId != payloadUserId || redemptionUserDomain != payloadUserDomain)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.RedemptionIdentityMismatch, null);
        }
    }

    /// <summary>
    /// Cross-check a single redeemed claim's <c>user_id</c> against the already-verified
    /// callback payload's <c>user_id</c>. Checked BEFORE the claim's own signature is
    /// verified, so a mismatch here is never confused with a signature failure. Mismatch
    /// is fatal: a claim about a different subject must never be attributed to this
    /// login, even if the claim's own signature verifies correctly (that only proves the
    /// signer attested it about ITS named subject, not about the user who is logging in)
    /// — otherwise a malicious IDP could splice in a claim belonging to a different
    /// user_id inside an otherwise-valid, correctly-signed redemption response.
    /// </summary>
    public static void VerifyClaimIdentity(string claimUserId, string payloadUserId)
    {
        if (claimUserId != payloadUserId)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.ClaimIdentityMismatch, null);
        }
    }

    /// <summary>
    /// Enforce that every claim type in <paramref name="requiredClaims"/> appears in
    /// <paramref name="verifiedClaimTypes"/> — the claim types that survived FULL
    /// verification (signature quorum, revocation/expiry, and the identity check above).
    /// An unsigned/unverifiable claim can never satisfy a requirement. Fatal if any
    /// required claim type is missing, including the case where
    /// <paramref name="verifiedClaimTypes"/> is empty because the redemption returned no
    /// claims at all.
    /// </summary>
    public static void VerifyRequiredClaimsSatisfied(IReadOnlyList<string> requiredClaims, IReadOnlySet<string> verifiedClaimTypes)
    {
        var missing = requiredClaims.Where(c => !verifiedClaimTypes.Contains(c)).ToList();
        if (missing.Count > 0)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.RequiredClaimsNotSatisfied, string.Join(", ", missing));
        }
    }

    // -----------------------------------------------------------------
    // Signing-key validity (mirrors liblinkkeys::crypto::check_signing_key_valid
    // exactly, including its use of the real wall clock rather than an explicit
    // `now` parameter)
    // -----------------------------------------------------------------

    /// <summary>Rejects a signing key that is not usable as a signer: wrong key_usage, revoked, or expired (wall clock).</summary>
    public static void CheckSigningKeyValid(DomainPublicKey key)
    {
        if (key.KeyUsage != "sign")
        {
            throw new LocalRpError(LocalRpError.ErrorKind.SignatureInvalid, "key_usage is not 'sign'");
        }

        if (key.RevokedAt is not null)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.KeyRevoked, key.KeyId);
        }

        DateTimeOffset expires;
        try
        {
            expires = Rfc3339.Parse("expires_at", key.ExpiresAt);
        }
        catch (LocalRpError)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.KeyExpired, key.KeyId);
        }

        if (DateTimeOffset.UtcNow > expires)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.KeyExpired, key.KeyId);
        }
    }

    // -----------------------------------------------------------------
    // Descriptor
    // -----------------------------------------------------------------

    public static LocalRpDescriptor BuildLocalRpDescriptor(
        string appName,
        string? localDomainHint,
        byte[] signingPublicKey,
        byte[] encryptionPublicKey,
        IReadOnlyList<string> supportedSuites,
        string createdAt,
        string expiresAt) => new(
        appName,
        localDomainHint,
        (byte[])signingPublicKey.Clone(),
        (byte[])encryptionPublicKey.Clone(),
        Crypto.Crypto.Fingerprint(signingPublicKey),
        supportedSuites,
        createdAt,
        expiresAt);

    public static SignedLocalRpDescriptor SignLocalRpDescriptor(LocalRpDescriptor descriptor, byte[] privateKeySeed)
    {
        var descriptorBytes = Codec.EncodeLocalRpDescriptor(descriptor);
        var sigInput = EnvelopeSignatureInput(CtxLocalRpDescriptor, descriptorBytes);
        var signature = Crypto.Crypto.SignEd25519(sigInput, privateKeySeed);
        return new SignedLocalRpDescriptor(descriptorBytes, signature);
    }

    public static LocalRpDescriptor VerifyLocalRpDescriptor(SignedLocalRpDescriptor signed, DateTimeOffset now, long skewSeconds)
    {
        LocalRpDescriptor descriptor;
        try
        {
            descriptor = Codec.DecodeLocalRpDescriptor(signed.Descriptor);
        }
        catch (Exception e) when (e is not LocalRpError)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.Decode, e.Message, e);
        }

        if (descriptor.SigningPublicKey.Length != 32)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.InvalidKeyLength, null);
        }

        var expectedFingerprint = Crypto.Crypto.Fingerprint(descriptor.SigningPublicKey);
        if (descriptor.Fingerprint != expectedFingerprint)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.FingerprintMismatch, null);
        }

        var sigInput = EnvelopeSignatureInput(CtxLocalRpDescriptor, signed.Descriptor);
        if (!Crypto.Crypto.VerifyEd25519(sigInput, signed.Signature, descriptor.SigningPublicKey))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.SignatureInvalid, null);
        }

        CheckTimestamps(descriptor.CreatedAt, descriptor.ExpiresAt, now, skewSeconds);
        return descriptor;
    }

    // -----------------------------------------------------------------
    // Login request
    // -----------------------------------------------------------------

    public static LocalRpLoginRequest BuildLocalRpLoginRequest(
        SignedLocalRpDescriptor descriptor,
        string callbackUrl,
        byte[] nonce,
        byte[] state,
        IReadOnlyList<string> requestedClaims,
        IReadOnlyList<string> requiredClaims,
        string issuedAt,
        string expiresAt) => new(descriptor, callbackUrl, nonce, state, requestedClaims, requiredClaims, issuedAt, expiresAt);

    public static SignedLocalRpLoginRequest SignLocalRpLoginRequest(LocalRpLoginRequest request, byte[] privateKeySeed)
    {
        var requestBytes = Codec.EncodeLocalRpLoginRequest(request);
        var sigInput = EnvelopeSignatureInput(CtxLocalRpLoginRequest, requestBytes);
        var signature = Crypto.Crypto.SignEd25519(sigInput, privateKeySeed);
        return new SignedLocalRpLoginRequest(requestBytes, signature);
    }

    public static LocalRpLoginRequest VerifyLocalRpLoginRequest(SignedLocalRpLoginRequest signed, DateTimeOffset now, long skewSeconds)
    {
        LocalRpLoginRequest request;
        try
        {
            request = Codec.DecodeLocalRpLoginRequest(signed.Request);
        }
        catch (Exception e) when (e is not LocalRpError)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.Decode, e.Message, e);
        }

        var descriptor = VerifyLocalRpDescriptor(request.Descriptor, now, skewSeconds);

        var sigInput = EnvelopeSignatureInput(CtxLocalRpLoginRequest, signed.Request);
        if (!Crypto.Crypto.VerifyEd25519(sigInput, signed.Signature, descriptor.SigningPublicKey))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.SignatureInvalid, null);
        }

        CheckTimestamps(request.IssuedAt, request.ExpiresAt, now, skewSeconds);
        return request;
    }

    // -----------------------------------------------------------------
    // Ticket redemption
    // -----------------------------------------------------------------

    public static LocalRpTicketRedemptionRequest BuildLocalRpTicketRedemptionRequest(
        byte[] claimTicket, string fingerprint, string issuedAt) => new(claimTicket, fingerprint, issuedAt);

    public static SignedLocalRpTicketRedemptionRequest SignLocalRpTicketRedemptionRequest(
        LocalRpTicketRedemptionRequest request, byte[] privateKeySeed)
    {
        var requestBytes = Codec.EncodeLocalRpTicketRedemptionRequest(request);
        var sigInput = EnvelopeSignatureInput(CtxLocalRpTicketRedemption, requestBytes);
        var signature = Crypto.Crypto.SignEd25519(sigInput, privateKeySeed);
        return new SignedLocalRpTicketRedemptionRequest(requestBytes, signature);
    }

    /// <summary>
    /// Verify a ticket-redemption request's possession proof: <paramref name="signingPublicKey"/>
    /// is the key the caller resolved for <paramref name="expectedFingerprint"/> — the
    /// signature must verify against it, AND that key's own fingerprint plus the
    /// request's embedded fingerprint field must both equal <paramref name="expectedFingerprint"/>.
    /// </summary>
    public static LocalRpTicketRedemptionRequest VerifyLocalRpTicketRedemptionRequest(
        SignedLocalRpTicketRedemptionRequest signed, byte[] signingPublicKey, string expectedFingerprint)
    {
        var sigInput = EnvelopeSignatureInput(CtxLocalRpTicketRedemption, signed.Request);
        if (!Crypto.Crypto.VerifyEd25519(sigInput, signed.Signature, signingPublicKey))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.SignatureInvalid, null);
        }

        LocalRpTicketRedemptionRequest request;
        try
        {
            request = Codec.DecodeLocalRpTicketRedemptionRequest(signed.Request);
        }
        catch (Exception e) when (e is not LocalRpError)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.Decode, e.Message, e);
        }

        var keyFingerprint = Crypto.Crypto.Fingerprint(signingPublicKey);
        if (keyFingerprint != expectedFingerprint || request.Fingerprint != expectedFingerprint)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.FingerprintMismatch, null);
        }

        return request;
    }

    // -----------------------------------------------------------------
    // Callback payload (domain-signed envelope)
    // -----------------------------------------------------------------

    public static LocalRpCallbackPayload BuildLocalRpCallbackPayload(
        string userId,
        string userDomain,
        byte[] claimTicket,
        string audienceFingerprint,
        string callbackUrl,
        byte[] nonce,
        byte[] state,
        string issuedAt,
        string expiresAt) => new(userId, userDomain, claimTicket, audienceFingerprint, callbackUrl, nonce, state, issuedAt, expiresAt);

    /// <summary>
    /// Sign a callback payload with one of the issuing domain's signing keys. Server-side
    /// (IDP) operation, exposed here only because it is a pure protocol helper — a
    /// local-RP SDK never calls this in production, only test fixtures (fake IDPs) do.
    /// </summary>
    public static SignedLocalRpCallbackPayload SignLocalRpCallbackPayload(
        LocalRpCallbackPayload payload, string keyId, byte[] privateKeySeed)
    {
        var payloadBytes = Codec.EncodeLocalRpCallbackPayload(payload);
        var sigInput = EnvelopeSignatureInput(CtxLocalRpCallback, payloadBytes);
        var signature = Crypto.Crypto.SignEd25519(sigInput, privateKeySeed);
        return new SignedLocalRpCallbackPayload(payloadBytes, keyId, signature);
    }

    /// <summary>
    /// Verify a domain-signed callback payload envelope against a set of domain public
    /// keys: resolve <c>signing_key_id</c>, reject a revoked/expired/non-signing key,
    /// verify the envelope signature, decode, then check <c>issued_at</c>/<c>expires_at</c> bounds.
    /// </summary>
    public static LocalRpCallbackPayload VerifyLocalRpCallbackPayload(
        SignedLocalRpCallbackPayload signed, IReadOnlyList<DomainPublicKey> domainPublicKeys, DateTimeOffset now, long skewSeconds)
    {
        var key = domainPublicKeys.FirstOrDefault(k => k.KeyId == signed.SigningKeyId)
            ?? throw new LocalRpError(LocalRpError.ErrorKind.KeyNotFound, signed.SigningKeyId);

        CheckSigningKeyValid(key);

        if (key.Algorithm != "ed25519")
        {
            throw new LocalRpError(LocalRpError.ErrorKind.UnsupportedAlgorithm, key.Algorithm);
        }

        var sigInput = EnvelopeSignatureInput(CtxLocalRpCallback, signed.Payload);
        if (!Crypto.Crypto.VerifyEd25519(sigInput, signed.Signature, key.PublicKey))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.SignatureInvalid, null);
        }

        LocalRpCallbackPayload payload;
        try
        {
            payload = Codec.DecodeLocalRpCallbackPayload(signed.Payload);
        }
        catch (Exception e) when (e is not LocalRpError)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.Decode, e.Message, e);
        }

        CheckTimestamps(payload.IssuedAt, payload.ExpiresAt, now, skewSeconds);
        return payload;
    }

    /// <summary>
    /// Cross-check the cleartext callback header's routing fields against the
    /// authoritative copies inside the decrypted, domain-signature-verified payload. The
    /// header is already bound as AEAD associated data, but a verifier must still consult
    /// the signed copies rather than trusting the header alone.
    /// </summary>
    public static void CheckCallbackHeaderMatchesPayload(LocalRpCallbackHeader header, LocalRpCallbackPayload payload)
    {
        if (header.Fingerprint != payload.AudienceFingerprint)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.HeaderPayloadMismatch, "fingerprint");
        }

        if (!header.Nonce.AsSpan().SequenceEqual(payload.Nonce))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.HeaderPayloadMismatch, "nonce");
        }

        if (!header.State.AsSpan().SequenceEqual(payload.State))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.HeaderPayloadMismatch, "state");
        }

        if (header.IssuedAt != payload.IssuedAt)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.HeaderPayloadMismatch, "issued_at");
        }

        if (header.ExpiresAt != payload.ExpiresAt)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.HeaderPayloadMismatch, "expires_at");
        }
    }

    // -----------------------------------------------------------------
    // Callback sealed box (Wire Precision: "Callback sealed box")
    // -----------------------------------------------------------------

    private sealed record KdfResult(byte[] Key, byte[] Context);

    /// <summary>
    /// Derive the AEAD key and construct the KDF <c>info</c>/AAD-prefix context for the
    /// local-RP callback sealed box:
    /// <c>tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)</c>, raw
    /// concatenation. HKDF-SHA256 with no salt, expanded to 32 bytes.
    /// </summary>
    private static KdfResult LocalRpCallbackKdf(Crypto.AeadSuite suite, byte[] ephemeralPublic, byte[] recipientPublic, byte[] sharedSecret)
    {
        var tag = System.Text.Encoding.UTF8.GetBytes(LocalRpCallbackBoxTag);
        var suiteId = System.Text.Encoding.UTF8.GetBytes(suite.WireId());
        var context = new byte[tag.Length + suiteId.Length + 32 + 32];
        int pos = 0;
        tag.CopyTo(context, pos);
        pos += tag.Length;
        suiteId.CopyTo(context, pos);
        pos += suiteId.Length;
        ephemeralPublic.CopyTo(context, pos);
        pos += 32;
        recipientPublic.CopyTo(context, pos);

        var key = Crypto.Crypto.HkdfSha256(sharedSecret, context, 32);
        return new KdfResult(key, context);
    }

    /// <summary>
    /// Seal a <see cref="SignedLocalRpCallbackPayload"/> into a
    /// <see cref="LocalRpEncryptedCallback"/> for <paramref name="recipientEncryptionPublicKey"/>,
    /// using <paramref name="suite"/>. Production path: fresh random ephemeral X25519
    /// keypair and AEAD nonce.
    /// </summary>
    public static LocalRpEncryptedCallback SealLocalRpCallback(
        SignedLocalRpCallbackPayload signedPayload,
        Crypto.AeadSuite suite,
        byte[] recipientEncryptionPublicKey,
        string fingerprint,
        byte[] nonce,
        byte[] state,
        string issuedAt,
        string expiresAt)
    {
        var ephemeral = Crypto.Crypto.GenerateX25519KeyPair();
        var aeadNonce = Crypto.Crypto.RandomBytes(12);
        return SealLocalRpCallbackInner(
            signedPayload, suite, recipientEncryptionPublicKey, fingerprint, nonce, state, issuedAt, expiresAt,
            ephemeral.PrivateKey, ephemeral.PublicKey, aeadNonce);
    }

    /// <summary>
    /// Deterministic variant of <see cref="SealLocalRpCallback"/>: the caller supplies
    /// the ephemeral X25519 private key and AEAD nonce instead of sourcing them from the
    /// CSPRNG. Production code must always use <see cref="SealLocalRpCallback"/>; this
    /// variant exists solely so tests can reproduce the checked-in conformance vectors'
    /// exact ciphertexts.
    /// </summary>
    public static LocalRpEncryptedCallback SealLocalRpCallbackWithRandomness(
        SignedLocalRpCallbackPayload signedPayload,
        Crypto.AeadSuite suite,
        byte[] recipientEncryptionPublicKey,
        string fingerprint,
        byte[] nonce,
        byte[] state,
        string issuedAt,
        string expiresAt,
        byte[] ephemeralPrivateKey,
        byte[] aeadNonce)
    {
        var ephemeralPublic = Crypto.Crypto.DerivePublicFromX25519Private(ephemeralPrivateKey);
        return SealLocalRpCallbackInner(
            signedPayload, suite, recipientEncryptionPublicKey, fingerprint, nonce, state, issuedAt, expiresAt,
            ephemeralPrivateKey, ephemeralPublic, aeadNonce);
    }

    private static LocalRpEncryptedCallback SealLocalRpCallbackInner(
        SignedLocalRpCallbackPayload signedPayload,
        Crypto.AeadSuite suite,
        byte[] recipientEncryptionPublicKey,
        string fingerprint,
        byte[] nonce,
        byte[] state,
        string issuedAt,
        string expiresAt,
        byte[] ephemeralPrivateKey,
        byte[] ephemeralPublicKey,
        byte[] aeadNonce)
    {
        var plaintext = Codec.EncodeSignedLocalRpCallbackPayload(signedPayload);

        var sharedSecret = Crypto.Crypto.X25519DiffieHellman(ephemeralPrivateKey, recipientEncryptionPublicKey);

        var header = new LocalRpCallbackHeader(fingerprint, nonce, state, suite.WireId(), ephemeralPublicKey, aeadNonce, issuedAt, expiresAt);
        var headerBytes = Codec.EncodeLocalRpCallbackHeader(header);

        var kdf = LocalRpCallbackKdf(suite, ephemeralPublicKey, recipientEncryptionPublicKey, sharedSecret);

        var aad = new byte[kdf.Context.Length + headerBytes.Length];
        kdf.Context.CopyTo(aad, 0);
        headerBytes.CopyTo(aad, kdf.Context.Length);

        var ciphertext = Crypto.Crypto.AeadEncrypt(suite, kdf.Key, aeadNonce, aad, plaintext);
        return new LocalRpEncryptedCallback(headerBytes, ciphertext);
    }

    /// <summary>
    /// Open a <see cref="LocalRpEncryptedCallback"/> with the local RP's encryption
    /// private key. <paramref name="allowedSuites"/> is the local RP's own
    /// supported-suite list (from its descriptor): a header advertising a suite NOT in
    /// that list is rejected even if it is otherwise a valid registry id.
    ///
    /// <para>Returns the decoded header and the still domain-signature-unverified
    /// <see cref="SignedLocalRpCallbackPayload"/> — callers must still call
    /// <see cref="VerifyLocalRpCallbackPayload"/> against fetched domain keys, and then
    /// <see cref="CheckCallbackHeaderMatchesPayload"/>, before trusting the result.</para>
    /// </summary>
    public sealed record OpenedCallback(LocalRpCallbackHeader Header, SignedLocalRpCallbackPayload SignedPayload);

    public static OpenedCallback OpenLocalRpCallback(
        LocalRpEncryptedCallback encrypted, byte[] recipientEncryptionPrivateKey, IReadOnlyList<Crypto.AeadSuite> allowedSuites)
    {
        LocalRpCallbackHeader header;
        try
        {
            header = Codec.DecodeLocalRpCallbackHeader(encrypted.Header);
        }
        catch (Exception e) when (e is not LocalRpError)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.Decode, e.Message, e);
        }

        var suite = Crypto.AeadSuiteExtensions.Parse(header.Suite);
        if (suite is null)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.UnsupportedSuite, header.Suite);
        }

        if (!allowedSuites.Contains(suite.Value))
        {
            throw new LocalRpError(LocalRpError.ErrorKind.SuiteNotAdvertised, header.Suite);
        }

        if (header.EphemeralPublicKey.Length != 32)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.InvalidKeyLength, null);
        }

        if (header.AeadNonce.Length != 12)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.InvalidKeyLength, null);
        }

        var recipientPublic = Crypto.Crypto.DerivePublicFromX25519Private(recipientEncryptionPrivateKey);

        byte[] sharedSecret;
        try
        {
            sharedSecret = Crypto.Crypto.X25519DiffieHellman(recipientEncryptionPrivateKey, header.EphemeralPublicKey);
        }
        catch (Crypto.CryptoException e)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.Crypto, "non-contributory ephemeral key", e);
        }

        var kdf = LocalRpCallbackKdf(suite.Value, header.EphemeralPublicKey, recipientPublic, sharedSecret);

        var aad = new byte[kdf.Context.Length + encrypted.Header.Length];
        kdf.Context.CopyTo(aad, 0);
        encrypted.Header.CopyTo(aad, kdf.Context.Length);

        byte[] plaintext;
        try
        {
            plaintext = Crypto.Crypto.AeadDecrypt(suite.Value, kdf.Key, header.AeadNonce, aad, encrypted.Ciphertext);
        }
        catch (Crypto.CryptoException e)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.Crypto, "decrypt failed", e);
        }

        SignedLocalRpCallbackPayload signedPayload;
        try
        {
            signedPayload = Codec.DecodeSignedLocalRpCallbackPayload(plaintext);
        }
        catch (Exception e) when (e is not LocalRpError)
        {
            throw new LocalRpError(LocalRpError.ErrorKind.Decode, e.Message, e);
        }

        return new OpenedCallback(header, signedPayload);
    }
}
