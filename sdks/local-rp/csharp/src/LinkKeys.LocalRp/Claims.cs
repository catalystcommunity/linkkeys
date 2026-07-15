using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp;

/// <summary>
/// Claim signature verification — mirrors <c>crates/liblinkkeys/src/claims.rs</c>. Only
/// the verification half matters in production (claims are always signed by an IDP,
/// server-side); <see cref="SignClaim"/> is reproduced exactly (same tag, same tuple
/// field order/CBOR shape) purely so test fixtures (fake IDPs) can build claims this SDK
/// can verify against the real Rust wire format — a genuine interop requirement, not
/// internal self-consistency.
/// </summary>
public static class Claims
{
    private const string ClaimPayloadTag = "linkkeys-claim-v2";

    /// <summary>Bound on distinct claim-signer domains a completion will fetch keys for; see <see cref="Complete"/>.</summary>
    public const int MaxClaimSignerDomains = 8;

    /// <summary>
    /// The canonical bytes a single signature covers for a claim. The subject is the
    /// single full identity <c>user_id@subject_domain</c> (not the bare user_id), so a
    /// claim about a user_id at one domain can't be replayed as the same user_id at
    /// another. <paramref name="signingDomain"/> is bound per-signature so a signature
    /// from domain A cannot satisfy a claim presented as signed by B.
    /// </summary>
    internal static byte[] ClaimSignPayload(
        string claimId,
        string claimType,
        byte[] claimValue,
        string userId,
        string subjectDomain,
        string signingDomain,
        string? expiresAt,
        string attestedAt)
    {
        var subject = $"{userId}@{subjectDomain}";
        return Cbor.Encode(Cbor.Tuple(
            Cbor.VTextOf(ClaimPayloadTag),
            Cbor.VTextOf(claimId),
            Cbor.VTextOf(claimType),
            Cbor.VBytesOf(claimValue),
            Cbor.VTextOf(subject),
            Cbor.VTextOf(signingDomain),
            Cbor.OptTextItem(expiresAt),
            Cbor.VTextOf(attestedAt)));
    }

    /// <summary>What is being claimed, independent of who signs it. Mirrors <c>liblinkkeys::claims::ClaimSpec</c>.</summary>
    public sealed record ClaimSpec(
        string ClaimId,
        string ClaimType,
        byte[] ClaimValue,
        string UserId,
        string SubjectDomain,
        string? ExpiresAt,
        string AttestedAt);

    /// <summary>One signer of a claim: a single key, owned by <paramref name="Domain"/>.</summary>
    public sealed record ClaimSigner(string Domain, string KeyId, byte[] PrivateKeySeed);

    /// <summary>
    /// Sign a claim with one or more keys (test-fixture helper; see class docs for why
    /// this is a pure protocol helper rather than something the SDK calls in production).
    /// </summary>
    public static Claim SignClaim(ClaimSpec spec, IReadOnlyList<ClaimSigner> signers)
    {
        var signatures = new List<ClaimSignature>();
        foreach (var signer in signers)
        {
            var payload = ClaimSignPayload(
                spec.ClaimId, spec.ClaimType, spec.ClaimValue, spec.UserId, spec.SubjectDomain, signer.Domain,
                spec.ExpiresAt, spec.AttestedAt);
            var sig = Crypto.Crypto.SignEd25519(payload, signer.PrivateKeySeed);
            signatures.Add(new ClaimSignature(signer.Domain, signer.KeyId, sig));
        }

        return new Claim(
            spec.ClaimId, spec.UserId, spec.ClaimType, spec.ClaimValue, signatures, spec.AttestedAt,
            Rfc3339.Format(DateTimeOffset.UtcNow), spec.ExpiresAt, null);
    }

    /// <summary>A domain and the set of its currently-known public keys, resolved by the caller before verifying.</summary>
    public sealed record DomainKeySet(string Domain, IReadOnlyList<DomainPublicKey> Keys);

    private static void VerifyOneClaimSignature(ClaimSignature sig, byte[] payload, IReadOnlyList<DomainPublicKey> keys)
    {
        var key = keys.FirstOrDefault(k => k.KeyId == sig.SignedByKeyId)
            ?? throw new ClaimError(ClaimError.ErrorKind.KeyNotFound, sig.SignedByKeyId);

        if (key.KeyUsage != "sign")
        {
            throw new ClaimError(ClaimError.ErrorKind.SignatureInvalid, "key is not a signing key");
        }

        if (key.RevokedAt is not null)
        {
            throw new ClaimError(ClaimError.ErrorKind.KeyRevoked, key.KeyId);
        }

        DateTimeOffset expires;
        try
        {
            expires = Rfc3339.Parse("expires_at", key.ExpiresAt);
        }
        catch (LocalRpError)
        {
            throw new ClaimError(ClaimError.ErrorKind.KeyExpired, key.KeyId);
        }

        if (DateTimeOffset.UtcNow > expires)
        {
            throw new ClaimError(ClaimError.ErrorKind.KeyExpired, key.KeyId);
        }

        if (key.Algorithm != "ed25519")
        {
            throw new ClaimError(ClaimError.ErrorKind.UnsupportedAlgorithm, key.Algorithm);
        }

        if (!Crypto.Crypto.VerifyEd25519(payload, sig.Signature, key.PublicKey))
        {
            throw new ClaimError(ClaimError.ErrorKind.SignatureInvalid, null);
        }
    }

    /// <summary>
    /// Verify only the cryptographic per-domain quorum: every domain that signed must
    /// contribute at least one signature from a currently-valid key of that domain. Does
    /// NOT check the claim's own revocation/expiry.
    /// </summary>
    private static void VerifySignatureQuorum(
        IReadOnlyList<ClaimSignature> signatures, IReadOnlyList<DomainKeySet> domainKeys, Func<string, byte[]> payloadFor)
    {
        if (signatures.Count == 0)
        {
            throw new ClaimError(ClaimError.ErrorKind.Unsigned, null);
        }

        var domains = new List<string>(new SortedSet<string>(signatures.Select(s => s.Domain), StringComparer.Ordinal));

        foreach (var signingDomain in domains)
        {
            var set = domainKeys.FirstOrDefault(d => d.Domain == signingDomain)
                ?? throw new ClaimError(ClaimError.ErrorKind.DomainKeysUnavailable, signingDomain);

            var payload = payloadFor(signingDomain);

            Exception lastErr = new ClaimError(ClaimError.ErrorKind.DomainUnverified, signingDomain);
            bool satisfied = false;
            foreach (var sig in signatures)
            {
                if (sig.Domain != signingDomain)
                {
                    continue;
                }

                try
                {
                    VerifyOneClaimSignature(sig, payload, set.Keys);
                    satisfied = true;
                    break;
                }
                catch (ClaimError e)
                {
                    lastErr = e;
                }
            }

            if (!satisfied)
            {
                throw lastErr;
            }
        }
    }

    /// <summary>
    /// Verify only the cryptographic per-domain quorum for <paramref name="claim"/>;
    /// <paramref name="subjectDomain"/> is the subject's home domain, supplied from
    /// authoritative context (never attacker-controlled input).
    /// </summary>
    public static void VerifyClaimSignatures(Claim claim, string subjectDomain, IReadOnlyList<DomainKeySet> domainKeys) =>
        VerifySignatureQuorum(
            claim.Signatures,
            domainKeys,
            signingDomain => ClaimSignPayload(
                claim.ClaimId, claim.ClaimType, claim.ClaimValue, claim.UserId, subjectDomain, signingDomain,
                claim.ExpiresAt, claim.AttestedAt));

    /// <summary>Full claim verification: the cryptographic per-domain quorum plus the claim's own revocation and expiry.</summary>
    public static void VerifyClaim(Claim claim, string subjectDomain, IReadOnlyList<DomainKeySet> domainKeys)
    {
        VerifyClaimSignatures(claim, subjectDomain, domainKeys);

        if (claim.RevokedAt is not null)
        {
            throw new ClaimError(ClaimError.ErrorKind.Revoked, null);
        }

        if (claim.ExpiresAt is not null)
        {
            DateTimeOffset expires;
            try
            {
                expires = Rfc3339.Parse("expires_at", claim.ExpiresAt);
            }
            catch (LocalRpError)
            {
                throw new ClaimError(ClaimError.ErrorKind.BadExpiry, null);
            }

            if (DateTimeOffset.UtcNow > expires)
            {
                throw new ClaimError(ClaimError.ErrorKind.Expired, null);
            }
        }
    }
}
