using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp;

/// <summary>
/// Sibling-signed key revocation certificate verification — mirrors
/// <c>crates/liblinkkeys/src/revocation.rs</c>. Only verification is ported here
/// (building/signing a revocation certificate is a domain-admin/server-side operation,
/// out of scope for a local-RP SDK); this SDK verifies revocation certificates fetched
/// alongside domain keys so it can drop a key a quorum-verified sibling revocation
/// targets.
/// </summary>
public static class Revocation
{
    /// <summary>Minimum number of distinct sibling signatures required to revoke a key.</summary>
    public const int Quorum = 2;

    /// <summary>Domain-separation tag/version for the signed revocation payload.</summary>
    private const string Tag = "linkkeys-key-revocation-v1";

    /// <summary>
    /// The canonical signed bytes: the tag, the target key id + fingerprint, the
    /// revocation instant, and the signing sibling's domain (bound per-signature to stop
    /// cross-domain reuse of a signature). This is the OLDER house tuple pattern — a
    /// five-element array with the domain-separation tag first — NOT the two-element
    /// <c>CBOR([context, payload])</c> envelope framing the four local-RP structures use.
    /// </summary>
    internal static byte[] RevocationPayload(string targetKeyId, string targetFingerprint, string revokedAt, string signingDomain) =>
        Cbor.Encode(Cbor.Tuple(
            Cbor.VTextOf(Tag), Cbor.VTextOf(targetKeyId), Cbor.VTextOf(targetFingerprint), Cbor.VTextOf(revokedAt),
            Cbor.VTextOf(signingDomain)));

    /// <summary>
    /// Verify a revocation certificate against a domain's public key set. Requires at
    /// least <see cref="Quorum"/> DISTINCT signing keys of <paramref name="domain"/>,
    /// each currently valid and NOT the target key, to have signed the canonical payload.
    /// </summary>
    public static void VerifyRevocationCertificate(RevocationCertificate cert, IReadOnlyList<DomainPublicKey> domainKeys, string domain)
    {
        int counted = CountValidSigners(cert, domainKeys, domain);
        if (counted < Quorum)
        {
            throw new RevocationError(counted, Quorum);
        }
    }

    /// <summary>
    /// The number of distinct, currently-valid, non-self, correctly-signed sibling
    /// signatures the certificate carries for <paramref name="domain"/>. Exposed
    /// (internal) so conformance tests can pinpoint exactly which filtering rule an
    /// implementation got wrong, per <c>revocations.json</c>'s
    /// <c>expected_counted_signers</c> field; <see cref="VerifyRevocationCertificate"/>
    /// is the only entry point production code should call.
    /// </summary>
    internal static int CountValidSigners(RevocationCertificate cert, IReadOnlyList<DomainPublicKey> domainKeys, string domain)
    {
        var validSigners = new HashSet<string>();

        foreach (var sig in cert.Signatures)
        {
            // A key can never authorize its own revocation.
            if (sig.SignedByKeyId == cert.TargetKeyId)
            {
                continue;
            }

            // The signature must be bound to this domain.
            if (sig.Domain != domain)
            {
                continue;
            }

            var key = domainKeys.FirstOrDefault(k => k.KeyId == sig.SignedByKeyId);
            if (key is null)
            {
                continue;
            }

            // Only a currently-valid signing key counts toward the quorum.
            try
            {
                LocalRp.CheckSigningKeyValid(key);
            }
            catch (LocalRpError)
            {
                continue;
            }

            var payload = RevocationPayload(cert.TargetKeyId, cert.TargetFingerprint, cert.RevokedAt, sig.Domain);
            if (key.Algorithm == "ed25519" && key.PublicKey.Length == 32 && Crypto.Crypto.VerifyEd25519(payload, sig.Signature, key.PublicKey))
            {
                validSigners.Add(sig.SignedByKeyId);
            }
        }

        return validSigners.Count;
    }
}
