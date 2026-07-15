using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp.Dns;

/// <summary>
/// DNS TXT record parsing, pinning, and vouch verification — mirrors
/// <c>crates/liblinkkeys/src/dns.rs</c>. This class performs no I/O itself;
/// <see cref="IDnsResolver"/> is the network seam (design doc, "Required Network
/// Access": every SDK needs a DNS TXT lookup capability, configurable, defaulting to
/// the system resolver).
/// </summary>
public static class Dns
{
    /// <summary>Default TCP port for the LinkKeys protocol service. Advertised <c>tcp=</c> values omit the port when it equals this.</summary>
    public const int DefaultTcpPort = 4987;

    public static string LinkKeysDnsName(string domain) => $"_linkkeys.{domain}";

    public static string LinkKeysApisDnsName(string domain) => $"_linkkeys_apis.{domain}";

    /// <summary>A parsed <c>_linkkeys.{domain}</c> TXT record — the trust anchor.</summary>
    public sealed record LinkKeysRecord(IReadOnlyList<string> Fingerprints);

    /// <summary>A parsed <c>_linkkeys_apis.{domain}</c> TXT record — service endpoints.</summary>
    public sealed record LinkKeysApis(string? Tcp, string? HttpsBase);

    private static void RequireLk1Version(IReadOnlyList<string> parts)
    {
        string? version = null;
        bool found = false;
        foreach (var p in parts)
        {
            if (p.StartsWith("v=", StringComparison.Ordinal))
            {
                version = p[2..];
                found = true;
                break;
            }
        }

        if (!found)
        {
            throw new DnsParseError(DnsParseError.ErrorKind.MissingVersion, null);
        }

        if (version != "lk1")
        {
            throw new DnsParseError(DnsParseError.ErrorKind.UnsupportedVersion, version);
        }
    }

    private static List<string> Fields(string txt) =>
        txt.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).ToList();

    /// <summary>Parse a single <c>_linkkeys</c> TXT record string. Errors if it isn't a LinkKeys v1 record.</summary>
    public static LinkKeysRecord ParseLinkKeysTxt(string txt)
    {
        var parts = Fields(txt);
        RequireLk1Version(parts);
        var fingerprints = new List<string>();
        foreach (var p in parts)
        {
            if (p.StartsWith("fp=", StringComparison.Ordinal))
            {
                fingerprints.Add(p[3..]);
            }
        }

        return new LinkKeysRecord(fingerprints);
    }

    private static string NormalizeTcpEndpoint(string value)
    {
        if (value.Length == 0 || value.Contains(':'))
        {
            return value;
        }

        return $"{value}:{DefaultTcpPort}";
    }

    /// <summary>Parse a single <c>_linkkeys_apis</c> TXT record string. Errors if it isn't a LinkKeys v1 record or carries no endpoint.</summary>
    public static LinkKeysApis ParseLinkKeysApisTxt(string txt)
    {
        var parts = Fields(txt);
        RequireLk1Version(parts);

        string? tcp = null;
        string? httpsBase = null;
        foreach (var p in parts)
        {
            if (tcp is null && p.StartsWith("tcp=", StringComparison.Ordinal))
            {
                var v = NormalizeTcpEndpoint(p[4..]);
                if (v.Length != 0)
                {
                    tcp = v;
                }
            }

            if (httpsBase is null && p.StartsWith("https=", StringComparison.Ordinal))
            {
                var v = p[6..];
                if (v.Length != 0)
                {
                    httpsBase = $"https://{v}";
                }
            }
        }

        if (tcp is null && httpsBase is null)
        {
            throw new DnsParseError(DnsParseError.ErrorKind.MissingApisEndpoint, null);
        }

        return new LinkKeysApis(tcp, httpsBase);
    }

    /// <summary>Whether <paramref name="fp"/> is a syntactically valid key fingerprint: 64 hex chars (a SHA-256 digest), case-insensitive.</summary>
    public static bool IsValidFingerprint(string fp)
    {
        if (fp.Length != 64)
        {
            return false;
        }

        foreach (var c in fp)
        {
            bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Pin fetched keys to the DNS-published fingerprint set: for each candidate key,
    /// RECOMPUTE <c>fingerprint(public_key)</c> (never trust the wire <c>fingerprint</c>
    /// field, which is attacker-controlled) and keep only keys whose recomputed
    /// fingerprint is a member of <paramref name="pinned"/>.
    /// </summary>
    public static List<DomainPublicKey> PinKeysToFingerprints(IReadOnlyList<DomainPublicKey> keys, IReadOnlyList<string> pinned)
    {
        var pinnedLower = new HashSet<string>();
        foreach (var f in pinned)
        {
            if (IsValidFingerprint(f))
            {
                pinnedLower.Add(f.ToLowerInvariant());
            }
        }

        var outKeys = new List<DomainPublicKey>();
        foreach (var k in keys)
        {
            var fp = Crypto.Crypto.Fingerprint(k.PublicKey).ToLowerInvariant();
            if (pinnedLower.Contains(fp))
            {
                outKeys.Add(k);
            }
        }

        return outKeys;
    }

    private const string KeyVouchTag = "linkkeys-key-vouch-v1";

    internal static byte[] KeyVouchPayload(string encFingerprint, string encExpiresAt) =>
        Cbor.Encode(Cbor.Tuple(Cbor.VTextOf(KeyVouchTag), Cbor.VTextOf(encFingerprint), Cbor.VTextOf(encExpiresAt)));

    /// <summary>
    /// Verify that <paramref name="signingKey"/> vouches for <paramref name="encKey"/>: the
    /// encryption key names this signing key, the signing key is itself valid, and its
    /// signature covers the recomputed encrypt-key fingerprint + expiry.
    /// </summary>
    public static bool VerifyKeyVouch(DomainPublicKey encKey, DomainPublicKey signingKey)
    {
        if (encKey.SignedByKeyId is null || encKey.SignedByKeyId != signingKey.KeyId)
        {
            return false;
        }

        try
        {
            LinkKeys.LocalRp.LocalRp.CheckSigningKeyValid(signingKey);
        }
        catch (Exception)
        {
            return false;
        }

        if (encKey.KeySignature is null)
        {
            return false;
        }

        if (signingKey.Algorithm != "ed25519")
        {
            return false;
        }

        var recomputedFp = Crypto.Crypto.Fingerprint(encKey.PublicKey);
        var payload = KeyVouchPayload(recomputedFp, encKey.ExpiresAt);
        return Crypto.Crypto.VerifyEd25519(payload, encKey.KeySignature, signingKey.PublicKey);
    }

    /// <summary>
    /// Establish the trusted key set from a fetched key list and the DNS-pinned
    /// fingerprint set: signing keys (<c>key_usage == "sign"</c>) are pinned directly;
    /// encryption keys (<c>key_usage == "encrypt"</c>) are trusted only when a
    /// DNS-pinned signing key vouches for them.
    /// </summary>
    public static List<DomainPublicKey> TrustKeys(IReadOnlyList<DomainPublicKey> keys, IReadOnlyList<string> pinned)
    {
        var signing = keys.Where(k => k.KeyUsage == "sign").ToList();
        var pinnedSigning = PinKeysToFingerprints(signing, pinned);

        var trusted = new List<DomainPublicKey>(pinnedSigning);
        foreach (var k in keys)
        {
            if (k.KeyUsage != "encrypt")
            {
                continue;
            }

            foreach (var sk in pinnedSigning)
            {
                if (VerifyKeyVouch(k, sk))
                {
                    trusted.Add(k);
                    break;
                }
            }
        }

        return trusted;
    }
}
