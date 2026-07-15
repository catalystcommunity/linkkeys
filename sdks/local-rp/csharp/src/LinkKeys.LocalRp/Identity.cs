using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp;

/// <summary>
/// <c>generate_local_rp_identity</c> and the raw-byte storage helpers (design doc: "SDK
/// API Shape", "Byte Storage Helpers").
///
/// <para>A local RP identity is exactly one Ed25519 signing keypair, one X25519
/// encryption keypair, and a self-signed <see cref="SignedLocalRpDescriptor"/> binding
/// them together. There is no continuity story across rotation: generating a new
/// identity means a new fingerprint, full stop.</para>
///
/// <para>Security note (design doc, "Byte Storage Helpers"): the private key fields in
/// <see cref="LocalRpKeyMaterial"/> do not directly identify a user, but they control
/// this app's entire local RP identity — anyone holding them can sign login requests and
/// redeem claim tickets as this app. Store them with ordinary application-secret care
/// (the same care as a database credential or API key), not merely as configuration.</para>
/// </summary>
public static class Identity
{
    /// <summary>Default local RP key lifetime: 10 years (design doc: "Default lifetime: 10 years").</summary>
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromDays(3650);

    /// <summary>Input to <see cref="GenerateLocalRpIdentity"/>. Big-config, single record, per the design doc's "SDK API Shape".</summary>
    /// <param name="AppName">Display name shown on the IDP's consent screen. NOT identity — display/audit metadata only.</param>
    /// <param name="Now">The current time — never read from the system clock inside this class.</param>
    /// <param name="LocalDomainHint">Optional local domain/origin hint, also display/audit metadata.</param>
    /// <param name="SupportedSuites">AEAD suites this app can decrypt callbacks with, preference order. Defaults to both registry suites.</param>
    /// <param name="Lifetime">Key/descriptor lifetime from <paramref name="Now"/>. Defaults to <see cref="DefaultLifetime"/>.</param>
    public sealed record GenerateLocalRpIdentityConfig(
        string AppName,
        DateTimeOffset Now,
        string? LocalDomainHint = null,
        IReadOnlyList<string>? SupportedSuites = null,
        TimeSpan? Lifetime = null);

    /// <summary>
    /// A local RP's full key material: signing keypair, encryption keypair, the
    /// self-signed descriptor binding them (which also carries <c>AppName</c>,
    /// <c>LocalDomainHint</c>, <c>SupportedSuites</c>, and the created/expires
    /// timestamps), and the identity fingerprint.
    /// </summary>
    public sealed record LocalRpKeyMaterial(
        byte[] SigningPrivateKey,
        byte[] SigningPublicKey,
        byte[] EncryptionPrivateKey,
        byte[] EncryptionPublicKey,
        SignedLocalRpDescriptor Descriptor,
        string Fingerprint);

    /// <summary>
    /// <c>generate_local_rp_identity(config) -&gt; LocalRpKeyMaterial</c> (design doc, "SDK
    /// API Shape"). Generates a fresh Ed25519 signing keypair and a *separate* X25519
    /// encryption keypair (never algebraically derived), builds and self-signs the
    /// descriptor binding them.
    /// </summary>
    public static LocalRpKeyMaterial GenerateLocalRpIdentity(GenerateLocalRpIdentityConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.AppName))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "app_name must not be empty");
        }

        var signing = Crypto.Crypto.GenerateEd25519KeyPair();
        var encryption = Crypto.Crypto.GenerateX25519KeyPair();

        var suites = config.SupportedSuites ?? Crypto.AeadSuiteExtensions.AllSupported;
        if (suites.Count == 0)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "supported_suites must not be empty");
        }

        var lifetime = config.Lifetime ?? DefaultLifetime;
        var createdAt = Rfc3339.Format(config.Now);
        var expiresAt = Rfc3339.Format(config.Now + lifetime);

        var descriptor = LocalRp.BuildLocalRpDescriptor(
            config.AppName, config.LocalDomainHint, signing.PublicKey, encryption.PublicKey, suites, createdAt, expiresAt);
        var fingerprint = descriptor.Fingerprint;
        var signedDescriptor = LocalRp.SignLocalRpDescriptor(descriptor, signing.PrivateKeySeed);

        return new LocalRpKeyMaterial(
            signing.PrivateKeySeed, signing.PublicKey, encryption.PrivateKey, encryption.PublicKey, signedDescriptor, fingerprint);
    }

    // -----------------------------------------------------------------
    // Byte storage helpers (design doc: "Byte Storage Helpers")
    // -----------------------------------------------------------------

    public static byte[] SigningKeyToBytes(byte[] key) => (byte[])key.Clone();

    public static byte[] SigningKeyFromBytes(byte[] bytes)
    {
        if (bytes.Length != 32)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, $"signing key must be 32 bytes, got {bytes.Length}");
        }

        return (byte[])bytes.Clone();
    }

    public static byte[] EncryptionKeyToBytes(byte[] key) => (byte[])key.Clone();

    public static byte[] EncryptionKeyFromBytes(byte[] bytes)
    {
        if (bytes.Length != 32)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, $"encryption key must be 32 bytes, got {bytes.Length}");
        }

        return (byte[])bytes.Clone();
    }

    /// <summary>The canonical fingerprint string form — a pass-through, since the fingerprint IS a hex string already.</summary>
    public static string FingerprintToString(string fingerprint) => fingerprint;

    /// <summary>Parse/validate a fingerprint string: exactly 64 lowercase-normalized hex characters (a SHA-256 digest).</summary>
    public static string FingerprintFromString(string s)
    {
        if (!Dns.Dns.IsValidFingerprint(s))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, $"not a valid fingerprint (want 64 hex chars): {s}");
        }

        return s.ToLowerInvariant();
    }

    /// <summary>
    /// Magic prefix for the identity-bundle byte format below. This is an SDK-local
    /// storage convenience, NOT a protocol wire format — nothing in the design doc's Wire
    /// Precision governs it, and no conformance vector covers it.
    /// </summary>
    private static readonly byte[] IdentityBundleMagic = "LKI1"u8.ToArray();
    private const int HeaderLen = 4 + 32 + 32 + 4;

    /// <summary>
    /// <c>local_rp_identity_to_bytes(identity) -&gt; bytes</c> (design doc, "SDK API
    /// Shape" + "Byte Storage Helpers"). Layout:
    /// <c>MAGIC(4) || signing_private_key(32) || encryption_private_key(32) || descriptor_len(4, BE) || descriptor_cbor</c>.
    /// </summary>
    public static byte[] LocalRpIdentityToBytes(LocalRpKeyMaterial identity)
    {
        var descriptorBytes = Codec.EncodeSignedLocalRpDescriptor(identity.Descriptor);
        using var stream = new MemoryStream(HeaderLen + descriptorBytes.Length);
        stream.Write(IdentityBundleMagic);
        stream.Write(identity.SigningPrivateKey);
        stream.Write(identity.EncryptionPrivateKey);
        int len = descriptorBytes.Length;
        stream.Write([(byte)(len >> 24), (byte)(len >> 16), (byte)(len >> 8), (byte)len]);
        stream.Write(descriptorBytes);
        return stream.ToArray();
    }

    /// <summary>
    /// <c>local_rp_identity_from_bytes(bytes) -&gt; LocalRpIdentity</c> — the inverse of
    /// <see cref="LocalRpIdentityToBytes"/>. Public keys and the fingerprint are read
    /// back out of the embedded descriptor rather than re-derived from the private keys.
    /// Does no signature/expiry verification (that is
    /// <see cref="LinkKeysLocalRp.CheckExpirations"/>'s and the protocol verification
    /// chain's job).
    /// </summary>
    public static LocalRpKeyMaterial LocalRpIdentityFromBytes(byte[] bytes)
    {
        if (bytes.Length < HeaderLen)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "identity bundle too short");
        }

        if (!bytes.AsSpan(0, 4).SequenceEqual(IdentityBundleMagic))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "identity bundle has an unrecognized magic prefix");
        }

        var signingPrivateKey = bytes[4..36];
        var encryptionPrivateKey = bytes[36..68];
        int descriptorLen = (bytes[68] << 24) | (bytes[69] << 16) | (bytes[70] << 8) | bytes[71];
        if (descriptorLen < 0 || HeaderLen + (long)descriptorLen > bytes.Length)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "identity bundle descriptor length exceeds available bytes");
        }

        var descriptorBytes = bytes[HeaderLen..(HeaderLen + descriptorLen)];

        var signedDescriptor = Codec.DecodeSignedLocalRpDescriptor(descriptorBytes);
        var descriptor = Codec.DecodeLocalRpDescriptor(signedDescriptor.Descriptor);

        if (descriptor.SigningPublicKey.Length != 32)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "descriptor signing_public_key was not 32 bytes");
        }

        if (descriptor.EncryptionPublicKey.Length != 32)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "descriptor encryption_public_key was not 32 bytes");
        }

        return new LocalRpKeyMaterial(
            signingPrivateKey, descriptor.SigningPublicKey, encryptionPrivateKey, descriptor.EncryptionPublicKey,
            signedDescriptor, descriptor.Fingerprint);
    }
}
