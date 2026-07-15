using System.Security.Cryptography;
using NSec.Cryptography;

namespace LinkKeys.LocalRp.Crypto;

/// <summary>
/// Crypto primitives this SDK needs (design doc, Language Crypto Matrix,
/// "C#/.NET" row): <a href="https://nsec.rocks/">NSec.Cryptography</a> for
/// Ed25519 sign/verify and X25519 key agreement (the BCL has no Ed25519/X25519
/// support at all — <see cref="ECDiffieHellman"/> is NIST-curves-only), and the
/// BCL for everything else: <see cref="AesGcm"/> and
/// <see cref="System.Security.Cryptography.ChaCha20Poly1305"/> for AEAD,
/// <see cref="HKDF"/> for key derivation, <see cref="SHA256"/> for
/// fingerprinting, <see cref="RandomNumberGenerator"/> for CSPRNG bytes.
///
/// <para><b>Why not NSec's AEAD?</b> NSec's own AES-256-GCM binding is gated on
/// hardware AES-NI support (it throws/is unavailable when the CPU lacks the
/// instruction, per the design doc's language matrix note); the BCL's
/// <see cref="AesGcm"/> goes through OpenSSL on Linux (via
/// <c>System.Security.Cryptography.Native.OpenSsl</c>) and has no such gate.
/// <see cref="System.Security.Cryptography.ChaCha20Poly1305.IsSupported"/> is
/// checked at runtime before use (see <see cref="AeadEncrypt"/>/
/// <see cref="AeadDecrypt"/>); on this box (OpenSSL-backed Linux) it reports
/// supported, so the optional suite is fully exercised rather than skipped.</para>
///
/// <para><b>NSec's low-order X25519 behavior</b>: <see cref="X25519DiffieHellman"/>
/// treats <see cref="KeyAgreementAlgorithm.Agree"/> returning <c>null</c> the
/// same as an explicit all-zero-output check — NSec's libsodium-backed X25519
/// already rejects the all-zero/low-order case at the C layer by returning a
/// null <see cref="SharedSecret"/>, so this method never even sees an all-zero
/// byte array to check; either way, rejection is uniform and verified against
/// <c>callback_box.json</c>'s <c>low_order_ephemeral_key_rejected</c> vector.</para>
/// </summary>
public static class Crypto
{
    private static readonly SignatureAlgorithm Ed25519Algo = SignatureAlgorithm.Ed25519;
    private static readonly KeyAgreementAlgorithm X25519Algo = KeyAgreementAlgorithm.X25519;

    // KeyCreationParameters/SharedSecretCreationParameters are ref structs (NSec), so
    // they cannot be cached in a static field; build a fresh one per call instead.
    private static KeyCreationParameters ExportableKeyParams() =>
        new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };

    private static SharedSecretCreationParameters ExportableSecretParams() =>
        new() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };

    // -----------------------------------------------------------------
    // Fingerprint / randomness
    // -----------------------------------------------------------------

    /// <summary><c>sha256(public_key_bytes)</c>, lowercase hex — the canonical LinkKeys fingerprint format, everywhere.</summary>
    public static string Fingerprint(byte[] publicKeyBytes) => Hex.Encode(SHA256.HashData(publicKeyBytes));

    /// <summary>CSPRNG bytes (<see cref="RandomNumberGenerator"/>).</summary>
    public static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    private static void RequireLen(byte[] b, int len, string what)
    {
        if (b.Length != len)
        {
            throw new CryptoException($"{what} must be {len} bytes, got {b.Length}");
        }
    }

    // -----------------------------------------------------------------
    // Ed25519
    // -----------------------------------------------------------------

    public sealed record Ed25519KeyPair(byte[] PublicKey, byte[] PrivateKeySeed);

    /// <summary>Generate a fresh Ed25519 keypair, returning raw 32-byte public key and 32-byte private seed.</summary>
    public static Ed25519KeyPair GenerateEd25519KeyPair()
    {
        using var key = Key.Create(Ed25519Algo, ExportableKeyParams());
        byte[] pub = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] seed = key.Export(KeyBlobFormat.RawPrivateKey);
        return new Ed25519KeyPair(pub, seed);
    }

    /// <summary>Raw 32-byte Ed25519 public key -&gt; an NSec <see cref="PublicKey"/> for verification.</summary>
    public static PublicKey ImportEd25519PublicKey(byte[] raw)
    {
        RequireLen(raw, 32, "Ed25519 public key");
        if (!PublicKey.TryImport(Ed25519Algo, raw, KeyBlobFormat.RawPublicKey, out var pub) || pub is null)
        {
            throw new CryptoException("invalid Ed25519 public key bytes");
        }

        return pub;
    }

    /// <summary>Raw 32-byte Ed25519 private key seed -&gt; an NSec <see cref="Key"/> for signing.</summary>
    public static Key ImportEd25519PrivateKey(byte[] seed)
    {
        RequireLen(seed, 32, "Ed25519 private key seed");
        try
        {
            return Key.Import(Ed25519Algo, seed, KeyBlobFormat.RawPrivateKey, ExportableKeyParams());
        }
        catch (Exception e) when (e is FormatException or ArgumentException)
        {
            throw new CryptoException("invalid Ed25519 private key seed", e);
        }
    }

    /// <summary>Sign <paramref name="message"/> with an Ed25519 seed (raw 32-byte private key). Returns a 64-byte signature.</summary>
    public static byte[] SignEd25519(byte[] message, byte[] privateKeySeed)
    {
        using var key = ImportEd25519PrivateKey(privateKeySeed);
        return Ed25519Algo.Sign(key, message);
    }

    /// <summary>
    /// Verify an Ed25519 signature. Never throws for a malformed key/signature — returns
    /// <c>false</c> uniformly, so callers can treat every failure mode alike (design doc:
    /// signature verification is a closed, uniform pass/fail boundary).
    /// </summary>
    public static bool VerifyEd25519(byte[] message, byte[] signature, byte[] publicKey)
    {
        if (publicKey.Length != 32 || signature.Length != 64)
        {
            return false;
        }

        if (!PublicKey.TryImport(Ed25519Algo, publicKey, KeyBlobFormat.RawPublicKey, out var pub) || pub is null)
        {
            return false;
        }

        return Ed25519Algo.Verify(pub, message, signature);
    }

    // -----------------------------------------------------------------
    // X25519 (key agreement)
    // -----------------------------------------------------------------

    public sealed record X25519KeyPair(byte[] PublicKey, byte[] PrivateKey);

    /// <summary>Generate a fresh X25519 encryption keypair — a *separate* key from any signing key.</summary>
    public static X25519KeyPair GenerateX25519KeyPair()
    {
        using var key = Key.Create(X25519Algo, ExportableKeyParams());
        byte[] pub = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] priv = key.Export(KeyBlobFormat.RawPrivateKey);
        return new X25519KeyPair(pub, priv);
    }

    /// <summary>Raw 32-byte X25519 public key (u-coordinate, RFC 7748) -&gt; an NSec <see cref="PublicKey"/>.</summary>
    public static PublicKey ImportX25519PublicKey(byte[] raw)
    {
        RequireLen(raw, 32, "X25519 public key");
        if (!PublicKey.TryImport(X25519Algo, raw, KeyBlobFormat.RawPublicKey, out var pub) || pub is null)
        {
            throw new CryptoException("invalid X25519 public key bytes");
        }

        return pub;
    }

    /// <summary>Raw 32-byte X25519 private scalar -&gt; an NSec <see cref="Key"/>. Clamping happens internally at agreement time.</summary>
    public static Key ImportX25519PrivateKey(byte[] raw)
    {
        RequireLen(raw, 32, "X25519 private key");
        try
        {
            return Key.Import(X25519Algo, raw, KeyBlobFormat.RawPrivateKey, ExportableKeyParams());
        }
        catch (Exception e) when (e is FormatException or ArgumentException)
        {
            throw new CryptoException("invalid X25519 private key bytes", e);
        }
    }

    /// <summary>RFC 7748 base point (<c>u = 9</c>), little-endian 32-byte encoding. Used by <see cref="DerivePublicFromX25519Private"/>.</summary>
    private static readonly byte[] X25519BasePointRaw = BuildBasePoint();

    private static byte[] BuildBasePoint()
    {
        var b = new byte[32];
        b[0] = 9;
        return b;
    }

    /// <summary>
    /// Derive the raw 32-byte X25519 public key for a raw 32-byte private scalar — needed
    /// on the decrypting side of the callback sealed box, which must feed its OWN public
    /// key (not the ephemeral sender's) into the KDF/AAD construction from only its private
    /// key. NSec (like JCA) has no direct "scalar -&gt; point" primitive independent of a key
    /// agreement, but scalar multiplication by the RFC 7748 base point <em>is</em> exactly
    /// what a key agreement against the base point "public key" computes — the same
    /// well-known trick the Java SDK uses, needing zero hand-rolled curve arithmetic.
    /// </summary>
    public static byte[] DerivePublicFromX25519Private(byte[] privateKey) =>
        X25519DiffieHellman(privateKey, X25519BasePointRaw);

    /// <summary>
    /// X25519 Diffie-Hellman, rejecting a non-contributory (low-order) result (Wire
    /// Precision: "reject an all-zero shared secret"). NSec's libsodium-backed
    /// <see cref="KeyAgreementAlgorithm.Agree"/> already rejects known low-order inputs by
    /// returning <c>null</c> rather than an all-zero secret; this method treats a null result
    /// identically to an explicit all-zero check, so rejection is uniform regardless of which
    /// layer catches it.
    /// </summary>
    public static byte[] X25519DiffieHellman(byte[] privateKey, byte[] publicKey)
    {
        using var priv = ImportX25519PrivateKey(privateKey);
        var pub = ImportX25519PublicKey(publicKey);
        using var shared = X25519Algo.Agree(priv, pub, ExportableSecretParams());
        if (shared is null)
        {
            throw new CryptoException("non-contributory (low-order) X25519 key rejected");
        }

        byte[] sharedBytes = shared.Export(SharedSecretBlobFormat.RawSharedSecret);
        if (IsAllZero(sharedBytes))
        {
            throw new CryptoException("non-contributory (low-order) X25519 key rejected");
        }

        return sharedBytes;
    }

    private static bool IsAllZero(byte[] b)
    {
        foreach (var x in b)
        {
            if (x != 0)
            {
                return false;
            }
        }

        return true;
    }

    // -----------------------------------------------------------------
    // HKDF-SHA256 (BCL: System.Security.Cryptography.HKDF)
    // -----------------------------------------------------------------

    /// <summary>
    /// HKDF-SHA256(salt=none, ikm).expand(info, length) — exactly
    /// <c>hkdf::Hkdf::&lt;Sha256&gt;::new(None, ikm).expand(info, &amp;mut out)</c> on the Rust
    /// side. A <c>null</c>/empty salt is treated by <see cref="HKDF.DeriveKey"/> as a
    /// zero-filled salt of hash length per RFC 5869, matching every other SDK's HKDF call.
    /// </summary>
    public static byte[] HkdfSha256(byte[] ikm, byte[] info, int length) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt: null, info: info);

    // -----------------------------------------------------------------
    // AEAD dispatch (AES-256-GCM baseline, ChaCha20-Poly1305 optional)
    // -----------------------------------------------------------------

    private const int AeadTagLen = 16;
    private const int AeadNonceLen = 12;

    /// <summary>Whether <paramref name="suite"/> is usable on this runtime. Always true for AES-256-GCM.</summary>
    public static bool IsSuiteSupported(AeadSuite suite) => suite switch
    {
        AeadSuite.Aes256Gcm => AesGcm.IsSupported,
        AeadSuite.ChaCha20Poly1305 => System.Security.Cryptography.ChaCha20Poly1305.IsSupported,
        _ => false,
    };

    /// <summary>Encrypt under <paramref name="suite"/>. Output is <c>ciphertext || 16-byte tag</c> (the wire convention every SDK uses).</summary>
    public static byte[] AeadEncrypt(AeadSuite suite, byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
    {
        RequireLen(key, 32, "AEAD key");
        RequireLen(nonce, AeadNonceLen, "AEAD nonce");
        RequireSuiteSupported(suite);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AeadTagLen];
        try
        {
            switch (suite)
            {
                case AeadSuite.Aes256Gcm:
                    using (var aes = new AesGcm(key, AeadTagLen))
                    {
                        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
                    }

                    break;
                case AeadSuite.ChaCha20Poly1305:
                    using (var cc = new System.Security.Cryptography.ChaCha20Poly1305(key))
                    {
                        cc.Encrypt(nonce, plaintext, ciphertext, tag, aad);
                    }

                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(suite));
            }
        }
        catch (CryptographicException e)
        {
            throw new CryptoException("AEAD encryption failed", e);
        }

        var combined = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(combined, 0);
        tag.CopyTo(combined, ciphertext.Length);
        return combined;
    }

    /// <summary>
    /// Decrypt <c>ciphertext || tag</c> under <paramref name="suite"/>. Throws
    /// <see cref="CryptoException"/> on any authentication failure (tampering, wrong
    /// key/nonce/AAD, truncation) — never returns unauthenticated plaintext.
    /// </summary>
    public static byte[] AeadDecrypt(AeadSuite suite, byte[] key, byte[] nonce, byte[] aad, byte[] ciphertextAndTag)
    {
        RequireLen(key, 32, "AEAD key");
        RequireLen(nonce, AeadNonceLen, "AEAD nonce");
        RequireSuiteSupported(suite);

        if (ciphertextAndTag.Length < AeadTagLen)
        {
            throw new CryptoException("AEAD decryption failed (ciphertext shorter than the authentication tag)");
        }

        int ctLen = ciphertextAndTag.Length - AeadTagLen;
        var ciphertext = ciphertextAndTag.AsSpan(0, ctLen);
        var tag = ciphertextAndTag.AsSpan(ctLen, AeadTagLen);
        var plaintext = new byte[ctLen];

        try
        {
            switch (suite)
            {
                case AeadSuite.Aes256Gcm:
                    using (var aes = new AesGcm(key, AeadTagLen))
                    {
                        aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                    }

                    break;
                case AeadSuite.ChaCha20Poly1305:
                    using (var cc = new System.Security.Cryptography.ChaCha20Poly1305(key))
                    {
                        cc.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                    }

                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(suite));
            }
        }
        catch (CryptographicException e)
        {
            throw new CryptoException("AEAD decryption failed (tampering, wrong key, or wrong AAD)", e);
        }

        return plaintext;
    }

    private static void RequireSuiteSupported(AeadSuite suite)
    {
        if (!IsSuiteSupported(suite))
        {
            throw new CryptoException($"AEAD suite {suite.WireId()} is not supported on this runtime");
        }
    }

    /// <summary>Constant-time byte-array equality (defense in depth; NSec/BCL's own MAC/signature checks are already constant-time).</summary>
    public static bool ConstantTimeEquals(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);
}
