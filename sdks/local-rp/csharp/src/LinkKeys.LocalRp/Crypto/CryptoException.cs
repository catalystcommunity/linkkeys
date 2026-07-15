namespace LinkKeys.LocalRp.Crypto;

/// <summary>
/// Thrown for any cryptographic failure in this namespace: signature verification
/// failure, AEAD authentication failure, a non-contributory (low-order) X25519 key,
/// a malformed key length, or an unexpected NSec/BCL provider error. Never carries
/// key material, shared secrets, or plaintext in its message (AGENTS.md: "Never log
/// sensitive information").
/// </summary>
public class CryptoException : Exception
{
    public CryptoException(string message) : base(message)
    {
    }

    public CryptoException(string message, Exception cause) : base(message, cause)
    {
    }
}
