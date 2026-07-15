package community.catalyst.linkkeys.localrp.crypto;

/**
 * Thrown for any cryptographic failure in this package: signature
 * verification failure, AEAD authentication failure, a non-contributory
 * (low-order) X25519 key, a malformed key length, or an unexpected JCA
 * provider error. Never carries key material, shared secrets, or plaintext
 * in its message (AGENTS.md: "Never log sensitive information").
 */
public class CryptoException extends RuntimeException {
    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
