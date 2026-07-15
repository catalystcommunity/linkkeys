package community.catalyst.linkkeys.localrp.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * JCA/JCE-only crypto primitives this SDK needs (design doc, Language Crypto
 * Matrix, "Java" row): Ed25519 sign/verify, XDH/X25519 key agreement,
 * AES-256-GCM and ChaCha20-Poly1305 AEAD, SHA-256 fingerprinting, CSPRNG
 * bytes, and a hand-rolled HKDF-SHA256 (the one gap in JCA on JDK 17 &mdash;
 * the standard {@code javax.crypto.KDF} API only lands in JDK 24). Zero
 * external dependencies.
 *
 * <h2>The raw-key-import/export footgun (EdEC/XDH raw bytes)</h2>
 *
 * JCA's {@code KeyFactory} for Ed25519/XDH does not take raw 32-byte keys
 * directly as a constructor argument the way, say, {@code ed25519-dalek}'s
 * {@code SigningKey::from_bytes} does. The two raw-bytes shapes this
 * protocol uses (RFC 8032 for Ed25519, RFC 7748 for X25519) are each a
 * little-endian encoding with one special bit:
 *
 * <ul>
 *   <li><b>Ed25519 public key</b> (32 bytes): the little-endian encoding of
 *       the curve point's {@code y}-coordinate, with the point's
 *       {@code x}-coordinate parity bit stashed in the <em>top bit of the
 *       last byte</em> (byte index 31). JCA's {@link EdECPoint} models this
 *       natively as {@code (boolean xOdd, BigInteger y)} &mdash; so the
 *       conversion is: reverse the 32 bytes to big-endian, read off (and
 *       clear) the top bit of the now-first byte as {@code xOdd}, and the
 *       rest as {@code y}. {@link #importEd25519PublicKey} /
 *       {@link #exportEd25519PublicKey} do exactly this, verified
 *       byte-for-byte against every {@code verify_key_hex} in
 *       {@code envelopes.json}.</li>
 *   <li><b>Ed25519 private key</b> (32-byte seed): {@link EdECPrivateKeySpec}
 *       takes the raw seed directly (no point decoding needed), and a
 *       generated {@link EdECPrivateKey}'s {@code getBytes()} returns the
 *       raw seed back out &mdash; no PKCS8/DER wrapping required on JDK 17's
 *       SunEC provider.</li>
 *   <li><b>X25519 public key</b> (32 bytes): the little-endian encoding of
 *       the {@code u}-coordinate (RFC 7748), with the caveat that the
 *       decoder MUST mask the top bit of the last byte before interpreting
 *       the rest as the coordinate's magnitude (RFC 7748 &sect;5: "When
 *       receiving such an array, implementations of X25519 MUST mask the
 *       most significant bit in the final byte"). {@link XECPublicKeySpec}
 *       takes the {@code u}-coordinate as a plain {@link BigInteger}, so
 *       {@link #importX25519PublicKey} does the same reverse-and-mask dance
 *       as the Ed25519 case, without the parity bit.</li>
 *   <li><b>X25519 private key</b> (32-byte scalar): {@link XECPrivateKeySpec}
 *       takes the raw scalar directly; SunEC clamps it internally at
 *       agreement time per RFC 7748, so this SDK never has to implement
 *       clamping itself. A generated {@link XECPrivateKey}'s
 *       {@code getScalar()} returns the raw scalar back out.</li>
 * </ul>
 *
 * All four directions are exercised by this SDK's conformance tests against
 * {@code keys.json}, {@code envelopes.json}, and {@code callback_box.json}.
 */
public final class Crypto {
    private Crypto() {}

    private static final NamedParameterSpec ED25519_PARAMS = new NamedParameterSpec("Ed25519");
    private static final NamedParameterSpec X25519_PARAMS = new NamedParameterSpec("X25519");
    private static final SecureRandom RANDOM = new SecureRandom();

    // -----------------------------------------------------------------
    // Fingerprint / randomness
    // -----------------------------------------------------------------

    /** {@code sha256(public_key_bytes)}, lowercase hex &mdash; the canonical LinkKeys fingerprint format, everywhere. */
    public static String fingerprint(byte[] publicKeyBytes) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return Hex.encode(sha256.digest(publicKeyBytes));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("SHA-256 unavailable", e);
        }
    }

    /** CSPRNG bytes ({@code SecureRandom}, the JCA equivalent of {@code OsRng}/{@code rand::random}). */
    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }

    private static void requireLen(byte[] b, int len, String what) {
        if (b.length != len) {
            throw new CryptoException(what + " must be " + len + " bytes, got " + b.length);
        }
    }

    /**
     * Reverse a byte array's order, returning a new array. Used to flip
     * between the wire's little-endian raw-key encoding and JCA's
     * big-endian {@link BigInteger} magnitude.
     */
    private static byte[] reversedCopy(byte[] a) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = a[a.length - 1 - i];
        }
        return out;
    }

    /**
     * Encode a nonnegative {@link BigInteger} magnitude as exactly
     * {@code len} little-endian bytes (left-zero-padded in big-endian terms
     * before reversal). Throws if the magnitude does not fit.
     */
    private static byte[] toFixedLenLittleEndian(BigInteger v, int len) {
        byte[] be = v.toByteArray(); // big-endian, two's complement (v >= 0, so at most one leading zero sign byte)
        int offset = 0;
        while (offset < be.length - 1 && be[offset] == 0) {
            offset++;
        }
        int usedLen = be.length - offset;
        if (usedLen > len) {
            throw new CryptoException("value does not fit in " + len + " bytes");
        }
        byte[] bigEndianFixed = new byte[len];
        System.arraycopy(be, offset, bigEndianFixed, len - usedLen, usedLen);
        return reversedCopy(bigEndianFixed);
    }

    // -----------------------------------------------------------------
    // Ed25519
    // -----------------------------------------------------------------

    public record Ed25519KeyPair(byte[] publicKey, byte[] privateKeySeed) {}

    /** Generate a fresh Ed25519 keypair, returning raw 32-byte public key and 32-byte private seed. */
    public static Ed25519KeyPair generateEd25519KeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair pair = kpg.generateKeyPair();
            return new Ed25519KeyPair(
                    exportEd25519PublicKey(pair.getPublic()), exportEd25519PrivateKey(pair.getPrivate()));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 key generation failed", e);
        }
    }

    /** Raw 32-byte Ed25519 public key -&gt; JCA {@link PublicKey}. See class docs for the point encoding. */
    public static PublicKey importEd25519PublicKey(byte[] raw) {
        requireLen(raw, 32, "Ed25519 public key");
        byte[] bigEndian = reversedCopy(raw);
        boolean xOdd = (bigEndian[0] & 0x80) != 0;
        bigEndian[0] = (byte) (bigEndian[0] & 0x7f);
        BigInteger y = new BigInteger(1, bigEndian);
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            return kf.generatePublic(new EdECPublicKeySpec(ED25519_PARAMS, new EdECPoint(xOdd, y)));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("invalid Ed25519 public key bytes", e);
        }
    }

    /** JCA Ed25519 {@link PublicKey} -&gt; raw 32 bytes. Inverse of {@link #importEd25519PublicKey}. */
    public static byte[] exportEd25519PublicKey(PublicKey pub) {
        if (!(pub instanceof EdECPublicKey edPub)) {
            throw new CryptoException("not an Ed25519 public key: " + pub.getClass());
        }
        EdECPoint point = edPub.getPoint();
        byte[] out = toFixedLenLittleEndian(point.getY(), 32);
        out[31] = (byte) (out[31] & 0x7f);
        if (point.isXOdd()) {
            out[31] = (byte) (out[31] | 0x80);
        }
        return out;
    }

    /** Raw 32-byte Ed25519 private key seed -&gt; JCA {@link PrivateKey}. */
    public static PrivateKey importEd25519PrivateKey(byte[] seed) {
        requireLen(seed, 32, "Ed25519 private key seed");
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            return kf.generatePrivate(new EdECPrivateKeySpec(ED25519_PARAMS, seed.clone()));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("invalid Ed25519 private key seed", e);
        }
    }

    /** JCA Ed25519 {@link PrivateKey} -&gt; raw 32-byte seed. Inverse of {@link #importEd25519PrivateKey}. */
    public static byte[] exportEd25519PrivateKey(PrivateKey priv) {
        if (!(priv instanceof EdECPrivateKey edPriv)) {
            throw new CryptoException("not an Ed25519 private key: " + priv.getClass());
        }
        Optional<byte[]> bytes = edPriv.getBytes();
        return bytes.orElseThrow(() -> new CryptoException("Ed25519 private key seed not extractable"));
    }

    /** Sign {@code message} with an Ed25519 seed (raw 32-byte private key). Returns a 64-byte signature. */
    public static byte[] signEd25519(byte[] message, byte[] privateKeySeed) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(importEd25519PrivateKey(privateKeySeed));
            sig.update(message);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Ed25519 signing failed", e);
        }
    }

    /**
     * Verify an Ed25519 signature. Never throws for a malformed key/signature
     * &mdash; returns {@code false} uniformly, so callers can treat every
     * failure mode alike (design doc: signature verification is a closed,
     * uniform pass/fail boundary).
     */
    public static boolean verifyEd25519(byte[] message, byte[] signature, byte[] publicKey) {
        if (publicKey.length != 32 || signature.length != 64) {
            return false;
        }
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(importEd25519PublicKey(publicKey));
            sig.update(message);
            return sig.verify(signature);
        } catch (GeneralSecurityException | CryptoException e) {
            return false;
        }
    }

    // -----------------------------------------------------------------
    // X25519 (XDH)
    // -----------------------------------------------------------------

    public record X25519KeyPair(byte[] publicKey, byte[] privateKey) {}

    /** Generate a fresh X25519 encryption keypair &mdash; a *separate* key from any signing key. */
    public static X25519KeyPair generateX25519KeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            KeyPair pair = kpg.generateKeyPair();
            return new X25519KeyPair(
                    exportX25519PublicKey(pair.getPublic()), exportX25519PrivateKey(pair.getPrivate()));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("X25519 key generation failed", e);
        }
    }

    /** Raw 32-byte X25519 public key (u-coordinate, RFC 7748) -&gt; JCA {@link PublicKey}. */
    public static PublicKey importX25519PublicKey(byte[] raw) {
        requireLen(raw, 32, "X25519 public key");
        byte[] bigEndian = reversedCopy(raw);
        // RFC 7748 section 5: mask the most significant bit of the final (here: first, post-reversal) byte.
        bigEndian[0] = (byte) (bigEndian[0] & 0x7f);
        BigInteger u = new BigInteger(1, bigEndian);
        try {
            KeyFactory kf = KeyFactory.getInstance("X25519");
            return kf.generatePublic(new XECPublicKeySpec(X25519_PARAMS, u));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("invalid X25519 public key bytes", e);
        }
    }

    /** JCA X25519 {@link PublicKey} -&gt; raw 32 bytes. Inverse of {@link #importX25519PublicKey}. */
    public static byte[] exportX25519PublicKey(PublicKey pub) {
        if (!(pub instanceof XECPublicKey xecPub)) {
            throw new CryptoException("not an X25519 public key: " + pub.getClass());
        }
        return toFixedLenLittleEndian(xecPub.getU(), 32);
    }

    /** Raw 32-byte X25519 private scalar -&gt; JCA {@link PrivateKey}. Clamping happens internally at agreement time. */
    public static PrivateKey importX25519PrivateKey(byte[] raw) {
        requireLen(raw, 32, "X25519 private key");
        try {
            KeyFactory kf = KeyFactory.getInstance("X25519");
            return kf.generatePrivate(new XECPrivateKeySpec(X25519_PARAMS, raw.clone()));
        } catch (GeneralSecurityException e) {
            throw new CryptoException("invalid X25519 private key bytes", e);
        }
    }

    /** JCA X25519 {@link PrivateKey} -&gt; raw 32-byte scalar. Inverse of {@link #importX25519PrivateKey}. */
    public static byte[] exportX25519PrivateKey(PrivateKey priv) {
        if (!(priv instanceof XECPrivateKey xecPriv)) {
            throw new CryptoException("not an X25519 private key: " + priv.getClass());
        }
        Optional<byte[]> scalar = xecPriv.getScalar();
        return scalar.orElseThrow(() -> new CryptoException("X25519 private scalar not extractable"));
    }

    /**
     * RFC 7748 base point ({@code u = 9}), little-endian 32-byte encoding.
     * Used by {@link #derivePublicFromX25519Private} below.
     */
    private static final byte[] X25519_BASE_POINT_RAW = basePointRaw();

    private static byte[] basePointRaw() {
        byte[] b = new byte[32];
        b[0] = 9;
        return b;
    }

    /**
     * Derive the raw 32-byte X25519 public key for a raw 32-byte private
     * scalar &mdash; needed on the decrypting side of the callback sealed
     * box, which must feed its OWN public key (not the ephemeral sender's)
     * into the KDF/AAD construction from only its private key (mirrors
     * {@code local_rp.rs::open_local_rp_callback}'s
     * {@code X25519PublicKey::from(&recipient_secret)}).
     *
     * <p>JCA has no direct "scalar -&gt; point" primitive independent of a
     * {@link KeyAgreement}, but scalar multiplication by the RFC 7748 base
     * point <em>is</em> exactly what a key agreement against the base point
     * "public key" computes &mdash; a standard, well-known trick that needs
     * no hand-rolled elliptic-curve arithmetic and stays entirely within
     * JCA/JCE.
     */
    public static byte[] derivePublicFromX25519Private(byte[] privateKey) {
        return x25519DiffieHellman(privateKey, X25519_BASE_POINT_RAW);
    }

    /**
     * X25519 Diffie-Hellman, rejecting a non-contributory (low-order) result
     * (Wire Precision: "reject an all-zero shared secret"). JDK's XDH
     * {@link KeyAgreement} already rejects several known low-order inputs at
     * {@code doPhase} time by throwing {@link InvalidKeyException}; this
     * method treats that identically to an explicit all-zero check on the
     * output, so rejection is uniform regardless of which layer catches it.
     */
    public static byte[] x25519DiffieHellman(byte[] privateKey, byte[] publicKey) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(importX25519PrivateKey(privateKey));
            ka.doPhase(importX25519PublicKey(publicKey), true);
            byte[] shared = ka.generateSecret();
            rejectLowOrder(shared);
            return shared;
        } catch (InvalidKeyException e) {
            throw new CryptoException("non-contributory (low-order) X25519 key rejected", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("X25519 key agreement failed", e);
        }
    }

    private static void rejectLowOrder(byte[] sharedSecret) {
        boolean allZero = true;
        for (byte b : sharedSecret) {
            if (b != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            throw new CryptoException("non-contributory (low-order) X25519 key rejected");
        }
    }

    // -----------------------------------------------------------------
    // HKDF-SHA256 (hand-rolled: the one JCA/JCE gap on JDK 17 -- the
    // standard javax.crypto.KDF API only lands in JDK 24)
    // -----------------------------------------------------------------

    private static final int HASH_LEN = 32;

    /** RFC 5869 HKDF-Extract with HMAC-SHA256. A {@code null}/empty salt uses a zero-filled salt of hash length. */
    static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        byte[] realSalt = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(realSalt, "HmacSHA256"));
            return mac.doFinal(ikm);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HKDF extract failed", e);
        }
    }

    /** RFC 5869 HKDF-Expand with HMAC-SHA256, to {@code length} output bytes. */
    static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            int n = (length + HASH_LEN - 1) / HASH_LEN;
            if (n > 255) {
                throw new CryptoException("HKDF expand length too large: " + length);
            }
            byte[] out = new byte[length];
            byte[] t = new byte[0];
            int written = 0;
            for (int i = 1; i <= n; i++) {
                mac.reset();
                mac.update(t);
                mac.update(info);
                mac.update((byte) i);
                t = mac.doFinal();
                int toCopy = Math.min(HASH_LEN, length - written);
                System.arraycopy(t, 0, out, written, toCopy);
                written += toCopy;
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("HKDF expand failed", e);
        }
    }

    /**
     * HKDF-SHA256(salt=none, ikm).expand(info, length) &mdash; exactly
     * {@code hkdf::Hkdf::<Sha256>::new(None, ikm).expand(info, &mut out)} on
     * the Rust side. This is the ~15-line hand-rolled gap the design doc
     * calls out for Java on JDK 17.
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] info, int length) {
        byte[] prk = hkdfExtract(null, ikm);
        return hkdfExpand(prk, info, length);
    }

    // -----------------------------------------------------------------
    // AEAD dispatch (AES-256-GCM baseline, ChaCha20-Poly1305 optional)
    // -----------------------------------------------------------------

    private static final int AEAD_TAG_BITS = 128;

    private static Cipher aeadCipher(AeadSuite suite) {
        try {
            return switch (suite) {
                case AES_256_GCM -> Cipher.getInstance("AES/GCM/NoPadding");
                case CHACHA20_POLY1305 -> Cipher.getInstance("ChaCha20-Poly1305");
            };
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AEAD cipher unavailable: " + suite, e);
        }
    }

    /** Encrypt under {@code suite}. Output is {@code ciphertext || 16-byte tag} (RustCrypto/JCA convention). */
    public static byte[] aeadEncrypt(AeadSuite suite, byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        requireLen(key, 32, "AEAD key");
        requireLen(nonce, 12, "AEAD nonce");
        try {
            Cipher cipher = aeadCipher(suite);
            String keyAlg = suite == AeadSuite.AES_256_GCM ? "AES" : "ChaCha20";
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, keyAlg),
                    aeadParams(suite, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AEAD encryption failed", e);
        }
    }

    /**
     * Decrypt {@code ciphertext || tag} under {@code suite}. Throws
     * {@link CryptoException} on any authentication failure (tampering,
     * wrong key/nonce/AAD, truncation) &mdash; never returns unauthenticated
     * plaintext.
     */
    public static byte[] aeadDecrypt(AeadSuite suite, byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) {
        requireLen(key, 32, "AEAD key");
        requireLen(nonce, 12, "AEAD nonce");
        try {
            Cipher cipher = aeadCipher(suite);
            String keyAlg = suite == AeadSuite.AES_256_GCM ? "AES" : "ChaCha20";
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, keyAlg),
                    aeadParams(suite, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AEAD decryption failed (tampering, wrong key, or wrong AAD)", e);
        }
    }

    private static java.security.spec.AlgorithmParameterSpec aeadParams(AeadSuite suite, byte[] nonce) {
        return switch (suite) {
            case AES_256_GCM -> new GCMParameterSpec(AEAD_TAG_BITS, nonce);
            case CHACHA20_POLY1305 -> new IvParameterSpec(nonce);
        };
    }

    /** Constant-time byte-array equality (for defense in depth; JCA's own MAC/signature checks are already constant-time). */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
}
