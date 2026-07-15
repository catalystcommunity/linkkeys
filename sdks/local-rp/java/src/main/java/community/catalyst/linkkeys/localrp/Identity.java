package community.catalyst.linkkeys.localrp;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import community.catalyst.linkkeys.localrp.crypto.AeadSuite;
import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.dns.Dns;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpDescriptor;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpDescriptor;

/**
 * {@code generate_local_rp_identity} and the raw-byte storage helpers
 * (design doc: "SDK API Shape", "Byte Storage Helpers").
 *
 * <p>A local RP identity is exactly one Ed25519 signing keypair, one X25519
 * encryption keypair, and a self-signed {@link SignedLocalRpDescriptor}
 * binding them together. There is no continuity story across rotation:
 * generating a new identity means a new fingerprint, full stop.
 *
 * <p>Security note (design doc, "Byte Storage Helpers"): the private key
 * fields in {@link LocalRpKeyMaterial} do not directly identify a user, but
 * they control this app's entire local RP identity &mdash; anyone holding
 * them can sign login requests and redeem claim tickets as this app. Store
 * them with ordinary application-secret care (the same care as a database
 * credential or API key), not merely as configuration.
 */
public final class Identity {
    private Identity() {}

    /** Default local RP key lifetime: 10 years (design doc: "Default lifetime: 10 years"). */
    public static final Duration DEFAULT_LIFETIME = Duration.ofDays(3650);

    /** Input to {@link #generateLocalRpIdentity}. Big-config, single class, per the design doc's "SDK API Shape". */
    public static final class GenerateLocalRpIdentityConfig {
        /** Display name shown on the IDP's consent screen. NOT identity &mdash; display/audit metadata only. */
        public String appName;
        /** Optional local domain/origin hint, also display/audit metadata. */
        public String localDomainHint;
        /** AEAD suites this app can decrypt callbacks with, preference order. Defaults to both registry suites. */
        public List<String> supportedSuites;
        /** Key/descriptor lifetime from {@code now}. Defaults to {@link #DEFAULT_LIFETIME}. */
        public Duration lifetime;
        /** The current time &mdash; never read from the system clock inside this class. */
        public final Instant now;

        public GenerateLocalRpIdentityConfig(String appName, Instant now) {
            this.appName = appName;
            this.now = now;
        }
    }

    /**
     * A local RP's full key material: signing keypair, encryption keypair,
     * the self-signed descriptor binding them (which also carries
     * {@code appName}, {@code localDomainHint}, {@code supportedSuites}, and
     * the created/expires timestamps), and the identity fingerprint.
     */
    public record LocalRpKeyMaterial(
            byte[] signingPrivateKey,
            byte[] signingPublicKey,
            byte[] encryptionPrivateKey,
            byte[] encryptionPublicKey,
            SignedLocalRpDescriptor descriptor,
            String fingerprint) {}

    /**
     * {@code generate_local_rp_identity(config) -> LocalRpKeyMaterial}
     * (design doc, "SDK API Shape"). Generates a fresh Ed25519 signing
     * keypair and a *separate* X25519 encryption keypair (never
     * algebraically derived), builds and self-signs the descriptor binding
     * them.
     */
    public static LocalRpKeyMaterial generateLocalRpIdentity(GenerateLocalRpIdentityConfig config) {
        if (config.appName == null || config.appName.isBlank()) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "app_name must not be empty");
        }

        Crypto.Ed25519KeyPair signing = Crypto.generateEd25519KeyPair();
        Crypto.X25519KeyPair encryption = Crypto.generateX25519KeyPair();

        List<String> suites = config.supportedSuites != null ? config.supportedSuites : AeadSuite.allSupported();
        if (suites.isEmpty()) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "supported_suites must not be empty");
        }

        Duration lifetime = config.lifetime != null ? config.lifetime : DEFAULT_LIFETIME;
        String createdAt = Rfc3339.format(config.now);
        String expiresAt = Rfc3339.format(config.now.plus(lifetime));

        LocalRpDescriptor descriptor = LocalRp.buildLocalRpDescriptor(
                config.appName,
                config.localDomainHint,
                signing.publicKey(),
                encryption.publicKey(),
                suites,
                createdAt,
                expiresAt);
        String fingerprint = descriptor.fingerprint();
        SignedLocalRpDescriptor signedDescriptor = LocalRp.signLocalRpDescriptor(descriptor, signing.privateKeySeed());

        return new LocalRpKeyMaterial(
                signing.privateKeySeed(), signing.publicKey(), encryption.privateKey(), encryption.publicKey(),
                signedDescriptor, fingerprint);
    }

    // -----------------------------------------------------------------
    // Byte storage helpers (design doc: "Byte Storage Helpers")
    // -----------------------------------------------------------------

    public static byte[] signingKeyToBytes(byte[] key) {
        return key.clone();
    }

    public static byte[] signingKeyFromBytes(byte[] bytes) {
        if (bytes.length != 32) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "signing key must be 32 bytes, got " + bytes.length);
        }
        return bytes.clone();
    }

    public static byte[] encryptionKeyToBytes(byte[] key) {
        return key.clone();
    }

    public static byte[] encryptionKeyFromBytes(byte[] bytes) {
        if (bytes.length != 32) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "encryption key must be 32 bytes, got " + bytes.length);
        }
        return bytes.clone();
    }

    /** The canonical fingerprint string form &mdash; a pass-through, since the fingerprint IS a hex string already. */
    public static String fingerprintToString(String fingerprint) {
        return fingerprint;
    }

    /** Parse/validate a fingerprint string: exactly 64 lowercase-normalized hex characters (a SHA-256 digest). */
    public static String fingerprintFromString(String s) {
        if (!Dns.isValidFingerprint(s)) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "not a valid fingerprint (want 64 hex chars): " + s);
        }
        return s.toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * Magic prefix for the identity-bundle byte format below. This is an
     * SDK-local storage convenience, NOT a protocol wire format &mdash;
     * nothing in the design doc's Wire Precision governs it, and no
     * conformance vector covers it.
     */
    private static final byte[] IDENTITY_BUNDLE_MAGIC = {'L', 'K', 'I', '1'};
    private static final int HEADER_LEN = 4 + 32 + 32 + 4;

    /**
     * {@code local_rp_identity_to_bytes(identity) -> bytes} (design doc,
     * "SDK API Shape" + "Byte Storage Helpers"). Layout:
     * {@code MAGIC(4) || signing_private_key(32) || encryption_private_key(32) || descriptor_len(4, BE) || descriptor_cbor}.
     */
    public static byte[] localRpIdentityToBytes(LocalRpKeyMaterial identity) {
        byte[] descriptorBytes = Codec.encodeSignedLocalRpDescriptor(identity.descriptor());
        ByteBuffer buf = ByteBuffer.allocate(HEADER_LEN + descriptorBytes.length);
        buf.put(IDENTITY_BUNDLE_MAGIC);
        buf.put(identity.signingPrivateKey());
        buf.put(identity.encryptionPrivateKey());
        buf.putInt(descriptorBytes.length);
        buf.put(descriptorBytes);
        return buf.array();
    }

    /**
     * {@code local_rp_identity_from_bytes(bytes) -> LocalRpIdentity} &mdash;
     * the inverse of {@link #localRpIdentityToBytes}. Public keys and the
     * fingerprint are read back out of the embedded descriptor rather than
     * re-derived from the private keys. Does no signature/expiry
     * verification (that is {@link LinkKeysLocalRp#checkExpirations}'s and
     * the protocol verification chain's job).
     */
    public static LocalRpKeyMaterial localRpIdentityFromBytes(byte[] bytes) {
        if (bytes.length < HEADER_LEN) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "identity bundle too short");
        }
        if (!Arrays.equals(Arrays.copyOfRange(bytes, 0, 4), IDENTITY_BUNDLE_MAGIC)) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "identity bundle has an unrecognized magic prefix");
        }
        byte[] signingPrivateKey = Arrays.copyOfRange(bytes, 4, 36);
        byte[] encryptionPrivateKey = Arrays.copyOfRange(bytes, 36, 68);
        int descriptorLen = ByteBuffer.wrap(bytes, 68, 4).getInt();
        if (descriptorLen < 0 || HEADER_LEN + (long) descriptorLen > bytes.length) {
            throw new SdkException(
                    SdkException.Kind.INVALID_INPUT, "identity bundle descriptor length exceeds available bytes");
        }
        byte[] descriptorBytes = Arrays.copyOfRange(bytes, HEADER_LEN, HEADER_LEN + descriptorLen);

        SignedLocalRpDescriptor signedDescriptor = Codec.decodeSignedLocalRpDescriptor(descriptorBytes);
        LocalRpDescriptor descriptor = Codec.decodeLocalRpDescriptor(signedDescriptor.descriptor());

        if (descriptor.signingPublicKey().length != 32) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "descriptor signing_public_key was not 32 bytes");
        }
        if (descriptor.encryptionPublicKey().length != 32) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "descriptor encryption_public_key was not 32 bytes");
        }

        return new LocalRpKeyMaterial(
                signingPrivateKey,
                descriptor.signingPublicKey(),
                encryptionPrivateKey,
                descriptor.encryptionPublicKey(),
                signedDescriptor,
                descriptor.fingerprint());
    }
}
