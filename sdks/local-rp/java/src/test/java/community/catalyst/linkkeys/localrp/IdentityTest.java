package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.crypto.AeadSuite;
import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpDescriptor;

/** Unit tests for {@link Identity} (mirrors the Rust/Go SDKs' own {@code identity} module tests). */
class IdentityTest {

    private static Identity.LocalRpKeyMaterial material() {
        return Identity.generateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("Test App", Instant.now()));
    }

    @Test
    void generateIdentityDefaultsBothSuitesAndTenYearLifetime() {
        Identity.LocalRpKeyMaterial identity = material();
        assertEquals(64, identity.fingerprint().length());
        assertEquals(Crypto.fingerprint(identity.signingPublicKey()), identity.fingerprint());

        LocalRpDescriptor descriptor = Codec.decodeLocalRpDescriptor(identity.descriptor().descriptor());
        assertEquals("Test App", descriptor.appName());
        assertEquals(AeadSuite.allSupported(), descriptor.supportedSuites());
    }

    @Test
    void generateIdentityRejectsEmptyAppName() {
        assertThrows(
                SdkException.class,
                () -> Identity.generateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("", Instant.now())));
    }

    @Test
    void generateIdentityRejectsEmptySuiteList() {
        Identity.GenerateLocalRpIdentityConfig config =
                new Identity.GenerateLocalRpIdentityConfig("Test App", Instant.now());
        config.supportedSuites = List.of();
        assertThrows(SdkException.class, () -> Identity.generateLocalRpIdentity(config));
    }

    @Test
    void signingAndEncryptionKeyByteRoundTrips() {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 7);
        assertArrayEquals(key, Identity.signingKeyFromBytes(Identity.signingKeyToBytes(key)));
        assertArrayEquals(key, Identity.encryptionKeyFromBytes(Identity.encryptionKeyToBytes(key)));
        assertThrows(SdkException.class, () -> Identity.signingKeyFromBytes(new byte[31]));
        assertThrows(SdkException.class, () -> Identity.encryptionKeyFromBytes(new byte[33]));
    }

    @Test
    void fingerprintStringRoundTripValidatesHex() {
        Identity.LocalRpKeyMaterial identity = material();
        String s = Identity.fingerprintToString(identity.fingerprint());
        assertEquals(identity.fingerprint(), Identity.fingerprintFromString(s));
        assertThrows(SdkException.class, () -> Identity.fingerprintFromString("not-hex"));
        assertThrows(SdkException.class, () -> Identity.fingerprintFromString("a".repeat(63)));
    }

    @Test
    void identityBundleByteRoundTrip() {
        Identity.LocalRpKeyMaterial identity = material();
        byte[] bytes = Identity.localRpIdentityToBytes(identity);
        Identity.LocalRpKeyMaterial roundTripped = Identity.localRpIdentityFromBytes(bytes);

        assertArrayEquals(identity.signingPrivateKey(), roundTripped.signingPrivateKey());
        assertArrayEquals(identity.signingPublicKey(), roundTripped.signingPublicKey());
        assertArrayEquals(identity.encryptionPrivateKey(), roundTripped.encryptionPrivateKey());
        assertArrayEquals(identity.encryptionPublicKey(), roundTripped.encryptionPublicKey());
        assertEquals(identity.fingerprint(), roundTripped.fingerprint());
        assertArrayEquals(identity.descriptor().descriptor(), roundTripped.descriptor().descriptor());
        assertArrayEquals(identity.descriptor().signature(), roundTripped.descriptor().signature());
    }

    @Test
    void identityBundleRejectsBadMagicAndTruncation() {
        Identity.LocalRpKeyMaterial identity = material();
        byte[] bytes = Identity.localRpIdentityToBytes(identity);
        byte[] badMagic = bytes.clone();
        badMagic[0] ^= (byte) 0xff;
        assertThrows(SdkException.class, () -> Identity.localRpIdentityFromBytes(badMagic));

        byte[] truncated = java.util.Arrays.copyOfRange(bytes, 0, 10);
        assertThrows(SdkException.class, () -> Identity.localRpIdentityFromBytes(truncated));
    }

    @Test
    void checkExpirationsWrapsThresholds() {
        Identity.GenerateLocalRpIdentityConfig config =
                new Identity.GenerateLocalRpIdentityConfig("Test App", Instant.now());
        config.lifetime = Duration.ofDays(100);
        Identity.LocalRpKeyMaterial identity = Identity.generateLocalRpIdentity(config);

        LocalRp.ExpirationStatus status = LinkKeysLocalRp.checkExpirations(identity, Instant.now());
        assertEquals(LocalRp.ExpirationLevel.NOTICE, status.level());

        Instant farFuture = Instant.now().plus(Duration.ofDays(200));
        LocalRp.ExpirationStatus expired = LinkKeysLocalRp.checkExpirations(identity, farFuture);
        assertEquals(LocalRp.ExpirationLevel.EXPIRED, expired.level());
    }
}
