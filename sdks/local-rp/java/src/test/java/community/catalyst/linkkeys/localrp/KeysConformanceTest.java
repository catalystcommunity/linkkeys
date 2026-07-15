package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.testutil.Fixtures;
import community.catalyst.linkkeys.localrp.testutil.MiniJson.JsonValue;

/** Conformance vectors: {@code keys.json}. */
class KeysConformanceTest {

    @Test
    void fingerprintsRoundTripThroughSdkFingerprintHelpers() {
        JsonValue d = Fixtures.load("keys.json");

        for (JsonValue node : new JsonValue[] {d.get("local_rp").get("signing"), d.get("domain_signing_key")}) {
            byte[] seed = Fixtures.hex(node.get("seed_hex").asString());
            byte[] expectedPublic = Fixtures.hex(node.get("public_key_hex").asString());
            String expectedFp = node.get("fingerprint_hex").asString();

            // Confirm seed and public key correspond to the same Ed25519
            // keypair: signing with the seed and verifying against the
            // fixture's public key must succeed.
            byte[] message = "conformance-check".getBytes(StandardCharsets.UTF_8);
            byte[] sig = Crypto.signEd25519(message, seed);
            assertTrue(Crypto.verifyEd25519(message, sig, expectedPublic));

            String computed = Crypto.fingerprint(expectedPublic);
            assertEquals(expectedFp, computed);

            // Round-trip through the SDK's own fingerprint string helpers.
            String s = Identity.fingerprintToString(computed);
            assertEquals(expectedFp, Identity.fingerprintFromString(s));

            assertEquals(32, seed.length);
        }

        // fingerprintFromString must reject non-fingerprint strings even
        // when they happen to be valid hex of the wrong length.
        assertThrows(SdkException.class, () -> Identity.fingerprintFromString("deadbeef"));
    }

    @Test
    void x25519PublicKeysDeriveFromPrivateKeys() {
        JsonValue d = Fixtures.load("keys.json");
        for (JsonValue node : new JsonValue[] {d.get("local_rp").get("encryption"), d.get("domain_encryption_recipient")}) {
            byte[] priv = Fixtures.hex(node.get("private_key_hex").asString());
            byte[] expectedPublic = Fixtures.hex(node.get("public_key_hex").asString());
            assertArrayEquals(expectedPublic, Crypto.derivePublicFromX25519Private(priv));
        }
    }
}
