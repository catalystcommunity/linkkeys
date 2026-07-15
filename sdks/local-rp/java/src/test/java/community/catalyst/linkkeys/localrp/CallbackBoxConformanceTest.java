package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.crypto.AeadSuite;
import community.catalyst.linkkeys.localrp.testutil.Fixtures;
import community.catalyst.linkkeys.localrp.testutil.MiniJson.JsonValue;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpEncryptedCallback;

/** Conformance vectors: {@code callback_box.json}. */
class CallbackBoxConformanceTest {

    private static List<AeadSuite> parseAllowedSuites(JsonValue c) {
        List<AeadSuite> out = new ArrayList<>();
        for (JsonValue s : c.get("allowed_suites").asArray()) {
            AeadSuite suite = AeadSuite.parse(s.asString());
            if (suite == null) {
                throw new IllegalStateException("unregistered suite id in fixture: " + s.asString());
            }
            out.add(suite);
        }
        return out;
    }

    @Test
    void positiveCasesOpenViaSdkDependency() {
        JsonValue d = Fixtures.load("callback_box.json");
        List<JsonValue> cases = d.get("positive_cases").asArray();
        assertEquals(2, cases.size());

        for (JsonValue c : cases) {
            byte[] headerBytes = Fixtures.hex(c.get("header_cbor_hex").asString());
            byte[] ciphertext = Fixtures.hex(c.get("ciphertext_hex").asString());
            byte[] decryptKey = Fixtures.hex(c.get("decrypt_private_key_hex").asString());
            List<AeadSuite> allowed = parseAllowedSuites(c);

            LocalRpEncryptedCallback encrypted = new LocalRpEncryptedCallback(headerBytes, ciphertext);
            LocalRp.OpenedCallback opened = LocalRp.openLocalRpCallback(encrypted, decryptKey, allowed);

            assertEquals(c.get("suite").asString(), opened.header().suite());
            assertEquals(c.get("fingerprint").asString(), opened.header().fingerprint());
            assertArrayEquals(Fixtures.hex(c.get("nonce_hex").asString()), opened.header().nonce());
            assertArrayEquals(Fixtures.hex(c.get("state_hex").asString()), opened.header().state());
            assertEquals(c.get("issued_at").asString(), opened.header().issuedAt());
            assertEquals(c.get("expires_at").asString(), opened.header().expiresAt());

            byte[] plaintext = Codec.encodeSignedLocalRpCallbackPayload(opened.signedPayload());
            assertArrayEquals(Fixtures.hex(c.get("plaintext_cbor_hex").asString()), plaintext);
        }
    }

    @Test
    void negativeCasesFail() {
        JsonValue d = Fixtures.load("callback_box.json");
        List<JsonValue> cases = d.get("negative_cases").asArray();
        assertEquals(13, cases.size());

        for (JsonValue c : cases) {
            byte[] headerBytes = Fixtures.hex(c.get("header_cbor_hex").asString());
            byte[] ciphertext = Fixtures.hex(c.get("ciphertext_hex").asString());
            byte[] decryptKey = Fixtures.hex(c.get("decrypt_private_key_hex").asString());
            List<AeadSuite> allowed = parseAllowedSuites(c);

            LocalRpEncryptedCallback encrypted = new LocalRpEncryptedCallback(headerBytes, ciphertext);
            assertThrows(
                    RuntimeException.class,
                    () -> LocalRp.openLocalRpCallback(encrypted, decryptKey, allowed),
                    "negative case unexpectedly opened: " + c.getOrNull("name"));
        }
    }
}
