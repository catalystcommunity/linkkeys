package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.testutil.Fixtures;
import community.catalyst.linkkeys.localrp.testutil.MiniJson.JsonValue;

/** Conformance vectors: {@code envelopes.json} &mdash; the four signature contexts. */
class EnvelopesConformanceTest {

    private void checkCase(JsonValue c, boolean expectValid) {
        String context = c.get("context").asString();
        byte[] payload = Fixtures.hex(c.get("payload_cbor_hex").asString());
        byte[] expectedSigInput = Fixtures.hex(c.get("signature_input_cbor_hex").asString());
        byte[] signature = Fixtures.hex(c.get("signature_hex").asString());
        byte[] verifyKey = Fixtures.hex(c.get("verify_key_hex").asString());

        byte[] computedSigInput = LocalRp.envelopeSignatureInput(context, payload);
        assertArrayEquals(expectedSigInput, computedSigInput, "signature_input_cbor_hex mismatch");

        boolean valid = Crypto.verifyEd25519(computedSigInput, signature, verifyKey);
        assertEquals(expectValid, valid, "verify result mismatch");
    }

    @Test
    void positiveCasesVerify() {
        JsonValue d = Fixtures.load("envelopes.json");
        List<JsonValue> cases = d.get("cases").asArray();
        assertEquals(4, cases.size());
        for (JsonValue c : cases) {
            assertTrue(c.get("expected_valid").asBoolean());
            checkCase(c, true);
        }
    }

    @Test
    void negativeCasesFail() {
        JsonValue d = Fixtures.load("envelopes.json");
        List<JsonValue> cases = d.get("negative_cases").asArray();
        assertEquals(20, cases.size());
        for (JsonValue c : cases) {
            assertFalse(c.get("expected_valid").asBoolean());
            checkCase(c, false);
        }
    }

    @Test
    void contextStringsMatchTheFourConstants() {
        JsonValue d = Fixtures.load("envelopes.json").get("context_strings");
        assertEquals(LocalRp.CTX_LOCAL_RP_DESCRIPTOR, d.get("descriptor").asString());
        assertEquals(LocalRp.CTX_LOCAL_RP_LOGIN_REQUEST, d.get("login_request").asString());
        assertEquals(LocalRp.CTX_LOCAL_RP_CALLBACK, d.get("callback_payload").asString());
        assertEquals(LocalRp.CTX_LOCAL_RP_TICKET_REDEMPTION, d.get("ticket_redemption").asString());
    }
}
