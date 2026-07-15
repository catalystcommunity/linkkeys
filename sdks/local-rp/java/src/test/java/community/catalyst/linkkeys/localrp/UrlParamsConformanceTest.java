package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.testutil.Fixtures;
import community.catalyst.linkkeys.localrp.testutil.MiniJson.JsonValue;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpEncryptedCallback;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpLoginRequest;

/** Conformance vectors: {@code url_params.json}. */
class UrlParamsConformanceTest {

    @Test
    void casesRoundTripBothDirections() {
        JsonValue d = Fixtures.load("url_params.json");
        List<JsonValue> cases = d.get("cases").asArray();
        assertEquals(2, cases.size());

        for (JsonValue c : cases) {
            byte[] cbor = Fixtures.hex(c.get("cbor_hex").asString());
            String b64 = c.get("base64url_unpadded").asString();

            assertEquals(b64, Base64.getUrlEncoder().withoutPadding().encodeToString(cbor));
            assertArrayEquals(cbor, Base64.getUrlDecoder().decode(b64));

            String name = c.get("name").asString();
            switch (name) {
                case "signed_local_rp_login_request" -> {
                    SignedLocalRpLoginRequest typed = Codec.decodeSignedLocalRpLoginRequest(cbor);
                    assertEquals(b64, Encoding.signedLocalRpLoginRequestToUrlParam(typed));
                    SignedLocalRpLoginRequest roundTripped = Encoding.signedLocalRpLoginRequestFromUrlParam(b64);
                    assertArrayEquals(roundTripped.request(), typed.request());
                    assertArrayEquals(roundTripped.signature(), typed.signature());
                }
                case "local_rp_encrypted_callback" -> {
                    LocalRpEncryptedCallback typed = Codec.decodeLocalRpEncryptedCallback(cbor);
                    assertEquals(b64, Encoding.localRpEncryptedCallbackToUrlParam(typed));
                    LocalRpEncryptedCallback roundTripped = Encoding.localRpEncryptedCallbackFromUrlParam(b64);
                    assertArrayEquals(roundTripped.header(), typed.header());
                    assertArrayEquals(roundTripped.ciphertext(), typed.ciphertext());
                }
                default -> throw new IllegalStateException("unrecognized url_params.json case name: " + name);
            }
        }
    }

    @Test
    void negativeCasesRejected() {
        JsonValue d = Fixtures.load("url_params.json");
        List<JsonValue> cases = d.get("negative_cases").asArray();
        assertEquals(2, cases.size());
        for (JsonValue c : cases) {
            String input = c.get("input").asString();
            assertThrows(RuntimeException.class, () -> Encoding.localRpEncryptedCallbackFromUrlParam(input));
        }
    }
}
