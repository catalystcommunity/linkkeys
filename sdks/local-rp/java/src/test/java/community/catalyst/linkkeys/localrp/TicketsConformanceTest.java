package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.List;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.testutil.Fixtures;
import community.catalyst.linkkeys.localrp.testutil.MiniJson.JsonValue;

/** Conformance vectors: {@code tickets.json}. */
class TicketsConformanceTest {

    @Test
    void hashPairsMatchFingerprintRoutine() {
        JsonValue d = Fixtures.load("tickets.json");
        List<JsonValue> cases = d.get("cases").asArray();
        assertFalse(cases.isEmpty());
        for (JsonValue c : cases) {
            byte[] ticket = Fixtures.hex(c.get("ticket_hex").asString());
            assertEquals(32, ticket.length);
            assertEquals(c.get("sha256_hex").asString(), Crypto.fingerprint(ticket));
        }
    }
}
