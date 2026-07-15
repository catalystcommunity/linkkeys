package community.catalyst.linkkeys.localrp.kt

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.Crypto
import community.catalyst.linkkeys.localrp.kt.testutil.Fixtures

/** Conformance vectors: `tickets.json`, exercised through this package's own [Crypto.fingerprint]. */
class TicketsConformanceTest {

    @Test
    fun hashPairsMatchFingerprintRoutine() {
        val d = Fixtures.load("tickets.json")
        val cases = d.get("cases").asArray()
        assertFalse(cases.isEmpty())
        for (c in cases) {
            val ticket = Fixtures.hex(c.get("ticket_hex").asString())
            assertEquals(32, ticket.size)
            assertEquals(c.get("sha256_hex").asString(), Crypto.fingerprint(ticket))
        }
    }
}
