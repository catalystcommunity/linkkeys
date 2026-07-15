package community.catalyst.linkkeys.localrp.kt

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.DnsRecords
import community.catalyst.linkkeys.localrp.kt.testutil.Fixtures

/** Conformance vectors: `dns.json`, exercised through this package's own [DnsRecords]. */
class DnsConformanceTest {

    @Test
    fun linkkeysTxtCases() {
        val d = Fixtures.load("dns.json").get("linkkeys_txt")

        for (c in d.get("valid_cases").asArray()) {
            val txt = c.get("txt").asString()
            val record = DnsRecords.parseLinkKeysTxt(txt)
            val expected = c.get("expected_fingerprints").asArray().map { it.asString() }
            assertEquals(expected, record.fingerprints, "txt=$txt")
        }

        for (c in d.get("invalid_cases").asArray()) {
            val txt = c.get("txt").asString()
            val err = assertThrows(LocalRpException.Dns::class.java) { DnsRecords.parseLinkKeysTxt(txt) }
            assertEquals(c.get("expected_error").asString(), err.kind.name.lowercase())
        }

        assertTrue(d.get("no_record_case").get("documentation_only").asBoolean())
    }

    @Test
    fun linkkeysApisTxtCases() {
        val d = Fixtures.load("dns.json").get("linkkeys_apis_txt")

        for (c in d.get("valid_cases").asArray()) {
            val txt = c.get("txt").asString()
            val apis = DnsRecords.parseLinkKeysApisTxt(txt)
            val expectedTcp = if (c.get("expected_tcp").isNull()) null else c.get("expected_tcp").asString()
            val expectedHttps = if (c.get("expected_https_base").isNull()) null else c.get("expected_https_base").asString()
            assertEquals(expectedTcp, apis.tcp, "txt=$txt")
            assertEquals(expectedHttps, apis.httpsBase, "txt=$txt")
        }

        for (c in d.get("invalid_cases").asArray()) {
            val txt = c.get("txt").asString()
            val err = assertThrows(LocalRpException.Dns::class.java) { DnsRecords.parseLinkKeysApisTxt(txt) }
            assertEquals(c.get("expected_error").asString(), err.kind.name.lowercase())
        }

        assertEquals(Fixtures.load("dns.json").get("default_tcp_port").asLong(), DnsRecords.DEFAULT_TCP_PORT.toLong())
    }
}
