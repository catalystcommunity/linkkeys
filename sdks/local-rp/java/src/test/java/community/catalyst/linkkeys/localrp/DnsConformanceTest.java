package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.dns.Dns;
import community.catalyst.linkkeys.localrp.dns.DnsParseError;
import community.catalyst.linkkeys.localrp.testutil.Fixtures;
import community.catalyst.linkkeys.localrp.testutil.MiniJson.JsonValue;

/** Conformance vectors: {@code dns.json}. */
class DnsConformanceTest {

    private static String errorSymbol(DnsParseError e) {
        return e.symbol();
    }

    @Test
    void linkkeysTxtCases() {
        JsonValue d = Fixtures.load("dns.json").get("linkkeys_txt");

        for (JsonValue c : d.get("valid_cases").asArray()) {
            String txt = c.get("txt").asString();
            Dns.LinkKeysRecord record = Dns.parseLinkKeysTxt(txt);
            List<String> expected = c.get("expected_fingerprints").asArray().stream()
                    .map(JsonValue::asString)
                    .toList();
            assertEquals(expected, record.fingerprints(), "txt=" + txt);
        }

        for (JsonValue c : d.get("invalid_cases").asArray()) {
            String txt = c.get("txt").asString();
            DnsParseError err = assertThrows(DnsParseError.class, () -> Dns.parseLinkKeysTxt(txt));
            assertEquals(c.get("expected_error").asString(), errorSymbol(err));
        }

        assertTrue(d.get("no_record_case").get("documentation_only").asBoolean());
    }

    @Test
    void linkkeysApisTxtCases() {
        JsonValue d = Fixtures.load("dns.json").get("linkkeys_apis_txt");

        for (JsonValue c : d.get("valid_cases").asArray()) {
            String txt = c.get("txt").asString();
            Dns.LinkKeysApis apis = Dns.parseLinkKeysApisTxt(txt);
            String expectedTcp = c.get("expected_tcp").isNull() ? null : c.get("expected_tcp").asString();
            String expectedHttps = c.get("expected_https_base").isNull() ? null : c.get("expected_https_base").asString();
            assertEquals(expectedTcp, apis.tcp(), "txt=" + txt);
            assertEquals(expectedHttps, apis.httpsBase(), "txt=" + txt);
        }

        for (JsonValue c : d.get("invalid_cases").asArray()) {
            String txt = c.get("txt").asString();
            DnsParseError err = assertThrows(DnsParseError.class, () -> Dns.parseLinkKeysApisTxt(txt));
            assertEquals(c.get("expected_error").asString(), errorSymbol(err));
        }

        assertEquals(Fixtures.load("dns.json").get("default_tcp_port").asLong(), Dns.DEFAULT_TCP_PORT);
    }
}
