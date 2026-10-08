package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class Rfc3339Test {
    @Test
    void aWholeMinuteKeepsItsSeconds() {
        assertEquals("2026-10-06T12:05:00Z", Rfc3339.format(Instant.parse("2026-10-06T12:05:00Z")));
    }

    @Test
    void fractionsAreKeptAndRoundTrip() {
        Instant t = Instant.parse("2026-10-06T12:05:07.250Z");
        assertEquals("2026-10-06T12:05:07.250Z", Rfc3339.format(t));
        assertEquals(t, Rfc3339.parse("t", Rfc3339.format(t)));
    }
}
