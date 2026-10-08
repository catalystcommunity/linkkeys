package community.catalyst.linkkeys.localrp;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;

/**
 * RFC3339 timestamp parse/format helpers. Parsing accepts both the {@code Z}
 * and {@code +00:00} UTC-offset spellings (conformance vectors use the
 * latter; this SDK's own output uses the former) &mdash; both are valid
 * RFC3339 and {@link OffsetDateTime}'s ISO offset parser accepts either.
 */
final class Rfc3339 {
    private Rfc3339() {}

    static Instant parse(String field, String s) {
        try {
            return OffsetDateTime.parse(s).toInstant();
        } catch (DateTimeParseException e) {
            throw new LocalRpError(LocalRpError.Kind.BAD_TIMESTAMP, field + ": " + e.getMessage());
        }
    }

    /**
     * Always writes the seconds. {@code OffsetDateTime.toString()} drops them
     * when seconds and nanoseconds are both zero ({@code ...T12:05Z}), which
     * is not valid RFC3339 and which the server refuses.
     */
    static String format(Instant instant) {
        return java.time.format.DateTimeFormatter.ISO_INSTANT.format(instant);
    }
}
