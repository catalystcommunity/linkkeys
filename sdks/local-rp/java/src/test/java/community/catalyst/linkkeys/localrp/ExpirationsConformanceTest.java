package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.testutil.Fixtures;
import community.catalyst.linkkeys.localrp.testutil.MiniJson.JsonValue;

/** Conformance vectors: {@code expirations.json}. */
class ExpirationsConformanceTest {

    @Test
    void checkExpirationsThresholdsViaSdkWrapper() {
        JsonValue d = Fixtures.load("expirations.json").get("check_expirations");
        String expiresAt = d.get("expires_at").asString();
        List<JsonValue> cases = d.get("cases").asArray();
        assertEquals(11, cases.size());

        // Build an identity whose descriptor expires at exactly `expiresAt`,
        // exercising `LinkKeysLocalRp.checkExpirations` end to end (identity
        // -> descriptor -> threshold logic), not the underlying LocalRp
        // function directly.
        Instant expires = OffsetDateTime.parse(expiresAt).toInstant();
        Instant createdAt = expires.minus(Duration.ofDays(3650));
        Identity.GenerateLocalRpIdentityConfig config =
                new Identity.GenerateLocalRpIdentityConfig("Conformance Test App", createdAt);
        config.lifetime = Duration.between(createdAt, expires);
        Identity.LocalRpKeyMaterial identity = Identity.generateLocalRpIdentity(config);

        for (JsonValue c : cases) {
            Instant now = OffsetDateTime.parse(c.get("now").asString()).toInstant();
            LocalRp.ExpirationStatus status = LinkKeysLocalRp.checkExpirations(identity, now);
            assertEquals(c.get("expected_level").asString(), status.level().wireName(), "now=" + now);
        }
    }

    @Test
    void checkTimestampsSkewBoundariesAreExact() {
        JsonValue d = Fixtures.load("expirations.json").get("check_timestamps");
        String issuedAt = d.get("issued_at").asString();
        String expiresAt = d.get("expires_at").asString();
        long skew = d.get("skew_seconds").asLong();
        List<JsonValue> cases = d.get("cases").asArray();
        assertEquals(4, cases.size());

        for (JsonValue c : cases) {
            Instant now = OffsetDateTime.parse(c.get("now").asString()).toInstant();
            boolean expectedValid = c.get("expected_valid").asBoolean();
            boolean valid;
            try {
                LocalRp.checkTimestamps(issuedAt, expiresAt, now, skew);
                valid = true;
            } catch (LocalRpError e) {
                valid = false;
            }
            assertEquals(expectedValid, valid, "now=" + now);
        }
    }
}
