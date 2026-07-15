package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;

import org.junit.jupiter.api.Test;

/** Unit tests for {@link Begin} (mirrors the Rust/Go SDKs' own {@code begin} module tests). */
class BeginTest {

    private static Identity.LocalRpKeyMaterial material() {
        return Identity.generateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("Test App", Instant.now()));
    }

    @Test
    void beginDefaultsClaimsAndProducesPendingState() {
        Identity.LocalRpKeyMaterial m = material();
        Begin.BeginResult result = Begin.beginLocalLogin(
                new Begin.BeginLocalLoginConfig(m, "http://localhost:8080/callback", "example.com", Instant.now()));

        assertTrue(result.redirect().redirectUrl().startsWith("https://example.com/auth/local-rp?signed_request="));
        assertEquals("example.com", result.pending().userDomain());
        assertEquals("http://localhost:8080/callback", result.pending().callbackUrl());
        assertEquals(32, result.pending().nonce().length);
        assertEquals(32, result.pending().state().length);
    }

    @Test
    void beginRejectsNonHttpCallbackScheme() {
        Identity.LocalRpKeyMaterial m = material();
        assertThrows(
                SdkException.class,
                () -> Begin.beginLocalLogin(
                        new Begin.BeginLocalLoginConfig(m, "myapp://callback", "example.com", Instant.now())));
    }

    @Test
    void beginRejectsEmptyUserDomain() {
        Identity.LocalRpKeyMaterial m = material();
        assertThrows(
                SdkException.class,
                () -> Begin.beginLocalLogin(
                        new Begin.BeginLocalLoginConfig(m, "http://localhost/callback", "", Instant.now())));
    }

    @Test
    void beginDefaultsRequiredClaimsOnPendingLogin() {
        Identity.LocalRpKeyMaterial m = material();
        Begin.BeginResult result = Begin.beginLocalLogin(
                new Begin.BeginLocalLoginConfig(m, "http://localhost:8080/callback", "example.com", Instant.now()));
        assertEquals(Begin.DEFAULT_REQUIRED_CLAIMS, result.pending().requiredClaims());
    }

    @Test
    void pendingLoginRoundTripsThroughItsByteSerializeForm() {
        Identity.LocalRpKeyMaterial m = material();
        Begin.BeginLocalLoginConfig config =
                new Begin.BeginLocalLoginConfig(m, "http://localhost:8080/callback", "example.com", Instant.now());
        config.requiredClaims = java.util.List.of("handle", "email");
        Begin.PendingLogin pending = Begin.beginLocalLogin(config).pending();

        Begin.PendingLogin roundTripped = Begin.PendingLogin.fromBytes(pending.toBytes());

        // Records compare array components by reference, not content, so
        // nonce/state need an explicit content comparison.
        assertTrue(java.util.Arrays.equals(pending.nonce(), roundTripped.nonce()));
        assertTrue(java.util.Arrays.equals(pending.state(), roundTripped.state()));
        assertEquals(pending.userDomain(), roundTripped.userDomain());
        assertEquals(pending.callbackUrl(), roundTripped.callbackUrl());
        assertEquals(java.util.List.of("handle", "email"), roundTripped.requiredClaims());
    }

    @Test
    void beginTwoCallsNeverReuseNonceOrState() {
        Identity.LocalRpKeyMaterial m = material();
        Begin.BeginResult r1 = Begin.beginLocalLogin(
                new Begin.BeginLocalLoginConfig(m, "http://localhost/callback", "example.com", Instant.now()));
        Begin.BeginResult r2 = Begin.beginLocalLogin(
                new Begin.BeginLocalLoginConfig(m, "http://localhost/callback", "example.com", Instant.now()));
        assertNotEquals(
                java.util.Arrays.toString(r1.pending().nonce()), java.util.Arrays.toString(r2.pending().nonce()));
        assertNotEquals(
                java.util.Arrays.toString(r1.pending().state()), java.util.Arrays.toString(r2.pending().state()));
    }
}
