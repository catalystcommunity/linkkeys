package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.dns.DnsResolver;

/**
 * Unit tests for {@link Begin} (mirrors the Rust/Go SDKs' own {@code begin}
 * module tests). Every config here injects {@link #NO_DNS}, a resolver that
 * fails every lookup, so begin takes its documented fallback
 * ({@code https://<identity domain>}) and no test performs a live DNS
 * request. Discovery itself is covered by {@link BrowserTest}.
 */
class BeginTest {

    private static final DnsResolver NO_DNS = name -> {
        throw new SdkException(SdkException.Kind.DNS, "no DNS in unit tests: " + name);
    };

    private static Identity.LocalRpKeyMaterial material() {
        return Identity.generateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("Test App", Instant.now()));
    }

    private static Begin.BeginLocalLoginConfig config(Identity.LocalRpKeyMaterial m, String callbackUrl, String userDomain) {
        Begin.BeginLocalLoginConfig config = new Begin.BeginLocalLoginConfig(m, callbackUrl, userDomain, Instant.now());
        config.dns = NO_DNS;
        return config;
    }

    @Test
    void beginDefaultsClaimsAndProducesPendingState() {
        Identity.LocalRpKeyMaterial m = material();
        Begin.BeginResult result = Begin.beginLocalLogin(
                config(m, "http://localhost:8080/callback", "example.com"));

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
                        config(m, "myapp://callback", "example.com")));
    }

    @Test
    void beginParsesIdentityInput() {
        Identity.LocalRpKeyMaterial m = material();
        Begin.BeginResult result = Begin.beginLocalLogin(
                config(m, "http://localhost/callback", "Alice+work@ID.Example.TEST"));
        assertTrue(result.redirect().redirectUrl().endsWith("&username=Alice%2Bwork"));
        assertEquals("id.example.test", result.pending().userDomain());
        for (String input : List.of("alice", "alice@@example.test", "https://example.test")) {
            assertThrows(SdkException.class, () -> Begin.beginLocalLogin(
                    config(m, "http://localhost/callback", input)));
        }
    }

    @Test
    void beginRejectsEmptyUserDomain() {
        Identity.LocalRpKeyMaterial m = material();
        assertThrows(
                SdkException.class,
                () -> Begin.beginLocalLogin(
                        config(m, "http://localhost/callback", "")));
    }

    @Test
    void beginDefaultsRequiredClaimsOnPendingLogin() {
        Identity.LocalRpKeyMaterial m = material();
        Begin.BeginResult result = Begin.beginLocalLogin(
                config(m, "http://localhost:8080/callback", "example.com"));
        assertEquals(Begin.DEFAULT_REQUIRED_CLAIMS, result.pending().requiredClaims());
    }

    @Test
    void pendingLoginRoundTripsThroughItsByteSerializeForm() {
        Identity.LocalRpKeyMaterial m = material();
        Begin.BeginLocalLoginConfig config =
                config(m, "http://localhost:8080/callback", "example.com");
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
                config(m, "http://localhost/callback", "example.com"));
        Begin.BeginResult r2 = Begin.beginLocalLogin(
                config(m, "http://localhost/callback", "example.com"));
        assertNotEquals(
                java.util.Arrays.toString(r1.pending().nonce()), java.util.Arrays.toString(r2.pending().nonce()));
        assertNotEquals(
                java.util.Arrays.toString(r1.pending().state()), java.util.Arrays.toString(r2.pending().state()));
    }
}
