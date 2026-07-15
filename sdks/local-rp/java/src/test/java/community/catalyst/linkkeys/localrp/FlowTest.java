package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.function.UnaryOperator;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.crypto.AeadSuite;
import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.crypto.Hex;
import community.catalyst.linkkeys.localrp.dns.DnsResolver;
import community.catalyst.linkkeys.localrp.rpc.RpcEnvelope;
import community.catalyst.linkkeys.localrp.rpc.Transport;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.Claim;
import community.catalyst.linkkeys.localrp.wire.Types.ClaimSignature;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;
import community.catalyst.linkkeys.localrp.wire.Types.GetDomainKeysResponse;
import community.catalyst.linkkeys.localrp.wire.Types.GetRevocationsResponse;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpCallbackPayload;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpEncryptedCallback;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpTicketRedemptionResponse;
import community.catalyst.linkkeys.localrp.wire.Types.RevocationCertificate;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpCallbackPayload;

/**
 * Flow tests: {@code completeLocalLogin}'s full verification chain, end to
 * end, against a real (but locally spun up, fake-identity) LinkKeys IDP
 * &mdash; DNS-pinned TLS, CSIL-RPC framing, and all. Only two things are
 * faked: the DNS TXT answers ({@link FakeDnsResolver}, so no real
 * network/DNS is touched) and the IDP's identity itself (a throwaway domain
 * signing key generated per test, not a real LinkKeys deployment). A custom
 * {@link Transport} ({@link TestTransport}) is used rather than
 * {@link community.catalyst.linkkeys.localrp.rpc.StdTransport} to demonstrate
 * the seam is genuinely injectable &mdash; the TLS handshake,
 * certificate-pinning, and RPC wire format underneath it are all this SDK's
 * real production code paths ({@code rpc/} package).
 *
 * <p>The fake IDP's TLS certificate is minted with the system {@code openssl}
 * CLI, since JCA on JDK 17 has no certificate-<em>issuing</em> API (only
 * consuming): the fixed test-run domain signing seed is wrapped in a PKCS8
 * PEM (the RFC 8410 Ed25519 prefix + the raw seed, the same trick
 * {@link Crypto}'s class docs describe for key import/export) and handed to
 * {@code openssl req -x509}, so the resulting certificate's SPKI fingerprint
 * is exactly what the domain signing key's fingerprint (and hence the test's
 * DNS answer) says it is.
 *
 * <p>Unlike the Rust/Go/TypeScript reference SDKs' flow tests, this class
 * does not hardcode the specific fixed key seeds from
 * {@code conformance/keys.json}: nothing here compares byte-for-byte against
 * another language's output (the conformance tests already do that
 * exhaustively), so a fresh keypair per test run is simpler and just as
 * effective at exercising the verification chain.
 */
class FlowTest {
    private static final String USER_DOMAIN = "example.test";
    private static final String CALLBACK_URL = "http://localhost/callback";
    private static final String DOMAIN_KEY_ID = "test-domain-key-1";

    // -----------------------------------------------------------------
    // Test doubles
    // -----------------------------------------------------------------

    /** A {@link Transport} the test provides itself, proving the seam is genuinely injectable. */
    static final class TestTransport implements Transport {
        @Override
        public Socket dial(String hostPort) {
            int idx = hostPort.lastIndexOf(':');
            String host = hostPort.substring(0, idx);
            int port = Integer.parseInt(hostPort.substring(idx + 1));
            try {
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(host, port), 5000);
                return socket;
            } catch (IOException e) {
                throw new SdkException(SdkException.Kind.TRANSPORT, e.getMessage(), e);
            }
        }
    }

    /** Canned DNS answers for exactly one domain. */
    static final class FakeDnsResolver implements DnsResolver {
        private final String linkkeysTxt;
        private final String apisTxt;

        FakeDnsResolver(String linkkeysTxt, String apisTxt) {
            this.linkkeysTxt = linkkeysTxt;
            this.apisTxt = apisTxt;
        }

        @Override
        public List<String> txtLookup(String name) {
            if (name.equals("_linkkeys." + USER_DOMAIN)) {
                return List.of(linkkeysTxt);
            }
            if (name.equals("_linkkeys_apis." + USER_DOMAIN)) {
                return List.of(apisTxt);
            }
            throw new SdkException(SdkException.Kind.DNS, "no fake record for " + name);
        }
    }

    // -----------------------------------------------------------------
    // Fake IDP TLS certificate (minted via the system `openssl` CLI)
    // -----------------------------------------------------------------

    private static final byte[] ED25519_PKCS8_PREFIX = Hex.decode("302e020100300506032b657004220420");

    private static String ed25519SeedToPkcs8Pem(byte[] seed) {
        byte[] der = new byte[ED25519_PKCS8_PREFIX.length + seed.length];
        System.arraycopy(ED25519_PKCS8_PREFIX, 0, der, 0, ED25519_PKCS8_PREFIX.length);
        System.arraycopy(seed, 0, der, ED25519_PKCS8_PREFIX.length, seed.length);
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder("-----BEGIN PRIVATE KEY-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END PRIVATE KEY-----\n");
        return sb.toString();
    }

    private static X509Certificate generateDomainTlsCert(String domain, byte[] seed) throws Exception {
        Path dir = Files.createTempDirectory("linkkeys-local-rp-flow-test-");
        Path keyPath = dir.resolve("key.pem");
        Path certPath = dir.resolve("cert.pem");
        Files.writeString(keyPath, ed25519SeedToPkcs8Pem(seed));
        Process proc = new ProcessBuilder(
                        "openssl", "req", "-new", "-x509", "-key", keyPath.toString(), "-days", "3", "-subj",
                        "/CN=" + domain, "-out", certPath.toString())
                .redirectErrorStream(true)
                .start();
        String output = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int exit = proc.waitFor();
        if (exit != 0) {
            throw new IllegalStateException("openssl req failed (exit " + exit + "): " + output);
        }
        try (InputStream in = Files.newInputStream(certPath)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    // -----------------------------------------------------------------
    // Fake IDP: a real TCP+TLS(fp-pinned)+CSIL-RPC server for exactly N requests
    // -----------------------------------------------------------------

    @FunctionalInterface
    interface Dispatch {
        RpcEnvelope.Response apply(String service, String op, byte[] payload);
    }

    private static void sendFrame(OutputStream out, byte[] data) throws IOException {
        int len = data.length;
        out.write(new byte[] {(byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len});
        out.write(data);
        out.flush();
    }

    private static byte[] readFrame(InputStream in) throws IOException {
        byte[] lenBuf = in.readNBytes(4);
        if (lenBuf.length < 4) {
            throw new IOException("connection closed before length prefix arrived");
        }
        int len = ((lenBuf[0] & 0xff) << 24) | ((lenBuf[1] & 0xff) << 16) | ((lenBuf[2] & 0xff) << 8) | (lenBuf[3] & 0xff);
        byte[] body = in.readNBytes(len);
        if (body.length < len) {
            throw new IOException("connection closed before frame body arrived");
        }
        return body;
    }

    /**
     * Spawns a background thread that accepts {@code expectedRequests} TLS
     * connections on a fresh loopback port, presenting a certificate derived
     * from {@code domainSeed}, and answers each with
     * {@code dispatch(service, op, payload)}. Returns the bound address. A
     * connection that never completes its TLS handshake (the "bad pin"
     * test) is swallowed rather than propagated, so it can't hang the test.
     */
    private static String spawnFakeIdp(byte[] domainSeed, int expectedRequests, Dispatch dispatch) throws Exception {
        PrivateKey privateKey = Crypto.importEd25519PrivateKey(domainSeed);
        X509Certificate cert = generateDomainTlsCert(USER_DOMAIN, domainSeed);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("idp", privateKey, "changeit".toCharArray(), new Certificate[] {cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, new SecureRandom());

        SSLServerSocket serverSocket =
                (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        int port = serverSocket.getLocalPort();

        Thread thread = new Thread(
                () -> {
                    for (int i = 0; i < expectedRequests; i++) {
                        try (Socket socket = serverSocket.accept()) {
                            InputStream in = socket.getInputStream();
                            OutputStream out = socket.getOutputStream();
                            byte[] reqBytes = readFrame(in);
                            RpcEnvelope.Response resp;
                            try {
                                RpcEnvelope.Request req = RpcEnvelope.decodeRequest(reqBytes);
                                resp = dispatch.apply(req.service(), req.op(), req.payload());
                            } catch (RuntimeException e) {
                                resp = RpcEnvelope.Response.transportError(
                                        RpcEnvelope.Status.MALFORMED_ENVELOPE, String.valueOf(e.getMessage()));
                            }
                            sendFrame(out, resp.encode());
                        } catch (IOException e) {
                            // A deliberately-bad-pin test aborts the TLS
                            // handshake before ever reaching this handler.
                        }
                    }
                    try {
                        serverSocket.close();
                    } catch (IOException ignored) {
                        // best-effort cleanup only
                    }
                },
                "fake-idp");
        thread.setDaemon(true);
        thread.start();
        return "127.0.0.1:" + port;
    }

    // -----------------------------------------------------------------
    // Scenario construction
    // -----------------------------------------------------------------

    private static Identity.LocalRpKeyMaterial fixedKeyMaterial(Instant now) {
        Identity.GenerateLocalRpIdentityConfig config =
                new Identity.GenerateLocalRpIdentityConfig("Flow Test App", now.minus(Duration.ofDays(1)));
        config.lifetime = Duration.ofDays(3651);
        return Identity.generateLocalRpIdentity(config);
    }

    /** Every knob a failure-case test can turn, applied in this order: build the correct objects, then mutate, then sign/seal/serve. */
    static final class Scenario {
        UnaryOperator<LocalRpCallbackPayload> mutatePayload = p -> p;
        UnaryOperator<DomainPublicKey> mutateDomainKey = k -> k;
        UnaryOperator<Claim> mutateClaim = c -> c;
        UnaryOperator<LocalRpTicketRedemptionResponse> mutateRedemption = r -> r;
        /** {@code null} means "use the default single {@code handle} claim"; non-null replaces the claims list wholesale (may be empty). */
        List<Claim> claimsOverride;
        /** {@code null} means "use {@code Begin}'s defaults" ({@code ["handle"]}). */
        List<String> requiredClaimsOverride;
        /** Additional domain keys served alongside the callback-signing key (e.g. revocation-quorum siblings). */
        List<DomainPublicKey> extraDomainKeys = List.of();
        /** Revocation certificates the fake IDP's {@code get-revocations} route returns. */
        List<RevocationCertificate> revocations = List.of();
        /** When true, {@code get-revocations} answers with a transport error instead of a response. */
        boolean dropRevocationsResponse = false;
        String dnsFingerprintOverride;
        // get-domain-keys + get-revocations (FIX B: always fetched) + redeem-claim-ticket.
        int expectedRequests = 3;
    }

    private static Complete.VerifiedLocalLogin runScenario(Scenario scenario) throws Exception {
        Instant now = Instant.now();
        Identity.LocalRpKeyMaterial keyMaterial = fixedKeyMaterial(now);

        Begin.BeginLocalLoginConfig beginConfig =
                new Begin.BeginLocalLoginConfig(keyMaterial, CALLBACK_URL, USER_DOMAIN, now);
        beginConfig.requiredClaims = scenario.requiredClaimsOverride;
        Begin.BeginResult begun = Begin.beginLocalLogin(beginConfig);
        Begin.PendingLogin pending = begun.pending();

        Crypto.Ed25519KeyPair domainSigning = Crypto.generateEd25519KeyPair();
        DomainPublicKey domainKey = new DomainPublicKey(
                DOMAIN_KEY_ID,
                domainSigning.publicKey(),
                Crypto.fingerprint(domainSigning.publicKey()),
                "ed25519",
                "sign",
                Rfc3339.format(now.minus(Duration.ofDays(30))),
                Rfc3339.format(now.plus(Duration.ofDays(365))),
                null,
                null,
                null);
        domainKey = scenario.mutateDomainKey.apply(domainKey);

        byte[] claimTicket = new byte[32];
        Arrays.fill(claimTicket, (byte) 7);
        LocalRpCallbackPayload payload = LocalRp.buildLocalRpCallbackPayload(
                "user-1",
                USER_DOMAIN,
                claimTicket,
                keyMaterial.fingerprint(),
                CALLBACK_URL,
                pending.nonce(),
                pending.state(),
                Rfc3339.format(now),
                Rfc3339.format(now.plus(Duration.ofMinutes(5))));
        payload = scenario.mutatePayload.apply(payload);

        SignedLocalRpCallbackPayload signedPayload =
                LocalRp.signLocalRpCallbackPayload(payload, DOMAIN_KEY_ID, domainSigning.privateKeySeed());

        LocalRpEncryptedCallback encrypted = LocalRp.sealLocalRpCallback(
                signedPayload,
                AeadSuite.AES_256_GCM,
                keyMaterial.encryptionPublicKey(),
                payload.audienceFingerprint(),
                payload.nonce(),
                payload.state(),
                payload.issuedAt(),
                payload.expiresAt());
        String encryptedToken = Encoding.localRpEncryptedCallbackToUrlParam(encrypted);
        String arrivedUrl = CALLBACK_URL + "?encrypted_token=" + encryptedToken;

        Claims.ClaimSpec claimSpec = new Claims.ClaimSpec(
                "claim-1", "handle", "flowtestuser".getBytes(StandardCharsets.UTF_8), "user-1", USER_DOMAIN, null,
                Rfc3339.format(now));
        Claim claim = Claims.signClaim(
                claimSpec, List.of(new Claims.ClaimSigner(USER_DOMAIN, DOMAIN_KEY_ID, domainSigning.privateKeySeed())));
        claim = scenario.mutateClaim.apply(claim);
        List<Claim> claims = scenario.claimsOverride != null ? scenario.claimsOverride : List.of(claim);

        LocalRpTicketRedemptionResponse redemptionResponse = new LocalRpTicketRedemptionResponse(
                "user-1", USER_DOMAIN, claims, Rfc3339.format(now.plus(Duration.ofHours(1))));
        redemptionResponse = scenario.mutateRedemption.apply(redemptionResponse);

        DomainPublicKey domainKeyForWire = domainKey;
        LocalRpTicketRedemptionResponse finalRedemptionResponse = redemptionResponse;
        List<DomainPublicKey> servedDomainKeys = new ArrayList<>();
        servedDomainKeys.add(domainKeyForWire);
        servedDomainKeys.addAll(scenario.extraDomainKeys);
        String addr = spawnFakeIdp(domainSigning.privateKeySeed(), scenario.expectedRequests, (service, op, reqPayload) -> {
            String route = service + "/" + op;
            if (route.equals("DomainKeys/get-domain-keys")) {
                GetDomainKeysResponse resp = new GetDomainKeysResponse(USER_DOMAIN, servedDomainKeys, null);
                return RpcEnvelope.Response.ok("GetDomainKeysResponse", Codec.encodeGetDomainKeysResponse(resp));
            }
            if (route.equals("DomainKeys/get-revocations")) {
                if (scenario.dropRevocationsResponse) {
                    return RpcEnvelope.Response.transportError(
                            RpcEnvelope.Status.INTERNAL, "fake IDP deliberately fails get-revocations");
                }
                GetRevocationsResponse resp = new GetRevocationsResponse(scenario.revocations);
                return RpcEnvelope.Response.ok("GetRevocationsResponse", Codec.encodeGetRevocationsResponse(resp));
            }
            if (route.equals("LocalRp/redeem-claim-ticket")) {
                return RpcEnvelope.Response.ok(
                        "LocalRpTicketRedemptionResponse",
                        Codec.encodeLocalRpTicketRedemptionResponse(finalRedemptionResponse));
            }
            return RpcEnvelope.Response.transportError(
                    RpcEnvelope.Status.UNKNOWN_SERVICE_OR_OP, "fake IDP has no handler for " + route);
        });

        String realFingerprint = Crypto.fingerprint(domainSigning.publicKey());
        String pinnedFingerprint = scenario.dnsFingerprintOverride != null ? scenario.dnsFingerprintOverride : realFingerprint;
        StringBuilder linkkeysTxt = new StringBuilder("v=lk1 fp=").append(pinnedFingerprint);
        // Extra domain keys (e.g. revocation-quorum siblings) must also be
        // DNS-pinned directly -- signing keys are only ever trusted when
        // their own fingerprint is in the pinned set (Dns.trustKeys).
        for (DomainPublicKey extra : scenario.extraDomainKeys) {
            linkkeysTxt.append(" fp=").append(extra.fingerprint());
        }
        DnsResolver dns = new FakeDnsResolver(linkkeysTxt.toString(), "v=lk1 tcp=" + addr);
        Transport transport = new TestTransport();

        Complete.CompleteLocalLoginConfig config =
                new Complete.CompleteLocalLoginConfig(keyMaterial, pending, encryptedToken, arrivedUrl, now);
        config.transport = transport;
        config.dns = dns;
        return Complete.completeLocalLogin(config);
    }

    // -----------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------

    @Test
    void happyPathReturnsVerifiedLogin() throws Exception {
        Complete.VerifiedLocalLogin result = runScenario(new Scenario());
        assertEquals("user-1", result.userId());
        assertEquals(USER_DOMAIN, result.userDomain());
        assertEquals(1, result.claims().size());
        assertEquals("handle", result.claims().get(0).claimType());
        assertEquals(64, result.localRpFingerprint().length());
        assertEquals(1, result.domainPublicKeys().size());
    }

    @Test
    void wrongAudienceFingerprintIsRejected() throws Exception {
        Scenario s = new Scenario();
        s.mutatePayload = p -> new LocalRpCallbackPayload(
                p.userId(), p.userDomain(), p.claimTicket(), "b".repeat(64), p.callbackUrl(), p.nonce(), p.state(),
                p.issuedAt(), p.expiresAt());
        // get-domain-keys + get-revocations only -- fails before redemption is ever attempted.
        s.expectedRequests = 2;
        assertThrows(LocalRpError.class, () -> runScenario(s));
    }

    @Test
    void wrongIssuerDomainIsRejected() throws Exception {
        Scenario s = new Scenario();
        s.mutatePayload = p -> new LocalRpCallbackPayload(
                p.userId(), "attacker.test", p.claimTicket(), p.audienceFingerprint(), p.callbackUrl(), p.nonce(),
                p.state(), p.issuedAt(), p.expiresAt());
        s.expectedRequests = 2;
        assertThrows(LocalRpError.class, () -> runScenario(s));
    }

    @Test
    void nonceMismatchIsRejected() throws Exception {
        Scenario s = new Scenario();
        byte[] wrongNonce = new byte[32];
        Arrays.fill(wrongNonce, (byte) 0xEE);
        s.mutatePayload = p -> new LocalRpCallbackPayload(
                p.userId(), p.userDomain(), p.claimTicket(), p.audienceFingerprint(), p.callbackUrl(), wrongNonce,
                p.state(), p.issuedAt(), p.expiresAt());
        s.expectedRequests = 2;
        assertThrows(LocalRpError.class, () -> runScenario(s));
    }

    @Test
    void expiredCallbackPayloadIsRejected() throws Exception {
        Scenario s = new Scenario();
        s.mutatePayload = p -> {
            Instant n = Instant.now();
            return new LocalRpCallbackPayload(
                    p.userId(), p.userDomain(), p.claimTicket(), p.audienceFingerprint(), p.callbackUrl(), p.nonce(),
                    p.state(), Rfc3339.format(n.minus(Duration.ofHours(2))), Rfc3339.format(n.minus(Duration.ofHours(1))));
        };
        s.expectedRequests = 2;
        assertThrows(LocalRpError.class, () -> runScenario(s));
    }

    @Test
    void dnsFingerprintPinMismatchIsRejected() throws Exception {
        Scenario s = new Scenario();
        s.dnsFingerprintOverride = "c".repeat(64);
        s.expectedRequests = 1;
        // Fails during the TLS handshake's mandatory post-handshake pin
        // check (the fake IDP's real cert fingerprint no longer matches the
        // pinned set) -- either way it must never reach a verified result.
        assertThrows(RuntimeException.class, () -> runScenario(s));
    }

    @Test
    void revokedSigningKeyIsRejected() throws Exception {
        Scenario s = new Scenario();
        s.mutateDomainKey = k -> new DomainPublicKey(
                k.keyId(), k.publicKey(), k.fingerprint(), k.algorithm(), k.keyUsage(), k.createdAt(), k.expiresAt(),
                Rfc3339.format(Instant.now()), k.signedByKeyId(), k.keySignature());
        s.expectedRequests = 2;
        assertThrows(LocalRpError.class, () -> runScenario(s));
    }

    @Test
    void tamperedClaimSignatureIsRejected() throws Exception {
        Scenario s = new Scenario();
        s.mutateClaim = c -> {
            var sigs = new ArrayList<>(c.signatures());
            if (!sigs.isEmpty()) {
                var sig = sigs.get(0);
                byte[] flipped = sig.signature().clone();
                flipped[0] ^= (byte) 0xff;
                sigs.set(0, new ClaimSignature(sig.domain(), sig.signedByKeyId(), flipped));
            }
            return new Claim(
                    c.claimId(), c.userId(), c.claimType(), c.claimValue(), sigs, c.attestedAt(), c.createdAt(),
                    c.expiresAt(), c.revokedAt());
        };
        assertThrows(ClaimError.class, () -> runScenario(s));
    }

    // -----------------------------------------------------------------
    // Hostile-IDP tests (security review fixes: identity binding,
    // required-claims enforcement, fail-closed revocation fetching).
    // -----------------------------------------------------------------

    @Test
    void redemptionIdentityMismatchWithSignedPayloadIsRejected() throws Exception {
        Scenario s = new Scenario();
        // The domain-signed callback payload vouches for "user-1", but the
        // (unsigned) redemption response claims a different user entirely --
        // a compromised/malicious IDP trying to swap in another identity
        // after the ticket was already redeemed for the real one.
        s.mutateRedemption = r -> new LocalRpTicketRedemptionResponse(
                "attacker-user", r.userDomain(), r.claims(), r.ticketExpiresAt());
        LocalRpError e = assertThrows(LocalRpError.class, () -> runScenario(s));
        assertEquals(LocalRpError.Kind.REDEMPTION_IDENTITY_MISMATCH, e.kind());
    }

    @Test
    void redemptionDomainMismatchWithSignedPayloadIsRejected() throws Exception {
        Scenario s = new Scenario();
        s.mutateRedemption = r -> new LocalRpTicketRedemptionResponse(
                r.userId(), "attacker.test", r.claims(), r.ticketExpiresAt());
        LocalRpError e = assertThrows(LocalRpError.class, () -> runScenario(s));
        assertEquals(LocalRpError.Kind.REDEMPTION_IDENTITY_MISMATCH, e.kind());
    }

    @Test
    void claimUserIdMismatchWithSignedPayloadIsRejected() throws Exception {
        Scenario s = new Scenario();
        // The claim is validly signed, but for a DIFFERENT subject than the
        // user the domain-signed payload vouches for -- must never be
        // attributed to this login even though its signature verifies.
        s.mutateClaim = c -> new Claim(
                c.claimId(), "attacker-user", c.claimType(), c.claimValue(), c.signatures(), c.attestedAt(),
                c.createdAt(), c.expiresAt(), c.revokedAt());
        LocalRpError e = assertThrows(LocalRpError.class, () -> runScenario(s));
        assertEquals(LocalRpError.Kind.CLAIM_IDENTITY_MISMATCH, e.kind());
    }

    @Test
    void emptyClaimsWithNonEmptyRequiredClaimsIsRejected() throws Exception {
        Scenario s = new Scenario();
        // The IDP redeems the ticket successfully but returns NO claims at
        // all, even though the pending login required "handle".
        s.claimsOverride = List.of();
        LocalRpError e = assertThrows(LocalRpError.class, () -> runScenario(s));
        assertEquals(LocalRpError.Kind.REQUIRED_CLAIMS_NOT_SATISFIED, e.kind());
    }

    @Test
    void insufficientClaimsMissingARequiredTypeIsRejected() throws Exception {
        Scenario s = new Scenario();
        // Two claim types are required, but the IDP only ever attests one.
        s.requiredClaimsOverride = List.of("handle", "email");
        LocalRpError e = assertThrows(LocalRpError.class, () -> runScenario(s));
        assertEquals(LocalRpError.Kind.REQUIRED_CLAIMS_NOT_SATISFIED, e.kind());
    }

    @Test
    void getRevocationsErrorFailsClosed() throws Exception {
        Scenario s = new Scenario();
        s.dropRevocationsResponse = true;
        // get-domain-keys succeeds, get-revocations errors -- the login
        // must never proceed to redemption on a "best effort" basis.
        s.expectedRequests = 2;
        SdkException e = assertThrows(SdkException.class, () -> runScenario(s));
        assertEquals(SdkException.Kind.REVOCATION_UNAVAILABLE, e.kind());
    }

    @Test
    void certificateRevokedSigningKeyIsRejected() throws Exception {
        Instant now = Instant.now();
        Crypto.Ed25519KeyPair sibling1 = Crypto.generateEd25519KeyPair();
        Crypto.Ed25519KeyPair sibling2 = Crypto.generateEd25519KeyPair();
        String sibling1KeyId = "sibling-key-1";
        String sibling2KeyId = "sibling-key-2";
        DomainPublicKey sibling1Key = new DomainPublicKey(
                sibling1KeyId, sibling1.publicKey(), Crypto.fingerprint(sibling1.publicKey()), "ed25519", "sign",
                Rfc3339.format(now.minus(Duration.ofDays(30))), Rfc3339.format(now.plus(Duration.ofDays(365))), null,
                null, null);
        DomainPublicKey sibling2Key = new DomainPublicKey(
                sibling2KeyId, sibling2.publicKey(), Crypto.fingerprint(sibling2.publicKey()), "ed25519", "sign",
                Rfc3339.format(now.minus(Duration.ofDays(30))), Rfc3339.format(now.plus(Duration.ofDays(365))), null,
                null, null);

        Scenario s = new Scenario();
        // Two sibling signing keys, both DNS-pinned alongside the real
        // callback-signing key (needed to satisfy Revocation.QUORUM = 2).
        s.extraDomainKeys = List.of(sibling1Key, sibling2Key);
        // mutateDomainKey runs (inside runScenario) right after the real
        // callback-signing key is built -- it's the only place we learn
        // that key's actual key id/fingerprint, so build the quorum-verified
        // revocation certificate targeting it here and stash it directly
        // onto `s.revocations`, which the fake IDP's get-revocations route
        // reads lazily (after this mutator has already run).
        s.mutateDomainKey = k -> {
            String revokedAt = Rfc3339.format(now);
            byte[] payload = Revocation.revocationPayload(k.keyId(), k.fingerprint(), revokedAt, USER_DOMAIN);
            byte[] sig1 = Crypto.signEd25519(payload, sibling1.privateKeySeed());
            byte[] sig2 = Crypto.signEd25519(payload, sibling2.privateKeySeed());
            s.revocations = List.of(new RevocationCertificate(
                    k.keyId(), k.fingerprint(), revokedAt,
                    List.of(
                            new ClaimSignature(USER_DOMAIN, sibling1KeyId, sig1),
                            new ClaimSignature(USER_DOMAIN, sibling2KeyId, sig2))));
            return k;
        };
        // Fails at envelope verification (the signing key was just revoked
        // out of the trusted set) -- redemption is never attempted.
        s.expectedRequests = 2;
        LocalRpError e = assertThrows(LocalRpError.class, () -> runScenario(s));
        assertEquals(LocalRpError.Kind.KEY_NOT_FOUND, e.kind());
    }
}
