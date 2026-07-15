package community.catalyst.linkkeys.localrp.kt

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.Claims as JClaims
import community.catalyst.linkkeys.localrp.Encoding as JEncoding
import community.catalyst.linkkeys.localrp.LocalRp as JLocalRp
import community.catalyst.linkkeys.localrp.crypto.AeadSuite as JAeadSuite
import community.catalyst.linkkeys.localrp.crypto.Crypto as JCrypto
import community.catalyst.linkkeys.localrp.crypto.Hex as JHex
import community.catalyst.linkkeys.localrp.rpc.RpcEnvelope as JRpcEnvelope
import community.catalyst.linkkeys.localrp.wire.Cbor as JCbor
import community.catalyst.linkkeys.localrp.wire.Codec as JCodec
import community.catalyst.linkkeys.localrp.wire.Types as JTypes

/**
 * Flow tests: [completeLocalLogin]'s full verification chain, end to end,
 * against a real (but locally spun up, fake-identity) LinkKeys IDP -- DNS-pinned
 * TLS, CSIL-RPC framing, and all. Only two things are faked: the DNS TXT
 * answers ([FakeDnsResolver], so no real network/DNS is touched) and the
 * IDP's identity itself (a throwaway domain signing key generated per test,
 * not a real LinkKeys deployment).
 *
 * The system under test throughout is this package's own [beginLocalLogin]
 * and [completeLocalLogin] -- the "fake IDP" side necessarily speaks the
 * underlying dependency's wire types directly (`community.catalyst.linkkeys.localrp.*`,
 * the Java SDK this project wraps -- see README's "Architecture decision"),
 * since playing the IDP means constructing exactly the bytes a real IDP would
 * send, which by definition sits below this package's own client-side API
 * surface. This mirrors the Java sibling's own `FlowTest`.
 */
class FlowTest {
    companion object {
        private const val USER_DOMAIN = "example.test"
        private const val CALLBACK_URL = "http://localhost/callback"
        private const val DOMAIN_KEY_ID = "test-domain-key-1"
    }

    // -----------------------------------------------------------------
    // Test doubles
    // -----------------------------------------------------------------

    /** A [Transport] the test provides itself, proving the seam is genuinely injectable. */
    private class TestTransport : Transport {
        override fun dial(hostPort: String): Socket {
            val idx = hostPort.lastIndexOf(':')
            val host = hostPort.substring(0, idx)
            val port = hostPort.substring(idx + 1).toInt()
            return try {
                val socket = Socket()
                socket.connect(InetSocketAddress(host, port), 5000)
                socket
            } catch (e: IOException) {
                throw LocalRpException.Network(NetworkErrorKind.TRANSPORT, e.message ?: "transport failed", e)
            }
        }
    }

    /** Canned DNS answers for exactly one domain. */
    private class FakeDnsResolver(private val linkkeysTxt: String, private val apisTxt: String) : DnsResolver {
        override fun txtLookup(name: String): List<String> = when (name) {
            "_linkkeys.$USER_DOMAIN" -> listOf(linkkeysTxt)
            "_linkkeys_apis.$USER_DOMAIN" -> listOf(apisTxt)
            else -> throw LocalRpException.Dns(DnsErrorKind.NO_LINKKEYS_RECORD, "no fake record for $name")
        }
    }

    // -----------------------------------------------------------------
    // Fake IDP TLS certificate (minted via the system `openssl` CLI -- JCA
    // on JDK 17 has no certificate-issuing API, only consuming)
    // -----------------------------------------------------------------

    private fun ed25519SeedToPkcs8Pem(seed: ByteArray): String {
        val prefix = JHex.decode("302e020100300506032b657004220420")
        val der = prefix + seed
        val b64 = Base64.getEncoder().encodeToString(der)
        val sb = StringBuilder("-----BEGIN PRIVATE KEY-----\n")
        var i = 0
        while (i < b64.length) {
            sb.append(b64, i, minOf(i + 64, b64.length)).append('\n')
            i += 64
        }
        sb.append("-----END PRIVATE KEY-----\n")
        return sb.toString()
    }

    private fun generateDomainTlsCert(domain: String, seed: ByteArray): X509Certificate {
        val dir = Files.createTempDirectory("linkkeys-local-rp-kt-flow-test-")
        val keyPath = dir.resolve("key.pem")
        val certPath = dir.resolve("cert.pem")
        Files.writeString(keyPath, ed25519SeedToPkcs8Pem(seed))
        val proc = ProcessBuilder(
            "openssl", "req", "-new", "-x509", "-key", keyPath.toString(), "-days", "3", "-subj",
            "/CN=$domain", "-out", certPath.toString(),
        ).redirectErrorStream(true).start()
        val output = String(proc.inputStream.readAllBytes(), StandardCharsets.UTF_8)
        val exit = proc.waitFor()
        check(exit == 0) { "openssl req failed (exit $exit): $output" }
        return Files.newInputStream(certPath).use { CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate }
    }

    // -----------------------------------------------------------------
    // Fake IDP: a real TCP+TLS(fp-pinned)+CSIL-RPC server for exactly N requests
    // -----------------------------------------------------------------

    private fun sendFrame(out: OutputStream, data: ByteArray) {
        val len = data.size
        out.write(byteArrayOf((len ushr 24).toByte(), (len ushr 16).toByte(), (len ushr 8).toByte(), len.toByte()))
        out.write(data)
        out.flush()
    }

    private fun readFrame(inp: InputStream): ByteArray {
        val lenBuf = inp.readNBytes(4)
        check(lenBuf.size == 4) { "connection closed before length prefix arrived" }
        val len = ((lenBuf[0].toInt() and 0xff) shl 24) or ((lenBuf[1].toInt() and 0xff) shl 16) or
            ((lenBuf[2].toInt() and 0xff) shl 8) or (lenBuf[3].toInt() and 0xff)
        val body = inp.readNBytes(len)
        check(body.size == len) { "connection closed before frame body arrived" }
        return body
    }

    /**
     * Spawns a background thread that accepts [expectedRequests] TLS
     * connections on a fresh loopback port, presenting a certificate derived
     * from [domainSeed], and answers each with `dispatch(service, op, payload)`.
     * Returns the bound address.
     */
    private fun spawnFakeIdp(domainSeed: ByteArray, expectedRequests: Int, dispatch: (String, String, ByteArray) -> JRpcEnvelope.Response): String {
        val privateKey: PrivateKey = JCrypto.importEd25519PrivateKey(domainSeed)
        val cert = generateDomainTlsCert(USER_DOMAIN, domainSeed)

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("idp", privateKey, "changeit".toCharArray(), arrayOf<Certificate>(cert))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, "changeit".toCharArray())
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, SecureRandom())

        val serverSocket = ctx.serverSocketFactory.createServerSocket(0, 50, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        val port = serverSocket.localPort

        val thread = Thread({
            for (i in 0 until expectedRequests) {
                try {
                    serverSocket.accept().use { socket ->
                        val inp = socket.getInputStream()
                        val out = socket.getOutputStream()
                        val reqBytes = readFrame(inp)
                        val resp = try {
                            val req = JRpcEnvelope.decodeRequest(reqBytes)
                            dispatch(req.service(), req.op(), req.payload())
                        } catch (e: RuntimeException) {
                            JRpcEnvelope.Response.transportError(JRpcEnvelope.Status.MALFORMED_ENVELOPE, e.message.toString())
                        }
                        sendFrame(out, resp.encode())
                    }
                } catch (e: IOException) {
                    // A deliberately-bad-pin test aborts the TLS handshake before ever reaching this handler.
                }
            }
            try {
                serverSocket.close()
            } catch (ignored: IOException) {
                // best-effort cleanup only
            }
        }, "fake-idp")
        thread.isDaemon = true
        thread.start()
        return "127.0.0.1:$port"
    }

    // -----------------------------------------------------------------
    // Scenario construction
    // -----------------------------------------------------------------

    private fun rfc3339(instant: Instant): String = instant.atOffset(ZoneOffset.UTC).toString()

    private fun fixedIdentity(now: Instant): LocalRpIdentity =
        generateLocalRpIdentity(appName = "Flow Test App", now = now.minus(Duration.ofDays(1)), lifetime = Duration.ofDays(3651))

    /** Every knob a failure-case test can turn, applied in this order: build the correct objects, then mutate, then sign/seal/serve. */
    private class Scenario {
        var mutatePayload: (JTypes.LocalRpCallbackPayload) -> JTypes.LocalRpCallbackPayload = { it }
        var mutateDomainKey: (JTypes.DomainPublicKey) -> JTypes.DomainPublicKey = { it }
        var mutateClaim: (JTypes.Claim) -> JTypes.Claim = { it }
        var mutateRedemption: (JTypes.LocalRpTicketRedemptionResponse) -> JTypes.LocalRpTicketRedemptionResponse = { it }
        /** `null` means "use the default single `handle` claim"; non-null replaces the claims list wholesale (may be empty). */
        var claimsOverride: List<JTypes.Claim>? = null
        /** `null` means "use [beginLocalLogin]'s defaults" (`["handle"]`). */
        var requiredClaimsOverride: List<String>? = null
        /** Additional domain keys served alongside the callback-signing key (e.g. revocation-quorum siblings). */
        var extraDomainKeys: List<JTypes.DomainPublicKey> = listOf()
        /** Revocation certificates the fake IDP's `get-revocations` route returns. */
        var revocations: List<JTypes.RevocationCertificate> = listOf()
        /** When true, `get-revocations` answers with a transport error instead of a response. */
        var dropRevocationsResponse: Boolean = false
        var dnsFingerprintOverride: String? = null
        // get-domain-keys + get-revocations (always fetched) + redeem-claim-ticket.
        var expectedRequests: Int = 3
    }

    private fun runScenario(scenario: Scenario): VerifiedLocalLogin {
        val now = Instant.now()
        val identity = fixedIdentity(now)

        val begun = beginLocalLogin(
            identity, CALLBACK_URL, USER_DOMAIN, now,
            requiredClaims = scenario.requiredClaimsOverride ?: DefaultClaims.REQUIRED,
        )
        val pending = begun.pending

        val domainSigning = JCrypto.generateEd25519KeyPair()
        var domainKey = JTypes.DomainPublicKey(
            DOMAIN_KEY_ID,
            domainSigning.publicKey(),
            JCrypto.fingerprint(domainSigning.publicKey()),
            "ed25519",
            "sign",
            rfc3339(now.minus(Duration.ofDays(30))),
            rfc3339(now.plus(Duration.ofDays(365))),
            null,
            null,
            null,
        )
        domainKey = scenario.mutateDomainKey(domainKey)

        val claimTicket = ByteArray(32) { 7 }
        var payload = JLocalRp.buildLocalRpCallbackPayload(
            "user-1",
            USER_DOMAIN,
            claimTicket,
            identity.fingerprint,
            CALLBACK_URL,
            pending.nonce,
            pending.state,
            rfc3339(now),
            rfc3339(now.plus(Duration.ofMinutes(5))),
        )
        payload = scenario.mutatePayload(payload)

        val signedPayload = JLocalRp.signLocalRpCallbackPayload(payload, DOMAIN_KEY_ID, domainSigning.privateKeySeed())

        val encrypted = JLocalRp.sealLocalRpCallback(
            signedPayload,
            JAeadSuite.AES_256_GCM,
            identity.encryptionPublicKey,
            payload.audienceFingerprint(),
            payload.nonce(),
            payload.state(),
            payload.issuedAt(),
            payload.expiresAt(),
        )
        val encryptedToken = JEncoding.localRpEncryptedCallbackToUrlParam(encrypted)
        val arrivedUrl = "$CALLBACK_URL?encrypted_token=$encryptedToken"

        val claimSpec = JClaims.ClaimSpec(
            "claim-1", "handle", "flowtestuser".toByteArray(StandardCharsets.UTF_8), "user-1", USER_DOMAIN, null, rfc3339(now),
        )
        var claim = JClaims.signClaim(claimSpec, listOf(JClaims.ClaimSigner(USER_DOMAIN, DOMAIN_KEY_ID, domainSigning.privateKeySeed())))
        claim = scenario.mutateClaim(claim)
        val claims = scenario.claimsOverride ?: listOf(claim)

        var redemptionResponse = JTypes.LocalRpTicketRedemptionResponse(
            "user-1", USER_DOMAIN, claims, rfc3339(now.plus(Duration.ofHours(1))),
        )
        redemptionResponse = scenario.mutateRedemption(redemptionResponse)

        val servedDomainKeys = ArrayList<JTypes.DomainPublicKey>()
        servedDomainKeys.add(domainKey)
        servedDomainKeys.addAll(scenario.extraDomainKeys)
        val finalRedemptionResponse = redemptionResponse
        val addr = spawnFakeIdp(domainSigning.privateKeySeed(), scenario.expectedRequests) { service, op, _ ->
            when ("$service/$op") {
                "DomainKeys/get-domain-keys" -> {
                    val resp = JTypes.GetDomainKeysResponse(USER_DOMAIN, servedDomainKeys, null)
                    JRpcEnvelope.Response.ok("GetDomainKeysResponse", JCodec.encodeGetDomainKeysResponse(resp))
                }
                "DomainKeys/get-revocations" -> {
                    if (scenario.dropRevocationsResponse) {
                        JRpcEnvelope.Response.transportError(JRpcEnvelope.Status.INTERNAL, "fake IDP deliberately fails get-revocations")
                    } else {
                        val resp = JTypes.GetRevocationsResponse(scenario.revocations)
                        JRpcEnvelope.Response.ok("GetRevocationsResponse", JCodec.encodeGetRevocationsResponse(resp))
                    }
                }
                "LocalRp/redeem-claim-ticket" ->
                    JRpcEnvelope.Response.ok("LocalRpTicketRedemptionResponse", JCodec.encodeLocalRpTicketRedemptionResponse(finalRedemptionResponse))
                else -> JRpcEnvelope.Response.transportError(JRpcEnvelope.Status.UNKNOWN_SERVICE_OR_OP, "fake IDP has no handler for $service/$op")
            }
        }

        val realFingerprint = JCrypto.fingerprint(domainSigning.publicKey())
        val pinnedFingerprint = scenario.dnsFingerprintOverride ?: realFingerprint
        val linkkeysTxt = StringBuilder("v=lk1 fp=$pinnedFingerprint")
        // Extra domain keys (e.g. revocation-quorum siblings) must also be
        // DNS-pinned directly -- signing keys are only ever trusted when
        // their own fingerprint is in the pinned set.
        for (extra in scenario.extraDomainKeys) {
            linkkeysTxt.append(" fp=").append(extra.fingerprint())
        }
        val dns: DnsResolver = FakeDnsResolver(linkkeysTxt.toString(), "v=lk1 tcp=$addr")
        val transport: Transport = TestTransport()

        return completeLocalLogin(identity, pending, encryptedToken, arrivedUrl, now, transport = transport, dns = dns)
    }

    // -----------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------

    @Test
    fun happyPathReturnsVerifiedLogin() {
        val result = runScenario(Scenario())
        assertEquals("user-1", result.userId)
        assertEquals(USER_DOMAIN, result.userDomain)
        assertEquals(1, result.claims.size)
        assertEquals("handle", result.claims[0].claimType)
        assertEquals(64, result.localRpFingerprint.length)
        assertEquals(1, result.domainPublicKeys.size)
    }

    @Test
    fun wrongAudienceFingerprintIsRejected() {
        val s = Scenario()
        s.mutatePayload = { p ->
            JTypes.LocalRpCallbackPayload(p.userId(), p.userDomain(), p.claimTicket(), "b".repeat(64), p.callbackUrl(), p.nonce(), p.state(), p.issuedAt(), p.expiresAt())
        }
        // get-domain-keys + get-revocations only -- fails before redemption is ever attempted.
        s.expectedRequests = 2
        assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
    }

    @Test
    fun wrongIssuerDomainIsRejected() {
        val s = Scenario()
        s.mutatePayload = { p ->
            JTypes.LocalRpCallbackPayload(p.userId(), "attacker.test", p.claimTicket(), p.audienceFingerprint(), p.callbackUrl(), p.nonce(), p.state(), p.issuedAt(), p.expiresAt())
        }
        s.expectedRequests = 2
        assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
    }

    @Test
    fun nonceMismatchIsRejected() {
        val s = Scenario()
        val wrongNonce = ByteArray(32) { 0xEE.toByte() }
        s.mutatePayload = { p ->
            JTypes.LocalRpCallbackPayload(p.userId(), p.userDomain(), p.claimTicket(), p.audienceFingerprint(), p.callbackUrl(), wrongNonce, p.state(), p.issuedAt(), p.expiresAt())
        }
        s.expectedRequests = 2
        assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
    }

    @Test
    fun expiredCallbackPayloadIsRejected() {
        val s = Scenario()
        s.mutatePayload = { p ->
            val n = Instant.now()
            JTypes.LocalRpCallbackPayload(
                p.userId(), p.userDomain(), p.claimTicket(), p.audienceFingerprint(), p.callbackUrl(), p.nonce(), p.state(),
                rfc3339(n.minus(Duration.ofHours(2))), rfc3339(n.minus(Duration.ofHours(1))),
            )
        }
        s.expectedRequests = 2
        assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
    }

    @Test
    fun dnsFingerprintPinMismatchIsRejected() {
        val s = Scenario()
        s.dnsFingerprintOverride = "c".repeat(64)
        s.expectedRequests = 1
        // Fails during the TLS handshake's mandatory post-handshake pin
        // check (the fake IDP's real cert fingerprint no longer matches the
        // pinned set) -- either way it must never reach a verified result.
        assertThrows(RuntimeException::class.java) { runScenario(s) }
    }

    @Test
    fun revokedSigningKeyIsRejected() {
        val s = Scenario()
        s.mutateDomainKey = { k ->
            JTypes.DomainPublicKey(k.keyId(), k.publicKey(), k.fingerprint(), k.algorithm(), k.keyUsage(), k.createdAt(), k.expiresAt(), rfc3339(Instant.now()), k.signedByKeyId(), k.keySignature())
        }
        s.expectedRequests = 2
        assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
    }

    @Test
    fun tamperedClaimSignatureIsRejected() {
        val s = Scenario()
        s.mutateClaim = { c ->
            val sigs = ArrayList(c.signatures())
            if (sigs.isNotEmpty()) {
                val sig = sigs[0]
                val flipped = sig.signature().clone()
                flipped[0] = (flipped[0].toInt() xor 0xff).toByte()
                sigs[0] = JTypes.ClaimSignature(sig.domain(), sig.signedByKeyId(), flipped)
            }
            JTypes.Claim(c.claimId(), c.userId(), c.claimType(), c.claimValue(), sigs, c.attestedAt(), c.createdAt(), c.expiresAt(), c.revokedAt())
        }
        assertThrows(LocalRpException.ClaimVerification::class.java) { runScenario(s) }
    }

    // -----------------------------------------------------------------
    // Hostile-IDP tests (security review fixes: identity binding,
    // required-claims enforcement, fail-closed revocation fetching). Every
    // one of these proves the FAILURE is fail-closed through this package's
    // own public beginLocalLogin/completeLocalLogin API -- never a
    // "verified" result reaching app code.
    // -----------------------------------------------------------------

    @Test
    fun redemptionIdentityMismatchWithSignedPayloadIsRejected() {
        val s = Scenario()
        // The domain-signed callback payload vouches for "user-1", but the
        // (unsigned) redemption response claims a different user entirely --
        // a compromised/malicious IDP trying to swap in another identity
        // after the ticket was already redeemed for the real one.
        s.mutateRedemption = { r ->
            JTypes.LocalRpTicketRedemptionResponse("attacker-user", r.userDomain(), r.claims(), r.ticketExpiresAt())
        }
        val e = assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
        assertEquals(ProtocolErrorKind.REDEMPTION_IDENTITY_MISMATCH, e.kind)
    }

    @Test
    fun redemptionDomainMismatchWithSignedPayloadIsRejected() {
        val s = Scenario()
        s.mutateRedemption = { r ->
            JTypes.LocalRpTicketRedemptionResponse(r.userId(), "attacker.test", r.claims(), r.ticketExpiresAt())
        }
        val e = assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
        assertEquals(ProtocolErrorKind.REDEMPTION_IDENTITY_MISMATCH, e.kind)
    }

    @Test
    fun claimUserIdMismatchWithSignedPayloadIsRejected() {
        val s = Scenario()
        // The claim is validly signed, but for a DIFFERENT subject than the
        // user the domain-signed payload vouches for -- must never be
        // attributed to this login even though its signature verifies.
        s.mutateClaim = { c ->
            JTypes.Claim(c.claimId(), "attacker-user", c.claimType(), c.claimValue(), c.signatures(), c.attestedAt(), c.createdAt(), c.expiresAt(), c.revokedAt())
        }
        val e = assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
        assertEquals(ProtocolErrorKind.CLAIM_IDENTITY_MISMATCH, e.kind)
    }

    @Test
    fun emptyClaimsWithNonEmptyRequiredClaimsIsRejected() {
        val s = Scenario()
        // The IDP redeems the ticket successfully but returns NO claims at
        // all, even though the pending login required "handle".
        s.claimsOverride = listOf()
        val e = assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
        assertEquals(ProtocolErrorKind.REQUIRED_CLAIMS_NOT_SATISFIED, e.kind)
    }

    @Test
    fun insufficientClaimsMissingARequiredTypeIsRejected() {
        val s = Scenario()
        // Two claim types are required, but the IDP only ever attests one.
        s.requiredClaimsOverride = listOf("handle", "email")
        val e = assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
        assertEquals(ProtocolErrorKind.REQUIRED_CLAIMS_NOT_SATISFIED, e.kind)
    }

    @Test
    fun getRevocationsErrorFailsClosed() {
        val s = Scenario()
        s.dropRevocationsResponse = true
        // get-domain-keys succeeds, get-revocations errors -- the login
        // must never proceed to redemption on a "best effort" basis.
        s.expectedRequests = 2
        val e = assertThrows(LocalRpException.Network::class.java) { runScenario(s) }
        assertEquals(NetworkErrorKind.REVOCATION_UNAVAILABLE, e.kind)
    }

    @Test
    fun certificateRevokedSigningKeyIsRejected() {
        val now = Instant.now()
        val sibling1 = JCrypto.generateEd25519KeyPair()
        val sibling2 = JCrypto.generateEd25519KeyPair()
        val sibling1KeyId = "sibling-key-1"
        val sibling2KeyId = "sibling-key-2"
        val sibling1Key = JTypes.DomainPublicKey(
            sibling1KeyId, sibling1.publicKey(), JCrypto.fingerprint(sibling1.publicKey()), "ed25519", "sign",
            rfc3339(now.minus(Duration.ofDays(30))), rfc3339(now.plus(Duration.ofDays(365))), null, null, null,
        )
        val sibling2Key = JTypes.DomainPublicKey(
            sibling2KeyId, sibling2.publicKey(), JCrypto.fingerprint(sibling2.publicKey()), "ed25519", "sign",
            rfc3339(now.minus(Duration.ofDays(30))), rfc3339(now.plus(Duration.ofDays(365))), null, null, null,
        )

        val s = Scenario()
        // Two sibling signing keys, both DNS-pinned alongside the real
        // callback-signing key (needed to satisfy the revocation quorum of 2).
        s.extraDomainKeys = listOf(sibling1Key, sibling2Key)
        // mutateDomainKey runs (inside runScenario) right after the real
        // callback-signing key is built -- it's the only place we learn that
        // key's actual key id/fingerprint, so build the quorum-verified
        // revocation certificate targeting it here and stash it directly
        // onto `s.revocations`, which the fake IDP's get-revocations route
        // reads lazily (after this mutator has already run). The canonical
        // signed payload (`CBOR([tag, target_key_id, target_fingerprint,
        // revoked_at, signing_domain])`) is rebuilt here via the public
        // `Cbor` wire helper -- the tag "linkkeys-key-revocation-v1" is the
        // same protocol constant RevocationsConformanceTest asserts against
        // `revocations.json`; the underlying dependency's own payload
        // builder is a package-private white-box hook, not part of this
        // SDK's (or the Java SDK's) public surface.
        s.mutateDomainKey = { k ->
            val revokedAt = rfc3339(now)
            val payload = JCbor.encode(
                JCbor.tuple(
                    JCbor.vtext("linkkeys-key-revocation-v1"),
                    JCbor.vtext(k.keyId()),
                    JCbor.vtext(k.fingerprint()),
                    JCbor.vtext(revokedAt),
                    JCbor.vtext(USER_DOMAIN),
                ),
            )
            val sig1 = JCrypto.signEd25519(payload, sibling1.privateKeySeed())
            val sig2 = JCrypto.signEd25519(payload, sibling2.privateKeySeed())
            s.revocations = listOf(
                JTypes.RevocationCertificate(
                    k.keyId(), k.fingerprint(), revokedAt,
                    listOf(
                        JTypes.ClaimSignature(USER_DOMAIN, sibling1KeyId, sig1),
                        JTypes.ClaimSignature(USER_DOMAIN, sibling2KeyId, sig2),
                    ),
                ),
            )
            k
        }
        // Fails at envelope verification (the signing key was just revoked
        // out of the trusted set) -- redemption is never attempted.
        s.expectedRequests = 2
        val e = assertThrows(LocalRpException.Protocol::class.java) { runScenario(s) }
        assertEquals(ProtocolErrorKind.KEY_NOT_FOUND, e.kind)
    }
}
