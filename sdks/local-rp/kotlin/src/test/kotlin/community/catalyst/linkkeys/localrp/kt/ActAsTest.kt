package community.catalyst.linkkeys.localrp.kt

import java.nio.ByteBuffer
import java.time.Duration
import java.time.Instant
import java.util.Base64
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.testutil.Fixtures
import community.catalyst.linkkeys.localrp.kt.testutil.MiniJson
import community.catalyst.linkkeys.localrp.LocalRp as JLocalRp
import community.catalyst.linkkeys.localrp.crypto.Crypto as JCrypto
import community.catalyst.linkkeys.localrp.crypto.Hex as JHex
import community.catalyst.linkkeys.localrp.rpc.RpcEnvelope as JRpcEnvelope
import community.catalyst.linkkeys.localrp.wire.Cbor as JCbor
import community.catalyst.linkkeys.localrp.wire.Codec as JCodec
import community.catalyst.linkkeys.localrp.wire.Types as JTypes

/**
 * Act-as grantee support through the Kotlin surface: byte-exact signing
 * against `sdks/regular-rp/conformance/act_as_grantee_signing.json`
 * (`local_rp_grantee` case), begin URL discovery, callback nonce checks, and
 * refresh over [FlowTest]'s loopback fake IDP. No live network: DNS is always
 * a canned fake. The fake IDP side speaks the Java wire types directly, as in
 * [FlowTest].
 */
class ActAsTest {
    companion object {
        private const val IDENTITY_DOMAIN = "ident.example.test"
        private const val CALLBACK_URL = "http://app.lan:8080/act-as/callback"
        private val VECTORS: MiniJson.JsonValue by lazy { Fixtures.loadRegularRp("act_as_grantee_signing.json") }
    }

    private fun localRpCase(): MiniJson.JsonValue =
        VECTORS.get("cases").asArray().first { it.get("name").asString() == "local_rp_grantee" }

    private fun scopeSetCbor(): ByteArray =
        JHex.decode(localRpCase().get("grant_request").get("inputs").get("scope_set_signed_cbor_hex").asString())

    /** The vector's identity, loaded through the public storage format (signing seed + signed descriptor). */
    private fun vectorIdentity(): LocalRpIdentity {
        val local = VECTORS.get("local_rp_grantee")
        val seed = JHex.decode(local.get("signing_private_key_hex").asString())
        val descriptor = JHex.decode(local.get("signed_descriptor_cbor_hex").asString())
        val buf = ByteBuffer.allocate(4 + 32 + 32 + 4 + descriptor.size)
        buf.put(byteArrayOf('L'.code.toByte(), 'K'.code.toByte(), 'I'.code.toByte(), '1'.code.toByte()))
        buf.put(seed)
        buf.put(ByteArray(32))
        buf.putInt(descriptor.size)
        buf.put(descriptor)
        return localRpIdentityFromBytes(buf.array())
    }

    private fun optLong(obj: MiniJson.JsonValue, key: String): Long? = obj.getOrNull(key)?.takeUnless { it.isNull() }?.asLong()

    @Test
    fun localRpGranteeVectorsAreByteExact() {
        val identity = vectorIdentity()
        val case = localRpCase()
        assertEquals(VECTORS.get("local_rp_grantee").get("fingerprint").asString(), identity.fingerprint)
        assertEquals(ActAsDefaults.GRANT_REQUEST_TAG, VECTORS.get("tags").get("grant_request").asString())
        assertEquals(ActAsDefaults.REFRESH_REQUEST_TAG, VECTORS.get("tags").get("refresh_request").asString())
        assertEquals(ActAsDefaults.PRESENTATION_TAG, VECTORS.get("tags").get("presentation").asString())

        val g = case.get("grant_request")
        val gi = g.get("inputs")
        val signedRequest = signActAsGrantRequest(
            identity,
            scopeSetCbor = JHex.decode(gi.get("scope_set_signed_cbor_hex").asString()),
            callbackUrl = gi.get("callback_url").asString(),
            nonce = gi.get("nonce").asString(),
            requestedAt = gi.get("requested_at").asString(),
            expiresAt = gi.get("expires_at").asString(),
            requestedLifetimeSeconds = optLong(gi, "requested_lifetime_seconds"),
            requestedRenewalWindowSeconds = optLong(gi, "requested_renewal_window_seconds"),
        )
        assertEquals(g.get("signed_cbor_hex").asString(), JHex.encode(signedRequest))
        assertEquals(g.get("url_param").asString(), Base64.getUrlEncoder().withoutPadding().encodeToString(signedRequest))

        val r = case.get("refresh_request")
        val ri = r.get("inputs")
        val signedRefresh = signActAsRefreshRequest(
            identity,
            grantId = ri.get("grant_id").asString(),
            requestedAt = ri.get("requested_at").asString(),
            expiresAt = ri.get("expires_at").asString(),
            nonce = ri.get("nonce").asString(),
        )
        assertEquals(r.get("signed_cbor_hex").asString(), JHex.encode(signedRefresh))

        val p = case.get("presentation")
        val pi = p.get("inputs")
        val grant = SignedActAsGrant.fromBytes(JHex.decode(pi.get("grant_signed_cbor_hex").asString()))
        val aud = pi.get("audience")
        val credential = presentActAs(
            grant,
            ApplicationRef(aud.get("subject_user_id").asString(), aud.get("subject_domain").asString(), aud.get("application_id").asString()),
            requestDigest = JHex.decode(pi.get("request_digest_hex").asString()),
            now = Instant.parse(pi.get("presented_at").asString()),
            nonce = JHex.decode(pi.get("nonce_hex").asString()),
            identity = identity,
        )
        assertEquals(p.get("grant_hash_hex").asString(), JHex.encode(actAsGrantHash(grant.grant)))
        assertEquals(p.get("presentation_cbor_hex").asString(), JHex.encode(credential.presentation))
        assertEquals(p.get("credential_cbor_hex").asString(), JHex.encode(credential.bytes))
    }

    private fun freshIdentity(now: Instant): LocalRpIdentity = generateLocalRpIdentity("act-as-kt-test", now)

    @Test
    fun beginActAsUsesDiscoveredHostAndSignsTheRequest() {
        val now = Instant.parse("2026-10-06T11:59:00Z")
        val identity = freshIdentity(now)
        val dns = DnsResolver { name ->
            if (name == "_linkkeys_apis.$IDENTITY_DOMAIN") {
                listOf("v=lk1 tcp=x.example.test https=login.example.test")
            } else {
                throw LocalRpException.Network(NetworkErrorKind.DNS, "no fake record for $name")
            }
        }
        val result = beginActAs(
            identity, "alice@$IDENTITY_DOMAIN", scopeSetCbor(), CALLBACK_URL, now,
            requestedLifetimeSeconds = 1800, requestedRenewalWindowSeconds = 600, dns = dns,
        )
        val prefix = "https://login.example.test/auth/act-as?signed_request="
        assertTrue(result.redirectUrl.startsWith(prefix), result.redirectUrl)
        assertEquals(PendingActAs(result.pending.nonce, IDENTITY_DOMAIN, CALLBACK_URL), result.pending)
        assertEquals(result.pending, PendingActAs.fromBytes(result.pending.toBytes()))

        val signed = JCodec.decodeSignedActAsGrantRequest(Base64.getUrlDecoder().decode(result.redirectUrl.substring(prefix.length)))
        assertTrue(
            JCrypto.verifyEd25519(
                JLocalRp.envelopeSignatureInput(ActAsDefaults.GRANT_REQUEST_TAG, signed.request()),
                signed.proof().signature().signature(),
                identity.signingPublicKey,
            ),
        )
        val request = JCodec.decodeActAsGrantRequest(signed.request())
        assertEquals(identity.fingerprint, request.grantee().localRpDescriptorFingerprint())
        assertEquals(result.pending.nonce, request.nonce())
        assertEquals("2026-10-06T12:04:00Z", request.expiresAt())
        assertEquals(1800L, request.requestedLifetimeSeconds())
        assertEquals(600L, request.requestedRenewalWindowSeconds())
        assertArrayEquals(scopeSetCbor(), JCodec.encodeSignedActAsScopeSet(request.scopeSet()))
    }

    @Test
    fun beginActAsFallsBackAndRejectsLongWindows() {
        val now = Instant.parse("2026-10-06T11:59:00Z")
        val identity = freshIdentity(now)
        val failing = DnsResolver { throw LocalRpException.Network(NetworkErrorKind.DNS, "SERVFAIL") }
        val result = beginActAs(identity, IDENTITY_DOMAIN, scopeSetCbor(), CALLBACK_URL, now, dns = failing)
        assertTrue(result.redirectUrl.startsWith("https://$IDENTITY_DOMAIN/auth/act-as?signed_request="), result.redirectUrl)

        assertThrows(LocalRpException.InvalidInput::class.java) {
            beginActAs(identity, IDENTITY_DOMAIN, scopeSetCbor(), CALLBACK_URL, now, requestWindow = Duration.ofSeconds(901), dns = failing)
        }
        assertThrows(LocalRpException.InvalidInput::class.java) {
            beginActAs(identity, IDENTITY_DOMAIN, byteArrayOf(1), CALLBACK_URL, now, dns = failing)
        }
    }

    @Test
    fun callbackChecksTheNonce() {
        val pending = PendingActAs("expected", IDENTITY_DOMAIN, CALLBACK_URL)
        assertEquals("g-1", completeActAsCallback(pending, "$CALLBACK_URL?act_as_grant_id=g-1&nonce=expected"))
        val mismatch = assertThrows(LocalRpException.Protocol::class.java) {
            completeActAsCallback(pending, "$CALLBACK_URL?act_as_grant_id=g-1&nonce=other")
        }
        assertEquals(ProtocolErrorKind.NONCE_MISMATCH, mismatch.kind)
        assertThrows(LocalRpException.InvalidInput::class.java) { completeActAsCallback(pending, "$CALLBACK_URL?nonce=expected") }
    }

    /**
     * A grant as a home domain stores it, as CBOR(SignedActAsGrant). Only the
     * identifying fields matter to the grantee; the audience checks the signature.
     */
    private fun servedGrant(grantId: String, fingerprint: String, subjectDomain: String): ByteArray {
        fun map(vararg entries: Pair<String, JCbor.Value>) = JCbor.vmap(entries.map { JCbor.entry(it.first, it.second) })
        val grant = map(
            "grant_id" to JCbor.vtext(grantId),
            "user_id" to JCbor.vtext("user-1"),
            "subject_domain" to JCbor.vtext(subjectDomain),
            "grantee" to map("local_rp_descriptor_fingerprint" to JCbor.vtext(fingerprint)),
            "audience" to map(
                "subject_user_id" to JCbor.vtext("audience-owner"),
                "subject_domain" to JCbor.vtext("audience.test"),
                "application_id" to JCbor.vtext("audience-app"),
            ),
            "scope_set" to map(
                "scope_set" to JCbor.vbytes(byteArrayOf(0xa0.toByte())),
                "signer_instance_id" to JCbor.vtext("audience-inst"),
                "signatures" to JCbor.varray(
                    listOf(
                        map(
                            "signed_by_key_id" to JCbor.vtext("audience-key"),
                            "signature" to JCbor.vbytes(ByteArray(64)),
                        ),
                    ),
                ),
            ),
            "approved_scope" to JCbor.varray(listOf(JCbor.vtext("read"))),
            "issued_at" to JCbor.vtext("2026-10-06T12:00:00Z"),
            "expires_at" to JCbor.vtext("2026-10-06T13:00:00Z"),
            "series_issued_at" to JCbor.vtext("2026-10-06T12:00:00Z"),
            "renewable_until" to JCbor.vtext("2026-10-06T13:00:00Z"),
        )
        return JCodec.encodeSignedActAsGrant(
            JTypes.SignedActAsGrant(
                JCbor.encode(grant),
                listOf(JTypes.ClaimSignature(subjectDomain, "domain-key", ByteArray(64))),
            ),
        )
    }

    @Test
    fun refreshRefusesAGrantForAnotherGrantIdGranteeOrDomain() {
        val now = Instant.parse("2026-10-06T12:40:00Z")
        val identity = freshIdentity(now)
        for (served in listOf(
            servedGrant("grant-2", identity.fingerprint, FlowTest.USER_DOMAIN),
            servedGrant("grant-1", "another-local-rp", FlowTest.USER_DOMAIN),
            servedGrant("grant-1", identity.fingerprint, "other.test"),
        )) {
            val domain = JCrypto.generateEd25519KeyPair()
            val addr = FlowTest().spawnFakeIdp(domain.privateKeySeed(), 1) { _, _, _ ->
                JRpcEnvelope.Response.ok(
                    "RefreshActAsGrantResponse",
                    JCodec.encodeRefreshActAsGrantResponse(
                        JTypes.RefreshActAsGrantResponse(JCodec.decodeSignedActAsGrant(served), false),
                    ),
                )
            }
            val e = assertThrows(LocalRpException.Protocol::class.java) {
                refreshActAsGrant(
                    identity, FlowTest.USER_DOMAIN, "grant-1", now,
                    transport = FlowTest.TestTransport(),
                    dns = FlowTest.FakeDnsResolver("v=lk1 fp=${JCrypto.fingerprint(domain.publicKey())}", "v=lk1 tcp=$addr"),
                )
            }
            assertEquals(ProtocolErrorKind.GRANT_MISMATCH, e.kind)
        }
    }

    @Test
    fun refreshCallsActAsRefreshGrant() {
        val now = Instant.parse("2026-10-06T12:40:00Z")
        val identity = freshIdentity(now)
        val grantBytes = servedGrant("grant-1", identity.fingerprint, FlowTest.USER_DOMAIN)
        val domain = JCrypto.generateEd25519KeyPair()
        val routes = mutableListOf<String>()
        val payloads = mutableListOf<ByteArray>()
        val addr = FlowTest().spawnFakeIdp(domain.privateKeySeed(), 1) { service, op, payload ->
            routes.add("$service/$op")
            payloads.add(payload)
            JRpcEnvelope.Response.ok(
                "RefreshActAsGrantResponse",
                JCodec.encodeRefreshActAsGrantResponse(
                    JTypes.RefreshActAsGrantResponse(JCodec.decodeSignedActAsGrant(grantBytes), false),
                ),
            )
        }
        val result = refreshActAsGrant(
            identity, FlowTest.USER_DOMAIN, "grant-1", now,
            transport = FlowTest.TestTransport(),
            dns = FlowTest.FakeDnsResolver("v=lk1 fp=${JCrypto.fingerprint(domain.publicKey())}", "v=lk1 tcp=$addr"),
        )
        assertFalse(result.signed)
        assertArrayEquals(grantBytes, result.grant.toBytes())
        assertEquals("grant-1", result.grant.decodeUnverified().grantId)
        assertEquals(listOf("ActAs/refresh-grant"), routes)

        val signed = JCodec.decodeRefreshActAsGrantRequest(payloads[0]).request()
        assertTrue(
            JCrypto.verifyEd25519(
                JLocalRp.envelopeSignatureInput(ActAsDefaults.REFRESH_REQUEST_TAG, signed.request()),
                signed.proof().signature().signature(),
                identity.signingPublicKey,
            ),
        )
        val request = JCodec.decodeActAsRefreshRequest(signed.request())
        assertEquals("grant-1", request.grantId())
        assertEquals(identity.fingerprint, request.grantee().localRpDescriptorFingerprint())
        assertNull(request.grantee().application())
        assertEquals("2026-10-06T12:45:00Z", request.expiresAt())
    }

    @Test
    fun refreshSurfacesTransportErrors() {
        val now = Instant.parse("2026-10-06T12:40:00Z")
        val identity = freshIdentity(now)
        val domain = JCrypto.generateEd25519KeyPair()
        val addr = FlowTest().spawnFakeIdp(domain.privateKeySeed(), 1) { _, _, _ ->
            JRpcEnvelope.Response.transportError(JRpcEnvelope.Status.FORBIDDEN, "not yours")
        }
        val e = assertThrows(LocalRpException.Server::class.java) {
            refreshActAsGrant(
                identity, FlowTest.USER_DOMAIN, "grant-1", now,
                transport = FlowTest.TestTransport(),
                dns = FlowTest.FakeDnsResolver("v=lk1 fp=${JCrypto.fingerprint(domain.publicKey())}", "v=lk1 tcp=$addr"),
            )
        }
        assertEquals(JRpcEnvelope.Status.FORBIDDEN, e.status)
    }
}
