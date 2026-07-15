package community.catalyst.linkkeys.localrp.kt

import java.time.Instant
import java.time.OffsetDateTime
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.CallbackPayload
import community.catalyst.linkkeys.localrp.kt.protocol.RevocationCertificate
import community.catalyst.linkkeys.localrp.kt.protocol.Revocations
import community.catalyst.linkkeys.localrp.kt.testutil.Fixtures
import community.catalyst.linkkeys.localrp.kt.testutil.MiniJson.JsonValue

/**
 * Conformance vectors: `revocations.json` -- sibling-signed key revocation
 * certificates, exercised through this package's own [Revocations] and
 * [CallbackPayload].
 */
class RevocationsConformanceTest {

    private fun parseDomainKey(k: JsonValue): DomainPublicKey = DomainPublicKey(
        k.get("key_id").asString(),
        Fixtures.hex(k.get("public_key_hex").asString()),
        k.get("fingerprint_hex").asString(),
        k.get("algorithm").asString(),
        k.get("key_usage").asString(),
        OffsetDateTime.parse(k.get("created_at").asString()).toInstant(),
        OffsetDateTime.parse(k.get("expires_at").asString()).toInstant(),
        k.getStringOrNull("revoked_at")?.let { OffsetDateTime.parse(it).toInstant() },
        null,
        null,
    )

    private fun parseCertificate(certNode: JsonValue): RevocationCertificate {
        val signatures = certNode.get("signatures").asArray().map { s ->
            ClaimSignature(s.get("domain").asString(), s.get("signed_by_key_id").asString(), Fixtures.hex(s.get("signature_hex").asString()))
        }
        return RevocationCertificate(
            certNode.get("target_key_id").asString(),
            certNode.get("target_fingerprint").asString(),
            // Raw wire string, deliberately not parsed to Instant -- see
            // RevocationCertificate's docs: it is exact signed-payload bytes.
            certNode.get("revoked_at").asString(),
            signatures,
        )
    }

    @Test
    fun certificateCasesMatchExpectedValidity() {
        val d = Fixtures.load("revocations.json")
        assertEquals(2, d.get("quorum").asLong())
        assertEquals("linkkeys-key-revocation-v1", d.get("tag").asString())
        assertEquals(Revocations.QUORUM.toLong(), d.get("quorum").asLong())

        val domainKeys = d.get("domain_keys").asArray().map { parseDomainKey(it) }

        val cases = d.get("certificate_cases").asArray()
        assertEquals(9, cases.size)

        for (c in cases) {
            val name = c.get("name").asString()
            val cert = parseCertificate(c.get("certificate"))
            val verifyDomain = c.get("verify_domain").asString()
            val expectedValid = c.get("expected_valid").asBoolean()

            if (expectedValid) {
                assertDoesNotThrow({ Revocations.verify(cert, domainKeys, verifyDomain) }, "$name unexpectedly failed to verify")
            } else {
                assertThrows(LocalRpException.Revocation::class.java, { Revocations.verify(cert, domainKeys, verifyDomain) }, "$name unexpectedly verified")
            }
        }
    }

    @Test
    fun applicationCaseRevocationIsAppliedToTheKeySet() {
        val d = Fixtures.load("revocations.json")
        val domain = d.get("domain").asString()

        val domainKeys = d.get("domain_keys").asArray().map { parseDomainKey(it) }

        val quorumCase = d.get("certificate_cases").asArray().first { it.get("name").asString() == "valid_quorum_two_siblings" }
        val cert = parseCertificate(quorumCase.get("certificate"))

        val app = d.get("application_case")
        val envelope = app.get("envelope")
        val payloadCbor = Fixtures.hex(envelope.get("payload_cbor_hex").asString())
        val signingKeyId = envelope.get("signing_key_id").asString()
        val signature = Fixtures.hex(envelope.get("signature_hex").asString())
        val verifyNow: Instant = OffsetDateTime.parse(app.get("verify_now").asString()).toInstant()
        val skew = app.get("clock_skew_seconds").asLong()

        // Before applying the revocation certificate: the fetched key list
        // shows the target key with no revoked_at, so the envelope verifies.
        CallbackPayload.verifySignedEnvelope(payloadCbor, signingKeyId, signature, domainKeys, verifyNow, skew)

        // Apply the quorum-verified certificate exactly as
        // completeLocalLogin would: verify it, then drop its target from the
        // trusted key set.
        Revocations.verify(cert, domainKeys, domain)
        val afterRevocation = domainKeys.filter { it.keyId != cert.targetKeyId }

        // After applying: the same envelope must fail signature/key-lookup
        // verification, because its signing key is no longer in the trusted set.
        assertThrows(LocalRpException.Protocol::class.java) {
            CallbackPayload.verifySignedEnvelope(payloadCbor, signingKeyId, signature, afterRevocation, verifyNow, skew)
        }
    }
}
