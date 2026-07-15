package community.catalyst.linkkeys.localrp.kt

import java.time.OffsetDateTime
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.kt.protocol.Claims
import community.catalyst.linkkeys.localrp.kt.protocol.ClaimDomainKeySet
import community.catalyst.linkkeys.localrp.kt.protocol.Crypto
import community.catalyst.linkkeys.localrp.kt.protocol.TicketRedemptionResponses
import community.catalyst.linkkeys.localrp.kt.testutil.Fixtures
import community.catalyst.linkkeys.localrp.kt.testutil.MiniJson.JsonValue

/**
 * Conformance vectors: `claims.json` -- claim wire encoding and
 * claim-signature verification, exercised through this package's own
 * [Claims] and [TicketRedemptionResponses].
 *
 * The trap this file exists to catch (README, `claims.json`): `claim_value`
 * is CBOR *bytes* (bstr), never text (tstr), both on the wire and inside the
 * signed payload -- a codec wired as tstr passes its own self-tests
 * (sign-wrong/verify-wrong is self-consistent) and only these
 * cross-implementation vectors expose it.
 */
class ClaimsConformanceTest {

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

    /** Group a flat `domain_keys[]` JSON array (each entry carries its own `domain` field) into per-domain key sets, as [Claims.verifyClaim]/[Claims.verifyClaimSignatures] require. */
    private fun parseDomainKeySets(domainKeysJson: JsonValue): List<ClaimDomainKeySet> =
        domainKeysJson.asArray()
            .groupBy { it.get("domain").asString() }
            .map { (domain, entries) -> ClaimDomainKeySet(domain, entries.map { parseDomainKey(it) }) }

    private fun publicKeyOf(domainKeysJson: JsonValue, keyId: String): ByteArray =
        Fixtures.hex(domainKeysJson.asArray().first { it.get("key_id").asString() == keyId }.get("public_key_hex").asString())

    @Test
    fun positiveCasesRoundTripAndVerify() {
        val d = Fixtures.load("claims.json")
        val defaultDomainKeys = parseDomainKeySets(d.get("domain_keys"))
        val cases = d.get("cases").asArray()
        assertEquals(3, cases.size, "expected 3 positive cases")

        for (c in cases) {
            val name = c.get("name").asString()
            assertTrue(c.get("expected_valid").asBoolean(), "$name: expected_valid should be true for cases[]")

            val claimCbor = Fixtures.hex(c.get("claim_cbor_hex").asString())
            val subjectDomain = c.get("subject_domain").asString()
            assertEquals("conformance.example", subjectDomain)

            // Byte-exact wire round-trip: decode then re-encode must reproduce
            // claim_cbor_hex exactly -- this is what catches a bstr/tstr mixup
            // for claim_value.
            assertArrayEquals(claimCbor, Claims.reencodeCbor(claimCbor), "$name: claim_cbor_hex did not round-trip byte-exactly")

            val claim = Claims.decode(claimCbor)
            val claimJson = c.get("claim")
            assertEquals(claimJson.get("claim_id").asString(), claim.claimId, name)
            assertEquals(claimJson.get("user_id").asString(), claim.userId, name)
            assertEquals(claimJson.get("claim_type").asString(), claim.claimType, name)
            assertArrayEquals(Fixtures.hex(claimJson.get("claim_value_hex").asString()), claim.claimValue, "$name: claim_value must be wired as bstr, not tstr")
            assertEquals(OffsetDateTime.parse(claimJson.get("attested_at").asString()).toInstant(), claim.attestedAt, name)
            assertEquals(OffsetDateTime.parse(claimJson.get("created_at").asString()).toInstant(), claim.createdAt, name)
            val expiresAtJson = claimJson.getStringOrNull("expires_at")
            if (expiresAtJson == null) {
                assertNull(claim.expiresAt, "$name: expires_at should be absent")
            } else {
                assertEquals(OffsetDateTime.parse(expiresAtJson).toInstant(), claim.expiresAt, name)
            }
            assertNull(claim.revokedAt, "$name: revoked_at should be absent")

            val sigsJson = claimJson.get("signatures").asArray()
            assertEquals(sigsJson.size, claim.signatures.size, "$name: signature count mismatch")
            for (i in sigsJson.indices) {
                val sigJson = sigsJson[i]
                val sig = claim.signatures[i]
                assertEquals(sigJson.get("domain").asString(), sig.domain, name)
                assertEquals(sigJson.get("signed_by_key_id").asString(), sig.signedByKeyId, name)
                assertArrayEquals(Fixtures.hex(sigJson.get("signature_hex").asString()), sig.signature, name)

                // Independent, lower-level cross-check: Ed25519-verify the
                // vector's own signed_payload_cbor_hex/signature_hex directly
                // against the signer's public key, without going through
                // Claims.verifyClaim at all.
                val payload = Fixtures.hex(sigJson.get("signed_payload_cbor_hex").asString())
                val signature = Fixtures.hex(sigJson.get("signature_hex").asString())
                val publicKey = publicKeyOf(d.get("domain_keys"), sigJson.get("signed_by_key_id").asString())
                assertTrue(Crypto.verifyEd25519(payload, signature, publicKey), "$name: raw Ed25519 verify of signed_payload_cbor_hex failed")
            }

            // Full verification (signature quorum + revocation/expiry) through
            // this package's own public surface.
            assertDoesNotThrow({ Claims.verifyClaim(claimCbor, subjectDomain, defaultDomainKeys) }, "$name unexpectedly failed to verify")
            assertDoesNotThrow({ Claims.verifyClaimSignatures(claimCbor, subjectDomain, defaultDomainKeys) }, "$name unexpectedly failed signature-only verification")
        }
    }

    @Test
    fun decodeNegativeCasesRejected() {
        val d = Fixtures.load("claims.json")
        val cases = d.get("decode_negative_cases").asArray()
        assertEquals(1, cases.size)

        for (c in cases) {
            val name = c.get("name").asString()
            assertFalse(c.get("expected_decode_ok").asBoolean(), name)
            val claimCbor = Fixtures.hex(c.get("claim_cbor_hex").asString())
            // claim_value_as_cbor_text_rejected: byte-identical to a positive
            // case except claim_value is encoded as CBOR major type 3 (text)
            // instead of major type 2 (bytes). A strict bstr codec must
            // refuse to decode this at all.
            assertThrows(RuntimeException::class.java, { Claims.decode(claimCbor) }, "$name unexpectedly decoded")
        }
    }

    @Test
    fun negativeCasesFailVerification() {
        val d = Fixtures.load("claims.json")
        val defaultDomainKeys = parseDomainKeySets(d.get("domain_keys"))
        val cases = d.get("negative_cases").asArray()
        assertEquals(4, cases.size)

        for (c in cases) {
            val name = c.get("name").asString()
            val claimCbor = Fixtures.hex(c.get("claim_cbor_hex").asString())
            val subjectDomain = c.get("subject_domain").asString()
            val expectedErrorName = c.get("expected_error").asString()
            val expectedKind = ClaimErrorKind.valueOf(expectedErrorName.uppercase())

            val domainKeysOverride = c.getOrNull("domain_keys")
            val domainKeys = if (domainKeysOverride != null) parseDomainKeySets(domainKeysOverride) else defaultDomainKeys

            val ex = assertThrows(LocalRpException.ClaimVerification::class.java, { Claims.verifyClaim(claimCbor, subjectDomain, domainKeys) }, "$name unexpectedly verified")
            assertEquals(expectedKind, ex.kind, "$name: wrong ClaimErrorKind")
        }
    }

    @Test
    fun ticketRedemptionResponseRoundTripsAndClaimsVerify() {
        val d = Fixtures.load("claims.json")
        val defaultDomainKeys = parseDomainKeySets(d.get("domain_keys"))
        val respJson = d.get("ticket_redemption_response")
        val responseCbor = Fixtures.hex(respJson.get("response_cbor_hex").asString())

        // Byte-exact whole-message round-trip.
        assertArrayEquals(responseCbor, TicketRedemptionResponses.reencodeCbor(responseCbor), "response_cbor_hex did not round-trip byte-exactly")

        val response = TicketRedemptionResponses.decode(responseCbor)
        assertEquals(respJson.get("user_id").asString(), response.userId)
        assertEquals(respJson.get("user_domain").asString(), response.userDomain)
        assertEquals(OffsetDateTime.parse(respJson.get("ticket_expires_at").asString()).toInstant(), response.ticketExpiresAt)
        assertEquals(3, response.claims.size, "expected all three positive-case claims, in order")

        val expectedNamesInOrder = listOf("claim_utf8_text_value", "claim_non_utf8_binary_value", "claim_multiple_signatures")
        val positiveCasesByName = d.get("cases").asArray().associateBy { it.get("name").asString() }
        val claimIdsInOrder = expectedNamesInOrder.map { positiveCasesByName.getValue(it).get("claim").get("claim_id").asString() }
        assertEquals(claimIdsInOrder, response.claims.map { it.claimId })

        // Decoding without verifying fails the point: verify every embedded
        // claim's signatures, from the claims' own re-encoded CBOR bytes
        // (never through the lossy Instant-backed Claim type -- see Claims'
        // class docs).
        val claimCborBytesList = TicketRedemptionResponses.claimCborBytes(responseCbor)
        assertEquals(3, claimCborBytesList.size)
        for (claimCbor in claimCborBytesList) {
            assertDoesNotThrow({ Claims.verifyClaim(claimCbor, response.userDomain, defaultDomainKeys) }, "embedded claim unexpectedly failed to verify")
        }
    }
}
