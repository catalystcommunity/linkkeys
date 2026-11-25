package community.catalyst.linkkeys.localrp.kt

import java.time.Instant
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import community.catalyst.linkkeys.localrp.Claims as JClaims
import community.catalyst.linkkeys.localrp.crypto.Crypto as JCrypto
import community.catalyst.linkkeys.localrp.crypto.Hex as JHex
import community.catalyst.linkkeys.localrp.wire.Cbor as JCbor
import community.catalyst.linkkeys.localrp.wire.Codec as JCodec
import community.catalyst.linkkeys.localrp.wire.Types as JTypes
import community.catalyst.linkkeys.localrp.kt.protocol.ClaimDomainKeySet
import community.catalyst.linkkeys.localrp.kt.protocol.Claims
import community.catalyst.linkkeys.localrp.kt.protocol.RevocationCertificate
import community.catalyst.linkkeys.localrp.kt.protocol.Revocations

/** CSIL wire rules through the Kotlin surface: tag-0 timestamps, named-number enums, whole-second signed times. */
class WireFormatTest {
    private val t: Instant = Instant.parse("2026-01-01T00:10:00Z")
    private val later: Instant = Instant.now().plusSeconds(3600)

    private fun signingKey(id: String, pair: JCrypto.Ed25519KeyPair) = DomainPublicKey(
        id, pair.publicKey(), JCrypto.fingerprint(pair.publicKey()), "ed25519", "sign", t, later, null, null, null,
    )

    @Test
    fun timestampIsTagZeroUtcText() {
        val expected = "c074" + JHex.encode("2026-01-01T00:10:00Z".toByteArray())
        assertEquals(expected, JHex.encode(JCbor.encode(JCbor.vtimestamp(t))))
        // A non-UTC offset decodes to the same instant.
        assertEquals(t, JCbor.asTimestamp(JCbor.vtag(0, JCbor.vtext("2026-01-01T01:10:00+01:00"))))
    }

    @Test
    fun untaggedOrNonRfc3339TimestampIsRefused() {
        assertThrows(JCbor.CborDecodeException::class.java) { JCbor.asTimestamp(JCbor.vtext("2026-01-01T00:10:00Z")) }
        for (bad in listOf("2026-01-01T00:10Z", "2026-01-01T00:10:00", "2026-01-01", "yesterday")) {
            assertThrows(JCbor.CborDecodeException::class.java, { JCbor.asTimestamp(JCbor.vtag(0, JCbor.vtext(bad))) }, bad)
        }
    }

    @Test
    fun enumNumbersMatchTheCsilAndUnknownIsRefused() {
        val m = JCbor.decode(JCodec.encodeDomainPublicKey(signingKey("k1", JCrypto.generateEd25519KeyPair()).toJava()))
        assertEquals(1L, JCbor.asInt(JCbor.require(m, "algorithm")))
        assertEquals(1L, JCbor.asInt(JCbor.require(m, "key_usage")))
        assertEquals(2L, JCbor.KEY_USAGE.number("encrypt"))
        assertEquals(3L, JCbor.KEY_USAGE.number("agree"))
        assertEquals(2L, JCbor.KEY_ALGORITHM.number("x25519"))
        assertEquals(1L, JCbor.AEAD_SUITE.number("aes-256-gcm"))
        assertEquals(2L, JCbor.AEAD_SUITE.number("chacha20-poly1305"))
        assertThrows(JCbor.CborDecodeException::class.java) { JCbor.AEAD_SUITE.decode(JCbor.vint(3)) }
        assertThrows(JCbor.CborDecodeException::class.java) { JCbor.KEY_USAGE.decode(JCbor.vtext("sign")) }
    }

    @Test
    fun fractionalClaimTimeFailsVerification() {
        val signer = JCrypto.generateEd25519KeyPair()
        val spec = JClaims.ClaimSpec("c1", "handle", byteArrayOf(1), "u1", "example.com", null, t)
        val claim = JClaims.signClaim(spec, listOf(JClaims.ClaimSigner("example.com", "k1", signer.privateKeySeed())))
        val keys = listOf(ClaimDomainKeySet("example.com", listOf(signingKey("k1", signer))))
        assertDoesNotThrow { Claims.verifyClaim(JCodec.encodeClaim(claim), "example.com", keys) }

        // Same signature, attested_at moved by half a second. Rounding down would make it verify.
        val fractional = JTypes.Claim(
            claim.claimId(), claim.userId(), claim.claimType(), claim.claimValue(), claim.signatures(),
            t.plusMillis(500), claim.createdAt(), null, null,
        )
        val e = assertThrows(LocalRpException.ClaimVerification::class.java) {
            Claims.verifyClaim(JCodec.encodeClaim(fractional), "example.com", keys)
        }
        assertEquals(ClaimErrorKind.BAD_TIMESTAMP, e.kind)
    }

    @Test
    fun fractionalRevocationTimeIsNotCounted() {
        val s1 = JCrypto.generateEd25519KeyPair()
        val s2 = JCrypto.generateEd25519KeyPair()
        val keys = listOf(signingKey("s1", s1), signingKey("s2", s2))
        val payload = JCbor.encode(
            JCbor.tuple(
                JCbor.vtext("linkkeys-key-revocation-v1alpha"),
                JCbor.vtext("target"),
                JCbor.vtext("fp"),
                JCbor.vint(t.epochSecond),
                JCbor.vtext("example.com"),
            ),
        )
        val sigs = listOf(
            ClaimSignature("example.com", "s1", JCrypto.signEd25519(payload, s1.privateKeySeed())),
            ClaimSignature("example.com", "s2", JCrypto.signEd25519(payload, s2.privateKeySeed())),
        )
        assertDoesNotThrow { Revocations.verify(RevocationCertificate("target", "fp", t, sigs), keys, "example.com") }
        assertThrows(LocalRpException.Revocation::class.java) {
            Revocations.verify(RevocationCertificate("target", "fp", t.plusNanos(1), sigs), keys, "example.com")
        }
    }
}
