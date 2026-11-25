package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.crypto.Hex;
import community.catalyst.linkkeys.localrp.dns.Dns;
import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.Claim;
import community.catalyst.linkkeys.localrp.wire.Types.ClaimSignature;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;
import community.catalyst.linkkeys.localrp.wire.Types.RevocationCertificate;

/** CSIL wire rules: tag-0 timestamps, named-number enums, and whole-second signed times. */
class WireFormatTest {
    private static final Instant T = Instant.parse("2026-01-01T00:10:00Z");

    private static DomainPublicKey key(String algorithm, String usage, Instant expiresAt) {
        return new DomainPublicKey(
                "k1", new byte[32], "fp", algorithm, usage, T, expiresAt, null, null, null);
    }

    // -----------------------------------------------------------------
    // Timestamps
    // -----------------------------------------------------------------

    @Test
    void timestampIsTagZeroUtcText() {
        // c0 = tag 0, 74 = text(20), then "2026-01-01T00:10:00Z".
        assertEquals("c074" + Hex.encode("2026-01-01T00:10:00Z".getBytes()), Hex.encode(Cbor.encode(Cbor.vtimestamp(T))));
    }

    @Test
    void timestampFractionIsWrittenInGroupsOfThree() {
        assertEquals("2026-10-06T12:05:07.250Z", Cbor.formatRfc3339(Instant.parse("2026-10-06T12:05:07.25Z")));
        assertEquals("2026-10-06T12:05:00Z", Cbor.formatRfc3339(Instant.parse("2026-10-06T12:05:00Z")));
    }

    @Test
    void timestampDecodeNormalizesOffsetsToUtc() {
        Cbor.Value v = Cbor.vtag(0, Cbor.vtext("2026-01-01T01:10:00+01:00"));
        assertEquals(T, Cbor.asTimestamp(v));
    }

    @Test
    void untaggedTimestampTextIsRefused() {
        assertThrows(Cbor.CborDecodeException.class, () -> Cbor.asTimestamp(Cbor.vtext("2026-01-01T00:10:00Z")));
    }

    @Test
    void wrongTagIsRefused() {
        assertThrows(
                Cbor.CborDecodeException.class,
                () -> Cbor.asTimestamp(Cbor.vtag(1, Cbor.vtext("2026-01-01T00:10:00Z"))));
        assertThrows(Cbor.CborDecodeException.class, () -> Cbor.asTimestamp(Cbor.vtag(0, Cbor.vint(1767226200))));
    }

    @Test
    void nonRfc3339TextIsRefused() {
        for (String bad : List.of(
                "2026-01-01T00:10Z", // no seconds
                "2026-01-01T00:10:00", // no offset
                "2026-01-01", // date only
                "2026-13-01T00:10:00Z", // month 13
                "not a time")) {
            assertNull(Cbor.parseRfc3339(bad), bad);
            assertThrows(Cbor.CborDecodeException.class, () -> Cbor.asTimestamp(Cbor.vtag(0, Cbor.vtext(bad))), bad);
        }
    }

    @Test
    void domainKeyWithUntaggedTimeFailsToDecode() {
        byte[] good = Codec.encodeDomainPublicKey(key("ed25519", "sign", T));
        Codec.decodeDomainPublicKey(good);
        List<Cbor.Entry> entries = new ArrayList<>();
        for (Cbor.Entry e : ((Cbor.VMap) Cbor.decode(good)).entries()) {
            boolean expires = e.key() instanceof Cbor.VText t && t.value().equals("expires_at");
            entries.add(expires ? Cbor.entry("expires_at", Cbor.vtext("2026-01-01T00:10:00Z")) : e);
        }
        byte[] untagged = Cbor.encode(Cbor.vmap(entries));
        assertThrows(RuntimeException.class, () -> Codec.decodeDomainPublicKey(untagged));
    }

    // -----------------------------------------------------------------
    // Enums
    // -----------------------------------------------------------------

    @Test
    void enumNumbersMatchTheCsil() {
        assertEquals(1, Cbor.KEY_ALGORITHM.number("ed25519"));
        assertEquals(2, Cbor.KEY_ALGORITHM.number("x25519"));
        assertEquals(1, Cbor.KEY_USAGE.number("sign"));
        assertEquals(2, Cbor.KEY_USAGE.number("encrypt"));
        assertEquals(3, Cbor.KEY_USAGE.number("agree"));
        assertEquals(1, Cbor.AEAD_SUITE.number("aes-256-gcm"));
        assertEquals(2, Cbor.AEAD_SUITE.number("chacha20-poly1305"));
    }

    @Test
    void domainKeyEnumsAreUnsignedIntegersOnTheWire() {
        Cbor.Value m = Cbor.decode(Codec.encodeDomainPublicKey(key("ed25519", "encrypt", T)));
        assertEquals(1, Cbor.asInt(Cbor.require(m, "algorithm")));
        assertEquals(2, Cbor.asInt(Cbor.require(m, "key_usage")));
    }

    @Test
    void unknownEnumNumberIsRefused() {
        assertThrows(Cbor.CborDecodeException.class, () -> Cbor.KEY_USAGE.decode(Cbor.vint(9)));
        assertThrows(Cbor.CborDecodeException.class, () -> Cbor.AEAD_SUITE.decode(Cbor.vint(3)));
        assertThrows(Cbor.CborDecodeException.class, () -> Cbor.AEAD_SUITE.decode(Cbor.vint(0)));
        // The text label is not the wire form any more.
        assertThrows(Cbor.CborDecodeException.class, () -> Cbor.AEAD_SUITE.decode(Cbor.vtext("aes-256-gcm")));
        assertThrows(IllegalArgumentException.class, () -> Cbor.KEY_ALGORITHM.number("rsa"));
    }

    // -----------------------------------------------------------------
    // Signed tuple times
    // -----------------------------------------------------------------

    @Test
    void signedTimeIsWholeUnixSeconds() {
        assertEquals(T.getEpochSecond(), Cbor.asInt(Cbor.signedTime(T)));
        assertThrows(IllegalArgumentException.class, () -> Cbor.signedTime(T.plusMillis(500)));
    }

    @Test
    void fractionalClaimTimeFailsVerificationAndIsNotRounded() {
        Crypto.Ed25519KeyPair signer = Crypto.generateEd25519KeyPair();
        DomainPublicKey signerKey = new DomainPublicKey(
                "k1", signer.publicKey(), Crypto.fingerprint(signer.publicKey()), "ed25519", "sign", T,
                Instant.now().plusSeconds(3600), null, null, null);
        Claims.ClaimSpec spec = new Claims.ClaimSpec("c1", "handle", new byte[] {1}, "u1", "example.com", null, T);
        Claim claim = Claims.signClaim(
                spec, List.of(new Claims.ClaimSigner("example.com", "k1", signer.privateKeySeed())));
        List<Claims.DomainKeySet> keys = List.of(new Claims.DomainKeySet("example.com", List.of(signerKey)));
        Claims.verifyClaim(claim, "example.com", keys);

        // Same signature, attested_at moved by half a second. Rounding down would make it verify.
        Claim fractional = new Claim(
                claim.claimId(), claim.userId(), claim.claimType(), claim.claimValue(), claim.signatures(),
                T.plusMillis(500), claim.createdAt(), null, null);
        ClaimError e = assertThrows(ClaimError.class, () -> Claims.verifyClaim(fractional, "example.com", keys));
        assertEquals(ClaimError.Kind.BAD_TIMESTAMP, e.kind());

        // Signing a fractional time is refused too.
        Claims.ClaimSpec fractionalSpec =
                new Claims.ClaimSpec("c1", "handle", new byte[] {1}, "u1", "example.com", null, T.plusMillis(500));
        assertThrows(
                ClaimError.class,
                () -> Claims.signClaim(
                        fractionalSpec, List.of(new Claims.ClaimSigner("example.com", "k1", signer.privateKeySeed()))));
    }

    @Test
    void fractionalRevocationTimeCountsNoSigners() {
        Instant later = Instant.now().plusSeconds(3600);
        Crypto.Ed25519KeyPair s1 = Crypto.generateEd25519KeyPair();
        Crypto.Ed25519KeyPair s2 = Crypto.generateEd25519KeyPair();
        List<DomainPublicKey> keys = List.of(
                new DomainPublicKey("s1", s1.publicKey(), "fp1", "ed25519", "sign", T, later, null, null, null),
                new DomainPublicKey("s2", s2.publicKey(), "fp2", "ed25519", "sign", T, later, null, null, null));
        byte[] payload = Revocation.revocationPayload("target", "fp", T, "example.com");
        List<ClaimSignature> sigs = List.of(
                new ClaimSignature("example.com", "s1", Crypto.signEd25519(payload, s1.privateKeySeed())),
                new ClaimSignature("example.com", "s2", Crypto.signEd25519(payload, s2.privateKeySeed())));
        assertEquals(2, Revocation.countValidSigners(new RevocationCertificate("target", "fp", T, sigs), keys, "example.com"));
        RevocationCertificate fractional = new RevocationCertificate("target", "fp", T.plusNanos(1), sigs);
        assertEquals(0, Revocation.countValidSigners(fractional, keys, "example.com"));
    }

    @Test
    void fractionalKeyVouchExpiryIsRefused() {
        Crypto.Ed25519KeyPair signing = Crypto.generateEd25519KeyPair();
        DomainPublicKey signingKey = new DomainPublicKey(
                "k1", signing.publicKey(), Crypto.fingerprint(signing.publicKey()), "ed25519", "sign", T,
                Instant.parse("2126-01-01T00:00:00Z"), null, null, null);
        byte[] encPublic = Crypto.generateX25519KeyPair().publicKey();
        Instant expires = Instant.parse("2126-01-01T00:00:00Z");
        byte[] vouchPayload = Cbor.encode(Cbor.tuple(
                Cbor.vtext("linkkeys-key-vouch-v1alpha"),
                Cbor.vtext(Crypto.fingerprint(encPublic)),
                Cbor.vint(expires.getEpochSecond())));
        byte[] vouch = Crypto.signEd25519(vouchPayload, signing.privateKeySeed());
        DomainPublicKey enc = new DomainPublicKey(
                "e1", encPublic, Crypto.fingerprint(encPublic), "x25519", "encrypt", T, expires, null, "k1", vouch);
        assertTrue(Dns.verifyKeyVouch(enc, signingKey));
        DomainPublicKey fractional = new DomainPublicKey(
                "e1", encPublic, Crypto.fingerprint(encPublic), "x25519", "encrypt", T, expires.plusMillis(500), null,
                "k1", vouch);
        assertFalse(Dns.verifyKeyVouch(fractional, signingKey));
    }
}
