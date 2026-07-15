package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.testutil.Fixtures;
import community.catalyst.linkkeys.localrp.testutil.MiniJson.JsonValue;
import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.Claim;
import community.catalyst.linkkeys.localrp.wire.Types.ClaimSignature;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpTicketRedemptionResponse;

/**
 * Conformance vectors: {@code claims.json} &mdash; {@code Claim} wire
 * encoding and claim-signature verification (design doc's discriminator for
 * the {@code claim_value} bstr-vs-tstr trap: an SDK that wires it as text
 * passes its own self-tests and only these cross-implementation vectors
 * expose the bug). Every case is driven through this SDK's own verification
 * path ({@link Claims}), the same path {@link Complete} uses.
 */
class ClaimsConformanceTest {

    private static DomainPublicKey parseDomainKey(JsonValue k) {
        return new DomainPublicKey(
                k.get("key_id").asString(),
                Fixtures.hex(k.get("public_key_hex").asString()),
                k.get("fingerprint_hex").asString(),
                k.get("algorithm").asString(),
                k.get("key_usage").asString(),
                k.get("created_at").asString(),
                k.get("expires_at").asString(),
                k.getStringOrNull("revoked_at"),
                null,
                null);
    }

    /** Group a flat {@code domain_keys} JSON array into {@link Claims.DomainKeySet}s by their {@code domain} field. */
    private static List<Claims.DomainKeySet> parseDomainKeySets(JsonValue domainKeysArray) {
        Map<String, List<DomainPublicKey>> byDomain = new LinkedHashMap<>();
        for (JsonValue k : domainKeysArray.asArray()) {
            byDomain.computeIfAbsent(k.get("domain").asString(), d -> new ArrayList<>()).add(parseDomainKey(k));
        }
        List<Claims.DomainKeySet> out = new ArrayList<>();
        for (Map.Entry<String, List<DomainPublicKey>> e : byDomain.entrySet()) {
            out.add(new Claims.DomainKeySet(e.getKey(), e.getValue()));
        }
        return out;
    }

    private static ClaimError.Kind expectedKind(String s) {
        return switch (s) {
            case "signature_invalid" -> ClaimError.Kind.SIGNATURE_INVALID;
            case "key_not_found" -> ClaimError.Kind.KEY_NOT_FOUND;
            default -> throw new IllegalArgumentException("unmapped expected_error: " + s);
        };
    }

    @Test
    void positiveCasesRoundTripByteExactlyAndVerify() {
        JsonValue d = Fixtures.load("claims.json");
        assertEquals("linkkeys-claim-v2", d.get("tag").asString());
        String fileSubjectDomain = d.get("subject_domain").asString();
        List<Claims.DomainKeySet> defaultDomainKeys = parseDomainKeySets(d.get("domain_keys"));

        List<JsonValue> cases = d.get("cases").asArray();
        assertEquals(3, cases.size());

        for (JsonValue c : cases) {
            String name = c.get("name").asString();
            assertTrue(c.get("expected_valid").asBoolean(), name);
            String subjectDomain = c.get("subject_domain").asString();
            assertEquals(fileSubjectDomain, subjectDomain, name);

            byte[] claimBytes = Fixtures.hex(c.get("claim_cbor_hex").asString());
            Claim claim = Codec.decodeClaim(claimBytes);
            assertArrayEquals(claimBytes, Codec.encodeClaim(claim), name + ": byte-exact re-encode");

            JsonValue claimJson = c.get("claim");
            assertEquals(claimJson.get("claim_id").asString(), claim.claimId(), name);
            assertEquals(claimJson.get("user_id").asString(), claim.userId(), name);
            assertEquals(claimJson.get("claim_type").asString(), claim.claimType(), name);
            assertArrayEquals(
                    Fixtures.hex(claimJson.get("claim_value_hex").asString()),
                    claim.claimValue(),
                    name + ": claim_value must be wire bytes (bstr), not CBOR text");
            assertEquals(claimJson.get("attested_at").asString(), claim.attestedAt(), name);
            assertEquals(claimJson.get("created_at").asString(), claim.createdAt(), name);
            assertEquals(claimJson.getStringOrNull("expires_at"), claim.expiresAt(), name);
            assertEquals(claimJson.getStringOrNull("revoked_at"), claim.revokedAt(), name);

            List<JsonValue> sigJsons = claimJson.get("signatures").asArray();
            assertEquals(sigJsons.size(), claim.signatures().size(), name);
            for (int i = 0; i < sigJsons.size(); i++) {
                JsonValue sigJson = sigJsons.get(i);
                ClaimSignature sig = claim.signatures().get(i);
                String signingDomain = sigJson.get("domain").asString();
                assertEquals(signingDomain, sig.domain(), name);
                assertEquals(sigJson.get("signed_by_key_id").asString(), sig.signedByKeyId(), name);
                assertArrayEquals(Fixtures.hex(sigJson.get("signature_hex").asString()), sig.signature(), name);

                // Re-derive the exact 8-element signed-payload array this SDK would sign/verify
                // over and confirm it matches the vector byte-for-byte.
                byte[] expectedPayload = Fixtures.hex(sigJson.get("signed_payload_cbor_hex").asString());
                byte[] computedPayload = Claims.claimSignPayload(
                        claim.claimId(),
                        claim.claimType(),
                        claim.claimValue(),
                        claim.userId(),
                        subjectDomain,
                        signingDomain,
                        claim.expiresAt(),
                        claim.attestedAt());
                assertArrayEquals(expectedPayload, computedPayload, name + ": signed_payload_cbor_hex mismatch");
            }

            // Through the SDK's own claim verification path, as the Complete flow uses.
            Claims.verifyClaim(claim, subjectDomain, defaultDomainKeys);
        }
    }

    @Test
    void negativeCasesFailWithExpectedErrorKind() {
        JsonValue d = Fixtures.load("claims.json");
        List<Claims.DomainKeySet> defaultDomainKeys = parseDomainKeySets(d.get("domain_keys"));
        List<JsonValue> cases = d.get("negative_cases").asArray();
        assertEquals(4, cases.size());

        for (JsonValue c : cases) {
            String name = c.get("name").asString();
            byte[] claimBytes = Fixtures.hex(c.get("claim_cbor_hex").asString());
            Claim claim = Codec.decodeClaim(claimBytes);
            String subjectDomain = c.get("subject_domain").asString();
            JsonValue override = c.getOrNull("domain_keys");
            List<Claims.DomainKeySet> domainKeys = override == null ? defaultDomainKeys : parseDomainKeySets(override);
            ClaimError.Kind expected = expectedKind(c.get("expected_error").asString());

            ClaimError err = assertThrows(
                    ClaimError.class,
                    () -> Claims.verifyClaimSignatures(claim, subjectDomain, domainKeys),
                    name + " unexpectedly verified");
            assertEquals(expected, err.kind(), name);
        }
    }

    @Test
    void decodeNegativeCaseRejectsClaimValueEncodedAsCborText() {
        JsonValue d = Fixtures.load("claims.json");
        List<JsonValue> cases = d.get("decode_negative_cases").asArray();
        assertEquals(1, cases.size());

        for (JsonValue c : cases) {
            String name = c.get("name").asString();
            assertFalse(c.get("expected_decode_ok").asBoolean(), name);
            byte[] claimBytes = Fixtures.hex(c.get("claim_cbor_hex").asString());
            assertThrows(
                    Cbor.CborDecodeException.class,
                    () -> Codec.decodeClaim(claimBytes),
                    name + ": a tstr claim_value must be rejected by a strict bstr codec");
        }
    }

    @Test
    void ticketRedemptionResponseRoundTripsAndEmbeddedClaimsVerify() {
        JsonValue d = Fixtures.load("claims.json");
        List<Claims.DomainKeySet> defaultDomainKeys = parseDomainKeySets(d.get("domain_keys"));
        JsonValue t = d.get("ticket_redemption_response");

        byte[] responseBytes = Fixtures.hex(t.get("response_cbor_hex").asString());
        LocalRpTicketRedemptionResponse resp = Codec.decodeLocalRpTicketRedemptionResponse(responseBytes);

        assertEquals(t.get("user_id").asString(), resp.userId());
        assertEquals(t.get("user_domain").asString(), resp.userDomain());
        assertEquals(t.get("ticket_expires_at").asString(), resp.ticketExpiresAt());
        assertEquals(3, resp.claims().size());

        assertArrayEquals(
                responseBytes,
                Codec.encodeLocalRpTicketRedemptionResponse(resp),
                "LocalRpTicketRedemptionResponse byte-exact re-encode");

        // Decoding without verifying fails the point: verify every embedded claim
        // through the same path complete_local_login's caller would use.
        for (Claim claim : resp.claims()) {
            Claims.verifyClaim(claim, resp.userDomain(), defaultDomainKeys);
        }
    }
}
