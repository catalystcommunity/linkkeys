package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.testutil.Fixtures;
import community.catalyst.linkkeys.localrp.testutil.MiniJson.JsonValue;
import community.catalyst.linkkeys.localrp.wire.Types.ClaimSignature;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;
import community.catalyst.linkkeys.localrp.wire.Types.RevocationCertificate;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpCallbackPayload;

/**
 * Conformance vectors: {@code revocations.json} &mdash; sibling-signed key
 * revocation certificates (design doc: "extension landing in parallel";
 * see {@code sdks/local-rp/go/revocation.go} for the compact reference this
 * SDK's {@link Revocation} mirrors).
 */
class RevocationsConformanceTest {

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

    private static RevocationCertificate parseCertificate(JsonValue certNode) {
        List<ClaimSignature> signatures = new ArrayList<>();
        for (JsonValue s : certNode.get("signatures").asArray()) {
            signatures.add(new ClaimSignature(
                    s.get("domain").asString(),
                    s.get("signed_by_key_id").asString(),
                    Fixtures.hex(s.get("signature_hex").asString())));
        }
        return new RevocationCertificate(
                certNode.get("target_key_id").asString(),
                certNode.get("target_fingerprint").asString(),
                certNode.get("revoked_at").asString(),
                signatures);
    }

    @Test
    void certificateCasesMatchExpectedValidityAndCountedSigners() {
        JsonValue d = Fixtures.load("revocations.json");
        assertEquals(2, d.get("quorum").asLong());
        assertEquals("linkkeys-key-revocation-v1", d.get("tag").asString());

        List<DomainPublicKey> domainKeys = new ArrayList<>();
        for (JsonValue k : d.get("domain_keys").asArray()) {
            domainKeys.add(parseDomainKey(k));
        }

        List<JsonValue> cases = d.get("certificate_cases").asArray();
        assertEquals(9, cases.size());

        for (JsonValue c : cases) {
            String name = c.get("name").asString();
            RevocationCertificate cert = parseCertificate(c.get("certificate"));
            String verifyDomain = c.get("verify_domain").asString();
            boolean expectedValid = c.get("expected_valid").asBoolean();
            long expectedCounted = c.get("expected_counted_signers").asLong();

            int counted = Revocation.countValidSigners(cert, domainKeys, verifyDomain);
            assertEquals(expectedCounted, counted, "expected_counted_signers mismatch for " + name);

            if (expectedValid) {
                Revocation.verifyRevocationCertificate(cert, domainKeys, verifyDomain);
            } else {
                assertThrows(
                        RevocationError.class,
                        () -> Revocation.verifyRevocationCertificate(cert, domainKeys, verifyDomain),
                        name + " unexpectedly verified");
            }
        }
    }

    @Test
    void applicationCaseRevocationIsAppliedToTheKeySet() {
        JsonValue d = Fixtures.load("revocations.json");
        String domain = d.get("domain").asString();

        List<DomainPublicKey> domainKeys = new ArrayList<>();
        for (JsonValue k : d.get("domain_keys").asArray()) {
            domainKeys.add(parseDomainKey(k));
        }

        JsonValue quorumCase = d.get("certificate_cases").asArray().stream()
                .filter(c -> c.get("name").asString().equals("valid_quorum_two_siblings"))
                .findFirst()
                .orElseThrow();
        RevocationCertificate cert = parseCertificate(quorumCase.get("certificate"));

        JsonValue app = d.get("application_case");
        JsonValue envelope = app.get("envelope");
        SignedLocalRpCallbackPayload signedPayload = new SignedLocalRpCallbackPayload(
                Fixtures.hex(envelope.get("payload_cbor_hex").asString()),
                envelope.get("signing_key_id").asString(),
                Fixtures.hex(envelope.get("signature_hex").asString()));
        Instant verifyNow = OffsetDateTime.parse(app.get("verify_now").asString()).toInstant();
        long skew = app.get("clock_skew_seconds").asLong();

        // Before applying the revocation certificate: the fetched key list
        // shows the target key with no revoked_at, so the envelope verifies.
        LocalRp.verifyLocalRpCallbackPayload(signedPayload, domainKeys, verifyNow, skew);

        // Apply the quorum-verified certificate exactly as
        // Complete/RpcClient would: verify it, then drop its target from
        // the trusted key set.
        Revocation.verifyRevocationCertificate(cert, domainKeys, domain);
        List<DomainPublicKey> afterRevocation = domainKeys.stream()
                .filter(k -> !k.keyId().equals(cert.targetKeyId()))
                .toList();

        // After applying: the same envelope must fail signature/key-lookup
        // verification, because its signing key is no longer in the trusted
        // set.
        assertThrows(
                LocalRpError.class,
                () -> LocalRp.verifyLocalRpCallbackPayload(signedPayload, afterRevocation, verifyNow, skew));
    }
}
