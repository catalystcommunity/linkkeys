using LinkKeys.LocalRp.Tests.TestUtil;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp.Tests;

/// <summary>
/// Conformance vectors: <c>revocations.json</c> — sibling-signed key revocation
/// certificates.
/// </summary>
public class RevocationsConformanceTests
{
    private static DomainPublicKey ParseDomainKey(System.Text.Json.JsonElement k) => new(
        k.Get("key_id").AsString(),
        Fixtures.Hex(k.Get("public_key_hex").AsString()),
        k.Get("fingerprint_hex").AsString(),
        k.Get("algorithm").AsString(),
        k.Get("key_usage").AsString(),
        k.Get("created_at").AsString(),
        k.Get("expires_at").AsString(),
        k.GetStringOrNull("revoked_at"),
        null,
        null);

    private static RevocationCertificate ParseCertificate(System.Text.Json.JsonElement certNode)
    {
        var signatures = new List<ClaimSignature>();
        foreach (var s in certNode.Get("signatures").AsArray())
        {
            signatures.Add(new ClaimSignature(
                s.Get("domain").AsString(),
                s.Get("signed_by_key_id").AsString(),
                Fixtures.Hex(s.Get("signature_hex").AsString())));
        }

        return new RevocationCertificate(
            certNode.Get("target_key_id").AsString(),
            certNode.Get("target_fingerprint").AsString(),
            certNode.Get("revoked_at").AsString(),
            signatures);
    }

    [Fact]
    public void CertificateCasesMatchExpectedValidityAndCountedSigners()
    {
        var d = Fixtures.Load("revocations.json");
        Assert.Equal(2, d.Get("quorum").AsLong());
        Assert.Equal("linkkeys-key-revocation-v1", d.Get("tag").AsString());

        var domainKeys = d.Get("domain_keys").AsArray().Select(ParseDomainKey).ToList();

        var cases = d.Get("certificate_cases").AsArray().ToList();
        Assert.Equal(9, cases.Count);

        foreach (var c in cases)
        {
            var name = c.Get("name").AsString();
            var cert = ParseCertificate(c.Get("certificate"));
            var verifyDomain = c.Get("verify_domain").AsString();
            var expectedValid = c.Get("expected_valid").AsBoolean();
            var expectedCounted = c.Get("expected_counted_signers").AsLong();

            var counted = Revocation.CountValidSigners(cert, domainKeys, verifyDomain);
            Assert.Equal(expectedCounted, counted);

            if (expectedValid)
            {
                Revocation.VerifyRevocationCertificate(cert, domainKeys, verifyDomain);
            }
            else
            {
                Assert.Throws<RevocationError>(() => Revocation.VerifyRevocationCertificate(cert, domainKeys, verifyDomain));
            }
        }
    }

    [Fact]
    public void ApplicationCaseRevocationIsAppliedToTheKeySet()
    {
        var d = Fixtures.Load("revocations.json");
        var domain = d.Get("domain").AsString();

        var domainKeys = d.Get("domain_keys").AsArray().Select(ParseDomainKey).ToList();

        var quorumCase = d.Get("certificate_cases").AsArray().First(c => c.Get("name").AsString() == "valid_quorum_two_siblings");
        var cert = ParseCertificate(quorumCase.Get("certificate"));

        var app = d.Get("application_case");
        var envelope = app.Get("envelope");
        var signedPayload = new SignedLocalRpCallbackPayload(
            Fixtures.Hex(envelope.Get("payload_cbor_hex").AsString()),
            envelope.Get("signing_key_id").AsString(),
            Fixtures.Hex(envelope.Get("signature_hex").AsString()));
        var verifyNow = DateTimeOffset.Parse(app.Get("verify_now").AsString());
        var skew = app.Get("clock_skew_seconds").AsLong();

        // Before applying the revocation certificate: the fetched key list shows the
        // target key with no revoked_at, so the envelope verifies.
        LocalRp.VerifyLocalRpCallbackPayload(signedPayload, domainKeys, verifyNow, skew);

        // Apply the quorum-verified certificate exactly as Complete/RpcClient would:
        // verify it, then drop its target from the trusted key set.
        Revocation.VerifyRevocationCertificate(cert, domainKeys, domain);
        var afterRevocation = domainKeys.Where(k => k.KeyId != cert.TargetKeyId).ToList();

        // After applying: the same envelope must fail signature/key-lookup
        // verification, because its signing key is no longer in the trusted set.
        Assert.Throws<LocalRpError>(() => LocalRp.VerifyLocalRpCallbackPayload(signedPayload, afterRevocation, verifyNow, skew));
    }
}
