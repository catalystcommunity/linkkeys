using LinkKeys.LocalRp.Tests.TestUtil;
using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp.Tests;

/// <summary>
/// Conformance vectors: <c>claims.json</c> — Claim wire encoding and claim-signature
/// verification. The trap this file exists to catch: <c>Claim.claim_value</c> is CBOR
/// bytes (bstr), never text (tstr), both on the wire and inside the signed payload. An
/// SDK that gets this wrong passes its own self-tests (sign-wrong/verify-wrong is
/// self-consistent) and only cross-implementation vectors expose it.
/// </summary>
public class ClaimsConformanceTests
{
    private static List<Claims.DomainKeySet> ParseDomainKeySets(System.Text.Json.JsonElement arr)
    {
        var groups = new Dictionary<string, List<DomainPublicKey>>();
        foreach (var k in arr.AsArray())
        {
            var domain = k.Get("domain").AsString();
            var key = new DomainPublicKey(
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

            if (!groups.TryGetValue(domain, out var list))
            {
                list = new List<DomainPublicKey>();
                groups[domain] = list;
            }

            list.Add(key);
        }

        return groups.Select(kv => new Claims.DomainKeySet(kv.Key, kv.Value)).ToList();
    }

    [Fact]
    public void PositiveCasesRoundTripByteExactAndVerifyIndependently()
    {
        var d = Fixtures.Load("claims.json");
        Assert.Equal("linkkeys-claim-v2", d.Get("tag").AsString());
        Assert.Equal(
            "CBOR([tag, claim_id, claim_type, claim_value(bstr), 'user_id@subject_domain', signing_domain, expires_at_or_null, attested_at])",
            d.Get("payload_layout").AsString());

        var defaultDomainKeys = ParseDomainKeySets(d.Get("domain_keys"));
        var cases = d.Get("cases").AsArray().ToList();
        Assert.Equal(3, cases.Count);

        foreach (var c in cases)
        {
            Assert.True(c.Get("expected_valid").AsBoolean());
            var subjectDomain = c.Get("subject_domain").AsString();
            var claimCbor = Fixtures.Hex(c.Get("claim_cbor_hex").AsString());

            // Byte-exact wire round trip: decode then re-encode reproduces the exact bytes.
            var claim = Codec.DecodeClaim(claimCbor);
            Assert.Equal(claimCbor, Codec.EncodeClaim(claim));

            var claimJson = c.Get("claim");
            Assert.Equal(claimJson.Get("claim_id").AsString(), claim.ClaimId);
            Assert.Equal(claimJson.Get("user_id").AsString(), claim.UserId);
            Assert.Equal(claimJson.Get("claim_type").AsString(), claim.ClaimType);
            Assert.Equal(Fixtures.Hex(claimJson.Get("claim_value_hex").AsString()), claim.ClaimValue);
            Assert.Equal(claimJson.Get("attested_at").AsString(), claim.AttestedAt);
            Assert.Equal(claimJson.Get("created_at").AsString(), claim.CreatedAt);
            Assert.Equal(claimJson.GetStringOrNull("expires_at"), claim.ExpiresAt);
            Assert.Equal(claimJson.GetStringOrNull("revoked_at"), claim.RevokedAt);

            var sigJsonList = claimJson.Get("signatures").AsArray().ToList();
            Assert.Equal(sigJsonList.Count, claim.Signatures.Count);
            for (int i = 0; i < sigJsonList.Count; i++)
            {
                var sigJson = sigJsonList[i];
                var sig = claim.Signatures[i];
                Assert.Equal(sigJson.Get("domain").AsString(), sig.Domain);
                Assert.Equal(sigJson.Get("signed_by_key_id").AsString(), sig.SignedByKeyId);
                Assert.Equal(Fixtures.Hex(sigJson.Get("signature_hex").AsString()), sig.Signature);

                var expectedPayload = Fixtures.Hex(sigJson.Get("signed_payload_cbor_hex").AsString());

                // Recompute the signed-payload bytes independently from the decoded claim
                // (not by trusting the fixture's own precomputed bytes) and confirm the SDK's
                // construction matches, then Ed25519-verify against it.
                var computedPayload = Claims.ClaimSignPayload(
                    claim.ClaimId, claim.ClaimType, claim.ClaimValue, claim.UserId, subjectDomain,
                    sig.Domain, claim.ExpiresAt, claim.AttestedAt);
                Assert.Equal(expectedPayload, computedPayload);

                var pubKey = defaultDomainKeys
                    .First(s => s.Domain == sig.Domain).Keys
                    .First(k => k.KeyId == sig.SignedByKeyId).PublicKey;
                Assert.True(Crypto.Crypto.VerifyEd25519(computedPayload, sig.Signature, pubKey));
            }

            // Through the SDK's own claim-verification path — exactly what CompleteLocalLogin uses.
            Claims.VerifyClaim(claim, subjectDomain, defaultDomainKeys);
        }
    }

    [Fact]
    public void NegativeCasesFailVerificationWithExpectedErrorKind()
    {
        var d = Fixtures.Load("claims.json");
        var defaultDomainKeys = ParseDomainKeySets(d.Get("domain_keys"));
        var cases = d.Get("negative_cases").AsArray().ToList();
        Assert.Equal(4, cases.Count);

        var expectedKinds = new Dictionary<string, ClaimError.ErrorKind>
        {
            ["signature_invalid"] = ClaimError.ErrorKind.SignatureInvalid,
            ["key_not_found"] = ClaimError.ErrorKind.KeyNotFound,
        };

        foreach (var c in cases)
        {
            var name = c.Get("name").AsString();
            var subjectDomain = c.Get("subject_domain").AsString();
            var claimCbor = Fixtures.Hex(c.Get("claim_cbor_hex").AsString());
            var claim = Codec.DecodeClaim(claimCbor);

            var domainKeysOverride = c.GetOrNull("domain_keys");
            var domainKeys = domainKeysOverride is { } dk ? ParseDomainKeySets(dk) : defaultDomainKeys;

            var expectedErrorName = c.Get("expected_error").AsString();
            Assert.True(
                expectedKinds.TryGetValue(expectedErrorName, out var expectedKind),
                $"case '{name}': unmapped expected_error '{expectedErrorName}'");

            var err = Assert.Throws<ClaimError>(() => Claims.VerifyClaim(claim, subjectDomain, domainKeys));
            Assert.True(expectedKind == err.Kind, $"case '{name}': expected {expectedKind}, got {err.Kind}");
        }
    }

    [Fact]
    public void DecodeNegativeCasesRejectCborTextClaimValue()
    {
        var d = Fixtures.Load("claims.json");
        var cases = d.Get("decode_negative_cases").AsArray().ToList();
        Assert.Single(cases);

        foreach (var c in cases)
        {
            Assert.False(c.Get("expected_decode_ok").AsBoolean());
            var claimCbor = Fixtures.Hex(c.Get("claim_cbor_hex").AsString());

            // CSIL declares claim_value as bytes (bstr). A claim wire message carrying it as
            // CBOR text (tstr) must be REJECTED at decode time, not silently accepted.
            Assert.Throws<Cbor.CborDecodeException>(() => Codec.DecodeClaim(claimCbor));
        }
    }

    [Fact]
    public void TicketRedemptionResponseRoundTripsAndEmbeddedClaimsVerify()
    {
        var d = Fixtures.Load("claims.json");
        var defaultDomainKeys = ParseDomainKeySets(d.Get("domain_keys"));
        var fixture = d.Get("ticket_redemption_response");
        var responseCbor = Fixtures.Hex(fixture.Get("response_cbor_hex").AsString());

        // This is the wire message complete_local_login actually consumes Claims from.
        var response = Codec.DecodeLocalRpTicketRedemptionResponse(responseCbor);
        Assert.Equal(responseCbor, Codec.EncodeLocalRpTicketRedemptionResponse(response));

        Assert.Equal(fixture.Get("user_id").AsString(), response.UserId);
        Assert.Equal(fixture.Get("user_domain").AsString(), response.UserDomain);
        Assert.Equal(fixture.Get("ticket_expires_at").AsString(), response.TicketExpiresAt);
        Assert.Equal(3, response.Claims.Count);

        // Decoding without verifying fails the point: verify every embedded claim's
        // signatures through the same SDK path CompleteLocalLogin uses.
        foreach (var claim in response.Claims)
        {
            Claims.VerifyClaim(claim, response.UserDomain, defaultDomainKeys);
        }
    }
}
