using LinkKeys.LocalRp.Tests.TestUtil;

namespace LinkKeys.LocalRp.Tests;

/// <summary>Conformance vectors: <c>envelopes.json</c> — the four signature contexts.</summary>
public class EnvelopesConformanceTests
{
    private static void CheckCase(System.Text.Json.JsonElement c, bool expectValid)
    {
        var context = c.Get("context").AsString();
        var payload = Fixtures.Hex(c.Get("payload_cbor_hex").AsString());
        var expectedSigInput = Fixtures.Hex(c.Get("signature_input_cbor_hex").AsString());
        var signature = Fixtures.Hex(c.Get("signature_hex").AsString());
        var verifyKey = Fixtures.Hex(c.Get("verify_key_hex").AsString());

        var computedSigInput = LocalRp.EnvelopeSignatureInput(context, payload);
        Assert.Equal(expectedSigInput, computedSigInput);

        var valid = Crypto.Crypto.VerifyEd25519(computedSigInput, signature, verifyKey);
        Assert.Equal(expectValid, valid);
    }

    [Fact]
    public void PositiveCasesVerify()
    {
        var d = Fixtures.Load("envelopes.json");
        var cases = d.Get("cases").AsArray().ToList();
        Assert.Equal(4, cases.Count);
        foreach (var c in cases)
        {
            Assert.True(c.Get("expected_valid").AsBoolean());
            CheckCase(c, true);
        }
    }

    [Fact]
    public void NegativeCasesFail()
    {
        var d = Fixtures.Load("envelopes.json");
        var cases = d.Get("negative_cases").AsArray().ToList();
        Assert.Equal(20, cases.Count);
        foreach (var c in cases)
        {
            Assert.False(c.Get("expected_valid").AsBoolean());
            CheckCase(c, false);
        }
    }

    [Fact]
    public void ContextStringsMatchTheFourConstants()
    {
        var d = Fixtures.Load("envelopes.json").Get("context_strings");
        Assert.Equal(LocalRp.CtxLocalRpDescriptor, d.Get("descriptor").AsString());
        Assert.Equal(LocalRp.CtxLocalRpLoginRequest, d.Get("login_request").AsString());
        Assert.Equal(LocalRp.CtxLocalRpCallback, d.Get("callback_payload").AsString());
        Assert.Equal(LocalRp.CtxLocalRpTicketRedemption, d.Get("ticket_redemption").AsString());
    }
}
