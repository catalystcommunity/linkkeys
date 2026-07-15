using LinkKeys.LocalRp.Crypto;
using LinkKeys.LocalRp.Tests.TestUtil;
using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp.Tests;

/// <summary>Conformance vectors: <c>callback_box.json</c>.</summary>
public class CallbackBoxConformanceTests
{
    private static List<AeadSuite> ParseAllowedSuites(System.Text.Json.JsonElement c)
    {
        var outSuites = new List<AeadSuite>();
        foreach (var s in c.Get("allowed_suites").AsArray())
        {
            var suite = AeadSuiteExtensions.Parse(s.AsString());
            if (suite is null)
            {
                throw new InvalidOperationException($"unregistered suite id in fixture: {s.AsString()}");
            }

            outSuites.Add(suite.Value);
        }

        return outSuites;
    }

    [Fact]
    public void PositiveCasesOpenViaSdkDependency()
    {
        var d = Fixtures.Load("callback_box.json");
        var cases = d.Get("positive_cases").AsArray().ToList();
        Assert.Equal(2, cases.Count);

        foreach (var c in cases)
        {
            var headerBytes = Fixtures.Hex(c.Get("header_cbor_hex").AsString());
            var ciphertext = Fixtures.Hex(c.Get("ciphertext_hex").AsString());
            var decryptKey = Fixtures.Hex(c.Get("decrypt_private_key_hex").AsString());
            var allowed = ParseAllowedSuites(c);

            var encrypted = new LocalRpEncryptedCallback(headerBytes, ciphertext);
            var opened = LocalRp.OpenLocalRpCallback(encrypted, decryptKey, allowed);

            Assert.Equal(c.Get("suite").AsString(), opened.Header.Suite);
            Assert.Equal(c.Get("fingerprint").AsString(), opened.Header.Fingerprint);
            Assert.Equal(Fixtures.Hex(c.Get("nonce_hex").AsString()), opened.Header.Nonce);
            Assert.Equal(Fixtures.Hex(c.Get("state_hex").AsString()), opened.Header.State);
            Assert.Equal(c.Get("issued_at").AsString(), opened.Header.IssuedAt);
            Assert.Equal(c.Get("expires_at").AsString(), opened.Header.ExpiresAt);

            var plaintext = Codec.EncodeSignedLocalRpCallbackPayload(opened.SignedPayload);
            Assert.Equal(Fixtures.Hex(c.Get("plaintext_cbor_hex").AsString()), plaintext);
        }
    }

    [Fact]
    public void NegativeCasesFail()
    {
        var d = Fixtures.Load("callback_box.json");
        var cases = d.Get("negative_cases").AsArray().ToList();
        Assert.Equal(13, cases.Count);

        foreach (var c in cases)
        {
            var headerBytes = Fixtures.Hex(c.Get("header_cbor_hex").AsString());
            var ciphertext = Fixtures.Hex(c.Get("ciphertext_hex").AsString());
            var decryptKey = Fixtures.Hex(c.Get("decrypt_private_key_hex").AsString());
            var allowed = ParseAllowedSuites(c);

            var encrypted = new LocalRpEncryptedCallback(headerBytes, ciphertext);
            var name = c.GetOrNull("name")?.AsString() ?? "<unnamed>";
            Assert.ThrowsAny<Exception>(() => LocalRp.OpenLocalRpCallback(encrypted, decryptKey, allowed));
        }
    }
}
