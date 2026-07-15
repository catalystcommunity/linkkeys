using LinkKeys.LocalRp.Tests.TestUtil;
using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp.Tests;

/// <summary>Conformance vectors: <c>url_params.json</c>.</summary>
public class UrlParamsConformanceTests
{
    private static string ToBase64UrlUnpadded(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64UrlUnpadded(string s)
    {
        var standard = s.Replace('-', '+').Replace('_', '/');
        int pad = (4 - (standard.Length % 4)) % 4;
        return Convert.FromBase64String(standard + new string('=', pad));
    }

    [Fact]
    public void CasesRoundTripBothDirections()
    {
        var d = Fixtures.Load("url_params.json");
        var cases = d.Get("cases").AsArray().ToList();
        Assert.Equal(2, cases.Count);

        foreach (var c in cases)
        {
            var cbor = Fixtures.Hex(c.Get("cbor_hex").AsString());
            var b64 = c.Get("base64url_unpadded").AsString();

            Assert.Equal(b64, ToBase64UrlUnpadded(cbor));
            Assert.Equal(cbor, FromBase64UrlUnpadded(b64));

            var name = c.Get("name").AsString();
            switch (name)
            {
                case "signed_local_rp_login_request":
                {
                    var typed = Codec.DecodeSignedLocalRpLoginRequest(cbor);
                    Assert.Equal(b64, UrlEncoding.SignedLocalRpLoginRequestToUrlParam(typed));
                    var roundTripped = UrlEncoding.SignedLocalRpLoginRequestFromUrlParam(b64);
                    Assert.Equal(roundTripped.Request, typed.Request);
                    Assert.Equal(roundTripped.Signature, typed.Signature);
                    break;
                }

                case "local_rp_encrypted_callback":
                {
                    var typed = Codec.DecodeLocalRpEncryptedCallback(cbor);
                    Assert.Equal(b64, UrlEncoding.LocalRpEncryptedCallbackToUrlParam(typed));
                    var roundTripped = UrlEncoding.LocalRpEncryptedCallbackFromUrlParam(b64);
                    Assert.Equal(roundTripped.Header, typed.Header);
                    Assert.Equal(roundTripped.Ciphertext, typed.Ciphertext);
                    break;
                }

                default:
                    throw new InvalidOperationException($"unrecognized url_params.json case name: {name}");
            }
        }
    }

    [Fact]
    public void NegativeCasesRejected()
    {
        var d = Fixtures.Load("url_params.json");
        var cases = d.Get("negative_cases").AsArray().ToList();
        Assert.Equal(2, cases.Count);
        foreach (var c in cases)
        {
            var input = c.Get("input").AsString();
            Assert.ThrowsAny<Exception>(() => UrlEncoding.LocalRpEncryptedCallbackFromUrlParam(input));
        }
    }
}
