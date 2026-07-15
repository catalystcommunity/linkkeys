using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp;

/// <summary>
/// URL parameter encoding helpers — mirrors <c>crates/liblinkkeys/src/encoding.rs</c>.
/// All CBOR-in-URL values are base64url-encoded, unpadded (RFC 4648 §5), matching
/// <c>base64ct::Base64UrlUnpadded</c> exactly: no standard-alphabet (<c>+</c>/<c>/</c>)
/// characters, no <c>=</c> padding.
/// </summary>
public static class UrlEncoding
{
    private static string EncodeUrlParam(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeUrlParam(string s)
    {
        if (s.Contains('='))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "padded base64 is not accepted (expected unpadded base64url)");
        }

        if (s.Contains('+') || s.Contains('/'))
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, "standard base64 alphabet is not accepted (expected base64url)");
        }

        var standard = s.Replace('-', '+').Replace('_', '/');
        int pad = (4 - (standard.Length % 4)) % 4;
        standard += new string('=', pad);

        try
        {
            return Convert.FromBase64String(standard);
        }
        catch (FormatException e)
        {
            throw new SdkException(SdkException.ErrorKind.InvalidInput, $"base64url decode failed: {e.Message}", e);
        }
    }

    /// <summary>Encode for the begin route's <c>?signed_request=&lt;...&gt;</c> query parameter.</summary>
    public static string SignedLocalRpLoginRequestToUrlParam(SignedLocalRpLoginRequest signed) =>
        EncodeUrlParam(Codec.EncodeSignedLocalRpLoginRequest(signed));

    public static SignedLocalRpLoginRequest SignedLocalRpLoginRequestFromUrlParam(string param) =>
        Codec.DecodeSignedLocalRpLoginRequest(DecodeUrlParam(param));

    /// <summary>Encode for the callback redirect's <c>&amp;encrypted_token=&lt;...&gt;</c> query parameter.</summary>
    public static string LocalRpEncryptedCallbackToUrlParam(LocalRpEncryptedCallback callback) =>
        EncodeUrlParam(Codec.EncodeLocalRpEncryptedCallback(callback));

    public static LocalRpEncryptedCallback LocalRpEncryptedCallbackFromUrlParam(string param) =>
        Codec.DecodeLocalRpEncryptedCallback(DecodeUrlParam(param));
}
