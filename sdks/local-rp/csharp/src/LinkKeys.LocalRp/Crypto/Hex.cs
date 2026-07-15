namespace LinkKeys.LocalRp.Crypto;

/// <summary>
/// Lowercase hex encode/decode, no separators, no <c>0x</c> prefix — the encoding
/// every conformance vector uses.
/// </summary>
public static class Hex
{
    public static string Encode(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static byte[] Decode(string hex)
    {
        if (hex.Length % 2 != 0)
        {
            throw new ArgumentException($"odd-length hex string: {hex}");
        }

        try
        {
            return Convert.FromHexString(hex);
        }
        catch (FormatException e)
        {
            throw new ArgumentException($"invalid hex string: {hex}", e);
        }
    }
}
