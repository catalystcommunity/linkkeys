namespace LinkKeys.LocalRp.Crypto;

/// <summary>
/// The negotiated AEAD suite registry (design doc, Wire Precision "AEAD suite
/// registry"). Exact, case-sensitive strings from a closed registry — never
/// "close enough", never case-folded. Mirrors <c>liblinkkeys::crypto::AeadSuite</c>.
/// </summary>
public enum AeadSuite
{
    /// <summary>Mandatory-to-implement baseline.</summary>
    Aes256Gcm,

    /// <summary>Optional second suite.</summary>
    ChaCha20Poly1305,
}

public static class AeadSuiteExtensions
{
    public static string WireId(this AeadSuite suite) => suite switch
    {
        AeadSuite.Aes256Gcm => "aes-256-gcm",
        AeadSuite.ChaCha20Poly1305 => "chacha20-poly1305",
        _ => throw new ArgumentOutOfRangeException(nameof(suite)),
    };

    /// <summary>Parse a wire-format suite id string. Returns <c>null</c> for an id outside the registry.</summary>
    public static AeadSuite? Parse(string s) => s switch
    {
        "aes-256-gcm" => AeadSuite.Aes256Gcm,
        "chacha20-poly1305" => AeadSuite.ChaCha20Poly1305,
        _ => null,
    };

    /// <summary>Every registry suite id, in preference order (baseline first).</summary>
    public static IReadOnlyList<string> AllSupported { get; } = ["aes-256-gcm", "chacha20-poly1305"];

    /// <summary>
    /// Pick the first suite in <paramref name="advertised"/> (preference order) that
    /// this implementation supports. Never returns a suite outside
    /// <paramref name="advertised"/>, even if this implementation also supports it.
    /// </summary>
    public static AeadSuite? SelectSupported(IReadOnlyList<string> advertised)
    {
        foreach (var s in advertised)
        {
            var suite = Parse(s);
            if (suite is not null)
            {
                return suite;
            }
        }

        return null;
    }
}
