using System.Globalization;

namespace LinkKeys.LocalRp;

/// <summary>
/// RFC3339 timestamp parse/format helpers. Parsing accepts both the <c>Z</c> and
/// <c>+00:00</c> UTC-offset spellings (conformance vectors use the latter; this SDK's
/// own output uses the former) — both are valid RFC3339 and
/// <see cref="DateTimeOffset"/>'s round-trip/ISO parser accepts either.
/// </summary>
internal static class Rfc3339
{
    public static DateTimeOffset Parse(string field, string s)
    {
        if (DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out var result))
        {
            return result;
        }

        throw new LocalRpError(LocalRpError.ErrorKind.BadTimestamp, $"{field}: could not parse '{s}' as RFC3339");
    }

    public static string Format(DateTimeOffset instant) =>
        instant.ToUniversalTime().ToString("yyyy-MM-dd\\THH:mm:ss.FFFFFFF\\Z", CultureInfo.InvariantCulture);
}
