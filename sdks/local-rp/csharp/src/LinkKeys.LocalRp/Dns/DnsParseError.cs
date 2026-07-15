namespace LinkKeys.LocalRp.Dns;

/// <summary>A <c>_linkkeys</c>/<c>_linkkeys_apis</c> TXT record failed to parse. Mirrors <c>liblinkkeys::dns::DnsParseError</c>.</summary>
public class DnsParseError : Exception
{
    public enum ErrorKind
    {
        NoLinkKeysRecord,
        MissingVersion,
        UnsupportedVersion,
        MissingApisEndpoint,
        InvalidFormat,
    }

    public ErrorKind Kind { get; }

    public DnsParseError(ErrorKind kind, string? detail) : base(detail is null ? kind.ToString() : $"{kind}: {detail}")
    {
        Kind = kind;
    }

    /// <summary>The symbolic string <c>dns.json</c>'s <c>expected_error</c> field uses.</summary>
    public string Symbol => Kind switch
    {
        ErrorKind.NoLinkKeysRecord => "no_linkkeys_record",
        ErrorKind.MissingVersion => "missing_version",
        ErrorKind.UnsupportedVersion => "unsupported_version",
        ErrorKind.MissingApisEndpoint => "missing_apis_endpoint",
        ErrorKind.InvalidFormat => "invalid_format",
        _ => throw new ArgumentOutOfRangeException(),
    };
}
