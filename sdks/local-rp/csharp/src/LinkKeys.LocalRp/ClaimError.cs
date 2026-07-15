namespace LinkKeys.LocalRp;

/// <summary>A claim signature/revocation/expiry verification failure. Mirrors <c>liblinkkeys::claims::ClaimError</c>.</summary>
public class ClaimError : Exception
{
    public enum ErrorKind
    {
        Unsigned,
        KeyNotFound,
        KeyRevoked,
        KeyExpired,
        UnsupportedAlgorithm,
        SignatureInvalid,
        DomainKeysUnavailable,
        DomainUnverified,
        Revoked,
        BadExpiry,
        Expired,
    }

    public ErrorKind Kind { get; }

    public string? Detail { get; }

    public ClaimError(ErrorKind kind, string? detail) : base(detail is null ? kind.ToString() : $"{kind}: {detail}")
    {
        Kind = kind;
        Detail = detail;
    }
}
