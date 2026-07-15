namespace LinkKeys.LocalRp;

/// <summary>
/// The SDK's network/IO-layer error type — everything that isn't a pure protocol
/// verification failure (<see cref="LocalRpError"/>/<see cref="ClaimError"/>/
/// <see cref="RevocationError"/>). Every fallible network operation in this SDK throws
/// one of these. None of these variants carry key material, nonces, tokens, tickets, or
/// claim values (AGENTS.md: "Never log sensitive information") — only domain names,
/// field names, and short messages.
/// </summary>
public class SdkException : Exception
{
    public enum ErrorKind
    {
        /// <summary>A field the caller supplied was structurally invalid.</summary>
        InvalidInput,

        /// <summary>DNS TXT lookup or record parsing failed for a domain.</summary>
        Dns,

        /// <summary>The TCP transport could not reach a domain's endpoint.</summary>
        Transport,

        /// <summary>TLS handshake / certificate pinning failed.</summary>
        Tls,

        /// <summary>The CSIL-RPC envelope could not be encoded/decoded, or wire framing was malformed.</summary>
        Protocol,

        /// <summary>The peer returned a non-Ok RPC transport status.</summary>
        Server,

        /// <summary>No trustworthy domain keys were established for a domain.</summary>
        NoTrustedDomainKeys,

        /// <summary>
        /// <c>DomainKeys/get-revocations</c> could not be fetched or decoded for a
        /// domain. Fatal (fail closed): revocation delivery is mandatory context for
        /// trusting a domain's keys at all, so an unreachable/erroring/malformed
        /// get-revocations call must never be silently treated as "no revocations" — a
        /// hostile or merely-unreliable IDP could otherwise suppress a key's revocation
        /// simply by dropping this call.
        /// </summary>
        RevocationUnavailable,
    }

    public ErrorKind Kind { get; }

    public int ServerStatus { get; }

    public SdkException(ErrorKind kind, string message) : base(message)
    {
        Kind = kind;
        ServerStatus = 0;
    }

    public SdkException(ErrorKind kind, string message, Exception cause) : base(message, cause)
    {
        Kind = kind;
        ServerStatus = 0;
    }

    public SdkException(int serverStatus, string message) : base($"server error ({serverStatus}): {message}")
    {
        Kind = ErrorKind.Server;
        ServerStatus = serverStatus;
    }
}
