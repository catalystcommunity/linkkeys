namespace LinkKeys.LocalRp.Rpc;

/// <summary>Which destination addresses <see cref="StdTransport"/> is willing to dial. Default is <see cref="Permissive"/>.</summary>
public enum AddressPolicy
{
    /// <summary>
    /// Dial anything the OS resolver returns. Correct default for this mode: a
    /// LAN/loopback local RP talking to its LinkKeys domain's published
    /// <c>_linkkeys_apis</c> <c>tcp=</c> endpoint is routinely a private address.
    /// </summary>
    Permissive,

    /// <summary>
    /// Refuse loopback/private/link-local/CGNAT/documentation/unspecified addresses,
    /// mirroring (not reusing) the server-side SSRF guard the Rust
    /// <c>linkkeys-rpc-client</c> applies to its own outbound calls. Opt-in only.
    /// </summary>
    PublicOnly,
}
