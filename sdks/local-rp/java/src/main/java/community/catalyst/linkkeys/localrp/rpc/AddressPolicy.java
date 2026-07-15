package community.catalyst.linkkeys.localrp.rpc;

/** Which destination addresses {@link StdTransport} is willing to dial. Default is {@link #PERMISSIVE}. */
public enum AddressPolicy {
    /**
     * Dial anything the OS resolver returns. Correct default for this mode:
     * a LAN/loopback local RP talking to its LinkKeys domain's published
     * {@code _linkkeys_apis} {@code tcp=} endpoint is routinely a private
     * address.
     */
    PERMISSIVE,
    /**
     * Refuse loopback/private/link-local/CGNAT/documentation/unspecified
     * addresses, mirroring (not reusing) the server-side SSRF guard the
     * Rust {@code linkkeys-rpc-client} applies to its own outbound calls.
     * Opt-in only.
     */
    PUBLIC_ONLY,
}
