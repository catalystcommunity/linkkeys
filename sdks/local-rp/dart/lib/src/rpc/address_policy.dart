// Which destination addresses [StdTransport] is willing to dial. Default is
// [AddressPolicy.permissive].
library;

enum AddressPolicy {
  /// Dial anything the OS resolver returns. Correct default for this mode: a
  /// LAN/loopback local RP talking to its LinkKeys domain's published
  /// `_linkkeys_apis` `tcp=` endpoint is routinely a private address.
  permissive,

  /// Refuse loopback/private/link-local/CGNAT/documentation/unspecified
  /// addresses, mirroring (not reusing) the server-side SSRF guard the Rust
  /// `linkkeys-rpc-client` applies to its own outbound calls. Opt-in only.
  publicOnly,
}
