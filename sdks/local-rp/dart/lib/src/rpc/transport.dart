// The TCP dial seam. Deliberately narrow: this interface only *connects a
// byte-stream socket* to `host:port`. TLS (certificate-pin verification
// against DNS `fp=` records) is layered on top in `rpc_client.dart`, not
// here, so a test double can swap out "how do I open a socket" without also
// having to fake a TLS handshake.
//
// Wire Precision is explicit that this SDK must NOT default to refusing
// non-public addresses: that refusal is a server-side SSRF guard, and
// "connecting from a LAN box to wherever `_linkkeys_apis` points is the
// entire point of this mode." The default policy ([StdTransport]'s default
// [AddressPolicy.permissive]) reflects that. [AddressPolicy.publicOnly] is
// offered as opt-in for integrators who specifically want a stricter
// posture.
library;

import 'dart:io';

/// Dial `host:port` and return a connected, unencrypted socket.
abstract class Transport {
  Future<Socket> dial(String hostPort);
}
