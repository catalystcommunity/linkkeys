package community.catalyst.linkkeys.localrp.rpc;

import java.net.Socket;

/**
 * The TCP dial seam. Deliberately narrow: this interface only *connects a
 * byte-stream socket* to {@code host:port}. TLS (certificate-pin
 * verification against DNS {@code fp=} records) is layered on top in
 * {@link RpcClient}, not here, so a test double can swap out "how do I open
 * a socket" without also having to fake a TLS handshake.
 *
 * <p>Wire Precision is explicit that this SDK must NOT default to refusing
 * non-public addresses: that refusal is a server-side SSRF guard, and
 * "connecting from a LAN box to wherever {@code _linkkeys_apis} points is
 * the entire point of this mode." The default policy ({@link StdTransport}'s
 * default {@link AddressPolicy#PERMISSIVE}) reflects that. {@link
 * AddressPolicy#PUBLIC_ONLY} is offered as opt-in for integrators who
 * specifically want a stricter posture.
 */
public interface Transport {
    /** Dial {@code host:port} and return a connected, un-encrypted socket. */
    Socket dial(String hostPort);
}
