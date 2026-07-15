using System.Net.Sockets;

namespace LinkKeys.LocalRp.Rpc;

/// <summary>
/// The TCP dial seam. Deliberately narrow: this interface only *connects a byte-stream
/// socket* to <c>host:port</c>. TLS (certificate-pin verification against DNS
/// <c>fp=</c> records) is layered on top in <see cref="RpcClient"/>, not here, so a
/// test double can swap out "how do I open a socket" without also having to fake a TLS
/// handshake.
///
/// <para>Wire Precision is explicit that this SDK must NOT default to refusing
/// non-public addresses: that refusal is a server-side SSRF guard, and "connecting from
/// a LAN box to wherever <c>_linkkeys_apis</c> points is the entire point of this mode."
/// The default policy (<see cref="StdTransport"/>'s default
/// <see cref="AddressPolicy.Permissive"/>) reflects that. <see cref="AddressPolicy.PublicOnly"/>
/// is offered as opt-in for integrators who specifically want a stricter posture.</para>
/// </summary>
public interface ITransport
{
    /// <summary>Dial <c>host:port</c> and return a connected, un-encrypted socket.</summary>
    Socket Dial(string hostPort);
}
