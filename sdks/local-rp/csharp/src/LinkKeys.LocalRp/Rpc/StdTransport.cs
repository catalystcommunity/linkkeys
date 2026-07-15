using System.Net;
using System.Net.Sockets;

namespace LinkKeys.LocalRp.Rpc;

/// <summary>Default <see cref="ITransport"/>: a plain blocking <see cref="Socket"/> dialer, gated only by <see cref="_policy"/>.</summary>
public sealed class StdTransport : ITransport
{
    private readonly AddressPolicy _policy;
    private readonly int _connectTimeoutMillis;
    private readonly int _ioTimeoutMillis;

    public StdTransport() : this(AddressPolicy.Permissive, 10_000, 30_000)
    {
    }

    public StdTransport(AddressPolicy policy) : this(policy, 10_000, 30_000)
    {
    }

    public StdTransport(AddressPolicy policy, int connectTimeoutMillis, int ioTimeoutMillis)
    {
        _policy = policy;
        _connectTimeoutMillis = connectTimeoutMillis;
        _ioTimeoutMillis = ioTimeoutMillis;
    }

    public Socket Dial(string hostPort)
    {
        int idx = hostPort.LastIndexOf(':');
        if (idx < 0)
        {
            throw new SdkException(SdkException.ErrorKind.Transport, $"{hostPort}: missing port");
        }

        var host = hostPort[..idx];
        if (!int.TryParse(hostPort[(idx + 1)..], out var port))
        {
            throw new SdkException(SdkException.ErrorKind.Transport, $"{hostPort}: invalid port");
        }

        IPAddress[] addrs;
        try
        {
            addrs = System.Net.Dns.GetHostAddresses(host);
        }
        catch (SocketException e)
        {
            throw new SdkException(SdkException.ErrorKind.Transport, $"{hostPort}: resolve failed: {e.Message}", e);
        }

        SdkException? lastError = null;
        foreach (var addr in addrs)
        {
            if (_policy == AddressPolicy.PublicOnly && IsNonPublic(addr))
            {
                lastError = new SdkException(
                    SdkException.ErrorKind.Transport,
                    $"{addr}: refusing non-public address under AddressPolicy.PublicOnly");
                continue;
            }

            var socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                // .GetAwaiter().GetResult() (rather than .Wait()/.Result) rethrows the
                // original exception directly instead of wrapping it in an
                // AggregateException, so a connect failure surfaces as a plain
                // SocketException/TimeoutException with a readable message.
                socket.ConnectAsync(addr, port).WaitAsync(TimeSpan.FromMilliseconds(_connectTimeoutMillis)).GetAwaiter().GetResult();

                socket.SendTimeout = _ioTimeoutMillis;
                socket.ReceiveTimeout = _ioTimeoutMillis;
                return socket;
            }
            catch (Exception e) when (e is SocketException or TimeoutException)
            {
                socket.Close();
                lastError = new SdkException(SdkException.ErrorKind.Transport, $"{hostPort}: {e.Message}", e);
            }
        }

        throw lastError ?? new SdkException(SdkException.ErrorKind.Transport, $"{hostPort}: no address resolved");
    }

    /// <summary>
    /// True for loopback/private/link-local/CGNAT/documentation/unspecified addresses.
    /// Only consulted under <see cref="AddressPolicy.PublicOnly"/>, never by default.
    /// </summary>
    internal static bool IsNonPublic(IPAddress addr)
    {
        if (IPAddress.IsLoopback(addr) || addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal || addr.IsIPv6Multicast)
        {
            return true;
        }

        if (IPAddress.Any.Equals(addr) || IPAddress.IPv6Any.Equals(addr))
        {
            return true;
        }

        var a = addr.GetAddressBytes();
        if (a.Length == 4)
        {
            int o0 = a[0];
            int o1 = a[1];
            if (o0 == 10)
            {
                return true; // 10.0.0.0/8
            }

            if (o0 == 172 && o1 is >= 16 and <= 31)
            {
                return true; // 172.16.0.0/12
            }

            if (o0 == 192 && o1 == 168)
            {
                return true; // 192.168.0.0/16
            }

            if (o0 == 169 && o1 == 254)
            {
                return true; // link-local
            }

            if (o0 == 100 && (o1 & 0xc0) == 0x40)
            {
                return true; // CGNAT 100.64.0.0/10
            }

            if (o0 == 192 && o1 == 0 && a[2] == 2)
            {
                return true; // documentation 192.0.2.0/24
            }

            if (o0 == 198 && o1 == 51 && a[2] == 100)
            {
                return true; // documentation 198.51.100.0/24
            }

            if (o0 == 203 && o1 == 0 && a[2] == 113)
            {
                return true; // documentation 203.0.113.0/24
            }

            if (o0 == 255 && o1 == 255 && a[2] == 255 && a[3] == 255)
            {
                return true; // broadcast
            }
        }
        else if (a.Length == 16)
        {
            if ((a[0] & 0xfe) == 0xfc)
            {
                return true; // ULA fc00::/7
            }
        }

        return false;
    }
}
