using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LinkKeys.LocalRp.Dns;

/// <summary>
/// Default <see cref="IDnsResolver"/>: a minimal, hand-rolled DNS TXT client speaking
/// the wire protocol directly over UDP (falling back to TCP when the response is
/// truncated), reading nameservers from <c>/etc/resolv.conf</c>.
///
/// <para><b>Why hand-rolled instead of a NuGet package.</b> The BCL's
/// <see cref="System.Net.Dns"/> only resolves A/AAAA/PTR records — there is no
/// stdlib TXT lookup on .NET (design doc, C#/.NET column: "add the DnsClient NuGet
/// package ... OR hand-roll a minimal UDP DNS TXT query reading /etc/resolv.conf like
/// a sibling might; pick one and justify"). This SDK already carries exactly one
/// justified runtime dependency (NSec.Cryptography, for Ed25519/X25519 — the BCL has
/// no support for either). A DNS TXT query is a small, stable, well-specified wire
/// format (RFC 1035 §4) — build query, parse header + one answer section, handle
/// name-compression pointers and the truncation-then-TCP-retry case — well within
/// what AGENTS.md's "every dependency is a liability, prefer standard library where
/// reasonable" calls for, rather than pulling in a general-purpose DNS client library
/// for one record type. This mirrors the same choice the Go sibling SDK makes bundling
/// its DNS logic instead of taking a dependency, adapted here to a stdlib that has no
/// TXT support at all.</para>
///
/// <para>Per the design doc's "Decided" section: resolver spoofing on a LAN is an
/// accepted, documented tradeoff for this mode; operators wanting hardening can inject
/// their own <see cref="IDnsResolver"/> (e.g. a DoH client) instead of this one.</para>
/// </summary>
public sealed class SystemDnsResolver : IDnsResolver
{
    private const int DnsPort = 53;
    private const int MaxUdpPayloadSize = 4096;
    private const int MaxNameCompressionJumps = 32;

    private readonly IReadOnlyList<string>? _configuredServers;
    private readonly int _timeoutMillis;

    public SystemDnsResolver() : this(null, 5_000)
    {
    }

    /// <summary><paramref name="servers"/> entries are <c>host</c> or <c>host:port</c> (DNS server port, default 53).</summary>
    public SystemDnsResolver(IReadOnlyList<string>? servers) : this(servers, 5_000)
    {
    }

    public SystemDnsResolver(IReadOnlyList<string>? servers, int timeoutMillis)
    {
        _configuredServers = servers;
        _timeoutMillis = timeoutMillis;
    }

    public IReadOnlyList<string> TxtLookup(string name)
    {
        var servers = _configuredServers ?? ReadResolvConfNameservers();
        if (servers.Count == 0)
        {
            throw new SdkException(SdkException.ErrorKind.Dns, $"{name}: no DNS servers configured (checked /etc/resolv.conf)");
        }

        Exception? lastError = null;
        foreach (var server in servers)
        {
            var (host, port) = SplitHostPort(server);
            try
            {
                return QueryOneServer(host, port, name);
            }
            catch (Exception e) when (e is SocketException or SdkException)
            {
                lastError = e;
            }
        }

        throw new SdkException(SdkException.ErrorKind.Dns, $"{name}: all DNS servers failed: {lastError?.Message}", lastError!);
    }

    private static (string Host, int Port) SplitHostPort(string server)
    {
        int idx = server.LastIndexOf(':');
        // Guard against bare IPv6 literals (which contain ':' but no port suffix).
        if (idx > 0 && server.IndexOf(':') == idx && int.TryParse(server[(idx + 1)..], out var p))
        {
            return (server[..idx], p);
        }

        return (server, DnsPort);
    }

    private static IReadOnlyList<string> ReadResolvConfNameservers()
    {
        const string path = "/etc/resolv.conf";
        var result = new List<string>();
        if (!File.Exists(path))
        {
            return result;
        }

        foreach (var rawLine in File.ReadLines(path))
        {
            var line = rawLine.Trim();
            if (line.StartsWith('#') || line.StartsWith(';'))
            {
                continue;
            }

            if (!line.StartsWith("nameserver", StringComparison.Ordinal))
            {
                continue;
            }

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                result.Add(parts[1]);
            }
        }

        return result;
    }

    private IReadOnlyList<string> QueryOneServer(string host, int port, string name)
    {
        ushort id = (ushort)Random.Shared.Next(ushort.MinValue, ushort.MaxValue + 1);
        byte[] query = BuildQuery(id, name);

        var serverAddr = IPAddress.Parse(host);
        var endpoint = new IPEndPoint(serverAddr, port);

        byte[] response;
        try
        {
            response = QueryUdp(endpoint, query);
        }
        catch (SocketException e)
        {
            throw new SdkException(SdkException.ErrorKind.Dns, $"{name}: UDP query to {host}:{port} failed: {e.Message}", e);
        }

        var parsed = ParseResponse(response, id, name);
        if (parsed.Truncated)
        {
            try
            {
                response = QueryTcp(endpoint, query);
            }
            catch (SocketException e)
            {
                throw new SdkException(SdkException.ErrorKind.Dns, $"{name}: TCP fallback query to {host}:{port} failed: {e.Message}", e);
            }

            parsed = ParseResponse(response, id, name);
        }

        return parsed.TxtRecords;
    }

    // -----------------------------------------------------------------
    // Wire: query construction (RFC 1035 §4)
    // -----------------------------------------------------------------

    private static byte[] BuildQuery(ushort id, string name)
    {
        var stream = new MemoryStream();
        WriteUInt16(stream, id);
        WriteUInt16(stream, 0x0100); // standard query, recursion desired
        WriteUInt16(stream, 1); // QDCOUNT
        WriteUInt16(stream, 0); // ANCOUNT
        WriteUInt16(stream, 0); // NSCOUNT
        WriteUInt16(stream, 1); // ARCOUNT (the EDNS0 OPT record below)

        WriteQName(stream, name);
        WriteUInt16(stream, 16); // QTYPE = TXT
        WriteUInt16(stream, 1); // QCLASS = IN

        // EDNS0 OPT pseudo-record advertising a larger UDP payload size, to avoid
        // truncation for the (short) TXT records this protocol uses.
        stream.WriteByte(0); // root name
        WriteUInt16(stream, 41); // TYPE = OPT
        WriteUInt16(stream, MaxUdpPayloadSize); // CLASS = requestor's UDP payload size
        stream.WriteByte(0); // extended RCODE
        stream.WriteByte(0); // EDNS version
        WriteUInt16(stream, 0); // flags
        WriteUInt16(stream, 0); // RDLENGTH

        return stream.ToArray();
    }

    private static void WriteUInt16(MemoryStream stream, int v)
    {
        stream.WriteByte((byte)(v >> 8));
        stream.WriteByte((byte)v);
    }

    private static void WriteQName(MemoryStream stream, string name)
    {
        var trimmed = name.Trim('.');
        if (trimmed.Length > 0)
        {
            foreach (var label in trimmed.Split('.'))
            {
                var bytes = System.Text.Encoding.ASCII.GetBytes(label);
                if (bytes.Length is 0 or > 63)
                {
                    throw new SdkException(SdkException.ErrorKind.InvalidInput, $"invalid DNS label in name: {name}");
                }

                stream.WriteByte((byte)bytes.Length);
                stream.Write(bytes);
            }
        }

        stream.WriteByte(0);
    }

    // -----------------------------------------------------------------
    // Transport
    // -----------------------------------------------------------------

    private byte[] QueryUdp(IPEndPoint endpoint, byte[] query)
    {
        using var udp = new UdpClient(endpoint.AddressFamily);
        udp.Client.SendTimeout = _timeoutMillis;
        udp.Client.ReceiveTimeout = _timeoutMillis;
        udp.Connect(endpoint);
        udp.Send(query, query.Length);

        IPEndPoint remote = new(IPAddress.Any, 0);
        return udp.Receive(ref remote);
    }

    private byte[] QueryTcp(IPEndPoint endpoint, byte[] query)
    {
        using var tcp = new TcpClient();
        tcp.SendTimeout = _timeoutMillis;
        tcp.ReceiveTimeout = _timeoutMillis;
        if (!tcp.ConnectAsync(endpoint.Address, endpoint.Port).Wait(_timeoutMillis))
        {
            throw new SocketException((int)SocketError.TimedOut);
        }

        using var stream = tcp.GetStream();
        var lenPrefix = new byte[2];
        lenPrefix[0] = (byte)(query.Length >> 8);
        lenPrefix[1] = (byte)query.Length;
        stream.Write(lenPrefix);
        stream.Write(query);

        var respLenBuf = ReadExact(stream, 2);
        int respLen = (respLenBuf[0] << 8) | respLenBuf[1];
        return ReadExact(stream, respLen);
    }

    private static byte[] ReadExact(Stream stream, int n)
    {
        var buf = new byte[n];
        int off = 0;
        while (off < n)
        {
            int read = stream.Read(buf, off, n - off);
            if (read <= 0)
            {
                throw new SdkException(SdkException.ErrorKind.Dns, "connection closed before expected bytes arrived");
            }

            off += read;
        }

        return buf;
    }

    // -----------------------------------------------------------------
    // Wire: response parsing
    // -----------------------------------------------------------------

    private sealed record ParsedResponse(bool Truncated, IReadOnlyList<string> TxtRecords);

    private static ParsedResponse ParseResponse(byte[] data, ushort expectedId, string queryName)
    {
        if (data.Length < 12)
        {
            throw new SdkException(SdkException.ErrorKind.Dns, $"{queryName}: DNS response too short");
        }

        int pos = 0;
        int id = ReadUInt16(data, ref pos);
        if (id != expectedId)
        {
            throw new SdkException(SdkException.ErrorKind.Dns, $"{queryName}: DNS response id mismatch");
        }

        int flags = ReadUInt16(data, ref pos);
        bool truncated = (flags & 0x0200) != 0;
        int rcode = flags & 0x000f;

        int qdCount = ReadUInt16(data, ref pos);
        int anCount = ReadUInt16(data, ref pos);
        ReadUInt16(data, ref pos); // nsCount, unused
        ReadUInt16(data, ref pos); // arCount, unused

        for (int i = 0; i < qdCount; i++)
        {
            ReadName(data, ref pos);
            pos += 4; // QTYPE + QCLASS
        }

        if (rcode == 3) // NXDOMAIN
        {
            return new ParsedResponse(truncated, []);
        }

        if (rcode != 0)
        {
            throw new SdkException(SdkException.ErrorKind.Dns, $"{queryName}: DNS server returned rcode {rcode}");
        }

        var txtRecords = new List<string>();
        for (int i = 0; i < anCount; i++)
        {
            ReadName(data, ref pos);
            int type = ReadUInt16(data, ref pos);
            ReadUInt16(data, ref pos); // class, unused
            pos += 4; // TTL
            int rdLength = ReadUInt16(data, ref pos);
            int rdStart = pos;
            if (type == 16) // TXT
            {
                txtRecords.Add(ParseTxtRData(data, rdStart, rdLength));
            }

            pos = rdStart + rdLength;
        }

        return new ParsedResponse(truncated, txtRecords);
    }

    private static string ParseTxtRData(byte[] data, int start, int length)
    {
        var sb = new StringBuilder();
        int pos = start;
        int end = start + length;
        while (pos < end)
        {
            int segLen = data[pos];
            pos += 1;
            if (pos + segLen > end)
            {
                throw new SdkException(SdkException.ErrorKind.Dns, "malformed TXT record rdata (character-string overruns rdlength)");
            }

            sb.Append(System.Text.Encoding.ASCII.GetString(data, pos, segLen));
            pos += segLen;
        }

        return sb.ToString();
    }

    private static int ReadUInt16(byte[] data, ref int pos)
    {
        if (pos + 2 > data.Length)
        {
            throw new SdkException(SdkException.ErrorKind.Dns, "truncated DNS response");
        }

        int v = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        return v;
    }

    /// <summary>Reads a (possibly compressed) DNS name starting at <paramref name="pos"/>, advancing it past the name.</summary>
    private static void ReadName(byte[] data, ref int pos)
    {
        int jumps = 0;
        int cursor = pos;
        bool advancedMain = false;

        while (true)
        {
            if (cursor >= data.Length)
            {
                throw new SdkException(SdkException.ErrorKind.Dns, "truncated DNS name");
            }

            int len = data[cursor];
            if ((len & 0xc0) == 0xc0)
            {
                if (cursor + 1 >= data.Length)
                {
                    throw new SdkException(SdkException.ErrorKind.Dns, "truncated DNS name compression pointer");
                }

                if (!advancedMain)
                {
                    pos = cursor + 2;
                    advancedMain = true;
                }

                int pointer = ((len & 0x3f) << 8) | data[cursor + 1];
                jumps++;
                if (jumps > MaxNameCompressionJumps)
                {
                    throw new SdkException(SdkException.ErrorKind.Dns, "DNS name compression pointer loop");
                }

                cursor = pointer;
                continue;
            }

            if (len == 0)
            {
                cursor += 1;
                if (!advancedMain)
                {
                    pos = cursor;
                }

                return;
            }

            cursor += 1 + len;
        }
    }
}
