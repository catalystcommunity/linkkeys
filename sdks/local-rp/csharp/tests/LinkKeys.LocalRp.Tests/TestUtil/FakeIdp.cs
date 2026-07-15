using System.Diagnostics;
using System.Net.Sockets;
using LinkKeys.LocalRp.Dns;
using LinkKeys.LocalRp.Rpc;

namespace LinkKeys.LocalRp.Tests.TestUtil;

/// <summary>
/// A fake LinkKeys IDP TLS+CSIL-RPC endpoint for <see cref="FlowTests"/>, backed by the
/// real system <c>openssl s_server</c> process rather than an in-process .NET
/// <see cref="System.Net.Security.SslStream"/> server.
///
/// <para><b>Why an external process instead of an in-process server (unlike the
/// Java/TypeScript sibling SDKs' flow tests).</b> A runtime spike confirmed .NET 8's
/// crypto stack cannot construct a usable Ed25519 private key object at all — even
/// <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile"/>
/// throws <c>CryptographicException: '1.3.101.112' is not a known key algorithm</c> — so
/// there is no way to make .NET's <see cref="System.Net.Security.SslStream"/> present an
/// Ed25519 server certificate; that capability simply does not exist on this platform, as
/// distinct from merely being awkward. (The *client* side is fully supported and is this
/// SDK's actual production code path — verified separately: a .NET
/// <see cref="System.Net.Security.SslStream"/> client completes a TLS 1.3 handshake
/// against a real `openssl s_server`-terminated Ed25519 certificate without issue, and
/// <see cref="TlsPinning"/> is exercised for real by every scenario here.)</para>
///
/// <para>Each fake-IDP interaction in this SDK's own production code
/// (<see cref="RpcClient"/>) opens a brand-new TLS connection per RPC call rather than
/// reusing one — so a single-shot <c>openssl s_server -naccept 1</c> process, preloaded
/// via stdin with exactly the one CSIL-RPC response frame it should hand back, is a
/// faithful substitute for "one call, one connection, one canned reply": as soon as the
/// TLS handshake completes, `s_server` forwards whatever bytes are waiting on its stdin
/// to the client, independent of what the client itself sent (verified by a runtime
/// spike). One process is spawned per expected call, each on ITS OWN loopback port; a
/// call-order-aware <see cref="IDnsResolver"/> (<see cref="RotatingDnsResolver"/>)
/// advertises a different port per successive <c>_linkkeys_apis</c> TXT lookup, so the
/// real production <see cref="RpcClient"/>/<see cref="TlsPinning"/>/<see cref="StreamFraming"/>
/// code paths run unmodified against each in turn. (A real domain would of course
/// advertise one stable <c>tcp=</c> endpoint; the port-per-call indirection here is a
/// pure test-harness artifact to work around the one-shot-process design, not a protocol
/// concept.)</para>
/// </summary>
public sealed class FakeIdp : IDisposable
{
    private readonly List<Process> _processes = [];

    /// <summary>The loopback ports allocated for each pre-spawned single-shot server, in call order.</summary>
    public IReadOnlyList<int> Ports { get; }

    private FakeIdp(IReadOnlyList<int> ports)
    {
        Ports = ports;
    }

    /// <summary>
    /// Spawn one single-shot <c>openssl s_server</c> per entry in
    /// <paramref name="framedResponses"/>, each presenting a certificate derived from
    /// <paramref name="domainSeed"/> and preloaded with that call's exact framed
    /// CSIL-RPC response bytes. Blocks until every spawned server is confirmed
    /// listening.
    /// </summary>
    public static FakeIdp Start(string domain, byte[] domainSeed, IReadOnlyList<byte[]> framedResponses)
    {
        var (certPath, keyPath) = CertFixtures.GenerateDomainTlsCert(domain, domainSeed);
        var fakeIdp = new FakeIdp(AllocatePorts(framedResponses.Count));

        for (int i = 0; i < framedResponses.Count; i++)
        {
            var port = fakeIdp.Ports[i];
            var psi = new ProcessStartInfo
            {
                FileName = "openssl",
                ArgumentList =
                {
                    "s_server", "-accept", port.ToString(), "-cert", certPath, "-key", keyPath, "-naccept", "1", "-quiet",
                },
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            var proc = Process.Start(psi) ?? throw new InvalidOperationException("failed to start openssl s_server");
            fakeIdp._processes.Add(proc);

            var response = framedResponses[i];
            _ = Task.Run(async () =>
            {
                try
                {
                    await proc.StandardInput.BaseStream.WriteAsync(response);
                    proc.StandardInput.BaseStream.Close();
                }
                catch (IOException)
                {
                    // The client may abort the handshake before ever reading a reply
                    // (the "bad pin" scenario) -- nothing to deliver in that case.
                }
            });
            // Drain stdout/stderr so the child process never blocks on a full pipe buffer.
            _ = proc.StandardOutput.ReadToEndAsync();
            _ = proc.StandardError.ReadToEndAsync();
        }

        foreach (var port in fakeIdp.Ports)
        {
            WaitUntilListening(port, TimeSpan.FromSeconds(5));
        }

        return fakeIdp;
    }

    private static List<int> AllocatePorts(int count)
    {
        var ports = new List<int>(count);
        for (int i = 0; i < count; i++)
        {
            using var probe = new TcpListener(System.Net.IPAddress.Loopback, 0);
            probe.Start();
            ports.Add(((System.Net.IPEndPoint)probe.LocalEndpoint).Port);
            probe.Stop();
        }

        return ports;
    }

    /// <summary>
    /// Waits for <paramref name="port"/> to be bound, WITHOUT ever completing a TCP
    /// connection to it. A connect-based readiness probe would be wrong here: each
    /// spawned server is <c>-naccept 1</c> (accepts exactly one connection, then exits),
    /// so a probe connection would itself consume that one slot and starve the real
    /// client (confirmed the hard way -- an earlier connect-based probe here produced
    /// consistent "connection refused" on every real dial). Instead, this repeatedly
    /// tries to bind the SAME port itself: while nothing is listening, our own bind
    /// succeeds (and is immediately released); once `openssl s_server` has bound it,
    /// our bind fails with `AddressAlreadyInUse`, which is exactly the transition we're
    /// waiting for.
    /// </summary>
    private static void WaitUntilListening(int port, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                probe.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, port));
                // Bind succeeded -- nobody is listening on this port yet. Release it and retry.
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                // Something (presumably our just-spawned openssl process) is now bound
                // to this port -- ready, without ever occupying its single accept slot.
                return;
            }

            Thread.Sleep(25);
        }

        throw new TimeoutException($"openssl s_server never started listening on port {port}");
    }

    public void Dispose()
    {
        foreach (var proc in _processes)
        {
            try
            {
                if (!proc.HasExited)
                {
                    proc.Kill(entireProcessTree: true);
                }

                proc.WaitForExit(2000);
            }
            catch (InvalidOperationException)
            {
                // already exited between the check and the kill -- fine.
            }
            finally
            {
                proc.Dispose();
            }
        }
    }
}

/// <summary>
/// A call-order-aware <see cref="IDnsResolver"/>: the <c>_linkkeys</c> (trust-anchor)
/// answer is fixed, but each successive <c>_linkkeys_apis</c> lookup advances to the
/// next port in <see cref="FakeIdp.Ports"/> (see that class's docs for why). Any lookup
/// past the end of the port list repeats the last port, which only happens if a
/// scenario's real call count exceeds what the test declared.
/// </summary>
public sealed class RotatingDnsResolver(string domain, string linkkeysFingerprint, IReadOnlyList<int> apiPorts) : IDnsResolver
{
    private int _apisCallCount;

    public IReadOnlyList<string> TxtLookup(string name)
    {
        if (name == $"_linkkeys.{domain}")
        {
            return [$"v=lk1 fp={linkkeysFingerprint}"];
        }

        if (name == $"_linkkeys_apis.{domain}")
        {
            int idx = Math.Min(_apisCallCount, apiPorts.Count - 1);
            _apisCallCount++;
            return [$"v=lk1 tcp=127.0.0.1:{apiPorts[idx]}"];
        }

        throw new SdkException(SdkException.ErrorKind.Dns, $"no fake record for {name}");
    }
}
