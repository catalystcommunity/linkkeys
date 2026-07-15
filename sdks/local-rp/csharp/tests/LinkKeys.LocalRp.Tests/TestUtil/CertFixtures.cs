using System.Diagnostics;
using System.Text;
using LinkKeys.LocalRp.Crypto;

namespace LinkKeys.LocalRp.Tests.TestUtil;

/// <summary>
/// Mints a self-signed Ed25519 TLS certificate via the system <c>openssl</c> CLI,
/// test-scope only (matching the Java/TypeScript sibling SDKs' approach) — .NET 8's own
/// crypto stack has no certificate-<em>issuing</em> API for Ed25519 at all
/// (<see cref="System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile"/>
/// itself throws "not a known key algorithm" for an Ed25519 private key, confirmed by a
/// runtime spike — .NET cannot even construct an Ed25519-keyed <c>X509Certificate2</c>
/// with a usable private key, let alone act as a TLS server presenting one). Never a
/// runtime dependency of the SDK itself — see <see cref="FlowTests"/> for why the fake
/// IDP's TLS *server* role is therefore played by <c>openssl s_server</c> rather than an
/// in-process .NET <see cref="System.Net.Security.SslStream"/> server.
/// </summary>
public static class CertFixtures
{
    // The fixed RFC 8410 PKCS8 DER prefix for an Ed25519 private key (empty
    // parameters, `id-Ed25519` AlgorithmIdentifier, then an OCTET STRING wrapping the
    // 32-byte seed as its own OCTET STRING) -- the same trick the Java SDK's FlowTest
    // uses to hand an OS-generated raw seed to `openssl req`.
    private static readonly byte[] Ed25519Pkcs8Prefix = Hex.Decode("302e020100300506032b657004220420");

    private static string Ed25519SeedToPkcs8Pem(byte[] seed)
    {
        var der = new byte[Ed25519Pkcs8Prefix.Length + seed.Length];
        Ed25519Pkcs8Prefix.CopyTo(der, 0);
        seed.CopyTo(der, Ed25519Pkcs8Prefix.Length);
        var b64 = Convert.ToBase64String(der);
        var sb = new StringBuilder("-----BEGIN PRIVATE KEY-----\n");
        for (int i = 0; i < b64.Length; i += 64)
        {
            sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
        }

        sb.Append("-----END PRIVATE KEY-----\n");
        return sb.ToString();
    }

    /// <summary>
    /// Generate a self-signed Ed25519 certificate for <paramref name="domain"/> whose
    /// signing key is exactly <paramref name="seed"/> (so the certificate's SPKI
    /// fingerprint is exactly the fingerprint the test's DNS answer pins). Returns the
    /// PEM cert and key file paths in a fresh temp directory.
    /// </summary>
    public static (string CertPemPath, string KeyPemPath) GenerateDomainTlsCert(string domain, byte[] seed)
    {
        var dir = Directory.CreateTempSubdirectory("linkkeys-local-rp-flow-test-");
        var keyPath = Path.Combine(dir.FullName, "key.pem");
        var certPath = Path.Combine(dir.FullName, "cert.pem");
        File.WriteAllText(keyPath, Ed25519SeedToPkcs8Pem(seed));

        var psi = new ProcessStartInfo
        {
            FileName = "openssl",
            ArgumentList = { "req", "-new", "-x509", "-key", keyPath, "-days", "3", "-subj", $"/CN={domain}", "-out", certPath },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("failed to start openssl");
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        if (proc.ExitCode != 0)
        {
            throw new InvalidOperationException($"openssl req failed (exit {proc.ExitCode}): {stdout}{stderr}");
        }

        return (certPath, keyPath);
    }
}
