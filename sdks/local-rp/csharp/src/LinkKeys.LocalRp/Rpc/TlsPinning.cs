using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace LinkKeys.LocalRp.Rpc;

/// <summary>
/// TLS transport for CSIL-RPC, pinned to a domain's DNS <c>fp=</c> records — the same
/// trust anchor <c>crates/linkkeys/src/tcp/tls.rs</c> uses for the S2S path. WebPKI
/// certificate-chain validity is <b>not</b> the trust anchor here (there is no CA chain
/// for a domain's TCP-service certificate to begin with); the DNS-pinned SPKI
/// fingerprint is.
///
/// <h2>Why an all-trusting <see cref="RemoteCertificateValidationCallback"/> is safe here</h2>
///
/// <para>A validation callback that accepts any certificate chain would be a severe
/// vulnerability in almost any other context, because it would let a network attacker
/// present <em>any</em> certificate and have it accepted. That is not what happens
/// here: this class installs an all-accepting callback to get PAST .NET's normal WebPKI
/// chain validation (which would otherwise reject a certificate we have no CA basis to
/// validate) and then <b>mandatorily</b>, before any application data is sent or read,
/// recomputes the SHA-256 fingerprint of the peer certificate's raw Ed25519
/// SubjectPublicKeyInfo key bytes and requires it to be a member of the caller-supplied
/// pinned set (from a DNS <c>fp=</c> TXT lookup already verified by the caller). The
/// pin, not the chain, is the anchor — exactly the posture
/// <c>crates/linkkeys/src/tcp/tls.rs</c>'s <c>FingerprintVerifier</c> and the Java SDK's
/// <c>rpc.TlsPinning</c> take. Skipping the mandatory post-handshake pin check here
/// would defeat the entire construction, so <see cref="ConnectPinned"/> always performs
/// it before returning the stream.</para>
///
/// <h2>Ed25519 SPKI extraction on .NET</h2>
///
/// <para>Per the design doc: "System.Security.Cryptography.X509Certificates may not
/// parse Ed25519 public keys into key objects — work at the DER byte level like the
/// Java SDK does." In practice, .NET 8's <see cref="X509Certificate2.PublicKey"/>
/// recognizes the Ed25519 OID (<c>1.3.101.112</c>) well enough to report it, but
/// <see cref="PublicKey.ExportSubjectPublicKeyInfo"/> throws
/// (<c>CryptographicException: ASN1 corrupted data</c>) for Ed25519 keys on this
/// runtime — confirmed by a runtime spike, not merely asserted. The legacy
/// <see cref="X509Certificate.GetPublicKey"/> API does NOT hit that bug: for an
/// Ed25519 certificate it returns exactly the 32 raw public-key bytes (RFC 8410's
/// SubjectPublicKey BIT STRING content has no further DER wrapping, unlike RSA/DSA), the
/// same bytes the Java SDK recovers by manually stripping a fixed 12-byte
/// SubjectPublicKeyInfo prefix from the full SPKI DER. This class therefore calls
/// <see cref="X509Certificate.GetPublicKey"/> directly and requires exactly 32 bytes,
/// rather than parsing SPKI DER by hand — .NET already gives us the post-prefix bytes.</para>
/// </summary>
public static class TlsPinning
{
    private const int Ed25519RawKeyLen = 32;

    /// <summary>Compute the pin fingerprint (lowercase hex SHA-256) of a peer certificate's raw Ed25519 public key.</summary>
    public static string CertFingerprint(X509Certificate2 cert)
    {
        byte[] raw = cert.GetPublicKey();
        if (raw.Length != Ed25519RawKeyLen)
        {
            throw new SdkException(
                SdkException.ErrorKind.Tls,
                $"peer certificate is not a 32-byte Ed25519 public key (got {raw.Length} bytes)");
        }

        return Crypto.Crypto.Fingerprint(raw);
    }

    /// <summary>
    /// Wrap an already-connected raw socket in TLS, complete the handshake, and
    /// MANDATORILY verify the peer certificate's SPKI fingerprint is a member of
    /// <paramref name="pinnedFingerprints"/> before returning. Throws and closes the
    /// socket on any failure (handshake failure, non-Ed25519 cert, or pin mismatch) — a
    /// caller never receives a stream that has not passed this check.
    /// </summary>
    public static SslStream ConnectPinned(Socket raw, string hostname, IReadOnlyList<string> pinnedFingerprints)
    {
        var networkStream = new NetworkStream(raw, ownsSocket: true);
        X509Certificate2? capturedLeaf = null;

        var sslStream = new SslStream(
            networkStream,
            leaveInnerStreamOpen: false,
            userCertificateValidationCallback: (_, cert, _, _) =>
            {
                // All-trusting on purpose: see class docs. The mandatory pin check below
                // is the real trust decision, made after the handshake completes.
                if (cert is not null)
                {
                    capturedLeaf = cert as X509Certificate2 ?? new X509Certificate2(cert);
                }

                return true;
            });

        try
        {
            sslStream.AuthenticateAsClient(new SslClientAuthenticationOptions
            {
                TargetHost = hostname,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.None,
            });
        }
        catch (Exception e) when (e is System.Security.Authentication.AuthenticationException or IOException)
        {
            CloseQuietly(sslStream);
            throw new SdkException(SdkException.ErrorKind.Tls, $"TLS handshake failed: {e.Message}", e);
        }

        if (capturedLeaf is null)
        {
            CloseQuietly(sslStream);
            throw new SdkException(SdkException.ErrorKind.Tls, "peer presented no usable certificate");
        }

        string fp;
        try
        {
            fp = CertFingerprint(capturedLeaf);
        }
        catch (SdkException)
        {
            CloseQuietly(sslStream);
            throw;
        }

        bool pinned = pinnedFingerprints.Any(p => string.Equals(p, fp, StringComparison.OrdinalIgnoreCase));
        if (!pinned)
        {
            CloseQuietly(sslStream);
            throw new SdkException(
                SdkException.ErrorKind.Tls,
                $"certificate fingerprint {fp} does not match any pinned fingerprint for this domain");
        }

        return sslStream;
    }

    private static void CloseQuietly(IDisposable c)
    {
        try
        {
            c.Dispose();
        }
        catch (IOException)
        {
            // best-effort cleanup only
        }
    }
}
