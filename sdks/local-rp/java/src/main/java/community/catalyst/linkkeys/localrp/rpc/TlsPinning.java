package community.catalyst.linkkeys.localrp.rpc;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import community.catalyst.linkkeys.localrp.SdkException;
import community.catalyst.linkkeys.localrp.crypto.Crypto;

/**
 * TLS transport for CSIL-RPC, pinned to a domain's DNS {@code fp=} records
 * &mdash; the same trust anchor {@code crates/linkkeys/src/tcp/tls.rs} uses
 * for the S2S path. WebPKI certificate-chain validity is <b>not</b> the
 * trust anchor here (there is no CA chain for a domain's TCP-service
 * certificate to begin with); the DNS-pinned SPKI fingerprint is.
 *
 * <h2>Why an all-trusting {@link TrustManager} is safe here</h2>
 *
 * A {@link TrustManager} that accepts any certificate chain would be a
 * severe vulnerability in almost any other context, because it would let a
 * network attacker present <em>any</em> certificate and have it accepted.
 * That is not what happens here: this class installs an all-trusting
 * manager to get PAST the JDK's normal WebPKI chain validation (which would
 * otherwise reject a certificate we have no CA basis to validate) and then
 * <b>mandatorily</b>, before any application data is sent or read,
 * recomputes the SHA-256 fingerprint of the peer certificate's raw SPKI
 * public-key bytes and requires it to be a member of the caller-supplied
 * pinned set (from a DNS {@code fp=} TXT lookup already verified by the
 * caller). The pin, not the chain, is the anchor &mdash; exactly the
 * posture {@code crates/linkkeys/src/tcp/tls.rs}'s {@code FingerprintVerifier}
 * and the Go/TypeScript reference SDKs take (Go:
 * {@code InsecureSkipVerify: true} + {@code VerifyPeerCertificate}).
 * Skipping the mandatory post-handshake pin check here would defeat the
 * entire construction, so {@link #connectPinned} always performs it before
 * returning the socket.
 */
public final class TlsPinning {
    private TlsPinning() {}

    /**
     * The fixed length, in bytes, of the RFC 8410 Ed25519 SubjectPublicKeyInfo
     * DER prefix (AlgorithmIdentifier + BIT STRING header) preceding the raw
     * 32-byte public key. {@code X509Certificate.getPublicKey().getEncoded()}
     * returns the full SPKI DER; for an Ed25519 key this is always exactly
     * this fixed prefix followed by the 32 raw key bytes (RFC 8410 defines a
     * single, parameterless AlgorithmIdentifier for id-Ed25519, so the prefix
     * never varies). Stripping it recovers exactly the bytes
     * {@code crates/linkkeys/src/tcp/tls.rs} fingerprints
     * ({@code spki.subject_public_key.data}), without needing to trust that
     * the JCA provider parsed the key into an {@code EdECPublicKey} instance.
     */
    private static final int ED25519_SPKI_PREFIX_LEN = 12;
    private static final int ED25519_SPKI_TOTAL_LEN = ED25519_SPKI_PREFIX_LEN + 32;

    private static final class AllTrustingTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    /**
     * Extract the raw 32-byte Ed25519 public key from a certificate's SPKI
     * DER encoding &mdash; the same bytes the pin fingerprint is computed
     * over.
     */
    static byte[] rawEd25519PublicKeyFromCert(X509Certificate cert) {
        byte[] spkiDer = cert.getPublicKey().getEncoded();
        if (spkiDer.length != ED25519_SPKI_TOTAL_LEN) {
            throw new SdkException(
                    SdkException.Kind.TLS,
                    "peer certificate is not a 32-byte Ed25519 SPKI key (SPKI DER length "
                            + spkiDer.length
                            + ")");
        }
        return Arrays.copyOfRange(spkiDer, ED25519_SPKI_PREFIX_LEN, spkiDer.length);
    }

    /** Compute the pin fingerprint (lowercase hex SHA-256) of a peer certificate's raw Ed25519 SPKI key. */
    public static String certFingerprint(X509Certificate cert) {
        return Crypto.fingerprint(rawEd25519PublicKeyFromCert(cert));
    }

    private static SSLContext trustAllContext() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {new AllTrustingTrustManager()}, new SecureRandom());
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new SdkException(SdkException.Kind.TLS, "failed to build TLS context", e);
        }
    }

    /**
     * Wrap an already-connected raw socket in TLS, complete the handshake,
     * and MANDATORILY verify the peer certificate's SPKI fingerprint is a
     * member of {@code pinnedFingerprints} before returning. Throws and
     * closes the socket on any failure (handshake failure, non-Ed25519
     * cert, or pin mismatch) &mdash; a caller never receives a socket that
     * has not passed this check.
     */
    public static SSLSocket connectPinned(Socket raw, String hostname, List<String> pinnedFingerprints) {
        try {
            SSLSocketFactory factory = trustAllContext().getSocketFactory();
            SSLSocket tls = (SSLSocket) factory.createSocket(raw, hostname, raw.getPort(), true);
            SSLParameters params = tls.getSSLParameters();
            params.setServerNames(List.of(new SNIHostName(hostname)));
            // No endpoint identification algorithm is set (no "HTTPS" hostname
            // check): the DNS-pinned fingerprint below is the trust anchor,
            // not the certificate's subject/SAN.
            tls.setSSLParameters(params);
            tls.startHandshake();

            Certificate[] chain = tls.getSession().getPeerCertificates();
            if (chain.length == 0 || !(chain[0] instanceof X509Certificate leaf)) {
                closeQuietly(tls);
                throw new SdkException(SdkException.Kind.TLS, "peer presented no usable certificate");
            }
            String fp = certFingerprint(leaf);
            boolean pinned = pinnedFingerprints.stream().anyMatch(p -> p.toLowerCase(Locale.ROOT).equals(fp));
            if (!pinned) {
                closeQuietly(tls);
                throw new SdkException(
                        SdkException.Kind.TLS,
                        "certificate fingerprint " + fp + " does not match any pinned fingerprint for this domain");
            }
            return tls;
        } catch (javax.net.ssl.SSLException e) {
            closeQuietly(raw);
            throw new SdkException(SdkException.Kind.TLS, "TLS handshake failed: " + e.getMessage(), e);
        } catch (java.io.IOException e) {
            closeQuietly(raw);
            throw new SdkException(SdkException.Kind.TRANSPORT, e.getMessage(), e);
        }
    }

    private static void closeQuietly(java.io.Closeable c) {
        try {
            c.close();
        } catch (java.io.IOException ignored) {
            // best-effort cleanup only
        }
    }
}
