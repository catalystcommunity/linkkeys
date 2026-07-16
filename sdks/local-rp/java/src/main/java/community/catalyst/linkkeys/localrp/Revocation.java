package community.catalyst.linkkeys.localrp;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Types.ClaimSignature;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;
import community.catalyst.linkkeys.localrp.wire.Types.RevocationCertificate;

/**
 * Sibling-signed key revocation certificate verification &mdash; mirrors
 * {@code crates/liblinkkeys/src/revocation.rs} / {@code sdks/local-rp/go/revocation.go}.
 * Only verification is ported here (building/signing a revocation
 * certificate is a domain-admin/server-side operation, out of scope for a
 * local-RP SDK); this SDK verifies revocation certificates fetched alongside
 * domain keys so it can drop a key a quorum-verified sibling revocation
 * targets.
 */
public final class Revocation {
    private Revocation() {}

    /** Minimum number of distinct sibling signatures required to revoke a key. */
    public static final int QUORUM = 2;

    /** Domain-separation tag/version for the signed revocation payload. */
    private static final String TAG = "linkkeys-key-revocation-v1alpha";

    /**
     * The canonical signed bytes: the tag, the target key id + fingerprint,
     * the revocation instant, and the signing sibling's domain (bound
     * per-signature to stop cross-domain reuse of a signature). This is the
     * OLDER house tuple pattern &mdash; a five-element array with the
     * domain-separation tag first &mdash; NOT the two-element
     * {@code CBOR([context, payload])} envelope framing the four local-RP
     * structures use.
     */
    static byte[] revocationPayload(String targetKeyId, String targetFingerprint, String revokedAt, String signingDomain) {
        return Cbor.encode(Cbor.tuple(
                Cbor.vtext(TAG),
                Cbor.vtext(targetKeyId),
                Cbor.vtext(targetFingerprint),
                Cbor.vtext(revokedAt),
                Cbor.vtext(signingDomain)));
    }

    /**
     * Verify a revocation certificate against a domain's public key set.
     * Requires at least {@link #QUORUM} DISTINCT signing keys of
     * {@code domain}, each currently valid and NOT the target key, to have
     * signed the canonical payload.
     */
    public static void verifyRevocationCertificate(
            RevocationCertificate cert, List<DomainPublicKey> domainKeys, String domain) {
        int counted = countValidSigners(cert, domainKeys, domain);
        if (counted < QUORUM) {
            throw new RevocationError(counted, QUORUM);
        }
    }

    /**
     * The number of distinct, currently-valid, non-self, correctly-signed
     * sibling signatures the certificate carries for {@code domain}. Exposed
     * (package-private) so conformance tests can pinpoint exactly which
     * filtering rule an implementation got wrong, per
     * {@code revocations.json}'s {@code expected_counted_signers} field;
     * {@link #verifyRevocationCertificate} is the only entry point
     * production code should call.
     */
    static int countValidSigners(RevocationCertificate cert, List<DomainPublicKey> domainKeys, String domain) {
        Set<String> validSigners = new HashSet<>();

        for (ClaimSignature sig : cert.signatures()) {
            // A key can never authorize its own revocation.
            if (sig.signedByKeyId().equals(cert.targetKeyId())) {
                continue;
            }
            // The signature must be bound to this domain.
            if (!sig.domain().equals(domain)) {
                continue;
            }
            DomainPublicKey key = domainKeys.stream()
                    .filter(k -> k.keyId().equals(sig.signedByKeyId()))
                    .findFirst()
                    .orElse(null);
            if (key == null) {
                continue;
            }
            // Only a currently-valid signing key counts toward the quorum.
            try {
                LocalRp.checkSigningKeyValid(key);
            } catch (LocalRpError e) {
                continue;
            }
            byte[] payload = revocationPayload(cert.targetKeyId(), cert.targetFingerprint(), cert.revokedAt(), sig.domain());
            if ("ed25519".equals(key.algorithm())
                    && key.publicKey().length == 32
                    && Crypto.verifyEd25519(payload, sig.signature(), key.publicKey())) {
                validSigners.add(sig.signedByKeyId());
            }
        }

        return validSigners.size();
    }
}
