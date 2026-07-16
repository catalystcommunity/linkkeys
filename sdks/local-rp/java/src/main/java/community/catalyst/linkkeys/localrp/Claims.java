package community.catalyst.linkkeys.localrp;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Types.Claim;
import community.catalyst.linkkeys.localrp.wire.Types.ClaimSignature;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;

/**
 * Claim signature verification &mdash; mirrors
 * {@code crates/liblinkkeys/src/claims.rs} / {@code sdks/local-rp/go/claims.go}.
 * Only the verification half matters in production (claims are always
 * signed by an IDP, server-side); {@link #signClaim} is reproduced exactly
 * (same tag, same tuple field order/CBOR shape) purely so test fixtures
 * (fake IDPs) can build claims this SDK can verify against the real Rust
 * wire format &mdash; a genuine interop requirement, not internal
 * self-consistency.
 */
public final class Claims {
    private Claims() {}

    private static final String CLAIM_PAYLOAD_TAG = "linkkeys-claim-v1alpha";

    /** Bound on distinct claim-signer domains a completion will fetch keys for; see {@code Complete}. */
    public static final int MAX_CLAIM_SIGNER_DOMAINS = 8;

    /**
     * The canonical bytes a single signature covers for a claim. The
     * subject is the single full identity {@code user_id@subject_domain}
     * (not the bare user_id), so a claim about a user_id at one domain can't
     * be replayed as the same user_id at another. {@code signingDomain} is
     * bound per-signature so a signature from domain A cannot satisfy a
     * claim presented as signed by B.
     */
    static byte[] claimSignPayload(
            String claimId,
            String claimType,
            byte[] claimValue,
            String userId,
            String subjectDomain,
            String signingDomain,
            String expiresAt,
            String attestedAt) {
        String subject = userId + "@" + subjectDomain;
        return Cbor.encode(Cbor.tuple(
                Cbor.vtext(CLAIM_PAYLOAD_TAG),
                Cbor.vtext(claimId),
                Cbor.vtext(claimType),
                Cbor.vbytes(claimValue),
                Cbor.vtext(subject),
                Cbor.vtext(signingDomain),
                Cbor.optTextItem(expiresAt),
                Cbor.vtext(attestedAt)));
    }

    /** What is being claimed, independent of who signs it. Mirrors {@code liblinkkeys::claims::ClaimSpec}. */
    public record ClaimSpec(
            String claimId,
            String claimType,
            byte[] claimValue,
            String userId,
            String subjectDomain,
            String expiresAt,
            String attestedAt) {}

    /** One signer of a claim: a single key, owned by {@code domain}. */
    public record ClaimSigner(String domain, String keyId, byte[] privateKeySeed) {}

    /**
     * Sign a claim with one or more keys (test-fixture helper; see class
     * docs for why this is a pure protocol helper rather than something the
     * SDK calls in production).
     */
    public static Claim signClaim(ClaimSpec spec, List<ClaimSigner> signers) {
        List<ClaimSignature> signatures = new ArrayList<>();
        for (ClaimSigner signer : signers) {
            byte[] payload = claimSignPayload(
                    spec.claimId(),
                    spec.claimType(),
                    spec.claimValue(),
                    spec.userId(),
                    spec.subjectDomain(),
                    signer.domain(),
                    spec.expiresAt(),
                    spec.attestedAt());
            byte[] sig = Crypto.signEd25519(payload, signer.privateKeySeed());
            signatures.add(new ClaimSignature(signer.domain(), signer.keyId(), sig));
        }
        return new Claim(
                spec.claimId(),
                spec.userId(),
                spec.claimType(),
                spec.claimValue(),
                signatures,
                spec.attestedAt(),
                Rfc3339.format(Instant.now()),
                spec.expiresAt(),
                null);
    }

    /** A domain and the set of its currently-known public keys, resolved by the caller before verifying. */
    public record DomainKeySet(String domain, List<DomainPublicKey> keys) {}

    private static void verifyOneClaimSignature(ClaimSignature sig, byte[] payload, List<DomainPublicKey> keys) {
        DomainPublicKey key = keys.stream()
                .filter(k -> k.keyId().equals(sig.signedByKeyId()))
                .findFirst()
                .orElseThrow(() -> new ClaimError(ClaimError.Kind.KEY_NOT_FOUND, sig.signedByKeyId()));

        if (!"sign".equals(key.keyUsage())) {
            throw new ClaimError(ClaimError.Kind.SIGNATURE_INVALID, "key is not a signing key");
        }
        if (key.revokedAt() != null) {
            throw new ClaimError(ClaimError.Kind.KEY_REVOKED, key.keyId());
        }
        Instant expires;
        try {
            expires = Rfc3339.parse("expires_at", key.expiresAt());
        } catch (LocalRpError e) {
            throw new ClaimError(ClaimError.Kind.KEY_EXPIRED, key.keyId());
        }
        if (Instant.now().isAfter(expires)) {
            throw new ClaimError(ClaimError.Kind.KEY_EXPIRED, key.keyId());
        }
        if (!"ed25519".equals(key.algorithm())) {
            throw new ClaimError(ClaimError.Kind.UNSUPPORTED_ALGORITHM, key.algorithm());
        }
        if (!Crypto.verifyEd25519(payload, sig.signature(), key.publicKey())) {
            throw new ClaimError(ClaimError.Kind.SIGNATURE_INVALID, null);
        }
    }

    private interface PayloadFor {
        byte[] apply(String signingDomain);
    }

    /**
     * Verify only the cryptographic per-domain quorum: every domain that
     * signed must contribute at least one signature from a currently-valid
     * key of that domain. Does NOT check the claim's own revocation/expiry.
     */
    private static void verifySignatureQuorum(
            List<ClaimSignature> signatures, List<DomainKeySet> domainKeys, PayloadFor payloadFor) {
        if (signatures.isEmpty()) {
            throw new ClaimError(ClaimError.Kind.UNSIGNED, null);
        }
        Set<String> domains = new LinkedHashSet<>();
        for (ClaimSignature s : signatures) {
            domains.add(s.domain());
        }
        List<String> sortedDomains = new ArrayList<>(domains);
        sortedDomains.sort(String::compareTo);

        for (String signingDomain : sortedDomains) {
            DomainKeySet set = domainKeys.stream()
                    .filter(d -> d.domain().equals(signingDomain))
                    .findFirst()
                    .orElseThrow(() -> new ClaimError(ClaimError.Kind.DOMAIN_KEYS_UNAVAILABLE, signingDomain));

            byte[] payload = payloadFor.apply(signingDomain);

            RuntimeException lastErr = new ClaimError(ClaimError.Kind.DOMAIN_UNVERIFIED, signingDomain);
            boolean satisfied = false;
            for (ClaimSignature sig : signatures) {
                if (!sig.domain().equals(signingDomain)) {
                    continue;
                }
                try {
                    verifyOneClaimSignature(sig, payload, set.keys());
                    satisfied = true;
                    break;
                } catch (ClaimError e) {
                    lastErr = e;
                }
            }
            if (!satisfied) {
                throw lastErr;
            }
        }
    }

    /**
     * Verify only the cryptographic per-domain quorum for {@code claim};
     * {@code subjectDomain} is the subject's home domain, supplied from
     * authoritative context (never attacker-controlled input).
     */
    public static void verifyClaimSignatures(Claim claim, String subjectDomain, List<DomainKeySet> domainKeys) {
        verifySignatureQuorum(
                claim.signatures(),
                domainKeys,
                signingDomain -> claimSignPayload(
                        claim.claimId(),
                        claim.claimType(),
                        claim.claimValue(),
                        claim.userId(),
                        subjectDomain,
                        signingDomain,
                        claim.expiresAt(),
                        claim.attestedAt()));
    }

    /**
     * Full claim verification: the cryptographic per-domain quorum plus the
     * claim's own revocation and expiry.
     */
    public static void verifyClaim(Claim claim, String subjectDomain, List<DomainKeySet> domainKeys) {
        verifyClaimSignatures(claim, subjectDomain, domainKeys);

        if (claim.revokedAt() != null) {
            throw new ClaimError(ClaimError.Kind.REVOKED, null);
        }
        if (claim.expiresAt() != null) {
            Instant expires;
            try {
                expires = Rfc3339.parse("expires_at", claim.expiresAt());
            } catch (LocalRpError e) {
                throw new ClaimError(ClaimError.Kind.BAD_EXPIRY, null);
            }
            if (Instant.now().isAfter(expires)) {
                throw new ClaimError(ClaimError.Kind.EXPIRED, null);
            }
        }
    }
}
