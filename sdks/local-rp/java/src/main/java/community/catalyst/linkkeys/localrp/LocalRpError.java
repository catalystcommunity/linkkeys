package community.catalyst.linkkeys.localrp;

/**
 * A local-RP protocol verification failure: signature, envelope, timestamp,
 * nonce/state, audience, issuer, callback URL, or suite-negotiation check.
 * Mirrors {@code liblinkkeys::local_rp::LocalRpError} / Go's
 * {@code LocalRpError}. Unchecked, since the verification chain in
 * {@link Complete} is a long sequence of steps that must each fail closed;
 * callers who need to branch on failure reason inspect {@link #kind()}.
 *
 * <p>Never carries key material, nonces, tokens, tickets, or claim values in
 * its message (AGENTS.md: "Never log sensitive information") &mdash; only
 * enough context (a field name, an algorithm id, a key id) to explain what
 * failed.
 */
public class LocalRpError extends RuntimeException {
    public enum Kind {
        DECODE,
        INVALID_KEY_LENGTH,
        FINGERPRINT_MISMATCH,
        NOT_YET_VALID,
        EXPIRED,
        BAD_TIMESTAMP,
        NONCE_MISMATCH,
        STATE_MISMATCH,
        AUDIENCE_MISMATCH,
        ISSUER_MISMATCH,
        CALLBACK_URL_MISMATCH,
        UNSUPPORTED_SUITE,
        SUITE_NOT_ADVERTISED,
        HEADER_PAYLOAD_MISMATCH,
        KEY_NOT_FOUND,
        KEY_REVOKED,
        KEY_EXPIRED,
        SIGNATURE_INVALID,
        UNSUPPORTED_ALGORITHM,
        CRYPTO,
        /**
         * The ticket-redemption response's {@code user_id}/{@code user_domain}
         * did not match the SIGNED callback payload's. The redemption
         * response is not itself domain-signed, so it must always be bound
         * to the identity the domain already vouched for in the payload
         * &mdash; never trusted on its own.
         */
        REDEMPTION_IDENTITY_MISMATCH,
        /**
         * A redeemed claim's {@code user_id} did not match the SIGNED
         * callback payload's {@code user_id}. A claim naming a different
         * subject must never be attributed to this login.
         */
        CLAIM_IDENTITY_MISMATCH,
        /**
         * The pending login's {@code requiredClaims} were not fully
         * satisfied by the claims that actually passed verification
         * (missing entirely, or the claim set was empty).
         */
        REQUIRED_CLAIMS_NOT_SATISFIED,
    }

    private final Kind kind;
    private final String detail;

    public LocalRpError(Kind kind, String detail) {
        super(detail == null ? kind.toString() : kind + ": " + detail);
        this.kind = kind;
        this.detail = detail;
    }

    public LocalRpError(Kind kind, String detail, Throwable cause) {
        super(detail == null ? kind.toString() : kind + ": " + detail, cause);
        this.kind = kind;
        this.detail = detail;
    }

    public Kind kind() {
        return kind;
    }

    public String detail() {
        return detail;
    }
}
