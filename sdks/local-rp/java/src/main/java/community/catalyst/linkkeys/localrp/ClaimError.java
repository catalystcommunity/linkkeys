package community.catalyst.linkkeys.localrp;

/** A claim signature/revocation/expiry verification failure. Mirrors {@code liblinkkeys::claims::ClaimError}. */
public class ClaimError extends RuntimeException {
    public enum Kind {
        UNSIGNED,
        KEY_NOT_FOUND,
        KEY_REVOKED,
        KEY_EXPIRED,
        UNSUPPORTED_ALGORITHM,
        SIGNATURE_INVALID,
        DOMAIN_KEYS_UNAVAILABLE,
        DOMAIN_UNVERIFIED,
        REVOKED,
        BAD_EXPIRY,
        /** A signed time (attested_at or expires_at) has a fraction of a second, so it was never signed. */
        BAD_TIMESTAMP,
        EXPIRED,
    }

    private final Kind kind;
    private final String detail;

    public ClaimError(Kind kind, String detail) {
        super(detail == null ? kind.toString() : kind + ": " + detail);
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
