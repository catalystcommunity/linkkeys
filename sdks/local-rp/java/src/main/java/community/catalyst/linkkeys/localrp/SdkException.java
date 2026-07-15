package community.catalyst.linkkeys.localrp;

/**
 * The SDK's network/IO-layer error type &mdash; everything that isn't a pure
 * protocol verification failure ({@link LocalRpError}/{@link ClaimError}/
 * {@link RevocationError}). Every fallible network operation in this SDK
 * throws one of these. None of these variants carry key material, nonces,
 * tokens, tickets, or claim values (AGENTS.md: "Never log sensitive
 * information") &mdash; only domain names, field names, and short messages.
 */
public class SdkException extends RuntimeException {
    public enum Kind {
        /** A field the caller supplied was structurally invalid. */
        INVALID_INPUT,
        /** DNS TXT lookup or record parsing failed for a domain. */
        DNS,
        /** The TCP transport could not reach a domain's endpoint. */
        TRANSPORT,
        /** TLS handshake / certificate pinning failed. */
        TLS,
        /** The CSIL-RPC envelope could not be encoded/decoded, or wire framing was malformed. */
        PROTOCOL,
        /** The peer returned a non-Ok RPC transport status. */
        SERVER,
        /** No trustworthy domain keys were established for a domain. */
        NO_TRUSTED_DOMAIN_KEYS,
        /**
         * Fetching or decoding a domain's revocation list failed. Fatal
         * (fail closed): revocation delivery is mandatory context for
         * trusting a domain's keys, not a best-effort nicety &mdash; a
         * hostile or merely-unreachable IDP must not be able to suppress a
         * key's revocation by dropping or erroring this call.
         */
        REVOCATION_UNAVAILABLE,
    }

    private final Kind kind;
    private final int serverStatus;

    public SdkException(Kind kind, String message) {
        super(message);
        this.kind = kind;
        this.serverStatus = 0;
    }

    public SdkException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
        this.serverStatus = 0;
    }

    public SdkException(int serverStatus, String message) {
        super("server error (" + serverStatus + "): " + message);
        this.kind = Kind.SERVER;
        this.serverStatus = serverStatus;
    }

    public Kind kind() {
        return kind;
    }

    public int serverStatus() {
        return serverStatus;
    }
}
