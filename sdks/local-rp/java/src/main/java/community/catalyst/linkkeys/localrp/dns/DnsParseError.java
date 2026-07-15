package community.catalyst.linkkeys.localrp.dns;

/** A {@code _linkkeys}/{@code _linkkeys_apis} TXT record failed to parse. Mirrors {@code liblinkkeys::dns::DnsParseError}. */
public class DnsParseError extends RuntimeException {
    public enum Kind {
        NO_LINKKEYS_RECORD,
        MISSING_VERSION,
        UNSUPPORTED_VERSION,
        MISSING_APIS_ENDPOINT,
        INVALID_FORMAT,
    }

    private final Kind kind;

    public DnsParseError(Kind kind, String detail) {
        super(detail == null ? kind.toString() : kind + ": " + detail);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }

    /** The symbolic string {@code dns.json}'s {@code expected_error} field uses. */
    public String symbol() {
        return switch (kind) {
            case NO_LINKKEYS_RECORD -> "no_linkkeys_record";
            case MISSING_VERSION -> "missing_version";
            case UNSUPPORTED_VERSION -> "unsupported_version";
            case MISSING_APIS_ENDPOINT -> "missing_apis_endpoint";
            case INVALID_FORMAT -> "invalid_format";
        };
    }
}
