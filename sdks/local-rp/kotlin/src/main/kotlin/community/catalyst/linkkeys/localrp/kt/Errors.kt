package community.catalyst.linkkeys.localrp.kt

import community.catalyst.linkkeys.localrp.ClaimError as JClaimError
import community.catalyst.linkkeys.localrp.LocalRpError as JLocalRpError
import community.catalyst.linkkeys.localrp.RevocationError as JRevocationError
import community.catalyst.linkkeys.localrp.SdkException as JSdkException
import community.catalyst.linkkeys.localrp.dns.DnsParseError as JDnsParseError

/**
 * The Kotlin SDK's own error hierarchy. Every checked-in Java exception type
 * this SDK's dependency (`../java`, see README's "Architecture decision") can
 * throw is translated at the Kotlin API boundary into one of these sealed
 * subtypes -- callers of this package never need to catch a
 * `community.catalyst.linkkeys.localrp.*` (Java) exception type directly.
 *
 * As required by AGENTS.md ("Never log sensitive information"): no subtype's
 * message ever carries key material, nonces, tokens, tickets, or claim
 * values -- only field names, algorithm ids, key ids, and domain names, the
 * same discipline the Java SDK's own exception types follow.
 */
sealed class LocalRpException(message: String, cause: Throwable? = null) : RuntimeException(message, cause) {

    /** A field the caller supplied was structurally invalid (empty app name, non-http(s) callback URL, wrong-length key, ...). */
    class InvalidInput(message: String, cause: Throwable? = null) : LocalRpException(message, cause)

    /** A local-RP protocol verification failure: signature, envelope, timestamp, nonce/state, audience, issuer, callback URL, or suite negotiation. */
    class Protocol(val kind: ProtocolErrorKind, message: String, cause: Throwable? = null) : LocalRpException(message, cause)

    /** A claim signature/revocation/expiry verification failure. */
    class ClaimVerification(val kind: ClaimErrorKind, message: String, cause: Throwable? = null) : LocalRpException(message, cause)

    /** A sibling-signed key revocation certificate failed to meet quorum. */
    class Revocation(message: String, cause: Throwable? = null) : LocalRpException(message, cause)

    /** A `_linkkeys`/`_linkkeys_apis` TXT record failed to parse. */
    class Dns(val kind: DnsErrorKind, message: String, cause: Throwable? = null) : LocalRpException(message, cause)

    /** A network/IO-layer failure: DNS lookup, TCP transport, TLS pinning, or RPC envelope framing. */
    class Network(val kind: NetworkErrorKind, message: String, cause: Throwable? = null) : LocalRpException(message, cause)

    /** The peer (the user's LinkKeys domain) returned a non-Ok RPC transport status. */
    class Server(val status: Int, message: String, cause: Throwable? = null) : LocalRpException(message, cause)
}

/** Mirrors `community.catalyst.linkkeys.localrp.LocalRpError.Kind` exactly. */
enum class ProtocolErrorKind {
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
     * The ticket-redemption response's `user_id`/`user_domain` did not
     * match the SIGNED callback payload's. The redemption response is not
     * itself domain-signed, so it must always be bound to the identity the
     * domain already vouched for in the payload -- never trusted on its own.
     */
    REDEMPTION_IDENTITY_MISMATCH,
    /**
     * A redeemed claim's `user_id` did not match the SIGNED callback
     * payload's `user_id`. A claim naming a different subject must never be
     * attributed to this login.
     */
    CLAIM_IDENTITY_MISMATCH,
    /**
     * The pending login's `requiredClaims` were not fully satisfied by the
     * claims that actually passed verification (missing entirely, or the
     * claim set was empty).
     */
    REQUIRED_CLAIMS_NOT_SATISFIED,
}

/** Mirrors `community.catalyst.linkkeys.localrp.ClaimError.Kind` exactly. */
enum class ClaimErrorKind {
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
    EXPIRED,
}

/** Mirrors `community.catalyst.linkkeys.localrp.dns.DnsParseError.Kind` exactly. */
enum class DnsErrorKind {
    NO_LINKKEYS_RECORD,
    MISSING_VERSION,
    UNSUPPORTED_VERSION,
    MISSING_APIS_ENDPOINT,
    INVALID_FORMAT,
}

/** The non-{INVALID_INPUT, SERVER} members of `community.catalyst.linkkeys.localrp.SdkException.Kind`. */
enum class NetworkErrorKind {
    DNS,
    TRANSPORT,
    TLS,
    PROTOCOL,
    NO_TRUSTED_DOMAIN_KEYS,
    /**
     * Fetching or decoding a domain's revocation list failed. Fatal (fail
     * closed): revocation delivery is mandatory context for trusting a
     * domain's keys, not a best-effort nicety -- a hostile or
     * merely-unreachable IDP must not be able to suppress a key's
     * revocation by dropping or erroring this call.
     */
    REVOCATION_UNAVAILABLE,
}

/**
 * Run [block], translating any Java SDK exception it throws into this
 * package's [LocalRpException] hierarchy. Every public function in this
 * package that calls into the underlying Java SDK goes through this so no
 * `community.catalyst.linkkeys.localrp.*` (Java) exception type ever escapes
 * to a caller of the Kotlin API.
 */
internal inline fun <T> runCatchingSdk(block: () -> T): T {
    try {
        return block()
    } catch (e: JLocalRpError) {
        throw LocalRpException.Protocol(ProtocolErrorKind.valueOf(e.kind().name), e.message ?: e.kind().name, e)
    } catch (e: JClaimError) {
        throw LocalRpException.ClaimVerification(ClaimErrorKind.valueOf(e.kind().name), e.message ?: e.kind().name, e)
    } catch (e: JRevocationError) {
        throw LocalRpException.Revocation(e.message ?: "revocation certificate did not meet quorum", e)
    } catch (e: JDnsParseError) {
        throw LocalRpException.Dns(DnsErrorKind.valueOf(e.kind().name), e.message ?: e.kind().name, e)
    } catch (e: JSdkException) {
        throw when (e.kind()) {
            JSdkException.Kind.INVALID_INPUT -> LocalRpException.InvalidInput(e.message ?: "invalid input", e)
            JSdkException.Kind.SERVER -> LocalRpException.Server(e.serverStatus(), e.message ?: "server error", e)
            else -> LocalRpException.Network(NetworkErrorKind.valueOf(e.kind().name), e.message ?: e.kind().name, e)
        }
    }
}
