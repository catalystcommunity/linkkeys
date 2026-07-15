namespace LinkKeys.LocalRp;

/// <summary>
/// A local-RP protocol verification failure: signature, envelope, timestamp,
/// nonce/state, audience, issuer, callback URL, or suite-negotiation check. Mirrors
/// <c>liblinkkeys::local_rp::LocalRpError</c>. Unchecked, since the verification chain
/// in <see cref="Complete"/> is a long sequence of steps that must each fail closed;
/// callers who need to branch on failure reason inspect <see cref="Kind"/>.
///
/// <para>Never carries key material, nonces, tokens, tickets, or claim values in its
/// message (AGENTS.md: "Never log sensitive information") — only enough context (a
/// field name, an algorithm id, a key id) to explain what failed.</para>
/// </summary>
public class LocalRpError : Exception
{
    public enum ErrorKind
    {
        Decode,
        InvalidKeyLength,
        FingerprintMismatch,
        NotYetValid,
        Expired,
        BadTimestamp,
        NonceMismatch,
        StateMismatch,
        AudienceMismatch,
        IssuerMismatch,
        CallbackUrlMismatch,
        UnsupportedSuite,
        SuiteNotAdvertised,
        HeaderPayloadMismatch,
        KeyNotFound,
        KeyRevoked,
        KeyExpired,
        SignatureInvalid,
        UnsupportedAlgorithm,
        Crypto,

        /// <summary>
        /// The ticket-redemption response's <c>user_id</c>/<c>user_domain</c> did not
        /// match the SIGNED callback payload's. The redemption response carries no
        /// signature of its own, so it must always be bound to the identity the domain
        /// already vouched for in the payload — never trusted on its own (a
        /// compromised/malicious IDP could otherwise redeem a ticket for one user while
        /// an already domain-signed callback names another).
        /// </summary>
        RedemptionIdentityMismatch,

        /// <summary>
        /// A redeemed claim's <c>user_id</c> did not match the SIGNED callback payload's
        /// <c>user_id</c>. A claim naming a different subject must never be attributed to
        /// this login, even if the claim's own signature verifies correctly — that only
        /// proves the signer attested it about ITS named subject, not about the user who
        /// is logging in.
        /// </summary>
        ClaimIdentityMismatch,

        /// <summary>
        /// One or more claim types in <see cref="Begin.PendingLogin.RequiredClaims"/>
        /// (declared when the login was begun) were not present among the redemption's
        /// claims that passed full verification. Missing or insufficient — including an
        /// empty claim set — is fatal.
        /// </summary>
        RequiredClaimsNotSatisfied,
    }

    public ErrorKind Kind { get; }

    public string? Detail { get; }

    public LocalRpError(ErrorKind kind, string? detail)
        : base(detail is null ? kind.ToString() : $"{kind}: {detail}")
    {
        Kind = kind;
        Detail = detail;
    }

    public LocalRpError(ErrorKind kind, string? detail, Exception cause)
        : base(detail is null ? kind.ToString() : $"{kind}: {detail}", cause)
    {
        Kind = kind;
        Detail = detail;
    }
}
