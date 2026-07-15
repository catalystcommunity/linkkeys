using System.Text;
using LinkKeys.LocalRp.Crypto;
using LinkKeys.LocalRp.Rpc;
using LinkKeys.LocalRp.Tests.TestUtil;
using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp.Tests;

/// <summary>
/// Flow tests: <see cref="Complete.CompleteLocalLogin"/>'s full verification chain, end
/// to end, against a real (but locally spun up, fake-identity) LinkKeys IDP — real
/// DNS-pinned TLS (via <c>openssl s_server</c>; see <see cref="FakeIdp"/>'s docs for
/// why), real CSIL-RPC framing, and all. Only two things are faked: the DNS TXT answers
/// (<see cref="RotatingDnsResolver"/>, so no real network/DNS is touched) and the IDP's
/// identity itself (a throwaway domain signing key generated per test, not a real
/// LinkKeys deployment).
///
/// <para>Every scenario's fake IDP serves a <c>DomainKeys/get-revocations</c> reply
/// immediately after <c>get-domain-keys</c>, unconditionally — this is itself a standing
/// regression test for the "revocation fail-open" security fix
/// (<see cref="RpcClient.FetchDomainKeys"/>): a reverted fix would either never issue that
/// second RPC call at all (leaving a fake-IDP process unconsumed) or would consult
/// <c>RecentRevocationsAvailable</c> (always <c>null</c> here) to skip it, and every
/// <see cref="Scenario.ExpectedRequests"/> count in this file would go stale.</para>
///
/// <para>Requires the system <c>openssl</c> CLI on <c>PATH</c> — test-scope only, never
/// a runtime dependency of the SDK itself.</para>
/// </summary>
public class FlowTests
{
    private const string UserDomain = "example.test";
    private const string CallbackUrl = "http://localhost/callback";
    private const string DomainKeyId = "test-domain-key-1";
    private const string SiblingAKeyId = "sibling-key-a";
    private const string SiblingBKeyId = "sibling-key-b";

    private static byte[] FrameBytes(byte[] data)
    {
        int len = data.Length;
        var framed = new byte[4 + len];
        framed[0] = (byte)(len >> 24);
        framed[1] = (byte)(len >> 16);
        framed[2] = (byte)(len >> 8);
        framed[3] = (byte)len;
        data.CopyTo(framed, 4);
        return framed;
    }

    private static Identity.LocalRpKeyMaterial FixedKeyMaterial(DateTimeOffset now) =>
        Identity.GenerateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig(
            "Flow Test App", now - TimeSpan.FromDays(1), Lifetime: TimeSpan.FromDays(3651)));

    /// <summary>Build a domain signing <see cref="DomainPublicKey"/> for an arbitrary key pair/id.</summary>
    private static DomainPublicKey KeyedDomainPublicKey(DateTimeOffset now, byte[] publicKey, string keyId) => new(
        keyId,
        publicKey,
        Crypto.Crypto.Fingerprint(publicKey),
        "ed25519",
        "sign",
        Rfc3339.Format(now - TimeSpan.FromDays(30)),
        Rfc3339.Format(now + TimeSpan.FromDays(365)),
        null,
        null,
        null);

    /// <summary>Every knob a failure-case test can turn, applied in this order: build the correct objects, then mutate, then sign/seal/serve.</summary>
    private sealed class Scenario
    {
        public Func<LocalRpCallbackPayload, LocalRpCallbackPayload> MutatePayload { get; init; } = p => p;
        public Func<DomainPublicKey, DomainPublicKey> MutateDomainKey { get; init; } = k => k;
        public Func<Claim, Claim> MutateClaim { get; init; } = c => c;

        /// <summary>
        /// Applied to the ticket-redemption response after it's built from the (already
        /// claim-signed) fixture claim — lets a test make the UNSIGNED redemption
        /// response disagree with the SIGNED callback payload, which is exactly the class
        /// of attack Fix A closes.
        /// </summary>
        public Func<LocalRpTicketRedemptionResponse, LocalRpTicketRedemptionResponse> MutateRedemption { get; init; } = r => r;

        /// <summary>Additional domain signing keys the fake IDP serves alongside the primary one (revocation-quorum test only).</summary>
        public IReadOnlyList<DomainPublicKey> ExtraDomainKeys { get; init; } = [];

        /// <summary>
        /// Builds the revocation certificates the fake IDP's <c>get-revocations</c>
        /// returns, given the (already <see cref="MutateDomainKey"/>-mutated) primary
        /// domain key — so a certificate can be built to target that exact key's
        /// <see cref="Types.DomainPublicKey.Fingerprint"/> without the test needing to
        /// predict a randomly-generated key pair in advance. Defaults to an empty list.
        /// </summary>
        public Func<DomainPublicKey, IReadOnlyList<RevocationCertificate>> BuildRevocations { get; init; } = _ => [];

        /// <summary>When true, the fake IDP answers <c>get-revocations</c> with a transport error instead of a certificate list.</summary>
        public bool FailRevocations { get; init; }

        public string? DnsFingerprintOverride { get; init; }

        /// <summary>
        /// Number of fake-IDP processes/responses to serve, in call order:
        /// get-domain-keys, get-revocations, redeem-claim-ticket. Defaults to all 3 (the
        /// happy path); failure scenarios that never reach a later call trim this down so
        /// the harness doesn't leave an unconsumed single-shot process hanging around.
        /// </summary>
        public int ExpectedRequests { get; init; } = 3;
    }

    private static Complete.VerifiedLocalLogin RunScenario(Scenario scenario)
    {
        var now = DateTimeOffset.UtcNow;
        var keyMaterial = FixedKeyMaterial(now);

        var begun = Begin.BeginLocalLogin(new Begin.BeginLocalLoginConfig(keyMaterial, CallbackUrl, UserDomain, now));
        var pending = begun.Pending;

        var domainSigning = Crypto.Crypto.GenerateEd25519KeyPair();
        var domainKey = KeyedDomainPublicKey(now, domainSigning.PublicKey, DomainKeyId);
        domainKey = scenario.MutateDomainKey(domainKey);
        var allDomainKeys = new List<DomainPublicKey> { domainKey };
        allDomainKeys.AddRange(scenario.ExtraDomainKeys);

        var claimTicket = new byte[32];
        Array.Fill(claimTicket, (byte)7);
        var payload = LocalRp.BuildLocalRpCallbackPayload(
            "user-1",
            UserDomain,
            claimTicket,
            keyMaterial.Fingerprint,
            CallbackUrl,
            pending.Nonce,
            pending.State,
            Rfc3339.Format(now),
            Rfc3339.Format(now + TimeSpan.FromMinutes(5)));
        payload = scenario.MutatePayload(payload);

        var signedPayload = LocalRp.SignLocalRpCallbackPayload(payload, DomainKeyId, domainSigning.PrivateKeySeed);

        var encrypted = LocalRp.SealLocalRpCallback(
            signedPayload,
            AeadSuite.Aes256Gcm,
            keyMaterial.EncryptionPublicKey,
            payload.AudienceFingerprint,
            payload.Nonce,
            payload.State,
            payload.IssuedAt,
            payload.ExpiresAt);
        var encryptedToken = UrlEncoding.LocalRpEncryptedCallbackToUrlParam(encrypted);
        var arrivedUrl = $"{CallbackUrl}?encrypted_token={encryptedToken}";

        var claimSpec = new Claims.ClaimSpec(
            "claim-1", "handle", Encoding.UTF8.GetBytes("flowtestuser"), "user-1", UserDomain, null, Rfc3339.Format(now));
        var claim = Claims.SignClaim(claimSpec, [new Claims.ClaimSigner(UserDomain, DomainKeyId, domainSigning.PrivateKeySeed)]);
        claim = scenario.MutateClaim(claim);

        var redemptionResponse = new LocalRpTicketRedemptionResponse(
            "user-1", UserDomain, [claim], Rfc3339.Format(now + TimeSpan.FromHours(1)));
        redemptionResponse = scenario.MutateRedemption(redemptionResponse);

        var getDomainKeysResponse = FrameBytes(RpcEnvelope.Response
            .Ok("GetDomainKeysResponse", Codec.EncodeGetDomainKeysResponse(new GetDomainKeysResponse(UserDomain, allDomainKeys, null)))
            .Encode());

        var getRevocationsResponse = FrameBytes((scenario.FailRevocations
            ? RpcEnvelope.Response.TransportError(RpcEnvelope.Status.Unavailable, "revocations temporarily unavailable (hostile IDP simulation)")
            : RpcEnvelope.Response.Ok(
                "GetRevocationsResponse", Codec.EncodeGetRevocationsResponse(new GetRevocationsResponse(scenario.BuildRevocations(domainKey)))))
            .Encode());

        var redeemResponse = FrameBytes(RpcEnvelope.Response
            .Ok("LocalRpTicketRedemptionResponse", Codec.EncodeLocalRpTicketRedemptionResponse(redemptionResponse))
            .Encode());

        var allResponses = new List<byte[]> { getDomainKeysResponse, getRevocationsResponse, redeemResponse };
        var framedResponses = allResponses.Take(scenario.ExpectedRequests).ToList();

        using var fakeIdp = FakeIdp.Start(UserDomain, domainSigning.PrivateKeySeed, framedResponses);

        // Pin ALL served domain keys' fingerprints (not just the primary one) -- the
        // revocation-quorum test needs its sibling signer keys to be directly
        // DNS-pinned too (Dns.TrustKeys only trusts signing keys pinned this way; a
        // sibling with no vouch-signature from a pinned key would otherwise never make
        // it into the trusted set, and so could never count toward a revocation
        // certificate's quorum). RotatingDnsResolver interpolates this value directly
        // after "fp=", so joining on " fp=" produces one token per fingerprint.
        var realFingerprints = string.Join(" fp=", allDomainKeys.Select(k => k.Fingerprint));
        var pinnedFingerprint = scenario.DnsFingerprintOverride ?? realFingerprints;
        var dns = new RotatingDnsResolver(UserDomain, pinnedFingerprint, fakeIdp.Ports);
        ITransport transport = new StdTransport(AddressPolicy.Permissive, connectTimeoutMillis: 5000, ioTimeoutMillis: 5000);

        var config = new Complete.CompleteLocalLoginConfig(
            keyMaterial, pending, encryptedToken, arrivedUrl, now, Transport: transport, Dns: dns);
        return Complete.CompleteLocalLogin(config);
    }

    [Fact]
    public void HappyPathReturnsVerifiedLogin()
    {
        var result = RunScenario(new Scenario());
        Assert.Equal("user-1", result.UserId);
        Assert.Equal(UserDomain, result.UserDomain);
        Assert.Single(result.Claims);
        Assert.Equal("handle", result.Claims[0].ClaimType);
        Assert.Equal(64, result.LocalRpFingerprint.Length);
        Assert.Single(result.DomainPublicKeys);
    }

    [Fact]
    public void WrongAudienceFingerprintIsRejected()
    {
        var s = new Scenario
        {
            MutatePayload = p => p with { AudienceFingerprint = new string('b', 64) },
            ExpectedRequests = 2,
        };
        Assert.Throws<LocalRpError>(() => RunScenario(s));
    }

    [Fact]
    public void WrongIssuerDomainIsRejected()
    {
        var s = new Scenario
        {
            MutatePayload = p => p with { UserDomain = "attacker.test" },
            ExpectedRequests = 2,
        };
        Assert.Throws<LocalRpError>(() => RunScenario(s));
    }

    [Fact]
    public void NonceMismatchIsRejected()
    {
        var wrongNonce = new byte[32];
        Array.Fill(wrongNonce, (byte)0xEE);
        var s = new Scenario
        {
            MutatePayload = p => p with { Nonce = wrongNonce },
            ExpectedRequests = 2,
        };
        Assert.Throws<LocalRpError>(() => RunScenario(s));
    }

    [Fact]
    public void ExpiredCallbackPayloadIsRejected()
    {
        var s = new Scenario
        {
            MutatePayload = p =>
            {
                var n = DateTimeOffset.UtcNow;
                return p with
                {
                    IssuedAt = Rfc3339.Format(n - TimeSpan.FromHours(2)),
                    ExpiresAt = Rfc3339.Format(n - TimeSpan.FromHours(1)),
                };
            },
            ExpectedRequests = 2,
        };
        Assert.Throws<LocalRpError>(() => RunScenario(s));
    }

    [Fact]
    public void DnsFingerprintPinMismatchIsRejected()
    {
        var s = new Scenario { DnsFingerprintOverride = new string('c', 64), ExpectedRequests = 1 };
        // Fails during the TLS handshake's mandatory post-handshake pin check (the fake
        // IDP's real cert fingerprint no longer matches the pinned set) -- either way it
        // must never reach a verified result.
        Assert.ThrowsAny<Exception>(() => RunScenario(s));
    }

    [Fact]
    public void RevokedSigningKeyIsRejected()
    {
        var s = new Scenario
        {
            MutateDomainKey = k => k with { RevokedAt = Rfc3339.Format(DateTimeOffset.UtcNow) },
            ExpectedRequests = 2,
        };
        Assert.Throws<LocalRpError>(() => RunScenario(s));
    }

    [Fact]
    public void TamperedClaimSignatureIsRejected()
    {
        var s = new Scenario
        {
            MutateClaim = c =>
            {
                if (c.Signatures.Count == 0)
                {
                    return c;
                }

                var sig = c.Signatures[0];
                var flipped = (byte[])sig.Signature.Clone();
                flipped[0] ^= 0xff;
                var newSigs = new List<ClaimSignature> { sig with { Signature = flipped } };
                newSigs.AddRange(c.Signatures.Skip(1));
                return c with { Signatures = newSigs };
            },
            ExpectedRequests = 3,
        };
        Assert.Throws<ClaimError>(() => RunScenario(s));
    }

    // ---------------------------------------------------------------------
    // Hostile-IDP tests (security review fix-up): a compromised/malicious IDP
    // controls every network response this SDK receives. Each test proves one
    // specific lie the IDP might tell is caught and rejected -- FATAL, never a
    // silent fallback to unverified data.
    // ---------------------------------------------------------------------

    /// <summary>
    /// (1) The claim-ticket redemption response -- which carries no signature of its own
    /// -- names a different user than the domain-SIGNED callback payload. A pre-fix SDK
    /// trusted the redemption response's identity outright; this must be fatal.
    /// </summary>
    [Fact]
    public void RedemptionUserIdMismatchWithSignedPayloadIsRejected()
    {
        var s = new Scenario
        {
            MutateRedemption = r => r with { UserId = "attacker-user" },
            ExpectedRequests = 3,
        };
        var ex = Assert.Throws<LocalRpError>(() => RunScenario(s));
        Assert.Equal(LocalRpError.ErrorKind.RedemptionIdentityMismatch, ex.Kind);
    }

    /// <summary>(1, continued) Same lie, on the domain field instead of the user id.</summary>
    [Fact]
    public void RedemptionUserDomainMismatchWithSignedPayloadIsRejected()
    {
        var s = new Scenario
        {
            MutateRedemption = r => r with { UserDomain = "attacker.test" },
            ExpectedRequests = 3,
        };
        var ex = Assert.Throws<LocalRpError>(() => RunScenario(s));
        Assert.Equal(LocalRpError.ErrorKind.RedemptionIdentityMismatch, ex.Kind);
    }

    /// <summary>
    /// (2) An individual claim inside an otherwise-correctly-signed redemption response
    /// names a different <c>user_id</c> than the signed callback payload -- a malicious
    /// IDP splicing another user's claim into this login's response. The claim's own
    /// signature only proves ITS issuing domain signed that claim, not that it belongs to
    /// this login's subject, so this must be checked and rejected independently of
    /// signature validity.
    /// </summary>
    [Fact]
    public void ClaimUserIdMismatchWithSignedPayloadIsRejected()
    {
        var s = new Scenario
        {
            MutateClaim = c => c with { UserId = "attacker-user" },
            ExpectedRequests = 3,
        };
        var ex = Assert.Throws<LocalRpError>(() => RunScenario(s));
        Assert.Equal(LocalRpError.ErrorKind.ClaimIdentityMismatch, ex.Kind);
    }

    /// <summary>
    /// (3) <see cref="Begin.BeginLocalLogin"/>'s default <c>RequiredClaims</c>
    /// (<c>["handle"]</c>) demands a claim the redemption response doesn't actually
    /// return. A pre-fix SDK never checked <c>RequiredClaims</c> at all, so a
    /// malicious/degraded IDP could silently drop a required claim and completion would
    /// still succeed.
    /// </summary>
    [Fact]
    public void RequiredClaimsNotSatisfiedWhenRedemptionReturnsNoClaimsIsRejected()
    {
        var s = new Scenario
        {
            MutateRedemption = r => r with { Claims = [] },
            ExpectedRequests = 3,
        };
        var ex = Assert.Throws<LocalRpError>(() => RunScenario(s));
        Assert.Equal(LocalRpError.ErrorKind.RequiredClaimsNotSatisfied, ex.Kind);
        Assert.Equal("handle", ex.Detail);
    }

    /// <summary>
    /// (4) The fake IDP answers <c>get-domain-keys</c> normally but fails
    /// <c>get-revocations</c> outright. A pre-fix SDK treated revocation delivery as
    /// best-effort and silently proceeded with an unfiltered (possibly containing revoked
    /// signers) key set; this must fail closed instead.
    /// </summary>
    [Fact]
    public void GetRevocationsTransportErrorFailsClosed()
    {
        var s = new Scenario
        {
            FailRevocations = true,
            ExpectedRequests = 2,
        };
        var ex = Assert.Throws<SdkException>(() => RunScenario(s));
        Assert.Equal(SdkException.ErrorKind.RevocationUnavailable, ex.Kind);
    }

    /// <summary>
    /// (5) A genuine, quorum-valid sibling-signed revocation certificate targets the
    /// exact domain signing key that signed both the callback envelope and the claim.
    /// Because the fixture never sets <c>RecentRevocationsAvailable</c>, this also proves
    /// revocations are fetched unconditionally: a pre-fix SDK gated the
    /// <c>get-revocations</c> call on that flag and would never have learned of this
    /// certificate at all, so the envelope would still verify against the (now-revoked)
    /// signing key.
    /// </summary>
    [Fact]
    public void RevocationCertificateDropsSigningKeyAndLoginFailsClosed()
    {
        var now = DateTimeOffset.UtcNow;
        var siblingA = Crypto.Crypto.GenerateEd25519KeyPair();
        var siblingB = Crypto.Crypto.GenerateEd25519KeyPair();
        var siblingAKey = KeyedDomainPublicKey(now, siblingA.PublicKey, SiblingAKeyId);
        var siblingBKey = KeyedDomainPublicKey(now, siblingB.PublicKey, SiblingBKeyId);

        var s = new Scenario
        {
            ExtraDomainKeys = [siblingAKey, siblingBKey],
            // Built from the (randomly-generated-per-run) primary domain key RunScenario
            // passes in here, so the certificate targets the exact key that will go on to
            // sign both the callback envelope and the claim -- a genuine, quorum-valid
            // (two DISTINCT sibling signers, per Revocation.Quorum) revocation.
            BuildRevocations = domainKey =>
            {
                var revokedAt = Rfc3339.Format(now);
                var payload = Revocation.RevocationPayload(DomainKeyId, domainKey.Fingerprint, revokedAt, UserDomain);
                var sigA = Crypto.Crypto.SignEd25519(payload, siblingA.PrivateKeySeed);
                var sigB = Crypto.Crypto.SignEd25519(payload, siblingB.PrivateKeySeed);
                return
                [
                    new RevocationCertificate(
                        DomainKeyId,
                        domainKey.Fingerprint,
                        revokedAt,
                        [
                            new ClaimSignature(UserDomain, SiblingAKeyId, sigA),
                            new ClaimSignature(UserDomain, SiblingBKeyId, sigB),
                        ]),
                ];
            },
            // get-domain-keys + get-revocations only: the envelope fails to verify (its
            // signing key was just dropped) before any ticket is ever redeemed.
            ExpectedRequests = 2,
        };

        var ex = Assert.Throws<LocalRpError>(() => RunScenario(s));
        Assert.Equal(LocalRpError.ErrorKind.KeyNotFound, ex.Kind);
    }
}
