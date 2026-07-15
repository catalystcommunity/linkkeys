using LinkKeys.LocalRp.Dns;
using LinkKeys.LocalRp.Rpc;
using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp;

/// <summary>
/// <c>complete_local_login</c> (design doc: "SDK API Shape", "Flow" steps 12-13).
///
/// <para>This is the SDK's full verification chain, run in the exact order the pure
/// <see cref="LocalRp"/> helpers require:</para>
///
/// <list type="number">
/// <item>decode the callback ciphertext from its URL-param encoding</item>
/// <item>open it (decrypt) — only with a suite this identity's own descriptor advertises</item>
/// <item>fetch the pending domain's public keys + revocations, DNS-<c>fp=</c>-pinned, over TCP CSIL-RPC</item>
/// <item>verify the domain-signed envelope (key lookup, revocation/expiry, signature,
/// payload timestamp bounds) — only now is anything inside the payload trusted</item>
/// <item>cross-check the cleartext header's routing fields against the now-verified payload</item>
/// <item>audience / issuer / callback-URL / nonce-state checks</item>
/// <item>redeem the claim ticket over TCP CSIL-RPC (signed with the local RP's own key —
/// the possession proof)</item>
/// <item>cross-check the (unsigned) redemption response's identity against the SIGNED
/// callback payload's identity — fatal on mismatch</item>
/// <item>verify every returned claim's signatures against ITS signer domain's keys
/// (fetched the same pinned way), which also checks the claim's own revocation/expiry,
/// AND that each claim's subject matches the verified payload's identity</item>
/// <item>enforce that every <c>RequiredClaims</c> entry from the pending login is
/// covered by a claim that passed the checks above</item>
/// </list>
/// </summary>
public static class Complete
{
    /// <summary>
    /// Bound on the number of distinct claim-signer domains
    /// <see cref="CompleteLocalLogin"/> will fetch keys for per completion. The
    /// redemption response's claim signatures name their signing domains as plain,
    /// not-yet-verified strings — a malicious/compromised home IDP could otherwise list
    /// an unbounded number of distinct "signer domains" purely to make this SDK perform
    /// many outbound DNS/TCP calls to attacker-chosen targets before any signature is
    /// actually checked (an SSRF/DoS amplification vector against the app's own
    /// process).
    /// </summary>
    public const int MaxClaimSignerDomains = Claims.MaxClaimSignerDomains;

    /// <summary>Input to <see cref="CompleteLocalLogin"/>. Every field is load-bearing.</summary>
    /// <param name="KeyMaterial">The same identity <see cref="Begin.BeginLocalLogin"/> used.</param>
    /// <param name="Pending">The pending-login state <c>BeginLocalLogin</c> returned, exactly as the app persisted it.</param>
    /// <param name="EncryptedToken">The raw callback data — the <c>encrypted_token</c> query-parameter value.</param>
    /// <param name="ArrivedUrl">The URL the callback actually arrived at (the app's own HTTP handler's request URL).</param>
    /// <param name="ClockSkewSeconds">Clock-skew tolerance for timestamp checks. Defaults to <see cref="LocalRp.DefaultClockSkewSeconds"/> when <c>null</c>.</param>
    /// <param name="Transport">The TCP dial seam. Defaults to <see cref="LinkKeysLocalRp.DefaultTransport"/>.</param>
    /// <param name="Dns">The DNS TXT lookup seam. Defaults to <see cref="LinkKeysLocalRp.DefaultDnsResolver"/>.</param>
    public sealed record CompleteLocalLoginConfig(
        Identity.LocalRpKeyMaterial KeyMaterial,
        Begin.PendingLogin Pending,
        string EncryptedToken,
        string ArrivedUrl,
        DateTimeOffset Now,
        long? ClockSkewSeconds = null,
        ITransport? Transport = null,
        IDnsResolver? Dns = null);

    /// <summary>What <see cref="CompleteLocalLogin"/> returns to app code.</summary>
    public sealed record VerifiedLocalLogin(
        string UserId,
        string UserDomain,
        IReadOnlyList<Claim> Claims,
        IReadOnlyList<DomainPublicKey> DomainPublicKeys,
        string LocalRpFingerprint,
        DateTimeOffset IssuedAt,
        DateTimeOffset ExpiresAt,
        DateTimeOffset TicketExpiresAt);

    /// <summary>
    /// Undo the exact <c>?</c>/<c>&amp;</c> + <c>encrypted_token=</c> suffix construction
    /// the IDP uses to deliver the callback, so the recovered value can be compared
    /// against the signed payload's <c>callback_url</c>. If the arrived URL doesn't end
    /// with that exact suffix, returns it unchanged — the subsequent
    /// <see cref="LocalRp.VerifyCallbackUrl"/> equality check then correctly fails closed
    /// rather than this method guessing.
    /// </summary>
    internal static string StripEncryptedTokenParam(string arrivedUrl)
    {
        foreach (var sep in new[] { '?', '&' })
        {
            var marker = $"{sep}encrypted_token=";
            var idx = arrivedUrl.LastIndexOf(marker, StringComparison.Ordinal);
            if (idx >= 0)
            {
                return arrivedUrl[..idx];
            }
        }

        return arrivedUrl;
    }

    /// <summary><c>complete_local_login(config) -&gt; VerifiedLocalLogin</c> (design doc, "SDK API Shape").</summary>
    public static VerifiedLocalLogin CompleteLocalLogin(CompleteLocalLoginConfig config)
    {
        long skew = config.ClockSkewSeconds ?? LocalRp.DefaultClockSkewSeconds;
        var transport = config.Transport ?? LinkKeysLocalRp.DefaultTransport();
        var dns = config.Dns ?? LinkKeysLocalRp.DefaultDnsResolver();

        // 1. Decode the callback's URL-param encoding.
        var encrypted = UrlEncoding.LocalRpEncryptedCallbackFromUrlParam(config.EncryptedToken);

        // 2. Open it, restricted to suites THIS identity's own descriptor advertises.
        var ownDescriptor = Codec.DecodeLocalRpDescriptor(config.KeyMaterial.Descriptor.Descriptor);
        var allowedSuites = new List<Crypto.AeadSuite>();
        foreach (var s in ownDescriptor.SupportedSuites)
        {
            var suite = Crypto.AeadSuiteExtensions.Parse(s);
            if (suite is not null)
            {
                allowedSuites.Add(suite.Value);
            }
        }

        var opened = LocalRp.OpenLocalRpCallback(encrypted, config.KeyMaterial.EncryptionPrivateKey, allowedSuites);

        // 3. Fetch the PENDING state's domain's keys + revocations, DNS-pinned, over TCP CSIL-RPC.
        var userDomainKeys = RpcClient.FetchDomainKeys(transport, dns, config.Pending.UserDomain);

        // 4. Verify the domain-signed envelope against those keys. Nothing inside
        // `payload` is trusted before this succeeds.
        var payload = LocalRp.VerifyLocalRpCallbackPayload(opened.SignedPayload, userDomainKeys, config.Now, skew);

        // 5. Cross-check the cleartext header's routing twins against the now-verified payload.
        LocalRp.CheckCallbackHeaderMatchesPayload(opened.Header, payload);

        // 6a. Audience: the callback names THIS local RP.
        LocalRp.VerifyAudience(payload.AudienceFingerprint, config.KeyMaterial.Fingerprint);

        // 6b. Issuer binding: the payload's user_domain must be the domain the login was BEGUN with.
        LocalRp.VerifyIssuer(payload.UserDomain, config.Pending.UserDomain);

        // 6c. Callback URL binding against the URL the callback actually arrived at.
        var arrivedBaseUrl = StripEncryptedTokenParam(config.ArrivedUrl);
        LocalRp.VerifyCallbackUrl(payload.CallbackUrl, arrivedBaseUrl);

        // 6d. Nonce/state equality against the pending state.
        LocalRp.VerifyNonceState(config.Pending.Nonce, config.Pending.State, payload.Nonce, payload.State);

        // 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the local RP's own key.
        var redemptionRequest = LocalRp.BuildLocalRpTicketRedemptionRequest(
            payload.ClaimTicket, config.KeyMaterial.Fingerprint, Rfc3339.Format(config.Now));
        var signedRedemption = LocalRp.SignLocalRpTicketRedemptionRequest(redemptionRequest, config.KeyMaterial.SigningPrivateKey);
        var redemption = RpcClient.RedeemClaimTicket(transport, dns, config.Pending.UserDomain, signedRedemption);

        // 7a. Identity binding (SEC fix): the ticket redemption response carries no
        // signature of its own — it is trusted only because it was fetched over the
        // DNS-pinned TLS channel for the domain the SIGNED callback payload named. That is
        // not the same as the redemption response actually agreeing with the payload: a
        // compromised/malicious IDP could hand back claims for a different user than the
        // one it cryptographically vouched for in the signed callback (e.g. to launder an
        // approval given to user A onto user B's claims). Cross-check unconditionally, and
        // treat any mismatch as fatal — never fall back to either identity alone.
        LocalRp.VerifyRedemptionIdentity(redemption.UserId, redemption.UserDomain, payload.UserId, payload.UserDomain);

        // 8. Verify every returned claim's signatures against ITS signer domain's keys,
        // fetched the same pinned way. Reuse the home domain's already-fetched keys;
        // fetch any additional signer domains on demand, capped at MaxClaimSignerDomains.
        //
        // The redemption response's claim signatures name their signing domains as plain,
        // not-yet-verified strings — a malicious/compromised home IDP could otherwise list
        // an unbounded number of distinct "signer domains" purely to make this SDK perform
        // many outbound DNS/TCP calls to attacker-chosen targets before any signature is
        // actually checked (an SSRF/DoS amplification vector against the app's own
        // process). MaxClaimSignerDomains bounds that.
        var domainKeySets = new List<Claims.DomainKeySet> { new(config.Pending.UserDomain, userDomainKeys) };
        foreach (var claim in redemption.Claims)
        {
            foreach (var sig in claim.Signatures)
            {
                bool known = domainKeySets.Any(s => s.Domain == sig.Domain);
                if (!known)
                {
                    if (domainKeySets.Count >= MaxClaimSignerDomains)
                    {
                        throw new SdkException(
                            SdkException.ErrorKind.InvalidInput,
                            $"claim set names more than {MaxClaimSignerDomains} distinct signer domains; refusing to fetch further keys");
                    }

                    var keys = RpcClient.FetchDomainKeys(transport, dns, sig.Domain);
                    domainKeySets.Add(new Claims.DomainKeySet(sig.Domain, keys));
                }
            }
        }

        // Subject domain for signature verification is the VERIFIED, SIGNED payload's
        // UserDomain — not the (unsigned) redemption response's, even though the two are
        // now known to agree (checked above). Each claim must also name the SAME user the
        // signed payload vouched for: without this check, a malicious IDP could splice in
        // a claim belonging to a different user_id inside an otherwise-valid,
        // correctly-signed redemption response (the claim's own signature only proves the
        // issuing domain signed THAT claim, not that it's the claim for THIS login).
        // Checked before signature verification so it is never confused with a signature
        // failure. Only claim types that survive both checks count toward RequiredClaims.
        var verifiedClaimTypes = new HashSet<string>();
        foreach (var claim in redemption.Claims)
        {
            LocalRp.VerifyClaimIdentity(claim.UserId, payload.UserId);
            Claims.VerifyClaim(claim, payload.UserDomain, domainKeySets);
            verifiedClaimTypes.Add(claim.ClaimType);
        }

        // Enforce the RequiredClaims the login was BEGUN with (SEC checklist: "the
        // app-declared required claims are actually enforced"). Only claim types that
        // survived the checks above count — an unsigned/unverifiable claim, or one naming
        // the wrong subject, can never satisfy a requirement. An empty or insufficient
        // claim set against a non-empty requirement is fatal.
        LocalRp.VerifyRequiredClaimsSatisfied(config.Pending.RequiredClaims, verifiedClaimTypes);

        return new VerifiedLocalLogin(
            // Sourced from the VERIFIED, SIGNED payload — not the redemption response —
            // even though the two are now known to agree (checked above). The payload is
            // the thing that was actually cryptographically attested by the domain; the
            // redemption response is merely corroborating data fetched over a channel that
            // is pinned but otherwise unsigned.
            payload.UserId,
            payload.UserDomain,
            redemption.Claims,
            userDomainKeys,
            config.KeyMaterial.Fingerprint,
            Rfc3339.Parse("issued_at", payload.IssuedAt),
            Rfc3339.Parse("expires_at", payload.ExpiresAt),
            Rfc3339.Parse("ticket_expires_at", redemption.TicketExpiresAt));
    }
}
