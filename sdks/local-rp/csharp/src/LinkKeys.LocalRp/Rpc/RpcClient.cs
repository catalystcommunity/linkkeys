using LinkKeys.LocalRp.Dns;
using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp.Rpc;

/// <summary>
/// CSIL-RPC over the injected <see cref="ITransport"/>, TLS-pinned to a domain's DNS
/// <c>fp=</c> records — this SDK's only network surface, per the design doc's "Required
/// Network Access": domain public keys, revocations, and claim-ticket redemption, all
/// unauthenticated-TLS TCP CSIL-RPC calls.
/// </summary>
public static class RpcClient
{
    /// <summary>A discovered endpoint for a domain: its pinned trust-anchor fingerprints and its CSIL-RPC TCP address.</summary>
    public sealed record DomainEndpoint(IReadOnlyList<string> Fingerprints, string TcpAddr);

    /// <summary>
    /// Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails closed: a
    /// missing/unparseable record, or a <c>_linkkeys</c> record with no <c>fp=</c>
    /// entries, or a <c>_linkkeys_apis</c> record with no <c>tcp=</c> entry, is an error.
    /// </summary>
    public static DomainEndpoint DiscoverDomainEndpoint(IDnsResolver dns, string domain)
    {
        var anchorName = LinkKeys.LocalRp.Dns.Dns.LinkKeysDnsName(domain);
        var anchorTxts = dns.TxtLookup(anchorName);
        IReadOnlyList<string>? fingerprints = null;
        foreach (var txt in anchorTxts)
        {
            try
            {
                var rec = LinkKeys.LocalRp.Dns.Dns.ParseLinkKeysTxt(txt);
                if (rec.Fingerprints.Count > 0)
                {
                    fingerprints = rec.Fingerprints;
                    break;
                }
            }
            catch (DnsParseError)
            {
                // try the next TXT record
            }
        }

        if (fingerprints is null)
        {
            throw new SdkException(SdkException.ErrorKind.Dns, $"no usable {anchorName} TXT record with fp= entries");
        }

        var apisName = LinkKeys.LocalRp.Dns.Dns.LinkKeysApisDnsName(domain);
        var apisTxts = dns.TxtLookup(apisName);
        string? tcpAddr = null;
        foreach (var txt in apisTxts)
        {
            try
            {
                var apis = LinkKeys.LocalRp.Dns.Dns.ParseLinkKeysApisTxt(txt);
                if (apis.Tcp is not null)
                {
                    tcpAddr = apis.Tcp;
                    break;
                }
            }
            catch (DnsParseError)
            {
                // try the next TXT record
            }
        }

        if (tcpAddr is null)
        {
            throw new SdkException(SdkException.ErrorKind.Dns, $"no usable {apisName} TXT record with tcp= entry");
        }

        return new DomainEndpoint(fingerprints, tcpAddr);
    }

    private static string ExtractHostname(string hostPort)
    {
        if (hostPort.StartsWith('['))
        {
            int end = hostPort.IndexOf(']');
            if (end != -1)
            {
                return hostPort[1..end];
            }
        }

        int idx = hostPort.LastIndexOf(':');
        return idx == -1 ? hostPort : hostPort[..idx];
    }

    /// <summary>Send one CSIL-RPC request over a fresh TLS connection to <paramref name="endpoint"/> and return the decoded success payload.</summary>
    private static byte[] Call(ITransport transport, DomainEndpoint endpoint, string service, string op, byte[] payload)
    {
        var raw = transport.Dial(endpoint.TcpAddr);
        var hostname = ExtractHostname(endpoint.TcpAddr);
        using var tls = TlsPinning.ConnectPinned(raw, hostname, endpoint.Fingerprints);

        var request = new RpcEnvelope.Request(service, op, payload);
        StreamFraming.SendFrame(tls, request.Encode());
        var respBytes = StreamFraming.ReadFrame(tls);
        var resp = RpcEnvelope.DecodeResponse(respBytes);

        if (!resp.IsOk)
        {
            throw new SdkException(resp.StatusCode, resp.Error ?? "unknown error");
        }

        return resp.Payload;
    }

    /// <summary>
    /// Fetch <paramref name="domain"/>'s currently-trusted public keys:
    /// <c>DomainKeys/get-domain-keys</c> over TCP CSIL-RPC, pinned to the domain's DNS
    /// <c>fp=</c> set, with signing keys pinned directly and encryption keys trusted
    /// only via a pinned signing key's vouch. <b>Always</b> also fetches
    /// <c>DomainKeys/get-revocations</c> for the same domain — regardless of what the
    /// <c>get-domain-keys</c> response's <c>RecentRevocationsAvailable</c> flag says — and
    /// drops any key a quorum-verified sibling revocation certificate targets.
    /// <c>RecentRevocationsAvailable</c> is an optional performance hint a well-behaved
    /// IDP may use to signal "you don't even need to ask"; a compromised/malicious or
    /// merely buggy IDP could otherwise use its absence to suppress this SDK from ever
    /// learning about a revocation, which is exactly the scenario revocation exists to
    /// guard against — so this SDK never uses it to skip the check. A
    /// <c>get-revocations</c> RPC or decode error is FATAL: this SDK must fail closed
    /// rather than silently proceed with a possibly-stale key set an attacker could have
    /// engineered by making the endpoint fail. An empty revocation list is normal
    /// success (nothing to apply). An empty trusted result (after applying revocations)
    /// is a fail-closed <see cref="SdkException"/>, matching the server's own posture.
    /// </summary>
    public static List<DomainPublicKey> FetchDomainKeys(ITransport transport, IDnsResolver dns, string domain)
    {
        var endpoint = DiscoverDomainEndpoint(dns, domain);

        var payload = Codec.EncodeEmptyRequest(new EmptyRequest());
        var respBytes = Call(transport, endpoint, "DomainKeys", "get-domain-keys", payload);
        var resp = Codec.DecodeGetDomainKeysResponse(respBytes);

        var trusted = new List<DomainPublicKey>(LinkKeys.LocalRp.Dns.Dns.TrustKeys(resp.Keys, endpoint.Fingerprints));
        if (trusted.Count == 0)
        {
            throw new SdkException(SdkException.ErrorKind.NoTrustedDomainKeys, domain);
        }

        // Always fetch revocations — never gated on RecentRevocationsAvailable (see this
        // method's doc comment). A failure here is FATAL: it must never be swallowed to
        // "just proceed unfiltered". Re-resolved (rather than reusing `endpoint`) so this
        // is a fresh, independently-pinned dial like every other RPC call this SDK makes
        // — matching `RedeemClaimTicket`'s own resolve-then-dial shape rather than
        // threading connection state across two logically separate calls.
        var revocationsEndpoint = DiscoverDomainEndpoint(dns, domain);
        var since = DateTimeOffset.UtcNow.AddDays(-30).ToString("O");
        var reqPayload = Codec.EncodeGetRevocationsRequest(new GetRevocationsRequest(since));
        GetRevocationsResponse revResp;
        try
        {
            var revRespBytes = Call(transport, revocationsEndpoint, "DomainKeys", "get-revocations", reqPayload);
            revResp = Codec.DecodeGetRevocationsResponse(revRespBytes);
        }
        catch (Exception e) when (e is not OutOfMemoryException and not StackOverflowException)
        {
            // Fail closed: an unreachable/erroring/malformed get-revocations call (RPC
            // transport failure, TLS failure, or a decode error) must never be silently
            // treated as "no revocations" — that would let a hostile or merely-unreliable
            // IDP suppress a key's revocation simply by dropping or corrupting this call.
            throw new SdkException(
                SdkException.ErrorKind.RevocationUnavailable, $"get-revocations failed for domain {domain}", e);
        }

        foreach (var cert in revResp.Revocations)
        {
            try
            {
                Revocation.VerifyRevocationCertificate(cert, trusted, domain);
                trusted.RemoveAll(k => k.KeyId == cert.TargetKeyId);
            }
            catch (RevocationError)
            {
                // certificate didn't meet quorum; key stays trusted
            }
        }

        if (trusted.Count == 0)
        {
            throw new SdkException(SdkException.ErrorKind.NoTrustedDomainKeys, domain);
        }

        return trusted;
    }

    /// <summary>
    /// Redeem a claim ticket with <paramref name="domain"/>'s IDP:
    /// <c>LocalRp/redeem-claim-ticket</c> over TCP CSIL-RPC, pinned via the domain's DNS
    /// <c>fp=</c> set. Unauthenticated at the transport layer (no client cert) — the
    /// redemption request itself is signed with the local RP's signing key, which is the
    /// possession proof the server checks.
    /// </summary>
    public static LocalRpTicketRedemptionResponse RedeemClaimTicket(
        ITransport transport, IDnsResolver dns, string domain, SignedLocalRpTicketRedemptionRequest signedRequest)
    {
        var endpoint = DiscoverDomainEndpoint(dns, domain);
        var payload = Codec.EncodeSignedLocalRpTicketRedemptionRequest(signedRequest);
        var respBytes = Call(transport, endpoint, "LocalRp", "redeem-claim-ticket", payload);
        return Codec.DecodeLocalRpTicketRedemptionResponse(respBytes);
    }
}
