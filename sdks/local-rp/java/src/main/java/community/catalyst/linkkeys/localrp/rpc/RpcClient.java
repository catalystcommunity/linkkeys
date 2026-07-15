package community.catalyst.linkkeys.localrp.rpc;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLSocket;

import community.catalyst.linkkeys.localrp.Revocation;
import community.catalyst.linkkeys.localrp.SdkException;
import community.catalyst.linkkeys.localrp.dns.Dns;
import community.catalyst.linkkeys.localrp.dns.DnsParseError;
import community.catalyst.linkkeys.localrp.dns.DnsResolver;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;
import community.catalyst.linkkeys.localrp.wire.Types.EmptyRequest;
import community.catalyst.linkkeys.localrp.wire.Types.GetDomainKeysResponse;
import community.catalyst.linkkeys.localrp.wire.Types.GetRevocationsRequest;
import community.catalyst.linkkeys.localrp.wire.Types.GetRevocationsResponse;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpTicketRedemptionResponse;
import community.catalyst.linkkeys.localrp.wire.Types.RevocationCertificate;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpTicketRedemptionRequest;

/**
 * CSIL-RPC over the injected {@link Transport}, TLS-pinned to a domain's DNS
 * {@code fp=} records &mdash; this SDK's only network surface, per the
 * design doc's "Required Network Access": domain public keys, revocations,
 * and claim-ticket redemption, all unauthenticated-TLS TCP CSIL-RPC calls.
 */
public final class RpcClient {
    private RpcClient() {}

    /** A discovered endpoint for a domain: its pinned trust-anchor fingerprints and its CSIL-RPC TCP address. */
    public record DomainEndpoint(List<String> fingerprints, String tcpAddr) {}

    /**
     * Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails
     * closed: a missing/unparseable record, or a {@code _linkkeys} record
     * with no {@code fp=} entries, or a {@code _linkkeys_apis} record with
     * no {@code tcp=} entry, is an error.
     */
    public static DomainEndpoint discoverDomainEndpoint(DnsResolver dns, String domain) {
        String anchorName = Dns.linkkeysDnsName(domain);
        List<String> anchorTxts = dns.txtLookup(anchorName);
        List<String> fingerprints = null;
        for (String txt : anchorTxts) {
            try {
                Dns.LinkKeysRecord rec = Dns.parseLinkKeysTxt(txt);
                if (!rec.fingerprints().isEmpty()) {
                    fingerprints = rec.fingerprints();
                    break;
                }
            } catch (DnsParseError ignored) {
                // try the next TXT record
            }
        }
        if (fingerprints == null) {
            throw new SdkException(SdkException.Kind.DNS, "no usable " + anchorName + " TXT record with fp= entries");
        }

        String apisName = Dns.linkkeysApisDnsName(domain);
        List<String> apisTxts = dns.txtLookup(apisName);
        String tcpAddr = null;
        for (String txt : apisTxts) {
            try {
                Dns.LinkKeysApis apis = Dns.parseLinkKeysApisTxt(txt);
                if (apis.tcp() != null) {
                    tcpAddr = apis.tcp();
                    break;
                }
            } catch (DnsParseError ignored) {
                // try the next TXT record
            }
        }
        if (tcpAddr == null) {
            throw new SdkException(SdkException.Kind.DNS, "no usable " + apisName + " TXT record with tcp= entry");
        }

        return new DomainEndpoint(fingerprints, tcpAddr);
    }

    private static String extractHostname(String hostPort) {
        if (hostPort.startsWith("[")) {
            int end = hostPort.indexOf(']');
            if (end != -1) {
                return hostPort.substring(1, end);
            }
        }
        int idx = hostPort.lastIndexOf(':');
        return idx == -1 ? hostPort : hostPort.substring(0, idx);
    }

    /** Send one CSIL-RPC request over a fresh TLS connection to {@code endpoint} and return the decoded success payload. */
    static byte[] call(Transport transport, DomainEndpoint endpoint, String service, String op, byte[] payload) {
        Socket raw = transport.dial(endpoint.tcpAddr());
        String hostname = extractHostname(endpoint.tcpAddr());
        try (SSLSocket tls = TlsPinning.connectPinned(raw, hostname, endpoint.fingerprints())) {
            OutputStream out = tls.getOutputStream();
            InputStream in = tls.getInputStream();

            RpcEnvelope.Request request = new RpcEnvelope.Request(service, op, payload);
            StreamFraming.sendFrame(out, request.encode());
            byte[] respBytes = StreamFraming.readFrame(in);
            RpcEnvelope.Response resp = RpcEnvelope.decodeResponse(respBytes);

            if (!resp.isOk()) {
                throw new SdkException(resp.status(), resp.error() == null ? "unknown error" : resp.error());
            }
            return resp.payload();
        } catch (java.io.IOException e) {
            throw new SdkException(SdkException.Kind.TRANSPORT, e.getMessage(), e);
        }
    }

    /**
     * Fetch {@code domain}'s currently-trusted public keys:
     * {@code DomainKeys/get-domain-keys} over TCP CSIL-RPC, pinned to the
     * domain's DNS {@code fp=} set, with signing keys pinned directly and
     * encryption keys trusted only via a pinned signing key's vouch.
     * <b>Always</b> also fetches {@code DomainKeys/get-revocations} for
     * this domain &mdash; regardless of any {@code recent_revocations_available}
     * hint the peer includes in the keys response, since that flag is
     * peer-supplied and a malicious/compromised IDP could simply omit it to
     * suppress a revocation. A failure to fetch or decode the revocation
     * list is <b>fatal</b> (fail closed), not best-effort: revocation
     * delivery is mandatory context for trusting these keys at all. An
     * empty revocation list is a normal, successful outcome. Verified
     * revocation certificates are applied before returning. An empty
     * trusted result (either because no keys were pinned, or because
     * revocation emptied the set) is a fail-closed {@link SdkException}.
     */
    public static List<DomainPublicKey> fetchDomainKeys(Transport transport, DnsResolver dns, String domain) {
        DomainEndpoint endpoint = discoverDomainEndpoint(dns, domain);

        byte[] payload = Codec.encodeEmptyRequest(new EmptyRequest());
        byte[] respBytes = call(transport, endpoint, "DomainKeys", "get-domain-keys", payload);
        GetDomainKeysResponse resp = Codec.decodeGetDomainKeysResponse(respBytes);

        List<DomainPublicKey> trusted =
                new ArrayList<>(community.catalyst.linkkeys.localrp.dns.Dns.trustKeys(resp.keys(), endpoint.fingerprints()));
        if (trusted.isEmpty()) {
            throw new SdkException(SdkException.Kind.NO_TRUSTED_DOMAIN_KEYS, domain);
        }

        String since = Instant.now().minus(Duration.ofDays(30)).toString();
        byte[] reqPayload = Codec.encodeGetRevocationsRequest(new GetRevocationsRequest(since));
        GetRevocationsResponse revResp;
        try {
            byte[] revRespBytes = call(transport, endpoint, "DomainKeys", "get-revocations", reqPayload);
            revResp = Codec.decodeGetRevocationsResponse(revRespBytes);
        } catch (RuntimeException e) {
            // Fail closed: an unreachable/erroring/malformed get-revocations
            // call must never be silently treated as "no revocations" --
            // that would let a hostile or merely-unreliable IDP suppress a
            // key's revocation simply by dropping this call.
            throw new SdkException(
                    SdkException.Kind.REVOCATION_UNAVAILABLE,
                    "get-revocations failed for domain " + domain,
                    e);
        }
        for (RevocationCertificate cert : revResp.revocations()) {
            try {
                Revocation.verifyRevocationCertificate(cert, trusted, domain);
                trusted.removeIf(k -> k.keyId().equals(cert.targetKeyId()));
            } catch (RuntimeException ignored) {
                // certificate didn't meet quorum; key stays trusted
            }
        }

        if (trusted.isEmpty()) {
            throw new SdkException(SdkException.Kind.NO_TRUSTED_DOMAIN_KEYS, domain);
        }
        return trusted;
    }

    /**
     * Redeem a claim ticket with {@code domain}'s IDP:
     * {@code LocalRp/redeem-claim-ticket} over TCP CSIL-RPC, pinned via the
     * domain's DNS {@code fp=} set. Unauthenticated at the transport layer
     * (no client cert) &mdash; the redemption request itself is signed with
     * the local RP's signing key, which is the possession proof the server
     * checks.
     */
    public static LocalRpTicketRedemptionResponse redeemClaimTicket(
            Transport transport, DnsResolver dns, String domain, SignedLocalRpTicketRedemptionRequest signedRequest) {
        DomainEndpoint endpoint = discoverDomainEndpoint(dns, domain);
        byte[] payload = Codec.encodeSignedLocalRpTicketRedemptionRequest(signedRequest);
        byte[] respBytes = call(transport, endpoint, "LocalRp", "redeem-claim-ticket", payload);
        return Codec.decodeLocalRpTicketRedemptionResponse(respBytes);
    }
}
