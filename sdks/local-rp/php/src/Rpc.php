<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

use Csilgen\Generated\DomainPublicKey;
use Csilgen\Generated\EmptyRequest;
use Csilgen\Generated\GetRevocationsRequest;
use Csilgen\Generated\LocalRpTicketRedemptionResponse;
use Csilgen\Generated\SignedLocalRpTicketRedemptionRequest;

/**
 * CSIL-RPC over the injected {@see Transport}, TLS-pinned to a domain's DNS
 * `fp=` records — this SDK's only network surface (design doc, "Required
 * Network Access"): domain public keys, revocations, and claim-ticket
 * redemption, all unauthenticated-TLS TCP CSIL-RPC calls pinned the same way
 * `crates/linkkeys/src/tcp/tls.rs` pins the S2S path.
 *
 * This class hand-builds the CSIL-RPC envelope
 * (`~/repos/catalystcommunity/csilgen/docs/csil-rpc-transport.md` §1.1/1.2:
 * `{v, service, op, ?id, payload, ?auth}` request / `{v, ?id, status,
 * ?variant, ?error, payload}` response, verbatim CSIL `service`/`op` names,
 * length-prefixed stream framing) rather than driving it through
 * `src/Generated/`'s generated client wrapper classes, for the same reason
 * the Rust and Python reference SDKs do: the generated client passes a
 * transport-agnostic `(service, method)` pair to an injected `Transport`
 * seam that is lossy for reconstructing the real wire names (confirmed
 * against `php-client`'s generated `client.php`: it collapses `service`/`op`
 * into one already-mangled route string, e.g. `'domain-keys/get-domain-keys'`
 * — see the csilgen defect filed for this at
 * `~/repos/catalystcommunity/csilgen/docs/csilgen-requests/`). This SDK only
 * ever calls two operations, so it builds the two real CSIL-RPC requests
 * directly, mirroring `sdks/local-rp/rust/src/rpc.rs` /
 * `sdks/local-rp/python/linkkeys_local_rp/rpc.py`.
 */
final class Rpc
{
    /**
     * Mirrors the server's own cap (`crates/linkkeys-rpc-client/src/lib.rs`)
     * so a malicious/compromised peer cannot drive this client to an
     * unbounded allocation via a forged length prefix.
     */
    public const MAX_FRAME_SIZE = 1024 * 1024;

    private const CSIL_RPC_VERSION = 1;
    private const TAG_ENCODED_CBOR = 24;

    /** @param resource $stream */
    private static function sendFrame($stream, string $data): void
    {
        $len = strlen($data);
        $header = pack('N', $len);
        self::writeAll($stream, $header . $data);
    }

    /** @param resource $stream */
    private static function writeAll($stream, string $data): void
    {
        $total = strlen($data);
        $written = 0;
        while ($written < $total) {
            $n = fwrite($stream, substr($data, $written));
            if ($n === false || $n === 0) {
                $meta = stream_get_meta_data($stream);
                if (!empty($meta['timed_out'])) {
                    throw new RpcTransportError('write timed out');
                }
                throw new RpcTransportError('connection closed while writing');
            }
            $written += $n;
        }
    }

    /** @param resource $stream */
    private static function readExact($stream, int $n): string
    {
        $buf = '';
        while (strlen($buf) < $n) {
            $chunk = fread($stream, $n - strlen($buf));
            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($stream);
                if (!empty($meta['timed_out'])) {
                    throw new RpcTransportError('read timed out');
                }
                throw new RpcProtocolError('connection closed before expected bytes were received');
            }
            $buf .= $chunk;
        }
        return $buf;
    }

    /** @param resource $stream */
    private static function recvFrame($stream): string
    {
        $lenBytes = self::readExact($stream, 4);
        $len = unpack('N', $lenBytes)[1];
        if ($len > self::MAX_FRAME_SIZE) {
            throw new RpcProtocolError("peer frame too large ({$len} bytes, max " . self::MAX_FRAME_SIZE . ')');
        }
        return self::readExact($stream, $len);
    }

    private static function encodeRequest(string $service, string $op, string $payload): string
    {
        return Cbor::encode([
            'v' => self::CSIL_RPC_VERSION,
            'service' => $service,
            'op' => $op,
            'payload' => Cbor::tag(self::TAG_ENCODED_CBOR, Cbor::bytes($payload)),
        ]);
    }

    /** @return array{status:int, variant:?string, error:?string, payload:string} */
    private static function decodeResponse(string $bytes): array
    {
        $m = Cbor::decode($bytes);
        if (!is_array($m) || !isset($m['status']) || !is_int($m['status'])) {
            throw new RpcProtocolError("RPC response envelope missing integer 'status'");
        }
        $payloadTag = $m['payload'] ?? null;
        $payload = '';
        if ($payloadTag instanceof CborTag && $payloadTag->tag === self::TAG_ENCODED_CBOR) {
            $payload = $payloadTag->value instanceof CborBytes ? $payloadTag->value->data : (string) $payloadTag->value;
        }
        return [
            'status' => $m['status'],
            'variant' => $m['variant'] ?? null,
            'error' => $m['error'] ?? null,
            'payload' => $payload,
        ];
    }

    // -------------------------------------------------------------------
    // Endpoint discovery
    // -------------------------------------------------------------------

    /**
     * Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails
     * closed: a missing/unparseable record, or a `_linkkeys` record with no
     * `fp=` entries, or a `_linkkeys_apis` record with no `tcp=` entry, is
     * an error — this SDK never proceeds without a fingerprint set to pin
     * to.
     */
    public static function discoverDomainEndpoint(DnsResolver $dns, string $domain): DomainEndpoint
    {
        $anchorName = Dns::linkkeysDnsName($domain);
        $fingerprints = [];
        foreach ($dns->txtLookup($anchorName) as $txt) {
            try {
                $fps = Dns::parseLinkKeysTxt($txt);
            } catch (DnsParseError $e) {
                continue;
            }
            if (!empty($fps)) {
                $fingerprints = $fps;
                break;
            }
        }
        if (empty($fingerprints)) {
            throw new DnsParseError(DnsParseError::NO_LINKKEYS_RECORD, "no usable {$anchorName} TXT record with fp= entries");
        }

        $apisName = Dns::linkkeysApisDnsName($domain);
        $tcpAddr = null;
        foreach ($dns->txtLookup($apisName) as $txt) {
            try {
                $apis = Dns::parseLinkKeysApisTxt($txt);
            } catch (DnsParseError $e) {
                continue;
            }
            if ($apis['tcp'] !== null) {
                $tcpAddr = $apis['tcp'];
                break;
            }
        }
        if ($tcpAddr === null) {
            throw new DnsParseError(DnsParseError::MISSING_APIS_ENDPOINT, "no usable {$apisName} TXT record with tcp= entry");
        }

        return new DomainEndpoint($fingerprints, $tcpAddr);
    }

    /**
     * Open a TLS connection to `$endpoint`, pinned to its fingerprints, over
     * a raw stream obtained from `$transport`. If `$transport` implements
     * {@see OpaqueTransport}, the real TLS-pinning wrap step
     * ({@see Tls::dialTlsPinned}) is skipped and `$transport`'s raw stream
     * is returned as-is — see that interface's docblock for why this exists
     * and why it is safe (no runtime-settable, process-global pin-bypass
     * switch: opting out of pinning requires supplying and injecting an
     * entire `Transport` implementation, a much larger and more visible
     * commitment than flipping a static property).
     *
     * @return resource
     */
    private static function dialTls(Transport $transport, DomainEndpoint $endpoint)
    {
        $raw = $transport->dial($endpoint->tcpAddr);
        if ($transport instanceof OpaqueTransport) {
            return $raw;
        }
        $hostname = Tls::extractHostname($endpoint->tcpAddr);
        try {
            return Tls::dialTlsPinned($raw, $hostname, $endpoint->fingerprints);
        } catch (\Throwable $e) {
            fclose($raw);
            throw $e;
        }
    }

    /** Send one CSIL-RPC request over a fresh TLS connection and return the decoded success payload. */
    private static function call(Transport $transport, DomainEndpoint $endpoint, string $service, string $op, string $payload): string
    {
        $stream = self::dialTls($transport, $endpoint);
        try {
            self::sendFrame($stream, self::encodeRequest($service, $op, $payload));
            $respBytes = self::recvFrame($stream);
        } finally {
            fclose($stream);
        }

        $resp = self::decodeResponse($respBytes);
        if ($resp['status'] !== 0) {
            throw new RpcServerError($resp['status'], $resp['error'] ?? 'unknown error');
        }
        return $resp['payload'];
    }

    // -------------------------------------------------------------------
    // High-level operations
    // -------------------------------------------------------------------

    /**
     * Fetch `$domain`'s currently-trusted public keys:
     * `DomainKeys/get-domain-keys` over TCP CSIL-RPC, pinned to the domain's
     * DNS `fp=` set, with signing keys pinned directly and encryption keys
     * trusted only via a pinned signing key's vouch ({@see Dns::trustKeys}).
     * ALWAYS also fetches `DomainKeys/get-revocations` for the same domain —
     * this is not suppressible by `recent_revocations_available` or any
     * other server-advertised hint (design doc, "Post-implementation
     * security review", item 4: a server-controlled flag must never be able
     * to suppress revocation delivery) — and drops any key a
     * quorum-verified sibling revocation certificate targets. A
     * `get-revocations` RPC/decode error is FATAL: this method fails closed
     * rather than verifying the callback against a possibly-stale,
     * unfiltered key set. An empty revocations list is a normal success (no
     * keys are revoked). An empty trusted result throws
     * {@see NoTrustedDomainKeysError} — fail closed.
     *
     * @return DomainPublicKey[]
     */
    public static function fetchDomainKeys(Transport $transport, DnsResolver $dns, string $domain, \DateTimeImmutable $now): array
    {
        $endpoint = self::discoverDomainEndpoint($dns, $domain);

        $payload = Wire::encodeEmptyRequest(new EmptyRequest());
        $respBytes = self::call($transport, $endpoint, 'DomainKeys', 'get-domain-keys', $payload);
        $resp = Wire::decodeGetDomainKeysResponse($respBytes);

        $trusted = Dns::trustKeys($resp->keys, $endpoint->fingerprints, $now);
        if (empty($trusted)) {
            throw new NoTrustedDomainKeysError($domain);
        }

        $since = Time::toRfc3339($now->sub(new \DateInterval('P30D')));
        $reqPayload = Wire::encodeGetRevocationsRequest(new GetRevocationsRequest(['since' => $since]));
        try {
            $respBytes = self::call($transport, $endpoint, 'DomainKeys', 'get-revocations', $reqPayload);
            $revResp = Wire::decodeGetRevocationsResponse($respBytes);
        } catch (\Throwable $e) {
            // Fail closed: we cannot verify the callback against a key set
            // we don't know is free of recently-revoked keys.
            throw new RevocationFetchError($domain, $e);
        }
        foreach ($revResp->revocations as $cert) {
            try {
                Revocation::verifyRevocationCertificate($cert, $trusted, $domain);
                $trusted = array_values(array_filter($trusted, fn ($k) => $k->keyId !== $cert->targetKeyId));
            } catch (RevocationError $e) {
                // Quorum not met for this particular certificate; ignore
                // just that certificate, not the whole revocation fetch.
            }
        }

        if (empty($trusted)) {
            throw new NoTrustedDomainKeysError($domain);
        }
        return $trusted;
    }

    /**
     * Redeem a claim ticket with `$domain`'s IDP:
     * `LocalRp/redeem-claim-ticket` over TCP CSIL-RPC, pinned via the
     * domain's DNS `fp=` set. Unauthenticated at the transport layer (no
     * client cert) — the redemption request itself is signed with the local
     * RP's signing key, which is the possession proof the server checks.
     */
    public static function redeemClaimTicket(Transport $transport, DnsResolver $dns, string $domain, SignedLocalRpTicketRedemptionRequest $signedRequest): LocalRpTicketRedemptionResponse
    {
        $endpoint = self::discoverDomainEndpoint($dns, $domain);
        $payload = Wire::encodeSignedLocalRpTicketRedemptionRequest($signedRequest);
        $respBytes = self::call($transport, $endpoint, 'LocalRp', 'redeem-claim-ticket', $payload);
        return Wire::decodeLocalRpTicketRedemptionResponse($respBytes);
    }
}

/** Discovered endpoint for a domain: its pinned trust-anchor fingerprints (`_linkkeys`) and its CSIL-RPC TCP address (`_linkkeys_apis` `tcp=`). */
final class DomainEndpoint
{
    /** @var string[] */
    public array $fingerprints;
    public string $tcpAddr;

    /** @param string[] $fingerprints */
    public function __construct(array $fingerprints, string $tcpAddr)
    {
        $this->fingerprints = $fingerprints;
        $this->tcpAddr = $tcpAddr;
    }
}

class RpcError extends \RuntimeException
{
}

final class RpcProtocolError extends RpcError
{
}

final class RpcTransportError extends RpcError
{
}

final class RpcServerError extends RpcError
{
    public int $status;
    public string $errorMessage;

    public function __construct(int $status, string $message)
    {
        parent::__construct("server error ({$status}): {$message}");
        $this->status = $status;
        $this->errorMessage = $message;
    }
}

final class NoTrustedDomainKeysError extends RpcError
{
    public string $domain;

    public function __construct(string $domain)
    {
        parent::__construct("no trusted public keys could be established for domain: {$domain}");
        $this->domain = $domain;
    }
}

/**
 * `DomainKeys/get-revocations` failed (transport, protocol, or decode
 * error). Fetching revocations is unconditional and this error is fatal —
 * {@see Rpc::fetchDomainKeys} fails closed rather than trusting a key set it
 * couldn't check for recent revocations against.
 */
final class RevocationFetchError extends RpcError
{
    public string $domain;

    public function __construct(string $domain, ?\Throwable $previous = null)
    {
        parent::__construct("failed to fetch revocations for domain: {$domain}", 0, $previous);
        $this->domain = $domain;
    }
}
