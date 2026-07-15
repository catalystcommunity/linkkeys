<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

/**
 * The TCP dial seam. Deliberately narrow: this interface only *connects a
 * byte stream* to `host:port`. TLS (certificate-pin verification against
 * DNS `fp=` records) is layered on top in {@see Tls}, not here, so a test
 * double can swap out "how do I open a socket" without also faking a TLS
 * handshake.
 *
 * Per the design doc's Wire Precision ("SDK endpoint discovery and
 * pinning"): the Rust `linkkeys-rpc-client` refuses non-public peer
 * addresses as a *server-side* SSRF guard. SDKs must not inherit that
 * refusal as a default — "connecting from a LAN box to wherever
 * `_linkkeys_apis` points is the entire point of this mode." The default
 * policy here is permissive. `AddressPolicy::PUBLIC_ONLY` is an opt-in for
 * integrators who specifically want that stricter posture; nothing in this
 * package selects it automatically.
 */
interface Transport
{
    /** @return resource */
    public function dial(string $hostPort);
}

/**
 * A marker for a {@see Transport} whose `dial()` already returns a
 * stream this SDK should treat as fully secured — {@see Rpc}'s TLS-pinning
 * wrap step is skipped for it entirely.
 *
 * This exists SOLELY so an in-process test double (an entirely fake,
 * non-TLS stream — see `tests/fixtures/FakeRpc.php`'s `FakeTransport`) can
 * exercise `Rpc`'s real CSIL-RPC framing end-to-end without a real TLS
 * handshake, without shipping a runtime-settable, process-global "disable
 * TLS pinning" switch in `src/` (a prior revision had exactly that: a
 * `public static` property any code could flip, silently affecting every
 * concurrent call in the process and easy to forget to reset). Choosing to
 * skip pinning now requires writing and explicitly injecting a whole
 * `Transport` implementation that opts into this interface — a
 * type-checked, call-site-visible decision, not a hidden global.
 *
 * No `Transport` implementation intended for production use should ever
 * implement this interface.
 */
interface OpaqueTransport extends Transport
{
}

final class AddressPolicy
{
    public const PERMISSIVE = 'permissive';
    public const PUBLIC_ONLY = 'public_only';
}

class TransportError extends \RuntimeException
{
}

final class AddressDeniedError extends TransportError
{
}

final class ConnectFailedError extends TransportError
{
}

/**
 * Default {@see Transport}: a plain blocking TCP socket via
 * `stream_socket_client`, gated only by `$policy` (permissive unless the
 * caller opts into {@see AddressPolicy::PUBLIC_ONLY}).
 */
final class StdTransport implements Transport
{
    public string $policy;
    public float $connectTimeoutSeconds;
    public float $ioTimeoutSeconds;

    public function __construct(string $policy = AddressPolicy::PERMISSIVE, float $connectTimeoutSeconds = 10.0, float $ioTimeoutSeconds = 30.0)
    {
        $this->policy = $policy;
        $this->connectTimeoutSeconds = $connectTimeoutSeconds;
        $this->ioTimeoutSeconds = $ioTimeoutSeconds;
    }

    /** @return resource */
    public function dial(string $hostPort)
    {
        $lastColon = strrpos($hostPort, ':');
        if ($lastColon === false) {
            throw new ConnectFailedError("{$hostPort}: missing port");
        }
        $host = substr($hostPort, 0, $lastColon);
        $port = substr($hostPort, $lastColon + 1);

        if ($this->policy === AddressPolicy::PUBLIC_ONLY) {
            $ip = $this->resolveOneAddress($host);
            if ($ip !== null && self::isNonPublic($ip)) {
                throw new AddressDeniedError("{$ip}: refusing non-public address under AddressPolicy::PUBLIC_ONLY");
            }
        }

        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client(
            "tcp://{$host}:{$port}",
            $errno,
            $errstr,
            $this->connectTimeoutSeconds,
            STREAM_CLIENT_CONNECT
        );
        if ($stream === false) {
            throw new ConnectFailedError("{$hostPort}: {$errstr} ({$errno})");
        }
        stream_set_timeout($stream, (int) $this->ioTimeoutSeconds);
        return $stream;
    }

    private function resolveOneAddress(string $host): ?string
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $host;
        }
        $ip = gethostbyname($host);
        return $ip !== $host ? $ip : null;
    }

    /**
     * True for loopback/private/link-local/CGNAT/documentation/unspecified
     * addresses. Only consulted under {@see AddressPolicy::PUBLIC_ONLY},
     * never by default.
     */
    public static function isNonPublic(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $isPublic = filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            );
            if ($isPublic === false) {
                return true;
            }
            $octets = array_map('intval', explode('.', $ip));
            // CGNAT 100.64.0.0/10.
            if ($octets[0] === 100 && ($octets[1] & 0xC0) === 0x40) {
                return true;
            }
            return false;
        }

        // IPv6.
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return true; // Unparseable: fail closed under PUBLIC_ONLY.
        }
        if ($ip === '::1' || $ip === '::') {
            return true;
        }
        $first2 = (ord($packed[0]) << 8) | ord($packed[1]);
        $linkLocal = ($first2 & 0xffc0) === 0xfe80;
        $ula = ($first2 & 0xfe00) === 0xfc00;
        $multicast = ord($packed[0]) === 0xff;
        if ($linkLocal || $ula || $multicast) {
            return true;
        }
        // IPv4-mapped IPv6 (::ffff:a.b.c.d).
        if (str_starts_with($packed, str_repeat("\x00", 10) . "\xff\xff")) {
            $v4 = inet_ntop(substr($packed, 12, 4));
            return self::isNonPublic($v4);
        }
        return false;
    }
}
