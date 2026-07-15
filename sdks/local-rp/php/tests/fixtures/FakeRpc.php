<?php

declare(strict_types=1);

/**
 * A fake CSIL-RPC "wire" for flow tests, entirely in-process (no sockets,
 * no threads, no TLS): a custom PHP stream wrapper whose `stream_write()`
 * decodes exactly one length-prefixed CSIL-RPC request frame per call and
 * synchronously produces the encoded response frame for subsequent
 * `stream_read()` calls to return. This lets flow tests exercise
 * `Rpc`'s REAL frame encode/decode logic end to end while faking only the
 * "Transport" seam — per the SDK's own test-support docs
 * ({@see LinkKeys\LocalRp\OpaqueTransport}), spinning a real concurrent TLS
 * server inside a single-threaded PHP CLI process (no pcntl available) is
 * impractical, and the design doc's conformance section sanctions a
 * Transport-seam fake for flow tests as long as the pin-check logic itself
 * is separately unit-tested against a real certificate fixture (see
 * `tests/TlsPinningTest.php`).
 */

use LinkKeys\LocalRp\Cbor;
use LinkKeys\LocalRp\CborBytes;
use LinkKeys\LocalRp\OpaqueTransport;

final class FakeRpcStreamWrapper
{
    /** @var array<string,callable> */
    public static array $responders = [];

    /** @var resource */
    public $context;

    private string $id = '';
    private string $writeBuf = '';
    private string $readBuf = '';

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        $this->id = (string) parse_url($path, PHP_URL_HOST);
        return true;
    }

    public function stream_write(string $data): int
    {
        $this->writeBuf .= $data;
        $this->processFrames();
        return strlen($data);
    }

    private function processFrames(): void
    {
        while (strlen($this->writeBuf) >= 4) {
            $len = unpack('N', substr($this->writeBuf, 0, 4))[1];
            if (strlen($this->writeBuf) < 4 + $len) {
                return;
            }
            $frame = substr($this->writeBuf, 4, $len);
            $this->writeBuf = substr($this->writeBuf, 4 + $len);
            $respBytes = self::dispatch($this->id, $frame);
            $this->readBuf .= pack('N', strlen($respBytes)) . $respBytes;
        }
    }

    private static function dispatch(string $id, string $frameBytes): string
    {
        $req = Cbor::decode($frameBytes);
        $service = $req['service'];
        $op = $req['op'];
        $payloadTag = $req['payload'];
        $payload = $payloadTag->value instanceof CborBytes ? $payloadTag->value->data : (string) $payloadTag->value;

        $responder = self::$responders[$id] ?? null;
        if ($responder === null) {
            $out = ['v' => 1, 'status' => 2, 'error' => 'no fake responder registered', 'payload' => Cbor::tag(24, Cbor::bytes(''))];
            return Cbor::encode($out);
        }

        [$status, $variant, $respPayload, $error] = $responder($service, $op, $payload);

        $out = [
            'v' => 1,
            'status' => $status,
            'payload' => Cbor::tag(24, Cbor::bytes($respPayload)),
        ];
        if ($variant !== null) {
            $out['variant'] = $variant;
        }
        if ($error !== null) {
            $out['error'] = $error;
        }
        if (isset($req['id'])) {
            $out['id'] = $req['id'];
        }
        return Cbor::encode($out);
    }

    public function stream_read(int $count): string
    {
        $chunk = substr($this->readBuf, 0, $count);
        $this->readBuf = substr($this->readBuf, strlen($chunk));
        return $chunk;
    }

    public function stream_eof(): bool
    {
        return $this->readBuf === '' && $this->writeBuf === '';
    }

    public function stream_close(): bool
    {
        return true;
    }

    /** @return mixed */
    public function stream_set_option(int $option, int $arg1, int $arg2)
    {
        return true;
    }

    /** @return array<int|string,mixed> */
    public function stream_stat(): array
    {
        return [];
    }
}

/**
 * A {@see OpaqueTransport} backed entirely by {@see FakeRpcStreamWrapper} —
 * no real socket is ever opened, and the fake stream is not real TLS, so
 * this implements the marker interface that tells {@see LinkKeys\LocalRp\Rpc}
 * to skip its TLS-pinning wrap step for this transport specifically (never
 * process-globally — see {@see OpaqueTransport}'s docblock). `$responder` is
 * `(string $service, string $op, string $payload): array{0:int,1:?string,2:string,3:?string}`
 * (status, variant, response payload bytes, error message).
 */
final class FakeTransport implements OpaqueTransport
{
    private string $id;

    public function __construct(callable $responder)
    {
        if (!in_array('fakerpc', stream_get_wrappers(), true)) {
            stream_wrapper_register('fakerpc', FakeRpcStreamWrapper::class);
        }
        $this->id = uniqid('fakerpc-', true);
        FakeRpcStreamWrapper::$responders[$this->id] = $responder;
    }

    /** @return resource */
    public function dial(string $hostPort)
    {
        $stream = fopen("fakerpc://{$this->id}/", 'r+');
        if ($stream === false) {
            throw new \RuntimeException('failed to open fake RPC stream');
        }
        return $stream;
    }
}
