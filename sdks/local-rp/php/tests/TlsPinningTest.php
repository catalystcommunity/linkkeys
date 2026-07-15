<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use LinkKeys\LocalRp\Crypto;
use LinkKeys\LocalRp\PinMismatchError;
use LinkKeys\LocalRp\Tls;

/**
 * Exercises {@see Tls}'s pin-check logic against a REAL X.509 certificate
 * (system `openssl` CLI-minted, matching the TypeScript reference SDK's
 * approach — there is no certificate-issuing API in PHP's `openssl`
 * extension either) and a REAL TLS handshake (a genuinely separate OS
 * process as the server — see `tests/fixtures/tls_server.php`'s docblock
 * for why a process rather than a background thread). This is the test the
 * design doc's conformance section requires even when flow tests fake the
 * Transport seam: "the pin-check logic itself must still be unit-tested
 * against a real cert fixture".
 */

const ED25519_PKCS8_PREFIX_HEX = '302e020100300506032b657004220420';

function ed25519SeedToPkcs8Pem(string $seed): string
{
    $der = hex2bin(ED25519_PKCS8_PREFIX_HEX) . $seed;
    $b64 = base64_encode($der);
    $lines = trim(chunk_split($b64, 64, "\n"));
    return "-----BEGIN PRIVATE KEY-----\n{$lines}\n-----END PRIVATE KEY-----\n";
}

function mintDomainCert(string $domain, string $seed, string $dir): array
{
    $keyPath = $dir . '/key.pem';
    $certPath = $dir . '/cert.pem';
    file_put_contents($keyPath, ed25519SeedToPkcs8Pem($seed));

    $cmd = sprintf(
        'openssl req -new -x509 -key %s -days 3 -subj %s -out %s 2>&1',
        escapeshellarg($keyPath),
        escapeshellarg("/CN={$domain}"),
        escapeshellarg($certPath)
    );
    exec($cmd, $output, $exitCode);
    if ($exitCode !== 0) {
        throw new \RuntimeException('openssl req failed: ' . implode("\n", $output));
    }
    return [$keyPath, $certPath];
}

function waitForServerReady($pipes, int $timeoutSeconds = 5): void
{
    stream_set_blocking($pipes[1], false);
    $deadline = microtime(true) + $timeoutSeconds;
    $buf = '';
    while (microtime(true) < $deadline) {
        $chunk = fread($pipes[1], 64);
        if ($chunk !== false && $chunk !== '') {
            $buf .= $chunk;
            if (str_contains($buf, "READY\n")) {
                return;
            }
        }
        usleep(20_000);
    }
    throw new \RuntimeException("fake TLS server did not signal readiness in time (got: {$buf})");
}

$dir = sys_get_temp_dir() . '/linkkeys-local-rp-tls-test-' . bin2hex(random_bytes(4));
mkdir($dir, 0700, true);

[$pub, $seed] = Crypto::generateEd25519Keypair();
$expectedFingerprint = Crypto::fingerprint($pub);
$domain = 'test.example.com';
[$keyPath, $certPath] = mintDomainCert($domain, $seed, $dir);

TestKit::test('tls.real_cert_spki_fingerprint_matches_public_key', function () use ($certPath, $expectedFingerprint) {
    $certPem = file_get_contents($certPath);
    $fp = Tls::leafPublicKeyFingerprint($certPem);
    TestKit::assertEquals($expectedFingerprint, $fp);
});

$port = 20000 + random_int(0, 20000);
$serverScript = __DIR__ . '/fixtures/tls_server.php';
$descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
$process = proc_open(
    ['php', $serverScript, $certPath, $keyPath, (string) $port, '3'],
    $descriptors,
    $pipes
);
if ($process === false) {
    throw new \RuntimeException('failed to spawn fake TLS server process');
}

try {
    waitForServerReady($pipes);

    TestKit::test('tls.dial_tls_pinned_succeeds_with_correct_fingerprint', function () use ($port, $domain, $expectedFingerprint) {
        $raw = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 10);
        TestKit::assertTrue($raw !== false, "connect failed: {$errstr}");
        $tls = Tls::dialTlsPinned($raw, $domain, [$expectedFingerprint]);
        $data = fread($tls, 2);
        TestKit::assertEquals('ok', $data);
        fclose($tls);
    });

    TestKit::test('tls.dial_tls_pinned_rejects_wrong_fingerprint', function () use ($port, $domain) {
        $raw = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 10);
        TestKit::assertTrue($raw !== false, "connect failed: {$errstr}");
        $wrongFingerprint = str_repeat('0', 64);
        try {
            Tls::dialTlsPinned($raw, $domain, [$wrongFingerprint]);
            throw new \RuntimeException('expected a PinMismatchError');
        } catch (PinMismatchError $e) {
            // Expected.
        } finally {
            if (is_resource($raw)) {
                fclose($raw);
            }
        }
    });

    TestKit::test('tls.dial_tls_pinned_case_insensitive_fingerprint_match', function () use ($port, $domain, $expectedFingerprint) {
        $raw = stream_socket_client("tcp://127.0.0.1:{$port}", $errno, $errstr, 10);
        TestKit::assertTrue($raw !== false, "connect failed: {$errstr}");
        $tls = Tls::dialTlsPinned($raw, $domain, [strtoupper($expectedFingerprint)]);
        $data = fread($tls, 2);
        TestKit::assertEquals('ok', $data);
        fclose($tls);
    });
} finally {
    proc_terminate($process);
    proc_close($process);
    @unlink($keyPath);
    @unlink($certPath);
    @rmdir($dir);
}

exit(TestKit::summary('TlsPinningTest') === 0 ? 0 : 1);
