<?php

declare(strict_types=1);

/**
 * A minimal, standalone TLS accept-loop used only by TlsPinningTest.php,
 * run as a genuinely separate OS process (via `proc_open`) so the real
 * client-side TLS handshake in `Tls::dialTlsPinned` has a real concurrent
 * peer to negotiate with — PHP CLI has no threads (and this container has
 * no pcntl), so a real server for this test has to be a separate process,
 * not a background "thread" the way the Rust/TypeScript reference SDKs do
 * it.
 *
 * Usage: php tls_server.php <cert.pem> <key.pem> <port> <connectionCount>
 */

[, $certPath, $keyPath, $port, $count] = $argv;

$context = stream_context_create([
    'ssl' => [
        'local_cert' => $certPath,
        'local_pk' => $keyPath,
        'allow_self_signed' => true,
        'verify_peer' => false,
    ],
]);

$server = stream_socket_server(
    "ssl://127.0.0.1:{$port}",
    $errno,
    $errstr,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
    $context
);
if ($server === false) {
    fwrite(STDERR, "server bind failed: {$errstr} ({$errno})\n");
    exit(1);
}

// Signal readiness to the parent process (which is polling for connectability,
// but this also helps diagnose startup failures in test output).
fwrite(STDOUT, "READY\n");
fflush(STDOUT);

for ($i = 0; $i < (int) $count; $i++) {
    $conn = @stream_socket_accept($server, 30);
    if ($conn === false) {
        // The client intentionally aborted (e.g. it detected a pin
        // mismatch and closed without completing/trusting the handshake).
        // That is an expected outcome for the negative test case, not a
        // server error — do not run further.
        continue;
    }
    fwrite($conn, 'ok');
    fclose($conn);
}

fclose($server);
