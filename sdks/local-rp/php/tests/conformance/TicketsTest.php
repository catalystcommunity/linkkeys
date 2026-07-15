<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

use LinkKeys\LocalRp\Crypto;

$vectors = loadJson(__DIR__ . '/../../../conformance/tickets.json');

foreach ($vectors['cases'] as $case) {
    TestKit::test('tickets.' . $case['name'], function () use ($case) {
        $ticket = hexToBytes($case['ticket_hex']);
        TestKit::assertEquals($case['sha256_hex'], Crypto::fingerprint($ticket));
    });
}

exit(TestKit::summary('TicketsTest') === 0 ? 0 : 1);
