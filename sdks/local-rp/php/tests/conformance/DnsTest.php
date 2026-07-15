<?php

declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

use LinkKeys\LocalRp\Dns;
use LinkKeys\LocalRp\DnsParseError;

$vectors = loadJson(__DIR__ . '/../../../conformance/dns.json');

foreach ($vectors['linkkeys_txt']['valid_cases'] as $i => $case) {
    TestKit::test("dns.linkkeys_txt.valid.{$i}", function () use ($case) {
        $fps = Dns::parseLinkKeysTxt($case['txt']);
        TestKit::assertEquals($case['expected_fingerprints'], $fps);
    });
}

foreach ($vectors['linkkeys_txt']['invalid_cases'] as $case) {
    TestKit::test('dns.linkkeys_txt.invalid.' . $case['name'], function () use ($case) {
        try {
            Dns::parseLinkKeysTxt($case['txt']);
            throw new \RuntimeException('expected a DnsParseError');
        } catch (DnsParseError $e) {
            TestKit::assertEquals($case['expected_error'], $e->kind);
        }
    });
}

TestKit::test('dns.linkkeys_txt.no_record_case_is_documentation_only', function () use ($vectors) {
    TestKit::assertTrue($vectors['linkkeys_txt']['no_record_case']['documentation_only'] === true);
    TestKit::assertTrue($vectors['linkkeys_txt']['no_record_case']['txt'] === null);
});

foreach ($vectors['linkkeys_apis_txt']['valid_cases'] as $case) {
    TestKit::test('dns.linkkeys_apis_txt.valid.' . $case['name'], function () use ($case) {
        $apis = Dns::parseLinkKeysApisTxt($case['txt']);
        TestKit::assertEquals($case['expected_tcp'], $apis['tcp']);
        TestKit::assertEquals($case['expected_https_base'], $apis['https_base']);
    });
}

foreach ($vectors['linkkeys_apis_txt']['invalid_cases'] as $case) {
    TestKit::test('dns.linkkeys_apis_txt.invalid.' . $case['name'], function () use ($case) {
        try {
            Dns::parseLinkKeysApisTxt($case['txt']);
            throw new \RuntimeException('expected a DnsParseError');
        } catch (DnsParseError $e) {
            TestKit::assertEquals($case['expected_error'], $e->kind);
        }
    });
}

TestKit::test('dns.default_tcp_port', function () use ($vectors) {
    TestKit::assertEquals($vectors['default_tcp_port'], Dns::DEFAULT_TCP_PORT);
});

exit(TestKit::summary('DnsTest') === 0 ? 0 : 1);
