<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Csilgen\Generated\EmptyRequest;
use Csilgen\Generated\GetRevocationsRequest;
use LinkKeys\LocalRp\Cbor;
use LinkKeys\LocalRp\Wire;

TestKit::test('cbor.empty_map_is_not_confused_with_empty_list', function () {
    // 0xa0 = major type 5 (map), 0 entries. 0x80 (major type 4, 0 entries)
    // would be the WRONG encoding for an empty struct/request (every CSIL
    // struct type is map-shaped even with zero fields present) -- this is
    // a real ambiguity PHP's array type has that this SDK works around via
    // Cbor::encodeMap() (see that method's docblock).
    TestKit::assertEquals("\xa0", Cbor::encodeMap([]));
    TestKit::assertEquals("\xa0", Wire::encodeEmptyRequest(new EmptyRequest()));
    TestKit::assertEquals("\xa0", Wire::encodeGetRevocationsRequest(new GetRevocationsRequest(['since' => null])));
});

TestKit::test('cbor.get_revocations_request_with_since_present', function () {
    $bytes = Wire::encodeGetRevocationsRequest(new GetRevocationsRequest(['since' => '2026-01-01T00:00:00+00:00']));
    $decoded = Cbor::decode($bytes);
    TestKit::assertEquals(['since' => '2026-01-01T00:00:00+00:00'], $decoded);
});

TestKit::test('cbor.byte_string_vs_text_string', function () {
    // A bare PHP string encodes as CBOR major type 3 (text); Cbor::bytes()
    // is required to force major type 2 (byte string).
    $textEncoded = Cbor::encode('ab');
    $bytesEncoded = Cbor::encode(Cbor::bytes('ab'));
    TestKit::assertTrue($textEncoded !== $bytesEncoded);
    TestKit::assertEquals("\x62ab", $textEncoded);
    TestKit::assertEquals("\x42ab", $bytesEncoded);
});

TestKit::test('cbor.roundtrip_nested_structures', function () {
    $value = ['a' => 1, 'b' => [1, 2, 3], 'c' => Cbor::bytes("\x00\x01"), 'd' => null, 'e' => true];
    $decoded = Cbor::decode(Cbor::encode($value));
    TestKit::assertEquals(1, $decoded['a']);
    TestKit::assertEquals([1, 2, 3], $decoded['b']);
    TestKit::assertEquals("\x00\x01", $decoded['c']);
    TestKit::assertEquals(null, $decoded['d']);
    TestKit::assertEquals(true, $decoded['e']);
});

TestKit::test('cbor.negative_integer_roundtrip', function () {
    TestKit::assertEquals(-1, Cbor::decode(Cbor::encode(-1)));
    TestKit::assertEquals(-1000, Cbor::decode(Cbor::encode(-1000)));
});

TestKit::test('cbor.trailing_bytes_rejected', function () {
    TestKit::assertThrows(fn () => Cbor::decode(Cbor::encode(1) . "\x00"));
});

exit(TestKit::summary('CborTest') === 0 ? 0 : 1);
