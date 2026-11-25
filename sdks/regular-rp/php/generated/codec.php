<?php

namespace Csilgen\Generated;

use Csilgen\Transport\CBOR;

/** Raised when decoded CBOR does not match the declared CSIL shape (unknown enum
 * member, tagged-sum literal-arm mismatch, or malformed union envelope). */
class CodecException extends \RuntimeException {}

/** A decoded CBOR map, apart from a CBOR array. */
final class CsilMap
{
    public $items;
    public $keys;

    public function __construct(array $items, array $keys)
    {
        $this->items = $items;
        $this->keys = $keys;
    }
}

class RpErrorRefusal extends \RuntimeException
{
    public $value;

    public function __construct($value)
    {
        parent::__construct('RpError');
        $this->value = $value;
    }
}

class Codec
{
    public static function encode_value($value)
    {
        return CBOR::encode($value);
    }

    public static function decode_value($bytes)
    {
        return self::csilPlain(self::csilDecode($bytes));
    }

    /** A literal-typed union/enum arm carries no shape of its own on the wire — the
     * variant index (or the bare value itself for an enum) already selects it — so
     * decode only needs to confirm the payload equals the declared literal. */
    public static function expectLiteral($value, $expected)
    {
        if ($value !== $expected) {
            throw new CodecException('csil cbor: literal mismatch, expected ' . var_export($expected, true) . ', got ' . var_export($value, true));
        }
        return $value;
    }

    private static function csilDecode($bytes)
    {
        if (!is_string($bytes)) {
            throw new CodecException('csil cbor: expected a byte string');
        }
        $pos = 0;
        $value = self::csilItem($bytes, $pos, 0);
        if ($pos !== strlen($bytes)) {
            throw new CodecException('csil cbor: trailing bytes after CBOR item');
        }
        return $value;
    }

    private static function csilItem($bytes, &$pos, $depth)
    {
        if ($depth > 64) {
            throw new CodecException('csil cbor: nesting limit exceeded');
        }
        self::csilNeed($bytes, $pos, 1);
        $initial = ord($bytes[$pos++]);
        $major = $initial >> 5;
        $info = $initial & 0x1f;
        if ($major === 7) {
            if ($info === 20) {
                return false;
            }
            if ($info === 21) {
                return true;
            }
            if ($info === 22) {
                return null;
            }
            if ($info === 25) {
                self::csilNeed($bytes, $pos, 2);
                $half = unpack('n', substr($bytes, $pos, 2))[1];
                $pos += 2;
                $exponent = ($half >> 10) & 0x1f;
                $mantissa = $half & 0x3ff;
                if ($exponent === 0) {
                    $value = $mantissa * (2.0 ** -24);
                } elseif ($exponent === 31) {
                    $value = $mantissa === 0 ? INF : NAN;
                } else {
                    $value = ($mantissa + 1024) * (2.0 ** ($exponent - 25));
                }
                return ($half & 0x8000) ? -$value : $value;
            }
            if ($info === 26) {
                self::csilNeed($bytes, $pos, 4);
                $value = unpack('G', substr($bytes, $pos, 4))[1];
                $pos += 4;
                return $value;
            }
            if ($info === 27) {
                self::csilNeed($bytes, $pos, 8);
                $value = unpack('E', substr($bytes, $pos, 8))[1];
                $pos += 8;
                return $value;
            }
            throw new CodecException('csil cbor: unsupported simple value');
        }
        $arg = self::csilArgument($bytes, $pos, $info);
        if ($major === 0) {
            return $arg;
        }
        if ($major === 1) {
            return -1 - $arg;
        }
        if ($major === 2 || $major === 3) {
            self::csilNeed($bytes, $pos, $arg);
            $text = substr($bytes, $pos, $arg);
            $pos += $arg;
            if ($major === 3 && preg_match('//u', $text) !== 1) {
                throw new CodecException('csil cbor: invalid UTF-8 text string');
            }
            return $text;
        }
        if ($major === 4 || $major === 5) {
            // Each element takes at least one byte, so a longer count is malformed.
            if ($arg > strlen($bytes) - $pos) {
                throw new CodecException('csil cbor: length exceeds remaining input');
            }
            $items = array();
            $keys = array();
            for ($i = 0; $i < $arg; $i++) {
                if ($major === 4) {
                    $items[] = self::csilItem($bytes, $pos, $depth + 1);
                    continue;
                }
                $start = $pos;
                $key = self::csilItem($bytes, $pos, $depth + 1);
                if (!is_int($key) && !is_string($key)) {
                    throw new CodecException('csil cbor: unsupported map key type');
                }
                $raw = substr($bytes, $start, $pos - $start);
                if (!self::csilShortest($raw)) {
                    throw new CodecException('csil cbor: map key is not in shortest form');
                }
                if (array_key_exists($key, $items)) {
                    throw new CodecException('csil cbor: duplicate key "' . addcslashes((string) $key, "\0..\37\"\\") . '"');
                }
                $items[$key] = self::csilItem($bytes, $pos, $depth + 1);
                $keys[] = $raw;
            }
            return $major === 4 ? $items : new CsilMap($items, $keys);
        }
        if ($major === 6) {
            // PHP holds byte and text strings in one type, so check the content major type here.
            if (($arg === 0 || $arg === 1004) && (!isset($bytes[$pos]) || ord($bytes[$pos]) >> 5 !== 3)) {
                throw new CodecException('csil cbor: tag ' . $arg . ' requires text');
            }
            return new \Csilgen\Transport\Tag($arg, self::csilItem($bytes, $pos, $depth + 1));
        }
        throw new CodecException('csil cbor: unsupported major type ' . $major);
    }

    private static function csilArgument($bytes, &$pos, $info)
    {
        if ($info < 24) {
            return $info;
        }
        $widths = array(24 => 1, 25 => 2, 26 => 4, 27 => 8);
        if (!isset($widths[$info])) {
            throw new CodecException('csil cbor: unsupported additional-info value ' . $info);
        }
        $n = $widths[$info];
        self::csilNeed($bytes, $pos, $n);
        $value = 0;
        for ($i = 0; $i < $n; $i++) {
            $value = $value * 256 + ord($bytes[$pos++]);
        }
        return $value;
    }

    private static function csilNeed($bytes, $pos, $n)
    {
        if ($pos + $n > strlen($bytes)) {
            throw new CodecException('csil cbor: unexpected end of input');
        }
    }

    /** Whether the head of an encoded item uses the fewest argument bytes. */
    private static function csilShortest($raw)
    {
        $info = ord($raw[0]) & 0x1f;
        if ($info < 24) {
            return true;
        }
        $widths = array(24 => 1, 25 => 2, 26 => 4, 27 => 8);
        $value = 0;
        for ($i = 1; $i <= $widths[$info]; $i++) {
            $value = $value * 256 + ord($raw[$i]);
        }
        $floors = array(24 => 24, 25 => 0x100, 26 => 0x10000, 27 => 0x100000000);
        return $value >= $floors[$info];
    }

    /** A dynamic map: its raw keys must be strictly ascending, bytewise. */
    private static function csilCanonicalMap($map)
    {
        if (!($map instanceof CsilMap)) {
            throw new CodecException('csil cbor: expected a map');
        }
        $previous = null;
        foreach ($map->keys as $key) {
            if ($previous !== null && strcmp($previous, $key) >= 0) {
                throw new CodecException('csil cbor: map keys are not in canonical order');
            }
            $previous = $key;
        }
        return $map->items;
    }

    private static function csilList($value)
    {
        if ($value === null) {
            return array();
        }
        if (!is_array($value)) {
            throw new CodecException('csil cbor: expected an array');
        }
        return $value;
    }

    /** The decoded tree with each map as a plain PHP array, for an untyped value. */
    private static function csilPlain($value)
    {
        if ($value instanceof CsilMap) {
            $value = $value->items;
        } elseif ($value instanceof \Csilgen\Transport\Tag) {
            return new \Csilgen\Transport\Tag($value->tag, self::csilPlain($value->value));
        }
        if (is_array($value)) {
            foreach ($value as $key => $item) {
                $value[$key] = self::csilPlain($item);
            }
        }
        return $value;
    }

    private static function csilRecord($value, $name, array $required)
    {
        if (!($value instanceof CsilMap)) {
            throw new CodecException('csil cbor: ' . $name . ' expects a map');
        }
        foreach ($required as $key) {
            if (!array_key_exists($key, $value->items)) {
                throw new CodecException('csil cbor: ' . $name . ' is missing field "' . $key . '"');
            }
        }
        return $value->items;
    }

    private static function csilTagged($value, $name)
    {
        if (!is_array($value) || count($value) !== 2 || !array_key_exists(0, $value) || !array_key_exists(1, $value)) {
            throw new CodecException('csil cbor: ' . $name . ' union expects a 2-element array');
        }
        return $value;
    }

    private static function calendarDate($text)
    {
        if (!is_string($text) || !preg_match('/\A([0-9]{4})-([0-9]{2})-([0-9]{2})\z/', $text, $p)
            || !checkdate((int)$p[2], (int)$p[3], $p[1] === '0000' ? 400 : (int)$p[1])) {
            throw new CodecException('expected YYYY-MM-DD');
        }
        return $text;
    }

    public static function encode_calendar_date($value)
    {
        return CBOR::encode(new \Csilgen\Transport\Tag(1004, self::calendarDate($value)));
    }

    public static function decode_calendar_date($bytes)
    {
        return self::readDate(self::csilDecode($bytes));
    }

    private static function readDate($value)
    {
        if (!($value instanceof \Csilgen\Transport\Tag) || $value->tag !== 1004) {
            throw new CodecException('expected calendar date tag 1004');
        }
        return self::calendarDate($value->value);
    }

    public static function encode_timestamp($value)
    {
        return CBOR::encode(self::timestampToCbor($value));
    }

    public static function decode_timestamp($bytes)
    {
        return self::timestampFromCbor(self::csilDecode($bytes));
    }

    private static function timestampToCbor($value)
    {
        if ($value instanceof \DateTime) {
            $value = \DateTimeImmutable::createFromMutable($value);
        }
        if (!($value instanceof \DateTimeImmutable)) {
            throw new CodecException('expected a DateTimeImmutable for a timestamp');
        }
        $utc = $value->setTimezone(new \DateTimeZone('UTC'));
        $year = (int)$utc->format('Y');
        if ($year < 1 || $year > 9999) {
            throw new CodecException('timestamp year outside 0001-9999');
        }
        $micros = (int)$utc->format('u');
        if ($micros === 0) {
            $fraction = '';
        } elseif ($micros % 1000 === 0) {
            $fraction = sprintf('.%03d', intdiv($micros, 1000));
        } else {
            $fraction = sprintf('.%06d', $micros);
        }
        return new \Csilgen\Transport\Tag(0, sprintf('%04d', $year) . $utc->format('-m-d\TH:i:s') . $fraction . 'Z');
    }

    private static function timestampFromCbor($value)
    {
        if (!($value instanceof \Csilgen\Transport\Tag) || $value->tag !== 0 || !is_string($value->value)
            || !preg_match('/\A([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2}))\z/', $value->value, $p)) {
            throw new CodecException('expected tag 0 with RFC 3339 timestamp text');
        }
        $year = (int)$p[1];
        $month = (int)$p[2];
        $day = (int)$p[3];
        $hour = (int)$p[4];
        $minute = (int)$p[5];
        $second = (int)$p[6];
        if ($year < 1 || !checkdate($month, $day, $year) || $hour > 23 || $minute > 59 || $second > 59) {
            throw new CodecException('timestamp field out of range');
        }
        $digits = isset($p[7]) ? str_pad($p[7], 9, '0') : '000000000';
        if (substr($digits, 6) !== '000') {
            throw new CodecException('timestamp fraction finer than microseconds');
        }
        $offset = 0;
        if (isset($p[8]) && $p[8] !== '') {
            $offsetHour = (int)$p[9];
            $offsetMinute = (int)$p[10];
            if ($offsetHour > 23 || $offsetMinute > 59) {
                throw new CodecException('timestamp offset out of range');
            }
            $offset = ($offsetHour * 60 + $offsetMinute) * ($p[8] === '-' ? -1 : 1);
        }
        $utc = new \DateTimeZone('UTC');
        $instant = (new \DateTimeImmutable('@0'))->setTimezone($utc)
            ->setDate($year, $month, $day)
            ->setTime($hour, $minute, $second, (int)substr($digits, 0, 6));
        if ($offset !== 0) {
            $instant = $instant->modify(sprintf('%+d minutes', -$offset));
        }
        $utcYear = (int)$instant->format('Y');
        if ($utcYear < 1 || $utcYear > 9999) {
            throw new CodecException('timestamp year outside 0001-9999');
        }
        return $instant;
    }

    public static function encodeCheckValue($value)
    {
        return CBOR::encode(self::toCborCheckValue($value));
    }

    public static function decodeCheckValue($bytes)
    {
        return self::fromCborCheckValue(self::csilDecode($bytes));
    }

    public static function toCborCheckValue($value)
    {
        if (is_string($value)) {
            return array(0, $value);
        }
        if (is_int($value)) {
            return array(1, $value);
        }
        if (is_float($value)) {
            return array(2, $value);
        }
        throw new CodecException('csil cbor: value does not match any CheckValue variant');
    }

    public static function fromCborCheckValue($value)
    {
        $value = self::csilTagged($value, 'CheckValue');
        $csilIdx = $value[0];
        $csilVal = $value[1];
        if ($csilIdx === 0) {
            return $csilVal;
        }
        if ($csilIdx === 1) {
            return $csilVal;
        }
        if ($csilIdx === 2) {
            return $csilVal;
        }
        throw new CodecException('csil cbor: unknown CheckValue variant ' . var_export($csilIdx, true));
    }

    public static function encodeCheckEntries($value)
    {
        return CBOR::encode(self::toCborCheckEntries($value));
    }

    public static function decodeCheckEntries($bytes)
    {
        return self::fromCborCheckEntries(self::csilDecode($bytes));
    }

    public static function toCborCheckEntries($value)
    {
        return (function ($m) { $entries = array(); foreach (($m === null ? array() : $m) as $k => $v) { $entries[] = array((string) $k, self::toCborCheckValue($v)); } return CBOR::mapEntries($entries); })($value);
    }

    public static function fromCborCheckEntries($value)
    {
        return (function ($m) { $out = array(); foreach (self::csilCanonicalMap($m) as $k => $v) { $out[$k] = self::fromCborCheckValue($v); } return $out; })($value);
    }

    public static function encodeCheckResult($value)
    {
        return CBOR::encode(self::toCborCheckResult($value));
    }

    public static function decodeCheckResult($bytes)
    {
        return self::fromCborCheckResult(self::csilDecode($bytes));
    }

    public static function toCborCheckResult($value)
    {
        $out = array();
        $field = $value instanceof CheckResult ? $value->result : (is_array($value) && array_key_exists('result', $value) ? $value['result'] : null);
        $out['result'] = $field;
        $field = $value instanceof CheckResult ? $value->entries : (is_array($value) && array_key_exists('entries', $value) ? $value['entries'] : null);
        $out['entries'] = self::toCborCheckEntries($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCheckResult($value)
    {
        $value = self::csilRecord($value, 'CheckResult', array('result', 'entries'));
        return new CheckResult(array(
            'result' => array_key_exists('result', $value) ? $value['result'] : null,
            'entries' => array_key_exists('entries', $value) ? self::fromCborCheckEntries($value['entries']) : null,
        ));
    }

    public static function encodeKeyAlgorithm($value)
    {
        return CBOR::encode(self::toCborKeyAlgorithm($value));
    }

    public static function decodeKeyAlgorithm($bytes)
    {
        return self::fromCborKeyAlgorithm(self::csilDecode($bytes));
    }

    public static function toCborKeyAlgorithm($value)
    {
        try { return KeyAlgorithm::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborKeyAlgorithm($value)
    {
        try { return KeyAlgorithm::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeKeyUsage($value)
    {
        return CBOR::encode(self::toCborKeyUsage($value));
    }

    public static function decodeKeyUsage($bytes)
    {
        return self::fromCborKeyUsage(self::csilDecode($bytes));
    }

    public static function toCborKeyUsage($value)
    {
        try { return KeyUsage::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborKeyUsage($value)
    {
        try { return KeyUsage::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeAeadSuite($value)
    {
        return CBOR::encode(self::toCborAeadSuite($value));
    }

    public static function decodeAeadSuite($bytes)
    {
        return self::fromCborAeadSuite(self::csilDecode($bytes));
    }

    public static function toCborAeadSuite($value)
    {
        try { return AeadSuite::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborAeadSuite($value)
    {
        try { return AeadSuite::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeClaimValueType($value)
    {
        return CBOR::encode(self::toCborClaimValueType($value));
    }

    public static function decodeClaimValueType($bytes)
    {
        return self::fromCborClaimValueType(self::csilDecode($bytes));
    }

    public static function toCborClaimValueType($value)
    {
        try { return ClaimValueType::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborClaimValueType($value)
    {
        try { return ClaimValueType::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeSetRule($value)
    {
        return CBOR::encode(self::toCborSetRule($value));
    }

    public static function decodeSetRule($bytes)
    {
        return self::fromCborSetRule(self::csilDecode($bytes));
    }

    public static function toCborSetRule($value)
    {
        try { return SetRule::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborSetRule($value)
    {
        try { return SetRule::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeSigningRule($value)
    {
        return CBOR::encode(self::toCborSigningRule($value));
    }

    public static function decodeSigningRule($bytes)
    {
        return self::fromCborSigningRule(self::csilDecode($bytes));
    }

    public static function toCborSigningRule($value)
    {
        try { return SigningRule::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborSigningRule($value)
    {
        try { return SigningRule::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeSetClaimOutcome($value)
    {
        return CBOR::encode(self::toCborSetClaimOutcome($value));
    }

    public static function decodeSetClaimOutcome($bytes)
    {
        return self::fromCborSetClaimOutcome(self::csilDecode($bytes));
    }

    public static function toCborSetClaimOutcome($value)
    {
        try { return SetClaimOutcome::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborSetClaimOutcome($value)
    {
        try { return SetClaimOutcome::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeReleaseDisposition($value)
    {
        return CBOR::encode(self::toCborReleaseDisposition($value));
    }

    public static function decodeReleaseDisposition($bytes)
    {
        return self::fromCborReleaseDisposition(self::csilDecode($bytes));
    }

    public static function toCborReleaseDisposition($value)
    {
        try { return ReleaseDisposition::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborReleaseDisposition($value)
    {
        try { return ReleaseDisposition::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeConsentRowPolicy($value)
    {
        return CBOR::encode(self::toCborConsentRowPolicy($value));
    }

    public static function decodeConsentRowPolicy($bytes)
    {
        return self::fromCborConsentRowPolicy(self::csilDecode($bytes));
    }

    public static function toCborConsentRowPolicy($value)
    {
        try { return ConsentRowPolicy::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborConsentRowPolicy($value)
    {
        try { return ConsentRowPolicy::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeClaimApprovalStatus($value)
    {
        return CBOR::encode(self::toCborClaimApprovalStatus($value));
    }

    public static function decodeClaimApprovalStatus($bytes)
    {
        return self::fromCborClaimApprovalStatus(self::csilDecode($bytes));
    }

    public static function toCborClaimApprovalStatus($value)
    {
        try { return ClaimApprovalStatus::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborClaimApprovalStatus($value)
    {
        try { return ClaimApprovalStatus::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodePinRecheckOutcome($value)
    {
        return CBOR::encode(self::toCborPinRecheckOutcome($value));
    }

    public static function decodePinRecheckOutcome($bytes)
    {
        return self::fromCborPinRecheckOutcome(self::csilDecode($bytes));
    }

    public static function toCborPinRecheckOutcome($value)
    {
        try { return PinRecheckOutcome::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborPinRecheckOutcome($value)
    {
        try { return PinRecheckOutcome::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeNotificationPurpose($value)
    {
        return CBOR::encode(self::toCborNotificationPurpose($value));
    }

    public static function decodeNotificationPurpose($bytes)
    {
        return self::fromCborNotificationPurpose(self::csilDecode($bytes));
    }

    public static function toCborNotificationPurpose($value)
    {
        try { return NotificationPurpose::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborNotificationPurpose($value)
    {
        try { return NotificationPurpose::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeNotificationChannel($value)
    {
        return CBOR::encode(self::toCborNotificationChannel($value));
    }

    public static function decodeNotificationChannel($bytes)
    {
        return self::fromCborNotificationChannel(self::csilDecode($bytes));
    }

    public static function toCborNotificationChannel($value)
    {
        try { return NotificationChannel::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborNotificationChannel($value)
    {
        try { return NotificationChannel::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeDestinationKind($value)
    {
        return CBOR::encode(self::toCborDestinationKind($value));
    }

    public static function decodeDestinationKind($bytes)
    {
        return self::fromCborDestinationKind(self::csilDecode($bytes));
    }

    public static function toCborDestinationKind($value)
    {
        try { return DestinationKind::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborDestinationKind($value)
    {
        try { return DestinationKind::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeLocalRpPolicy($value)
    {
        return CBOR::encode(self::toCborLocalRpPolicy($value));
    }

    public static function decodeLocalRpPolicy($bytes)
    {
        return self::fromCborLocalRpPolicy(self::csilDecode($bytes));
    }

    public static function toCborLocalRpPolicy($value)
    {
        try { return LocalRpPolicy::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborLocalRpPolicy($value)
    {
        try { return LocalRpPolicy::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeLocalRpStatus($value)
    {
        return CBOR::encode(self::toCborLocalRpStatus($value));
    }

    public static function decodeLocalRpStatus($bytes)
    {
        return self::fromCborLocalRpStatus(self::csilDecode($bytes));
    }

    public static function toCborLocalRpStatus($value)
    {
        try { return LocalRpStatus::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborLocalRpStatus($value)
    {
        try { return LocalRpStatus::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeLocalRpAdmission($value)
    {
        return CBOR::encode(self::toCborLocalRpAdmission($value));
    }

    public static function decodeLocalRpAdmission($bytes)
    {
        return self::fromCborLocalRpAdmission(self::csilDecode($bytes));
    }

    public static function toCborLocalRpAdmission($value)
    {
        try { return LocalRpAdmission::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborLocalRpAdmission($value)
    {
        try { return LocalRpAdmission::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeAppAccessMode($value)
    {
        return CBOR::encode(self::toCborAppAccessMode($value));
    }

    public static function decodeAppAccessMode($bytes)
    {
        return self::fromCborAppAccessMode(self::csilDecode($bytes));
    }

    public static function toCborAppAccessMode($value)
    {
        try { return AppAccessMode::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborAppAccessMode($value)
    {
        try { return AppAccessMode::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeAppAccessTargetKind($value)
    {
        return CBOR::encode(self::toCborAppAccessTargetKind($value));
    }

    public static function decodeAppAccessTargetKind($bytes)
    {
        return self::fromCborAppAccessTargetKind(self::csilDecode($bytes));
    }

    public static function toCborAppAccessTargetKind($value)
    {
        try { return AppAccessTargetKind::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborAppAccessTargetKind($value)
    {
        try { return AppAccessTargetKind::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeClaimOperator($value)
    {
        return CBOR::encode(self::toCborClaimOperator($value));
    }

    public static function decodeClaimOperator($bytes)
    {
        return self::fromCborClaimOperator(self::csilDecode($bytes));
    }

    public static function toCborClaimOperator($value)
    {
        try { return ClaimOperator::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborClaimOperator($value)
    {
        try { return ClaimOperator::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeApplicationKeyChallengePurpose($value)
    {
        return CBOR::encode(self::toCborApplicationKeyChallengePurpose($value));
    }

    public static function decodeApplicationKeyChallengePurpose($bytes)
    {
        return self::fromCborApplicationKeyChallengePurpose(self::csilDecode($bytes));
    }

    public static function toCborApplicationKeyChallengePurpose($value)
    {
        try { return ApplicationKeyChallengePurpose::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborApplicationKeyChallengePurpose($value)
    {
        try { return ApplicationKeyChallengePurpose::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeAuthFlow($value)
    {
        return CBOR::encode(self::toCborAuthFlow($value));
    }

    public static function decodeAuthFlow($bytes)
    {
        return self::fromCborAuthFlow(self::csilDecode($bytes));
    }

    public static function toCborAuthFlow($value)
    {
        try { return AuthFlow::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborAuthFlow($value)
    {
        try { return AuthFlow::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeRpCacheStatus($value)
    {
        return CBOR::encode(self::toCborRpCacheStatus($value));
    }

    public static function decodeRpCacheStatus($bytes)
    {
        return self::fromCborRpCacheStatus(self::csilDecode($bytes));
    }

    public static function toCborRpCacheStatus($value)
    {
        try { return RpCacheStatus::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborRpCacheStatus($value)
    {
        try { return RpCacheStatus::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeAccountKind($value)
    {
        return CBOR::encode(self::toCborAccountKind($value));
    }

    public static function decodeAccountKind($bytes)
    {
        return self::fromCborAccountKind(self::csilDecode($bytes));
    }

    public static function toCborAccountKind($value)
    {
        try { return AccountKind::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborAccountKind($value)
    {
        try { return AccountKind::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeRpErrorCode($value)
    {
        return CBOR::encode(self::toCborRpErrorCode($value));
    }

    public static function decodeRpErrorCode($bytes)
    {
        return self::fromCborRpErrorCode(self::csilDecode($bytes));
    }

    public static function toCborRpErrorCode($value)
    {
        try { return RpErrorCode::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborRpErrorCode($value)
    {
        try { return RpErrorCode::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeIssuedClaimOutcome($value)
    {
        return CBOR::encode(self::toCborIssuedClaimOutcome($value));
    }

    public static function decodeIssuedClaimOutcome($bytes)
    {
        return self::fromCborIssuedClaimOutcome(self::csilDecode($bytes));
    }

    public static function toCborIssuedClaimOutcome($value)
    {
        try { return IssuedClaimOutcome::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborIssuedClaimOutcome($value)
    {
        try { return IssuedClaimOutcome::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeHelloRequest($value)
    {
        return CBOR::encode(self::toCborHelloRequest($value));
    }

    public static function decodeHelloRequest($bytes)
    {
        return self::fromCborHelloRequest(self::csilDecode($bytes));
    }

    public static function toCborHelloRequest($value)
    {
        $out = array();
        $field = $value instanceof HelloRequest ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        if ($field !== null) {
            $out['name'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborHelloRequest($value)
    {
        $value = self::csilRecord($value, 'HelloRequest', array());
        return new HelloRequest(array(
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
        ));
    }

    public static function encodeHelloResponse($value)
    {
        return CBOR::encode(self::toCborHelloResponse($value));
    }

    public static function decodeHelloResponse($bytes)
    {
        return self::fromCborHelloResponse(self::csilDecode($bytes));
    }

    public static function toCborHelloResponse($value)
    {
        $out = array();
        $field = $value instanceof HelloResponse ? $value->greeting : (is_array($value) && array_key_exists('greeting', $value) ? $value['greeting'] : null);
        $out['greeting'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborHelloResponse($value)
    {
        $value = self::csilRecord($value, 'HelloResponse', array('greeting'));
        return new HelloResponse(array(
            'greeting' => array_key_exists('greeting', $value) ? $value['greeting'] : null,
        ));
    }

    public static function encodeGuestbookEntry($value)
    {
        return CBOR::encode(self::toCborGuestbookEntry($value));
    }

    public static function decodeGuestbookEntry($bytes)
    {
        return self::fromCborGuestbookEntry(self::csilDecode($bytes));
    }

    public static function toCborGuestbookEntry($value)
    {
        $out = array();
        $field = $value instanceof GuestbookEntry ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof GuestbookEntry ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        $out['name'] = $field;
        $field = $value instanceof GuestbookEntry ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = self::timestampToCbor($field);
        $field = $value instanceof GuestbookEntry ? $value->updatedAt : (is_array($value) && array_key_exists('updated_at', $value) ? $value['updated_at'] : null);
        $out['updated_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGuestbookEntry($value)
    {
        $value = self::csilRecord($value, 'GuestbookEntry', array('id', 'name', 'created_at', 'updated_at'));
        return new GuestbookEntry(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
            'created_at' => array_key_exists('created_at', $value) ? self::timestampFromCbor($value['created_at']) : null,
            'updated_at' => array_key_exists('updated_at', $value) ? self::timestampFromCbor($value['updated_at']) : null,
        ));
    }

    public static function encodeCreateGuestbookRequest($value)
    {
        return CBOR::encode(self::toCborCreateGuestbookRequest($value));
    }

    public static function decodeCreateGuestbookRequest($bytes)
    {
        return self::fromCborCreateGuestbookRequest(self::csilDecode($bytes));
    }

    public static function toCborCreateGuestbookRequest($value)
    {
        $out = array();
        $field = $value instanceof CreateGuestbookRequest ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        $out['name'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCreateGuestbookRequest($value)
    {
        $value = self::csilRecord($value, 'CreateGuestbookRequest', array('name'));
        return new CreateGuestbookRequest(array(
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
        ));
    }

    public static function encodeUpdateGuestbookRequest($value)
    {
        return CBOR::encode(self::toCborUpdateGuestbookRequest($value));
    }

    public static function decodeUpdateGuestbookRequest($bytes)
    {
        return self::fromCborUpdateGuestbookRequest(self::csilDecode($bytes));
    }

    public static function toCborUpdateGuestbookRequest($value)
    {
        $out = array();
        $field = $value instanceof UpdateGuestbookRequest ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof UpdateGuestbookRequest ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        $out['name'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborUpdateGuestbookRequest($value)
    {
        $value = self::csilRecord($value, 'UpdateGuestbookRequest', array('id', 'name'));
        return new UpdateGuestbookRequest(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
        ));
    }

    public static function encodeDeleteGuestbookRequest($value)
    {
        return CBOR::encode(self::toCborDeleteGuestbookRequest($value));
    }

    public static function decodeDeleteGuestbookRequest($bytes)
    {
        return self::fromCborDeleteGuestbookRequest(self::csilDecode($bytes));
    }

    public static function toCborDeleteGuestbookRequest($value)
    {
        $out = array();
        $field = $value instanceof DeleteGuestbookRequest ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborDeleteGuestbookRequest($value)
    {
        $value = self::csilRecord($value, 'DeleteGuestbookRequest', array('id'));
        return new DeleteGuestbookRequest(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
        ));
    }

    public static function encodeDeleteGuestbookResponse($value)
    {
        return CBOR::encode(self::toCborDeleteGuestbookResponse($value));
    }

    public static function decodeDeleteGuestbookResponse($bytes)
    {
        return self::fromCborDeleteGuestbookResponse(self::csilDecode($bytes));
    }

    public static function toCborDeleteGuestbookResponse($value)
    {
        $out = array();
        $field = $value instanceof DeleteGuestbookResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborDeleteGuestbookResponse($value)
    {
        $value = self::csilRecord($value, 'DeleteGuestbookResponse', array('success'));
        return new DeleteGuestbookResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeGuestbookListRequest($value)
    {
        return CBOR::encode(self::toCborGuestbookListRequest($value));
    }

    public static function decodeGuestbookListRequest($bytes)
    {
        return self::fromCborGuestbookListRequest(self::csilDecode($bytes));
    }

    public static function toCborGuestbookListRequest($value)
    {
        $out = array();
        $field = $value instanceof GuestbookListRequest ? $value->offset : (is_array($value) && array_key_exists('offset', $value) ? $value['offset'] : null);
        if ($field !== null) {
            $out['offset'] = $field;
        }
        $field = $value instanceof GuestbookListRequest ? $value->limit : (is_array($value) && array_key_exists('limit', $value) ? $value['limit'] : null);
        if ($field !== null) {
            $out['limit'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGuestbookListRequest($value)
    {
        $value = self::csilRecord($value, 'GuestbookListRequest', array());
        return new GuestbookListRequest(array(
            'offset' => array_key_exists('offset', $value) ? $value['offset'] : null,
            'limit' => array_key_exists('limit', $value) ? $value['limit'] : null,
        ));
    }

    public static function encodeGuestbookListResponse($value)
    {
        return CBOR::encode(self::toCborGuestbookListResponse($value));
    }

    public static function decodeGuestbookListResponse($bytes)
    {
        return self::fromCborGuestbookListResponse(self::csilDecode($bytes));
    }

    public static function toCborGuestbookListResponse($value)
    {
        $out = array();
        $field = $value instanceof GuestbookListResponse ? $value->entries : (is_array($value) && array_key_exists('entries', $value) ? $value['entries'] : null);
        $out['entries'] = array_map(function ($item) { return self::toCborGuestbookEntry($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGuestbookListResponse($value)
    {
        $value = self::csilRecord($value, 'GuestbookListResponse', array('entries'));
        return new GuestbookListResponse(array(
            'entries' => array_key_exists('entries', $value) ? array_map(function ($item) { return self::fromCborGuestbookEntry($item); }, self::csilList($value['entries'])) : null,
        ));
    }

    public static function encodeEmptyRequest($value)
    {
        return CBOR::encode(self::toCborEmptyRequest($value));
    }

    public static function decodeEmptyRequest($bytes)
    {
        return self::fromCborEmptyRequest(self::csilDecode($bytes));
    }

    public static function toCborEmptyRequest($value)
    {
        $out = array();
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborEmptyRequest($value)
    {
        $value = self::csilRecord($value, 'EmptyRequest', array());
        return new EmptyRequest(array(
        ));
    }

    public static function encodeDomainPublicKey($value)
    {
        return CBOR::encode(self::toCborDomainPublicKey($value));
    }

    public static function decodeDomainPublicKey($bytes)
    {
        return self::fromCborDomainPublicKey(self::csilDecode($bytes));
    }

    public static function toCborDomainPublicKey($value)
    {
        $out = array();
        $field = $value instanceof DomainPublicKey ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof DomainPublicKey ? $value->publicKey : (is_array($value) && array_key_exists('public_key', $value) ? $value['public_key'] : null);
        $out['public_key'] = CBOR::bytes($field);
        $field = $value instanceof DomainPublicKey ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof DomainPublicKey ? $value->algorithm : (is_array($value) && array_key_exists('algorithm', $value) ? $value['algorithm'] : null);
        $out['algorithm'] = self::toCborKeyAlgorithm($field);
        $field = $value instanceof DomainPublicKey ? $value->keyUsage : (is_array($value) && array_key_exists('key_usage', $value) ? $value['key_usage'] : null);
        $out['key_usage'] = self::toCborKeyUsage($field);
        $field = $value instanceof DomainPublicKey ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = self::timestampToCbor($field);
        $field = $value instanceof DomainPublicKey ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof DomainPublicKey ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof DomainPublicKey ? $value->signedByKeyId : (is_array($value) && array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null);
        if ($field !== null) {
            $out['signed_by_key_id'] = $field;
        }
        $field = $value instanceof DomainPublicKey ? $value->keySignature : (is_array($value) && array_key_exists('key_signature', $value) ? $value['key_signature'] : null);
        if ($field !== null) {
            $out['key_signature'] = CBOR::bytes($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborDomainPublicKey($value)
    {
        $value = self::csilRecord($value, 'DomainPublicKey', array('key_id', 'public_key', 'fingerprint', 'algorithm', 'key_usage', 'created_at', 'expires_at'));
        return new DomainPublicKey(array(
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'public_key' => array_key_exists('public_key', $value) ? $value['public_key'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'algorithm' => array_key_exists('algorithm', $value) ? self::fromCborKeyAlgorithm($value['algorithm']) : null,
            'key_usage' => array_key_exists('key_usage', $value) ? self::fromCborKeyUsage($value['key_usage']) : null,
            'created_at' => array_key_exists('created_at', $value) ? self::timestampFromCbor($value['created_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
            'signed_by_key_id' => array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null,
            'key_signature' => array_key_exists('key_signature', $value) ? $value['key_signature'] : null,
        ));
    }

    public static function encodeGetDomainKeysResponse($value)
    {
        return CBOR::encode(self::toCborGetDomainKeysResponse($value));
    }

    public static function decodeGetDomainKeysResponse($bytes)
    {
        return self::fromCborGetDomainKeysResponse(self::csilDecode($bytes));
    }

    public static function toCborGetDomainKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof GetDomainKeysResponse ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof GetDomainKeysResponse ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborDomainPublicKey($item); }, $field === null ? array() : $field);
        $field = $value instanceof GetDomainKeysResponse ? $value->recentRevocationsAvailable : (is_array($value) && array_key_exists('recent_revocations_available', $value) ? $value['recent_revocations_available'] : null);
        if ($field !== null) {
            $out['recent_revocations_available'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetDomainKeysResponse($value)
    {
        $value = self::csilRecord($value, 'GetDomainKeysResponse', array('domain', 'keys'));
        return new GetDomainKeysResponse(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborDomainPublicKey($item); }, self::csilList($value['keys'])) : null,
            'recent_revocations_available' => array_key_exists('recent_revocations_available', $value) ? $value['recent_revocations_available'] : null,
        ));
    }

    public static function encodeGetRevocationsRequest($value)
    {
        return CBOR::encode(self::toCborGetRevocationsRequest($value));
    }

    public static function decodeGetRevocationsRequest($bytes)
    {
        return self::fromCborGetRevocationsRequest(self::csilDecode($bytes));
    }

    public static function toCborGetRevocationsRequest($value)
    {
        $out = array();
        $field = $value instanceof GetRevocationsRequest ? $value->since : (is_array($value) && array_key_exists('since', $value) ? $value['since'] : null);
        if ($field !== null) {
            $out['since'] = self::timestampToCbor($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetRevocationsRequest($value)
    {
        $value = self::csilRecord($value, 'GetRevocationsRequest', array());
        return new GetRevocationsRequest(array(
            'since' => array_key_exists('since', $value) ? self::timestampFromCbor($value['since']) : null,
        ));
    }

    public static function encodeGetRevocationsResponse($value)
    {
        return CBOR::encode(self::toCborGetRevocationsResponse($value));
    }

    public static function decodeGetRevocationsResponse($bytes)
    {
        return self::fromCborGetRevocationsResponse(self::csilDecode($bytes));
    }

    public static function toCborGetRevocationsResponse($value)
    {
        $out = array();
        $field = $value instanceof GetRevocationsResponse ? $value->revocations : (is_array($value) && array_key_exists('revocations', $value) ? $value['revocations'] : null);
        $out['revocations'] = array_map(function ($item) { return self::toCborRevocationCertificate($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetRevocationsResponse($value)
    {
        $value = self::csilRecord($value, 'GetRevocationsResponse', array('revocations'));
        return new GetRevocationsResponse(array(
            'revocations' => array_key_exists('revocations', $value) ? array_map(function ($item) { return self::fromCborRevocationCertificate($item); }, self::csilList($value['revocations'])) : null,
        ));
    }

    public static function encodeRecheckPinsRequest($value)
    {
        return CBOR::encode(self::toCborRecheckPinsRequest($value));
    }

    public static function decodeRecheckPinsRequest($bytes)
    {
        return self::fromCborRecheckPinsRequest(self::csilDecode($bytes));
    }

    public static function toCborRecheckPinsRequest($value)
    {
        $out = array();
        $field = $value instanceof RecheckPinsRequest ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        if ($field !== null) {
            $out['domain'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRecheckPinsRequest($value)
    {
        $value = self::csilRecord($value, 'RecheckPinsRequest', array());
        return new RecheckPinsRequest(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
        ));
    }

    public static function encodePinRecheckResult($value)
    {
        return CBOR::encode(self::toCborPinRecheckResult($value));
    }

    public static function decodePinRecheckResult($bytes)
    {
        return self::fromCborPinRecheckResult(self::csilDecode($bytes));
    }

    public static function toCborPinRecheckResult($value)
    {
        $out = array();
        $field = $value instanceof PinRecheckResult ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof PinRecheckResult ? $value->outcome : (is_array($value) && array_key_exists('outcome', $value) ? $value['outcome'] : null);
        $out['outcome'] = self::toCborPinRecheckOutcome($field);
        $field = $value instanceof PinRecheckResult ? $value->message : (is_array($value) && array_key_exists('message', $value) ? $value['message'] : null);
        if ($field !== null) {
            $out['message'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPinRecheckResult($value)
    {
        $value = self::csilRecord($value, 'PinRecheckResult', array('domain', 'outcome'));
        return new PinRecheckResult(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'outcome' => array_key_exists('outcome', $value) ? self::fromCborPinRecheckOutcome($value['outcome']) : null,
            'message' => array_key_exists('message', $value) ? $value['message'] : null,
        ));
    }

    public static function encodeRecheckPinsResponse($value)
    {
        return CBOR::encode(self::toCborRecheckPinsResponse($value));
    }

    public static function decodeRecheckPinsResponse($bytes)
    {
        return self::fromCborRecheckPinsResponse(self::csilDecode($bytes));
    }

    public static function toCborRecheckPinsResponse($value)
    {
        $out = array();
        $field = $value instanceof RecheckPinsResponse ? $value->results : (is_array($value) && array_key_exists('results', $value) ? $value['results'] : null);
        $out['results'] = array_map(function ($item) { return self::toCborPinRecheckResult($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRecheckPinsResponse($value)
    {
        $value = self::csilRecord($value, 'RecheckPinsResponse', array('results'));
        return new RecheckPinsResponse(array(
            'results' => array_key_exists('results', $value) ? array_map(function ($item) { return self::fromCborPinRecheckResult($item); }, self::csilList($value['results'])) : null,
        ));
    }

    public static function encodeUserPublicKey($value)
    {
        return CBOR::encode(self::toCborUserPublicKey($value));
    }

    public static function decodeUserPublicKey($bytes)
    {
        return self::fromCborUserPublicKey(self::csilDecode($bytes));
    }

    public static function toCborUserPublicKey($value)
    {
        $out = array();
        $field = $value instanceof UserPublicKey ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof UserPublicKey ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof UserPublicKey ? $value->publicKey : (is_array($value) && array_key_exists('public_key', $value) ? $value['public_key'] : null);
        $out['public_key'] = CBOR::bytes($field);
        $field = $value instanceof UserPublicKey ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof UserPublicKey ? $value->algorithm : (is_array($value) && array_key_exists('algorithm', $value) ? $value['algorithm'] : null);
        $out['algorithm'] = self::toCborKeyAlgorithm($field);
        $field = $value instanceof UserPublicKey ? $value->keyUsage : (is_array($value) && array_key_exists('key_usage', $value) ? $value['key_usage'] : null);
        $out['key_usage'] = self::toCborKeyUsage($field);
        $field = $value instanceof UserPublicKey ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = self::timestampToCbor($field);
        $field = $value instanceof UserPublicKey ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof UserPublicKey ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof UserPublicKey ? $value->signedByKeyId : (is_array($value) && array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null);
        if ($field !== null) {
            $out['signed_by_key_id'] = $field;
        }
        $field = $value instanceof UserPublicKey ? $value->keySignature : (is_array($value) && array_key_exists('key_signature', $value) ? $value['key_signature'] : null);
        if ($field !== null) {
            $out['key_signature'] = CBOR::bytes($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborUserPublicKey($value)
    {
        $value = self::csilRecord($value, 'UserPublicKey', array('key_id', 'user_id', 'public_key', 'fingerprint', 'algorithm', 'key_usage', 'created_at', 'expires_at'));
        return new UserPublicKey(array(
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'public_key' => array_key_exists('public_key', $value) ? $value['public_key'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'algorithm' => array_key_exists('algorithm', $value) ? self::fromCborKeyAlgorithm($value['algorithm']) : null,
            'key_usage' => array_key_exists('key_usage', $value) ? self::fromCborKeyUsage($value['key_usage']) : null,
            'created_at' => array_key_exists('created_at', $value) ? self::timestampFromCbor($value['created_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
            'signed_by_key_id' => array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null,
            'key_signature' => array_key_exists('key_signature', $value) ? $value['key_signature'] : null,
        ));
    }

    public static function encodeGetUserKeysRequest($value)
    {
        return CBOR::encode(self::toCborGetUserKeysRequest($value));
    }

    public static function decodeGetUserKeysRequest($bytes)
    {
        return self::fromCborGetUserKeysRequest(self::csilDecode($bytes));
    }

    public static function toCborGetUserKeysRequest($value)
    {
        $out = array();
        $field = $value instanceof GetUserKeysRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetUserKeysRequest($value)
    {
        $value = self::csilRecord($value, 'GetUserKeysRequest', array('user_id'));
        return new GetUserKeysRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeGetUserKeysResponse($value)
    {
        return CBOR::encode(self::toCborGetUserKeysResponse($value));
    }

    public static function decodeGetUserKeysResponse($bytes)
    {
        return self::fromCborGetUserKeysResponse(self::csilDecode($bytes));
    }

    public static function toCborGetUserKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof GetUserKeysResponse ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof GetUserKeysResponse ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof GetUserKeysResponse ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborUserPublicKey($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetUserKeysResponse($value)
    {
        $value = self::csilRecord($value, 'GetUserKeysResponse', array('user_id', 'domain', 'keys'));
        return new GetUserKeysResponse(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborUserPublicKey($item); }, self::csilList($value['keys'])) : null,
        ));
    }

    public static function encodeClaimSignature($value)
    {
        return CBOR::encode(self::toCborClaimSignature($value));
    }

    public static function decodeClaimSignature($bytes)
    {
        return self::fromCborClaimSignature(self::csilDecode($bytes));
    }

    public static function toCborClaimSignature($value)
    {
        $out = array();
        $field = $value instanceof ClaimSignature ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof ClaimSignature ? $value->signedByKeyId : (is_array($value) && array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null);
        $out['signed_by_key_id'] = $field;
        $field = $value instanceof ClaimSignature ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborClaimSignature($value)
    {
        $value = self::csilRecord($value, 'ClaimSignature', array('domain', 'signed_by_key_id', 'signature'));
        return new ClaimSignature(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'signed_by_key_id' => array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeRevocationCertificate($value)
    {
        return CBOR::encode(self::toCborRevocationCertificate($value));
    }

    public static function decodeRevocationCertificate($bytes)
    {
        return self::fromCborRevocationCertificate(self::csilDecode($bytes));
    }

    public static function toCborRevocationCertificate($value)
    {
        $out = array();
        $field = $value instanceof RevocationCertificate ? $value->targetKeyId : (is_array($value) && array_key_exists('target_key_id', $value) ? $value['target_key_id'] : null);
        $out['target_key_id'] = $field;
        $field = $value instanceof RevocationCertificate ? $value->targetFingerprint : (is_array($value) && array_key_exists('target_fingerprint', $value) ? $value['target_fingerprint'] : null);
        $out['target_fingerprint'] = $field;
        $field = $value instanceof RevocationCertificate ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        $out['revoked_at'] = self::timestampToCbor($field);
        $field = $value instanceof RevocationCertificate ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevocationCertificate($value)
    {
        $value = self::csilRecord($value, 'RevocationCertificate', array('target_key_id', 'target_fingerprint', 'revoked_at', 'signatures'));
        return new RevocationCertificate(array(
            'target_key_id' => array_key_exists('target_key_id', $value) ? $value['target_key_id'] : null,
            'target_fingerprint' => array_key_exists('target_fingerprint', $value) ? $value['target_fingerprint'] : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, self::csilList($value['signatures'])) : null,
        ));
    }

    public static function encodeClaim($value)
    {
        return CBOR::encode(self::toCborClaim($value));
    }

    public static function decodeClaim($bytes)
    {
        return self::fromCborClaim(self::csilDecode($bytes));
    }

    public static function toCborClaim($value)
    {
        $out = array();
        $field = $value instanceof Claim ? $value->claimId : (is_array($value) && array_key_exists('claim_id', $value) ? $value['claim_id'] : null);
        $out['claim_id'] = $field;
        $field = $value instanceof Claim ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof Claim ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof Claim ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = CBOR::bytes($field);
        $field = $value instanceof Claim ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        $field = $value instanceof Claim ? $value->attestedAt : (is_array($value) && array_key_exists('attested_at', $value) ? $value['attested_at'] : null);
        $out['attested_at'] = self::timestampToCbor($field);
        $field = $value instanceof Claim ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = self::timestampToCbor($field);
        $field = $value instanceof Claim ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        if ($field !== null) {
            $out['expires_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof Claim ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = self::timestampToCbor($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborClaim($value)
    {
        $value = self::csilRecord($value, 'Claim', array('claim_id', 'user_id', 'claim_type', 'claim_value', 'signatures', 'attested_at', 'created_at'));
        return new Claim(array(
            'claim_id' => array_key_exists('claim_id', $value) ? $value['claim_id'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, self::csilList($value['signatures'])) : null,
            'attested_at' => array_key_exists('attested_at', $value) ? self::timestampFromCbor($value['attested_at']) : null,
            'created_at' => array_key_exists('created_at', $value) ? self::timestampFromCbor($value['created_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
        ));
    }

    public static function encodeGetUserClaimsRequest($value)
    {
        return CBOR::encode(self::toCborGetUserClaimsRequest($value));
    }

    public static function decodeGetUserClaimsRequest($bytes)
    {
        return self::fromCborGetUserClaimsRequest(self::csilDecode($bytes));
    }

    public static function toCborGetUserClaimsRequest($value)
    {
        $out = array();
        $field = $value instanceof GetUserClaimsRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof GetUserClaimsRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetUserClaimsRequest($value)
    {
        $value = self::csilRecord($value, 'GetUserClaimsRequest', array('user_id', 'token'));
        return new GetUserClaimsRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
        ));
    }

    public static function encodeGetUserClaimsResponse($value)
    {
        return CBOR::encode(self::toCborGetUserClaimsResponse($value));
    }

    public static function decodeGetUserClaimsResponse($bytes)
    {
        return self::fromCborGetUserClaimsResponse(self::csilDecode($bytes));
    }

    public static function toCborGetUserClaimsResponse($value)
    {
        $out = array();
        $field = $value instanceof GetUserClaimsResponse ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof GetUserClaimsResponse ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof GetUserClaimsResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetUserClaimsResponse($value)
    {
        $value = self::csilRecord($value, 'GetUserClaimsResponse', array('user_id', 'domain', 'claims'));
        return new GetUserClaimsResponse(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, self::csilList($value['claims'])) : null,
        ));
    }

    public static function encodeRequestedClaim($value)
    {
        return CBOR::encode(self::toCborRequestedClaim($value));
    }

    public static function decodeRequestedClaim($bytes)
    {
        return self::fromCborRequestedClaim(self::csilDecode($bytes));
    }

    public static function toCborRequestedClaim($value)
    {
        $out = array();
        $field = $value instanceof RequestedClaim ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof RequestedClaim ? $value->datatype : (is_array($value) && array_key_exists('datatype', $value) ? $value['datatype'] : null);
        $out['datatype'] = self::toCborClaimValueType($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRequestedClaim($value)
    {
        $value = self::csilRecord($value, 'RequestedClaim', array('claim_type', 'datatype'));
        return new RequestedClaim(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'datatype' => array_key_exists('datatype', $value) ? self::fromCborClaimValueType($value['datatype']) : null,
        ));
    }

    public static function encodeClaimRequest($value)
    {
        return CBOR::encode(self::toCborClaimRequest($value));
    }

    public static function decodeClaimRequest($bytes)
    {
        return self::fromCborClaimRequest(self::csilDecode($bytes));
    }

    public static function toCborClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof ClaimRequest ? $value->required : (is_array($value) && array_key_exists('required', $value) ? $value['required'] : null);
        $out['required'] = array_map(function ($item) { return self::toCborRequestedClaim($item); }, $field === null ? array() : $field);
        $field = $value instanceof ClaimRequest ? $value->optional : (is_array($value) && array_key_exists('optional', $value) ? $value['optional'] : null);
        $out['optional'] = array_map(function ($item) { return self::toCborRequestedClaim($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborClaimRequest($value)
    {
        $value = self::csilRecord($value, 'ClaimRequest', array('required', 'optional'));
        return new ClaimRequest(array(
            'required' => array_key_exists('required', $value) ? array_map(function ($item) { return self::fromCborRequestedClaim($item); }, self::csilList($value['required'])) : null,
            'optional' => array_key_exists('optional', $value) ? array_map(function ($item) { return self::fromCborRequestedClaim($item); }, self::csilList($value['optional'])) : null,
        ));
    }

    public static function encodeAuthenticationRequirements($value)
    {
        return CBOR::encode(self::toCborAuthenticationRequirements($value));
    }

    public static function decodeAuthenticationRequirements($bytes)
    {
        return self::fromCborAuthenticationRequirements(self::csilDecode($bytes));
    }

    public static function toCborAuthenticationRequirements($value)
    {
        $out = array();
        $field = $value instanceof AuthenticationRequirements ? $value->minimumFactorCount : (is_array($value) && array_key_exists('minimum_factor_count', $value) ? $value['minimum_factor_count'] : null);
        $out['minimum_factor_count'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAuthenticationRequirements($value)
    {
        $value = self::csilRecord($value, 'AuthenticationRequirements', array('minimum_factor_count'));
        return new AuthenticationRequirements(array(
            'minimum_factor_count' => array_key_exists('minimum_factor_count', $value) ? $value['minimum_factor_count'] : null,
        ));
    }

    public static function encodeAuthFlowContext($value)
    {
        return CBOR::encode(self::toCborAuthFlowContext($value));
    }

    public static function decodeAuthFlowContext($bytes)
    {
        return self::fromCborAuthFlowContext(self::csilDecode($bytes));
    }

    public static function toCborAuthFlowContext($value)
    {
        $out = array();
        $field = $value instanceof AuthFlowContext ? $value->flow : (is_array($value) && array_key_exists('flow', $value) ? $value['flow'] : null);
        $out['flow'] = self::toCborAuthFlow($field);
        $field = $value instanceof AuthFlowContext ? $value->priorSession : (is_array($value) && array_key_exists('prior_session', $value) ? $value['prior_session'] : null);
        if ($field !== null) {
            $out['prior_session'] = $field;
        }
        $field = $value instanceof AuthFlowContext ? $value->requestReason : (is_array($value) && array_key_exists('request_reason', $value) ? $value['request_reason'] : null);
        if ($field !== null) {
            $out['request_reason'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAuthFlowContext($value)
    {
        $value = self::csilRecord($value, 'AuthFlowContext', array('flow'));
        return new AuthFlowContext(array(
            'flow' => array_key_exists('flow', $value) ? self::fromCborAuthFlow($value['flow']) : null,
            'prior_session' => array_key_exists('prior_session', $value) ? $value['prior_session'] : null,
            'request_reason' => array_key_exists('request_reason', $value) ? $value['request_reason'] : null,
        ));
    }

    public static function encodeConsentGrant($value)
    {
        return CBOR::encode(self::toCborConsentGrant($value));
    }

    public static function decodeConsentGrant($bytes)
    {
        return self::fromCborConsentGrant(self::csilDecode($bytes));
    }

    public static function toCborConsentGrant($value)
    {
        $out = array();
        $field = $value instanceof ConsentGrant ? $value->grantId : (is_array($value) && array_key_exists('grant_id', $value) ? $value['grant_id'] : null);
        $out['grant_id'] = $field;
        $field = $value instanceof ConsentGrant ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof ConsentGrant ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ConsentGrant ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof ConsentGrant ? $value->claimTypes : (is_array($value) && array_key_exists('claim_types', $value) ? $value['claim_types'] : null);
        $out['claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof ConsentGrant ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof ConsentGrant ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof ConsentGrant ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof ConsentGrant ? $value->application : (is_array($value) && array_key_exists('application', $value) ? $value['application'] : null);
        if ($field !== null) {
            $out['application'] = self::toCborApplicationRef($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborConsentGrant($value)
    {
        $value = self::csilRecord($value, 'ConsentGrant', array('grant_id', 'user_id', 'subject_domain', 'audience', 'claim_types', 'issued_at', 'expires_at'));
        return new ConsentGrant(array(
            'grant_id' => array_key_exists('grant_id', $value) ? $value['grant_id'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'claim_types' => array_key_exists('claim_types', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['claim_types'])) : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
            'application' => array_key_exists('application', $value) ? self::fromCborApplicationRef($value['application']) : null,
        ));
    }

    public static function encodeSignedConsentGrant($value)
    {
        return CBOR::encode(self::toCborSignedConsentGrant($value));
    }

    public static function decodeSignedConsentGrant($bytes)
    {
        return self::fromCborSignedConsentGrant(self::csilDecode($bytes));
    }

    public static function toCborSignedConsentGrant($value)
    {
        $out = array();
        $field = $value instanceof SignedConsentGrant ? $value->grant : (is_array($value) && array_key_exists('grant', $value) ? $value['grant'] : null);
        $out['grant'] = CBOR::bytes($field);
        $field = $value instanceof SignedConsentGrant ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedConsentGrant($value)
    {
        $value = self::csilRecord($value, 'SignedConsentGrant', array('grant', 'signatures'));
        return new SignedConsentGrant(array(
            'grant' => array_key_exists('grant', $value) ? $value['grant'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, self::csilList($value['signatures'])) : null,
        ));
    }

    public static function encodeDomainClaim($value)
    {
        return CBOR::encode(self::toCborDomainClaim($value));
    }

    public static function decodeDomainClaim($bytes)
    {
        return self::fromCborDomainClaim(self::csilDecode($bytes));
    }

    public static function toCborDomainClaim($value)
    {
        $out = array();
        $field = $value instanceof DomainClaim ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof DomainClaim ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = CBOR::bytes($field);
        $field = $value instanceof DomainClaim ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        $field = $value instanceof DomainClaim ? $value->attestedAt : (is_array($value) && array_key_exists('attested_at', $value) ? $value['attested_at'] : null);
        $out['attested_at'] = self::timestampToCbor($field);
        $field = $value instanceof DomainClaim ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        if ($field !== null) {
            $out['expires_at'] = self::timestampToCbor($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborDomainClaim($value)
    {
        $value = self::csilRecord($value, 'DomainClaim', array('claim_type', 'claim_value', 'signatures', 'attested_at'));
        return new DomainClaim(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, self::csilList($value['signatures'])) : null,
            'attested_at' => array_key_exists('attested_at', $value) ? self::timestampFromCbor($value['attested_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeSigningRequest($value)
    {
        return CBOR::encode(self::toCborSigningRequest($value));
    }

    public static function decodeSigningRequest($bytes)
    {
        return self::fromCborSigningRequest(self::csilDecode($bytes));
    }

    public static function toCborSigningRequest($value)
    {
        $out = array();
        $field = $value instanceof SigningRequest ? $value->requestId : (is_array($value) && array_key_exists('request_id', $value) ? $value['request_id'] : null);
        $out['request_id'] = $field;
        $field = $value instanceof SigningRequest ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof SigningRequest ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof SigningRequest ? $value->issuerDomain : (is_array($value) && array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null);
        $out['issuer_domain'] = $field;
        $field = $value instanceof SigningRequest ? $value->requestedClaimTypes : (is_array($value) && array_key_exists('requested_claim_types', $value) ? $value['requested_claim_types'] : null);
        $out['requested_claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof SigningRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        $field = $value instanceof SigningRequest ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof SigningRequest ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof SigningRequest ? $value->callback : (is_array($value) && array_key_exists('callback', $value) ? $value['callback'] : null);
        if ($field !== null) {
            $out['callback'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSigningRequest($value)
    {
        $value = self::csilRecord($value, 'SigningRequest', array('request_id', 'subject_user_id', 'subject_domain', 'issuer_domain', 'requested_claim_types', 'nonce', 'issued_at', 'expires_at'));
        return new SigningRequest(array(
            'request_id' => array_key_exists('request_id', $value) ? $value['request_id'] : null,
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'issuer_domain' => array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null,
            'requested_claim_types' => array_key_exists('requested_claim_types', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['requested_claim_types'])) : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'callback' => array_key_exists('callback', $value) ? $value['callback'] : null,
        ));
    }

    public static function encodeSignedSigningRequest($value)
    {
        return CBOR::encode(self::toCborSignedSigningRequest($value));
    }

    public static function decodeSignedSigningRequest($bytes)
    {
        return self::fromCborSignedSigningRequest(self::csilDecode($bytes));
    }

    public static function toCborSignedSigningRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedSigningRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedSigningRequest ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedSigningRequest($value)
    {
        $value = self::csilRecord($value, 'SignedSigningRequest', array('request', 'signatures'));
        return new SignedSigningRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, self::csilList($value['signatures'])) : null,
        ));
    }

    public static function encodeDepositClaimRequest($value)
    {
        return CBOR::encode(self::toCborDepositClaimRequest($value));
    }

    public static function decodeDepositClaimRequest($bytes)
    {
        return self::fromCborDepositClaimRequest(self::csilDecode($bytes));
    }

    public static function toCborDepositClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof DepositClaimRequest ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        $out['claim'] = self::toCborClaim($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborDepositClaimRequest($value)
    {
        $value = self::csilRecord($value, 'DepositClaimRequest', array('claim'));
        return new DepositClaimRequest(array(
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
        ));
    }

    public static function encodeDepositClaimResponse($value)
    {
        return CBOR::encode(self::toCborDepositClaimResponse($value));
    }

    public static function decodeDepositClaimResponse($bytes)
    {
        return self::fromCborDepositClaimResponse(self::csilDecode($bytes));
    }

    public static function toCborDepositClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof DepositClaimResponse ? $value->stored : (is_array($value) && array_key_exists('stored', $value) ? $value['stored'] : null);
        $out['stored'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborDepositClaimResponse($value)
    {
        $value = self::csilRecord($value, 'DepositClaimResponse', array('stored'));
        return new DepositClaimResponse(array(
            'stored' => array_key_exists('stored', $value) ? $value['stored'] : null,
        ));
    }

    public static function encodeIdentityAssertion($value)
    {
        return CBOR::encode(self::toCborIdentityAssertion($value));
    }

    public static function decodeIdentityAssertion($bytes)
    {
        return self::fromCborIdentityAssertion(self::csilDecode($bytes));
    }

    public static function toCborIdentityAssertion($value)
    {
        $out = array();
        $field = $value instanceof IdentityAssertion ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof IdentityAssertion ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof IdentityAssertion ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof IdentityAssertion ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        $field = $value instanceof IdentityAssertion ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof IdentityAssertion ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof IdentityAssertion ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof IdentityAssertion ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        if ($field !== null) {
            $out['display_name'] = $field;
        }
        $field = $value instanceof IdentityAssertion ? $value->application : (is_array($value) && array_key_exists('application', $value) ? $value['application'] : null);
        $out['application'] = self::toCborApplicationRef($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborIdentityAssertion($value)
    {
        $value = self::csilRecord($value, 'IdentityAssertion', array('user_id', 'domain', 'audience', 'nonce', 'issued_at', 'expires_at', 'authorized_claims', 'application'));
        return new IdentityAssertion(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['authorized_claims'])) : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
            'application' => array_key_exists('application', $value) ? self::fromCborApplicationRef($value['application']) : null,
        ));
    }

    public static function encodeSignedIdentityAssertion($value)
    {
        return CBOR::encode(self::toCborSignedIdentityAssertion($value));
    }

    public static function decodeSignedIdentityAssertion($bytes)
    {
        return self::fromCborSignedIdentityAssertion(self::csilDecode($bytes));
    }

    public static function toCborSignedIdentityAssertion($value)
    {
        $out = array();
        $field = $value instanceof SignedIdentityAssertion ? $value->assertion : (is_array($value) && array_key_exists('assertion', $value) ? $value['assertion'] : null);
        $out['assertion'] = CBOR::bytes($field);
        $field = $value instanceof SignedIdentityAssertion ? $value->signingKeyId : (is_array($value) && array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null);
        $out['signing_key_id'] = $field;
        $field = $value instanceof SignedIdentityAssertion ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedIdentityAssertion($value)
    {
        $value = self::csilRecord($value, 'SignedIdentityAssertion', array('assertion', 'signing_key_id', 'signature'));
        return new SignedIdentityAssertion(array(
            'assertion' => array_key_exists('assertion', $value) ? $value['assertion'] : null,
            'signing_key_id' => array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeGetUserInfoRequest($value)
    {
        return CBOR::encode(self::toCborGetUserInfoRequest($value));
    }

    public static function decodeGetUserInfoRequest($bytes)
    {
        return self::fromCborGetUserInfoRequest(self::csilDecode($bytes));
    }

    public static function toCborGetUserInfoRequest($value)
    {
        $out = array();
        $field = $value instanceof GetUserInfoRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetUserInfoRequest($value)
    {
        $value = self::csilRecord($value, 'GetUserInfoRequest', array('token'));
        return new GetUserInfoRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
        ));
    }

    public static function encodeUserInfoRequest($value)
    {
        return CBOR::encode(self::toCborUserInfoRequest($value));
    }

    public static function decodeUserInfoRequest($bytes)
    {
        return self::fromCborUserInfoRequest(self::csilDecode($bytes));
    }

    public static function toCborUserInfoRequest($value)
    {
        $out = array();
        $field = $value instanceof UserInfoRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = CBOR::bytes($field);
        $field = $value instanceof UserInfoRequest ? $value->relyingParty : (is_array($value) && array_key_exists('relying_party', $value) ? $value['relying_party'] : null);
        $out['relying_party'] = $field;
        $field = $value instanceof UserInfoRequest ? $value->timestamp : (is_array($value) && array_key_exists('timestamp', $value) ? $value['timestamp'] : null);
        $out['timestamp'] = self::timestampToCbor($field);
        $field = $value instanceof UserInfoRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborUserInfoRequest($value)
    {
        $value = self::csilRecord($value, 'UserInfoRequest', array('token', 'relying_party', 'timestamp', 'nonce'));
        return new UserInfoRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
            'relying_party' => array_key_exists('relying_party', $value) ? $value['relying_party'] : null,
            'timestamp' => array_key_exists('timestamp', $value) ? self::timestampFromCbor($value['timestamp']) : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
        ));
    }

    public static function encodeSignedUserInfoRequest($value)
    {
        return CBOR::encode(self::toCborSignedUserInfoRequest($value));
    }

    public static function decodeSignedUserInfoRequest($bytes)
    {
        return self::fromCborSignedUserInfoRequest(self::csilDecode($bytes));
    }

    public static function toCborSignedUserInfoRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedUserInfoRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedUserInfoRequest ? $value->signingKeyId : (is_array($value) && array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null);
        $out['signing_key_id'] = $field;
        $field = $value instanceof SignedUserInfoRequest ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        $field = $value instanceof SignedUserInfoRequest ? $value->publicKeys : (is_array($value) && array_key_exists('public_keys', $value) ? $value['public_keys'] : null);
        if ($field !== null) {
            $out['public_keys'] = array_map(function ($item) { return self::toCborDomainPublicKey($item); }, $field === null ? array() : $field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedUserInfoRequest($value)
    {
        $value = self::csilRecord($value, 'SignedUserInfoRequest', array('request', 'signing_key_id', 'signature'));
        return new SignedUserInfoRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'signing_key_id' => array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
            'public_keys' => array_key_exists('public_keys', $value) ? array_map(function ($item) { return self::fromCborDomainPublicKey($item); }, self::csilList($value['public_keys'])) : null,
        ));
    }

    public static function encodeUserInfo($value)
    {
        return CBOR::encode(self::toCborUserInfo($value));
    }

    public static function decodeUserInfo($bytes)
    {
        return self::fromCborUserInfo(self::csilDecode($bytes));
    }

    public static function toCborUserInfo($value)
    {
        $out = array();
        $field = $value instanceof UserInfo ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof UserInfo ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof UserInfo ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        $out['display_name'] = $field;
        $field = $value instanceof UserInfo ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborUserInfo($value)
    {
        $value = self::csilRecord($value, 'UserInfo', array('user_id', 'domain', 'display_name', 'claims'));
        return new UserInfo(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, self::csilList($value['claims'])) : null,
        ));
    }

    public static function encodeRelyingPartyApplication($value)
    {
        return CBOR::encode(self::toCborRelyingPartyApplication($value));
    }

    public static function decodeRelyingPartyApplication($bytes)
    {
        return self::fromCborRelyingPartyApplication(self::csilDecode($bytes));
    }

    public static function toCborRelyingPartyApplication($value)
    {
        $out = array();
        $field = $value instanceof RelyingPartyApplication ? $value->application : (is_array($value) && array_key_exists('application', $value) ? $value['application'] : null);
        $out['application'] = self::toCborApplicationRef($field);
        $field = $value instanceof RelyingPartyApplication ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        $out['display_name'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRelyingPartyApplication($value)
    {
        $value = self::csilRecord($value, 'RelyingPartyApplication', array('application', 'display_name'));
        return new RelyingPartyApplication(array(
            'application' => array_key_exists('application', $value) ? self::fromCborApplicationRef($value['application']) : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
        ));
    }

    public static function encodeAuthRequest($value)
    {
        return CBOR::encode(self::toCborAuthRequest($value));
    }

    public static function decodeAuthRequest($bytes)
    {
        return self::fromCborAuthRequest(self::csilDecode($bytes));
    }

    public static function toCborAuthRequest($value)
    {
        $out = array();
        $field = $value instanceof AuthRequest ? $value->relyingParty : (is_array($value) && array_key_exists('relying_party', $value) ? $value['relying_party'] : null);
        $out['relying_party'] = $field;
        $field = $value instanceof AuthRequest ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof AuthRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        $field = $value instanceof AuthRequest ? $value->timestamp : (is_array($value) && array_key_exists('timestamp', $value) ? $value['timestamp'] : null);
        $out['timestamp'] = self::timestampToCbor($field);
        $field = $value instanceof AuthRequest ? $value->signingKeyId : (is_array($value) && array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null);
        $out['signing_key_id'] = $field;
        $field = $value instanceof AuthRequest ? $value->requestedClaims : (is_array($value) && array_key_exists('requested_claims', $value) ? $value['requested_claims'] : null);
        if ($field !== null) {
            $out['requested_claims'] = self::toCborClaimRequest($field);
        }
        $field = $value instanceof AuthRequest ? $value->authenticationRequirements : (is_array($value) && array_key_exists('authentication_requirements', $value) ? $value['authentication_requirements'] : null);
        if ($field !== null) {
            $out['authentication_requirements'] = self::toCborAuthenticationRequirements($field);
        }
        $field = $value instanceof AuthRequest ? $value->flowContext : (is_array($value) && array_key_exists('flow_context', $value) ? $value['flow_context'] : null);
        if ($field !== null) {
            $out['flow_context'] = self::toCborAuthFlowContext($field);
        }
        $field = $value instanceof AuthRequest ? $value->relyingPartyClaims : (is_array($value) && array_key_exists('relying_party_claims', $value) ? $value['relying_party_claims'] : null);
        if ($field !== null) {
            $out['relying_party_claims'] = array_map(function ($item) { return self::toCborDomainClaim($item); }, $field === null ? array() : $field);
        }
        $field = $value instanceof AuthRequest ? $value->application : (is_array($value) && array_key_exists('application', $value) ? $value['application'] : null);
        $out['application'] = self::toCborRelyingPartyApplication($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAuthRequest($value)
    {
        $value = self::csilRecord($value, 'AuthRequest', array('relying_party', 'callback_url', 'nonce', 'timestamp', 'signing_key_id', 'application'));
        return new AuthRequest(array(
            'relying_party' => array_key_exists('relying_party', $value) ? $value['relying_party'] : null,
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'timestamp' => array_key_exists('timestamp', $value) ? self::timestampFromCbor($value['timestamp']) : null,
            'signing_key_id' => array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null,
            'requested_claims' => array_key_exists('requested_claims', $value) ? self::fromCborClaimRequest($value['requested_claims']) : null,
            'authentication_requirements' => array_key_exists('authentication_requirements', $value) ? self::fromCborAuthenticationRequirements($value['authentication_requirements']) : null,
            'flow_context' => array_key_exists('flow_context', $value) ? self::fromCborAuthFlowContext($value['flow_context']) : null,
            'relying_party_claims' => array_key_exists('relying_party_claims', $value) ? array_map(function ($item) { return self::fromCborDomainClaim($item); }, self::csilList($value['relying_party_claims'])) : null,
            'application' => array_key_exists('application', $value) ? self::fromCborRelyingPartyApplication($value['application']) : null,
        ));
    }

    public static function encodeSignedAuthRequest($value)
    {
        return CBOR::encode(self::toCborSignedAuthRequest($value));
    }

    public static function decodeSignedAuthRequest($bytes)
    {
        return self::fromCborSignedAuthRequest(self::csilDecode($bytes));
    }

    public static function toCborSignedAuthRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedAuthRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedAuthRequest ? $value->signingKeyId : (is_array($value) && array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null);
        $out['signing_key_id'] = $field;
        $field = $value instanceof SignedAuthRequest ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedAuthRequest($value)
    {
        $value = self::csilRecord($value, 'SignedAuthRequest', array('request', 'signing_key_id', 'signature'));
        return new SignedAuthRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'signing_key_id' => array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeEncryptedToken($value)
    {
        return CBOR::encode(self::toCborEncryptedToken($value));
    }

    public static function decodeEncryptedToken($bytes)
    {
        return self::fromCborEncryptedToken(self::csilDecode($bytes));
    }

    public static function toCborEncryptedToken($value)
    {
        $out = array();
        $field = $value instanceof EncryptedToken ? $value->ephemeralPublicKey : (is_array($value) && array_key_exists('ephemeral_public_key', $value) ? $value['ephemeral_public_key'] : null);
        $out['ephemeral_public_key'] = CBOR::bytes($field);
        $field = $value instanceof EncryptedToken ? $value->ciphertext : (is_array($value) && array_key_exists('ciphertext', $value) ? $value['ciphertext'] : null);
        $out['ciphertext'] = CBOR::bytes($field);
        $field = $value instanceof EncryptedToken ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = CBOR::bytes($field);
        $field = $value instanceof EncryptedToken ? $value->suite : (is_array($value) && array_key_exists('suite', $value) ? $value['suite'] : null);
        if ($field !== null) {
            $out['suite'] = self::toCborAeadSuite($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborEncryptedToken($value)
    {
        $value = self::csilRecord($value, 'EncryptedToken', array('ephemeral_public_key', 'ciphertext', 'nonce'));
        return new EncryptedToken(array(
            'ephemeral_public_key' => array_key_exists('ephemeral_public_key', $value) ? $value['ephemeral_public_key'] : null,
            'ciphertext' => array_key_exists('ciphertext', $value) ? $value['ciphertext'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'suite' => array_key_exists('suite', $value) ? self::fromCborAeadSuite($value['suite']) : null,
        ));
    }

    public static function encodeAlgorithmSupport($value)
    {
        return CBOR::encode(self::toCborAlgorithmSupport($value));
    }

    public static function decodeAlgorithmSupport($bytes)
    {
        return self::fromCborAlgorithmSupport(self::csilDecode($bytes));
    }

    public static function toCborAlgorithmSupport($value)
    {
        $out = array();
        $field = $value instanceof AlgorithmSupport ? $value->signing : (is_array($value) && array_key_exists('signing', $value) ? $value['signing'] : null);
        $out['signing'] = array_map(function ($item) { return self::toCborKeyAlgorithm($item); }, $field === null ? array() : $field);
        $field = $value instanceof AlgorithmSupport ? $value->encryption : (is_array($value) && array_key_exists('encryption', $value) ? $value['encryption'] : null);
        if ($field !== null) {
            $out['encryption'] = array_map(function ($item) { return self::toCborAeadSuite($item); }, $field === null ? array() : $field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAlgorithmSupport($value)
    {
        $value = self::csilRecord($value, 'AlgorithmSupport', array('signing'));
        return new AlgorithmSupport(array(
            'signing' => array_key_exists('signing', $value) ? array_map(function ($item) { return self::fromCborKeyAlgorithm($item); }, self::csilList($value['signing'])) : null,
            'encryption' => array_key_exists('encryption', $value) ? array_map(function ($item) { return self::fromCborAeadSuite($item); }, self::csilList($value['encryption'])) : null,
        ));
    }

    public static function encodeHandshakeRequest($value)
    {
        return CBOR::encode(self::toCborHandshakeRequest($value));
    }

    public static function decodeHandshakeRequest($bytes)
    {
        return self::fromCborHandshakeRequest(self::csilDecode($bytes));
    }

    public static function toCborHandshakeRequest($value)
    {
        $out = array();
        $field = $value instanceof HandshakeRequest ? $value->version : (is_array($value) && array_key_exists('version', $value) ? $value['version'] : null);
        $out['version'] = $field;
        $field = $value instanceof HandshakeRequest ? $value->algorithms : (is_array($value) && array_key_exists('algorithms', $value) ? $value['algorithms'] : null);
        $out['algorithms'] = self::toCborAlgorithmSupport($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborHandshakeRequest($value)
    {
        $value = self::csilRecord($value, 'HandshakeRequest', array('version', 'algorithms'));
        return new HandshakeRequest(array(
            'version' => array_key_exists('version', $value) ? $value['version'] : null,
            'algorithms' => array_key_exists('algorithms', $value) ? self::fromCborAlgorithmSupport($value['algorithms']) : null,
        ));
    }

    public static function encodeHandshakeResponse($value)
    {
        return CBOR::encode(self::toCborHandshakeResponse($value));
    }

    public static function decodeHandshakeResponse($bytes)
    {
        return self::fromCborHandshakeResponse(self::csilDecode($bytes));
    }

    public static function toCborHandshakeResponse($value)
    {
        $out = array();
        $field = $value instanceof HandshakeResponse ? $value->version : (is_array($value) && array_key_exists('version', $value) ? $value['version'] : null);
        $out['version'] = $field;
        $field = $value instanceof HandshakeResponse ? $value->algorithms : (is_array($value) && array_key_exists('algorithms', $value) ? $value['algorithms'] : null);
        $out['algorithms'] = self::toCborAlgorithmSupport($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborHandshakeResponse($value)
    {
        $value = self::csilRecord($value, 'HandshakeResponse', array('version', 'algorithms'));
        return new HandshakeResponse(array(
            'version' => array_key_exists('version', $value) ? $value['version'] : null,
            'algorithms' => array_key_exists('algorithms', $value) ? self::fromCborAlgorithmSupport($value['algorithms']) : null,
        ));
    }

    public static function encodeRelation($value)
    {
        return CBOR::encode(self::toCborRelation($value));
    }

    public static function decodeRelation($bytes)
    {
        return self::fromCborRelation(self::csilDecode($bytes));
    }

    public static function toCborRelation($value)
    {
        $out = array();
        $field = $value instanceof Relation ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof Relation ? $value->subjectType : (is_array($value) && array_key_exists('subject_type', $value) ? $value['subject_type'] : null);
        $out['subject_type'] = $field;
        $field = $value instanceof Relation ? $value->subjectId : (is_array($value) && array_key_exists('subject_id', $value) ? $value['subject_id'] : null);
        $out['subject_id'] = $field;
        $field = $value instanceof Relation ? $value->relation : (is_array($value) && array_key_exists('relation', $value) ? $value['relation'] : null);
        $out['relation'] = $field;
        $field = $value instanceof Relation ? $value->objectType : (is_array($value) && array_key_exists('object_type', $value) ? $value['object_type'] : null);
        $out['object_type'] = $field;
        $field = $value instanceof Relation ? $value->objectId : (is_array($value) && array_key_exists('object_id', $value) ? $value['object_id'] : null);
        $out['object_id'] = $field;
        $field = $value instanceof Relation ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = self::timestampToCbor($field);
        $field = $value instanceof Relation ? $value->removedAt : (is_array($value) && array_key_exists('removed_at', $value) ? $value['removed_at'] : null);
        if ($field !== null) {
            $out['removed_at'] = self::timestampToCbor($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRelation($value)
    {
        $value = self::csilRecord($value, 'Relation', array('id', 'subject_type', 'subject_id', 'relation', 'object_type', 'object_id', 'created_at'));
        return new Relation(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'subject_type' => array_key_exists('subject_type', $value) ? $value['subject_type'] : null,
            'subject_id' => array_key_exists('subject_id', $value) ? $value['subject_id'] : null,
            'relation' => array_key_exists('relation', $value) ? $value['relation'] : null,
            'object_type' => array_key_exists('object_type', $value) ? $value['object_type'] : null,
            'object_id' => array_key_exists('object_id', $value) ? $value['object_id'] : null,
            'created_at' => array_key_exists('created_at', $value) ? self::timestampFromCbor($value['created_at']) : null,
            'removed_at' => array_key_exists('removed_at', $value) ? self::timestampFromCbor($value['removed_at']) : null,
        ));
    }

    public static function encodeAdminUser($value)
    {
        return CBOR::encode(self::toCborAdminUser($value));
    }

    public static function decodeAdminUser($bytes)
    {
        return self::fromCborAdminUser(self::csilDecode($bytes));
    }

    public static function toCborAdminUser($value)
    {
        $out = array();
        $field = $value instanceof AdminUser ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof AdminUser ? $value->username : (is_array($value) && array_key_exists('username', $value) ? $value['username'] : null);
        $out['username'] = $field;
        $field = $value instanceof AdminUser ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        $out['display_name'] = $field;
        $field = $value instanceof AdminUser ? $value->kind : (is_array($value) && array_key_exists('kind', $value) ? $value['kind'] : null);
        $out['kind'] = self::toCborAccountKind($field);
        $field = $value instanceof AdminUser ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        if ($field !== null) {
            $out['application_id'] = $field;
        }
        $field = $value instanceof AdminUser ? $value->isActive : (is_array($value) && array_key_exists('is_active', $value) ? $value['is_active'] : null);
        $out['is_active'] = $field;
        $field = $value instanceof AdminUser ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = self::timestampToCbor($field);
        $field = $value instanceof AdminUser ? $value->updatedAt : (is_array($value) && array_key_exists('updated_at', $value) ? $value['updated_at'] : null);
        $out['updated_at'] = self::timestampToCbor($field);
        $field = $value instanceof AdminUser ? $value->purgedAt : (is_array($value) && array_key_exists('purged_at', $value) ? $value['purged_at'] : null);
        if ($field !== null) {
            $out['purged_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof AdminUser ? $value->purgeReason : (is_array($value) && array_key_exists('purge_reason', $value) ? $value['purge_reason'] : null);
        if ($field !== null) {
            $out['purge_reason'] = $field;
        }
        $field = $value instanceof AdminUser ? $value->passwordLocked : (is_array($value) && array_key_exists('password_locked', $value) ? $value['password_locked'] : null);
        if ($field !== null) {
            $out['password_locked'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAdminUser($value)
    {
        $value = self::csilRecord($value, 'AdminUser', array('id', 'username', 'display_name', 'kind', 'is_active', 'created_at', 'updated_at'));
        return new AdminUser(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'username' => array_key_exists('username', $value) ? $value['username'] : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
            'kind' => array_key_exists('kind', $value) ? self::fromCborAccountKind($value['kind']) : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'is_active' => array_key_exists('is_active', $value) ? $value['is_active'] : null,
            'created_at' => array_key_exists('created_at', $value) ? self::timestampFromCbor($value['created_at']) : null,
            'updated_at' => array_key_exists('updated_at', $value) ? self::timestampFromCbor($value['updated_at']) : null,
            'purged_at' => array_key_exists('purged_at', $value) ? self::timestampFromCbor($value['purged_at']) : null,
            'purge_reason' => array_key_exists('purge_reason', $value) ? $value['purge_reason'] : null,
            'password_locked' => array_key_exists('password_locked', $value) ? $value['password_locked'] : null,
        ));
    }

    public static function encodeListUsersRequest($value)
    {
        return CBOR::encode(self::toCborListUsersRequest($value));
    }

    public static function decodeListUsersRequest($bytes)
    {
        return self::fromCborListUsersRequest(self::csilDecode($bytes));
    }

    public static function toCborListUsersRequest($value)
    {
        $out = array();
        $field = $value instanceof ListUsersRequest ? $value->offset : (is_array($value) && array_key_exists('offset', $value) ? $value['offset'] : null);
        if ($field !== null) {
            $out['offset'] = $field;
        }
        $field = $value instanceof ListUsersRequest ? $value->limit : (is_array($value) && array_key_exists('limit', $value) ? $value['limit'] : null);
        if ($field !== null) {
            $out['limit'] = $field;
        }
        $field = $value instanceof ListUsersRequest ? $value->includePurged : (is_array($value) && array_key_exists('include_purged', $value) ? $value['include_purged'] : null);
        if ($field !== null) {
            $out['include_purged'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListUsersRequest($value)
    {
        $value = self::csilRecord($value, 'ListUsersRequest', array());
        return new ListUsersRequest(array(
            'offset' => array_key_exists('offset', $value) ? $value['offset'] : null,
            'limit' => array_key_exists('limit', $value) ? $value['limit'] : null,
            'include_purged' => array_key_exists('include_purged', $value) ? $value['include_purged'] : null,
        ));
    }

    public static function encodeListUsersResponse($value)
    {
        return CBOR::encode(self::toCborListUsersResponse($value));
    }

    public static function decodeListUsersResponse($bytes)
    {
        return self::fromCborListUsersResponse(self::csilDecode($bytes));
    }

    public static function toCborListUsersResponse($value)
    {
        $out = array();
        $field = $value instanceof ListUsersResponse ? $value->users : (is_array($value) && array_key_exists('users', $value) ? $value['users'] : null);
        $out['users'] = array_map(function ($item) { return self::toCborAdminUser($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListUsersResponse($value)
    {
        $value = self::csilRecord($value, 'ListUsersResponse', array('users'));
        return new ListUsersResponse(array(
            'users' => array_key_exists('users', $value) ? array_map(function ($item) { return self::fromCborAdminUser($item); }, self::csilList($value['users'])) : null,
        ));
    }

    public static function encodeGetUserRequest($value)
    {
        return CBOR::encode(self::toCborGetUserRequest($value));
    }

    public static function decodeGetUserRequest($bytes)
    {
        return self::fromCborGetUserRequest(self::csilDecode($bytes));
    }

    public static function toCborGetUserRequest($value)
    {
        $out = array();
        $field = $value instanceof GetUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetUserRequest($value)
    {
        $value = self::csilRecord($value, 'GetUserRequest', array('user_id'));
        return new GetUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeGetUserResponse($value)
    {
        return CBOR::encode(self::toCborGetUserResponse($value));
    }

    public static function decodeGetUserResponse($bytes)
    {
        return self::fromCborGetUserResponse(self::csilDecode($bytes));
    }

    public static function toCborGetUserResponse($value)
    {
        $out = array();
        $field = $value instanceof GetUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetUserResponse($value)
    {
        $value = self::csilRecord($value, 'GetUserResponse', array('user'));
        return new GetUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeUserAuthenticationActivity($value)
    {
        return CBOR::encode(self::toCborUserAuthenticationActivity($value));
    }

    public static function decodeUserAuthenticationActivity($bytes)
    {
        return self::fromCborUserAuthenticationActivity(self::csilDecode($bytes));
    }

    public static function toCborUserAuthenticationActivity($value)
    {
        $out = array();
        $field = $value instanceof UserAuthenticationActivity ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof UserAuthenticationActivity ? $value->lastAuthenticatedAt : (is_array($value) && array_key_exists('last_authenticated_at', $value) ? $value['last_authenticated_at'] : null);
        if ($field !== null) {
            $out['last_authenticated_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof UserAuthenticationActivity ? $value->lastSeenAt : (is_array($value) && array_key_exists('last_seen_at', $value) ? $value['last_seen_at'] : null);
        if ($field !== null) {
            $out['last_seen_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof UserAuthenticationActivity ? $value->successfulAuthenticationCount : (is_array($value) && array_key_exists('successful_authentication_count', $value) ? $value['successful_authentication_count'] : null);
        $out['successful_authentication_count'] = $field;
        $field = $value instanceof UserAuthenticationActivity ? $value->activeBrowserSessionCount : (is_array($value) && array_key_exists('active_browser_session_count', $value) ? $value['active_browser_session_count'] : null);
        $out['active_browser_session_count'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborUserAuthenticationActivity($value)
    {
        $value = self::csilRecord($value, 'UserAuthenticationActivity', array('user_id', 'successful_authentication_count', 'active_browser_session_count'));
        return new UserAuthenticationActivity(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'last_authenticated_at' => array_key_exists('last_authenticated_at', $value) ? self::timestampFromCbor($value['last_authenticated_at']) : null,
            'last_seen_at' => array_key_exists('last_seen_at', $value) ? self::timestampFromCbor($value['last_seen_at']) : null,
            'successful_authentication_count' => array_key_exists('successful_authentication_count', $value) ? $value['successful_authentication_count'] : null,
            'active_browser_session_count' => array_key_exists('active_browser_session_count', $value) ? $value['active_browser_session_count'] : null,
        ));
    }

    public static function encodeGetUserAuthenticationActivityRequest($value)
    {
        return CBOR::encode(self::toCborGetUserAuthenticationActivityRequest($value));
    }

    public static function decodeGetUserAuthenticationActivityRequest($bytes)
    {
        return self::fromCborGetUserAuthenticationActivityRequest(self::csilDecode($bytes));
    }

    public static function toCborGetUserAuthenticationActivityRequest($value)
    {
        $out = array();
        $field = $value instanceof GetUserAuthenticationActivityRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetUserAuthenticationActivityRequest($value)
    {
        $value = self::csilRecord($value, 'GetUserAuthenticationActivityRequest', array('user_id'));
        return new GetUserAuthenticationActivityRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeGetUserAuthenticationActivityResponse($value)
    {
        return CBOR::encode(self::toCborGetUserAuthenticationActivityResponse($value));
    }

    public static function decodeGetUserAuthenticationActivityResponse($bytes)
    {
        return self::fromCborGetUserAuthenticationActivityResponse(self::csilDecode($bytes));
    }

    public static function toCborGetUserAuthenticationActivityResponse($value)
    {
        $out = array();
        $field = $value instanceof GetUserAuthenticationActivityResponse ? $value->activity : (is_array($value) && array_key_exists('activity', $value) ? $value['activity'] : null);
        $out['activity'] = self::toCborUserAuthenticationActivity($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetUserAuthenticationActivityResponse($value)
    {
        $value = self::csilRecord($value, 'GetUserAuthenticationActivityResponse', array('activity'));
        return new GetUserAuthenticationActivityResponse(array(
            'activity' => array_key_exists('activity', $value) ? self::fromCborUserAuthenticationActivity($value['activity']) : null,
        ));
    }

    public static function encodeCreateUserRequest($value)
    {
        return CBOR::encode(self::toCborCreateUserRequest($value));
    }

    public static function decodeCreateUserRequest($bytes)
    {
        return self::fromCborCreateUserRequest(self::csilDecode($bytes));
    }

    public static function toCborCreateUserRequest($value)
    {
        $out = array();
        $field = $value instanceof CreateUserRequest ? $value->username : (is_array($value) && array_key_exists('username', $value) ? $value['username'] : null);
        $out['username'] = $field;
        $field = $value instanceof CreateUserRequest ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        $out['display_name'] = $field;
        $field = $value instanceof CreateUserRequest ? $value->password : (is_array($value) && array_key_exists('password', $value) ? $value['password'] : null);
        if ($field !== null) {
            $out['password'] = $field;
        }
        $field = $value instanceof CreateUserRequest ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        if ($field !== null) {
            $out['application_id'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCreateUserRequest($value)
    {
        $value = self::csilRecord($value, 'CreateUserRequest', array('username', 'display_name'));
        return new CreateUserRequest(array(
            'username' => array_key_exists('username', $value) ? $value['username'] : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
            'password' => array_key_exists('password', $value) ? $value['password'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
        ));
    }

    public static function encodeCreateUserResponse($value)
    {
        return CBOR::encode(self::toCborCreateUserResponse($value));
    }

    public static function decodeCreateUserResponse($bytes)
    {
        return self::fromCborCreateUserResponse(self::csilDecode($bytes));
    }

    public static function toCborCreateUserResponse($value)
    {
        $out = array();
        $field = $value instanceof CreateUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        $field = $value instanceof CreateUserResponse ? $value->apiKey : (is_array($value) && array_key_exists('api_key', $value) ? $value['api_key'] : null);
        if ($field !== null) {
            $out['api_key'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCreateUserResponse($value)
    {
        $value = self::csilRecord($value, 'CreateUserResponse', array('user'));
        return new CreateUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
            'api_key' => array_key_exists('api_key', $value) ? $value['api_key'] : null,
        ));
    }

    public static function encodeRenameUserRequest($value)
    {
        return CBOR::encode(self::toCborRenameUserRequest($value));
    }

    public static function decodeRenameUserRequest($bytes)
    {
        return self::fromCborRenameUserRequest(self::csilDecode($bytes));
    }

    public static function toCborRenameUserRequest($value)
    {
        $out = array();
        $field = $value instanceof RenameUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof RenameUserRequest ? $value->username : (is_array($value) && array_key_exists('username', $value) ? $value['username'] : null);
        $out['username'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRenameUserRequest($value)
    {
        $value = self::csilRecord($value, 'RenameUserRequest', array('user_id', 'username'));
        return new RenameUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'username' => array_key_exists('username', $value) ? $value['username'] : null,
        ));
    }

    public static function encodeRenameUserResponse($value)
    {
        return CBOR::encode(self::toCborRenameUserResponse($value));
    }

    public static function decodeRenameUserResponse($bytes)
    {
        return self::fromCborRenameUserResponse(self::csilDecode($bytes));
    }

    public static function toCborRenameUserResponse($value)
    {
        $out = array();
        $field = $value instanceof RenameUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRenameUserResponse($value)
    {
        $value = self::csilRecord($value, 'RenameUserResponse', array('user'));
        return new RenameUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeSetApplicationIdRequest($value)
    {
        return CBOR::encode(self::toCborSetApplicationIdRequest($value));
    }

    public static function decodeSetApplicationIdRequest($bytes)
    {
        return self::fromCborSetApplicationIdRequest(self::csilDecode($bytes));
    }

    public static function toCborSetApplicationIdRequest($value)
    {
        $out = array();
        $field = $value instanceof SetApplicationIdRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof SetApplicationIdRequest ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetApplicationIdRequest($value)
    {
        $value = self::csilRecord($value, 'SetApplicationIdRequest', array('user_id', 'application_id'));
        return new SetApplicationIdRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
        ));
    }

    public static function encodeSetApplicationIdResponse($value)
    {
        return CBOR::encode(self::toCborSetApplicationIdResponse($value));
    }

    public static function decodeSetApplicationIdResponse($bytes)
    {
        return self::fromCborSetApplicationIdResponse(self::csilDecode($bytes));
    }

    public static function toCborSetApplicationIdResponse($value)
    {
        $out = array();
        $field = $value instanceof SetApplicationIdResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetApplicationIdResponse($value)
    {
        $value = self::csilRecord($value, 'SetApplicationIdResponse', array('user'));
        return new SetApplicationIdResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeApiKeyInfo($value)
    {
        return CBOR::encode(self::toCborApiKeyInfo($value));
    }

    public static function decodeApiKeyInfo($bytes)
    {
        return self::fromCborApiKeyInfo(self::csilDecode($bytes));
    }

    public static function toCborApiKeyInfo($value)
    {
        $out = array();
        $field = $value instanceof ApiKeyInfo ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof ApiKeyInfo ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        $out['name'] = $field;
        $field = $value instanceof ApiKeyInfo ? $value->hint : (is_array($value) && array_key_exists('hint', $value) ? $value['hint'] : null);
        $out['hint'] = $field;
        $field = $value instanceof ApiKeyInfo ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = self::timestampToCbor($field);
        $field = $value instanceof ApiKeyInfo ? $value->lastUsedAt : (is_array($value) && array_key_exists('last_used_at', $value) ? $value['last_used_at'] : null);
        if ($field !== null) {
            $out['last_used_at'] = self::timestampToCbor($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApiKeyInfo($value)
    {
        $value = self::csilRecord($value, 'ApiKeyInfo', array('key_id', 'name', 'hint', 'created_at'));
        return new ApiKeyInfo(array(
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
            'hint' => array_key_exists('hint', $value) ? $value['hint'] : null,
            'created_at' => array_key_exists('created_at', $value) ? self::timestampFromCbor($value['created_at']) : null,
            'last_used_at' => array_key_exists('last_used_at', $value) ? self::timestampFromCbor($value['last_used_at']) : null,
        ));
    }

    public static function encodeCreateApiKeyRequest($value)
    {
        return CBOR::encode(self::toCborCreateApiKeyRequest($value));
    }

    public static function decodeCreateApiKeyRequest($bytes)
    {
        return self::fromCborCreateApiKeyRequest(self::csilDecode($bytes));
    }

    public static function toCborCreateApiKeyRequest($value)
    {
        $out = array();
        $field = $value instanceof CreateApiKeyRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof CreateApiKeyRequest ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        $out['name'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCreateApiKeyRequest($value)
    {
        $value = self::csilRecord($value, 'CreateApiKeyRequest', array('user_id', 'name'));
        return new CreateApiKeyRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
        ));
    }

    public static function encodeCreateApiKeyResponse($value)
    {
        return CBOR::encode(self::toCborCreateApiKeyResponse($value));
    }

    public static function decodeCreateApiKeyResponse($bytes)
    {
        return self::fromCborCreateApiKeyResponse(self::csilDecode($bytes));
    }

    public static function toCborCreateApiKeyResponse($value)
    {
        $out = array();
        $field = $value instanceof CreateApiKeyResponse ? $value->key : (is_array($value) && array_key_exists('key', $value) ? $value['key'] : null);
        $out['key'] = self::toCborApiKeyInfo($field);
        $field = $value instanceof CreateApiKeyResponse ? $value->apiKey : (is_array($value) && array_key_exists('api_key', $value) ? $value['api_key'] : null);
        $out['api_key'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCreateApiKeyResponse($value)
    {
        $value = self::csilRecord($value, 'CreateApiKeyResponse', array('key', 'api_key'));
        return new CreateApiKeyResponse(array(
            'key' => array_key_exists('key', $value) ? self::fromCborApiKeyInfo($value['key']) : null,
            'api_key' => array_key_exists('api_key', $value) ? $value['api_key'] : null,
        ));
    }

    public static function encodeListApiKeysRequest($value)
    {
        return CBOR::encode(self::toCborListApiKeysRequest($value));
    }

    public static function decodeListApiKeysRequest($bytes)
    {
        return self::fromCborListApiKeysRequest(self::csilDecode($bytes));
    }

    public static function toCborListApiKeysRequest($value)
    {
        $out = array();
        $field = $value instanceof ListApiKeysRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListApiKeysRequest($value)
    {
        $value = self::csilRecord($value, 'ListApiKeysRequest', array('user_id'));
        return new ListApiKeysRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeListApiKeysResponse($value)
    {
        return CBOR::encode(self::toCborListApiKeysResponse($value));
    }

    public static function decodeListApiKeysResponse($bytes)
    {
        return self::fromCborListApiKeysResponse(self::csilDecode($bytes));
    }

    public static function toCborListApiKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof ListApiKeysResponse ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborApiKeyInfo($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListApiKeysResponse($value)
    {
        $value = self::csilRecord($value, 'ListApiKeysResponse', array('keys'));
        return new ListApiKeysResponse(array(
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborApiKeyInfo($item); }, self::csilList($value['keys'])) : null,
        ));
    }

    public static function encodeRevokeApiKeyRequest($value)
    {
        return CBOR::encode(self::toCborRevokeApiKeyRequest($value));
    }

    public static function decodeRevokeApiKeyRequest($bytes)
    {
        return self::fromCborRevokeApiKeyRequest(self::csilDecode($bytes));
    }

    public static function toCborRevokeApiKeyRequest($value)
    {
        $out = array();
        $field = $value instanceof RevokeApiKeyRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof RevokeApiKeyRequest ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeApiKeyRequest($value)
    {
        $value = self::csilRecord($value, 'RevokeApiKeyRequest', array('user_id', 'key_id'));
        return new RevokeApiKeyRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
        ));
    }

    public static function encodeRevokeApiKeyResponse($value)
    {
        return CBOR::encode(self::toCborRevokeApiKeyResponse($value));
    }

    public static function decodeRevokeApiKeyResponse($bytes)
    {
        return self::fromCborRevokeApiKeyResponse(self::csilDecode($bytes));
    }

    public static function toCborRevokeApiKeyResponse($value)
    {
        $out = array();
        $field = $value instanceof RevokeApiKeyResponse ? $value->revoked : (is_array($value) && array_key_exists('revoked', $value) ? $value['revoked'] : null);
        $out['revoked'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeApiKeyResponse($value)
    {
        $value = self::csilRecord($value, 'RevokeApiKeyResponse', array('revoked'));
        return new RevokeApiKeyResponse(array(
            'revoked' => array_key_exists('revoked', $value) ? $value['revoked'] : null,
        ));
    }

    public static function encodeAccountLimits($value)
    {
        return CBOR::encode(self::toCborAccountLimits($value));
    }

    public static function decodeAccountLimits($bytes)
    {
        return self::fromCborAccountLimits(self::csilDecode($bytes));
    }

    public static function toCborAccountLimits($value)
    {
        $out = array();
        $field = $value instanceof AccountLimits ? $value->maxApiKeys : (is_array($value) && array_key_exists('max_api_keys', $value) ? $value['max_api_keys'] : null);
        if ($field !== null) {
            $out['max_api_keys'] = $field;
        }
        $field = $value instanceof AccountLimits ? $value->maxDistinctUsers : (is_array($value) && array_key_exists('max_distinct_users', $value) ? $value['max_distinct_users'] : null);
        if ($field !== null) {
            $out['max_distinct_users'] = $field;
        }
        $field = $value instanceof AccountLimits ? $value->distinctUserWindowDays : (is_array($value) && array_key_exists('distinct_user_window_days', $value) ? $value['distinct_user_window_days'] : null);
        $out['distinct_user_window_days'] = $field;
        $field = $value instanceof AccountLimits ? $value->requestsPerMinute : (is_array($value) && array_key_exists('requests_per_minute', $value) ? $value['requests_per_minute'] : null);
        if ($field !== null) {
            $out['requests_per_minute'] = $field;
        }
        $field = $value instanceof AccountLimits ? $value->requestBurst : (is_array($value) && array_key_exists('request_burst', $value) ? $value['request_burst'] : null);
        if ($field !== null) {
            $out['request_burst'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAccountLimits($value)
    {
        $value = self::csilRecord($value, 'AccountLimits', array('distinct_user_window_days'));
        return new AccountLimits(array(
            'max_api_keys' => array_key_exists('max_api_keys', $value) ? $value['max_api_keys'] : null,
            'max_distinct_users' => array_key_exists('max_distinct_users', $value) ? $value['max_distinct_users'] : null,
            'distinct_user_window_days' => array_key_exists('distinct_user_window_days', $value) ? $value['distinct_user_window_days'] : null,
            'requests_per_minute' => array_key_exists('requests_per_minute', $value) ? $value['requests_per_minute'] : null,
            'request_burst' => array_key_exists('request_burst', $value) ? $value['request_burst'] : null,
        ));
    }

    public static function encodeGetAccountLimitsRequest($value)
    {
        return CBOR::encode(self::toCborGetAccountLimitsRequest($value));
    }

    public static function decodeGetAccountLimitsRequest($bytes)
    {
        return self::fromCborGetAccountLimitsRequest(self::csilDecode($bytes));
    }

    public static function toCborGetAccountLimitsRequest($value)
    {
        $out = array();
        $field = $value instanceof GetAccountLimitsRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetAccountLimitsRequest($value)
    {
        $value = self::csilRecord($value, 'GetAccountLimitsRequest', array('user_id'));
        return new GetAccountLimitsRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeGetAccountLimitsResponse($value)
    {
        return CBOR::encode(self::toCborGetAccountLimitsResponse($value));
    }

    public static function decodeGetAccountLimitsResponse($bytes)
    {
        return self::fromCborGetAccountLimitsResponse(self::csilDecode($bytes));
    }

    public static function toCborGetAccountLimitsResponse($value)
    {
        $out = array();
        $field = $value instanceof GetAccountLimitsResponse ? $value->limits : (is_array($value) && array_key_exists('limits', $value) ? $value['limits'] : null);
        $out['limits'] = self::toCborAccountLimits($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetAccountLimitsResponse($value)
    {
        $value = self::csilRecord($value, 'GetAccountLimitsResponse', array('limits'));
        return new GetAccountLimitsResponse(array(
            'limits' => array_key_exists('limits', $value) ? self::fromCborAccountLimits($value['limits']) : null,
        ));
    }

    public static function encodeSetAccountLimitsRequest($value)
    {
        return CBOR::encode(self::toCborSetAccountLimitsRequest($value));
    }

    public static function decodeSetAccountLimitsRequest($bytes)
    {
        return self::fromCborSetAccountLimitsRequest(self::csilDecode($bytes));
    }

    public static function toCborSetAccountLimitsRequest($value)
    {
        $out = array();
        $field = $value instanceof SetAccountLimitsRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof SetAccountLimitsRequest ? $value->limits : (is_array($value) && array_key_exists('limits', $value) ? $value['limits'] : null);
        $out['limits'] = self::toCborAccountLimits($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetAccountLimitsRequest($value)
    {
        $value = self::csilRecord($value, 'SetAccountLimitsRequest', array('user_id', 'limits'));
        return new SetAccountLimitsRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'limits' => array_key_exists('limits', $value) ? self::fromCborAccountLimits($value['limits']) : null,
        ));
    }

    public static function encodeSetAccountLimitsResponse($value)
    {
        return CBOR::encode(self::toCborSetAccountLimitsResponse($value));
    }

    public static function decodeSetAccountLimitsResponse($bytes)
    {
        return self::fromCborSetAccountLimitsResponse(self::csilDecode($bytes));
    }

    public static function toCborSetAccountLimitsResponse($value)
    {
        $out = array();
        $field = $value instanceof SetAccountLimitsResponse ? $value->limits : (is_array($value) && array_key_exists('limits', $value) ? $value['limits'] : null);
        $out['limits'] = self::toCborAccountLimits($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetAccountLimitsResponse($value)
    {
        $value = self::csilRecord($value, 'SetAccountLimitsResponse', array('limits'));
        return new SetAccountLimitsResponse(array(
            'limits' => array_key_exists('limits', $value) ? self::fromCborAccountLimits($value['limits']) : null,
        ));
    }

    public static function encodeRpUsageDay($value)
    {
        return CBOR::encode(self::toCborRpUsageDay($value));
    }

    public static function decodeRpUsageDay($bytes)
    {
        return self::fromCborRpUsageDay(self::csilDecode($bytes));
    }

    public static function toCborRpUsageDay($value)
    {
        $out = array();
        $field = $value instanceof RpUsageDay ? $value->day : (is_array($value) && array_key_exists('day', $value) ? $value['day'] : null);
        $out['day'] = new \Csilgen\Transport\Tag(1004, self::calendarDate($field));
        $field = $value instanceof RpUsageDay ? $value->operation : (is_array($value) && array_key_exists('operation', $value) ? $value['operation'] : null);
        $out['operation'] = $field;
        $field = $value instanceof RpUsageDay ? $value->succeeded : (is_array($value) && array_key_exists('succeeded', $value) ? $value['succeeded'] : null);
        $out['succeeded'] = $field;
        $field = $value instanceof RpUsageDay ? $value->failed : (is_array($value) && array_key_exists('failed', $value) ? $value['failed'] : null);
        $out['failed'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpUsageDay($value)
    {
        $value = self::csilRecord($value, 'RpUsageDay', array('day', 'operation', 'succeeded', 'failed'));
        return new RpUsageDay(array(
            'day' => array_key_exists('day', $value) ? self::readDate($value['day']) : null,
            'operation' => array_key_exists('operation', $value) ? $value['operation'] : null,
            'succeeded' => array_key_exists('succeeded', $value) ? $value['succeeded'] : null,
            'failed' => array_key_exists('failed', $value) ? $value['failed'] : null,
        ));
    }

    public static function encodeGetApplicationUsageRequest($value)
    {
        return CBOR::encode(self::toCborGetApplicationUsageRequest($value));
    }

    public static function decodeGetApplicationUsageRequest($bytes)
    {
        return self::fromCborGetApplicationUsageRequest(self::csilDecode($bytes));
    }

    public static function toCborGetApplicationUsageRequest($value)
    {
        $out = array();
        $field = $value instanceof GetApplicationUsageRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof GetApplicationUsageRequest ? $value->firstDay : (is_array($value) && array_key_exists('first_day', $value) ? $value['first_day'] : null);
        $out['first_day'] = new \Csilgen\Transport\Tag(1004, self::calendarDate($field));
        $field = $value instanceof GetApplicationUsageRequest ? $value->lastDay : (is_array($value) && array_key_exists('last_day', $value) ? $value['last_day'] : null);
        $out['last_day'] = new \Csilgen\Transport\Tag(1004, self::calendarDate($field));
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetApplicationUsageRequest($value)
    {
        $value = self::csilRecord($value, 'GetApplicationUsageRequest', array('user_id', 'first_day', 'last_day'));
        return new GetApplicationUsageRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'first_day' => array_key_exists('first_day', $value) ? self::readDate($value['first_day']) : null,
            'last_day' => array_key_exists('last_day', $value) ? self::readDate($value['last_day']) : null,
        ));
    }

    public static function encodeGetApplicationUsageResponse($value)
    {
        return CBOR::encode(self::toCborGetApplicationUsageResponse($value));
    }

    public static function decodeGetApplicationUsageResponse($bytes)
    {
        return self::fromCborGetApplicationUsageResponse(self::csilDecode($bytes));
    }

    public static function toCborGetApplicationUsageResponse($value)
    {
        $out = array();
        $field = $value instanceof GetApplicationUsageResponse ? $value->distinctUsers : (is_array($value) && array_key_exists('distinct_users', $value) ? $value['distinct_users'] : null);
        $out['distinct_users'] = $field;
        $field = $value instanceof GetApplicationUsageResponse ? $value->distinctUserWindowDays : (is_array($value) && array_key_exists('distinct_user_window_days', $value) ? $value['distinct_user_window_days'] : null);
        $out['distinct_user_window_days'] = $field;
        $field = $value instanceof GetApplicationUsageResponse ? $value->maxDistinctUsers : (is_array($value) && array_key_exists('max_distinct_users', $value) ? $value['max_distinct_users'] : null);
        if ($field !== null) {
            $out['max_distinct_users'] = $field;
        }
        $field = $value instanceof GetApplicationUsageResponse ? $value->days : (is_array($value) && array_key_exists('days', $value) ? $value['days'] : null);
        $out['days'] = array_map(function ($item) { return self::toCborRpUsageDay($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetApplicationUsageResponse($value)
    {
        $value = self::csilRecord($value, 'GetApplicationUsageResponse', array('distinct_users', 'distinct_user_window_days', 'days'));
        return new GetApplicationUsageResponse(array(
            'distinct_users' => array_key_exists('distinct_users', $value) ? $value['distinct_users'] : null,
            'distinct_user_window_days' => array_key_exists('distinct_user_window_days', $value) ? $value['distinct_user_window_days'] : null,
            'max_distinct_users' => array_key_exists('max_distinct_users', $value) ? $value['max_distinct_users'] : null,
            'days' => array_key_exists('days', $value) ? array_map(function ($item) { return self::fromCborRpUsageDay($item); }, self::csilList($value['days'])) : null,
        ));
    }

    public static function encodeUpdateUserRequest($value)
    {
        return CBOR::encode(self::toCborUpdateUserRequest($value));
    }

    public static function decodeUpdateUserRequest($bytes)
    {
        return self::fromCborUpdateUserRequest(self::csilDecode($bytes));
    }

    public static function toCborUpdateUserRequest($value)
    {
        $out = array();
        $field = $value instanceof UpdateUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof UpdateUserRequest ? $value->displayName : (is_array($value) && array_key_exists('display_name', $value) ? $value['display_name'] : null);
        if ($field !== null) {
            $out['display_name'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborUpdateUserRequest($value)
    {
        $value = self::csilRecord($value, 'UpdateUserRequest', array('user_id'));
        return new UpdateUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'display_name' => array_key_exists('display_name', $value) ? $value['display_name'] : null,
        ));
    }

    public static function encodeUpdateUserResponse($value)
    {
        return CBOR::encode(self::toCborUpdateUserResponse($value));
    }

    public static function decodeUpdateUserResponse($bytes)
    {
        return self::fromCborUpdateUserResponse(self::csilDecode($bytes));
    }

    public static function toCborUpdateUserResponse($value)
    {
        $out = array();
        $field = $value instanceof UpdateUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborUpdateUserResponse($value)
    {
        $value = self::csilRecord($value, 'UpdateUserResponse', array('user'));
        return new UpdateUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeDeactivateUserRequest($value)
    {
        return CBOR::encode(self::toCborDeactivateUserRequest($value));
    }

    public static function decodeDeactivateUserRequest($bytes)
    {
        return self::fromCborDeactivateUserRequest(self::csilDecode($bytes));
    }

    public static function toCborDeactivateUserRequest($value)
    {
        $out = array();
        $field = $value instanceof DeactivateUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborDeactivateUserRequest($value)
    {
        $value = self::csilRecord($value, 'DeactivateUserRequest', array('user_id'));
        return new DeactivateUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeDeactivateUserResponse($value)
    {
        return CBOR::encode(self::toCborDeactivateUserResponse($value));
    }

    public static function decodeDeactivateUserResponse($bytes)
    {
        return self::fromCborDeactivateUserResponse(self::csilDecode($bytes));
    }

    public static function toCborDeactivateUserResponse($value)
    {
        $out = array();
        $field = $value instanceof DeactivateUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborDeactivateUserResponse($value)
    {
        $value = self::csilRecord($value, 'DeactivateUserResponse', array('user'));
        return new DeactivateUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeActivateUserRequest($value)
    {
        return CBOR::encode(self::toCborActivateUserRequest($value));
    }

    public static function decodeActivateUserRequest($bytes)
    {
        return self::fromCborActivateUserRequest(self::csilDecode($bytes));
    }

    public static function toCborActivateUserRequest($value)
    {
        $out = array();
        $field = $value instanceof ActivateUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActivateUserRequest($value)
    {
        $value = self::csilRecord($value, 'ActivateUserRequest', array('user_id'));
        return new ActivateUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeActivateUserResponse($value)
    {
        return CBOR::encode(self::toCborActivateUserResponse($value));
    }

    public static function decodeActivateUserResponse($bytes)
    {
        return self::fromCborActivateUserResponse(self::csilDecode($bytes));
    }

    public static function toCborActivateUserResponse($value)
    {
        $out = array();
        $field = $value instanceof ActivateUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActivateUserResponse($value)
    {
        $value = self::csilRecord($value, 'ActivateUserResponse', array('user'));
        return new ActivateUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodePurgeUserRequest($value)
    {
        return CBOR::encode(self::toCborPurgeUserRequest($value));
    }

    public static function decodePurgeUserRequest($bytes)
    {
        return self::fromCborPurgeUserRequest(self::csilDecode($bytes));
    }

    public static function toCborPurgeUserRequest($value)
    {
        $out = array();
        $field = $value instanceof PurgeUserRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof PurgeUserRequest ? $value->reason : (is_array($value) && array_key_exists('reason', $value) ? $value['reason'] : null);
        if ($field !== null) {
            $out['reason'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPurgeUserRequest($value)
    {
        $value = self::csilRecord($value, 'PurgeUserRequest', array('user_id'));
        return new PurgeUserRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'reason' => array_key_exists('reason', $value) ? $value['reason'] : null,
        ));
    }

    public static function encodePurgeUserResponse($value)
    {
        return CBOR::encode(self::toCborPurgeUserResponse($value));
    }

    public static function decodePurgeUserResponse($bytes)
    {
        return self::fromCborPurgeUserResponse(self::csilDecode($bytes));
    }

    public static function toCborPurgeUserResponse($value)
    {
        $out = array();
        $field = $value instanceof PurgeUserResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        $field = $value instanceof PurgeUserResponse ? $value->credentialsRevoked : (is_array($value) && array_key_exists('credentials_revoked', $value) ? $value['credentials_revoked'] : null);
        $out['credentials_revoked'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->keysRevoked : (is_array($value) && array_key_exists('keys_revoked', $value) ? $value['keys_revoked'] : null);
        $out['keys_revoked'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->claimsRevoked : (is_array($value) && array_key_exists('claims_revoked', $value) ? $value['claims_revoked'] : null);
        $out['claims_revoked'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->relationsRemoved : (is_array($value) && array_key_exists('relations_removed', $value) ? $value['relations_removed'] : null);
        $out['relations_removed'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->profilesDeleted : (is_array($value) && array_key_exists('profiles_deleted', $value) ? $value['profiles_deleted'] : null);
        $out['profiles_deleted'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->consentGrantsDeleted : (is_array($value) && array_key_exists('consent_grants_deleted', $value) ? $value['consent_grants_deleted'] : null);
        $out['consent_grants_deleted'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->releasePrefsDeleted : (is_array($value) && array_key_exists('release_prefs_deleted', $value) ? $value['release_prefs_deleted'] : null);
        $out['release_prefs_deleted'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->emailVerificationsDeleted : (is_array($value) && array_key_exists('email_verifications_deleted', $value) ? $value['email_verifications_deleted'] : null);
        $out['email_verifications_deleted'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->reviewsResolved : (is_array($value) && array_key_exists('reviews_resolved', $value) ? $value['reviews_resolved'] : null);
        $out['reviews_resolved'] = $field;
        $field = $value instanceof PurgeUserResponse ? $value->localRpClaimTicketsDeleted : (is_array($value) && array_key_exists('local_rp_claim_tickets_deleted', $value) ? $value['local_rp_claim_tickets_deleted'] : null);
        $out['local_rp_claim_tickets_deleted'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPurgeUserResponse($value)
    {
        $value = self::csilRecord($value, 'PurgeUserResponse', array('user', 'credentials_revoked', 'keys_revoked', 'claims_revoked', 'relations_removed', 'profiles_deleted', 'consent_grants_deleted', 'release_prefs_deleted', 'email_verifications_deleted', 'reviews_resolved', 'local_rp_claim_tickets_deleted'));
        return new PurgeUserResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
            'credentials_revoked' => array_key_exists('credentials_revoked', $value) ? $value['credentials_revoked'] : null,
            'keys_revoked' => array_key_exists('keys_revoked', $value) ? $value['keys_revoked'] : null,
            'claims_revoked' => array_key_exists('claims_revoked', $value) ? $value['claims_revoked'] : null,
            'relations_removed' => array_key_exists('relations_removed', $value) ? $value['relations_removed'] : null,
            'profiles_deleted' => array_key_exists('profiles_deleted', $value) ? $value['profiles_deleted'] : null,
            'consent_grants_deleted' => array_key_exists('consent_grants_deleted', $value) ? $value['consent_grants_deleted'] : null,
            'release_prefs_deleted' => array_key_exists('release_prefs_deleted', $value) ? $value['release_prefs_deleted'] : null,
            'email_verifications_deleted' => array_key_exists('email_verifications_deleted', $value) ? $value['email_verifications_deleted'] : null,
            'reviews_resolved' => array_key_exists('reviews_resolved', $value) ? $value['reviews_resolved'] : null,
            'local_rp_claim_tickets_deleted' => array_key_exists('local_rp_claim_tickets_deleted', $value) ? $value['local_rp_claim_tickets_deleted'] : null,
        ));
    }

    public static function encodeRevokeDomainKeyRequest($value)
    {
        return CBOR::encode(self::toCborRevokeDomainKeyRequest($value));
    }

    public static function decodeRevokeDomainKeyRequest($bytes)
    {
        return self::fromCborRevokeDomainKeyRequest(self::csilDecode($bytes));
    }

    public static function toCborRevokeDomainKeyRequest($value)
    {
        $out = array();
        $field = $value instanceof RevokeDomainKeyRequest ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeDomainKeyRequest($value)
    {
        $value = self::csilRecord($value, 'RevokeDomainKeyRequest', array('key_id'));
        return new RevokeDomainKeyRequest(array(
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
        ));
    }

    public static function encodeRevokeDomainKeyResponse($value)
    {
        return CBOR::encode(self::toCborRevokeDomainKeyResponse($value));
    }

    public static function decodeRevokeDomainKeyResponse($bytes)
    {
        return self::fromCborRevokeDomainKeyResponse(self::csilDecode($bytes));
    }

    public static function toCborRevokeDomainKeyResponse($value)
    {
        $out = array();
        $field = $value instanceof RevokeDomainKeyResponse ? $value->revokedKey : (is_array($value) && array_key_exists('revoked_key', $value) ? $value['revoked_key'] : null);
        $out['revoked_key'] = self::toCborDomainPublicKey($field);
        $field = $value instanceof RevokeDomainKeyResponse ? $value->certificateIssued : (is_array($value) && array_key_exists('certificate_issued', $value) ? $value['certificate_issued'] : null);
        $out['certificate_issued'] = $field;
        $field = $value instanceof RevokeDomainKeyResponse ? $value->dnsRemovalReminder : (is_array($value) && array_key_exists('dns_removal_reminder', $value) ? $value['dns_removal_reminder'] : null);
        $out['dns_removal_reminder'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeDomainKeyResponse($value)
    {
        $value = self::csilRecord($value, 'RevokeDomainKeyResponse', array('revoked_key', 'certificate_issued', 'dns_removal_reminder'));
        return new RevokeDomainKeyResponse(array(
            'revoked_key' => array_key_exists('revoked_key', $value) ? self::fromCborDomainPublicKey($value['revoked_key']) : null,
            'certificate_issued' => array_key_exists('certificate_issued', $value) ? $value['certificate_issued'] : null,
            'dns_removal_reminder' => array_key_exists('dns_removal_reminder', $value) ? $value['dns_removal_reminder'] : null,
        ));
    }

    public static function encodeResetPasswordRequest($value)
    {
        return CBOR::encode(self::toCborResetPasswordRequest($value));
    }

    public static function decodeResetPasswordRequest($bytes)
    {
        return self::fromCborResetPasswordRequest(self::csilDecode($bytes));
    }

    public static function toCborResetPasswordRequest($value)
    {
        $out = array();
        $field = $value instanceof ResetPasswordRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof ResetPasswordRequest ? $value->newPassword : (is_array($value) && array_key_exists('new_password', $value) ? $value['new_password'] : null);
        $out['new_password'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborResetPasswordRequest($value)
    {
        $value = self::csilRecord($value, 'ResetPasswordRequest', array('user_id', 'new_password'));
        return new ResetPasswordRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'new_password' => array_key_exists('new_password', $value) ? $value['new_password'] : null,
        ));
    }

    public static function encodeResetPasswordResponse($value)
    {
        return CBOR::encode(self::toCborResetPasswordResponse($value));
    }

    public static function decodeResetPasswordResponse($bytes)
    {
        return self::fromCborResetPasswordResponse(self::csilDecode($bytes));
    }

    public static function toCborResetPasswordResponse($value)
    {
        $out = array();
        $field = $value instanceof ResetPasswordResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborResetPasswordResponse($value)
    {
        $value = self::csilRecord($value, 'ResetPasswordResponse', array('success'));
        return new ResetPasswordResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeAuthenticateRequest($value)
    {
        return CBOR::encode(self::toCborAuthenticateRequest($value));
    }

    public static function decodeAuthenticateRequest($bytes)
    {
        return self::fromCborAuthenticateRequest(self::csilDecode($bytes));
    }

    public static function toCborAuthenticateRequest($value)
    {
        $out = array();
        $field = $value instanceof AuthenticateRequest ? $value->username : (is_array($value) && array_key_exists('username', $value) ? $value['username'] : null);
        $out['username'] = $field;
        $field = $value instanceof AuthenticateRequest ? $value->password : (is_array($value) && array_key_exists('password', $value) ? $value['password'] : null);
        $out['password'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAuthenticateRequest($value)
    {
        $value = self::csilRecord($value, 'AuthenticateRequest', array('username', 'password'));
        return new AuthenticateRequest(array(
            'username' => array_key_exists('username', $value) ? $value['username'] : null,
            'password' => array_key_exists('password', $value) ? $value['password'] : null,
        ));
    }

    public static function encodeAuthenticateResponse($value)
    {
        return CBOR::encode(self::toCborAuthenticateResponse($value));
    }

    public static function decodeAuthenticateResponse($bytes)
    {
        return self::fromCborAuthenticateResponse(self::csilDecode($bytes));
    }

    public static function toCborAuthenticateResponse($value)
    {
        $out = array();
        $field = $value instanceof AuthenticateResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAuthenticateResponse($value)
    {
        $value = self::csilRecord($value, 'AuthenticateResponse', array('user'));
        return new AuthenticateResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeRemoveCredentialRequest($value)
    {
        return CBOR::encode(self::toCborRemoveCredentialRequest($value));
    }

    public static function decodeRemoveCredentialRequest($bytes)
    {
        return self::fromCborRemoveCredentialRequest(self::csilDecode($bytes));
    }

    public static function toCborRemoveCredentialRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveCredentialRequest ? $value->credentialId : (is_array($value) && array_key_exists('credential_id', $value) ? $value['credential_id'] : null);
        $out['credential_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveCredentialRequest($value)
    {
        $value = self::csilRecord($value, 'RemoveCredentialRequest', array('credential_id'));
        return new RemoveCredentialRequest(array(
            'credential_id' => array_key_exists('credential_id', $value) ? $value['credential_id'] : null,
        ));
    }

    public static function encodeRemoveCredentialResponse($value)
    {
        return CBOR::encode(self::toCborRemoveCredentialResponse($value));
    }

    public static function decodeRemoveCredentialResponse($bytes)
    {
        return self::fromCborRemoveCredentialResponse(self::csilDecode($bytes));
    }

    public static function toCborRemoveCredentialResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveCredentialResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveCredentialResponse($value)
    {
        $value = self::csilRecord($value, 'RemoveCredentialResponse', array('success'));
        return new RemoveCredentialResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeSetClaimRequest($value)
    {
        return CBOR::encode(self::toCborSetClaimRequest($value));
    }

    public static function decodeSetClaimRequest($bytes)
    {
        return self::fromCborSetClaimRequest(self::csilDecode($bytes));
    }

    public static function toCborSetClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof SetClaimRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof SetClaimRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetClaimRequest ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = $field;
        $field = $value instanceof SetClaimRequest ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        if ($field !== null) {
            $out['expires_at'] = self::timestampToCbor($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetClaimRequest($value)
    {
        $value = self::csilRecord($value, 'SetClaimRequest', array('user_id', 'claim_type', 'claim_value'));
        return new SetClaimRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeSetClaimResponse($value)
    {
        return CBOR::encode(self::toCborSetClaimResponse($value));
    }

    public static function decodeSetClaimResponse($bytes)
    {
        return self::fromCborSetClaimResponse(self::csilDecode($bytes));
    }

    public static function toCborSetClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof SetClaimResponse ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        $out['claim'] = self::toCborClaim($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetClaimResponse($value)
    {
        $value = self::csilRecord($value, 'SetClaimResponse', array('claim'));
        return new SetClaimResponse(array(
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
        ));
    }

    public static function encodeRemoveClaimRequest($value)
    {
        return CBOR::encode(self::toCborRemoveClaimRequest($value));
    }

    public static function decodeRemoveClaimRequest($bytes)
    {
        return self::fromCborRemoveClaimRequest(self::csilDecode($bytes));
    }

    public static function toCborRemoveClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimRequest ? $value->claimId : (is_array($value) && array_key_exists('claim_id', $value) ? $value['claim_id'] : null);
        $out['claim_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveClaimRequest($value)
    {
        $value = self::csilRecord($value, 'RemoveClaimRequest', array('claim_id'));
        return new RemoveClaimRequest(array(
            'claim_id' => array_key_exists('claim_id', $value) ? $value['claim_id'] : null,
        ));
    }

    public static function encodeRemoveClaimResponse($value)
    {
        return CBOR::encode(self::toCborRemoveClaimResponse($value));
    }

    public static function decodeRemoveClaimResponse($bytes)
    {
        return self::fromCborRemoveClaimResponse(self::csilDecode($bytes));
    }

    public static function toCborRemoveClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveClaimResponse($value)
    {
        $value = self::csilRecord($value, 'RemoveClaimResponse', array('success'));
        return new RemoveClaimResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeListUserClaimsRequest($value)
    {
        return CBOR::encode(self::toCborListUserClaimsRequest($value));
    }

    public static function decodeListUserClaimsRequest($bytes)
    {
        return self::fromCborListUserClaimsRequest(self::csilDecode($bytes));
    }

    public static function toCborListUserClaimsRequest($value)
    {
        $out = array();
        $field = $value instanceof ListUserClaimsRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListUserClaimsRequest($value)
    {
        $value = self::csilRecord($value, 'ListUserClaimsRequest', array('user_id'));
        return new ListUserClaimsRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeListUserClaimsResponse($value)
    {
        return CBOR::encode(self::toCborListUserClaimsResponse($value));
    }

    public static function decodeListUserClaimsResponse($bytes)
    {
        return self::fromCborListUserClaimsResponse(self::csilDecode($bytes));
    }

    public static function toCborListUserClaimsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListUserClaimsResponse ? $value->claimTypes : (is_array($value) && array_key_exists('claim_types', $value) ? $value['claim_types'] : null);
        $out['claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListUserClaimsResponse($value)
    {
        $value = self::csilRecord($value, 'ListUserClaimsResponse', array('claim_types'));
        return new ListUserClaimsResponse(array(
            'claim_types' => array_key_exists('claim_types', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['claim_types'])) : null,
        ));
    }

    public static function encodeAdminUserClaimsRequest($value)
    {
        return CBOR::encode(self::toCborAdminUserClaimsRequest($value));
    }

    public static function decodeAdminUserClaimsRequest($bytes)
    {
        return self::fromCborAdminUserClaimsRequest(self::csilDecode($bytes));
    }

    public static function toCborAdminUserClaimsRequest($value)
    {
        $out = array();
        $field = $value instanceof AdminUserClaimsRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAdminUserClaimsRequest($value)
    {
        $value = self::csilRecord($value, 'AdminUserClaimsRequest', array('user_id'));
        return new AdminUserClaimsRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeAdminUserClaimsResponse($value)
    {
        return CBOR::encode(self::toCborAdminUserClaimsResponse($value));
    }

    public static function decodeAdminUserClaimsResponse($bytes)
    {
        return self::fromCborAdminUserClaimsResponse(self::csilDecode($bytes));
    }

    public static function toCborAdminUserClaimsResponse($value)
    {
        $out = array();
        $field = $value instanceof AdminUserClaimsResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAdminUserClaimsResponse($value)
    {
        $value = self::csilRecord($value, 'AdminUserClaimsResponse', array('claims'));
        return new AdminUserClaimsResponse(array(
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, self::csilList($value['claims'])) : null,
        ));
    }

    public static function encodeSetUserClaimRequest($value)
    {
        return CBOR::encode(self::toCborSetUserClaimRequest($value));
    }

    public static function decodeSetUserClaimRequest($bytes)
    {
        return self::fromCborSetUserClaimRequest(self::csilDecode($bytes));
    }

    public static function toCborSetUserClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof SetUserClaimRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof SetUserClaimRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetUserClaimRequest ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetUserClaimRequest($value)
    {
        $value = self::csilRecord($value, 'SetUserClaimRequest', array('user_id', 'claim_type', 'claim_value'));
        return new SetUserClaimRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
        ));
    }

    public static function encodeSetUserClaimResponse($value)
    {
        return CBOR::encode(self::toCborSetUserClaimResponse($value));
    }

    public static function decodeSetUserClaimResponse($bytes)
    {
        return self::fromCborSetUserClaimResponse(self::csilDecode($bytes));
    }

    public static function toCborSetUserClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof SetUserClaimResponse ? $value->outcome : (is_array($value) && array_key_exists('outcome', $value) ? $value['outcome'] : null);
        $out['outcome'] = self::toCborSetClaimOutcome($field);
        $field = $value instanceof SetUserClaimResponse ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        if ($field !== null) {
            $out['claim'] = self::toCborClaim($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetUserClaimResponse($value)
    {
        $value = self::csilRecord($value, 'SetUserClaimResponse', array('outcome'));
        return new SetUserClaimResponse(array(
            'outcome' => array_key_exists('outcome', $value) ? self::fromCborSetClaimOutcome($value['outcome']) : null,
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
        ));
    }

    public static function encodeSettableClaimPolicy($value)
    {
        return CBOR::encode(self::toCborSettableClaimPolicy($value));
    }

    public static function decodeSettableClaimPolicy($bytes)
    {
        return self::fromCborSettableClaimPolicy(self::csilDecode($bytes));
    }

    public static function toCborSettableClaimPolicy($value)
    {
        $out = array();
        $field = $value instanceof SettableClaimPolicy ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        $out['description'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->datatype : (is_array($value) && array_key_exists('datatype', $value) ? $value['datatype'] : null);
        $out['datatype'] = self::toCborClaimValueType($field);
        $field = $value instanceof SettableClaimPolicy ? $value->maxBytes : (is_array($value) && array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null);
        $out['max_bytes'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->setRule : (is_array($value) && array_key_exists('set_rule', $value) ? $value['set_rule'] : null);
        $out['set_rule'] = self::toCborSetRule($field);
        $field = $value instanceof SettableClaimPolicy ? $value->requiresApproval : (is_array($value) && array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null);
        $out['requires_approval'] = $field;
        $field = $value instanceof SettableClaimPolicy ? $value->signingRule : (is_array($value) && array_key_exists('signing_rule', $value) ? $value['signing_rule'] : null);
        $out['signing_rule'] = self::toCborSigningRule($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSettableClaimPolicy($value)
    {
        $value = self::csilRecord($value, 'SettableClaimPolicy', array('claim_type', 'label', 'description', 'datatype', 'max_bytes', 'set_rule', 'requires_approval', 'signing_rule'));
        return new SettableClaimPolicy(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
            'datatype' => array_key_exists('datatype', $value) ? self::fromCborClaimValueType($value['datatype']) : null,
            'max_bytes' => array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null,
            'set_rule' => array_key_exists('set_rule', $value) ? self::fromCborSetRule($value['set_rule']) : null,
            'requires_approval' => array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null,
            'signing_rule' => array_key_exists('signing_rule', $value) ? self::fromCborSigningRule($value['signing_rule']) : null,
        ));
    }

    public static function encodeListSettablePoliciesResponse($value)
    {
        return CBOR::encode(self::toCborListSettablePoliciesResponse($value));
    }

    public static function decodeListSettablePoliciesResponse($bytes)
    {
        return self::fromCborListSettablePoliciesResponse(self::csilDecode($bytes));
    }

    public static function toCborListSettablePoliciesResponse($value)
    {
        $out = array();
        $field = $value instanceof ListSettablePoliciesResponse ? $value->policies : (is_array($value) && array_key_exists('policies', $value) ? $value['policies'] : null);
        $out['policies'] = array_map(function ($item) { return self::toCborSettableClaimPolicy($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListSettablePoliciesResponse($value)
    {
        $value = self::csilRecord($value, 'ListSettablePoliciesResponse', array('policies'));
        return new ListSettablePoliciesResponse(array(
            'policies' => array_key_exists('policies', $value) ? array_map(function ($item) { return self::fromCborSettableClaimPolicy($item); }, self::csilList($value['policies'])) : null,
        ));
    }

    public static function encodeClaimTypePolicy($value)
    {
        return CBOR::encode(self::toCborClaimTypePolicy($value));
    }

    public static function decodeClaimTypePolicy($bytes)
    {
        return self::fromCborClaimTypePolicy(self::csilDecode($bytes));
    }

    public static function toCborClaimTypePolicy($value)
    {
        $out = array();
        $field = $value instanceof ClaimTypePolicy ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        $out['description'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->valueType : (is_array($value) && array_key_exists('value_type', $value) ? $value['value_type'] : null);
        $out['value_type'] = self::toCborClaimValueType($field);
        $field = $value instanceof ClaimTypePolicy ? $value->maxBytes : (is_array($value) && array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null);
        $out['max_bytes'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->setRule : (is_array($value) && array_key_exists('set_rule', $value) ? $value['set_rule'] : null);
        $out['set_rule'] = self::toCborSetRule($field);
        $field = $value instanceof ClaimTypePolicy ? $value->signingRule : (is_array($value) && array_key_exists('signing_rule', $value) ? $value['signing_rule'] : null);
        $out['signing_rule'] = self::toCborSigningRule($field);
        $field = $value instanceof ClaimTypePolicy ? $value->requiresApproval : (is_array($value) && array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null);
        $out['requires_approval'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->userSettable : (is_array($value) && array_key_exists('user_settable', $value) ? $value['user_settable'] : null);
        $out['user_settable'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->defaultAutoSign : (is_array($value) && array_key_exists('default_auto_sign', $value) ? $value['default_auto_sign'] : null);
        $out['default_auto_sign'] = $field;
        $field = $value instanceof ClaimTypePolicy ? $value->suggested : (is_array($value) && array_key_exists('suggested', $value) ? $value['suggested'] : null);
        $out['suggested'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborClaimTypePolicy($value)
    {
        $value = self::csilRecord($value, 'ClaimTypePolicy', array('claim_type', 'label', 'description', 'value_type', 'max_bytes', 'set_rule', 'signing_rule', 'requires_approval', 'user_settable', 'default_auto_sign', 'suggested'));
        return new ClaimTypePolicy(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
            'value_type' => array_key_exists('value_type', $value) ? self::fromCborClaimValueType($value['value_type']) : null,
            'max_bytes' => array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null,
            'set_rule' => array_key_exists('set_rule', $value) ? self::fromCborSetRule($value['set_rule']) : null,
            'signing_rule' => array_key_exists('signing_rule', $value) ? self::fromCborSigningRule($value['signing_rule']) : null,
            'requires_approval' => array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null,
            'user_settable' => array_key_exists('user_settable', $value) ? $value['user_settable'] : null,
            'default_auto_sign' => array_key_exists('default_auto_sign', $value) ? $value['default_auto_sign'] : null,
            'suggested' => array_key_exists('suggested', $value) ? $value['suggested'] : null,
        ));
    }

    public static function encodeListClaimTypesResponse($value)
    {
        return CBOR::encode(self::toCborListClaimTypesResponse($value));
    }

    public static function decodeListClaimTypesResponse($bytes)
    {
        return self::fromCborListClaimTypesResponse(self::csilDecode($bytes));
    }

    public static function toCborListClaimTypesResponse($value)
    {
        $out = array();
        $field = $value instanceof ListClaimTypesResponse ? $value->claimTypes : (is_array($value) && array_key_exists('claim_types', $value) ? $value['claim_types'] : null);
        $out['claim_types'] = array_map(function ($item) { return self::toCborClaimTypePolicy($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListClaimTypesResponse($value)
    {
        $value = self::csilRecord($value, 'ListClaimTypesResponse', array('claim_types'));
        return new ListClaimTypesResponse(array(
            'claim_types' => array_key_exists('claim_types', $value) ? array_map(function ($item) { return self::fromCborClaimTypePolicy($item); }, self::csilList($value['claim_types'])) : null,
        ));
    }

    public static function encodeSetClaimTypeRequest($value)
    {
        return CBOR::encode(self::toCborSetClaimTypeRequest($value));
    }

    public static function decodeSetClaimTypeRequest($bytes)
    {
        return self::fromCborSetClaimTypeRequest(self::csilDecode($bytes));
    }

    public static function toCborSetClaimTypeRequest($value)
    {
        $out = array();
        $field = $value instanceof SetClaimTypeRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        if ($field !== null) {
            $out['description'] = $field;
        }
        $field = $value instanceof SetClaimTypeRequest ? $value->valueType : (is_array($value) && array_key_exists('value_type', $value) ? $value['value_type'] : null);
        $out['value_type'] = self::toCborClaimValueType($field);
        $field = $value instanceof SetClaimTypeRequest ? $value->maxBytes : (is_array($value) && array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null);
        $out['max_bytes'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->setRule : (is_array($value) && array_key_exists('set_rule', $value) ? $value['set_rule'] : null);
        $out['set_rule'] = self::toCborSetRule($field);
        $field = $value instanceof SetClaimTypeRequest ? $value->signingRule : (is_array($value) && array_key_exists('signing_rule', $value) ? $value['signing_rule'] : null);
        $out['signing_rule'] = self::toCborSigningRule($field);
        $field = $value instanceof SetClaimTypeRequest ? $value->userSettable : (is_array($value) && array_key_exists('user_settable', $value) ? $value['user_settable'] : null);
        $out['user_settable'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->defaultAutoSign : (is_array($value) && array_key_exists('default_auto_sign', $value) ? $value['default_auto_sign'] : null);
        $out['default_auto_sign'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->requiresApproval : (is_array($value) && array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null);
        $out['requires_approval'] = $field;
        $field = $value instanceof SetClaimTypeRequest ? $value->suggested : (is_array($value) && array_key_exists('suggested', $value) ? $value['suggested'] : null);
        $out['suggested'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetClaimTypeRequest($value)
    {
        $value = self::csilRecord($value, 'SetClaimTypeRequest', array('claim_type', 'label', 'value_type', 'max_bytes', 'set_rule', 'signing_rule', 'user_settable', 'default_auto_sign', 'requires_approval', 'suggested'));
        return new SetClaimTypeRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
            'value_type' => array_key_exists('value_type', $value) ? self::fromCborClaimValueType($value['value_type']) : null,
            'max_bytes' => array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null,
            'set_rule' => array_key_exists('set_rule', $value) ? self::fromCborSetRule($value['set_rule']) : null,
            'signing_rule' => array_key_exists('signing_rule', $value) ? self::fromCborSigningRule($value['signing_rule']) : null,
            'user_settable' => array_key_exists('user_settable', $value) ? $value['user_settable'] : null,
            'default_auto_sign' => array_key_exists('default_auto_sign', $value) ? $value['default_auto_sign'] : null,
            'requires_approval' => array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null,
            'suggested' => array_key_exists('suggested', $value) ? $value['suggested'] : null,
        ));
    }

    public static function encodeSetClaimTypeResponse($value)
    {
        return CBOR::encode(self::toCborSetClaimTypeResponse($value));
    }

    public static function decodeSetClaimTypeResponse($bytes)
    {
        return self::fromCborSetClaimTypeResponse(self::csilDecode($bytes));
    }

    public static function toCborSetClaimTypeResponse($value)
    {
        $out = array();
        $field = $value instanceof SetClaimTypeResponse ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = self::toCborClaimTypePolicy($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetClaimTypeResponse($value)
    {
        $value = self::csilRecord($value, 'SetClaimTypeResponse', array('claim_type'));
        return new SetClaimTypeResponse(array(
            'claim_type' => array_key_exists('claim_type', $value) ? self::fromCborClaimTypePolicy($value['claim_type']) : null,
        ));
    }

    public static function encodeRemoveClaimTypeRequest($value)
    {
        return CBOR::encode(self::toCborRemoveClaimTypeRequest($value));
    }

    public static function decodeRemoveClaimTypeRequest($bytes)
    {
        return self::fromCborRemoveClaimTypeRequest(self::csilDecode($bytes));
    }

    public static function toCborRemoveClaimTypeRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimTypeRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveClaimTypeRequest($value)
    {
        $value = self::csilRecord($value, 'RemoveClaimTypeRequest', array('claim_type'));
        return new RemoveClaimTypeRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
        ));
    }

    public static function encodeRemoveClaimTypeResponse($value)
    {
        return CBOR::encode(self::toCborRemoveClaimTypeResponse($value));
    }

    public static function decodeRemoveClaimTypeResponse($bytes)
    {
        return self::fromCborRemoveClaimTypeResponse(self::csilDecode($bytes));
    }

    public static function toCborRemoveClaimTypeResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimTypeResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveClaimTypeResponse($value)
    {
        $value = self::csilRecord($value, 'RemoveClaimTypeResponse', array('success'));
        return new RemoveClaimTypeResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeClaimTypeLabel($value)
    {
        return CBOR::encode(self::toCborClaimTypeLabel($value));
    }

    public static function decodeClaimTypeLabel($bytes)
    {
        return self::fromCborClaimTypeLabel(self::csilDecode($bytes));
    }

    public static function toCborClaimTypeLabel($value)
    {
        $out = array();
        $field = $value instanceof ClaimTypeLabel ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof ClaimTypeLabel ? $value->locale : (is_array($value) && array_key_exists('locale', $value) ? $value['locale'] : null);
        $out['locale'] = $field;
        $field = $value instanceof ClaimTypeLabel ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof ClaimTypeLabel ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        if ($field !== null) {
            $out['description'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborClaimTypeLabel($value)
    {
        $value = self::csilRecord($value, 'ClaimTypeLabel', array('claim_type', 'locale', 'label'));
        return new ClaimTypeLabel(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'locale' => array_key_exists('locale', $value) ? $value['locale'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
        ));
    }

    public static function encodeSetClaimTypeLabelRequest($value)
    {
        return CBOR::encode(self::toCborSetClaimTypeLabelRequest($value));
    }

    public static function decodeSetClaimTypeLabelRequest($bytes)
    {
        return self::fromCborSetClaimTypeLabelRequest(self::csilDecode($bytes));
    }

    public static function toCborSetClaimTypeLabelRequest($value)
    {
        $out = array();
        $field = $value instanceof SetClaimTypeLabelRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetClaimTypeLabelRequest ? $value->locale : (is_array($value) && array_key_exists('locale', $value) ? $value['locale'] : null);
        $out['locale'] = $field;
        $field = $value instanceof SetClaimTypeLabelRequest ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof SetClaimTypeLabelRequest ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        if ($field !== null) {
            $out['description'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetClaimTypeLabelRequest($value)
    {
        $value = self::csilRecord($value, 'SetClaimTypeLabelRequest', array('claim_type', 'locale', 'label'));
        return new SetClaimTypeLabelRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'locale' => array_key_exists('locale', $value) ? $value['locale'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
        ));
    }

    public static function encodeSetClaimTypeLabelResponse($value)
    {
        return CBOR::encode(self::toCborSetClaimTypeLabelResponse($value));
    }

    public static function decodeSetClaimTypeLabelResponse($bytes)
    {
        return self::fromCborSetClaimTypeLabelResponse(self::csilDecode($bytes));
    }

    public static function toCborSetClaimTypeLabelResponse($value)
    {
        $out = array();
        $field = $value instanceof SetClaimTypeLabelResponse ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = self::toCborClaimTypeLabel($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetClaimTypeLabelResponse($value)
    {
        $value = self::csilRecord($value, 'SetClaimTypeLabelResponse', array('label'));
        return new SetClaimTypeLabelResponse(array(
            'label' => array_key_exists('label', $value) ? self::fromCborClaimTypeLabel($value['label']) : null,
        ));
    }

    public static function encodeListClaimTypeLabelsResponse($value)
    {
        return CBOR::encode(self::toCborListClaimTypeLabelsResponse($value));
    }

    public static function decodeListClaimTypeLabelsResponse($bytes)
    {
        return self::fromCborListClaimTypeLabelsResponse(self::csilDecode($bytes));
    }

    public static function toCborListClaimTypeLabelsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListClaimTypeLabelsResponse ? $value->labels : (is_array($value) && array_key_exists('labels', $value) ? $value['labels'] : null);
        $out['labels'] = array_map(function ($item) { return self::toCborClaimTypeLabel($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListClaimTypeLabelsResponse($value)
    {
        $value = self::csilRecord($value, 'ListClaimTypeLabelsResponse', array('labels'));
        return new ListClaimTypeLabelsResponse(array(
            'labels' => array_key_exists('labels', $value) ? array_map(function ($item) { return self::fromCborClaimTypeLabel($item); }, self::csilList($value['labels'])) : null,
        ));
    }

    public static function encodeRemoveClaimTypeLabelRequest($value)
    {
        return CBOR::encode(self::toCborRemoveClaimTypeLabelRequest($value));
    }

    public static function decodeRemoveClaimTypeLabelRequest($bytes)
    {
        return self::fromCborRemoveClaimTypeLabelRequest(self::csilDecode($bytes));
    }

    public static function toCborRemoveClaimTypeLabelRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimTypeLabelRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof RemoveClaimTypeLabelRequest ? $value->locale : (is_array($value) && array_key_exists('locale', $value) ? $value['locale'] : null);
        $out['locale'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveClaimTypeLabelRequest($value)
    {
        $value = self::csilRecord($value, 'RemoveClaimTypeLabelRequest', array('claim_type', 'locale'));
        return new RemoveClaimTypeLabelRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'locale' => array_key_exists('locale', $value) ? $value['locale'] : null,
        ));
    }

    public static function encodeRemoveClaimTypeLabelResponse($value)
    {
        return CBOR::encode(self::toCborRemoveClaimTypeLabelResponse($value));
    }

    public static function decodeRemoveClaimTypeLabelResponse($bytes)
    {
        return self::fromCborRemoveClaimTypeLabelResponse(self::csilDecode($bytes));
    }

    public static function toCborRemoveClaimTypeLabelResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveClaimTypeLabelResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveClaimTypeLabelResponse($value)
    {
        $value = self::csilRecord($value, 'RemoveClaimTypeLabelResponse', array('success'));
        return new RemoveClaimTypeLabelResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeTrustedIssuer($value)
    {
        return CBOR::encode(self::toCborTrustedIssuer($value));
    }

    public static function decodeTrustedIssuer($bytes)
    {
        return self::fromCborTrustedIssuer(self::csilDecode($bytes));
    }

    public static function toCborTrustedIssuer($value)
    {
        $out = array();
        $field = $value instanceof TrustedIssuer ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof TrustedIssuer ? $value->issuerDomain : (is_array($value) && array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null);
        $out['issuer_domain'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborTrustedIssuer($value)
    {
        $value = self::csilRecord($value, 'TrustedIssuer', array('claim_type', 'issuer_domain'));
        return new TrustedIssuer(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'issuer_domain' => array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null,
        ));
    }

    public static function encodeListTrustedIssuersResponse($value)
    {
        return CBOR::encode(self::toCborListTrustedIssuersResponse($value));
    }

    public static function decodeListTrustedIssuersResponse($bytes)
    {
        return self::fromCborListTrustedIssuersResponse(self::csilDecode($bytes));
    }

    public static function toCborListTrustedIssuersResponse($value)
    {
        $out = array();
        $field = $value instanceof ListTrustedIssuersResponse ? $value->trustedIssuers : (is_array($value) && array_key_exists('trusted_issuers', $value) ? $value['trusted_issuers'] : null);
        $out['trusted_issuers'] = array_map(function ($item) { return self::toCborTrustedIssuer($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListTrustedIssuersResponse($value)
    {
        $value = self::csilRecord($value, 'ListTrustedIssuersResponse', array('trusted_issuers'));
        return new ListTrustedIssuersResponse(array(
            'trusted_issuers' => array_key_exists('trusted_issuers', $value) ? array_map(function ($item) { return self::fromCborTrustedIssuer($item); }, self::csilList($value['trusted_issuers'])) : null,
        ));
    }

    public static function encodeAddTrustedIssuerRequest($value)
    {
        return CBOR::encode(self::toCborAddTrustedIssuerRequest($value));
    }

    public static function decodeAddTrustedIssuerRequest($bytes)
    {
        return self::fromCborAddTrustedIssuerRequest(self::csilDecode($bytes));
    }

    public static function toCborAddTrustedIssuerRequest($value)
    {
        $out = array();
        $field = $value instanceof AddTrustedIssuerRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof AddTrustedIssuerRequest ? $value->issuerDomain : (is_array($value) && array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null);
        $out['issuer_domain'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAddTrustedIssuerRequest($value)
    {
        $value = self::csilRecord($value, 'AddTrustedIssuerRequest', array('claim_type', 'issuer_domain'));
        return new AddTrustedIssuerRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'issuer_domain' => array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null,
        ));
    }

    public static function encodeAddTrustedIssuerResponse($value)
    {
        return CBOR::encode(self::toCborAddTrustedIssuerResponse($value));
    }

    public static function decodeAddTrustedIssuerResponse($bytes)
    {
        return self::fromCborAddTrustedIssuerResponse(self::csilDecode($bytes));
    }

    public static function toCborAddTrustedIssuerResponse($value)
    {
        $out = array();
        $field = $value instanceof AddTrustedIssuerResponse ? $value->trustedIssuer : (is_array($value) && array_key_exists('trusted_issuer', $value) ? $value['trusted_issuer'] : null);
        $out['trusted_issuer'] = self::toCborTrustedIssuer($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAddTrustedIssuerResponse($value)
    {
        $value = self::csilRecord($value, 'AddTrustedIssuerResponse', array('trusted_issuer'));
        return new AddTrustedIssuerResponse(array(
            'trusted_issuer' => array_key_exists('trusted_issuer', $value) ? self::fromCborTrustedIssuer($value['trusted_issuer']) : null,
        ));
    }

    public static function encodeRemoveTrustedIssuerRequest($value)
    {
        return CBOR::encode(self::toCborRemoveTrustedIssuerRequest($value));
    }

    public static function decodeRemoveTrustedIssuerRequest($bytes)
    {
        return self::fromCborRemoveTrustedIssuerRequest(self::csilDecode($bytes));
    }

    public static function toCborRemoveTrustedIssuerRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveTrustedIssuerRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof RemoveTrustedIssuerRequest ? $value->issuerDomain : (is_array($value) && array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null);
        $out['issuer_domain'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveTrustedIssuerRequest($value)
    {
        $value = self::csilRecord($value, 'RemoveTrustedIssuerRequest', array('claim_type', 'issuer_domain'));
        return new RemoveTrustedIssuerRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'issuer_domain' => array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null,
        ));
    }

    public static function encodeRemoveTrustedIssuerResponse($value)
    {
        return CBOR::encode(self::toCborRemoveTrustedIssuerResponse($value));
    }

    public static function decodeRemoveTrustedIssuerResponse($bytes)
    {
        return self::fromCborRemoveTrustedIssuerResponse(self::csilDecode($bytes));
    }

    public static function toCborRemoveTrustedIssuerResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveTrustedIssuerResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveTrustedIssuerResponse($value)
    {
        $value = self::csilRecord($value, 'RemoveTrustedIssuerResponse', array('success'));
        return new RemoveTrustedIssuerResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeReleaseRule($value)
    {
        return CBOR::encode(self::toCborReleaseRule($value));
    }

    public static function decodeReleaseRule($bytes)
    {
        return self::fromCborReleaseRule(self::csilDecode($bytes));
    }

    public static function toCborReleaseRule($value)
    {
        $out = array();
        $field = $value instanceof ReleaseRule ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof ReleaseRule ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof ReleaseRule ? $value->disposition : (is_array($value) && array_key_exists('disposition', $value) ? $value['disposition'] : null);
        $out['disposition'] = self::toCborReleaseDisposition($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborReleaseRule($value)
    {
        $value = self::csilRecord($value, 'ReleaseRule', array('audience', 'claim_type', 'disposition'));
        return new ReleaseRule(array(
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'disposition' => array_key_exists('disposition', $value) ? self::fromCborReleaseDisposition($value['disposition']) : null,
        ));
    }

    public static function encodeListReleaseRulesResponse($value)
    {
        return CBOR::encode(self::toCborListReleaseRulesResponse($value));
    }

    public static function decodeListReleaseRulesResponse($bytes)
    {
        return self::fromCborListReleaseRulesResponse(self::csilDecode($bytes));
    }

    public static function toCborListReleaseRulesResponse($value)
    {
        $out = array();
        $field = $value instanceof ListReleaseRulesResponse ? $value->releaseRules : (is_array($value) && array_key_exists('release_rules', $value) ? $value['release_rules'] : null);
        $out['release_rules'] = array_map(function ($item) { return self::toCborReleaseRule($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListReleaseRulesResponse($value)
    {
        $value = self::csilRecord($value, 'ListReleaseRulesResponse', array('release_rules'));
        return new ListReleaseRulesResponse(array(
            'release_rules' => array_key_exists('release_rules', $value) ? array_map(function ($item) { return self::fromCborReleaseRule($item); }, self::csilList($value['release_rules'])) : null,
        ));
    }

    public static function encodeSetReleaseRuleRequest($value)
    {
        return CBOR::encode(self::toCborSetReleaseRuleRequest($value));
    }

    public static function decodeSetReleaseRuleRequest($bytes)
    {
        return self::fromCborSetReleaseRuleRequest(self::csilDecode($bytes));
    }

    public static function toCborSetReleaseRuleRequest($value)
    {
        $out = array();
        $field = $value instanceof SetReleaseRuleRequest ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof SetReleaseRuleRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetReleaseRuleRequest ? $value->disposition : (is_array($value) && array_key_exists('disposition', $value) ? $value['disposition'] : null);
        $out['disposition'] = self::toCborReleaseDisposition($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetReleaseRuleRequest($value)
    {
        $value = self::csilRecord($value, 'SetReleaseRuleRequest', array('audience', 'claim_type', 'disposition'));
        return new SetReleaseRuleRequest(array(
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'disposition' => array_key_exists('disposition', $value) ? self::fromCborReleaseDisposition($value['disposition']) : null,
        ));
    }

    public static function encodeSetReleaseRuleResponse($value)
    {
        return CBOR::encode(self::toCborSetReleaseRuleResponse($value));
    }

    public static function decodeSetReleaseRuleResponse($bytes)
    {
        return self::fromCborSetReleaseRuleResponse(self::csilDecode($bytes));
    }

    public static function toCborSetReleaseRuleResponse($value)
    {
        $out = array();
        $field = $value instanceof SetReleaseRuleResponse ? $value->releaseRule : (is_array($value) && array_key_exists('release_rule', $value) ? $value['release_rule'] : null);
        $out['release_rule'] = self::toCborReleaseRule($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetReleaseRuleResponse($value)
    {
        $value = self::csilRecord($value, 'SetReleaseRuleResponse', array('release_rule'));
        return new SetReleaseRuleResponse(array(
            'release_rule' => array_key_exists('release_rule', $value) ? self::fromCborReleaseRule($value['release_rule']) : null,
        ));
    }

    public static function encodeRemoveReleaseRuleRequest($value)
    {
        return CBOR::encode(self::toCborRemoveReleaseRuleRequest($value));
    }

    public static function decodeRemoveReleaseRuleRequest($bytes)
    {
        return self::fromCborRemoveReleaseRuleRequest(self::csilDecode($bytes));
    }

    public static function toCborRemoveReleaseRuleRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveReleaseRuleRequest ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof RemoveReleaseRuleRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveReleaseRuleRequest($value)
    {
        $value = self::csilRecord($value, 'RemoveReleaseRuleRequest', array('audience', 'claim_type'));
        return new RemoveReleaseRuleRequest(array(
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
        ));
    }

    public static function encodeRemoveReleaseRuleResponse($value)
    {
        return CBOR::encode(self::toCborRemoveReleaseRuleResponse($value));
    }

    public static function decodeRemoveReleaseRuleResponse($bytes)
    {
        return self::fromCborRemoveReleaseRuleResponse(self::csilDecode($bytes));
    }

    public static function toCborRemoveReleaseRuleResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveReleaseRuleResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveReleaseRuleResponse($value)
    {
        $value = self::csilRecord($value, 'RemoveReleaseRuleResponse', array('success'));
        return new RemoveReleaseRuleResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeClaimApproval($value)
    {
        return CBOR::encode(self::toCborClaimApproval($value));
    }

    public static function decodeClaimApproval($bytes)
    {
        return self::fromCborClaimApproval(self::csilDecode($bytes));
    }

    public static function toCborClaimApproval($value)
    {
        $out = array();
        $field = $value instanceof ClaimApproval ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof ClaimApproval ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof ClaimApproval ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof ClaimApproval ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = CBOR::bytes($field);
        $field = $value instanceof ClaimApproval ? $value->status : (is_array($value) && array_key_exists('status', $value) ? $value['status'] : null);
        $out['status'] = self::toCborClaimApprovalStatus($field);
        $field = $value instanceof ClaimApproval ? $value->resolvedBy : (is_array($value) && array_key_exists('resolved_by', $value) ? $value['resolved_by'] : null);
        if ($field !== null) {
            $out['resolved_by'] = $field;
        }
        $field = $value instanceof ClaimApproval ? $value->resolvedAt : (is_array($value) && array_key_exists('resolved_at', $value) ? $value['resolved_at'] : null);
        if ($field !== null) {
            $out['resolved_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof ClaimApproval ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborClaimApproval($value)
    {
        $value = self::csilRecord($value, 'ClaimApproval', array('id', 'user_id', 'claim_type', 'claim_value', 'status', 'created_at'));
        return new ClaimApproval(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
            'status' => array_key_exists('status', $value) ? self::fromCborClaimApprovalStatus($value['status']) : null,
            'resolved_by' => array_key_exists('resolved_by', $value) ? $value['resolved_by'] : null,
            'resolved_at' => array_key_exists('resolved_at', $value) ? self::timestampFromCbor($value['resolved_at']) : null,
            'created_at' => array_key_exists('created_at', $value) ? self::timestampFromCbor($value['created_at']) : null,
        ));
    }

    public static function encodeListPendingClaimApprovalsResponse($value)
    {
        return CBOR::encode(self::toCborListPendingClaimApprovalsResponse($value));
    }

    public static function decodeListPendingClaimApprovalsResponse($bytes)
    {
        return self::fromCborListPendingClaimApprovalsResponse(self::csilDecode($bytes));
    }

    public static function toCborListPendingClaimApprovalsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListPendingClaimApprovalsResponse ? $value->approvals : (is_array($value) && array_key_exists('approvals', $value) ? $value['approvals'] : null);
        $out['approvals'] = array_map(function ($item) { return self::toCborClaimApproval($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListPendingClaimApprovalsResponse($value)
    {
        $value = self::csilRecord($value, 'ListPendingClaimApprovalsResponse', array('approvals'));
        return new ListPendingClaimApprovalsResponse(array(
            'approvals' => array_key_exists('approvals', $value) ? array_map(function ($item) { return self::fromCborClaimApproval($item); }, self::csilList($value['approvals'])) : null,
        ));
    }

    public static function encodeApproveClaimRequest($value)
    {
        return CBOR::encode(self::toCborApproveClaimRequest($value));
    }

    public static function decodeApproveClaimRequest($bytes)
    {
        return self::fromCborApproveClaimRequest(self::csilDecode($bytes));
    }

    public static function toCborApproveClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof ApproveClaimRequest ? $value->approvalId : (is_array($value) && array_key_exists('approval_id', $value) ? $value['approval_id'] : null);
        $out['approval_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApproveClaimRequest($value)
    {
        $value = self::csilRecord($value, 'ApproveClaimRequest', array('approval_id'));
        return new ApproveClaimRequest(array(
            'approval_id' => array_key_exists('approval_id', $value) ? $value['approval_id'] : null,
        ));
    }

    public static function encodeApproveClaimResponse($value)
    {
        return CBOR::encode(self::toCborApproveClaimResponse($value));
    }

    public static function decodeApproveClaimResponse($bytes)
    {
        return self::fromCborApproveClaimResponse(self::csilDecode($bytes));
    }

    public static function toCborApproveClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof ApproveClaimResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApproveClaimResponse($value)
    {
        $value = self::csilRecord($value, 'ApproveClaimResponse', array('success'));
        return new ApproveClaimResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeRejectClaimRequest($value)
    {
        return CBOR::encode(self::toCborRejectClaimRequest($value));
    }

    public static function decodeRejectClaimRequest($bytes)
    {
        return self::fromCborRejectClaimRequest(self::csilDecode($bytes));
    }

    public static function toCborRejectClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof RejectClaimRequest ? $value->approvalId : (is_array($value) && array_key_exists('approval_id', $value) ? $value['approval_id'] : null);
        $out['approval_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRejectClaimRequest($value)
    {
        $value = self::csilRecord($value, 'RejectClaimRequest', array('approval_id'));
        return new RejectClaimRequest(array(
            'approval_id' => array_key_exists('approval_id', $value) ? $value['approval_id'] : null,
        ));
    }

    public static function encodeRejectClaimResponse($value)
    {
        return CBOR::encode(self::toCborRejectClaimResponse($value));
    }

    public static function decodeRejectClaimResponse($bytes)
    {
        return self::fromCborRejectClaimResponse(self::csilDecode($bytes));
    }

    public static function toCborRejectClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof RejectClaimResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRejectClaimResponse($value)
    {
        $value = self::csilRecord($value, 'RejectClaimResponse', array('success'));
        return new RejectClaimResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeAdminIssueAttestationRequest($value)
    {
        return CBOR::encode(self::toCborAdminIssueAttestationRequest($value));
    }

    public static function decodeAdminIssueAttestationRequest($bytes)
    {
        return self::fromCborAdminIssueAttestationRequest(self::csilDecode($bytes));
    }

    public static function toCborAdminIssueAttestationRequest($value)
    {
        $out = array();
        $field = $value instanceof AdminIssueAttestationRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof AdminIssueAttestationRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof AdminIssueAttestationRequest ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAdminIssueAttestationRequest($value)
    {
        $value = self::csilRecord($value, 'AdminIssueAttestationRequest', array('user_id', 'claim_type', 'claim_value'));
        return new AdminIssueAttestationRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
        ));
    }

    public static function encodeAdminIssueAttestationResponse($value)
    {
        return CBOR::encode(self::toCborAdminIssueAttestationResponse($value));
    }

    public static function decodeAdminIssueAttestationResponse($bytes)
    {
        return self::fromCborAdminIssueAttestationResponse(self::csilDecode($bytes));
    }

    public static function toCborAdminIssueAttestationResponse($value)
    {
        $out = array();
        $field = $value instanceof AdminIssueAttestationResponse ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        $out['claim'] = self::toCborClaim($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAdminIssueAttestationResponse($value)
    {
        $value = self::csilRecord($value, 'AdminIssueAttestationResponse', array('claim'));
        return new AdminIssueAttestationResponse(array(
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
        ));
    }

    public static function encodeGrantRelationRequest($value)
    {
        return CBOR::encode(self::toCborGrantRelationRequest($value));
    }

    public static function decodeGrantRelationRequest($bytes)
    {
        return self::fromCborGrantRelationRequest(self::csilDecode($bytes));
    }

    public static function toCborGrantRelationRequest($value)
    {
        $out = array();
        $field = $value instanceof GrantRelationRequest ? $value->subjectType : (is_array($value) && array_key_exists('subject_type', $value) ? $value['subject_type'] : null);
        $out['subject_type'] = $field;
        $field = $value instanceof GrantRelationRequest ? $value->subjectId : (is_array($value) && array_key_exists('subject_id', $value) ? $value['subject_id'] : null);
        $out['subject_id'] = $field;
        $field = $value instanceof GrantRelationRequest ? $value->relation : (is_array($value) && array_key_exists('relation', $value) ? $value['relation'] : null);
        $out['relation'] = $field;
        $field = $value instanceof GrantRelationRequest ? $value->objectType : (is_array($value) && array_key_exists('object_type', $value) ? $value['object_type'] : null);
        $out['object_type'] = $field;
        $field = $value instanceof GrantRelationRequest ? $value->objectId : (is_array($value) && array_key_exists('object_id', $value) ? $value['object_id'] : null);
        $out['object_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGrantRelationRequest($value)
    {
        $value = self::csilRecord($value, 'GrantRelationRequest', array('subject_type', 'subject_id', 'relation', 'object_type', 'object_id'));
        return new GrantRelationRequest(array(
            'subject_type' => array_key_exists('subject_type', $value) ? $value['subject_type'] : null,
            'subject_id' => array_key_exists('subject_id', $value) ? $value['subject_id'] : null,
            'relation' => array_key_exists('relation', $value) ? $value['relation'] : null,
            'object_type' => array_key_exists('object_type', $value) ? $value['object_type'] : null,
            'object_id' => array_key_exists('object_id', $value) ? $value['object_id'] : null,
        ));
    }

    public static function encodeGrantRelationResponse($value)
    {
        return CBOR::encode(self::toCborGrantRelationResponse($value));
    }

    public static function decodeGrantRelationResponse($bytes)
    {
        return self::fromCborGrantRelationResponse(self::csilDecode($bytes));
    }

    public static function toCborGrantRelationResponse($value)
    {
        $out = array();
        $field = $value instanceof GrantRelationResponse ? $value->relation : (is_array($value) && array_key_exists('relation', $value) ? $value['relation'] : null);
        $out['relation'] = self::toCborRelation($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGrantRelationResponse($value)
    {
        $value = self::csilRecord($value, 'GrantRelationResponse', array('relation'));
        return new GrantRelationResponse(array(
            'relation' => array_key_exists('relation', $value) ? self::fromCborRelation($value['relation']) : null,
        ));
    }

    public static function encodeRemoveRelationRequest($value)
    {
        return CBOR::encode(self::toCborRemoveRelationRequest($value));
    }

    public static function decodeRemoveRelationRequest($bytes)
    {
        return self::fromCborRemoveRelationRequest(self::csilDecode($bytes));
    }

    public static function toCborRemoveRelationRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveRelationRequest ? $value->relationId : (is_array($value) && array_key_exists('relation_id', $value) ? $value['relation_id'] : null);
        $out['relation_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveRelationRequest($value)
    {
        $value = self::csilRecord($value, 'RemoveRelationRequest', array('relation_id'));
        return new RemoveRelationRequest(array(
            'relation_id' => array_key_exists('relation_id', $value) ? $value['relation_id'] : null,
        ));
    }

    public static function encodeRemoveRelationResponse($value)
    {
        return CBOR::encode(self::toCborRemoveRelationResponse($value));
    }

    public static function decodeRemoveRelationResponse($bytes)
    {
        return self::fromCborRemoveRelationResponse(self::csilDecode($bytes));
    }

    public static function toCborRemoveRelationResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveRelationResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveRelationResponse($value)
    {
        $value = self::csilRecord($value, 'RemoveRelationResponse', array('success'));
        return new RemoveRelationResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeListRelationsRequest($value)
    {
        return CBOR::encode(self::toCborListRelationsRequest($value));
    }

    public static function decodeListRelationsRequest($bytes)
    {
        return self::fromCborListRelationsRequest(self::csilDecode($bytes));
    }

    public static function toCborListRelationsRequest($value)
    {
        $out = array();
        $field = $value instanceof ListRelationsRequest ? $value->subjectType : (is_array($value) && array_key_exists('subject_type', $value) ? $value['subject_type'] : null);
        if ($field !== null) {
            $out['subject_type'] = $field;
        }
        $field = $value instanceof ListRelationsRequest ? $value->subjectId : (is_array($value) && array_key_exists('subject_id', $value) ? $value['subject_id'] : null);
        if ($field !== null) {
            $out['subject_id'] = $field;
        }
        $field = $value instanceof ListRelationsRequest ? $value->objectType : (is_array($value) && array_key_exists('object_type', $value) ? $value['object_type'] : null);
        if ($field !== null) {
            $out['object_type'] = $field;
        }
        $field = $value instanceof ListRelationsRequest ? $value->objectId : (is_array($value) && array_key_exists('object_id', $value) ? $value['object_id'] : null);
        if ($field !== null) {
            $out['object_id'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListRelationsRequest($value)
    {
        $value = self::csilRecord($value, 'ListRelationsRequest', array());
        return new ListRelationsRequest(array(
            'subject_type' => array_key_exists('subject_type', $value) ? $value['subject_type'] : null,
            'subject_id' => array_key_exists('subject_id', $value) ? $value['subject_id'] : null,
            'object_type' => array_key_exists('object_type', $value) ? $value['object_type'] : null,
            'object_id' => array_key_exists('object_id', $value) ? $value['object_id'] : null,
        ));
    }

    public static function encodeListRelationsResponse($value)
    {
        return CBOR::encode(self::toCborListRelationsResponse($value));
    }

    public static function decodeListRelationsResponse($bytes)
    {
        return self::fromCborListRelationsResponse(self::csilDecode($bytes));
    }

    public static function toCborListRelationsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListRelationsResponse ? $value->relations : (is_array($value) && array_key_exists('relations', $value) ? $value['relations'] : null);
        $out['relations'] = array_map(function ($item) { return self::toCborRelation($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListRelationsResponse($value)
    {
        $value = self::csilRecord($value, 'ListRelationsResponse', array('relations'));
        return new ListRelationsResponse(array(
            'relations' => array_key_exists('relations', $value) ? array_map(function ($item) { return self::fromCborRelation($item); }, self::csilList($value['relations'])) : null,
        ));
    }

    public static function encodeCheckPermissionRequest($value)
    {
        return CBOR::encode(self::toCborCheckPermissionRequest($value));
    }

    public static function decodeCheckPermissionRequest($bytes)
    {
        return self::fromCborCheckPermissionRequest(self::csilDecode($bytes));
    }

    public static function toCborCheckPermissionRequest($value)
    {
        $out = array();
        $field = $value instanceof CheckPermissionRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof CheckPermissionRequest ? $value->relation : (is_array($value) && array_key_exists('relation', $value) ? $value['relation'] : null);
        $out['relation'] = $field;
        $field = $value instanceof CheckPermissionRequest ? $value->objectType : (is_array($value) && array_key_exists('object_type', $value) ? $value['object_type'] : null);
        $out['object_type'] = $field;
        $field = $value instanceof CheckPermissionRequest ? $value->objectId : (is_array($value) && array_key_exists('object_id', $value) ? $value['object_id'] : null);
        $out['object_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCheckPermissionRequest($value)
    {
        $value = self::csilRecord($value, 'CheckPermissionRequest', array('user_id', 'relation', 'object_type', 'object_id'));
        return new CheckPermissionRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'relation' => array_key_exists('relation', $value) ? $value['relation'] : null,
            'object_type' => array_key_exists('object_type', $value) ? $value['object_type'] : null,
            'object_id' => array_key_exists('object_id', $value) ? $value['object_id'] : null,
        ));
    }

    public static function encodeCheckPermissionResponse($value)
    {
        return CBOR::encode(self::toCborCheckPermissionResponse($value));
    }

    public static function decodeCheckPermissionResponse($bytes)
    {
        return self::fromCborCheckPermissionResponse(self::csilDecode($bytes));
    }

    public static function toCborCheckPermissionResponse($value)
    {
        $out = array();
        $field = $value instanceof CheckPermissionResponse ? $value->allowed : (is_array($value) && array_key_exists('allowed', $value) ? $value['allowed'] : null);
        $out['allowed'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCheckPermissionResponse($value)
    {
        $value = self::csilRecord($value, 'CheckPermissionResponse', array('allowed'));
        return new CheckPermissionResponse(array(
            'allowed' => array_key_exists('allowed', $value) ? $value['allowed'] : null,
        ));
    }

    public static function encodeChangePasswordRequest($value)
    {
        return CBOR::encode(self::toCborChangePasswordRequest($value));
    }

    public static function decodeChangePasswordRequest($bytes)
    {
        return self::fromCborChangePasswordRequest(self::csilDecode($bytes));
    }

    public static function toCborChangePasswordRequest($value)
    {
        $out = array();
        $field = $value instanceof ChangePasswordRequest ? $value->currentPassword : (is_array($value) && array_key_exists('current_password', $value) ? $value['current_password'] : null);
        $out['current_password'] = $field;
        $field = $value instanceof ChangePasswordRequest ? $value->newPassword : (is_array($value) && array_key_exists('new_password', $value) ? $value['new_password'] : null);
        $out['new_password'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborChangePasswordRequest($value)
    {
        $value = self::csilRecord($value, 'ChangePasswordRequest', array('current_password', 'new_password'));
        return new ChangePasswordRequest(array(
            'current_password' => array_key_exists('current_password', $value) ? $value['current_password'] : null,
            'new_password' => array_key_exists('new_password', $value) ? $value['new_password'] : null,
        ));
    }

    public static function encodeChangePasswordResponse($value)
    {
        return CBOR::encode(self::toCborChangePasswordResponse($value));
    }

    public static function decodeChangePasswordResponse($bytes)
    {
        return self::fromCborChangePasswordResponse(self::csilDecode($bytes));
    }

    public static function toCborChangePasswordResponse($value)
    {
        $out = array();
        $field = $value instanceof ChangePasswordResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborChangePasswordResponse($value)
    {
        $value = self::csilRecord($value, 'ChangePasswordResponse', array('success'));
        return new ChangePasswordResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeGetMyInfoResponse($value)
    {
        return CBOR::encode(self::toCborGetMyInfoResponse($value));
    }

    public static function decodeGetMyInfoResponse($bytes)
    {
        return self::fromCborGetMyInfoResponse(self::csilDecode($bytes));
    }

    public static function toCborGetMyInfoResponse($value)
    {
        $out = array();
        $field = $value instanceof GetMyInfoResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        $field = $value instanceof GetMyInfoResponse ? $value->relations : (is_array($value) && array_key_exists('relations', $value) ? $value['relations'] : null);
        $out['relations'] = array_map(function ($item) { return self::toCborRelation($item); }, $field === null ? array() : $field);
        $field = $value instanceof GetMyInfoResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetMyInfoResponse($value)
    {
        $value = self::csilRecord($value, 'GetMyInfoResponse', array('user', 'relations', 'claims'));
        return new GetMyInfoResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
            'relations' => array_key_exists('relations', $value) ? array_map(function ($item) { return self::fromCborRelation($item); }, self::csilList($value['relations'])) : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, self::csilList($value['claims'])) : null,
        ));
    }

    public static function encodeSetMyClaimRequest($value)
    {
        return CBOR::encode(self::toCborSetMyClaimRequest($value));
    }

    public static function decodeSetMyClaimRequest($bytes)
    {
        return self::fromCborSetMyClaimRequest(self::csilDecode($bytes));
    }

    public static function toCborSetMyClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof SetMyClaimRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetMyClaimRequest ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetMyClaimRequest($value)
    {
        $value = self::csilRecord($value, 'SetMyClaimRequest', array('claim_type', 'claim_value'));
        return new SetMyClaimRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
        ));
    }

    public static function encodeSetMyClaimResponse($value)
    {
        return CBOR::encode(self::toCborSetMyClaimResponse($value));
    }

    public static function decodeSetMyClaimResponse($bytes)
    {
        return self::fromCborSetMyClaimResponse(self::csilDecode($bytes));
    }

    public static function toCborSetMyClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof SetMyClaimResponse ? $value->outcome : (is_array($value) && array_key_exists('outcome', $value) ? $value['outcome'] : null);
        $out['outcome'] = self::toCborSetClaimOutcome($field);
        $field = $value instanceof SetMyClaimResponse ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        if ($field !== null) {
            $out['claim'] = self::toCborClaim($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetMyClaimResponse($value)
    {
        $value = self::csilRecord($value, 'SetMyClaimResponse', array('outcome'));
        return new SetMyClaimResponse(array(
            'outcome' => array_key_exists('outcome', $value) ? self::fromCborSetClaimOutcome($value['outcome']) : null,
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
        ));
    }

    public static function encodeRemoveMyClaimRequest($value)
    {
        return CBOR::encode(self::toCborRemoveMyClaimRequest($value));
    }

    public static function decodeRemoveMyClaimRequest($bytes)
    {
        return self::fromCborRemoveMyClaimRequest(self::csilDecode($bytes));
    }

    public static function toCborRemoveMyClaimRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveMyClaimRequest ? $value->claimId : (is_array($value) && array_key_exists('claim_id', $value) ? $value['claim_id'] : null);
        $out['claim_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveMyClaimRequest($value)
    {
        $value = self::csilRecord($value, 'RemoveMyClaimRequest', array('claim_id'));
        return new RemoveMyClaimRequest(array(
            'claim_id' => array_key_exists('claim_id', $value) ? $value['claim_id'] : null,
        ));
    }

    public static function encodeRemoveMyClaimResponse($value)
    {
        return CBOR::encode(self::toCborRemoveMyClaimResponse($value));
    }

    public static function decodeRemoveMyClaimResponse($bytes)
    {
        return self::fromCborRemoveMyClaimResponse(self::csilDecode($bytes));
    }

    public static function toCborRemoveMyClaimResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveMyClaimResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveMyClaimResponse($value)
    {
        $value = self::csilRecord($value, 'RemoveMyClaimResponse', array('success'));
        return new RemoveMyClaimResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeSetMyClaimSharingRequest($value)
    {
        return CBOR::encode(self::toCborSetMyClaimSharingRequest($value));
    }

    public static function decodeSetMyClaimSharingRequest($bytes)
    {
        return self::fromCborSetMyClaimSharingRequest(self::csilDecode($bytes));
    }

    public static function toCborSetMyClaimSharingRequest($value)
    {
        $out = array();
        $field = $value instanceof SetMyClaimSharingRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetMyClaimSharingRequest ? $value->share : (is_array($value) && array_key_exists('share', $value) ? $value['share'] : null);
        $out['share'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetMyClaimSharingRequest($value)
    {
        $value = self::csilRecord($value, 'SetMyClaimSharingRequest', array('claim_type', 'share'));
        return new SetMyClaimSharingRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'share' => array_key_exists('share', $value) ? $value['share'] : null,
        ));
    }

    public static function encodeSetMyClaimSharingResponse($value)
    {
        return CBOR::encode(self::toCborSetMyClaimSharingResponse($value));
    }

    public static function decodeSetMyClaimSharingResponse($bytes)
    {
        return self::fromCborSetMyClaimSharingResponse(self::csilDecode($bytes));
    }

    public static function toCborSetMyClaimSharingResponse($value)
    {
        $out = array();
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetMyClaimSharingResponse($value)
    {
        $value = self::csilRecord($value, 'SetMyClaimSharingResponse', array());
        return new SetMyClaimSharingResponse(array(
        ));
    }

    public static function encodeMyClaimSetting($value)
    {
        return CBOR::encode(self::toCborMyClaimSetting($value));
    }

    public static function decodeMyClaimSetting($bytes)
    {
        return self::fromCborMyClaimSetting(self::csilDecode($bytes));
    }

    public static function toCborMyClaimSetting($value)
    {
        $out = array();
        $field = $value instanceof MyClaimSetting ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof MyClaimSetting ? $value->keepVerified : (is_array($value) && array_key_exists('keep_verified', $value) ? $value['keep_verified'] : null);
        $out['keep_verified'] = $field;
        $field = $value instanceof MyClaimSetting ? $value->sharedWithEveryApp : (is_array($value) && array_key_exists('shared_with_every_app', $value) ? $value['shared_with_every_app'] : null);
        $out['shared_with_every_app'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborMyClaimSetting($value)
    {
        $value = self::csilRecord($value, 'MyClaimSetting', array('claim_type', 'keep_verified', 'shared_with_every_app'));
        return new MyClaimSetting(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'keep_verified' => array_key_exists('keep_verified', $value) ? $value['keep_verified'] : null,
            'shared_with_every_app' => array_key_exists('shared_with_every_app', $value) ? $value['shared_with_every_app'] : null,
        ));
    }

    public static function encodeMyClaimSettingsResponse($value)
    {
        return CBOR::encode(self::toCborMyClaimSettingsResponse($value));
    }

    public static function decodeMyClaimSettingsResponse($bytes)
    {
        return self::fromCborMyClaimSettingsResponse(self::csilDecode($bytes));
    }

    public static function toCborMyClaimSettingsResponse($value)
    {
        $out = array();
        $field = $value instanceof MyClaimSettingsResponse ? $value->settings : (is_array($value) && array_key_exists('settings', $value) ? $value['settings'] : null);
        $out['settings'] = array_map(function ($item) { return self::toCborMyClaimSetting($item); }, $field === null ? array() : $field);
        $field = $value instanceof MyClaimSettingsResponse ? $value->profiles : (is_array($value) && array_key_exists('profiles', $value) ? $value['profiles'] : null);
        $out['profiles'] = array_map(function ($item) { return self::toCborProfile($item); }, $field === null ? array() : $field);
        $field = $value instanceof MyClaimSettingsResponse ? $value->maxProfiles : (is_array($value) && array_key_exists('max_profiles', $value) ? $value['max_profiles'] : null);
        $out['max_profiles'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborMyClaimSettingsResponse($value)
    {
        $value = self::csilRecord($value, 'MyClaimSettingsResponse', array('settings', 'profiles', 'max_profiles'));
        return new MyClaimSettingsResponse(array(
            'settings' => array_key_exists('settings', $value) ? array_map(function ($item) { return self::fromCborMyClaimSetting($item); }, self::csilList($value['settings'])) : null,
            'profiles' => array_key_exists('profiles', $value) ? array_map(function ($item) { return self::fromCborProfile($item); }, self::csilList($value['profiles'])) : null,
            'max_profiles' => array_key_exists('max_profiles', $value) ? $value['max_profiles'] : null,
        ));
    }

    public static function encodeSetMyClaimKeepVerifiedRequest($value)
    {
        return CBOR::encode(self::toCborSetMyClaimKeepVerifiedRequest($value));
    }

    public static function decodeSetMyClaimKeepVerifiedRequest($bytes)
    {
        return self::fromCborSetMyClaimKeepVerifiedRequest(self::csilDecode($bytes));
    }

    public static function toCborSetMyClaimKeepVerifiedRequest($value)
    {
        $out = array();
        $field = $value instanceof SetMyClaimKeepVerifiedRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof SetMyClaimKeepVerifiedRequest ? $value->keepVerified : (is_array($value) && array_key_exists('keep_verified', $value) ? $value['keep_verified'] : null);
        $out['keep_verified'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetMyClaimKeepVerifiedRequest($value)
    {
        $value = self::csilRecord($value, 'SetMyClaimKeepVerifiedRequest', array('claim_type', 'keep_verified'));
        return new SetMyClaimKeepVerifiedRequest(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'keep_verified' => array_key_exists('keep_verified', $value) ? $value['keep_verified'] : null,
        ));
    }

    public static function encodeSetMyClaimKeepVerifiedResponse($value)
    {
        return CBOR::encode(self::toCborSetMyClaimKeepVerifiedResponse($value));
    }

    public static function decodeSetMyClaimKeepVerifiedResponse($bytes)
    {
        return self::fromCborSetMyClaimKeepVerifiedResponse(self::csilDecode($bytes));
    }

    public static function toCborSetMyClaimKeepVerifiedResponse($value)
    {
        $out = array();
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetMyClaimKeepVerifiedResponse($value)
    {
        $value = self::csilRecord($value, 'SetMyClaimKeepVerifiedResponse', array());
        return new SetMyClaimKeepVerifiedResponse(array(
        ));
    }

    public static function encodeProfile($value)
    {
        return CBOR::encode(self::toCborProfile($value));
    }

    public static function decodeProfile($bytes)
    {
        return self::fromCborProfile(self::csilDecode($bytes));
    }

    public static function toCborProfile($value)
    {
        $out = array();
        $field = $value instanceof Profile ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof Profile ? $value->accountId : (is_array($value) && array_key_exists('account_id', $value) ? $value['account_id'] : null);
        $out['account_id'] = $field;
        $field = $value instanceof Profile ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof Profile ? $value->isRoot : (is_array($value) && array_key_exists('is_root', $value) ? $value['is_root'] : null);
        $out['is_root'] = $field;
        $field = $value instanceof Profile ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        if ($field !== null) {
            $out['label'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborProfile($value)
    {
        $value = self::csilRecord($value, 'Profile', array('id', 'account_id', 'domain', 'is_root'));
        return new Profile(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'account_id' => array_key_exists('account_id', $value) ? $value['account_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'is_root' => array_key_exists('is_root', $value) ? $value['is_root'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
        ));
    }

    public static function encodeCreateProfileRequest($value)
    {
        return CBOR::encode(self::toCborCreateProfileRequest($value));
    }

    public static function decodeCreateProfileRequest($bytes)
    {
        return self::fromCborCreateProfileRequest(self::csilDecode($bytes));
    }

    public static function toCborCreateProfileRequest($value)
    {
        $out = array();
        $field = $value instanceof CreateProfileRequest ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        if ($field !== null) {
            $out['label'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCreateProfileRequest($value)
    {
        $value = self::csilRecord($value, 'CreateProfileRequest', array());
        return new CreateProfileRequest(array(
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
        ));
    }

    public static function encodeCreateProfileResponse($value)
    {
        return CBOR::encode(self::toCborCreateProfileResponse($value));
    }

    public static function decodeCreateProfileResponse($bytes)
    {
        return self::fromCborCreateProfileResponse(self::csilDecode($bytes));
    }

    public static function toCborCreateProfileResponse($value)
    {
        $out = array();
        $field = $value instanceof CreateProfileResponse ? $value->profile : (is_array($value) && array_key_exists('profile', $value) ? $value['profile'] : null);
        $out['profile'] = self::toCborProfile($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCreateProfileResponse($value)
    {
        $value = self::csilRecord($value, 'CreateProfileResponse', array('profile'));
        return new CreateProfileResponse(array(
            'profile' => array_key_exists('profile', $value) ? self::fromCborProfile($value['profile']) : null,
        ));
    }

    public static function encodeRequestVerificationRequest($value)
    {
        return CBOR::encode(self::toCborRequestVerificationRequest($value));
    }

    public static function decodeRequestVerificationRequest($bytes)
    {
        return self::fromCborRequestVerificationRequest(self::csilDecode($bytes));
    }

    public static function toCborRequestVerificationRequest($value)
    {
        $out = array();
        $field = $value instanceof RequestVerificationRequest ? $value->issuerDomain : (is_array($value) && array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null);
        $out['issuer_domain'] = $field;
        $field = $value instanceof RequestVerificationRequest ? $value->requestedClaimTypes : (is_array($value) && array_key_exists('requested_claim_types', $value) ? $value['requested_claim_types'] : null);
        $out['requested_claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRequestVerificationRequest($value)
    {
        $value = self::csilRecord($value, 'RequestVerificationRequest', array('issuer_domain', 'requested_claim_types'));
        return new RequestVerificationRequest(array(
            'issuer_domain' => array_key_exists('issuer_domain', $value) ? $value['issuer_domain'] : null,
            'requested_claim_types' => array_key_exists('requested_claim_types', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['requested_claim_types'])) : null,
        ));
    }

    public static function encodeRequestVerificationResponse($value)
    {
        return CBOR::encode(self::toCborRequestVerificationResponse($value));
    }

    public static function decodeRequestVerificationResponse($bytes)
    {
        return self::fromCborRequestVerificationResponse(self::csilDecode($bytes));
    }

    public static function toCborRequestVerificationResponse($value)
    {
        $out = array();
        $field = $value instanceof RequestVerificationResponse ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = self::toCborSignedSigningRequest($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRequestVerificationResponse($value)
    {
        $value = self::csilRecord($value, 'RequestVerificationResponse', array('signed_request'));
        return new RequestVerificationResponse(array(
            'signed_request' => array_key_exists('signed_request', $value) ? self::fromCborSignedSigningRequest($value['signed_request']) : null,
        ));
    }

    public static function encodePasswordPolicy($value)
    {
        return CBOR::encode(self::toCborPasswordPolicy($value));
    }

    public static function decodePasswordPolicy($bytes)
    {
        return self::fromCborPasswordPolicy(self::csilDecode($bytes));
    }

    public static function toCborPasswordPolicy($value)
    {
        $out = array();
        $field = $value instanceof PasswordPolicy ? $value->minLength : (is_array($value) && array_key_exists('min_length', $value) ? $value['min_length'] : null);
        $out['min_length'] = $field;
        $field = $value instanceof PasswordPolicy ? $value->maxLength : (is_array($value) && array_key_exists('max_length', $value) ? $value['max_length'] : null);
        $out['max_length'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPasswordPolicy($value)
    {
        $value = self::csilRecord($value, 'PasswordPolicy', array('min_length', 'max_length'));
        return new PasswordPolicy(array(
            'min_length' => array_key_exists('min_length', $value) ? $value['min_length'] : null,
            'max_length' => array_key_exists('max_length', $value) ? $value['max_length'] : null,
        ));
    }

    public static function encodeBrowserSessionInfo($value)
    {
        return CBOR::encode(self::toCborBrowserSessionInfo($value));
    }

    public static function decodeBrowserSessionInfo($bytes)
    {
        return self::fromCborBrowserSessionInfo(self::csilDecode($bytes));
    }

    public static function toCborBrowserSessionInfo($value)
    {
        $out = array();
        $field = $value instanceof BrowserSessionInfo ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        $field = $value instanceof BrowserSessionInfo ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof BrowserSessionInfo ? $value->authenticatedAt : (is_array($value) && array_key_exists('authenticated_at', $value) ? $value['authenticated_at'] : null);
        $out['authenticated_at'] = self::timestampToCbor($field);
        $field = $value instanceof BrowserSessionInfo ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof BrowserSessionInfo ? $value->authenticationMethods : (is_array($value) && array_key_exists('authentication_methods', $value) ? $value['authentication_methods'] : null);
        $out['authentication_methods'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserSessionInfo($value)
    {
        $value = self::csilRecord($value, 'BrowserSessionInfo', array('user', 'issued_at', 'authenticated_at', 'expires_at', 'authentication_methods'));
        return new BrowserSessionInfo(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
            'authenticated_at' => array_key_exists('authenticated_at', $value) ? self::timestampFromCbor($value['authenticated_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'authentication_methods' => array_key_exists('authentication_methods', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['authentication_methods'])) : null,
        ));
    }

    public static function encodeSessionPasswordLoginRequest($value)
    {
        return CBOR::encode(self::toCborSessionPasswordLoginRequest($value));
    }

    public static function decodeSessionPasswordLoginRequest($bytes)
    {
        return self::fromCborSessionPasswordLoginRequest(self::csilDecode($bytes));
    }

    public static function toCborSessionPasswordLoginRequest($value)
    {
        $out = array();
        $field = $value instanceof SessionPasswordLoginRequest ? $value->username : (is_array($value) && array_key_exists('username', $value) ? $value['username'] : null);
        $out['username'] = $field;
        $field = $value instanceof SessionPasswordLoginRequest ? $value->password : (is_array($value) && array_key_exists('password', $value) ? $value['password'] : null);
        $out['password'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSessionPasswordLoginRequest($value)
    {
        $value = self::csilRecord($value, 'SessionPasswordLoginRequest', array('username', 'password'));
        return new SessionPasswordLoginRequest(array(
            'username' => array_key_exists('username', $value) ? $value['username'] : null,
            'password' => array_key_exists('password', $value) ? $value['password'] : null,
        ));
    }

    public static function encodeSessionPasswordLoginResponse($value)
    {
        return CBOR::encode(self::toCborSessionPasswordLoginResponse($value));
    }

    public static function decodeSessionPasswordLoginResponse($bytes)
    {
        return self::fromCborSessionPasswordLoginResponse(self::csilDecode($bytes));
    }

    public static function toCborSessionPasswordLoginResponse($value)
    {
        $out = array();
        $field = $value instanceof SessionPasswordLoginResponse ? $value->session : (is_array($value) && array_key_exists('session', $value) ? $value['session'] : null);
        $out['session'] = self::toCborBrowserSessionInfo($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSessionPasswordLoginResponse($value)
    {
        $value = self::csilRecord($value, 'SessionPasswordLoginResponse', array('session'));
        return new SessionPasswordLoginResponse(array(
            'session' => array_key_exists('session', $value) ? self::fromCborBrowserSessionInfo($value['session']) : null,
        ));
    }

    public static function encodeSessionCurrentResponse($value)
    {
        return CBOR::encode(self::toCborSessionCurrentResponse($value));
    }

    public static function decodeSessionCurrentResponse($bytes)
    {
        return self::fromCborSessionCurrentResponse(self::csilDecode($bytes));
    }

    public static function toCborSessionCurrentResponse($value)
    {
        $out = array();
        $field = $value instanceof SessionCurrentResponse ? $value->session : (is_array($value) && array_key_exists('session', $value) ? $value['session'] : null);
        $out['session'] = self::toCborBrowserSessionInfo($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSessionCurrentResponse($value)
    {
        $value = self::csilRecord($value, 'SessionCurrentResponse', array('session'));
        return new SessionCurrentResponse(array(
            'session' => array_key_exists('session', $value) ? self::fromCborBrowserSessionInfo($value['session']) : null,
        ));
    }

    public static function encodeSessionLogoutResponse($value)
    {
        return CBOR::encode(self::toCborSessionLogoutResponse($value));
    }

    public static function decodeSessionLogoutResponse($bytes)
    {
        return self::fromCborSessionLogoutResponse(self::csilDecode($bytes));
    }

    public static function toCborSessionLogoutResponse($value)
    {
        $out = array();
        $field = $value instanceof SessionLogoutResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSessionLogoutResponse($value)
    {
        $value = self::csilRecord($value, 'SessionLogoutResponse', array('success'));
        return new SessionLogoutResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeIntrospectBrowserSessionRequest($value)
    {
        return CBOR::encode(self::toCborIntrospectBrowserSessionRequest($value));
    }

    public static function decodeIntrospectBrowserSessionRequest($bytes)
    {
        return self::fromCborIntrospectBrowserSessionRequest(self::csilDecode($bytes));
    }

    public static function toCborIntrospectBrowserSessionRequest($value)
    {
        $out = array();
        $field = $value instanceof IntrospectBrowserSessionRequest ? $value->sessionCookie : (is_array($value) && array_key_exists('session_cookie', $value) ? $value['session_cookie'] : null);
        $out['session_cookie'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborIntrospectBrowserSessionRequest($value)
    {
        $value = self::csilRecord($value, 'IntrospectBrowserSessionRequest', array('session_cookie'));
        return new IntrospectBrowserSessionRequest(array(
            'session_cookie' => array_key_exists('session_cookie', $value) ? $value['session_cookie'] : null,
        ));
    }

    public static function encodeIntrospectBrowserSessionResponse($value)
    {
        return CBOR::encode(self::toCborIntrospectBrowserSessionResponse($value));
    }

    public static function decodeIntrospectBrowserSessionResponse($bytes)
    {
        return self::fromCborIntrospectBrowserSessionResponse(self::csilDecode($bytes));
    }

    public static function toCborIntrospectBrowserSessionResponse($value)
    {
        $out = array();
        $field = $value instanceof IntrospectBrowserSessionResponse ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof IntrospectBrowserSessionResponse ? $value->userDomain : (is_array($value) && array_key_exists('user_domain', $value) ? $value['user_domain'] : null);
        $out['user_domain'] = $field;
        $field = $value instanceof IntrospectBrowserSessionResponse ? $value->authenticatedAt : (is_array($value) && array_key_exists('authenticated_at', $value) ? $value['authenticated_at'] : null);
        $out['authenticated_at'] = self::timestampToCbor($field);
        $field = $value instanceof IntrospectBrowserSessionResponse ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof IntrospectBrowserSessionResponse ? $value->authenticationMethods : (is_array($value) && array_key_exists('authentication_methods', $value) ? $value['authentication_methods'] : null);
        $out['authentication_methods'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborIntrospectBrowserSessionResponse($value)
    {
        $value = self::csilRecord($value, 'IntrospectBrowserSessionResponse', array('user_id', 'user_domain', 'authenticated_at', 'expires_at', 'authentication_methods'));
        return new IntrospectBrowserSessionResponse(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'user_domain' => array_key_exists('user_domain', $value) ? $value['user_domain'] : null,
            'authenticated_at' => array_key_exists('authenticated_at', $value) ? self::timestampFromCbor($value['authenticated_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'authentication_methods' => array_key_exists('authentication_methods', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['authentication_methods'])) : null,
        ));
    }

    public static function encodeNotificationCapability($value)
    {
        return CBOR::encode(self::toCborNotificationCapability($value));
    }

    public static function decodeNotificationCapability($bytes)
    {
        return self::fromCborNotificationCapability(self::csilDecode($bytes));
    }

    public static function toCborNotificationCapability($value)
    {
        $out = array();
        $field = $value instanceof NotificationCapability ? $value->purpose : (is_array($value) && array_key_exists('purpose', $value) ? $value['purpose'] : null);
        $out['purpose'] = self::toCborNotificationPurpose($field);
        $field = $value instanceof NotificationCapability ? $value->channel : (is_array($value) && array_key_exists('channel', $value) ? $value['channel'] : null);
        $out['channel'] = self::toCborNotificationChannel($field);
        $field = $value instanceof NotificationCapability ? $value->destinationKind : (is_array($value) && array_key_exists('destination_kind', $value) ? $value['destination_kind'] : null);
        $out['destination_kind'] = self::toCborDestinationKind($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborNotificationCapability($value)
    {
        $value = self::csilRecord($value, 'NotificationCapability', array('purpose', 'channel', 'destination_kind'));
        return new NotificationCapability(array(
            'purpose' => array_key_exists('purpose', $value) ? self::fromCborNotificationPurpose($value['purpose']) : null,
            'channel' => array_key_exists('channel', $value) ? self::fromCborNotificationChannel($value['channel']) : null,
            'destination_kind' => array_key_exists('destination_kind', $value) ? self::fromCborDestinationKind($value['destination_kind']) : null,
        ));
    }

    public static function encodeGetNotificationCapabilitiesResponse($value)
    {
        return CBOR::encode(self::toCborGetNotificationCapabilitiesResponse($value));
    }

    public static function decodeGetNotificationCapabilitiesResponse($bytes)
    {
        return self::fromCborGetNotificationCapabilitiesResponse(self::csilDecode($bytes));
    }

    public static function toCborGetNotificationCapabilitiesResponse($value)
    {
        $out = array();
        $field = $value instanceof GetNotificationCapabilitiesResponse ? $value->capabilities : (is_array($value) && array_key_exists('capabilities', $value) ? $value['capabilities'] : null);
        $out['capabilities'] = array_map(function ($item) { return self::toCborNotificationCapability($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetNotificationCapabilitiesResponse($value)
    {
        $value = self::csilRecord($value, 'GetNotificationCapabilitiesResponse', array('capabilities'));
        return new GetNotificationCapabilitiesResponse(array(
            'capabilities' => array_key_exists('capabilities', $value) ? array_map(function ($item) { return self::fromCborNotificationCapability($item); }, self::csilList($value['capabilities'])) : null,
        ));
    }

    public static function encodeVerifiedContactMethod($value)
    {
        return CBOR::encode(self::toCborVerifiedContactMethod($value));
    }

    public static function decodeVerifiedContactMethod($bytes)
    {
        return self::fromCborVerifiedContactMethod(self::csilDecode($bytes));
    }

    public static function toCborVerifiedContactMethod($value)
    {
        $out = array();
        $field = $value instanceof VerifiedContactMethod ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof VerifiedContactMethod ? $value->channel : (is_array($value) && array_key_exists('channel', $value) ? $value['channel'] : null);
        $out['channel'] = self::toCborNotificationChannel($field);
        $field = $value instanceof VerifiedContactMethod ? $value->destination : (is_array($value) && array_key_exists('destination', $value) ? $value['destination'] : null);
        $out['destination'] = $field;
        $field = $value instanceof VerifiedContactMethod ? $value->verifiedAt : (is_array($value) && array_key_exists('verified_at', $value) ? $value['verified_at'] : null);
        $out['verified_at'] = self::timestampToCbor($field);
        $field = $value instanceof VerifiedContactMethod ? $value->purposes : (is_array($value) && array_key_exists('purposes', $value) ? $value['purposes'] : null);
        $out['purposes'] = array_map(function ($item) { return self::toCborNotificationPurpose($item); }, $field === null ? array() : $field);
        $field = $value instanceof VerifiedContactMethod ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = self::timestampToCbor($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborVerifiedContactMethod($value)
    {
        $value = self::csilRecord($value, 'VerifiedContactMethod', array('id', 'channel', 'destination', 'verified_at', 'purposes'));
        return new VerifiedContactMethod(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'channel' => array_key_exists('channel', $value) ? self::fromCborNotificationChannel($value['channel']) : null,
            'destination' => array_key_exists('destination', $value) ? $value['destination'] : null,
            'verified_at' => array_key_exists('verified_at', $value) ? self::timestampFromCbor($value['verified_at']) : null,
            'purposes' => array_key_exists('purposes', $value) ? array_map(function ($item) { return self::fromCborNotificationPurpose($item); }, self::csilList($value['purposes'])) : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
        ));
    }

    public static function encodeListVerifiedContactMethodsResponse($value)
    {
        return CBOR::encode(self::toCborListVerifiedContactMethodsResponse($value));
    }

    public static function decodeListVerifiedContactMethodsResponse($bytes)
    {
        return self::fromCborListVerifiedContactMethodsResponse(self::csilDecode($bytes));
    }

    public static function toCborListVerifiedContactMethodsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListVerifiedContactMethodsResponse ? $value->contactMethods : (is_array($value) && array_key_exists('contact_methods', $value) ? $value['contact_methods'] : null);
        $out['contact_methods'] = array_map(function ($item) { return self::toCborVerifiedContactMethod($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListVerifiedContactMethodsResponse($value)
    {
        $value = self::csilRecord($value, 'ListVerifiedContactMethodsResponse', array('contact_methods'));
        return new ListVerifiedContactMethodsResponse(array(
            'contact_methods' => array_key_exists('contact_methods', $value) ? array_map(function ($item) { return self::fromCborVerifiedContactMethod($item); }, self::csilList($value['contact_methods'])) : null,
        ));
    }

    public static function encodeRevokeVerifiedContactMethodRequest($value)
    {
        return CBOR::encode(self::toCborRevokeVerifiedContactMethodRequest($value));
    }

    public static function decodeRevokeVerifiedContactMethodRequest($bytes)
    {
        return self::fromCborRevokeVerifiedContactMethodRequest(self::csilDecode($bytes));
    }

    public static function toCborRevokeVerifiedContactMethodRequest($value)
    {
        $out = array();
        $field = $value instanceof RevokeVerifiedContactMethodRequest ? $value->contactMethodId : (is_array($value) && array_key_exists('contact_method_id', $value) ? $value['contact_method_id'] : null);
        $out['contact_method_id'] = $field;
        $field = $value instanceof RevokeVerifiedContactMethodRequest ? $value->currentPassword : (is_array($value) && array_key_exists('current_password', $value) ? $value['current_password'] : null);
        $out['current_password'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeVerifiedContactMethodRequest($value)
    {
        $value = self::csilRecord($value, 'RevokeVerifiedContactMethodRequest', array('contact_method_id', 'current_password'));
        return new RevokeVerifiedContactMethodRequest(array(
            'contact_method_id' => array_key_exists('contact_method_id', $value) ? $value['contact_method_id'] : null,
            'current_password' => array_key_exists('current_password', $value) ? $value['current_password'] : null,
        ));
    }

    public static function encodeRevokeVerifiedContactMethodResponse($value)
    {
        return CBOR::encode(self::toCborRevokeVerifiedContactMethodResponse($value));
    }

    public static function decodeRevokeVerifiedContactMethodResponse($bytes)
    {
        return self::fromCborRevokeVerifiedContactMethodResponse(self::csilDecode($bytes));
    }

    public static function toCborRevokeVerifiedContactMethodResponse($value)
    {
        $out = array();
        $field = $value instanceof RevokeVerifiedContactMethodResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeVerifiedContactMethodResponse($value)
    {
        $value = self::csilRecord($value, 'RevokeVerifiedContactMethodResponse', array('success'));
        return new RevokeVerifiedContactMethodResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeRequestContactVerificationRequest($value)
    {
        return CBOR::encode(self::toCborRequestContactVerificationRequest($value));
    }

    public static function decodeRequestContactVerificationRequest($bytes)
    {
        return self::fromCborRequestContactVerificationRequest(self::csilDecode($bytes));
    }

    public static function toCborRequestContactVerificationRequest($value)
    {
        $out = array();
        $field = $value instanceof RequestContactVerificationRequest ? $value->channel : (is_array($value) && array_key_exists('channel', $value) ? $value['channel'] : null);
        $out['channel'] = self::toCborNotificationChannel($field);
        $field = $value instanceof RequestContactVerificationRequest ? $value->destination : (is_array($value) && array_key_exists('destination', $value) ? $value['destination'] : null);
        $out['destination'] = $field;
        $field = $value instanceof RequestContactVerificationRequest ? $value->currentPassword : (is_array($value) && array_key_exists('current_password', $value) ? $value['current_password'] : null);
        $out['current_password'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRequestContactVerificationRequest($value)
    {
        $value = self::csilRecord($value, 'RequestContactVerificationRequest', array('channel', 'destination', 'current_password'));
        return new RequestContactVerificationRequest(array(
            'channel' => array_key_exists('channel', $value) ? self::fromCborNotificationChannel($value['channel']) : null,
            'destination' => array_key_exists('destination', $value) ? $value['destination'] : null,
            'current_password' => array_key_exists('current_password', $value) ? $value['current_password'] : null,
        ));
    }

    public static function encodeRequestContactVerificationResponse($value)
    {
        return CBOR::encode(self::toCborRequestContactVerificationResponse($value));
    }

    public static function decodeRequestContactVerificationResponse($bytes)
    {
        return self::fromCborRequestContactVerificationResponse(self::csilDecode($bytes));
    }

    public static function toCborRequestContactVerificationResponse($value)
    {
        $out = array();
        $field = $value instanceof RequestContactVerificationResponse ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRequestContactVerificationResponse($value)
    {
        $value = self::csilRecord($value, 'RequestContactVerificationResponse', array('expires_at'));
        return new RequestContactVerificationResponse(array(
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeConfirmContactVerificationRequest($value)
    {
        return CBOR::encode(self::toCborConfirmContactVerificationRequest($value));
    }

    public static function decodeConfirmContactVerificationRequest($bytes)
    {
        return self::fromCborConfirmContactVerificationRequest(self::csilDecode($bytes));
    }

    public static function toCborConfirmContactVerificationRequest($value)
    {
        $out = array();
        $field = $value instanceof ConfirmContactVerificationRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborConfirmContactVerificationRequest($value)
    {
        $value = self::csilRecord($value, 'ConfirmContactVerificationRequest', array('token'));
        return new ConfirmContactVerificationRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
        ));
    }

    public static function encodeConfirmContactVerificationResponse($value)
    {
        return CBOR::encode(self::toCborConfirmContactVerificationResponse($value));
    }

    public static function decodeConfirmContactVerificationResponse($bytes)
    {
        return self::fromCborConfirmContactVerificationResponse(self::csilDecode($bytes));
    }

    public static function toCborConfirmContactVerificationResponse($value)
    {
        $out = array();
        $field = $value instanceof ConfirmContactVerificationResponse ? $value->contactMethod : (is_array($value) && array_key_exists('contact_method', $value) ? $value['contact_method'] : null);
        $out['contact_method'] = self::toCborVerifiedContactMethod($field);
        $field = $value instanceof ConfirmContactVerificationResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborConfirmContactVerificationResponse($value)
    {
        $value = self::csilRecord($value, 'ConfirmContactVerificationResponse', array('contact_method', 'claims'));
        return new ConfirmContactVerificationResponse(array(
            'contact_method' => array_key_exists('contact_method', $value) ? self::fromCborVerifiedContactMethod($value['contact_method']) : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, self::csilList($value['claims'])) : null,
        ));
    }

    public static function encodeRequestPasswordRecoveryRequest($value)
    {
        return CBOR::encode(self::toCborRequestPasswordRecoveryRequest($value));
    }

    public static function decodeRequestPasswordRecoveryRequest($bytes)
    {
        return self::fromCborRequestPasswordRecoveryRequest(self::csilDecode($bytes));
    }

    public static function toCborRequestPasswordRecoveryRequest($value)
    {
        $out = array();
        $field = $value instanceof RequestPasswordRecoveryRequest ? $value->identifier : (is_array($value) && array_key_exists('identifier', $value) ? $value['identifier'] : null);
        $out['identifier'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRequestPasswordRecoveryRequest($value)
    {
        $value = self::csilRecord($value, 'RequestPasswordRecoveryRequest', array('identifier'));
        return new RequestPasswordRecoveryRequest(array(
            'identifier' => array_key_exists('identifier', $value) ? $value['identifier'] : null,
        ));
    }

    public static function encodeRequestPasswordRecoveryResponse($value)
    {
        return CBOR::encode(self::toCborRequestPasswordRecoveryResponse($value));
    }

    public static function decodeRequestPasswordRecoveryResponse($bytes)
    {
        return self::fromCborRequestPasswordRecoveryResponse(self::csilDecode($bytes));
    }

    public static function toCborRequestPasswordRecoveryResponse($value)
    {
        $out = array();
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRequestPasswordRecoveryResponse($value)
    {
        $value = self::csilRecord($value, 'RequestPasswordRecoveryResponse', array());
        return new RequestPasswordRecoveryResponse(array(
        ));
    }

    public static function encodeValidatePasswordRecoveryRequest($value)
    {
        return CBOR::encode(self::toCborValidatePasswordRecoveryRequest($value));
    }

    public static function decodeValidatePasswordRecoveryRequest($bytes)
    {
        return self::fromCborValidatePasswordRecoveryRequest(self::csilDecode($bytes));
    }

    public static function toCborValidatePasswordRecoveryRequest($value)
    {
        $out = array();
        $field = $value instanceof ValidatePasswordRecoveryRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborValidatePasswordRecoveryRequest($value)
    {
        $value = self::csilRecord($value, 'ValidatePasswordRecoveryRequest', array('token'));
        return new ValidatePasswordRecoveryRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
        ));
    }

    public static function encodeValidatePasswordRecoveryResponse($value)
    {
        return CBOR::encode(self::toCborValidatePasswordRecoveryResponse($value));
    }

    public static function decodeValidatePasswordRecoveryResponse($bytes)
    {
        return self::fromCborValidatePasswordRecoveryResponse(self::csilDecode($bytes));
    }

    public static function toCborValidatePasswordRecoveryResponse($value)
    {
        $out = array();
        $field = $value instanceof ValidatePasswordRecoveryResponse ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof ValidatePasswordRecoveryResponse ? $value->passwordPolicy : (is_array($value) && array_key_exists('password_policy', $value) ? $value['password_policy'] : null);
        $out['password_policy'] = self::toCborPasswordPolicy($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborValidatePasswordRecoveryResponse($value)
    {
        $value = self::csilRecord($value, 'ValidatePasswordRecoveryResponse', array('expires_at', 'password_policy'));
        return new ValidatePasswordRecoveryResponse(array(
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'password_policy' => array_key_exists('password_policy', $value) ? self::fromCborPasswordPolicy($value['password_policy']) : null,
        ));
    }

    public static function encodeCompletePasswordRecoveryRequest($value)
    {
        return CBOR::encode(self::toCborCompletePasswordRecoveryRequest($value));
    }

    public static function decodeCompletePasswordRecoveryRequest($bytes)
    {
        return self::fromCborCompletePasswordRecoveryRequest(self::csilDecode($bytes));
    }

    public static function toCborCompletePasswordRecoveryRequest($value)
    {
        $out = array();
        $field = $value instanceof CompletePasswordRecoveryRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = $field;
        $field = $value instanceof CompletePasswordRecoveryRequest ? $value->newPassword : (is_array($value) && array_key_exists('new_password', $value) ? $value['new_password'] : null);
        $out['new_password'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCompletePasswordRecoveryRequest($value)
    {
        $value = self::csilRecord($value, 'CompletePasswordRecoveryRequest', array('token', 'new_password'));
        return new CompletePasswordRecoveryRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
            'new_password' => array_key_exists('new_password', $value) ? $value['new_password'] : null,
        ));
    }

    public static function encodeCompletePasswordRecoveryResponse($value)
    {
        return CBOR::encode(self::toCborCompletePasswordRecoveryResponse($value));
    }

    public static function decodeCompletePasswordRecoveryResponse($bytes)
    {
        return self::fromCborCompletePasswordRecoveryResponse(self::csilDecode($bytes));
    }

    public static function toCborCompletePasswordRecoveryResponse($value)
    {
        $out = array();
        $field = $value instanceof CompletePasswordRecoveryResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborCompletePasswordRecoveryResponse($value)
    {
        $value = self::csilRecord($value, 'CompletePasswordRecoveryResponse', array('success'));
        return new CompletePasswordRecoveryResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodeBrowserAuthorizationInspectRequest($value)
    {
        return CBOR::encode(self::toCborBrowserAuthorizationInspectRequest($value));
    }

    public static function decodeBrowserAuthorizationInspectRequest($bytes)
    {
        return self::fromCborBrowserAuthorizationInspectRequest(self::csilDecode($bytes));
    }

    public static function toCborBrowserAuthorizationInspectRequest($value)
    {
        $out = array();
        $field = $value instanceof BrowserAuthorizationInspectRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserAuthorizationInspectRequest($value)
    {
        $value = self::csilRecord($value, 'BrowserAuthorizationInspectRequest', array('signed_request'));
        return new BrowserAuthorizationInspectRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
        ));
    }

    public static function encodeBrowserConsentClaim($value)
    {
        return CBOR::encode(self::toCborBrowserConsentClaim($value));
    }

    public static function decodeBrowserConsentClaim($bytes)
    {
        return self::fromCborBrowserConsentClaim(self::csilDecode($bytes));
    }

    public static function toCborBrowserConsentClaim($value)
    {
        $out = array();
        $field = $value instanceof BrowserConsentClaim ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->label : (is_array($value) && array_key_exists('label', $value) ? $value['label'] : null);
        $out['label'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->datatype : (is_array($value) && array_key_exists('datatype', $value) ? $value['datatype'] : null);
        $out['datatype'] = self::toCborClaimValueType($field);
        $field = $value instanceof BrowserConsentClaim ? $value->required : (is_array($value) && array_key_exists('required', $value) ? $value['required'] : null);
        $out['required'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->available : (is_array($value) && array_key_exists('available', $value) ? $value['available'] : null);
        $out['available'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->defaultGranted : (is_array($value) && array_key_exists('default_granted', $value) ? $value['default_granted'] : null);
        $out['default_granted'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->policy : (is_array($value) && array_key_exists('policy', $value) ? $value['policy'] : null);
        $out['policy'] = self::toCborConsentRowPolicy($field);
        $field = $value instanceof BrowserConsentClaim ? $value->userSettable : (is_array($value) && array_key_exists('user_settable', $value) ? $value['user_settable'] : null);
        $out['user_settable'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->maxBytes : (is_array($value) && array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null);
        $out['max_bytes'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->requiresApproval : (is_array($value) && array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null);
        $out['requires_approval'] = $field;
        $field = $value instanceof BrowserConsentClaim ? $value->newlyRequested : (is_array($value) && array_key_exists('newly_requested', $value) ? $value['newly_requested'] : null);
        if ($field !== null) {
            $out['newly_requested'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserConsentClaim($value)
    {
        $value = self::csilRecord($value, 'BrowserConsentClaim', array('claim_type', 'label', 'datatype', 'required', 'available', 'default_granted', 'policy', 'user_settable', 'max_bytes', 'requires_approval'));
        return new BrowserConsentClaim(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'label' => array_key_exists('label', $value) ? $value['label'] : null,
            'datatype' => array_key_exists('datatype', $value) ? self::fromCborClaimValueType($value['datatype']) : null,
            'required' => array_key_exists('required', $value) ? $value['required'] : null,
            'available' => array_key_exists('available', $value) ? $value['available'] : null,
            'default_granted' => array_key_exists('default_granted', $value) ? $value['default_granted'] : null,
            'policy' => array_key_exists('policy', $value) ? self::fromCborConsentRowPolicy($value['policy']) : null,
            'user_settable' => array_key_exists('user_settable', $value) ? $value['user_settable'] : null,
            'max_bytes' => array_key_exists('max_bytes', $value) ? $value['max_bytes'] : null,
            'requires_approval' => array_key_exists('requires_approval', $value) ? $value['requires_approval'] : null,
            'newly_requested' => array_key_exists('newly_requested', $value) ? $value['newly_requested'] : null,
        ));
    }

    public static function encodeBrowserAuthorizationInspectResponse($value)
    {
        return CBOR::encode(self::toCborBrowserAuthorizationInspectResponse($value));
    }

    public static function decodeBrowserAuthorizationInspectResponse($bytes)
    {
        return self::fromCborBrowserAuthorizationInspectResponse(self::csilDecode($bytes));
    }

    public static function toCborBrowserAuthorizationInspectResponse($value)
    {
        $out = array();
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->relyingParty : (is_array($value) && array_key_exists('relying_party', $value) ? $value['relying_party'] : null);
        $out['relying_party'] = $field;
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborBrowserConsentClaim($item); }, $field === null ? array() : $field);
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->requestReason : (is_array($value) && array_key_exists('request_reason', $value) ? $value['request_reason'] : null);
        if ($field !== null) {
            $out['request_reason'] = $field;
        }
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->alreadyConsented : (is_array($value) && array_key_exists('already_consented', $value) ? $value['already_consented'] : null);
        if ($field !== null) {
            $out['already_consented'] = $field;
        }
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        if ($field !== null) {
            $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        }
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->accessDenied : (is_array($value) && array_key_exists('access_denied', $value) ? $value['access_denied'] : null);
        if ($field !== null) {
            $out['access_denied'] = self::toCborAppAccessDenial($field);
        }
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->application : (is_array($value) && array_key_exists('application', $value) ? $value['application'] : null);
        if ($field !== null) {
            $out['application'] = self::toCborRelyingPartyApplication($field);
        }
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->callbackHost : (is_array($value) && array_key_exists('callback_host', $value) ? $value['callback_host'] : null);
        if ($field !== null) {
            $out['callback_host'] = $field;
        }
        $field = $value instanceof BrowserAuthorizationInspectResponse ? $value->returnHost : (is_array($value) && array_key_exists('return_host', $value) ? $value['return_host'] : null);
        if ($field !== null) {
            $out['return_host'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserAuthorizationInspectResponse($value)
    {
        $value = self::csilRecord($value, 'BrowserAuthorizationInspectResponse', array('relying_party', 'claims'));
        return new BrowserAuthorizationInspectResponse(array(
            'relying_party' => array_key_exists('relying_party', $value) ? $value['relying_party'] : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborBrowserConsentClaim($item); }, self::csilList($value['claims'])) : null,
            'request_reason' => array_key_exists('request_reason', $value) ? $value['request_reason'] : null,
            'already_consented' => array_key_exists('already_consented', $value) ? $value['already_consented'] : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['authorized_claims'])) : null,
            'access_denied' => array_key_exists('access_denied', $value) ? self::fromCborAppAccessDenial($value['access_denied']) : null,
            'application' => array_key_exists('application', $value) ? self::fromCborRelyingPartyApplication($value['application']) : null,
            'callback_host' => array_key_exists('callback_host', $value) ? $value['callback_host'] : null,
            'return_host' => array_key_exists('return_host', $value) ? $value['return_host'] : null,
        ));
    }

    public static function encodeBrowserAuthorizationCompleteRequest($value)
    {
        return CBOR::encode(self::toCborBrowserAuthorizationCompleteRequest($value));
    }

    public static function decodeBrowserAuthorizationCompleteRequest($bytes)
    {
        return self::fromCborBrowserAuthorizationCompleteRequest(self::csilDecode($bytes));
    }

    public static function toCborBrowserAuthorizationCompleteRequest($value)
    {
        $out = array();
        $field = $value instanceof BrowserAuthorizationCompleteRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        $field = $value instanceof BrowserAuthorizationCompleteRequest ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof BrowserAuthorizationCompleteRequest ? $value->claimTypesToSet : (is_array($value) && array_key_exists('claim_types_to_set', $value) ? $value['claim_types_to_set'] : null);
        $out['claim_types_to_set'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof BrowserAuthorizationCompleteRequest ? $value->claimValuesToSet : (is_array($value) && array_key_exists('claim_values_to_set', $value) ? $value['claim_values_to_set'] : null);
        $out['claim_values_to_set'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof BrowserAuthorizationCompleteRequest ? $value->useStandingGrant : (is_array($value) && array_key_exists('use_standing_grant', $value) ? $value['use_standing_grant'] : null);
        if ($field !== null) {
            $out['use_standing_grant'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserAuthorizationCompleteRequest($value)
    {
        $value = self::csilRecord($value, 'BrowserAuthorizationCompleteRequest', array('signed_request', 'authorized_claims', 'claim_types_to_set', 'claim_values_to_set'));
        return new BrowserAuthorizationCompleteRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['authorized_claims'])) : null,
            'claim_types_to_set' => array_key_exists('claim_types_to_set', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['claim_types_to_set'])) : null,
            'claim_values_to_set' => array_key_exists('claim_values_to_set', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['claim_values_to_set'])) : null,
            'use_standing_grant' => array_key_exists('use_standing_grant', $value) ? $value['use_standing_grant'] : null,
        ));
    }

    public static function encodeBrowserAuthorizationCompleteResponse($value)
    {
        return CBOR::encode(self::toCborBrowserAuthorizationCompleteResponse($value));
    }

    public static function decodeBrowserAuthorizationCompleteResponse($bytes)
    {
        return self::fromCborBrowserAuthorizationCompleteResponse(self::csilDecode($bytes));
    }

    public static function toCborBrowserAuthorizationCompleteResponse($value)
    {
        $out = array();
        $field = $value instanceof BrowserAuthorizationCompleteResponse ? $value->redirectUrl : (is_array($value) && array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null);
        $out['redirect_url'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserAuthorizationCompleteResponse($value)
    {
        $value = self::csilRecord($value, 'BrowserAuthorizationCompleteResponse', array('redirect_url'));
        return new BrowserAuthorizationCompleteResponse(array(
            'redirect_url' => array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null,
        ));
    }

    public static function encodeBrowserLocalRpInspectRequest($value)
    {
        return CBOR::encode(self::toCborBrowserLocalRpInspectRequest($value));
    }

    public static function decodeBrowserLocalRpInspectRequest($bytes)
    {
        return self::fromCborBrowserLocalRpInspectRequest(self::csilDecode($bytes));
    }

    public static function toCborBrowserLocalRpInspectRequest($value)
    {
        $out = array();
        $field = $value instanceof BrowserLocalRpInspectRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserLocalRpInspectRequest($value)
    {
        $value = self::csilRecord($value, 'BrowserLocalRpInspectRequest', array('signed_request'));
        return new BrowserLocalRpInspectRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
        ));
    }

    public static function encodeBrowserLocalRpInspectResponse($value)
    {
        return CBOR::encode(self::toCborBrowserLocalRpInspectResponse($value));
    }

    public static function decodeBrowserLocalRpInspectResponse($bytes)
    {
        return self::fromCborBrowserLocalRpInspectResponse(self::csilDecode($bytes));
    }

    public static function toCborBrowserLocalRpInspectResponse($value)
    {
        $out = array();
        $field = $value instanceof BrowserLocalRpInspectResponse ? $value->admission : (is_array($value) && array_key_exists('admission', $value) ? $value['admission'] : null);
        $out['admission'] = self::toCborLocalRpAdmission($field);
        $field = $value instanceof BrowserLocalRpInspectResponse ? $value->appName : (is_array($value) && array_key_exists('app_name', $value) ? $value['app_name'] : null);
        $out['app_name'] = $field;
        $field = $value instanceof BrowserLocalRpInspectResponse ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof BrowserLocalRpInspectResponse ? $value->callbackHost : (is_array($value) && array_key_exists('callback_host', $value) ? $value['callback_host'] : null);
        $out['callback_host'] = $field;
        $field = $value instanceof BrowserLocalRpInspectResponse ? $value->firstSeenAt : (is_array($value) && array_key_exists('first_seen_at', $value) ? $value['first_seen_at'] : null);
        if ($field !== null) {
            $out['first_seen_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof BrowserLocalRpInspectResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborBrowserConsentClaim($item); }, $field === null ? array() : $field);
        $field = $value instanceof BrowserLocalRpInspectResponse ? $value->requestReason : (is_array($value) && array_key_exists('request_reason', $value) ? $value['request_reason'] : null);
        if ($field !== null) {
            $out['request_reason'] = $field;
        }
        $field = $value instanceof BrowserLocalRpInspectResponse ? $value->alreadyConsented : (is_array($value) && array_key_exists('already_consented', $value) ? $value['already_consented'] : null);
        if ($field !== null) {
            $out['already_consented'] = $field;
        }
        $field = $value instanceof BrowserLocalRpInspectResponse ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        if ($field !== null) {
            $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        }
        $field = $value instanceof BrowserLocalRpInspectResponse ? $value->accessDenied : (is_array($value) && array_key_exists('access_denied', $value) ? $value['access_denied'] : null);
        if ($field !== null) {
            $out['access_denied'] = self::toCborAppAccessDenial($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserLocalRpInspectResponse($value)
    {
        $value = self::csilRecord($value, 'BrowserLocalRpInspectResponse', array('admission', 'app_name', 'fingerprint', 'callback_host', 'claims'));
        return new BrowserLocalRpInspectResponse(array(
            'admission' => array_key_exists('admission', $value) ? self::fromCborLocalRpAdmission($value['admission']) : null,
            'app_name' => array_key_exists('app_name', $value) ? $value['app_name'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'callback_host' => array_key_exists('callback_host', $value) ? $value['callback_host'] : null,
            'first_seen_at' => array_key_exists('first_seen_at', $value) ? self::timestampFromCbor($value['first_seen_at']) : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborBrowserConsentClaim($item); }, self::csilList($value['claims'])) : null,
            'request_reason' => array_key_exists('request_reason', $value) ? $value['request_reason'] : null,
            'already_consented' => array_key_exists('already_consented', $value) ? $value['already_consented'] : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['authorized_claims'])) : null,
            'access_denied' => array_key_exists('access_denied', $value) ? self::fromCborAppAccessDenial($value['access_denied']) : null,
        ));
    }

    public static function encodeBrowserLocalRpCompleteRequest($value)
    {
        return CBOR::encode(self::toCborBrowserLocalRpCompleteRequest($value));
    }

    public static function decodeBrowserLocalRpCompleteRequest($bytes)
    {
        return self::fromCborBrowserLocalRpCompleteRequest(self::csilDecode($bytes));
    }

    public static function toCborBrowserLocalRpCompleteRequest($value)
    {
        $out = array();
        $field = $value instanceof BrowserLocalRpCompleteRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        $field = $value instanceof BrowserLocalRpCompleteRequest ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof BrowserLocalRpCompleteRequest ? $value->claimTypesToSet : (is_array($value) && array_key_exists('claim_types_to_set', $value) ? $value['claim_types_to_set'] : null);
        $out['claim_types_to_set'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof BrowserLocalRpCompleteRequest ? $value->claimValuesToSet : (is_array($value) && array_key_exists('claim_values_to_set', $value) ? $value['claim_values_to_set'] : null);
        $out['claim_values_to_set'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof BrowserLocalRpCompleteRequest ? $value->useStandingGrant : (is_array($value) && array_key_exists('use_standing_grant', $value) ? $value['use_standing_grant'] : null);
        if ($field !== null) {
            $out['use_standing_grant'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserLocalRpCompleteRequest($value)
    {
        $value = self::csilRecord($value, 'BrowserLocalRpCompleteRequest', array('signed_request', 'authorized_claims', 'claim_types_to_set', 'claim_values_to_set'));
        return new BrowserLocalRpCompleteRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['authorized_claims'])) : null,
            'claim_types_to_set' => array_key_exists('claim_types_to_set', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['claim_types_to_set'])) : null,
            'claim_values_to_set' => array_key_exists('claim_values_to_set', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['claim_values_to_set'])) : null,
            'use_standing_grant' => array_key_exists('use_standing_grant', $value) ? $value['use_standing_grant'] : null,
        ));
    }

    public static function encodeBrowserLocalRpCompleteResponse($value)
    {
        return CBOR::encode(self::toCborBrowserLocalRpCompleteResponse($value));
    }

    public static function decodeBrowserLocalRpCompleteResponse($bytes)
    {
        return self::fromCborBrowserLocalRpCompleteResponse(self::csilDecode($bytes));
    }

    public static function toCborBrowserLocalRpCompleteResponse($value)
    {
        $out = array();
        $field = $value instanceof BrowserLocalRpCompleteResponse ? $value->redirectUrl : (is_array($value) && array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null);
        $out['redirect_url'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserLocalRpCompleteResponse($value)
    {
        $value = self::csilRecord($value, 'BrowserLocalRpCompleteResponse', array('redirect_url'));
        return new BrowserLocalRpCompleteResponse(array(
            'redirect_url' => array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null,
        ));
    }

    public static function encodeUiTheme($value)
    {
        return CBOR::encode(self::toCborUiTheme($value));
    }

    public static function decodeUiTheme($bytes)
    {
        return self::fromCborUiTheme(self::csilDecode($bytes));
    }

    public static function toCborUiTheme($value)
    {
        $out = array();
        $field = $value instanceof UiTheme ? $value->stylesheetUrl : (is_array($value) && array_key_exists('stylesheet_url', $value) ? $value['stylesheet_url'] : null);
        if ($field !== null) {
            $out['stylesheet_url'] = $field;
        }
        $field = $value instanceof UiTheme ? $value->logoUrl : (is_array($value) && array_key_exists('logo_url', $value) ? $value['logo_url'] : null);
        if ($field !== null) {
            $out['logo_url'] = $field;
        }
        $field = $value instanceof UiTheme ? $value->faviconUrl : (is_array($value) && array_key_exists('favicon_url', $value) ? $value['favicon_url'] : null);
        if ($field !== null) {
            $out['favicon_url'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborUiTheme($value)
    {
        $value = self::csilRecord($value, 'UiTheme', array());
        return new UiTheme(array(
            'stylesheet_url' => array_key_exists('stylesheet_url', $value) ? $value['stylesheet_url'] : null,
            'logo_url' => array_key_exists('logo_url', $value) ? $value['logo_url'] : null,
            'favicon_url' => array_key_exists('favicon_url', $value) ? $value['favicon_url'] : null,
        ));
    }

    public static function encodeUiExtension($value)
    {
        return CBOR::encode(self::toCborUiExtension($value));
    }

    public static function decodeUiExtension($bytes)
    {
        return self::fromCborUiExtension(self::csilDecode($bytes));
    }

    public static function toCborUiExtension($value)
    {
        $out = array();
        $field = $value instanceof UiExtension ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof UiExtension ? $value->moduleUrl : (is_array($value) && array_key_exists('module_url', $value) ? $value['module_url'] : null);
        $out['module_url'] = $field;
        $field = $value instanceof UiExtension ? $value->apiVersion : (is_array($value) && array_key_exists('api_version', $value) ? $value['api_version'] : null);
        $out['api_version'] = $field;
        $field = $value instanceof UiExtension ? $value->stylesheetUrl : (is_array($value) && array_key_exists('stylesheet_url', $value) ? $value['stylesheet_url'] : null);
        if ($field !== null) {
            $out['stylesheet_url'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborUiExtension($value)
    {
        $value = self::csilRecord($value, 'UiExtension', array('id', 'module_url', 'api_version'));
        return new UiExtension(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'module_url' => array_key_exists('module_url', $value) ? $value['module_url'] : null,
            'api_version' => array_key_exists('api_version', $value) ? $value['api_version'] : null,
            'stylesheet_url' => array_key_exists('stylesheet_url', $value) ? $value['stylesheet_url'] : null,
        ));
    }

    public static function encodeUiDisplaySettings($value)
    {
        return CBOR::encode(self::toCborUiDisplaySettings($value));
    }

    public static function decodeUiDisplaySettings($bytes)
    {
        return self::fromCborUiDisplaySettings(self::csilDecode($bytes));
    }

    public static function toCborUiDisplaySettings($value)
    {
        $out = array();
        $field = $value instanceof UiDisplaySettings ? $value->siteName : (is_array($value) && array_key_exists('site_name', $value) ? $value['site_name'] : null);
        $out['site_name'] = $field;
        $field = $value instanceof UiDisplaySettings ? $value->supportUrl : (is_array($value) && array_key_exists('support_url', $value) ? $value['support_url'] : null);
        if ($field !== null) {
            $out['support_url'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborUiDisplaySettings($value)
    {
        $value = self::csilRecord($value, 'UiDisplaySettings', array('site_name'));
        return new UiDisplaySettings(array(
            'site_name' => array_key_exists('site_name', $value) ? $value['site_name'] : null,
            'support_url' => array_key_exists('support_url', $value) ? $value['support_url'] : null,
        ));
    }

    public static function encodeGetUiConfigurationResponse($value)
    {
        return CBOR::encode(self::toCborGetUiConfigurationResponse($value));
    }

    public static function decodeGetUiConfigurationResponse($bytes)
    {
        return self::fromCborGetUiConfigurationResponse(self::csilDecode($bytes));
    }

    public static function toCborGetUiConfigurationResponse($value)
    {
        $out = array();
        $field = $value instanceof GetUiConfigurationResponse ? $value->hostApiVersion : (is_array($value) && array_key_exists('host_api_version', $value) ? $value['host_api_version'] : null);
        $out['host_api_version'] = $field;
        $field = $value instanceof GetUiConfigurationResponse ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof GetUiConfigurationResponse ? $value->publicOrigin : (is_array($value) && array_key_exists('public_origin', $value) ? $value['public_origin'] : null);
        if ($field !== null) {
            $out['public_origin'] = $field;
        }
        $field = $value instanceof GetUiConfigurationResponse ? $value->capabilities : (is_array($value) && array_key_exists('capabilities', $value) ? $value['capabilities'] : null);
        $out['capabilities'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof GetUiConfigurationResponse ? $value->display : (is_array($value) && array_key_exists('display', $value) ? $value['display'] : null);
        $out['display'] = self::toCborUiDisplaySettings($field);
        $field = $value instanceof GetUiConfigurationResponse ? $value->theme : (is_array($value) && array_key_exists('theme', $value) ? $value['theme'] : null);
        if ($field !== null) {
            $out['theme'] = self::toCborUiTheme($field);
        }
        $field = $value instanceof GetUiConfigurationResponse ? $value->extensions : (is_array($value) && array_key_exists('extensions', $value) ? $value['extensions'] : null);
        $out['extensions'] = array_map(function ($item) { return self::toCborUiExtension($item); }, $field === null ? array() : $field);
        $field = $value instanceof GetUiConfigurationResponse ? $value->passwordPolicy : (is_array($value) && array_key_exists('password_policy', $value) ? $value['password_policy'] : null);
        if ($field !== null) {
            $out['password_policy'] = self::toCborPasswordPolicy($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetUiConfigurationResponse($value)
    {
        $value = self::csilRecord($value, 'GetUiConfigurationResponse', array('host_api_version', 'domain', 'capabilities', 'display', 'extensions'));
        return new GetUiConfigurationResponse(array(
            'host_api_version' => array_key_exists('host_api_version', $value) ? $value['host_api_version'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'public_origin' => array_key_exists('public_origin', $value) ? $value['public_origin'] : null,
            'capabilities' => array_key_exists('capabilities', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['capabilities'])) : null,
            'display' => array_key_exists('display', $value) ? self::fromCborUiDisplaySettings($value['display']) : null,
            'theme' => array_key_exists('theme', $value) ? self::fromCborUiTheme($value['theme']) : null,
            'extensions' => array_key_exists('extensions', $value) ? array_map(function ($item) { return self::fromCborUiExtension($item); }, self::csilList($value['extensions'])) : null,
            'password_policy' => array_key_exists('password_policy', $value) ? self::fromCborPasswordPolicy($value['password_policy']) : null,
        ));
    }

    public static function encodeRpSignRequest($value)
    {
        return CBOR::encode(self::toCborRpSignRequest($value));
    }

    public static function decodeRpSignRequest($bytes)
    {
        return self::fromCborRpSignRequest(self::csilDecode($bytes));
    }

    public static function toCborRpSignRequest($value)
    {
        $out = array();
        $field = $value instanceof RpSignRequest ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof RpSignRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        $field = $value instanceof RpSignRequest ? $value->requestedClaims : (is_array($value) && array_key_exists('requested_claims', $value) ? $value['requested_claims'] : null);
        if ($field !== null) {
            $out['requested_claims'] = self::toCborClaimRequest($field);
        }
        $field = $value instanceof RpSignRequest ? $value->authenticationRequirements : (is_array($value) && array_key_exists('authentication_requirements', $value) ? $value['authentication_requirements'] : null);
        if ($field !== null) {
            $out['authentication_requirements'] = self::toCborAuthenticationRequirements($field);
        }
        $field = $value instanceof RpSignRequest ? $value->flowContext : (is_array($value) && array_key_exists('flow_context', $value) ? $value['flow_context'] : null);
        if ($field !== null) {
            $out['flow_context'] = self::toCborAuthFlowContext($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpSignRequest($value)
    {
        $value = self::csilRecord($value, 'RpSignRequest', array('callback_url', 'nonce'));
        return new RpSignRequest(array(
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'requested_claims' => array_key_exists('requested_claims', $value) ? self::fromCborClaimRequest($value['requested_claims']) : null,
            'authentication_requirements' => array_key_exists('authentication_requirements', $value) ? self::fromCborAuthenticationRequirements($value['authentication_requirements']) : null,
            'flow_context' => array_key_exists('flow_context', $value) ? self::fromCborAuthFlowContext($value['flow_context']) : null,
        ));
    }

    public static function encodeRpSignResponse($value)
    {
        return CBOR::encode(self::toCborRpSignResponse($value));
    }

    public static function decodeRpSignResponse($bytes)
    {
        return self::fromCborRpSignResponse(self::csilDecode($bytes));
    }

    public static function toCborRpSignResponse($value)
    {
        $out = array();
        $field = $value instanceof RpSignResponse ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpSignResponse($value)
    {
        $value = self::csilRecord($value, 'RpSignResponse', array('signed_request'));
        return new RpSignResponse(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
        ));
    }

    public static function encodeRpDecryptRequest($value)
    {
        return CBOR::encode(self::toCborRpDecryptRequest($value));
    }

    public static function decodeRpDecryptRequest($bytes)
    {
        return self::fromCborRpDecryptRequest(self::csilDecode($bytes));
    }

    public static function toCborRpDecryptRequest($value)
    {
        $out = array();
        $field = $value instanceof RpDecryptRequest ? $value->encryptedToken : (is_array($value) && array_key_exists('encrypted_token', $value) ? $value['encrypted_token'] : null);
        $out['encrypted_token'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpDecryptRequest($value)
    {
        $value = self::csilRecord($value, 'RpDecryptRequest', array('encrypted_token'));
        return new RpDecryptRequest(array(
            'encrypted_token' => array_key_exists('encrypted_token', $value) ? $value['encrypted_token'] : null,
        ));
    }

    public static function encodeRpDecryptResponse($value)
    {
        return CBOR::encode(self::toCborRpDecryptResponse($value));
    }

    public static function decodeRpDecryptResponse($bytes)
    {
        return self::fromCborRpDecryptResponse(self::csilDecode($bytes));
    }

    public static function toCborRpDecryptResponse($value)
    {
        $out = array();
        $field = $value instanceof RpDecryptResponse ? $value->signedAssertion : (is_array($value) && array_key_exists('signed_assertion', $value) ? $value['signed_assertion'] : null);
        $out['signed_assertion'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpDecryptResponse($value)
    {
        $value = self::csilRecord($value, 'RpDecryptResponse', array('signed_assertion'));
        return new RpDecryptResponse(array(
            'signed_assertion' => array_key_exists('signed_assertion', $value) ? $value['signed_assertion'] : null,
        ));
    }

    public static function encodeRpVerifyRequest($value)
    {
        return CBOR::encode(self::toCborRpVerifyRequest($value));
    }

    public static function decodeRpVerifyRequest($bytes)
    {
        return self::fromCborRpVerifyRequest(self::csilDecode($bytes));
    }

    public static function toCborRpVerifyRequest($value)
    {
        $out = array();
        $field = $value instanceof RpVerifyRequest ? $value->signedAssertion : (is_array($value) && array_key_exists('signed_assertion', $value) ? $value['signed_assertion'] : null);
        $out['signed_assertion'] = $field;
        $field = $value instanceof RpVerifyRequest ? $value->expectedDomain : (is_array($value) && array_key_exists('expected_domain', $value) ? $value['expected_domain'] : null);
        $out['expected_domain'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpVerifyRequest($value)
    {
        $value = self::csilRecord($value, 'RpVerifyRequest', array('signed_assertion', 'expected_domain'));
        return new RpVerifyRequest(array(
            'signed_assertion' => array_key_exists('signed_assertion', $value) ? $value['signed_assertion'] : null,
            'expected_domain' => array_key_exists('expected_domain', $value) ? $value['expected_domain'] : null,
        ));
    }

    public static function encodeRpVerifyResponse($value)
    {
        return CBOR::encode(self::toCborRpVerifyResponse($value));
    }

    public static function decodeRpVerifyResponse($bytes)
    {
        return self::fromCborRpVerifyResponse(self::csilDecode($bytes));
    }

    public static function toCborRpVerifyResponse($value)
    {
        $out = array();
        $field = $value instanceof RpVerifyResponse ? $value->assertion : (is_array($value) && array_key_exists('assertion', $value) ? $value['assertion'] : null);
        $out['assertion'] = self::toCborIdentityAssertion($field);
        $field = $value instanceof RpVerifyResponse ? $value->verified : (is_array($value) && array_key_exists('verified', $value) ? $value['verified'] : null);
        $out['verified'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpVerifyResponse($value)
    {
        $value = self::csilRecord($value, 'RpVerifyResponse', array('assertion', 'verified'));
        return new RpVerifyResponse(array(
            'assertion' => array_key_exists('assertion', $value) ? self::fromCborIdentityAssertion($value['assertion']) : null,
            'verified' => array_key_exists('verified', $value) ? $value['verified'] : null,
        ));
    }

    public static function encodeRpUserInfoRequest($value)
    {
        return CBOR::encode(self::toCborRpUserInfoRequest($value));
    }

    public static function decodeRpUserInfoRequest($bytes)
    {
        return self::fromCborRpUserInfoRequest(self::csilDecode($bytes));
    }

    public static function toCborRpUserInfoRequest($value)
    {
        $out = array();
        $field = $value instanceof RpUserInfoRequest ? $value->token : (is_array($value) && array_key_exists('token', $value) ? $value['token'] : null);
        $out['token'] = $field;
        $field = $value instanceof RpUserInfoRequest ? $value->apiBase : (is_array($value) && array_key_exists('api_base', $value) ? $value['api_base'] : null);
        $out['api_base'] = $field;
        $field = $value instanceof RpUserInfoRequest ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpUserInfoRequest($value)
    {
        $value = self::csilRecord($value, 'RpUserInfoRequest', array('token', 'api_base', 'domain'));
        return new RpUserInfoRequest(array(
            'token' => array_key_exists('token', $value) ? $value['token'] : null,
            'api_base' => array_key_exists('api_base', $value) ? $value['api_base'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
        ));
    }

    public static function encodeRpError($value)
    {
        return CBOR::encode(self::toCborRpError($value));
    }

    public static function decodeRpError($bytes)
    {
        return self::fromCborRpError(self::csilDecode($bytes));
    }

    public static function toCborRpError($value)
    {
        $out = array();
        $field = $value instanceof RpError ? $value->code : (is_array($value) && array_key_exists('code', $value) ? $value['code'] : null);
        $out['code'] = self::toCborRpErrorCode($field);
        $field = $value instanceof RpError ? $value->message : (is_array($value) && array_key_exists('message', $value) ? $value['message'] : null);
        $out['message'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpError($value)
    {
        $value = self::csilRecord($value, 'RpError', array('code', 'message'));
        return new RpError(array(
            'code' => array_key_exists('code', $value) ? self::fromCborRpErrorCode($value['code']) : null,
            'message' => array_key_exists('message', $value) ? $value['message'] : null,
        ));
    }

    public static function encodeRpIssueAttestationRequest($value)
    {
        return CBOR::encode(self::toCborRpIssueAttestationRequest($value));
    }

    public static function decodeRpIssueAttestationRequest($bytes)
    {
        return self::fromCborRpIssueAttestationRequest(self::csilDecode($bytes));
    }

    public static function toCborRpIssueAttestationRequest($value)
    {
        $out = array();
        $field = $value instanceof RpIssueAttestationRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = self::toCborSignedSigningRequest($field);
        $field = $value instanceof RpIssueAttestationRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof RpIssueAttestationRequest ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        $out['claim_value'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpIssueAttestationRequest($value)
    {
        $value = self::csilRecord($value, 'RpIssueAttestationRequest', array('signed_request', 'claim_type', 'claim_value'));
        return new RpIssueAttestationRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? self::fromCborSignedSigningRequest($value['signed_request']) : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
        ));
    }

    public static function encodeRpIssueAttestationResponse($value)
    {
        return CBOR::encode(self::toCborRpIssueAttestationResponse($value));
    }

    public static function decodeRpIssueAttestationResponse($bytes)
    {
        return self::fromCborRpIssueAttestationResponse(self::csilDecode($bytes));
    }

    public static function toCborRpIssueAttestationResponse($value)
    {
        $out = array();
        $field = $value instanceof RpIssueAttestationResponse ? $value->claim : (is_array($value) && array_key_exists('claim', $value) ? $value['claim'] : null);
        $out['claim'] = self::toCborClaim($field);
        $field = $value instanceof RpIssueAttestationResponse ? $value->deposited : (is_array($value) && array_key_exists('deposited', $value) ? $value['deposited'] : null);
        $out['deposited'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpIssueAttestationResponse($value)
    {
        $value = self::csilRecord($value, 'RpIssueAttestationResponse', array('claim', 'deposited'));
        return new RpIssueAttestationResponse(array(
            'claim' => array_key_exists('claim', $value) ? self::fromCborClaim($value['claim']) : null,
            'deposited' => array_key_exists('deposited', $value) ? $value['deposited'] : null,
        ));
    }

    public static function encodeAuthorizeValidateRequest($value)
    {
        return CBOR::encode(self::toCborAuthorizeValidateRequest($value));
    }

    public static function decodeAuthorizeValidateRequest($bytes)
    {
        return self::fromCborAuthorizeValidateRequest(self::csilDecode($bytes));
    }

    public static function toCborAuthorizeValidateRequest($value)
    {
        $out = array();
        $field = $value instanceof AuthorizeValidateRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        $field = $value instanceof AuthorizeValidateRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        if ($field !== null) {
            $out['user_id'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAuthorizeValidateRequest($value)
    {
        $value = self::csilRecord($value, 'AuthorizeValidateRequest', array('signed_request'));
        return new AuthorizeValidateRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
        ));
    }

    public static function encodeAuthorizeValidateResponse($value)
    {
        return CBOR::encode(self::toCborAuthorizeValidateResponse($value));
    }

    public static function decodeAuthorizeValidateResponse($bytes)
    {
        return self::fromCborAuthorizeValidateResponse(self::csilDecode($bytes));
    }

    public static function toCborAuthorizeValidateResponse($value)
    {
        $out = array();
        $field = $value instanceof AuthorizeValidateResponse ? $value->relyingParty : (is_array($value) && array_key_exists('relying_party', $value) ? $value['relying_party'] : null);
        $out['relying_party'] = $field;
        $field = $value instanceof AuthorizeValidateResponse ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof AuthorizeValidateResponse ? $value->requestedClaims : (is_array($value) && array_key_exists('requested_claims', $value) ? $value['requested_claims'] : null);
        $out['requested_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof AuthorizeValidateResponse ? $value->alreadyConsented : (is_array($value) && array_key_exists('already_consented', $value) ? $value['already_consented'] : null);
        if ($field !== null) {
            $out['already_consented'] = $field;
        }
        $field = $value instanceof AuthorizeValidateResponse ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        if ($field !== null) {
            $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        }
        $field = $value instanceof AuthorizeValidateResponse ? $value->newlyRequestedClaims : (is_array($value) && array_key_exists('newly_requested_claims', $value) ? $value['newly_requested_claims'] : null);
        if ($field !== null) {
            $out['newly_requested_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        }
        $field = $value instanceof AuthorizeValidateResponse ? $value->accessDenied : (is_array($value) && array_key_exists('access_denied', $value) ? $value['access_denied'] : null);
        if ($field !== null) {
            $out['access_denied'] = self::toCborAppAccessDenial($field);
        }
        $field = $value instanceof AuthorizeValidateResponse ? $value->application : (is_array($value) && array_key_exists('application', $value) ? $value['application'] : null);
        if ($field !== null) {
            $out['application'] = self::toCborRelyingPartyApplication($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAuthorizeValidateResponse($value)
    {
        $value = self::csilRecord($value, 'AuthorizeValidateResponse', array('relying_party', 'callback_url', 'requested_claims'));
        return new AuthorizeValidateResponse(array(
            'relying_party' => array_key_exists('relying_party', $value) ? $value['relying_party'] : null,
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'requested_claims' => array_key_exists('requested_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['requested_claims'])) : null,
            'already_consented' => array_key_exists('already_consented', $value) ? $value['already_consented'] : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['authorized_claims'])) : null,
            'newly_requested_claims' => array_key_exists('newly_requested_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['newly_requested_claims'])) : null,
            'access_denied' => array_key_exists('access_denied', $value) ? self::fromCborAppAccessDenial($value['access_denied']) : null,
            'application' => array_key_exists('application', $value) ? self::fromCborRelyingPartyApplication($value['application']) : null,
        ));
    }

    public static function encodeAuthorizeFinalizeRequest($value)
    {
        return CBOR::encode(self::toCborAuthorizeFinalizeRequest($value));
    }

    public static function decodeAuthorizeFinalizeRequest($bytes)
    {
        return self::fromCborAuthorizeFinalizeRequest(self::csilDecode($bytes));
    }

    public static function toCborAuthorizeFinalizeRequest($value)
    {
        $out = array();
        $field = $value instanceof AuthorizeFinalizeRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof AuthorizeFinalizeRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        $field = $value instanceof AuthorizeFinalizeRequest ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAuthorizeFinalizeRequest($value)
    {
        $value = self::csilRecord($value, 'AuthorizeFinalizeRequest', array('user_id', 'signed_request', 'authorized_claims'));
        return new AuthorizeFinalizeRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['authorized_claims'])) : null,
        ));
    }

    public static function encodeAuthorizeFinalizeResponse($value)
    {
        return CBOR::encode(self::toCborAuthorizeFinalizeResponse($value));
    }

    public static function decodeAuthorizeFinalizeResponse($bytes)
    {
        return self::fromCborAuthorizeFinalizeResponse(self::csilDecode($bytes));
    }

    public static function toCborAuthorizeFinalizeResponse($value)
    {
        $out = array();
        $field = $value instanceof AuthorizeFinalizeResponse ? $value->redirectUrl : (is_array($value) && array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null);
        $out['redirect_url'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAuthorizeFinalizeResponse($value)
    {
        $value = self::csilRecord($value, 'AuthorizeFinalizeResponse', array('redirect_url'));
        return new AuthorizeFinalizeResponse(array(
            'redirect_url' => array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null,
        ));
    }

    public static function encodeApiErrorCode($value)
    {
        return CBOR::encode(self::toCborApiErrorCode($value));
    }

    public static function decodeApiErrorCode($bytes)
    {
        return self::fromCborApiErrorCode(self::csilDecode($bytes));
    }

    public static function toCborApiErrorCode($value)
    {
        try { return ApiErrorCode::toNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function fromCborApiErrorCode($value)
    {
        try { return ApiErrorCode::fromNumber($value); }
        catch (\InvalidArgumentException $e) { throw new CodecException($e->getMessage()); }
    }

    public static function encodeApiError($value)
    {
        return CBOR::encode(self::toCborApiError($value));
    }

    public static function decodeApiError($bytes)
    {
        return self::fromCborApiError(self::csilDecode($bytes));
    }

    public static function toCborApiError($value)
    {
        $out = array();
        $field = $value instanceof ApiError ? $value->code : (is_array($value) && array_key_exists('code', $value) ? $value['code'] : null);
        $out['code'] = self::toCborApiErrorCode($field);
        $field = $value instanceof ApiError ? $value->message : (is_array($value) && array_key_exists('message', $value) ? $value['message'] : null);
        $out['message'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApiError($value)
    {
        $value = self::csilRecord($value, 'ApiError', array('code', 'message'));
        return new ApiError(array(
            'code' => array_key_exists('code', $value) ? self::fromCborApiErrorCode($value['code']) : null,
            'message' => array_key_exists('message', $value) ? $value['message'] : null,
        ));
    }

    public static function encodeLocalRpDescriptor($value)
    {
        return CBOR::encode(self::toCborLocalRpDescriptor($value));
    }

    public static function decodeLocalRpDescriptor($bytes)
    {
        return self::fromCborLocalRpDescriptor(self::csilDecode($bytes));
    }

    public static function toCborLocalRpDescriptor($value)
    {
        $out = array();
        $field = $value instanceof LocalRpDescriptor ? $value->appName : (is_array($value) && array_key_exists('app_name', $value) ? $value['app_name'] : null);
        $out['app_name'] = $field;
        $field = $value instanceof LocalRpDescriptor ? $value->localDomainHint : (is_array($value) && array_key_exists('local_domain_hint', $value) ? $value['local_domain_hint'] : null);
        if ($field !== null) {
            $out['local_domain_hint'] = $field;
        }
        $field = $value instanceof LocalRpDescriptor ? $value->signingPublicKey : (is_array($value) && array_key_exists('signing_public_key', $value) ? $value['signing_public_key'] : null);
        $out['signing_public_key'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpDescriptor ? $value->encryptionPublicKey : (is_array($value) && array_key_exists('encryption_public_key', $value) ? $value['encryption_public_key'] : null);
        $out['encryption_public_key'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpDescriptor ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof LocalRpDescriptor ? $value->supportedSuites : (is_array($value) && array_key_exists('supported_suites', $value) ? $value['supported_suites'] : null);
        $out['supported_suites'] = array_map(function ($item) { return self::toCborAeadSuite($item); }, $field === null ? array() : $field);
        $field = $value instanceof LocalRpDescriptor ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = self::timestampToCbor($field);
        $field = $value instanceof LocalRpDescriptor ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborLocalRpDescriptor($value)
    {
        $value = self::csilRecord($value, 'LocalRpDescriptor', array('app_name', 'signing_public_key', 'encryption_public_key', 'fingerprint', 'supported_suites', 'created_at', 'expires_at'));
        return new LocalRpDescriptor(array(
            'app_name' => array_key_exists('app_name', $value) ? $value['app_name'] : null,
            'local_domain_hint' => array_key_exists('local_domain_hint', $value) ? $value['local_domain_hint'] : null,
            'signing_public_key' => array_key_exists('signing_public_key', $value) ? $value['signing_public_key'] : null,
            'encryption_public_key' => array_key_exists('encryption_public_key', $value) ? $value['encryption_public_key'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'supported_suites' => array_key_exists('supported_suites', $value) ? array_map(function ($item) { return self::fromCborAeadSuite($item); }, self::csilList($value['supported_suites'])) : null,
            'created_at' => array_key_exists('created_at', $value) ? self::timestampFromCbor($value['created_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeSignedLocalRpDescriptor($value)
    {
        return CBOR::encode(self::toCborSignedLocalRpDescriptor($value));
    }

    public static function decodeSignedLocalRpDescriptor($bytes)
    {
        return self::fromCborSignedLocalRpDescriptor(self::csilDecode($bytes));
    }

    public static function toCborSignedLocalRpDescriptor($value)
    {
        $out = array();
        $field = $value instanceof SignedLocalRpDescriptor ? $value->descriptor : (is_array($value) && array_key_exists('descriptor', $value) ? $value['descriptor'] : null);
        $out['descriptor'] = CBOR::bytes($field);
        $field = $value instanceof SignedLocalRpDescriptor ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedLocalRpDescriptor($value)
    {
        $value = self::csilRecord($value, 'SignedLocalRpDescriptor', array('descriptor', 'signature'));
        return new SignedLocalRpDescriptor(array(
            'descriptor' => array_key_exists('descriptor', $value) ? $value['descriptor'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeLocalRpLoginRequest($value)
    {
        return CBOR::encode(self::toCborLocalRpLoginRequest($value));
    }

    public static function decodeLocalRpLoginRequest($bytes)
    {
        return self::fromCborLocalRpLoginRequest(self::csilDecode($bytes));
    }

    public static function toCborLocalRpLoginRequest($value)
    {
        $out = array();
        $field = $value instanceof LocalRpLoginRequest ? $value->descriptor : (is_array($value) && array_key_exists('descriptor', $value) ? $value['descriptor'] : null);
        $out['descriptor'] = self::toCborSignedLocalRpDescriptor($field);
        $field = $value instanceof LocalRpLoginRequest ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof LocalRpLoginRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpLoginRequest ? $value->state : (is_array($value) && array_key_exists('state', $value) ? $value['state'] : null);
        $out['state'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpLoginRequest ? $value->requestedClaims : (is_array($value) && array_key_exists('requested_claims', $value) ? $value['requested_claims'] : null);
        $out['requested_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof LocalRpLoginRequest ? $value->requiredClaims : (is_array($value) && array_key_exists('required_claims', $value) ? $value['required_claims'] : null);
        $out['required_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof LocalRpLoginRequest ? $value->authenticationRequirements : (is_array($value) && array_key_exists('authentication_requirements', $value) ? $value['authentication_requirements'] : null);
        if ($field !== null) {
            $out['authentication_requirements'] = self::toCborAuthenticationRequirements($field);
        }
        $field = $value instanceof LocalRpLoginRequest ? $value->flowContext : (is_array($value) && array_key_exists('flow_context', $value) ? $value['flow_context'] : null);
        if ($field !== null) {
            $out['flow_context'] = self::toCborAuthFlowContext($field);
        }
        $field = $value instanceof LocalRpLoginRequest ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof LocalRpLoginRequest ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborLocalRpLoginRequest($value)
    {
        $value = self::csilRecord($value, 'LocalRpLoginRequest', array('descriptor', 'callback_url', 'nonce', 'state', 'requested_claims', 'required_claims', 'issued_at', 'expires_at'));
        return new LocalRpLoginRequest(array(
            'descriptor' => array_key_exists('descriptor', $value) ? self::fromCborSignedLocalRpDescriptor($value['descriptor']) : null,
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'state' => array_key_exists('state', $value) ? $value['state'] : null,
            'requested_claims' => array_key_exists('requested_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['requested_claims'])) : null,
            'required_claims' => array_key_exists('required_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['required_claims'])) : null,
            'authentication_requirements' => array_key_exists('authentication_requirements', $value) ? self::fromCborAuthenticationRequirements($value['authentication_requirements']) : null,
            'flow_context' => array_key_exists('flow_context', $value) ? self::fromCborAuthFlowContext($value['flow_context']) : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeSignedLocalRpLoginRequest($value)
    {
        return CBOR::encode(self::toCborSignedLocalRpLoginRequest($value));
    }

    public static function decodeSignedLocalRpLoginRequest($bytes)
    {
        return self::fromCborSignedLocalRpLoginRequest(self::csilDecode($bytes));
    }

    public static function toCborSignedLocalRpLoginRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedLocalRpLoginRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedLocalRpLoginRequest ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedLocalRpLoginRequest($value)
    {
        $value = self::csilRecord($value, 'SignedLocalRpLoginRequest', array('request', 'signature'));
        return new SignedLocalRpLoginRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeLocalRpCallbackHeader($value)
    {
        return CBOR::encode(self::toCborLocalRpCallbackHeader($value));
    }

    public static function decodeLocalRpCallbackHeader($bytes)
    {
        return self::fromCborLocalRpCallbackHeader(self::csilDecode($bytes));
    }

    public static function toCborLocalRpCallbackHeader($value)
    {
        $out = array();
        $field = $value instanceof LocalRpCallbackHeader ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof LocalRpCallbackHeader ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackHeader ? $value->state : (is_array($value) && array_key_exists('state', $value) ? $value['state'] : null);
        $out['state'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackHeader ? $value->suite : (is_array($value) && array_key_exists('suite', $value) ? $value['suite'] : null);
        $out['suite'] = self::toCborAeadSuite($field);
        $field = $value instanceof LocalRpCallbackHeader ? $value->ephemeralPublicKey : (is_array($value) && array_key_exists('ephemeral_public_key', $value) ? $value['ephemeral_public_key'] : null);
        $out['ephemeral_public_key'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackHeader ? $value->aeadNonce : (is_array($value) && array_key_exists('aead_nonce', $value) ? $value['aead_nonce'] : null);
        $out['aead_nonce'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackHeader ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof LocalRpCallbackHeader ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborLocalRpCallbackHeader($value)
    {
        $value = self::csilRecord($value, 'LocalRpCallbackHeader', array('fingerprint', 'nonce', 'state', 'suite', 'ephemeral_public_key', 'aead_nonce', 'issued_at', 'expires_at'));
        return new LocalRpCallbackHeader(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'state' => array_key_exists('state', $value) ? $value['state'] : null,
            'suite' => array_key_exists('suite', $value) ? self::fromCborAeadSuite($value['suite']) : null,
            'ephemeral_public_key' => array_key_exists('ephemeral_public_key', $value) ? $value['ephemeral_public_key'] : null,
            'aead_nonce' => array_key_exists('aead_nonce', $value) ? $value['aead_nonce'] : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeLocalRpEncryptedCallback($value)
    {
        return CBOR::encode(self::toCborLocalRpEncryptedCallback($value));
    }

    public static function decodeLocalRpEncryptedCallback($bytes)
    {
        return self::fromCborLocalRpEncryptedCallback(self::csilDecode($bytes));
    }

    public static function toCborLocalRpEncryptedCallback($value)
    {
        $out = array();
        $field = $value instanceof LocalRpEncryptedCallback ? $value->header : (is_array($value) && array_key_exists('header', $value) ? $value['header'] : null);
        $out['header'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpEncryptedCallback ? $value->ciphertext : (is_array($value) && array_key_exists('ciphertext', $value) ? $value['ciphertext'] : null);
        $out['ciphertext'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborLocalRpEncryptedCallback($value)
    {
        $value = self::csilRecord($value, 'LocalRpEncryptedCallback', array('header', 'ciphertext'));
        return new LocalRpEncryptedCallback(array(
            'header' => array_key_exists('header', $value) ? $value['header'] : null,
            'ciphertext' => array_key_exists('ciphertext', $value) ? $value['ciphertext'] : null,
        ));
    }

    public static function encodeLocalRpCallbackPayload($value)
    {
        return CBOR::encode(self::toCborLocalRpCallbackPayload($value));
    }

    public static function decodeLocalRpCallbackPayload($bytes)
    {
        return self::fromCborLocalRpCallbackPayload(self::csilDecode($bytes));
    }

    public static function toCborLocalRpCallbackPayload($value)
    {
        $out = array();
        $field = $value instanceof LocalRpCallbackPayload ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof LocalRpCallbackPayload ? $value->userDomain : (is_array($value) && array_key_exists('user_domain', $value) ? $value['user_domain'] : null);
        $out['user_domain'] = $field;
        $field = $value instanceof LocalRpCallbackPayload ? $value->claimTicket : (is_array($value) && array_key_exists('claim_ticket', $value) ? $value['claim_ticket'] : null);
        $out['claim_ticket'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackPayload ? $value->audienceFingerprint : (is_array($value) && array_key_exists('audience_fingerprint', $value) ? $value['audience_fingerprint'] : null);
        $out['audience_fingerprint'] = $field;
        $field = $value instanceof LocalRpCallbackPayload ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof LocalRpCallbackPayload ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackPayload ? $value->state : (is_array($value) && array_key_exists('state', $value) ? $value['state'] : null);
        $out['state'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpCallbackPayload ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof LocalRpCallbackPayload ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborLocalRpCallbackPayload($value)
    {
        $value = self::csilRecord($value, 'LocalRpCallbackPayload', array('user_id', 'user_domain', 'claim_ticket', 'audience_fingerprint', 'callback_url', 'nonce', 'state', 'issued_at', 'expires_at'));
        return new LocalRpCallbackPayload(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'user_domain' => array_key_exists('user_domain', $value) ? $value['user_domain'] : null,
            'claim_ticket' => array_key_exists('claim_ticket', $value) ? $value['claim_ticket'] : null,
            'audience_fingerprint' => array_key_exists('audience_fingerprint', $value) ? $value['audience_fingerprint'] : null,
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'state' => array_key_exists('state', $value) ? $value['state'] : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeSignedLocalRpCallbackPayload($value)
    {
        return CBOR::encode(self::toCborSignedLocalRpCallbackPayload($value));
    }

    public static function decodeSignedLocalRpCallbackPayload($bytes)
    {
        return self::fromCborSignedLocalRpCallbackPayload(self::csilDecode($bytes));
    }

    public static function toCborSignedLocalRpCallbackPayload($value)
    {
        $out = array();
        $field = $value instanceof SignedLocalRpCallbackPayload ? $value->payload : (is_array($value) && array_key_exists('payload', $value) ? $value['payload'] : null);
        $out['payload'] = CBOR::bytes($field);
        $field = $value instanceof SignedLocalRpCallbackPayload ? $value->signingKeyId : (is_array($value) && array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null);
        $out['signing_key_id'] = $field;
        $field = $value instanceof SignedLocalRpCallbackPayload ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedLocalRpCallbackPayload($value)
    {
        $value = self::csilRecord($value, 'SignedLocalRpCallbackPayload', array('payload', 'signing_key_id', 'signature'));
        return new SignedLocalRpCallbackPayload(array(
            'payload' => array_key_exists('payload', $value) ? $value['payload'] : null,
            'signing_key_id' => array_key_exists('signing_key_id', $value) ? $value['signing_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeLocalRpTicketRedemptionRequest($value)
    {
        return CBOR::encode(self::toCborLocalRpTicketRedemptionRequest($value));
    }

    public static function decodeLocalRpTicketRedemptionRequest($bytes)
    {
        return self::fromCborLocalRpTicketRedemptionRequest(self::csilDecode($bytes));
    }

    public static function toCborLocalRpTicketRedemptionRequest($value)
    {
        $out = array();
        $field = $value instanceof LocalRpTicketRedemptionRequest ? $value->claimTicket : (is_array($value) && array_key_exists('claim_ticket', $value) ? $value['claim_ticket'] : null);
        $out['claim_ticket'] = CBOR::bytes($field);
        $field = $value instanceof LocalRpTicketRedemptionRequest ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof LocalRpTicketRedemptionRequest ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborLocalRpTicketRedemptionRequest($value)
    {
        $value = self::csilRecord($value, 'LocalRpTicketRedemptionRequest', array('claim_ticket', 'fingerprint', 'issued_at'));
        return new LocalRpTicketRedemptionRequest(array(
            'claim_ticket' => array_key_exists('claim_ticket', $value) ? $value['claim_ticket'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
        ));
    }

    public static function encodeSignedLocalRpTicketRedemptionRequest($value)
    {
        return CBOR::encode(self::toCborSignedLocalRpTicketRedemptionRequest($value));
    }

    public static function decodeSignedLocalRpTicketRedemptionRequest($bytes)
    {
        return self::fromCborSignedLocalRpTicketRedemptionRequest(self::csilDecode($bytes));
    }

    public static function toCborSignedLocalRpTicketRedemptionRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedLocalRpTicketRedemptionRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedLocalRpTicketRedemptionRequest ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedLocalRpTicketRedemptionRequest($value)
    {
        $value = self::csilRecord($value, 'SignedLocalRpTicketRedemptionRequest', array('request', 'signature'));
        return new SignedLocalRpTicketRedemptionRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeLocalRpTicketRedemptionResponse($value)
    {
        return CBOR::encode(self::toCborLocalRpTicketRedemptionResponse($value));
    }

    public static function decodeLocalRpTicketRedemptionResponse($bytes)
    {
        return self::fromCborLocalRpTicketRedemptionResponse(self::csilDecode($bytes));
    }

    public static function toCborLocalRpTicketRedemptionResponse($value)
    {
        $out = array();
        $field = $value instanceof LocalRpTicketRedemptionResponse ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof LocalRpTicketRedemptionResponse ? $value->userDomain : (is_array($value) && array_key_exists('user_domain', $value) ? $value['user_domain'] : null);
        $out['user_domain'] = $field;
        $field = $value instanceof LocalRpTicketRedemptionResponse ? $value->claims : (is_array($value) && array_key_exists('claims', $value) ? $value['claims'] : null);
        $out['claims'] = array_map(function ($item) { return self::toCborClaim($item); }, $field === null ? array() : $field);
        $field = $value instanceof LocalRpTicketRedemptionResponse ? $value->ticketExpiresAt : (is_array($value) && array_key_exists('ticket_expires_at', $value) ? $value['ticket_expires_at'] : null);
        $out['ticket_expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborLocalRpTicketRedemptionResponse($value)
    {
        $value = self::csilRecord($value, 'LocalRpTicketRedemptionResponse', array('user_id', 'user_domain', 'claims', 'ticket_expires_at'));
        return new LocalRpTicketRedemptionResponse(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'user_domain' => array_key_exists('user_domain', $value) ? $value['user_domain'] : null,
            'claims' => array_key_exists('claims', $value) ? array_map(function ($item) { return self::fromCborClaim($item); }, self::csilList($value['claims'])) : null,
            'ticket_expires_at' => array_key_exists('ticket_expires_at', $value) ? self::timestampFromCbor($value['ticket_expires_at']) : null,
        ));
    }

    public static function encodeAdminLocalRp($value)
    {
        return CBOR::encode(self::toCborAdminLocalRp($value));
    }

    public static function decodeAdminLocalRp($bytes)
    {
        return self::fromCborAdminLocalRp(self::csilDecode($bytes));
    }

    public static function toCborAdminLocalRp($value)
    {
        $out = array();
        $field = $value instanceof AdminLocalRp ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof AdminLocalRp ? $value->signingPublicKey : (is_array($value) && array_key_exists('signing_public_key', $value) ? $value['signing_public_key'] : null);
        $out['signing_public_key'] = CBOR::bytes($field);
        $field = $value instanceof AdminLocalRp ? $value->encryptionPublicKey : (is_array($value) && array_key_exists('encryption_public_key', $value) ? $value['encryption_public_key'] : null);
        $out['encryption_public_key'] = CBOR::bytes($field);
        $field = $value instanceof AdminLocalRp ? $value->appName : (is_array($value) && array_key_exists('app_name', $value) ? $value['app_name'] : null);
        $out['app_name'] = $field;
        $field = $value instanceof AdminLocalRp ? $value->localDomainHint : (is_array($value) && array_key_exists('local_domain_hint', $value) ? $value['local_domain_hint'] : null);
        if ($field !== null) {
            $out['local_domain_hint'] = $field;
        }
        $field = $value instanceof AdminLocalRp ? $value->status : (is_array($value) && array_key_exists('status', $value) ? $value['status'] : null);
        $out['status'] = self::toCborLocalRpStatus($field);
        $field = $value instanceof AdminLocalRp ? $value->createdAt : (is_array($value) && array_key_exists('created_at', $value) ? $value['created_at'] : null);
        $out['created_at'] = self::timestampToCbor($field);
        $field = $value instanceof AdminLocalRp ? $value->updatedAt : (is_array($value) && array_key_exists('updated_at', $value) ? $value['updated_at'] : null);
        $out['updated_at'] = self::timestampToCbor($field);
        $field = $value instanceof AdminLocalRp ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        if ($field !== null) {
            $out['expires_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof AdminLocalRp ? $value->lastSeenAt : (is_array($value) && array_key_exists('last_seen_at', $value) ? $value['last_seen_at'] : null);
        if ($field !== null) {
            $out['last_seen_at'] = self::timestampToCbor($field);
        }
        $field = $value instanceof AdminLocalRp ? $value->adminNotes : (is_array($value) && array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null);
        if ($field !== null) {
            $out['admin_notes'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAdminLocalRp($value)
    {
        $value = self::csilRecord($value, 'AdminLocalRp', array('fingerprint', 'signing_public_key', 'encryption_public_key', 'app_name', 'status', 'created_at', 'updated_at'));
        return new AdminLocalRp(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'signing_public_key' => array_key_exists('signing_public_key', $value) ? $value['signing_public_key'] : null,
            'encryption_public_key' => array_key_exists('encryption_public_key', $value) ? $value['encryption_public_key'] : null,
            'app_name' => array_key_exists('app_name', $value) ? $value['app_name'] : null,
            'local_domain_hint' => array_key_exists('local_domain_hint', $value) ? $value['local_domain_hint'] : null,
            'status' => array_key_exists('status', $value) ? self::fromCborLocalRpStatus($value['status']) : null,
            'created_at' => array_key_exists('created_at', $value) ? self::timestampFromCbor($value['created_at']) : null,
            'updated_at' => array_key_exists('updated_at', $value) ? self::timestampFromCbor($value['updated_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'last_seen_at' => array_key_exists('last_seen_at', $value) ? self::timestampFromCbor($value['last_seen_at']) : null,
            'admin_notes' => array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null,
        ));
    }

    public static function encodeListLocalRpsRequest($value)
    {
        return CBOR::encode(self::toCborListLocalRpsRequest($value));
    }

    public static function decodeListLocalRpsRequest($bytes)
    {
        return self::fromCborListLocalRpsRequest(self::csilDecode($bytes));
    }

    public static function toCborListLocalRpsRequest($value)
    {
        $out = array();
        $field = $value instanceof ListLocalRpsRequest ? $value->offset : (is_array($value) && array_key_exists('offset', $value) ? $value['offset'] : null);
        if ($field !== null) {
            $out['offset'] = $field;
        }
        $field = $value instanceof ListLocalRpsRequest ? $value->limit : (is_array($value) && array_key_exists('limit', $value) ? $value['limit'] : null);
        if ($field !== null) {
            $out['limit'] = $field;
        }
        $field = $value instanceof ListLocalRpsRequest ? $value->status : (is_array($value) && array_key_exists('status', $value) ? $value['status'] : null);
        if ($field !== null) {
            $out['status'] = self::toCborLocalRpStatus($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListLocalRpsRequest($value)
    {
        $value = self::csilRecord($value, 'ListLocalRpsRequest', array());
        return new ListLocalRpsRequest(array(
            'offset' => array_key_exists('offset', $value) ? $value['offset'] : null,
            'limit' => array_key_exists('limit', $value) ? $value['limit'] : null,
            'status' => array_key_exists('status', $value) ? self::fromCborLocalRpStatus($value['status']) : null,
        ));
    }

    public static function encodeListLocalRpsResponse($value)
    {
        return CBOR::encode(self::toCborListLocalRpsResponse($value));
    }

    public static function decodeListLocalRpsResponse($bytes)
    {
        return self::fromCborListLocalRpsResponse(self::csilDecode($bytes));
    }

    public static function toCborListLocalRpsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListLocalRpsResponse ? $value->localRps : (is_array($value) && array_key_exists('local_rps', $value) ? $value['local_rps'] : null);
        $out['local_rps'] = array_map(function ($item) { return self::toCborAdminLocalRp($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListLocalRpsResponse($value)
    {
        $value = self::csilRecord($value, 'ListLocalRpsResponse', array('local_rps'));
        return new ListLocalRpsResponse(array(
            'local_rps' => array_key_exists('local_rps', $value) ? array_map(function ($item) { return self::fromCborAdminLocalRp($item); }, self::csilList($value['local_rps'])) : null,
        ));
    }

    public static function encodeGetLocalRpRequest($value)
    {
        return CBOR::encode(self::toCborGetLocalRpRequest($value));
    }

    public static function decodeGetLocalRpRequest($bytes)
    {
        return self::fromCborGetLocalRpRequest(self::csilDecode($bytes));
    }

    public static function toCborGetLocalRpRequest($value)
    {
        $out = array();
        $field = $value instanceof GetLocalRpRequest ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetLocalRpRequest($value)
    {
        $value = self::csilRecord($value, 'GetLocalRpRequest', array('fingerprint'));
        return new GetLocalRpRequest(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
        ));
    }

    public static function encodeGetLocalRpResponse($value)
    {
        return CBOR::encode(self::toCborGetLocalRpResponse($value));
    }

    public static function decodeGetLocalRpResponse($bytes)
    {
        return self::fromCborGetLocalRpResponse(self::csilDecode($bytes));
    }

    public static function toCborGetLocalRpResponse($value)
    {
        $out = array();
        $field = $value instanceof GetLocalRpResponse ? $value->localRp : (is_array($value) && array_key_exists('local_rp', $value) ? $value['local_rp'] : null);
        $out['local_rp'] = self::toCborAdminLocalRp($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetLocalRpResponse($value)
    {
        $value = self::csilRecord($value, 'GetLocalRpResponse', array('local_rp'));
        return new GetLocalRpResponse(array(
            'local_rp' => array_key_exists('local_rp', $value) ? self::fromCborAdminLocalRp($value['local_rp']) : null,
        ));
    }

    public static function encodeApproveLocalRpRequest($value)
    {
        return CBOR::encode(self::toCborApproveLocalRpRequest($value));
    }

    public static function decodeApproveLocalRpRequest($bytes)
    {
        return self::fromCborApproveLocalRpRequest(self::csilDecode($bytes));
    }

    public static function toCborApproveLocalRpRequest($value)
    {
        $out = array();
        $field = $value instanceof ApproveLocalRpRequest ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof ApproveLocalRpRequest ? $value->adminNotes : (is_array($value) && array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null);
        if ($field !== null) {
            $out['admin_notes'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApproveLocalRpRequest($value)
    {
        $value = self::csilRecord($value, 'ApproveLocalRpRequest', array('fingerprint'));
        return new ApproveLocalRpRequest(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'admin_notes' => array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null,
        ));
    }

    public static function encodeApproveLocalRpResponse($value)
    {
        return CBOR::encode(self::toCborApproveLocalRpResponse($value));
    }

    public static function decodeApproveLocalRpResponse($bytes)
    {
        return self::fromCborApproveLocalRpResponse(self::csilDecode($bytes));
    }

    public static function toCborApproveLocalRpResponse($value)
    {
        $out = array();
        $field = $value instanceof ApproveLocalRpResponse ? $value->localRp : (is_array($value) && array_key_exists('local_rp', $value) ? $value['local_rp'] : null);
        $out['local_rp'] = self::toCborAdminLocalRp($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApproveLocalRpResponse($value)
    {
        $value = self::csilRecord($value, 'ApproveLocalRpResponse', array('local_rp'));
        return new ApproveLocalRpResponse(array(
            'local_rp' => array_key_exists('local_rp', $value) ? self::fromCborAdminLocalRp($value['local_rp']) : null,
        ));
    }

    public static function encodeDenyLocalRpRequest($value)
    {
        return CBOR::encode(self::toCborDenyLocalRpRequest($value));
    }

    public static function decodeDenyLocalRpRequest($bytes)
    {
        return self::fromCborDenyLocalRpRequest(self::csilDecode($bytes));
    }

    public static function toCborDenyLocalRpRequest($value)
    {
        $out = array();
        $field = $value instanceof DenyLocalRpRequest ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof DenyLocalRpRequest ? $value->adminNotes : (is_array($value) && array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null);
        if ($field !== null) {
            $out['admin_notes'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborDenyLocalRpRequest($value)
    {
        $value = self::csilRecord($value, 'DenyLocalRpRequest', array('fingerprint'));
        return new DenyLocalRpRequest(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'admin_notes' => array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null,
        ));
    }

    public static function encodeDenyLocalRpResponse($value)
    {
        return CBOR::encode(self::toCborDenyLocalRpResponse($value));
    }

    public static function decodeDenyLocalRpResponse($bytes)
    {
        return self::fromCborDenyLocalRpResponse(self::csilDecode($bytes));
    }

    public static function toCborDenyLocalRpResponse($value)
    {
        $out = array();
        $field = $value instanceof DenyLocalRpResponse ? $value->localRp : (is_array($value) && array_key_exists('local_rp', $value) ? $value['local_rp'] : null);
        $out['local_rp'] = self::toCborAdminLocalRp($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborDenyLocalRpResponse($value)
    {
        $value = self::csilRecord($value, 'DenyLocalRpResponse', array('local_rp'));
        return new DenyLocalRpResponse(array(
            'local_rp' => array_key_exists('local_rp', $value) ? self::fromCborAdminLocalRp($value['local_rp']) : null,
        ));
    }

    public static function encodeRevokeLocalRpRequest($value)
    {
        return CBOR::encode(self::toCborRevokeLocalRpRequest($value));
    }

    public static function decodeRevokeLocalRpRequest($bytes)
    {
        return self::fromCborRevokeLocalRpRequest(self::csilDecode($bytes));
    }

    public static function toCborRevokeLocalRpRequest($value)
    {
        $out = array();
        $field = $value instanceof RevokeLocalRpRequest ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof RevokeLocalRpRequest ? $value->adminNotes : (is_array($value) && array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null);
        if ($field !== null) {
            $out['admin_notes'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeLocalRpRequest($value)
    {
        $value = self::csilRecord($value, 'RevokeLocalRpRequest', array('fingerprint'));
        return new RevokeLocalRpRequest(array(
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'admin_notes' => array_key_exists('admin_notes', $value) ? $value['admin_notes'] : null,
        ));
    }

    public static function encodeRevokeLocalRpResponse($value)
    {
        return CBOR::encode(self::toCborRevokeLocalRpResponse($value));
    }

    public static function decodeRevokeLocalRpResponse($bytes)
    {
        return self::fromCborRevokeLocalRpResponse(self::csilDecode($bytes));
    }

    public static function toCborRevokeLocalRpResponse($value)
    {
        $out = array();
        $field = $value instanceof RevokeLocalRpResponse ? $value->localRp : (is_array($value) && array_key_exists('local_rp', $value) ? $value['local_rp'] : null);
        $out['local_rp'] = self::toCborAdminLocalRp($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeLocalRpResponse($value)
    {
        $value = self::csilRecord($value, 'RevokeLocalRpResponse', array('local_rp'));
        return new RevokeLocalRpResponse(array(
            'local_rp' => array_key_exists('local_rp', $value) ? self::fromCborAdminLocalRp($value['local_rp']) : null,
        ));
    }

    public static function encodeGetLocalRpPolicyRequest($value)
    {
        return CBOR::encode(self::toCborGetLocalRpPolicyRequest($value));
    }

    public static function decodeGetLocalRpPolicyRequest($bytes)
    {
        return self::fromCborGetLocalRpPolicyRequest(self::csilDecode($bytes));
    }

    public static function toCborGetLocalRpPolicyRequest($value)
    {
        $out = array();
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetLocalRpPolicyRequest($value)
    {
        $value = self::csilRecord($value, 'GetLocalRpPolicyRequest', array());
        return new GetLocalRpPolicyRequest(array(
        ));
    }

    public static function encodeGetLocalRpPolicyResponse($value)
    {
        return CBOR::encode(self::toCborGetLocalRpPolicyResponse($value));
    }

    public static function decodeGetLocalRpPolicyResponse($bytes)
    {
        return self::fromCborGetLocalRpPolicyResponse(self::csilDecode($bytes));
    }

    public static function toCborGetLocalRpPolicyResponse($value)
    {
        $out = array();
        $field = $value instanceof GetLocalRpPolicyResponse ? $value->policy : (is_array($value) && array_key_exists('policy', $value) ? $value['policy'] : null);
        $out['policy'] = self::toCborLocalRpPolicy($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetLocalRpPolicyResponse($value)
    {
        $value = self::csilRecord($value, 'GetLocalRpPolicyResponse', array('policy'));
        return new GetLocalRpPolicyResponse(array(
            'policy' => array_key_exists('policy', $value) ? self::fromCborLocalRpPolicy($value['policy']) : null,
        ));
    }

    public static function encodeSetLocalRpPolicyRequest($value)
    {
        return CBOR::encode(self::toCborSetLocalRpPolicyRequest($value));
    }

    public static function decodeSetLocalRpPolicyRequest($bytes)
    {
        return self::fromCborSetLocalRpPolicyRequest(self::csilDecode($bytes));
    }

    public static function toCborSetLocalRpPolicyRequest($value)
    {
        $out = array();
        $field = $value instanceof SetLocalRpPolicyRequest ? $value->policy : (is_array($value) && array_key_exists('policy', $value) ? $value['policy'] : null);
        $out['policy'] = self::toCborLocalRpPolicy($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetLocalRpPolicyRequest($value)
    {
        $value = self::csilRecord($value, 'SetLocalRpPolicyRequest', array('policy'));
        return new SetLocalRpPolicyRequest(array(
            'policy' => array_key_exists('policy', $value) ? self::fromCborLocalRpPolicy($value['policy']) : null,
        ));
    }

    public static function encodeSetLocalRpPolicyResponse($value)
    {
        return CBOR::encode(self::toCborSetLocalRpPolicyResponse($value));
    }

    public static function decodeSetLocalRpPolicyResponse($bytes)
    {
        return self::fromCborSetLocalRpPolicyResponse(self::csilDecode($bytes));
    }

    public static function toCborSetLocalRpPolicyResponse($value)
    {
        $out = array();
        $field = $value instanceof SetLocalRpPolicyResponse ? $value->policy : (is_array($value) && array_key_exists('policy', $value) ? $value['policy'] : null);
        $out['policy'] = self::toCborLocalRpPolicy($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetLocalRpPolicyResponse($value)
    {
        $value = self::csilRecord($value, 'SetLocalRpPolicyResponse', array('policy'));
        return new SetLocalRpPolicyResponse(array(
            'policy' => array_key_exists('policy', $value) ? self::fromCborLocalRpPolicy($value['policy']) : null,
        ));
    }

    public static function encodeSignInPolicy($value)
    {
        return CBOR::encode(self::toCborSignInPolicy($value));
    }

    public static function decodeSignInPolicy($bytes)
    {
        return self::fromCborSignInPolicy(self::csilDecode($bytes));
    }

    public static function toCborSignInPolicy($value)
    {
        $out = array();
        $field = $value instanceof SignInPolicy ? $value->signInHours : (is_array($value) && array_key_exists('sign_in_hours', $value) ? $value['sign_in_hours'] : null);
        $out['sign_in_hours'] = $field;
        $field = $value instanceof SignInPolicy ? $value->defaultSignInHours : (is_array($value) && array_key_exists('default_sign_in_hours', $value) ? $value['default_sign_in_hours'] : null);
        $out['default_sign_in_hours'] = $field;
        $field = $value instanceof SignInPolicy ? $value->minSignInHours : (is_array($value) && array_key_exists('min_sign_in_hours', $value) ? $value['min_sign_in_hours'] : null);
        $out['min_sign_in_hours'] = $field;
        $field = $value instanceof SignInPolicy ? $value->maxSignInHours : (is_array($value) && array_key_exists('max_sign_in_hours', $value) ? $value['max_sign_in_hours'] : null);
        $out['max_sign_in_hours'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignInPolicy($value)
    {
        $value = self::csilRecord($value, 'SignInPolicy', array('sign_in_hours', 'default_sign_in_hours', 'min_sign_in_hours', 'max_sign_in_hours'));
        return new SignInPolicy(array(
            'sign_in_hours' => array_key_exists('sign_in_hours', $value) ? $value['sign_in_hours'] : null,
            'default_sign_in_hours' => array_key_exists('default_sign_in_hours', $value) ? $value['default_sign_in_hours'] : null,
            'min_sign_in_hours' => array_key_exists('min_sign_in_hours', $value) ? $value['min_sign_in_hours'] : null,
            'max_sign_in_hours' => array_key_exists('max_sign_in_hours', $value) ? $value['max_sign_in_hours'] : null,
        ));
    }

    public static function encodeSetSignInPolicyRequest($value)
    {
        return CBOR::encode(self::toCborSetSignInPolicyRequest($value));
    }

    public static function decodeSetSignInPolicyRequest($bytes)
    {
        return self::fromCborSetSignInPolicyRequest(self::csilDecode($bytes));
    }

    public static function toCborSetSignInPolicyRequest($value)
    {
        $out = array();
        $field = $value instanceof SetSignInPolicyRequest ? $value->signInHours : (is_array($value) && array_key_exists('sign_in_hours', $value) ? $value['sign_in_hours'] : null);
        $out['sign_in_hours'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetSignInPolicyRequest($value)
    {
        $value = self::csilRecord($value, 'SetSignInPolicyRequest', array('sign_in_hours'));
        return new SetSignInPolicyRequest(array(
            'sign_in_hours' => array_key_exists('sign_in_hours', $value) ? $value['sign_in_hours'] : null,
        ));
    }

    public static function encodeSetUserPasswordLockRequest($value)
    {
        return CBOR::encode(self::toCborSetUserPasswordLockRequest($value));
    }

    public static function decodeSetUserPasswordLockRequest($bytes)
    {
        return self::fromCborSetUserPasswordLockRequest(self::csilDecode($bytes));
    }

    public static function toCborSetUserPasswordLockRequest($value)
    {
        $out = array();
        $field = $value instanceof SetUserPasswordLockRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof SetUserPasswordLockRequest ? $value->locked : (is_array($value) && array_key_exists('locked', $value) ? $value['locked'] : null);
        $out['locked'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetUserPasswordLockRequest($value)
    {
        $value = self::csilRecord($value, 'SetUserPasswordLockRequest', array('user_id', 'locked'));
        return new SetUserPasswordLockRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'locked' => array_key_exists('locked', $value) ? $value['locked'] : null,
        ));
    }

    public static function encodeSetUserPasswordLockResponse($value)
    {
        return CBOR::encode(self::toCborSetUserPasswordLockResponse($value));
    }

    public static function decodeSetUserPasswordLockResponse($bytes)
    {
        return self::fromCborSetUserPasswordLockResponse(self::csilDecode($bytes));
    }

    public static function toCborSetUserPasswordLockResponse($value)
    {
        $out = array();
        $field = $value instanceof SetUserPasswordLockResponse ? $value->user : (is_array($value) && array_key_exists('user', $value) ? $value['user'] : null);
        $out['user'] = self::toCborAdminUser($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetUserPasswordLockResponse($value)
    {
        $value = self::csilRecord($value, 'SetUserPasswordLockResponse', array('user'));
        return new SetUserPasswordLockResponse(array(
            'user' => array_key_exists('user', $value) ? self::fromCborAdminUser($value['user']) : null,
        ));
    }

    public static function encodeAppAccessTarget($value)
    {
        return CBOR::encode(self::toCborAppAccessTarget($value));
    }

    public static function decodeAppAccessTarget($bytes)
    {
        return self::fromCborAppAccessTarget(self::csilDecode($bytes));
    }

    public static function toCborAppAccessTarget($value)
    {
        $out = array();
        $field = $value instanceof AppAccessTarget ? $value->kind : (is_array($value) && array_key_exists('kind', $value) ? $value['kind'] : null);
        $out['kind'] = self::toCborAppAccessTargetKind($field);
        $field = $value instanceof AppAccessTarget ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        if ($field !== null) {
            $out['user_id'] = $field;
        }
        $field = $value instanceof AppAccessTarget ? $value->groupName : (is_array($value) && array_key_exists('group_name', $value) ? $value['group_name'] : null);
        if ($field !== null) {
            $out['group_name'] = $field;
        }
        $field = $value instanceof AppAccessTarget ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        if ($field !== null) {
            $out['claim_type'] = $field;
        }
        $field = $value instanceof AppAccessTarget ? $value->claimOperator : (is_array($value) && array_key_exists('claim_operator', $value) ? $value['claim_operator'] : null);
        if ($field !== null) {
            $out['claim_operator'] = self::toCborClaimOperator($field);
        }
        $field = $value instanceof AppAccessTarget ? $value->claimValue : (is_array($value) && array_key_exists('claim_value', $value) ? $value['claim_value'] : null);
        if ($field !== null) {
            $out['claim_value'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAppAccessTarget($value)
    {
        $value = self::csilRecord($value, 'AppAccessTarget', array('kind'));
        return new AppAccessTarget(array(
            'kind' => array_key_exists('kind', $value) ? self::fromCborAppAccessTargetKind($value['kind']) : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'group_name' => array_key_exists('group_name', $value) ? $value['group_name'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'claim_operator' => array_key_exists('claim_operator', $value) ? self::fromCborClaimOperator($value['claim_operator']) : null,
            'claim_value' => array_key_exists('claim_value', $value) ? $value['claim_value'] : null,
        ));
    }

    public static function encodeAppAccessPolicy($value)
    {
        return CBOR::encode(self::toCborAppAccessPolicy($value));
    }

    public static function decodeAppAccessPolicy($bytes)
    {
        return self::fromCborAppAccessPolicy(self::csilDecode($bytes));
    }

    public static function toCborAppAccessPolicy($value)
    {
        $out = array();
        $field = $value instanceof AppAccessPolicy ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        $field = $value instanceof AppAccessPolicy ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        $out['name'] = $field;
        $field = $value instanceof AppAccessPolicy ? $value->mode : (is_array($value) && array_key_exists('mode', $value) ? $value['mode'] : null);
        $out['mode'] = self::toCborAppAccessMode($field);
        $field = $value instanceof AppAccessPolicy ? $value->patterns : (is_array($value) && array_key_exists('patterns', $value) ? $value['patterns'] : null);
        $out['patterns'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof AppAccessPolicy ? $value->message : (is_array($value) && array_key_exists('message', $value) ? $value['message'] : null);
        if ($field !== null) {
            $out['message'] = $field;
        }
        $field = $value instanceof AppAccessPolicy ? $value->targets : (is_array($value) && array_key_exists('targets', $value) ? $value['targets'] : null);
        $out['targets'] = array_map(function ($item) { return self::toCborAppAccessTarget($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAppAccessPolicy($value)
    {
        $value = self::csilRecord($value, 'AppAccessPolicy', array('id', 'name', 'mode', 'patterns', 'targets'));
        return new AppAccessPolicy(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
            'mode' => array_key_exists('mode', $value) ? self::fromCborAppAccessMode($value['mode']) : null,
            'patterns' => array_key_exists('patterns', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['patterns'])) : null,
            'message' => array_key_exists('message', $value) ? $value['message'] : null,
            'targets' => array_key_exists('targets', $value) ? array_map(function ($item) { return self::fromCborAppAccessTarget($item); }, self::csilList($value['targets'])) : null,
        ));
    }

    public static function encodeListAppAccessPoliciesResponse($value)
    {
        return CBOR::encode(self::toCborListAppAccessPoliciesResponse($value));
    }

    public static function decodeListAppAccessPoliciesResponse($bytes)
    {
        return self::fromCborListAppAccessPoliciesResponse(self::csilDecode($bytes));
    }

    public static function toCborListAppAccessPoliciesResponse($value)
    {
        $out = array();
        $field = $value instanceof ListAppAccessPoliciesResponse ? $value->policies : (is_array($value) && array_key_exists('policies', $value) ? $value['policies'] : null);
        $out['policies'] = array_map(function ($item) { return self::toCborAppAccessPolicy($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListAppAccessPoliciesResponse($value)
    {
        $value = self::csilRecord($value, 'ListAppAccessPoliciesResponse', array('policies'));
        return new ListAppAccessPoliciesResponse(array(
            'policies' => array_key_exists('policies', $value) ? array_map(function ($item) { return self::fromCborAppAccessPolicy($item); }, self::csilList($value['policies'])) : null,
        ));
    }

    public static function encodeSetAppAccessPolicyRequest($value)
    {
        return CBOR::encode(self::toCborSetAppAccessPolicyRequest($value));
    }

    public static function decodeSetAppAccessPolicyRequest($bytes)
    {
        return self::fromCborSetAppAccessPolicyRequest(self::csilDecode($bytes));
    }

    public static function toCborSetAppAccessPolicyRequest($value)
    {
        $out = array();
        $field = $value instanceof SetAppAccessPolicyRequest ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        if ($field !== null) {
            $out['id'] = $field;
        }
        $field = $value instanceof SetAppAccessPolicyRequest ? $value->name : (is_array($value) && array_key_exists('name', $value) ? $value['name'] : null);
        $out['name'] = $field;
        $field = $value instanceof SetAppAccessPolicyRequest ? $value->mode : (is_array($value) && array_key_exists('mode', $value) ? $value['mode'] : null);
        $out['mode'] = self::toCborAppAccessMode($field);
        $field = $value instanceof SetAppAccessPolicyRequest ? $value->patterns : (is_array($value) && array_key_exists('patterns', $value) ? $value['patterns'] : null);
        $out['patterns'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof SetAppAccessPolicyRequest ? $value->message : (is_array($value) && array_key_exists('message', $value) ? $value['message'] : null);
        if ($field !== null) {
            $out['message'] = $field;
        }
        $field = $value instanceof SetAppAccessPolicyRequest ? $value->targets : (is_array($value) && array_key_exists('targets', $value) ? $value['targets'] : null);
        $out['targets'] = array_map(function ($item) { return self::toCborAppAccessTarget($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetAppAccessPolicyRequest($value)
    {
        $value = self::csilRecord($value, 'SetAppAccessPolicyRequest', array('name', 'mode', 'patterns', 'targets'));
        return new SetAppAccessPolicyRequest(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
            'name' => array_key_exists('name', $value) ? $value['name'] : null,
            'mode' => array_key_exists('mode', $value) ? self::fromCborAppAccessMode($value['mode']) : null,
            'patterns' => array_key_exists('patterns', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['patterns'])) : null,
            'message' => array_key_exists('message', $value) ? $value['message'] : null,
            'targets' => array_key_exists('targets', $value) ? array_map(function ($item) { return self::fromCborAppAccessTarget($item); }, self::csilList($value['targets'])) : null,
        ));
    }

    public static function encodeSetAppAccessPolicyResponse($value)
    {
        return CBOR::encode(self::toCborSetAppAccessPolicyResponse($value));
    }

    public static function decodeSetAppAccessPolicyResponse($bytes)
    {
        return self::fromCborSetAppAccessPolicyResponse(self::csilDecode($bytes));
    }

    public static function toCborSetAppAccessPolicyResponse($value)
    {
        $out = array();
        $field = $value instanceof SetAppAccessPolicyResponse ? $value->policy : (is_array($value) && array_key_exists('policy', $value) ? $value['policy'] : null);
        $out['policy'] = self::toCborAppAccessPolicy($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSetAppAccessPolicyResponse($value)
    {
        $value = self::csilRecord($value, 'SetAppAccessPolicyResponse', array('policy'));
        return new SetAppAccessPolicyResponse(array(
            'policy' => array_key_exists('policy', $value) ? self::fromCborAppAccessPolicy($value['policy']) : null,
        ));
    }

    public static function encodeRemoveAppAccessPolicyRequest($value)
    {
        return CBOR::encode(self::toCborRemoveAppAccessPolicyRequest($value));
    }

    public static function decodeRemoveAppAccessPolicyRequest($bytes)
    {
        return self::fromCborRemoveAppAccessPolicyRequest(self::csilDecode($bytes));
    }

    public static function toCborRemoveAppAccessPolicyRequest($value)
    {
        $out = array();
        $field = $value instanceof RemoveAppAccessPolicyRequest ? $value->id : (is_array($value) && array_key_exists('id', $value) ? $value['id'] : null);
        $out['id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveAppAccessPolicyRequest($value)
    {
        $value = self::csilRecord($value, 'RemoveAppAccessPolicyRequest', array('id'));
        return new RemoveAppAccessPolicyRequest(array(
            'id' => array_key_exists('id', $value) ? $value['id'] : null,
        ));
    }

    public static function encodeRemoveAppAccessPolicyResponse($value)
    {
        return CBOR::encode(self::toCborRemoveAppAccessPolicyResponse($value));
    }

    public static function decodeRemoveAppAccessPolicyResponse($bytes)
    {
        return self::fromCborRemoveAppAccessPolicyResponse(self::csilDecode($bytes));
    }

    public static function toCborRemoveAppAccessPolicyResponse($value)
    {
        $out = array();
        $field = $value instanceof RemoveAppAccessPolicyResponse ? $value->success : (is_array($value) && array_key_exists('success', $value) ? $value['success'] : null);
        $out['success'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRemoveAppAccessPolicyResponse($value)
    {
        $value = self::csilRecord($value, 'RemoveAppAccessPolicyResponse', array('success'));
        return new RemoveAppAccessPolicyResponse(array(
            'success' => array_key_exists('success', $value) ? $value['success'] : null,
        ));
    }

    public static function encodePreviewAppAccessRequest($value)
    {
        return CBOR::encode(self::toCborPreviewAppAccessRequest($value));
    }

    public static function decodePreviewAppAccessRequest($bytes)
    {
        return self::fromCborPreviewAppAccessRequest(self::csilDecode($bytes));
    }

    public static function toCborPreviewAppAccessRequest($value)
    {
        $out = array();
        $field = $value instanceof PreviewAppAccessRequest ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof PreviewAppAccessRequest ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        if ($field !== null) {
            $out['domain'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPreviewAppAccessRequest($value)
    {
        $value = self::csilRecord($value, 'PreviewAppAccessRequest', array('user_id'));
        return new PreviewAppAccessRequest(array(
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
        ));
    }

    public static function encodePreviewAppAccessResponse($value)
    {
        return CBOR::encode(self::toCborPreviewAppAccessResponse($value));
    }

    public static function decodePreviewAppAccessResponse($bytes)
    {
        return self::fromCborPreviewAppAccessResponse(self::csilDecode($bytes));
    }

    public static function toCborPreviewAppAccessResponse($value)
    {
        $out = array();
        $field = $value instanceof PreviewAppAccessResponse ? $value->allowed : (is_array($value) && array_key_exists('allowed', $value) ? $value['allowed'] : null);
        $out['allowed'] = $field;
        $field = $value instanceof PreviewAppAccessResponse ? $value->appliedPolicies : (is_array($value) && array_key_exists('applied_policies', $value) ? $value['applied_policies'] : null);
        $out['applied_policies'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewAppAccessResponse ? $value->blockingPolicies : (is_array($value) && array_key_exists('blocking_policies', $value) ? $value['blocking_policies'] : null);
        $out['blocking_policies'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewAppAccessResponse ? $value->messages : (is_array($value) && array_key_exists('messages', $value) ? $value['messages'] : null);
        $out['messages'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPreviewAppAccessResponse($value)
    {
        $value = self::csilRecord($value, 'PreviewAppAccessResponse', array('allowed', 'applied_policies', 'blocking_policies', 'messages'));
        return new PreviewAppAccessResponse(array(
            'allowed' => array_key_exists('allowed', $value) ? $value['allowed'] : null,
            'applied_policies' => array_key_exists('applied_policies', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['applied_policies'])) : null,
            'blocking_policies' => array_key_exists('blocking_policies', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['blocking_policies'])) : null,
            'messages' => array_key_exists('messages', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['messages'])) : null,
        ));
    }

    public static function encodeAppAccessDenial($value)
    {
        return CBOR::encode(self::toCborAppAccessDenial($value));
    }

    public static function decodeAppAccessDenial($bytes)
    {
        return self::fromCborAppAccessDenial(self::csilDecode($bytes));
    }

    public static function toCborAppAccessDenial($value)
    {
        $out = array();
        $field = $value instanceof AppAccessDenial ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        if ($field !== null) {
            $out['domain'] = $field;
        }
        $field = $value instanceof AppAccessDenial ? $value->messages : (is_array($value) && array_key_exists('messages', $value) ? $value['messages'] : null);
        $out['messages'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAppAccessDenial($value)
    {
        $value = self::csilRecord($value, 'AppAccessDenial', array('messages'));
        return new AppAccessDenial(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'messages' => array_key_exists('messages', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['messages'])) : null,
        ));
    }

    public static function encodePurgeLocalRpTicketsRequest($value)
    {
        return CBOR::encode(self::toCborPurgeLocalRpTicketsRequest($value));
    }

    public static function decodePurgeLocalRpTicketsRequest($bytes)
    {
        return self::fromCborPurgeLocalRpTicketsRequest(self::csilDecode($bytes));
    }

    public static function toCborPurgeLocalRpTicketsRequest($value)
    {
        $out = array();
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPurgeLocalRpTicketsRequest($value)
    {
        $value = self::csilRecord($value, 'PurgeLocalRpTicketsRequest', array());
        return new PurgeLocalRpTicketsRequest(array(
        ));
    }

    public static function encodePurgeLocalRpTicketsResponse($value)
    {
        return CBOR::encode(self::toCborPurgeLocalRpTicketsResponse($value));
    }

    public static function decodePurgeLocalRpTicketsResponse($bytes)
    {
        return self::fromCborPurgeLocalRpTicketsResponse(self::csilDecode($bytes));
    }

    public static function toCborPurgeLocalRpTicketsResponse($value)
    {
        $out = array();
        $field = $value instanceof PurgeLocalRpTicketsResponse ? $value->purgedCount : (is_array($value) && array_key_exists('purged_count', $value) ? $value['purged_count'] : null);
        $out['purged_count'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPurgeLocalRpTicketsResponse($value)
    {
        $value = self::csilRecord($value, 'PurgeLocalRpTicketsResponse', array('purged_count'));
        return new PurgeLocalRpTicketsResponse(array(
            'purged_count' => array_key_exists('purged_count', $value) ? $value['purged_count'] : null,
        ));
    }

    public static function encodeLocaleMessages($value)
    {
        return CBOR::encode(self::toCborLocaleMessages($value));
    }

    public static function decodeLocaleMessages($bytes)
    {
        return self::fromCborLocaleMessages(self::csilDecode($bytes));
    }

    public static function toCborLocaleMessages($value)
    {
        return (function ($m) { $entries = array(); foreach (($m === null ? array() : $m) as $k => $v) { $entries[] = array((string) $k, $v); } return CBOR::mapEntries($entries); })($value);
    }

    public static function fromCborLocaleMessages($value)
    {
        return (function ($m) { $out = array(); foreach (self::csilCanonicalMap($m) as $k => $v) { $out[$k] = $v; } return $out; })($value);
    }

    public static function encodeTranslationsRequest($value)
    {
        return CBOR::encode(self::toCborTranslationsRequest($value));
    }

    public static function decodeTranslationsRequest($bytes)
    {
        return self::fromCborTranslationsRequest(self::csilDecode($bytes));
    }

    public static function toCborTranslationsRequest($value)
    {
        $out = array();
        $field = $value instanceof TranslationsRequest ? $value->locale : (is_array($value) && array_key_exists('locale', $value) ? $value['locale'] : null);
        if ($field !== null) {
            $out['locale'] = $field;
        }
        $field = $value instanceof TranslationsRequest ? $value->acceptLanguage : (is_array($value) && array_key_exists('accept_language', $value) ? $value['accept_language'] : null);
        if ($field !== null) {
            $out['accept_language'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborTranslationsRequest($value)
    {
        $value = self::csilRecord($value, 'TranslationsRequest', array());
        return new TranslationsRequest(array(
            'locale' => array_key_exists('locale', $value) ? $value['locale'] : null,
            'accept_language' => array_key_exists('accept_language', $value) ? $value['accept_language'] : null,
        ));
    }

    public static function encodeTranslationsResponse($value)
    {
        return CBOR::encode(self::toCborTranslationsResponse($value));
    }

    public static function decodeTranslationsResponse($bytes)
    {
        return self::fromCborTranslationsResponse(self::csilDecode($bytes));
    }

    public static function toCborTranslationsResponse($value)
    {
        $out = array();
        $field = $value instanceof TranslationsResponse ? $value->locale : (is_array($value) && array_key_exists('locale', $value) ? $value['locale'] : null);
        $out['locale'] = $field;
        $field = $value instanceof TranslationsResponse ? $value->availableLocales : (is_array($value) && array_key_exists('available_locales', $value) ? $value['available_locales'] : null);
        $out['available_locales'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof TranslationsResponse ? $value->messages : (is_array($value) && array_key_exists('messages', $value) ? $value['messages'] : null);
        $out['messages'] = self::toCborLocaleMessages($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborTranslationsResponse($value)
    {
        $value = self::csilRecord($value, 'TranslationsResponse', array('locale', 'available_locales', 'messages'));
        return new TranslationsResponse(array(
            'locale' => array_key_exists('locale', $value) ? $value['locale'] : null,
            'available_locales' => array_key_exists('available_locales', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['available_locales'])) : null,
            'messages' => array_key_exists('messages', $value) ? self::fromCborLocaleMessages($value['messages']) : null,
        ));
    }

    public static function encodeListLocalesResponse($value)
    {
        return CBOR::encode(self::toCborListLocalesResponse($value));
    }

    public static function decodeListLocalesResponse($bytes)
    {
        return self::fromCborListLocalesResponse(self::csilDecode($bytes));
    }

    public static function toCborListLocalesResponse($value)
    {
        $out = array();
        $field = $value instanceof ListLocalesResponse ? $value->availableLocales : (is_array($value) && array_key_exists('available_locales', $value) ? $value['available_locales'] : null);
        $out['available_locales'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListLocalesResponse($value)
    {
        $value = self::csilRecord($value, 'ListLocalesResponse', array('available_locales'));
        return new ListLocalesResponse(array(
            'available_locales' => array_key_exists('available_locales', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['available_locales'])) : null,
        ));
    }

    public static function encodeApplicationKeySignature($value)
    {
        return CBOR::encode(self::toCborApplicationKeySignature($value));
    }

    public static function decodeApplicationKeySignature($bytes)
    {
        return self::fromCborApplicationKeySignature(self::csilDecode($bytes));
    }

    public static function toCborApplicationKeySignature($value)
    {
        $out = array();
        $field = $value instanceof ApplicationKeySignature ? $value->signedByKeyId : (is_array($value) && array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null);
        $out['signed_by_key_id'] = $field;
        $field = $value instanceof ApplicationKeySignature ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApplicationKeySignature($value)
    {
        $value = self::csilRecord($value, 'ApplicationKeySignature', array('signed_by_key_id', 'signature'));
        return new ApplicationKeySignature(array(
            'signed_by_key_id' => array_key_exists('signed_by_key_id', $value) ? $value['signed_by_key_id'] : null,
            'signature' => array_key_exists('signature', $value) ? $value['signature'] : null,
        ));
    }

    public static function encodeApplicationKeyAttestation($value)
    {
        return CBOR::encode(self::toCborApplicationKeyAttestation($value));
    }

    public static function decodeApplicationKeyAttestation($bytes)
    {
        return self::fromCborApplicationKeyAttestation(self::csilDecode($bytes));
    }

    public static function toCborApplicationKeyAttestation($value)
    {
        $out = array();
        $field = $value instanceof ApplicationKeyAttestation ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->keyUsage : (is_array($value) && array_key_exists('key_usage', $value) ? $value['key_usage'] : null);
        $out['key_usage'] = self::toCborKeyUsage($field);
        $field = $value instanceof ApplicationKeyAttestation ? $value->algorithm : (is_array($value) && array_key_exists('algorithm', $value) ? $value['algorithm'] : null);
        $out['algorithm'] = self::toCborKeyAlgorithm($field);
        $field = $value instanceof ApplicationKeyAttestation ? $value->publicKey : (is_array($value) && array_key_exists('public_key', $value) ? $value['public_key'] : null);
        $out['public_key'] = CBOR::bytes($field);
        $field = $value instanceof ApplicationKeyAttestation ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof ApplicationKeyAttestation ? $value->keyCreatedAt : (is_array($value) && array_key_exists('key_created_at', $value) ? $value['key_created_at'] : null);
        $out['key_created_at'] = self::timestampToCbor($field);
        $field = $value instanceof ApplicationKeyAttestation ? $value->keyExpiresAt : (is_array($value) && array_key_exists('key_expires_at', $value) ? $value['key_expires_at'] : null);
        $out['key_expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof ApplicationKeyAttestation ? $value->attestedAt : (is_array($value) && array_key_exists('attested_at', $value) ? $value['attested_at'] : null);
        $out['attested_at'] = self::timestampToCbor($field);
        $field = $value instanceof ApplicationKeyAttestation ? $value->attestationExpiresAt : (is_array($value) && array_key_exists('attestation_expires_at', $value) ? $value['attestation_expires_at'] : null);
        $out['attestation_expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApplicationKeyAttestation($value)
    {
        $value = self::csilRecord($value, 'ApplicationKeyAttestation', array('subject_user_id', 'subject_domain', 'application_id', 'instance_id', 'key_id', 'key_usage', 'algorithm', 'public_key', 'fingerprint', 'key_created_at', 'key_expires_at', 'attested_at', 'attestation_expires_at'));
        return new ApplicationKeyAttestation(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'key_usage' => array_key_exists('key_usage', $value) ? self::fromCborKeyUsage($value['key_usage']) : null,
            'algorithm' => array_key_exists('algorithm', $value) ? self::fromCborKeyAlgorithm($value['algorithm']) : null,
            'public_key' => array_key_exists('public_key', $value) ? $value['public_key'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'key_created_at' => array_key_exists('key_created_at', $value) ? self::timestampFromCbor($value['key_created_at']) : null,
            'key_expires_at' => array_key_exists('key_expires_at', $value) ? self::timestampFromCbor($value['key_expires_at']) : null,
            'attested_at' => array_key_exists('attested_at', $value) ? self::timestampFromCbor($value['attested_at']) : null,
            'attestation_expires_at' => array_key_exists('attestation_expires_at', $value) ? self::timestampFromCbor($value['attestation_expires_at']) : null,
        ));
    }

    public static function encodeSignedApplicationKeyAttestation($value)
    {
        return CBOR::encode(self::toCborSignedApplicationKeyAttestation($value));
    }

    public static function decodeSignedApplicationKeyAttestation($bytes)
    {
        return self::fromCborSignedApplicationKeyAttestation(self::csilDecode($bytes));
    }

    public static function toCborSignedApplicationKeyAttestation($value)
    {
        $out = array();
        $field = $value instanceof SignedApplicationKeyAttestation ? $value->attestation : (is_array($value) && array_key_exists('attestation', $value) ? $value['attestation'] : null);
        $out['attestation'] = CBOR::bytes($field);
        $field = $value instanceof SignedApplicationKeyAttestation ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedApplicationKeyAttestation($value)
    {
        $value = self::csilRecord($value, 'SignedApplicationKeyAttestation', array('attestation', 'signatures'));
        return new SignedApplicationKeyAttestation(array(
            'attestation' => array_key_exists('attestation', $value) ? $value['attestation'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, self::csilList($value['signatures'])) : null,
        ));
    }

    public static function encodeApplicationKeyAddition($value)
    {
        return CBOR::encode(self::toCborApplicationKeyAddition($value));
    }

    public static function decodeApplicationKeyAddition($bytes)
    {
        return self::fromCborApplicationKeyAddition(self::csilDecode($bytes));
    }

    public static function toCborApplicationKeyAddition($value)
    {
        $out = array();
        $field = $value instanceof ApplicationKeyAddition ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->keyUsage : (is_array($value) && array_key_exists('key_usage', $value) ? $value['key_usage'] : null);
        $out['key_usage'] = self::toCborKeyUsage($field);
        $field = $value instanceof ApplicationKeyAddition ? $value->algorithm : (is_array($value) && array_key_exists('algorithm', $value) ? $value['algorithm'] : null);
        $out['algorithm'] = self::toCborKeyAlgorithm($field);
        $field = $value instanceof ApplicationKeyAddition ? $value->publicKey : (is_array($value) && array_key_exists('public_key', $value) ? $value['public_key'] : null);
        $out['public_key'] = CBOR::bytes($field);
        $field = $value instanceof ApplicationKeyAddition ? $value->fingerprint : (is_array($value) && array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null);
        $out['fingerprint'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->requestedKeyLifetimeSeconds : (is_array($value) && array_key_exists('requested_key_lifetime_seconds', $value) ? $value['requested_key_lifetime_seconds'] : null);
        $out['requested_key_lifetime_seconds'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->challengeId : (is_array($value) && array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null);
        $out['challenge_id'] = $field;
        $field = $value instanceof ApplicationKeyAddition ? $value->challenge : (is_array($value) && array_key_exists('challenge', $value) ? $value['challenge'] : null);
        $out['challenge'] = CBOR::bytes($field);
        $field = $value instanceof ApplicationKeyAddition ? $value->requestedAt : (is_array($value) && array_key_exists('requested_at', $value) ? $value['requested_at'] : null);
        $out['requested_at'] = self::timestampToCbor($field);
        $field = $value instanceof ApplicationKeyAddition ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApplicationKeyAddition($value)
    {
        $value = self::csilRecord($value, 'ApplicationKeyAddition', array('subject_user_id', 'subject_domain', 'application_id', 'instance_id', 'key_id', 'key_usage', 'algorithm', 'public_key', 'fingerprint', 'requested_key_lifetime_seconds', 'challenge_id', 'challenge', 'requested_at', 'expires_at'));
        return new ApplicationKeyAddition(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'key_usage' => array_key_exists('key_usage', $value) ? self::fromCborKeyUsage($value['key_usage']) : null,
            'algorithm' => array_key_exists('algorithm', $value) ? self::fromCborKeyAlgorithm($value['algorithm']) : null,
            'public_key' => array_key_exists('public_key', $value) ? $value['public_key'] : null,
            'fingerprint' => array_key_exists('fingerprint', $value) ? $value['fingerprint'] : null,
            'requested_key_lifetime_seconds' => array_key_exists('requested_key_lifetime_seconds', $value) ? $value['requested_key_lifetime_seconds'] : null,
            'challenge_id' => array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null,
            'challenge' => array_key_exists('challenge', $value) ? $value['challenge'] : null,
            'requested_at' => array_key_exists('requested_at', $value) ? self::timestampFromCbor($value['requested_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeSignedApplicationKeyAddition($value)
    {
        return CBOR::encode(self::toCborSignedApplicationKeyAddition($value));
    }

    public static function decodeSignedApplicationKeyAddition($bytes)
    {
        return self::fromCborSignedApplicationKeyAddition(self::csilDecode($bytes));
    }

    public static function toCborSignedApplicationKeyAddition($value)
    {
        $out = array();
        $field = $value instanceof SignedApplicationKeyAddition ? $value->addition : (is_array($value) && array_key_exists('addition', $value) ? $value['addition'] : null);
        $out['addition'] = CBOR::bytes($field);
        $field = $value instanceof SignedApplicationKeyAddition ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborApplicationKeySignature($item); }, $field === null ? array() : $field);
        $field = $value instanceof SignedApplicationKeyAddition ? $value->possessionProof : (is_array($value) && array_key_exists('possession_proof', $value) ? $value['possession_proof'] : null);
        if ($field !== null) {
            $out['possession_proof'] = CBOR::bytes($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedApplicationKeyAddition($value)
    {
        $value = self::csilRecord($value, 'SignedApplicationKeyAddition', array('addition', 'signatures'));
        return new SignedApplicationKeyAddition(array(
            'addition' => array_key_exists('addition', $value) ? $value['addition'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborApplicationKeySignature($item); }, self::csilList($value['signatures'])) : null,
            'possession_proof' => array_key_exists('possession_proof', $value) ? $value['possession_proof'] : null,
        ));
    }

    public static function encodeApplicationKeyRenewal($value)
    {
        return CBOR::encode(self::toCborApplicationKeyRenewal($value));
    }

    public static function decodeApplicationKeyRenewal($bytes)
    {
        return self::fromCborApplicationKeyRenewal(self::csilDecode($bytes));
    }

    public static function toCborApplicationKeyRenewal($value)
    {
        $out = array();
        $field = $value instanceof ApplicationKeyRenewal ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->keyId : (is_array($value) && array_key_exists('key_id', $value) ? $value['key_id'] : null);
        $out['key_id'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->challengeId : (is_array($value) && array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null);
        $out['challenge_id'] = $field;
        $field = $value instanceof ApplicationKeyRenewal ? $value->challenge : (is_array($value) && array_key_exists('challenge', $value) ? $value['challenge'] : null);
        $out['challenge'] = CBOR::bytes($field);
        $field = $value instanceof ApplicationKeyRenewal ? $value->requestedAt : (is_array($value) && array_key_exists('requested_at', $value) ? $value['requested_at'] : null);
        $out['requested_at'] = self::timestampToCbor($field);
        $field = $value instanceof ApplicationKeyRenewal ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApplicationKeyRenewal($value)
    {
        $value = self::csilRecord($value, 'ApplicationKeyRenewal', array('subject_user_id', 'subject_domain', 'application_id', 'instance_id', 'key_id', 'challenge_id', 'challenge', 'requested_at', 'expires_at'));
        return new ApplicationKeyRenewal(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'key_id' => array_key_exists('key_id', $value) ? $value['key_id'] : null,
            'challenge_id' => array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null,
            'challenge' => array_key_exists('challenge', $value) ? $value['challenge'] : null,
            'requested_at' => array_key_exists('requested_at', $value) ? self::timestampFromCbor($value['requested_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeSignedApplicationKeyRenewal($value)
    {
        return CBOR::encode(self::toCborSignedApplicationKeyRenewal($value));
    }

    public static function decodeSignedApplicationKeyRenewal($bytes)
    {
        return self::fromCborSignedApplicationKeyRenewal(self::csilDecode($bytes));
    }

    public static function toCborSignedApplicationKeyRenewal($value)
    {
        $out = array();
        $field = $value instanceof SignedApplicationKeyRenewal ? $value->renewal : (is_array($value) && array_key_exists('renewal', $value) ? $value['renewal'] : null);
        $out['renewal'] = CBOR::bytes($field);
        $field = $value instanceof SignedApplicationKeyRenewal ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborApplicationKeySignature($item); }, $field === null ? array() : $field);
        $field = $value instanceof SignedApplicationKeyRenewal ? $value->possessionProof : (is_array($value) && array_key_exists('possession_proof', $value) ? $value['possession_proof'] : null);
        if ($field !== null) {
            $out['possession_proof'] = CBOR::bytes($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedApplicationKeyRenewal($value)
    {
        $value = self::csilRecord($value, 'SignedApplicationKeyRenewal', array('renewal', 'signatures'));
        return new SignedApplicationKeyRenewal(array(
            'renewal' => array_key_exists('renewal', $value) ? $value['renewal'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborApplicationKeySignature($item); }, self::csilList($value['signatures'])) : null,
            'possession_proof' => array_key_exists('possession_proof', $value) ? $value['possession_proof'] : null,
        ));
    }

    public static function encodeApplicationKeyRevocation($value)
    {
        return CBOR::encode(self::toCborApplicationKeyRevocation($value));
    }

    public static function decodeApplicationKeyRevocation($bytes)
    {
        return self::fromCborApplicationKeyRevocation(self::csilDecode($bytes));
    }

    public static function toCborApplicationKeyRevocation($value)
    {
        $out = array();
        $field = $value instanceof ApplicationKeyRevocation ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->targetKeyId : (is_array($value) && array_key_exists('target_key_id', $value) ? $value['target_key_id'] : null);
        $out['target_key_id'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->targetFingerprint : (is_array($value) && array_key_exists('target_fingerprint', $value) ? $value['target_fingerprint'] : null);
        $out['target_fingerprint'] = $field;
        $field = $value instanceof ApplicationKeyRevocation ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        $out['revoked_at'] = self::timestampToCbor($field);
        $field = $value instanceof ApplicationKeyRevocation ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborApplicationKeySignature($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApplicationKeyRevocation($value)
    {
        $value = self::csilRecord($value, 'ApplicationKeyRevocation', array('subject_user_id', 'subject_domain', 'application_id', 'instance_id', 'target_key_id', 'target_fingerprint', 'revoked_at', 'signatures'));
        return new ApplicationKeyRevocation(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'target_key_id' => array_key_exists('target_key_id', $value) ? $value['target_key_id'] : null,
            'target_fingerprint' => array_key_exists('target_fingerprint', $value) ? $value['target_fingerprint'] : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborApplicationKeySignature($item); }, self::csilList($value['signatures'])) : null,
        ));
    }

    public static function encodeStartApplicationKeyChallengeRequest($value)
    {
        return CBOR::encode(self::toCborStartApplicationKeyChallengeRequest($value));
    }

    public static function decodeStartApplicationKeyChallengeRequest($bytes)
    {
        return self::fromCborStartApplicationKeyChallengeRequest(self::csilDecode($bytes));
    }

    public static function toCborStartApplicationKeyChallengeRequest($value)
    {
        $out = array();
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->purpose : (is_array($value) && array_key_exists('purpose', $value) ? $value['purpose'] : null);
        $out['purpose'] = self::toCborApplicationKeyChallengePurpose($field);
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->keyUsage : (is_array($value) && array_key_exists('key_usage', $value) ? $value['key_usage'] : null);
        $out['key_usage'] = self::toCborKeyUsage($field);
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->algorithm : (is_array($value) && array_key_exists('algorithm', $value) ? $value['algorithm'] : null);
        $out['algorithm'] = self::toCborKeyAlgorithm($field);
        $field = $value instanceof StartApplicationKeyChallengeRequest ? $value->publicKey : (is_array($value) && array_key_exists('public_key', $value) ? $value['public_key'] : null);
        $out['public_key'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborStartApplicationKeyChallengeRequest($value)
    {
        $value = self::csilRecord($value, 'StartApplicationKeyChallengeRequest', array('subject_user_id', 'application_id', 'instance_id', 'purpose', 'key_usage', 'algorithm', 'public_key'));
        return new StartApplicationKeyChallengeRequest(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'purpose' => array_key_exists('purpose', $value) ? self::fromCborApplicationKeyChallengePurpose($value['purpose']) : null,
            'key_usage' => array_key_exists('key_usage', $value) ? self::fromCborKeyUsage($value['key_usage']) : null,
            'algorithm' => array_key_exists('algorithm', $value) ? self::fromCborKeyAlgorithm($value['algorithm']) : null,
            'public_key' => array_key_exists('public_key', $value) ? $value['public_key'] : null,
        ));
    }

    public static function encodeStartApplicationKeyChallengeResponse($value)
    {
        return CBOR::encode(self::toCborStartApplicationKeyChallengeResponse($value));
    }

    public static function decodeStartApplicationKeyChallengeResponse($bytes)
    {
        return self::fromCborStartApplicationKeyChallengeResponse(self::csilDecode($bytes));
    }

    public static function toCborStartApplicationKeyChallengeResponse($value)
    {
        $out = array();
        $field = $value instanceof StartApplicationKeyChallengeResponse ? $value->challengeId : (is_array($value) && array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null);
        $out['challenge_id'] = $field;
        $field = $value instanceof StartApplicationKeyChallengeResponse ? $value->challenge : (is_array($value) && array_key_exists('challenge', $value) ? $value['challenge'] : null);
        if ($field !== null) {
            $out['challenge'] = CBOR::bytes($field);
        }
        $field = $value instanceof StartApplicationKeyChallengeResponse ? $value->sealedChallenge : (is_array($value) && array_key_exists('sealed_challenge', $value) ? $value['sealed_challenge'] : null);
        if ($field !== null) {
            $out['sealed_challenge'] = CBOR::bytes($field);
        }
        $field = $value instanceof StartApplicationKeyChallengeResponse ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborStartApplicationKeyChallengeResponse($value)
    {
        $value = self::csilRecord($value, 'StartApplicationKeyChallengeResponse', array('challenge_id', 'expires_at'));
        return new StartApplicationKeyChallengeResponse(array(
            'challenge_id' => array_key_exists('challenge_id', $value) ? $value['challenge_id'] : null,
            'challenge' => array_key_exists('challenge', $value) ? $value['challenge'] : null,
            'sealed_challenge' => array_key_exists('sealed_challenge', $value) ? $value['sealed_challenge'] : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeAddApplicationKeyRequest($value)
    {
        return CBOR::encode(self::toCborAddApplicationKeyRequest($value));
    }

    public static function decodeAddApplicationKeyRequest($bytes)
    {
        return self::fromCborAddApplicationKeyRequest(self::csilDecode($bytes));
    }

    public static function toCborAddApplicationKeyRequest($value)
    {
        $out = array();
        $field = $value instanceof AddApplicationKeyRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = self::toCborSignedApplicationKeyAddition($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAddApplicationKeyRequest($value)
    {
        $value = self::csilRecord($value, 'AddApplicationKeyRequest', array('request'));
        return new AddApplicationKeyRequest(array(
            'request' => array_key_exists('request', $value) ? self::fromCborSignedApplicationKeyAddition($value['request']) : null,
        ));
    }

    public static function encodeAddApplicationKeyResponse($value)
    {
        return CBOR::encode(self::toCborAddApplicationKeyResponse($value));
    }

    public static function decodeAddApplicationKeyResponse($bytes)
    {
        return self::fromCborAddApplicationKeyResponse(self::csilDecode($bytes));
    }

    public static function toCborAddApplicationKeyResponse($value)
    {
        $out = array();
        $field = $value instanceof AddApplicationKeyResponse ? $value->attestation : (is_array($value) && array_key_exists('attestation', $value) ? $value['attestation'] : null);
        $out['attestation'] = self::toCborSignedApplicationKeyAttestation($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborAddApplicationKeyResponse($value)
    {
        $value = self::csilRecord($value, 'AddApplicationKeyResponse', array('attestation'));
        return new AddApplicationKeyResponse(array(
            'attestation' => array_key_exists('attestation', $value) ? self::fromCborSignedApplicationKeyAttestation($value['attestation']) : null,
        ));
    }

    public static function encodeRenewApplicationKeyAttestationRequest($value)
    {
        return CBOR::encode(self::toCborRenewApplicationKeyAttestationRequest($value));
    }

    public static function decodeRenewApplicationKeyAttestationRequest($bytes)
    {
        return self::fromCborRenewApplicationKeyAttestationRequest(self::csilDecode($bytes));
    }

    public static function toCborRenewApplicationKeyAttestationRequest($value)
    {
        $out = array();
        $field = $value instanceof RenewApplicationKeyAttestationRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = self::toCborSignedApplicationKeyRenewal($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRenewApplicationKeyAttestationRequest($value)
    {
        $value = self::csilRecord($value, 'RenewApplicationKeyAttestationRequest', array('request'));
        return new RenewApplicationKeyAttestationRequest(array(
            'request' => array_key_exists('request', $value) ? self::fromCborSignedApplicationKeyRenewal($value['request']) : null,
        ));
    }

    public static function encodeRenewApplicationKeyAttestationResponse($value)
    {
        return CBOR::encode(self::toCborRenewApplicationKeyAttestationResponse($value));
    }

    public static function decodeRenewApplicationKeyAttestationResponse($bytes)
    {
        return self::fromCborRenewApplicationKeyAttestationResponse(self::csilDecode($bytes));
    }

    public static function toCborRenewApplicationKeyAttestationResponse($value)
    {
        $out = array();
        $field = $value instanceof RenewApplicationKeyAttestationResponse ? $value->attestation : (is_array($value) && array_key_exists('attestation', $value) ? $value['attestation'] : null);
        $out['attestation'] = self::toCborSignedApplicationKeyAttestation($field);
        $field = $value instanceof RenewApplicationKeyAttestationResponse ? $value->signed : (is_array($value) && array_key_exists('signed', $value) ? $value['signed'] : null);
        $out['signed'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRenewApplicationKeyAttestationResponse($value)
    {
        $value = self::csilRecord($value, 'RenewApplicationKeyAttestationResponse', array('attestation', 'signed'));
        return new RenewApplicationKeyAttestationResponse(array(
            'attestation' => array_key_exists('attestation', $value) ? self::fromCborSignedApplicationKeyAttestation($value['attestation']) : null,
            'signed' => array_key_exists('signed', $value) ? $value['signed'] : null,
        ));
    }

    public static function encodeRevokeApplicationKeyRequest($value)
    {
        return CBOR::encode(self::toCborRevokeApplicationKeyRequest($value));
    }

    public static function decodeRevokeApplicationKeyRequest($bytes)
    {
        return self::fromCborRevokeApplicationKeyRequest(self::csilDecode($bytes));
    }

    public static function toCborRevokeApplicationKeyRequest($value)
    {
        $out = array();
        $field = $value instanceof RevokeApplicationKeyRequest ? $value->revocation : (is_array($value) && array_key_exists('revocation', $value) ? $value['revocation'] : null);
        $out['revocation'] = self::toCborApplicationKeyRevocation($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeApplicationKeyRequest($value)
    {
        $value = self::csilRecord($value, 'RevokeApplicationKeyRequest', array('revocation'));
        return new RevokeApplicationKeyRequest(array(
            'revocation' => array_key_exists('revocation', $value) ? self::fromCborApplicationKeyRevocation($value['revocation']) : null,
        ));
    }

    public static function encodeRevokeApplicationKeyResponse($value)
    {
        return CBOR::encode(self::toCborRevokeApplicationKeyResponse($value));
    }

    public static function decodeRevokeApplicationKeyResponse($bytes)
    {
        return self::fromCborRevokeApplicationKeyResponse(self::csilDecode($bytes));
    }

    public static function toCborRevokeApplicationKeyResponse($value)
    {
        $out = array();
        $field = $value instanceof RevokeApplicationKeyResponse ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        $out['revoked_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeApplicationKeyResponse($value)
    {
        $value = self::csilRecord($value, 'RevokeApplicationKeyResponse', array('revoked_at'));
        return new RevokeApplicationKeyResponse(array(
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
        ));
    }

    public static function encodeEnrollApplicationInstanceRequest($value)
    {
        return CBOR::encode(self::toCborEnrollApplicationInstanceRequest($value));
    }

    public static function decodeEnrollApplicationInstanceRequest($bytes)
    {
        return self::fromCborEnrollApplicationInstanceRequest(self::csilDecode($bytes));
    }

    public static function toCborEnrollApplicationInstanceRequest($value)
    {
        $out = array();
        $field = $value instanceof EnrollApplicationInstanceRequest ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof EnrollApplicationInstanceRequest ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof EnrollApplicationInstanceRequest ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborSignedApplicationKeyAddition($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborEnrollApplicationInstanceRequest($value)
    {
        $value = self::csilRecord($value, 'EnrollApplicationInstanceRequest', array('application_id', 'instance_id', 'keys'));
        return new EnrollApplicationInstanceRequest(array(
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborSignedApplicationKeyAddition($item); }, self::csilList($value['keys'])) : null,
        ));
    }

    public static function encodeEnrollApplicationInstanceResponse($value)
    {
        return CBOR::encode(self::toCborEnrollApplicationInstanceResponse($value));
    }

    public static function decodeEnrollApplicationInstanceResponse($bytes)
    {
        return self::fromCborEnrollApplicationInstanceResponse(self::csilDecode($bytes));
    }

    public static function toCborEnrollApplicationInstanceResponse($value)
    {
        $out = array();
        $field = $value instanceof EnrollApplicationInstanceResponse ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof EnrollApplicationInstanceResponse ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof EnrollApplicationInstanceResponse ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof EnrollApplicationInstanceResponse ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof EnrollApplicationInstanceResponse ? $value->attestations : (is_array($value) && array_key_exists('attestations', $value) ? $value['attestations'] : null);
        $out['attestations'] = array_map(function ($item) { return self::toCborSignedApplicationKeyAttestation($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborEnrollApplicationInstanceResponse($value)
    {
        $value = self::csilRecord($value, 'EnrollApplicationInstanceResponse', array('subject_user_id', 'subject_domain', 'application_id', 'instance_id', 'attestations'));
        return new EnrollApplicationInstanceResponse(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'attestations' => array_key_exists('attestations', $value) ? array_map(function ($item) { return self::fromCborSignedApplicationKeyAttestation($item); }, self::csilList($value['attestations'])) : null,
        ));
    }

    public static function encodeGetApplicationKeysRequest($value)
    {
        return CBOR::encode(self::toCborGetApplicationKeysRequest($value));
    }

    public static function decodeGetApplicationKeysRequest($bytes)
    {
        return self::fromCborGetApplicationKeysRequest(self::csilDecode($bytes));
    }

    public static function toCborGetApplicationKeysRequest($value)
    {
        $out = array();
        $field = $value instanceof GetApplicationKeysRequest ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof GetApplicationKeysRequest ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof GetApplicationKeysRequest ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetApplicationKeysRequest($value)
    {
        $value = self::csilRecord($value, 'GetApplicationKeysRequest', array('subject_user_id', 'application_id', 'instance_id'));
        return new GetApplicationKeysRequest(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
        ));
    }

    public static function encodeGetApplicationKeysResponse($value)
    {
        return CBOR::encode(self::toCborGetApplicationKeysResponse($value));
    }

    public static function decodeGetApplicationKeysResponse($bytes)
    {
        return self::fromCborGetApplicationKeysResponse(self::csilDecode($bytes));
    }

    public static function toCborGetApplicationKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof GetApplicationKeysResponse ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof GetApplicationKeysResponse ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof GetApplicationKeysResponse ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof GetApplicationKeysResponse ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof GetApplicationKeysResponse ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborSignedApplicationKeyAttestation($item); }, $field === null ? array() : $field);
        $field = $value instanceof GetApplicationKeysResponse ? $value->revocations : (is_array($value) && array_key_exists('revocations', $value) ? $value['revocations'] : null);
        $out['revocations'] = array_map(function ($item) { return self::toCborApplicationKeyRevocation($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetApplicationKeysResponse($value)
    {
        $value = self::csilRecord($value, 'GetApplicationKeysResponse', array('subject_user_id', 'subject_domain', 'application_id', 'instance_id', 'keys', 'revocations'));
        return new GetApplicationKeysResponse(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborSignedApplicationKeyAttestation($item); }, self::csilList($value['keys'])) : null,
            'revocations' => array_key_exists('revocations', $value) ? array_map(function ($item) { return self::fromCborApplicationKeyRevocation($item); }, self::csilList($value['revocations'])) : null,
        ));
    }

    public static function encodeRpResolveDomainKeysRequest($value)
    {
        return CBOR::encode(self::toCborRpResolveDomainKeysRequest($value));
    }

    public static function decodeRpResolveDomainKeysRequest($bytes)
    {
        return self::fromCborRpResolveDomainKeysRequest(self::csilDecode($bytes));
    }

    public static function toCborRpResolveDomainKeysRequest($value)
    {
        $out = array();
        $field = $value instanceof RpResolveDomainKeysRequest ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof RpResolveDomainKeysRequest ? $value->maxCacheAgeSeconds : (is_array($value) && array_key_exists('max_cache_age_seconds', $value) ? $value['max_cache_age_seconds'] : null);
        if ($field !== null) {
            $out['max_cache_age_seconds'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpResolveDomainKeysRequest($value)
    {
        $value = self::csilRecord($value, 'RpResolveDomainKeysRequest', array('domain'));
        return new RpResolveDomainKeysRequest(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'max_cache_age_seconds' => array_key_exists('max_cache_age_seconds', $value) ? $value['max_cache_age_seconds'] : null,
        ));
    }

    public static function encodeRpResolveDomainKeysResponse($value)
    {
        return CBOR::encode(self::toCborRpResolveDomainKeysResponse($value));
    }

    public static function decodeRpResolveDomainKeysResponse($bytes)
    {
        return self::fromCborRpResolveDomainKeysResponse(self::csilDecode($bytes));
    }

    public static function toCborRpResolveDomainKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        $out['domain'] = $field;
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->keys : (is_array($value) && array_key_exists('keys', $value) ? $value['keys'] : null);
        $out['keys'] = array_map(function ($item) { return self::toCborDomainPublicKey($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->revocations : (is_array($value) && array_key_exists('revocations', $value) ? $value['revocations'] : null);
        $out['revocations'] = array_map(function ($item) { return self::toCborRevocationCertificate($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->fetchedAt : (is_array($value) && array_key_exists('fetched_at', $value) ? $value['fetched_at'] : null);
        $out['fetched_at'] = self::timestampToCbor($field);
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->revocationsCheckedAt : (is_array($value) && array_key_exists('revocations_checked_at', $value) ? $value['revocations_checked_at'] : null);
        $out['revocations_checked_at'] = self::timestampToCbor($field);
        $field = $value instanceof RpResolveDomainKeysResponse ? $value->cacheStatus : (is_array($value) && array_key_exists('cache_status', $value) ? $value['cache_status'] : null);
        $out['cache_status'] = self::toCborRpCacheStatus($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpResolveDomainKeysResponse($value)
    {
        $value = self::csilRecord($value, 'RpResolveDomainKeysResponse', array('domain', 'keys', 'revocations', 'fetched_at', 'revocations_checked_at', 'cache_status'));
        return new RpResolveDomainKeysResponse(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'keys' => array_key_exists('keys', $value) ? array_map(function ($item) { return self::fromCborDomainPublicKey($item); }, self::csilList($value['keys'])) : null,
            'revocations' => array_key_exists('revocations', $value) ? array_map(function ($item) { return self::fromCborRevocationCertificate($item); }, self::csilList($value['revocations'])) : null,
            'fetched_at' => array_key_exists('fetched_at', $value) ? self::timestampFromCbor($value['fetched_at']) : null,
            'revocations_checked_at' => array_key_exists('revocations_checked_at', $value) ? self::timestampFromCbor($value['revocations_checked_at']) : null,
            'cache_status' => array_key_exists('cache_status', $value) ? self::fromCborRpCacheStatus($value['cache_status']) : null,
        ));
    }

    public static function encodeRpResolveApplicationKeysRequest($value)
    {
        return CBOR::encode(self::toCborRpResolveApplicationKeysRequest($value));
    }

    public static function decodeRpResolveApplicationKeysRequest($bytes)
    {
        return self::fromCborRpResolveApplicationKeysRequest(self::csilDecode($bytes));
    }

    public static function toCborRpResolveApplicationKeysRequest($value)
    {
        $out = array();
        $field = $value instanceof RpResolveApplicationKeysRequest ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysRequest ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof RpResolveApplicationKeysRequest ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysRequest ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysRequest ? $value->maxCacheAgeSeconds : (is_array($value) && array_key_exists('max_cache_age_seconds', $value) ? $value['max_cache_age_seconds'] : null);
        if ($field !== null) {
            $out['max_cache_age_seconds'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpResolveApplicationKeysRequest($value)
    {
        $value = self::csilRecord($value, 'RpResolveApplicationKeysRequest', array('subject_user_id', 'subject_domain', 'application_id', 'instance_id'));
        return new RpResolveApplicationKeysRequest(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'max_cache_age_seconds' => array_key_exists('max_cache_age_seconds', $value) ? $value['max_cache_age_seconds'] : null,
        ));
    }

    public static function encodeRpResolveApplicationKeysResponse($value)
    {
        return CBOR::encode(self::toCborRpResolveApplicationKeysResponse($value));
    }

    public static function decodeRpResolveApplicationKeysResponse($bytes)
    {
        return self::fromCborRpResolveApplicationKeysResponse(self::csilDecode($bytes));
    }

    public static function toCborRpResolveApplicationKeysResponse($value)
    {
        $out = array();
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->instanceId : (is_array($value) && array_key_exists('instance_id', $value) ? $value['instance_id'] : null);
        $out['instance_id'] = $field;
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->applicationKeys : (is_array($value) && array_key_exists('application_keys', $value) ? $value['application_keys'] : null);
        $out['application_keys'] = array_map(function ($item) { return self::toCborSignedApplicationKeyAttestation($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->applicationKeyRevocations : (is_array($value) && array_key_exists('application_key_revocations', $value) ? $value['application_key_revocations'] : null);
        $out['application_key_revocations'] = array_map(function ($item) { return self::toCborApplicationKeyRevocation($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->homeDomainKeys : (is_array($value) && array_key_exists('home_domain_keys', $value) ? $value['home_domain_keys'] : null);
        $out['home_domain_keys'] = array_map(function ($item) { return self::toCborDomainPublicKey($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->homeDomainKeyRevocations : (is_array($value) && array_key_exists('home_domain_key_revocations', $value) ? $value['home_domain_key_revocations'] : null);
        $out['home_domain_key_revocations'] = array_map(function ($item) { return self::toCborRevocationCertificate($item); }, $field === null ? array() : $field);
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->fetchedAt : (is_array($value) && array_key_exists('fetched_at', $value) ? $value['fetched_at'] : null);
        $out['fetched_at'] = self::timestampToCbor($field);
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->revocationsCheckedAt : (is_array($value) && array_key_exists('revocations_checked_at', $value) ? $value['revocations_checked_at'] : null);
        $out['revocations_checked_at'] = self::timestampToCbor($field);
        $field = $value instanceof RpResolveApplicationKeysResponse ? $value->cacheStatus : (is_array($value) && array_key_exists('cache_status', $value) ? $value['cache_status'] : null);
        $out['cache_status'] = self::toCborRpCacheStatus($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpResolveApplicationKeysResponse($value)
    {
        $value = self::csilRecord($value, 'RpResolveApplicationKeysResponse', array('subject_user_id', 'subject_domain', 'application_id', 'instance_id', 'application_keys', 'application_key_revocations', 'home_domain_keys', 'home_domain_key_revocations', 'fetched_at', 'revocations_checked_at', 'cache_status'));
        return new RpResolveApplicationKeysResponse(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'instance_id' => array_key_exists('instance_id', $value) ? $value['instance_id'] : null,
            'application_keys' => array_key_exists('application_keys', $value) ? array_map(function ($item) { return self::fromCborSignedApplicationKeyAttestation($item); }, self::csilList($value['application_keys'])) : null,
            'application_key_revocations' => array_key_exists('application_key_revocations', $value) ? array_map(function ($item) { return self::fromCborApplicationKeyRevocation($item); }, self::csilList($value['application_key_revocations'])) : null,
            'home_domain_keys' => array_key_exists('home_domain_keys', $value) ? array_map(function ($item) { return self::fromCborDomainPublicKey($item); }, self::csilList($value['home_domain_keys'])) : null,
            'home_domain_key_revocations' => array_key_exists('home_domain_key_revocations', $value) ? array_map(function ($item) { return self::fromCborRevocationCertificate($item); }, self::csilList($value['home_domain_key_revocations'])) : null,
            'fetched_at' => array_key_exists('fetched_at', $value) ? self::timestampFromCbor($value['fetched_at']) : null,
            'revocations_checked_at' => array_key_exists('revocations_checked_at', $value) ? self::timestampFromCbor($value['revocations_checked_at']) : null,
            'cache_status' => array_key_exists('cache_status', $value) ? self::fromCborRpCacheStatus($value['cache_status']) : null,
        ));
    }

    public static function encodeApplicationRef($value)
    {
        return CBOR::encode(self::toCborApplicationRef($value));
    }

    public static function decodeApplicationRef($bytes)
    {
        return self::fromCborApplicationRef(self::csilDecode($bytes));
    }

    public static function toCborApplicationRef($value)
    {
        $out = array();
        $field = $value instanceof ApplicationRef ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof ApplicationRef ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ApplicationRef ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        $out['application_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborApplicationRef($value)
    {
        $value = self::csilRecord($value, 'ApplicationRef', array('subject_user_id', 'subject_domain', 'application_id'));
        return new ApplicationRef(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
        ));
    }

    public static function encodeGranteeRef($value)
    {
        return CBOR::encode(self::toCborGranteeRef($value));
    }

    public static function decodeGranteeRef($bytes)
    {
        return self::fromCborGranteeRef(self::csilDecode($bytes));
    }

    public static function toCborGranteeRef($value)
    {
        $out = array();
        $field = $value instanceof GranteeRef ? $value->application : (is_array($value) && array_key_exists('application', $value) ? $value['application'] : null);
        if ($field !== null) {
            $out['application'] = self::toCborApplicationRef($field);
        }
        $field = $value instanceof GranteeRef ? $value->localRpDescriptorFingerprint : (is_array($value) && array_key_exists('local_rp_descriptor_fingerprint', $value) ? $value['local_rp_descriptor_fingerprint'] : null);
        if ($field !== null) {
            $out['local_rp_descriptor_fingerprint'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGranteeRef($value)
    {
        $value = self::csilRecord($value, 'GranteeRef', array());
        return new GranteeRef(array(
            'application' => array_key_exists('application', $value) ? self::fromCborApplicationRef($value['application']) : null,
            'local_rp_descriptor_fingerprint' => array_key_exists('local_rp_descriptor_fingerprint', $value) ? $value['local_rp_descriptor_fingerprint'] : null,
        ));
    }

    public static function encodeGranteeProof($value)
    {
        return CBOR::encode(self::toCborGranteeProof($value));
    }

    public static function decodeGranteeProof($bytes)
    {
        return self::fromCborGranteeProof(self::csilDecode($bytes));
    }

    public static function toCborGranteeProof($value)
    {
        $out = array();
        $field = $value instanceof GranteeProof ? $value->applicationInstanceId : (is_array($value) && array_key_exists('application_instance_id', $value) ? $value['application_instance_id'] : null);
        if ($field !== null) {
            $out['application_instance_id'] = $field;
        }
        $field = $value instanceof GranteeProof ? $value->localRpDescriptor : (is_array($value) && array_key_exists('local_rp_descriptor', $value) ? $value['local_rp_descriptor'] : null);
        if ($field !== null) {
            $out['local_rp_descriptor'] = self::toCborSignedLocalRpDescriptor($field);
        }
        $field = $value instanceof GranteeProof ? $value->signature : (is_array($value) && array_key_exists('signature', $value) ? $value['signature'] : null);
        $out['signature'] = self::toCborApplicationKeySignature($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGranteeProof($value)
    {
        $value = self::csilRecord($value, 'GranteeProof', array('signature'));
        return new GranteeProof(array(
            'application_instance_id' => array_key_exists('application_instance_id', $value) ? $value['application_instance_id'] : null,
            'local_rp_descriptor' => array_key_exists('local_rp_descriptor', $value) ? self::fromCborSignedLocalRpDescriptor($value['local_rp_descriptor']) : null,
            'signature' => array_key_exists('signature', $value) ? self::fromCborApplicationKeySignature($value['signature']) : null,
        ));
    }

    public static function encodeActAsScopeEntry($value)
    {
        return CBOR::encode(self::toCborActAsScopeEntry($value));
    }

    public static function decodeActAsScopeEntry($bytes)
    {
        return self::fromCborActAsScopeEntry(self::csilDecode($bytes));
    }

    public static function toCborActAsScopeEntry($value)
    {
        $out = array();
        $field = $value instanceof ActAsScopeEntry ? $value->scope : (is_array($value) && array_key_exists('scope', $value) ? $value['scope'] : null);
        $out['scope'] = $field;
        $field = $value instanceof ActAsScopeEntry ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        if ($field !== null) {
            $out['description'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActAsScopeEntry($value)
    {
        $value = self::csilRecord($value, 'ActAsScopeEntry', array('scope'));
        return new ActAsScopeEntry(array(
            'scope' => array_key_exists('scope', $value) ? $value['scope'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
        ));
    }

    public static function encodeActAsScopeSet($value)
    {
        return CBOR::encode(self::toCborActAsScopeSet($value));
    }

    public static function decodeActAsScopeSet($bytes)
    {
        return self::fromCborActAsScopeSet(self::csilDecode($bytes));
    }

    public static function toCborActAsScopeSet($value)
    {
        $out = array();
        $field = $value instanceof ActAsScopeSet ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = self::toCborApplicationRef($field);
        $field = $value instanceof ActAsScopeSet ? $value->grantee : (is_array($value) && array_key_exists('grantee', $value) ? $value['grantee'] : null);
        $out['grantee'] = self::toCborGranteeRef($field);
        $field = $value instanceof ActAsScopeSet ? $value->entries : (is_array($value) && array_key_exists('entries', $value) ? $value['entries'] : null);
        $out['entries'] = array_map(function ($item) { return self::toCborActAsScopeEntry($item); }, $field === null ? array() : $field);
        $field = $value instanceof ActAsScopeSet ? $value->language : (is_array($value) && array_key_exists('language', $value) ? $value['language'] : null);
        if ($field !== null) {
            $out['language'] = $field;
        }
        $field = $value instanceof ActAsScopeSet ? $value->audienceHandleClaim : (is_array($value) && array_key_exists('audience_handle_claim', $value) ? $value['audience_handle_claim'] : null);
        if ($field !== null) {
            $out['audience_handle_claim'] = self::toCborClaim($field);
        }
        $field = $value instanceof ActAsScopeSet ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsScopeSet ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActAsScopeSet($value)
    {
        $value = self::csilRecord($value, 'ActAsScopeSet', array('audience', 'grantee', 'entries', 'issued_at', 'expires_at'));
        return new ActAsScopeSet(array(
            'audience' => array_key_exists('audience', $value) ? self::fromCborApplicationRef($value['audience']) : null,
            'grantee' => array_key_exists('grantee', $value) ? self::fromCborGranteeRef($value['grantee']) : null,
            'entries' => array_key_exists('entries', $value) ? array_map(function ($item) { return self::fromCborActAsScopeEntry($item); }, self::csilList($value['entries'])) : null,
            'language' => array_key_exists('language', $value) ? $value['language'] : null,
            'audience_handle_claim' => array_key_exists('audience_handle_claim', $value) ? self::fromCborClaim($value['audience_handle_claim']) : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeSignedActAsScopeSet($value)
    {
        return CBOR::encode(self::toCborSignedActAsScopeSet($value));
    }

    public static function decodeSignedActAsScopeSet($bytes)
    {
        return self::fromCborSignedActAsScopeSet(self::csilDecode($bytes));
    }

    public static function toCborSignedActAsScopeSet($value)
    {
        $out = array();
        $field = $value instanceof SignedActAsScopeSet ? $value->scopeSet : (is_array($value) && array_key_exists('scope_set', $value) ? $value['scope_set'] : null);
        $out['scope_set'] = CBOR::bytes($field);
        $field = $value instanceof SignedActAsScopeSet ? $value->signerInstanceId : (is_array($value) && array_key_exists('signer_instance_id', $value) ? $value['signer_instance_id'] : null);
        $out['signer_instance_id'] = $field;
        $field = $value instanceof SignedActAsScopeSet ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborApplicationKeySignature($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedActAsScopeSet($value)
    {
        $value = self::csilRecord($value, 'SignedActAsScopeSet', array('scope_set', 'signer_instance_id', 'signatures'));
        return new SignedActAsScopeSet(array(
            'scope_set' => array_key_exists('scope_set', $value) ? $value['scope_set'] : null,
            'signer_instance_id' => array_key_exists('signer_instance_id', $value) ? $value['signer_instance_id'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborApplicationKeySignature($item); }, self::csilList($value['signatures'])) : null,
        ));
    }

    public static function encodeActAsScopeSetRequest($value)
    {
        return CBOR::encode(self::toCborActAsScopeSetRequest($value));
    }

    public static function decodeActAsScopeSetRequest($bytes)
    {
        return self::fromCborActAsScopeSetRequest(self::csilDecode($bytes));
    }

    public static function toCborActAsScopeSetRequest($value)
    {
        $out = array();
        $field = $value instanceof ActAsScopeSetRequest ? $value->grantee : (is_array($value) && array_key_exists('grantee', $value) ? $value['grantee'] : null);
        $out['grantee'] = self::toCborGranteeRef($field);
        $field = $value instanceof ActAsScopeSetRequest ? $value->scope : (is_array($value) && array_key_exists('scope', $value) ? $value['scope'] : null);
        $out['scope'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof ActAsScopeSetRequest ? $value->localePreferences : (is_array($value) && array_key_exists('locale_preferences', $value) ? $value['locale_preferences'] : null);
        if ($field !== null) {
            $out['locale_preferences'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActAsScopeSetRequest($value)
    {
        $value = self::csilRecord($value, 'ActAsScopeSetRequest', array('grantee', 'scope'));
        return new ActAsScopeSetRequest(array(
            'grantee' => array_key_exists('grantee', $value) ? self::fromCborGranteeRef($value['grantee']) : null,
            'scope' => array_key_exists('scope', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['scope'])) : null,
            'locale_preferences' => array_key_exists('locale_preferences', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['locale_preferences'])) : null,
        ));
    }

    public static function encodeActAsGrant($value)
    {
        return CBOR::encode(self::toCborActAsGrant($value));
    }

    public static function decodeActAsGrant($bytes)
    {
        return self::fromCborActAsGrant(self::csilDecode($bytes));
    }

    public static function toCborActAsGrant($value)
    {
        $out = array();
        $field = $value instanceof ActAsGrant ? $value->grantId : (is_array($value) && array_key_exists('grant_id', $value) ? $value['grant_id'] : null);
        $out['grant_id'] = $field;
        $field = $value instanceof ActAsGrant ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof ActAsGrant ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ActAsGrant ? $value->grantee : (is_array($value) && array_key_exists('grantee', $value) ? $value['grantee'] : null);
        $out['grantee'] = self::toCborGranteeRef($field);
        $field = $value instanceof ActAsGrant ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = self::toCborApplicationRef($field);
        $field = $value instanceof ActAsGrant ? $value->scopeSet : (is_array($value) && array_key_exists('scope_set', $value) ? $value['scope_set'] : null);
        $out['scope_set'] = self::toCborSignedActAsScopeSet($field);
        $field = $value instanceof ActAsGrant ? $value->approvedScope : (is_array($value) && array_key_exists('approved_scope', $value) ? $value['approved_scope'] : null);
        $out['approved_scope'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof ActAsGrant ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsGrant ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsGrant ? $value->seriesIssuedAt : (is_array($value) && array_key_exists('series_issued_at', $value) ? $value['series_issued_at'] : null);
        $out['series_issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsGrant ? $value->renewableUntil : (is_array($value) && array_key_exists('renewable_until', $value) ? $value['renewable_until'] : null);
        $out['renewable_until'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsGrant ? $value->deviceFingerprint : (is_array($value) && array_key_exists('device_fingerprint', $value) ? $value['device_fingerprint'] : null);
        if ($field !== null) {
            $out['device_fingerprint'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActAsGrant($value)
    {
        $value = self::csilRecord($value, 'ActAsGrant', array('grant_id', 'user_id', 'subject_domain', 'grantee', 'audience', 'scope_set', 'approved_scope', 'issued_at', 'expires_at', 'series_issued_at', 'renewable_until'));
        return new ActAsGrant(array(
            'grant_id' => array_key_exists('grant_id', $value) ? $value['grant_id'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'grantee' => array_key_exists('grantee', $value) ? self::fromCborGranteeRef($value['grantee']) : null,
            'audience' => array_key_exists('audience', $value) ? self::fromCborApplicationRef($value['audience']) : null,
            'scope_set' => array_key_exists('scope_set', $value) ? self::fromCborSignedActAsScopeSet($value['scope_set']) : null,
            'approved_scope' => array_key_exists('approved_scope', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['approved_scope'])) : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'series_issued_at' => array_key_exists('series_issued_at', $value) ? self::timestampFromCbor($value['series_issued_at']) : null,
            'renewable_until' => array_key_exists('renewable_until', $value) ? self::timestampFromCbor($value['renewable_until']) : null,
            'device_fingerprint' => array_key_exists('device_fingerprint', $value) ? $value['device_fingerprint'] : null,
        ));
    }

    public static function encodeSignedActAsGrant($value)
    {
        return CBOR::encode(self::toCborSignedActAsGrant($value));
    }

    public static function decodeSignedActAsGrant($bytes)
    {
        return self::fromCborSignedActAsGrant(self::csilDecode($bytes));
    }

    public static function toCborSignedActAsGrant($value)
    {
        $out = array();
        $field = $value instanceof SignedActAsGrant ? $value->grant : (is_array($value) && array_key_exists('grant', $value) ? $value['grant'] : null);
        $out['grant'] = CBOR::bytes($field);
        $field = $value instanceof SignedActAsGrant ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedActAsGrant($value)
    {
        $value = self::csilRecord($value, 'SignedActAsGrant', array('grant', 'signatures'));
        return new SignedActAsGrant(array(
            'grant' => array_key_exists('grant', $value) ? $value['grant'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, self::csilList($value['signatures'])) : null,
        ));
    }

    public static function encodeActAsGrantRequest($value)
    {
        return CBOR::encode(self::toCborActAsGrantRequest($value));
    }

    public static function decodeActAsGrantRequest($bytes)
    {
        return self::fromCborActAsGrantRequest(self::csilDecode($bytes));
    }

    public static function toCborActAsGrantRequest($value)
    {
        $out = array();
        $field = $value instanceof ActAsGrantRequest ? $value->grantee : (is_array($value) && array_key_exists('grantee', $value) ? $value['grantee'] : null);
        $out['grantee'] = self::toCborGranteeRef($field);
        $field = $value instanceof ActAsGrantRequest ? $value->scopeSet : (is_array($value) && array_key_exists('scope_set', $value) ? $value['scope_set'] : null);
        $out['scope_set'] = self::toCborSignedActAsScopeSet($field);
        $field = $value instanceof ActAsGrantRequest ? $value->requestedLifetimeSeconds : (is_array($value) && array_key_exists('requested_lifetime_seconds', $value) ? $value['requested_lifetime_seconds'] : null);
        if ($field !== null) {
            $out['requested_lifetime_seconds'] = $field;
        }
        $field = $value instanceof ActAsGrantRequest ? $value->requestedRenewalWindowSeconds : (is_array($value) && array_key_exists('requested_renewal_window_seconds', $value) ? $value['requested_renewal_window_seconds'] : null);
        if ($field !== null) {
            $out['requested_renewal_window_seconds'] = $field;
        }
        $field = $value instanceof ActAsGrantRequest ? $value->granteeHandleClaim : (is_array($value) && array_key_exists('grantee_handle_claim', $value) ? $value['grantee_handle_claim'] : null);
        if ($field !== null) {
            $out['grantee_handle_claim'] = self::toCborClaim($field);
        }
        $field = $value instanceof ActAsGrantRequest ? $value->callbackUrl : (is_array($value) && array_key_exists('callback_url', $value) ? $value['callback_url'] : null);
        $out['callback_url'] = $field;
        $field = $value instanceof ActAsGrantRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        $field = $value instanceof ActAsGrantRequest ? $value->requestedAt : (is_array($value) && array_key_exists('requested_at', $value) ? $value['requested_at'] : null);
        $out['requested_at'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsGrantRequest ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActAsGrantRequest($value)
    {
        $value = self::csilRecord($value, 'ActAsGrantRequest', array('grantee', 'scope_set', 'callback_url', 'nonce', 'requested_at', 'expires_at'));
        return new ActAsGrantRequest(array(
            'grantee' => array_key_exists('grantee', $value) ? self::fromCborGranteeRef($value['grantee']) : null,
            'scope_set' => array_key_exists('scope_set', $value) ? self::fromCborSignedActAsScopeSet($value['scope_set']) : null,
            'requested_lifetime_seconds' => array_key_exists('requested_lifetime_seconds', $value) ? $value['requested_lifetime_seconds'] : null,
            'requested_renewal_window_seconds' => array_key_exists('requested_renewal_window_seconds', $value) ? $value['requested_renewal_window_seconds'] : null,
            'grantee_handle_claim' => array_key_exists('grantee_handle_claim', $value) ? self::fromCborClaim($value['grantee_handle_claim']) : null,
            'callback_url' => array_key_exists('callback_url', $value) ? $value['callback_url'] : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
            'requested_at' => array_key_exists('requested_at', $value) ? self::timestampFromCbor($value['requested_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
        ));
    }

    public static function encodeSignedActAsGrantRequest($value)
    {
        return CBOR::encode(self::toCborSignedActAsGrantRequest($value));
    }

    public static function decodeSignedActAsGrantRequest($bytes)
    {
        return self::fromCborSignedActAsGrantRequest(self::csilDecode($bytes));
    }

    public static function toCborSignedActAsGrantRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedActAsGrantRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedActAsGrantRequest ? $value->proof : (is_array($value) && array_key_exists('proof', $value) ? $value['proof'] : null);
        $out['proof'] = self::toCborGranteeProof($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedActAsGrantRequest($value)
    {
        $value = self::csilRecord($value, 'SignedActAsGrantRequest', array('request', 'proof'));
        return new SignedActAsGrantRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'proof' => array_key_exists('proof', $value) ? self::fromCborGranteeProof($value['proof']) : null,
        ));
    }

    public static function encodeActAsRefreshRequest($value)
    {
        return CBOR::encode(self::toCborActAsRefreshRequest($value));
    }

    public static function decodeActAsRefreshRequest($bytes)
    {
        return self::fromCborActAsRefreshRequest(self::csilDecode($bytes));
    }

    public static function toCborActAsRefreshRequest($value)
    {
        $out = array();
        $field = $value instanceof ActAsRefreshRequest ? $value->grantId : (is_array($value) && array_key_exists('grant_id', $value) ? $value['grant_id'] : null);
        $out['grant_id'] = $field;
        $field = $value instanceof ActAsRefreshRequest ? $value->grantee : (is_array($value) && array_key_exists('grantee', $value) ? $value['grantee'] : null);
        $out['grantee'] = self::toCborGranteeRef($field);
        $field = $value instanceof ActAsRefreshRequest ? $value->requestedAt : (is_array($value) && array_key_exists('requested_at', $value) ? $value['requested_at'] : null);
        $out['requested_at'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsRefreshRequest ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsRefreshRequest ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActAsRefreshRequest($value)
    {
        $value = self::csilRecord($value, 'ActAsRefreshRequest', array('grant_id', 'grantee', 'requested_at', 'expires_at', 'nonce'));
        return new ActAsRefreshRequest(array(
            'grant_id' => array_key_exists('grant_id', $value) ? $value['grant_id'] : null,
            'grantee' => array_key_exists('grantee', $value) ? self::fromCborGranteeRef($value['grantee']) : null,
            'requested_at' => array_key_exists('requested_at', $value) ? self::timestampFromCbor($value['requested_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
        ));
    }

    public static function encodeSignedActAsRefreshRequest($value)
    {
        return CBOR::encode(self::toCborSignedActAsRefreshRequest($value));
    }

    public static function decodeSignedActAsRefreshRequest($bytes)
    {
        return self::fromCborSignedActAsRefreshRequest(self::csilDecode($bytes));
    }

    public static function toCborSignedActAsRefreshRequest($value)
    {
        $out = array();
        $field = $value instanceof SignedActAsRefreshRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = CBOR::bytes($field);
        $field = $value instanceof SignedActAsRefreshRequest ? $value->proof : (is_array($value) && array_key_exists('proof', $value) ? $value['proof'] : null);
        $out['proof'] = self::toCborGranteeProof($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedActAsRefreshRequest($value)
    {
        $value = self::csilRecord($value, 'SignedActAsRefreshRequest', array('request', 'proof'));
        return new SignedActAsRefreshRequest(array(
            'request' => array_key_exists('request', $value) ? $value['request'] : null,
            'proof' => array_key_exists('proof', $value) ? self::fromCborGranteeProof($value['proof']) : null,
        ));
    }

    public static function encodeRefreshActAsGrantRequest($value)
    {
        return CBOR::encode(self::toCborRefreshActAsGrantRequest($value));
    }

    public static function decodeRefreshActAsGrantRequest($bytes)
    {
        return self::fromCborRefreshActAsGrantRequest(self::csilDecode($bytes));
    }

    public static function toCborRefreshActAsGrantRequest($value)
    {
        $out = array();
        $field = $value instanceof RefreshActAsGrantRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = self::toCborSignedActAsRefreshRequest($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRefreshActAsGrantRequest($value)
    {
        $value = self::csilRecord($value, 'RefreshActAsGrantRequest', array('request'));
        return new RefreshActAsGrantRequest(array(
            'request' => array_key_exists('request', $value) ? self::fromCborSignedActAsRefreshRequest($value['request']) : null,
        ));
    }

    public static function encodeRefreshActAsGrantResponse($value)
    {
        return CBOR::encode(self::toCborRefreshActAsGrantResponse($value));
    }

    public static function decodeRefreshActAsGrantResponse($bytes)
    {
        return self::fromCborRefreshActAsGrantResponse(self::csilDecode($bytes));
    }

    public static function toCborRefreshActAsGrantResponse($value)
    {
        $out = array();
        $field = $value instanceof RefreshActAsGrantResponse ? $value->grant : (is_array($value) && array_key_exists('grant', $value) ? $value['grant'] : null);
        $out['grant'] = self::toCborSignedActAsGrant($field);
        $field = $value instanceof RefreshActAsGrantResponse ? $value->signed : (is_array($value) && array_key_exists('signed', $value) ? $value['signed'] : null);
        $out['signed'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRefreshActAsGrantResponse($value)
    {
        $value = self::csilRecord($value, 'RefreshActAsGrantResponse', array('grant', 'signed'));
        return new RefreshActAsGrantResponse(array(
            'grant' => array_key_exists('grant', $value) ? self::fromCborSignedActAsGrant($value['grant']) : null,
            'signed' => array_key_exists('signed', $value) ? $value['signed'] : null,
        ));
    }

    public static function encodeActAsPresentation($value)
    {
        return CBOR::encode(self::toCborActAsPresentation($value));
    }

    public static function decodeActAsPresentation($bytes)
    {
        return self::fromCborActAsPresentation(self::csilDecode($bytes));
    }

    public static function toCborActAsPresentation($value)
    {
        $out = array();
        $field = $value instanceof ActAsPresentation ? $value->grantHash : (is_array($value) && array_key_exists('grant_hash', $value) ? $value['grant_hash'] : null);
        $out['grant_hash'] = CBOR::bytes($field);
        $field = $value instanceof ActAsPresentation ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = self::toCborApplicationRef($field);
        $field = $value instanceof ActAsPresentation ? $value->requestDigest : (is_array($value) && array_key_exists('request_digest', $value) ? $value['request_digest'] : null);
        $out['request_digest'] = CBOR::bytes($field);
        $field = $value instanceof ActAsPresentation ? $value->presentedAt : (is_array($value) && array_key_exists('presented_at', $value) ? $value['presented_at'] : null);
        $out['presented_at'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsPresentation ? $value->nonce : (is_array($value) && array_key_exists('nonce', $value) ? $value['nonce'] : null);
        $out['nonce'] = CBOR::bytes($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActAsPresentation($value)
    {
        $value = self::csilRecord($value, 'ActAsPresentation', array('grant_hash', 'audience', 'request_digest', 'presented_at', 'nonce'));
        return new ActAsPresentation(array(
            'grant_hash' => array_key_exists('grant_hash', $value) ? $value['grant_hash'] : null,
            'audience' => array_key_exists('audience', $value) ? self::fromCborApplicationRef($value['audience']) : null,
            'request_digest' => array_key_exists('request_digest', $value) ? $value['request_digest'] : null,
            'presented_at' => array_key_exists('presented_at', $value) ? self::timestampFromCbor($value['presented_at']) : null,
            'nonce' => array_key_exists('nonce', $value) ? $value['nonce'] : null,
        ));
    }

    public static function encodeSignedActAsPresentation($value)
    {
        return CBOR::encode(self::toCborSignedActAsPresentation($value));
    }

    public static function decodeSignedActAsPresentation($bytes)
    {
        return self::fromCborSignedActAsPresentation(self::csilDecode($bytes));
    }

    public static function toCborSignedActAsPresentation($value)
    {
        $out = array();
        $field = $value instanceof SignedActAsPresentation ? $value->presentation : (is_array($value) && array_key_exists('presentation', $value) ? $value['presentation'] : null);
        $out['presentation'] = CBOR::bytes($field);
        $field = $value instanceof SignedActAsPresentation ? $value->proof : (is_array($value) && array_key_exists('proof', $value) ? $value['proof'] : null);
        $out['proof'] = self::toCborGranteeProof($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedActAsPresentation($value)
    {
        $value = self::csilRecord($value, 'SignedActAsPresentation', array('presentation', 'proof'));
        return new SignedActAsPresentation(array(
            'presentation' => array_key_exists('presentation', $value) ? $value['presentation'] : null,
            'proof' => array_key_exists('proof', $value) ? self::fromCborGranteeProof($value['proof']) : null,
        ));
    }

    public static function encodeActAsCredential($value)
    {
        return CBOR::encode(self::toCborActAsCredential($value));
    }

    public static function decodeActAsCredential($bytes)
    {
        return self::fromCborActAsCredential(self::csilDecode($bytes));
    }

    public static function toCborActAsCredential($value)
    {
        $out = array();
        $field = $value instanceof ActAsCredential ? $value->grant : (is_array($value) && array_key_exists('grant', $value) ? $value['grant'] : null);
        $out['grant'] = self::toCborSignedActAsGrant($field);
        $field = $value instanceof ActAsCredential ? $value->presentation : (is_array($value) && array_key_exists('presentation', $value) ? $value['presentation'] : null);
        $out['presentation'] = self::toCborSignedActAsPresentation($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActAsCredential($value)
    {
        $value = self::csilRecord($value, 'ActAsCredential', array('grant', 'presentation'));
        return new ActAsCredential(array(
            'grant' => array_key_exists('grant', $value) ? self::fromCborSignedActAsGrant($value['grant']) : null,
            'presentation' => array_key_exists('presentation', $value) ? self::fromCborSignedActAsPresentation($value['presentation']) : null,
        ));
    }

    public static function encodeActAsGrantRevocation($value)
    {
        return CBOR::encode(self::toCborActAsGrantRevocation($value));
    }

    public static function decodeActAsGrantRevocation($bytes)
    {
        return self::fromCborActAsGrantRevocation(self::csilDecode($bytes));
    }

    public static function toCborActAsGrantRevocation($value)
    {
        $out = array();
        $field = $value instanceof ActAsGrantRevocation ? $value->grantId : (is_array($value) && array_key_exists('grant_id', $value) ? $value['grant_id'] : null);
        $out['grant_id'] = $field;
        $field = $value instanceof ActAsGrantRevocation ? $value->userId : (is_array($value) && array_key_exists('user_id', $value) ? $value['user_id'] : null);
        $out['user_id'] = $field;
        $field = $value instanceof ActAsGrantRevocation ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof ActAsGrantRevocation ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        $out['revoked_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActAsGrantRevocation($value)
    {
        $value = self::csilRecord($value, 'ActAsGrantRevocation', array('grant_id', 'user_id', 'subject_domain', 'revoked_at'));
        return new ActAsGrantRevocation(array(
            'grant_id' => array_key_exists('grant_id', $value) ? $value['grant_id'] : null,
            'user_id' => array_key_exists('user_id', $value) ? $value['user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
        ));
    }

    public static function encodeSignedActAsGrantRevocation($value)
    {
        return CBOR::encode(self::toCborSignedActAsGrantRevocation($value));
    }

    public static function decodeSignedActAsGrantRevocation($bytes)
    {
        return self::fromCborSignedActAsGrantRevocation(self::csilDecode($bytes));
    }

    public static function toCborSignedActAsGrantRevocation($value)
    {
        $out = array();
        $field = $value instanceof SignedActAsGrantRevocation ? $value->revocation : (is_array($value) && array_key_exists('revocation', $value) ? $value['revocation'] : null);
        $out['revocation'] = CBOR::bytes($field);
        $field = $value instanceof SignedActAsGrantRevocation ? $value->signatures : (is_array($value) && array_key_exists('signatures', $value) ? $value['signatures'] : null);
        $out['signatures'] = array_map(function ($item) { return self::toCborClaimSignature($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborSignedActAsGrantRevocation($value)
    {
        $value = self::csilRecord($value, 'SignedActAsGrantRevocation', array('revocation', 'signatures'));
        return new SignedActAsGrantRevocation(array(
            'revocation' => array_key_exists('revocation', $value) ? $value['revocation'] : null,
            'signatures' => array_key_exists('signatures', $value) ? array_map(function ($item) { return self::fromCborClaimSignature($item); }, self::csilList($value['signatures'])) : null,
        ));
    }

    public static function encodeGetActAsGrantRevocationsRequest($value)
    {
        return CBOR::encode(self::toCborGetActAsGrantRevocationsRequest($value));
    }

    public static function decodeGetActAsGrantRevocationsRequest($bytes)
    {
        return self::fromCborGetActAsGrantRevocationsRequest(self::csilDecode($bytes));
    }

    public static function toCborGetActAsGrantRevocationsRequest($value)
    {
        $out = array();
        $field = $value instanceof GetActAsGrantRevocationsRequest ? $value->grantIds : (is_array($value) && array_key_exists('grant_ids', $value) ? $value['grant_ids'] : null);
        $out['grant_ids'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetActAsGrantRevocationsRequest($value)
    {
        $value = self::csilRecord($value, 'GetActAsGrantRevocationsRequest', array('grant_ids'));
        return new GetActAsGrantRevocationsRequest(array(
            'grant_ids' => array_key_exists('grant_ids', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['grant_ids'])) : null,
        ));
    }

    public static function encodeGetActAsGrantRevocationsResponse($value)
    {
        return CBOR::encode(self::toCborGetActAsGrantRevocationsResponse($value));
    }

    public static function decodeGetActAsGrantRevocationsResponse($bytes)
    {
        return self::fromCborGetActAsGrantRevocationsResponse(self::csilDecode($bytes));
    }

    public static function toCborGetActAsGrantRevocationsResponse($value)
    {
        $out = array();
        $field = $value instanceof GetActAsGrantRevocationsResponse ? $value->revocations : (is_array($value) && array_key_exists('revocations', $value) ? $value['revocations'] : null);
        $out['revocations'] = array_map(function ($item) { return self::toCborSignedActAsGrantRevocation($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborGetActAsGrantRevocationsResponse($value)
    {
        $value = self::csilRecord($value, 'GetActAsGrantRevocationsResponse', array('revocations'));
        return new GetActAsGrantRevocationsResponse(array(
            'revocations' => array_key_exists('revocations', $value) ? array_map(function ($item) { return self::fromCborSignedActAsGrantRevocation($item); }, self::csilList($value['revocations'])) : null,
        ));
    }

    public static function encodeRpActAsRefreshRequest($value)
    {
        return CBOR::encode(self::toCborRpActAsRefreshRequest($value));
    }

    public static function decodeRpActAsRefreshRequest($bytes)
    {
        return self::fromCborRpActAsRefreshRequest(self::csilDecode($bytes));
    }

    public static function toCborRpActAsRefreshRequest($value)
    {
        $out = array();
        $field = $value instanceof RpActAsRefreshRequest ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof RpActAsRefreshRequest ? $value->request : (is_array($value) && array_key_exists('request', $value) ? $value['request'] : null);
        $out['request'] = self::toCborSignedActAsRefreshRequest($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpActAsRefreshRequest($value)
    {
        $value = self::csilRecord($value, 'RpActAsRefreshRequest', array('subject_domain', 'request'));
        return new RpActAsRefreshRequest(array(
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'request' => array_key_exists('request', $value) ? self::fromCborSignedActAsRefreshRequest($value['request']) : null,
        ));
    }

    public static function encodeRpResolveActAsRevocationsRequest($value)
    {
        return CBOR::encode(self::toCborRpResolveActAsRevocationsRequest($value));
    }

    public static function decodeRpResolveActAsRevocationsRequest($bytes)
    {
        return self::fromCborRpResolveActAsRevocationsRequest(self::csilDecode($bytes));
    }

    public static function toCborRpResolveActAsRevocationsRequest($value)
    {
        $out = array();
        $field = $value instanceof RpResolveActAsRevocationsRequest ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof RpResolveActAsRevocationsRequest ? $value->grantIds : (is_array($value) && array_key_exists('grant_ids', $value) ? $value['grant_ids'] : null);
        $out['grant_ids'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRpResolveActAsRevocationsRequest($value)
    {
        $value = self::csilRecord($value, 'RpResolveActAsRevocationsRequest', array('subject_domain', 'grant_ids'));
        return new RpResolveActAsRevocationsRequest(array(
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'grant_ids' => array_key_exists('grant_ids', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['grant_ids'])) : null,
        ));
    }

    public static function encodeBrowserActAsInspectRequest($value)
    {
        return CBOR::encode(self::toCborBrowserActAsInspectRequest($value));
    }

    public static function decodeBrowserActAsInspectRequest($bytes)
    {
        return self::fromCborBrowserActAsInspectRequest(self::csilDecode($bytes));
    }

    public static function toCborBrowserActAsInspectRequest($value)
    {
        $out = array();
        $field = $value instanceof BrowserActAsInspectRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserActAsInspectRequest($value)
    {
        $value = self::csilRecord($value, 'BrowserActAsInspectRequest', array('signed_request'));
        return new BrowserActAsInspectRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
        ));
    }

    public static function encodeBrowserActAsScopeEntry($value)
    {
        return CBOR::encode(self::toCborBrowserActAsScopeEntry($value));
    }

    public static function decodeBrowserActAsScopeEntry($bytes)
    {
        return self::fromCborBrowserActAsScopeEntry(self::csilDecode($bytes));
    }

    public static function toCborBrowserActAsScopeEntry($value)
    {
        $out = array();
        $field = $value instanceof BrowserActAsScopeEntry ? $value->scope : (is_array($value) && array_key_exists('scope', $value) ? $value['scope'] : null);
        $out['scope'] = $field;
        $field = $value instanceof BrowserActAsScopeEntry ? $value->description : (is_array($value) && array_key_exists('description', $value) ? $value['description'] : null);
        if ($field !== null) {
            $out['description'] = $field;
        }
        $field = $value instanceof BrowserActAsScopeEntry ? $value->removedByPolicy : (is_array($value) && array_key_exists('removed_by_policy', $value) ? $value['removed_by_policy'] : null);
        $out['removed_by_policy'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserActAsScopeEntry($value)
    {
        $value = self::csilRecord($value, 'BrowserActAsScopeEntry', array('scope', 'removed_by_policy'));
        return new BrowserActAsScopeEntry(array(
            'scope' => array_key_exists('scope', $value) ? $value['scope'] : null,
            'description' => array_key_exists('description', $value) ? $value['description'] : null,
            'removed_by_policy' => array_key_exists('removed_by_policy', $value) ? $value['removed_by_policy'] : null,
        ));
    }

    public static function encodeBrowserActAsParty($value)
    {
        return CBOR::encode(self::toCborBrowserActAsParty($value));
    }

    public static function decodeBrowserActAsParty($bytes)
    {
        return self::fromCborBrowserActAsParty(self::csilDecode($bytes));
    }

    public static function toCborBrowserActAsParty($value)
    {
        $out = array();
        $field = $value instanceof BrowserActAsParty ? $value->domain : (is_array($value) && array_key_exists('domain', $value) ? $value['domain'] : null);
        if ($field !== null) {
            $out['domain'] = $field;
        }
        $field = $value instanceof BrowserActAsParty ? $value->applicationId : (is_array($value) && array_key_exists('application_id', $value) ? $value['application_id'] : null);
        if ($field !== null) {
            $out['application_id'] = $field;
        }
        $field = $value instanceof BrowserActAsParty ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        if ($field !== null) {
            $out['subject_user_id'] = $field;
        }
        $field = $value instanceof BrowserActAsParty ? $value->handle : (is_array($value) && array_key_exists('handle', $value) ? $value['handle'] : null);
        if ($field !== null) {
            $out['handle'] = $field;
        }
        $field = $value instanceof BrowserActAsParty ? $value->localRpName : (is_array($value) && array_key_exists('local_rp_name', $value) ? $value['local_rp_name'] : null);
        if ($field !== null) {
            $out['local_rp_name'] = $field;
        }
        $field = $value instanceof BrowserActAsParty ? $value->localRpFingerprint : (is_array($value) && array_key_exists('local_rp_fingerprint', $value) ? $value['local_rp_fingerprint'] : null);
        if ($field !== null) {
            $out['local_rp_fingerprint'] = $field;
        }
        $field = $value instanceof BrowserActAsParty ? $value->ownDomain : (is_array($value) && array_key_exists('own_domain', $value) ? $value['own_domain'] : null);
        $out['own_domain'] = $field;
        $field = $value instanceof BrowserActAsParty ? $value->userHasHistory : (is_array($value) && array_key_exists('user_has_history', $value) ? $value['user_has_history'] : null);
        $out['user_has_history'] = $field;
        $field = $value instanceof BrowserActAsParty ? $value->domainKeyPinned : (is_array($value) && array_key_exists('domain_key_pinned', $value) ? $value['domain_key_pinned'] : null);
        $out['domain_key_pinned'] = $field;
        $field = $value instanceof BrowserActAsParty ? $value->operatorTrusted : (is_array($value) && array_key_exists('operator_trusted', $value) ? $value['operator_trusted'] : null);
        $out['operator_trusted'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserActAsParty($value)
    {
        $value = self::csilRecord($value, 'BrowserActAsParty', array('own_domain', 'user_has_history', 'domain_key_pinned', 'operator_trusted'));
        return new BrowserActAsParty(array(
            'domain' => array_key_exists('domain', $value) ? $value['domain'] : null,
            'application_id' => array_key_exists('application_id', $value) ? $value['application_id'] : null,
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'handle' => array_key_exists('handle', $value) ? $value['handle'] : null,
            'local_rp_name' => array_key_exists('local_rp_name', $value) ? $value['local_rp_name'] : null,
            'local_rp_fingerprint' => array_key_exists('local_rp_fingerprint', $value) ? $value['local_rp_fingerprint'] : null,
            'own_domain' => array_key_exists('own_domain', $value) ? $value['own_domain'] : null,
            'user_has_history' => array_key_exists('user_has_history', $value) ? $value['user_has_history'] : null,
            'domain_key_pinned' => array_key_exists('domain_key_pinned', $value) ? $value['domain_key_pinned'] : null,
            'operator_trusted' => array_key_exists('operator_trusted', $value) ? $value['operator_trusted'] : null,
        ));
    }

    public static function encodeBrowserActAsInspectResponse($value)
    {
        return CBOR::encode(self::toCborBrowserActAsInspectResponse($value));
    }

    public static function decodeBrowserActAsInspectResponse($bytes)
    {
        return self::fromCborBrowserActAsInspectResponse(self::csilDecode($bytes));
    }

    public static function toCborBrowserActAsInspectResponse($value)
    {
        $out = array();
        $field = $value instanceof BrowserActAsInspectResponse ? $value->grantee : (is_array($value) && array_key_exists('grantee', $value) ? $value['grantee'] : null);
        $out['grantee'] = self::toCborGranteeRef($field);
        $field = $value instanceof BrowserActAsInspectResponse ? $value->granteeParty : (is_array($value) && array_key_exists('grantee_party', $value) ? $value['grantee_party'] : null);
        $out['grantee_party'] = self::toCborBrowserActAsParty($field);
        $field = $value instanceof BrowserActAsInspectResponse ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = self::toCborApplicationRef($field);
        $field = $value instanceof BrowserActAsInspectResponse ? $value->audienceParty : (is_array($value) && array_key_exists('audience_party', $value) ? $value['audience_party'] : null);
        $out['audience_party'] = self::toCborBrowserActAsParty($field);
        $field = $value instanceof BrowserActAsInspectResponse ? $value->entries : (is_array($value) && array_key_exists('entries', $value) ? $value['entries'] : null);
        $out['entries'] = array_map(function ($item) { return self::toCborBrowserActAsScopeEntry($item); }, $field === null ? array() : $field);
        $field = $value instanceof BrowserActAsInspectResponse ? $value->language : (is_array($value) && array_key_exists('language', $value) ? $value['language'] : null);
        if ($field !== null) {
            $out['language'] = $field;
        }
        $field = $value instanceof BrowserActAsInspectResponse ? $value->defaultLifetimeSeconds : (is_array($value) && array_key_exists('default_lifetime_seconds', $value) ? $value['default_lifetime_seconds'] : null);
        $out['default_lifetime_seconds'] = $field;
        $field = $value instanceof BrowserActAsInspectResponse ? $value->maxLifetimeSeconds : (is_array($value) && array_key_exists('max_lifetime_seconds', $value) ? $value['max_lifetime_seconds'] : null);
        $out['max_lifetime_seconds'] = $field;
        $field = $value instanceof BrowserActAsInspectResponse ? $value->defaultRenewalWindowSeconds : (is_array($value) && array_key_exists('default_renewal_window_seconds', $value) ? $value['default_renewal_window_seconds'] : null);
        $out['default_renewal_window_seconds'] = $field;
        $field = $value instanceof BrowserActAsInspectResponse ? $value->maxRenewalWindowSeconds : (is_array($value) && array_key_exists('max_renewal_window_seconds', $value) ? $value['max_renewal_window_seconds'] : null);
        $out['max_renewal_window_seconds'] = $field;
        $field = $value instanceof BrowserActAsInspectResponse ? $value->accessDenied : (is_array($value) && array_key_exists('access_denied', $value) ? $value['access_denied'] : null);
        if ($field !== null) {
            $out['access_denied'] = self::toCborAppAccessDenial($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserActAsInspectResponse($value)
    {
        $value = self::csilRecord($value, 'BrowserActAsInspectResponse', array('grantee', 'grantee_party', 'audience', 'audience_party', 'entries', 'default_lifetime_seconds', 'max_lifetime_seconds', 'default_renewal_window_seconds', 'max_renewal_window_seconds'));
        return new BrowserActAsInspectResponse(array(
            'grantee' => array_key_exists('grantee', $value) ? self::fromCborGranteeRef($value['grantee']) : null,
            'grantee_party' => array_key_exists('grantee_party', $value) ? self::fromCborBrowserActAsParty($value['grantee_party']) : null,
            'audience' => array_key_exists('audience', $value) ? self::fromCborApplicationRef($value['audience']) : null,
            'audience_party' => array_key_exists('audience_party', $value) ? self::fromCborBrowserActAsParty($value['audience_party']) : null,
            'entries' => array_key_exists('entries', $value) ? array_map(function ($item) { return self::fromCborBrowserActAsScopeEntry($item); }, self::csilList($value['entries'])) : null,
            'language' => array_key_exists('language', $value) ? $value['language'] : null,
            'default_lifetime_seconds' => array_key_exists('default_lifetime_seconds', $value) ? $value['default_lifetime_seconds'] : null,
            'max_lifetime_seconds' => array_key_exists('max_lifetime_seconds', $value) ? $value['max_lifetime_seconds'] : null,
            'default_renewal_window_seconds' => array_key_exists('default_renewal_window_seconds', $value) ? $value['default_renewal_window_seconds'] : null,
            'max_renewal_window_seconds' => array_key_exists('max_renewal_window_seconds', $value) ? $value['max_renewal_window_seconds'] : null,
            'access_denied' => array_key_exists('access_denied', $value) ? self::fromCborAppAccessDenial($value['access_denied']) : null,
        ));
    }

    public static function encodeBrowserActAsCompleteRequest($value)
    {
        return CBOR::encode(self::toCborBrowserActAsCompleteRequest($value));
    }

    public static function decodeBrowserActAsCompleteRequest($bytes)
    {
        return self::fromCborBrowserActAsCompleteRequest(self::csilDecode($bytes));
    }

    public static function toCborBrowserActAsCompleteRequest($value)
    {
        $out = array();
        $field = $value instanceof BrowserActAsCompleteRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        $field = $value instanceof BrowserActAsCompleteRequest ? $value->approvedScope : (is_array($value) && array_key_exists('approved_scope', $value) ? $value['approved_scope'] : null);
        $out['approved_scope'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof BrowserActAsCompleteRequest ? $value->lifetimeSeconds : (is_array($value) && array_key_exists('lifetime_seconds', $value) ? $value['lifetime_seconds'] : null);
        $out['lifetime_seconds'] = $field;
        $field = $value instanceof BrowserActAsCompleteRequest ? $value->renewalWindowSeconds : (is_array($value) && array_key_exists('renewal_window_seconds', $value) ? $value['renewal_window_seconds'] : null);
        $out['renewal_window_seconds'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserActAsCompleteRequest($value)
    {
        $value = self::csilRecord($value, 'BrowserActAsCompleteRequest', array('signed_request', 'approved_scope', 'lifetime_seconds', 'renewal_window_seconds'));
        return new BrowserActAsCompleteRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
            'approved_scope' => array_key_exists('approved_scope', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['approved_scope'])) : null,
            'lifetime_seconds' => array_key_exists('lifetime_seconds', $value) ? $value['lifetime_seconds'] : null,
            'renewal_window_seconds' => array_key_exists('renewal_window_seconds', $value) ? $value['renewal_window_seconds'] : null,
        ));
    }

    public static function encodeBrowserActAsCompleteResponse($value)
    {
        return CBOR::encode(self::toCborBrowserActAsCompleteResponse($value));
    }

    public static function decodeBrowserActAsCompleteResponse($bytes)
    {
        return self::fromCborBrowserActAsCompleteResponse(self::csilDecode($bytes));
    }

    public static function toCborBrowserActAsCompleteResponse($value)
    {
        $out = array();
        $field = $value instanceof BrowserActAsCompleteResponse ? $value->redirectUrl : (is_array($value) && array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null);
        $out['redirect_url'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborBrowserActAsCompleteResponse($value)
    {
        $value = self::csilRecord($value, 'BrowserActAsCompleteResponse', array('redirect_url'));
        return new BrowserActAsCompleteResponse(array(
            'redirect_url' => array_key_exists('redirect_url', $value) ? $value['redirect_url'] : null,
        ));
    }

    public static function encodeActAsGrantSummary($value)
    {
        return CBOR::encode(self::toCborActAsGrantSummary($value));
    }

    public static function decodeActAsGrantSummary($bytes)
    {
        return self::fromCborActAsGrantSummary(self::csilDecode($bytes));
    }

    public static function toCborActAsGrantSummary($value)
    {
        $out = array();
        $field = $value instanceof ActAsGrantSummary ? $value->grantId : (is_array($value) && array_key_exists('grant_id', $value) ? $value['grant_id'] : null);
        $out['grant_id'] = $field;
        $field = $value instanceof ActAsGrantSummary ? $value->grantee : (is_array($value) && array_key_exists('grantee', $value) ? $value['grantee'] : null);
        $out['grantee'] = self::toCborGranteeRef($field);
        $field = $value instanceof ActAsGrantSummary ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = self::toCborApplicationRef($field);
        $field = $value instanceof ActAsGrantSummary ? $value->approvedScope : (is_array($value) && array_key_exists('approved_scope', $value) ? $value['approved_scope'] : null);
        $out['approved_scope'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof ActAsGrantSummary ? $value->issuedAt : (is_array($value) && array_key_exists('issued_at', $value) ? $value['issued_at'] : null);
        $out['issued_at'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsGrantSummary ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsGrantSummary ? $value->renewableUntil : (is_array($value) && array_key_exists('renewable_until', $value) ? $value['renewable_until'] : null);
        $out['renewable_until'] = self::timestampToCbor($field);
        $field = $value instanceof ActAsGrantSummary ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        if ($field !== null) {
            $out['revoked_at'] = self::timestampToCbor($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborActAsGrantSummary($value)
    {
        $value = self::csilRecord($value, 'ActAsGrantSummary', array('grant_id', 'grantee', 'audience', 'approved_scope', 'issued_at', 'expires_at', 'renewable_until'));
        return new ActAsGrantSummary(array(
            'grant_id' => array_key_exists('grant_id', $value) ? $value['grant_id'] : null,
            'grantee' => array_key_exists('grantee', $value) ? self::fromCborGranteeRef($value['grantee']) : null,
            'audience' => array_key_exists('audience', $value) ? self::fromCborApplicationRef($value['audience']) : null,
            'approved_scope' => array_key_exists('approved_scope', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['approved_scope'])) : null,
            'issued_at' => array_key_exists('issued_at', $value) ? self::timestampFromCbor($value['issued_at']) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'renewable_until' => array_key_exists('renewable_until', $value) ? self::timestampFromCbor($value['renewable_until']) : null,
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
        ));
    }

    public static function encodeListActAsGrantsResponse($value)
    {
        return CBOR::encode(self::toCborListActAsGrantsResponse($value));
    }

    public static function decodeListActAsGrantsResponse($bytes)
    {
        return self::fromCborListActAsGrantsResponse(self::csilDecode($bytes));
    }

    public static function toCborListActAsGrantsResponse($value)
    {
        $out = array();
        $field = $value instanceof ListActAsGrantsResponse ? $value->grants : (is_array($value) && array_key_exists('grants', $value) ? $value['grants'] : null);
        $out['grants'] = array_map(function ($item) { return self::toCborActAsGrantSummary($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborListActAsGrantsResponse($value)
    {
        $value = self::csilRecord($value, 'ListActAsGrantsResponse', array('grants'));
        return new ListActAsGrantsResponse(array(
            'grants' => array_key_exists('grants', $value) ? array_map(function ($item) { return self::fromCborActAsGrantSummary($item); }, self::csilList($value['grants'])) : null,
        ));
    }

    public static function encodeRevokeActAsGrantRequest($value)
    {
        return CBOR::encode(self::toCborRevokeActAsGrantRequest($value));
    }

    public static function decodeRevokeActAsGrantRequest($bytes)
    {
        return self::fromCborRevokeActAsGrantRequest(self::csilDecode($bytes));
    }

    public static function toCborRevokeActAsGrantRequest($value)
    {
        $out = array();
        $field = $value instanceof RevokeActAsGrantRequest ? $value->grantId : (is_array($value) && array_key_exists('grant_id', $value) ? $value['grant_id'] : null);
        $out['grant_id'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeActAsGrantRequest($value)
    {
        $value = self::csilRecord($value, 'RevokeActAsGrantRequest', array('grant_id'));
        return new RevokeActAsGrantRequest(array(
            'grant_id' => array_key_exists('grant_id', $value) ? $value['grant_id'] : null,
        ));
    }

    public static function encodeRevokeActAsGrantResponse($value)
    {
        return CBOR::encode(self::toCborRevokeActAsGrantResponse($value));
    }

    public static function decodeRevokeActAsGrantResponse($bytes)
    {
        return self::fromCborRevokeActAsGrantResponse(self::csilDecode($bytes));
    }

    public static function toCborRevokeActAsGrantResponse($value)
    {
        $out = array();
        $field = $value instanceof RevokeActAsGrantResponse ? $value->revokedAt : (is_array($value) && array_key_exists('revoked_at', $value) ? $value['revoked_at'] : null);
        $out['revoked_at'] = self::timestampToCbor($field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborRevokeActAsGrantResponse($value)
    {
        $value = self::csilRecord($value, 'RevokeActAsGrantResponse', array('revoked_at'));
        return new RevokeActAsGrantResponse(array(
            'revoked_at' => array_key_exists('revoked_at', $value) ? self::timestampFromCbor($value['revoked_at']) : null,
        ));
    }

    public static function encodePreviewReleasePolicyRequest($value)
    {
        return CBOR::encode(self::toCborPreviewReleasePolicyRequest($value));
    }

    public static function decodePreviewReleasePolicyRequest($bytes)
    {
        return self::fromCborPreviewReleasePolicyRequest(self::csilDecode($bytes));
    }

    public static function toCborPreviewReleasePolicyRequest($value)
    {
        $out = array();
        $field = $value instanceof PreviewReleasePolicyRequest ? $value->audience : (is_array($value) && array_key_exists('audience', $value) ? $value['audience'] : null);
        $out['audience'] = $field;
        $field = $value instanceof PreviewReleasePolicyRequest ? $value->requiredClaims : (is_array($value) && array_key_exists('required_claims', $value) ? $value['required_claims'] : null);
        $out['required_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewReleasePolicyRequest ? $value->optionalClaims : (is_array($value) && array_key_exists('optional_claims', $value) ? $value['optional_claims'] : null);
        $out['optional_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewReleasePolicyRequest ? $value->availableClaims : (is_array($value) && array_key_exists('available_claims', $value) ? $value['available_claims'] : null);
        $out['available_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewReleasePolicyRequest ? $value->userChoices : (is_array($value) && array_key_exists('user_choices', $value) ? $value['user_choices'] : null);
        $out['user_choices'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewReleasePolicyRequest ? $value->tempAudience : (is_array($value) && array_key_exists('temp_audience', $value) ? $value['temp_audience'] : null);
        if ($field !== null) {
            $out['temp_audience'] = $field;
        }
        $field = $value instanceof PreviewReleasePolicyRequest ? $value->tempClaimType : (is_array($value) && array_key_exists('temp_claim_type', $value) ? $value['temp_claim_type'] : null);
        if ($field !== null) {
            $out['temp_claim_type'] = $field;
        }
        $field = $value instanceof PreviewReleasePolicyRequest ? $value->tempDisposition : (is_array($value) && array_key_exists('temp_disposition', $value) ? $value['temp_disposition'] : null);
        if ($field !== null) {
            $out['temp_disposition'] = self::toCborReleaseDisposition($field);
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPreviewReleasePolicyRequest($value)
    {
        $value = self::csilRecord($value, 'PreviewReleasePolicyRequest', array('audience', 'required_claims', 'optional_claims', 'available_claims', 'user_choices'));
        return new PreviewReleasePolicyRequest(array(
            'audience' => array_key_exists('audience', $value) ? $value['audience'] : null,
            'required_claims' => array_key_exists('required_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['required_claims'])) : null,
            'optional_claims' => array_key_exists('optional_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['optional_claims'])) : null,
            'available_claims' => array_key_exists('available_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['available_claims'])) : null,
            'user_choices' => array_key_exists('user_choices', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['user_choices'])) : null,
            'temp_audience' => array_key_exists('temp_audience', $value) ? $value['temp_audience'] : null,
            'temp_claim_type' => array_key_exists('temp_claim_type', $value) ? $value['temp_claim_type'] : null,
            'temp_disposition' => array_key_exists('temp_disposition', $value) ? self::fromCborReleaseDisposition($value['temp_disposition']) : null,
        ));
    }

    public static function encodePreviewReleaseRow($value)
    {
        return CBOR::encode(self::toCborPreviewReleaseRow($value));
    }

    public static function decodePreviewReleaseRow($bytes)
    {
        return self::fromCborPreviewReleaseRow(self::csilDecode($bytes));
    }

    public static function toCborPreviewReleaseRow($value)
    {
        $out = array();
        $field = $value instanceof PreviewReleaseRow ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof PreviewReleaseRow ? $value->required : (is_array($value) && array_key_exists('required', $value) ? $value['required'] : null);
        $out['required'] = $field;
        $field = $value instanceof PreviewReleaseRow ? $value->available : (is_array($value) && array_key_exists('available', $value) ? $value['available'] : null);
        $out['available'] = $field;
        $field = $value instanceof PreviewReleaseRow ? $value->locked : (is_array($value) && array_key_exists('locked', $value) ? $value['locked'] : null);
        $out['locked'] = $field;
        $field = $value instanceof PreviewReleaseRow ? $value->policy : (is_array($value) && array_key_exists('policy', $value) ? $value['policy'] : null);
        $out['policy'] = self::toCborConsentRowPolicy($field);
        $field = $value instanceof PreviewReleaseRow ? $value->defaultGranted : (is_array($value) && array_key_exists('default_granted', $value) ? $value['default_granted'] : null);
        $out['default_granted'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPreviewReleaseRow($value)
    {
        $value = self::csilRecord($value, 'PreviewReleaseRow', array('claim_type', 'required', 'available', 'locked', 'policy', 'default_granted'));
        return new PreviewReleaseRow(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'required' => array_key_exists('required', $value) ? $value['required'] : null,
            'available' => array_key_exists('available', $value) ? $value['available'] : null,
            'locked' => array_key_exists('locked', $value) ? $value['locked'] : null,
            'policy' => array_key_exists('policy', $value) ? self::fromCborConsentRowPolicy($value['policy']) : null,
            'default_granted' => array_key_exists('default_granted', $value) ? $value['default_granted'] : null,
        ));
    }

    public static function encodePreviewReleasePolicyResponse($value)
    {
        return CBOR::encode(self::toCborPreviewReleasePolicyResponse($value));
    }

    public static function decodePreviewReleasePolicyResponse($bytes)
    {
        return self::fromCborPreviewReleasePolicyResponse(self::csilDecode($bytes));
    }

    public static function toCborPreviewReleasePolicyResponse($value)
    {
        $out = array();
        $field = $value instanceof PreviewReleasePolicyResponse ? $value->forcedAllow : (is_array($value) && array_key_exists('forced_allow', $value) ? $value['forced_allow'] : null);
        $out['forced_allow'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewReleasePolicyResponse ? $value->forcedDeny : (is_array($value) && array_key_exists('forced_deny', $value) ? $value['forced_deny'] : null);
        $out['forced_deny'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewReleasePolicyResponse ? $value->authorizedClaims : (is_array($value) && array_key_exists('authorized_claims', $value) ? $value['authorized_claims'] : null);
        $out['authorized_claims'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewReleasePolicyResponse ? $value->rows : (is_array($value) && array_key_exists('rows', $value) ? $value['rows'] : null);
        $out['rows'] = array_map(function ($item) { return self::toCborPreviewReleaseRow($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPreviewReleasePolicyResponse($value)
    {
        $value = self::csilRecord($value, 'PreviewReleasePolicyResponse', array('forced_allow', 'forced_deny', 'authorized_claims', 'rows'));
        return new PreviewReleasePolicyResponse(array(
            'forced_allow' => array_key_exists('forced_allow', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['forced_allow'])) : null,
            'forced_deny' => array_key_exists('forced_deny', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['forced_deny'])) : null,
            'authorized_claims' => array_key_exists('authorized_claims', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['authorized_claims'])) : null,
            'rows' => array_key_exists('rows', $value) ? array_map(function ($item) { return self::fromCborPreviewReleaseRow($item); }, self::csilList($value['rows'])) : null,
        ));
    }

    public static function encodePreviewIssuerPolicyRequest($value)
    {
        return CBOR::encode(self::toCborPreviewIssuerPolicyRequest($value));
    }

    public static function decodePreviewIssuerPolicyRequest($bytes)
    {
        return self::fromCborPreviewIssuerPolicyRequest(self::csilDecode($bytes));
    }

    public static function toCborPreviewIssuerPolicyRequest($value)
    {
        $out = array();
        $field = $value instanceof PreviewIssuerPolicyRequest ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof PreviewIssuerPolicyRequest ? $value->deniedDomains : (is_array($value) && array_key_exists('denied_domains', $value) ? $value['denied_domains'] : null);
        if ($field !== null) {
            $out['denied_domains'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        }
        $field = $value instanceof PreviewIssuerPolicyRequest ? $value->deniedTlds : (is_array($value) && array_key_exists('denied_tlds', $value) ? $value['denied_tlds'] : null);
        if ($field !== null) {
            $out['denied_tlds'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        }
        $field = $value instanceof PreviewIssuerPolicyRequest ? $value->issuerUserId : (is_array($value) && array_key_exists('issuer_user_id', $value) ? $value['issuer_user_id'] : null);
        if ($field !== null) {
            $out['issuer_user_id'] = $field;
        }
        $field = $value instanceof PreviewIssuerPolicyRequest ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        if ($field !== null) {
            $out['claim_type'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPreviewIssuerPolicyRequest($value)
    {
        $value = self::csilRecord($value, 'PreviewIssuerPolicyRequest', array('subject_domain'));
        return new PreviewIssuerPolicyRequest(array(
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'denied_domains' => array_key_exists('denied_domains', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['denied_domains'])) : null,
            'denied_tlds' => array_key_exists('denied_tlds', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['denied_tlds'])) : null,
            'issuer_user_id' => array_key_exists('issuer_user_id', $value) ? $value['issuer_user_id'] : null,
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
        ));
    }

    public static function encodePreviewIssuerPolicyResponse($value)
    {
        return CBOR::encode(self::toCborPreviewIssuerPolicyResponse($value));
    }

    public static function decodePreviewIssuerPolicyResponse($bytes)
    {
        return self::fromCborPreviewIssuerPolicyResponse(self::csilDecode($bytes));
    }

    public static function toCborPreviewIssuerPolicyResponse($value)
    {
        $out = array();
        $field = $value instanceof PreviewIssuerPolicyResponse ? $value->deniedDomains : (is_array($value) && array_key_exists('denied_domains', $value) ? $value['denied_domains'] : null);
        $out['denied_domains'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewIssuerPolicyResponse ? $value->deniedTlds : (is_array($value) && array_key_exists('denied_tlds', $value) ? $value['denied_tlds'] : null);
        $out['denied_tlds'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof PreviewIssuerPolicyResponse ? $value->allowed : (is_array($value) && array_key_exists('allowed', $value) ? $value['allowed'] : null);
        $out['allowed'] = $field;
        $field = $value instanceof PreviewIssuerPolicyResponse ? $value->reason : (is_array($value) && array_key_exists('reason', $value) ? $value['reason'] : null);
        $out['reason'] = $field;
        $field = $value instanceof PreviewIssuerPolicyResponse ? $value->userCanIssue : (is_array($value) && array_key_exists('user_can_issue', $value) ? $value['user_can_issue'] : null);
        if ($field !== null) {
            $out['user_can_issue'] = $field;
        }
        $field = $value instanceof PreviewIssuerPolicyResponse ? $value->attestedClaimTtlSeconds : (is_array($value) && array_key_exists('attested_claim_ttl_seconds', $value) ? $value['attested_claim_ttl_seconds'] : null);
        $out['attested_claim_ttl_seconds'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborPreviewIssuerPolicyResponse($value)
    {
        $value = self::csilRecord($value, 'PreviewIssuerPolicyResponse', array('denied_domains', 'denied_tlds', 'allowed', 'reason', 'attested_claim_ttl_seconds'));
        return new PreviewIssuerPolicyResponse(array(
            'denied_domains' => array_key_exists('denied_domains', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['denied_domains'])) : null,
            'denied_tlds' => array_key_exists('denied_tlds', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['denied_tlds'])) : null,
            'allowed' => array_key_exists('allowed', $value) ? $value['allowed'] : null,
            'reason' => array_key_exists('reason', $value) ? $value['reason'] : null,
            'user_can_issue' => array_key_exists('user_can_issue', $value) ? $value['user_can_issue'] : null,
            'attested_claim_ttl_seconds' => array_key_exists('attested_claim_ttl_seconds', $value) ? $value['attested_claim_ttl_seconds'] : null,
        ));
    }

    public static function encodeInspectSigningRequestRequest($value)
    {
        return CBOR::encode(self::toCborInspectSigningRequestRequest($value));
    }

    public static function decodeInspectSigningRequestRequest($bytes)
    {
        return self::fromCborInspectSigningRequestRequest(self::csilDecode($bytes));
    }

    public static function toCborInspectSigningRequestRequest($value)
    {
        $out = array();
        $field = $value instanceof InspectSigningRequestRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborInspectSigningRequestRequest($value)
    {
        $value = self::csilRecord($value, 'InspectSigningRequestRequest', array('signed_request'));
        return new InspectSigningRequestRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
        ));
    }

    public static function encodeInspectSigningRequestResponse($value)
    {
        return CBOR::encode(self::toCborInspectSigningRequestResponse($value));
    }

    public static function decodeInspectSigningRequestResponse($bytes)
    {
        return self::fromCborInspectSigningRequestResponse(self::csilDecode($bytes));
    }

    public static function toCborInspectSigningRequestResponse($value)
    {
        $out = array();
        $field = $value instanceof InspectSigningRequestResponse ? $value->subjectUserId : (is_array($value) && array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null);
        $out['subject_user_id'] = $field;
        $field = $value instanceof InspectSigningRequestResponse ? $value->subjectDomain : (is_array($value) && array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null);
        $out['subject_domain'] = $field;
        $field = $value instanceof InspectSigningRequestResponse ? $value->requestedClaimTypes : (is_array($value) && array_key_exists('requested_claim_types', $value) ? $value['requested_claim_types'] : null);
        $out['requested_claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof InspectSigningRequestResponse ? $value->expiresAt : (is_array($value) && array_key_exists('expires_at', $value) ? $value['expires_at'] : null);
        $out['expires_at'] = self::timestampToCbor($field);
        $field = $value instanceof InspectSigningRequestResponse ? $value->issuableClaimTypes : (is_array($value) && array_key_exists('issuable_claim_types', $value) ? $value['issuable_claim_types'] : null);
        $out['issuable_claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborInspectSigningRequestResponse($value)
    {
        $value = self::csilRecord($value, 'InspectSigningRequestResponse', array('subject_user_id', 'subject_domain', 'requested_claim_types', 'expires_at', 'issuable_claim_types'));
        return new InspectSigningRequestResponse(array(
            'subject_user_id' => array_key_exists('subject_user_id', $value) ? $value['subject_user_id'] : null,
            'subject_domain' => array_key_exists('subject_domain', $value) ? $value['subject_domain'] : null,
            'requested_claim_types' => array_key_exists('requested_claim_types', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['requested_claim_types'])) : null,
            'expires_at' => array_key_exists('expires_at', $value) ? self::timestampFromCbor($value['expires_at']) : null,
            'issuable_claim_types' => array_key_exists('issuable_claim_types', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['issuable_claim_types'])) : null,
        ));
    }

    public static function encodeIssueForSigningRequestRequest($value)
    {
        return CBOR::encode(self::toCborIssueForSigningRequestRequest($value));
    }

    public static function decodeIssueForSigningRequestRequest($bytes)
    {
        return self::fromCborIssueForSigningRequestRequest(self::csilDecode($bytes));
    }

    public static function toCborIssueForSigningRequestRequest($value)
    {
        $out = array();
        $field = $value instanceof IssueForSigningRequestRequest ? $value->signedRequest : (is_array($value) && array_key_exists('signed_request', $value) ? $value['signed_request'] : null);
        $out['signed_request'] = $field;
        $field = $value instanceof IssueForSigningRequestRequest ? $value->claimTypes : (is_array($value) && array_key_exists('claim_types', $value) ? $value['claim_types'] : null);
        $out['claim_types'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        $field = $value instanceof IssueForSigningRequestRequest ? $value->claimValues : (is_array($value) && array_key_exists('claim_values', $value) ? $value['claim_values'] : null);
        $out['claim_values'] = array_map(function ($item) { return $item; }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborIssueForSigningRequestRequest($value)
    {
        $value = self::csilRecord($value, 'IssueForSigningRequestRequest', array('signed_request', 'claim_types', 'claim_values'));
        return new IssueForSigningRequestRequest(array(
            'signed_request' => array_key_exists('signed_request', $value) ? $value['signed_request'] : null,
            'claim_types' => array_key_exists('claim_types', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['claim_types'])) : null,
            'claim_values' => array_key_exists('claim_values', $value) ? array_map(function ($item) { return $item; }, self::csilList($value['claim_values'])) : null,
        ));
    }

    public static function encodeIssuedClaimResult($value)
    {
        return CBOR::encode(self::toCborIssuedClaimResult($value));
    }

    public static function decodeIssuedClaimResult($bytes)
    {
        return self::fromCborIssuedClaimResult(self::csilDecode($bytes));
    }

    public static function toCborIssuedClaimResult($value)
    {
        $out = array();
        $field = $value instanceof IssuedClaimResult ? $value->claimType : (is_array($value) && array_key_exists('claim_type', $value) ? $value['claim_type'] : null);
        $out['claim_type'] = $field;
        $field = $value instanceof IssuedClaimResult ? $value->outcome : (is_array($value) && array_key_exists('outcome', $value) ? $value['outcome'] : null);
        $out['outcome'] = self::toCborIssuedClaimOutcome($field);
        $field = $value instanceof IssuedClaimResult ? $value->message : (is_array($value) && array_key_exists('message', $value) ? $value['message'] : null);
        if ($field !== null) {
            $out['message'] = $field;
        }
        $field = $value instanceof IssuedClaimResult ? $value->claimCode : (is_array($value) && array_key_exists('claim_code', $value) ? $value['claim_code'] : null);
        if ($field !== null) {
            $out['claim_code'] = $field;
        }
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborIssuedClaimResult($value)
    {
        $value = self::csilRecord($value, 'IssuedClaimResult', array('claim_type', 'outcome'));
        return new IssuedClaimResult(array(
            'claim_type' => array_key_exists('claim_type', $value) ? $value['claim_type'] : null,
            'outcome' => array_key_exists('outcome', $value) ? self::fromCborIssuedClaimOutcome($value['outcome']) : null,
            'message' => array_key_exists('message', $value) ? $value['message'] : null,
            'claim_code' => array_key_exists('claim_code', $value) ? $value['claim_code'] : null,
        ));
    }

    public static function encodeIssueForSigningRequestResponse($value)
    {
        return CBOR::encode(self::toCborIssueForSigningRequestResponse($value));
    }

    public static function decodeIssueForSigningRequestResponse($bytes)
    {
        return self::fromCborIssueForSigningRequestResponse(self::csilDecode($bytes));
    }

    public static function toCborIssueForSigningRequestResponse($value)
    {
        $out = array();
        $field = $value instanceof IssueForSigningRequestResponse ? $value->results : (is_array($value) && array_key_exists('results', $value) ? $value['results'] : null);
        $out['results'] = array_map(function ($item) { return self::toCborIssuedClaimResult($item); }, $field === null ? array() : $field);
        return $out === array() ? CBOR::mapEntries(array()) : $out;
    }

    public static function fromCborIssueForSigningRequestResponse($value)
    {
        $value = self::csilRecord($value, 'IssueForSigningRequestResponse', array('results'));
        return new IssueForSigningRequestResponse(array(
            'results' => array_key_exists('results', $value) ? array_map(function ($item) { return self::fromCborIssuedClaimResult($item); }, self::csilList($value['results'])) : null,
        ));
    }

    public static function encodeRpSignRequestReply(callable $handler)
    {
        try {
            return ['variant' => 'RpSignResponse', 'payload' => self::encodeRpSignResponse($handler())];
        } catch (RpErrorRefusal $error) {
            return ['variant' => 'RpError', 'payload' => self::encodeRpError($error->value)];
        }
    }

    public static function encodeRpDecryptTokenReply(callable $handler)
    {
        try {
            return ['variant' => 'RpDecryptResponse', 'payload' => self::encodeRpDecryptResponse($handler())];
        } catch (RpErrorRefusal $error) {
            return ['variant' => 'RpError', 'payload' => self::encodeRpError($error->value)];
        }
    }

    public static function encodeRpVerifyAssertionReply(callable $handler)
    {
        try {
            return ['variant' => 'RpVerifyResponse', 'payload' => self::encodeRpVerifyResponse($handler())];
        } catch (RpErrorRefusal $error) {
            return ['variant' => 'RpError', 'payload' => self::encodeRpError($error->value)];
        }
    }

    public static function encodeRpUserinfoFetchReply(callable $handler)
    {
        try {
            return ['variant' => 'UserInfo', 'payload' => self::encodeUserInfo($handler())];
        } catch (RpErrorRefusal $error) {
            return ['variant' => 'RpError', 'payload' => self::encodeRpError($error->value)];
        }
    }

    public static function resolveRpcReply($service, $op, $variant, $payload)
    {
        if ($service === 'Rp' && $op === 'sign-request') {
            if ($variant === 'RpSignResponse') return $payload;
            if ($variant === 'RpError') throw new RpErrorRefusal(self::decodeRpError($payload));
            throw new CodecException('invalid RPC reply variant');
        }
        if ($service === 'Rp' && $op === 'decrypt-token') {
            if ($variant === 'RpDecryptResponse') return $payload;
            if ($variant === 'RpError') throw new RpErrorRefusal(self::decodeRpError($payload));
            throw new CodecException('invalid RPC reply variant');
        }
        if ($service === 'Rp' && $op === 'verify-assertion') {
            if ($variant === 'RpVerifyResponse') return $payload;
            if ($variant === 'RpError') throw new RpErrorRefusal(self::decodeRpError($payload));
            throw new CodecException('invalid RPC reply variant');
        }
        if ($service === 'Rp' && $op === 'userinfo-fetch') {
            if ($variant === 'UserInfo') return $payload;
            if ($variant === 'RpError') throw new RpErrorRefusal(self::decodeRpError($payload));
            throw new CodecException('invalid RPC reply variant');
        }
        return $payload;
    }
}
