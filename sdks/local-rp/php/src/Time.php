<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

/**
 * Timestamps shared by every check in this SDK. No function in this SDK's
 * protocol-verification code reads the system clock directly — `now` is
 * always an explicit caller-supplied parameter, matching
 * `liblinkkeys::local_rp`'s own no-`Utc::now()` discipline.
 *
 * The SDK keeps a timestamp as RFC 3339 text in memory (the generated PHP
 * types have no native timestamp type). It has two wire forms
 * (`crates/liblinkkeys/src/timestamp.rs`):
 *
 * - A CSIL `timestamp` field: CBOR tag 0 that wraps RFC 3339 text in UTC
 *   with `Z` ({@see self::toWire}, {@see self::fromWire}).
 * - A timestamp inside a signed tuple payload: a CBOR integer of whole Unix
 *   seconds ({@see self::signedSeconds}). A value with a fraction of a
 *   second was never signed, so it is refused, not rounded.
 */
final class Time
{
    /** CBOR tag 0: standard date/time string (RFC 8949 §3.4.1). */
    public const CBOR_TAG_DATETIME = 0;

    private const RFC3339 = '/\A(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})\z/';

    /**
     * Parse RFC 3339 text into a UTC `DateTimeImmutable`. Throws
     * `\InvalidArgumentException` on text that is not RFC 3339 (PHP's own
     * parser also accepts relative forms such as `now`; this does not).
     */
    public static function parseRfc3339(string $s): \DateTimeImmutable
    {
        if (!preg_match(self::RFC3339, $s, $p)
            || !checkdate((int) $p[2], (int) $p[3], (int) $p[1])
            || (int) $p[4] > 23 || (int) $p[5] > 59 || (int) $p[6] > 60) {
            throw new \InvalidArgumentException('invalid RFC3339 timestamp');
        }
        // PHP keeps microseconds; digits after the sixth are dropped.
        $fraction = isset($p[7]) && $p[7] !== '' ? '.' . substr($p[7], 0, 6) : '';
        $offset = strtoupper($p[8]) === 'Z' ? '+00:00' : $p[8];
        $text = "{$p[1]}-{$p[2]}-{$p[3]}T{$p[4]}:{$p[5]}:{$p[6]}{$fraction}{$offset}";
        try {
            $dt = new \DateTimeImmutable($text);
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('invalid RFC3339 timestamp', 0, $e);
        }
        return $dt->setTimezone(new \DateTimeZone('UTC'));
    }

    /** Whole-second RFC 3339 text in UTC with a `+00:00` offset. */
    public static function toRfc3339(\DateTimeImmutable $dt): string
    {
        return $dt->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:sP');
    }

    /**
     * RFC 3339 text in UTC with `Z`, as a CSIL `timestamp` writes it. Keeps a
     * fraction of a second (3 or 6 digits) when there is one.
     */
    public static function toWireText(string $rfc3339): string
    {
        $dt = self::parseRfc3339($rfc3339);
        $micros = (int) $dt->format('u');
        $fraction = '';
        if ($micros !== 0) {
            $fraction = $micros % 1000 === 0 ? sprintf('.%03d', intdiv($micros, 1000)) : sprintf('.%06d', $micros);
        }
        return $dt->format('Y-m-d\TH:i:s') . $fraction . 'Z';
    }

    /** The CSIL `timestamp` wire value: tag 0 around UTC RFC 3339 text. */
    public static function toWire(string $rfc3339): CborTag
    {
        return new CborTag(self::CBOR_TAG_DATETIME, self::toWireText($rfc3339));
    }

    /** {@see self::toWire} for an optional field; `null` stays `null`. */
    public static function toWireOptional(?string $rfc3339): ?CborTag
    {
        return $rfc3339 === null ? null : self::toWire($rfc3339);
    }

    /**
     * Read a decoded CSIL `timestamp` value. It must be CBOR tag 0 around
     * valid RFC 3339 text; anything else throws {@see CborException}.
     * Returns the RFC 3339 text.
     *
     * @param mixed $value
     */
    public static function fromWire($value, string $field): string
    {
        if (!$value instanceof CborTag || $value->tag !== self::CBOR_TAG_DATETIME || !is_string($value->value)) {
            throw new CborException("{$field}: expected a timestamp (CBOR tag 0 with RFC 3339 text)");
        }
        try {
            self::parseRfc3339($value->value);
        } catch (\InvalidArgumentException $e) {
            throw new CborException("{$field}: timestamp is not RFC 3339", 0, $e);
        }
        return $value->value;
    }

    /**
     * {@see self::fromWire} for an optional field: an absent or `null`
     * value gives `null`.
     *
     * @param mixed $value
     */
    public static function fromWireOptional($value, string $field): ?string
    {
        return $value === null ? null : self::fromWire($value, $field);
    }

    /**
     * The signed-payload form of a timestamp: whole Unix seconds. Throws
     * `\InvalidArgumentException` when the text is not RFC 3339 or has a
     * fraction of a second that is not zero.
     */
    public static function signedSeconds(string $rfc3339): int
    {
        if (preg_match(self::RFC3339, $rfc3339, $p) && isset($p[7]) && trim($p[7], '0') !== '') {
            throw new \InvalidArgumentException('a signed timestamp must be a whole number of seconds');
        }
        return self::parseRfc3339($rfc3339)->getTimestamp();
    }

    /** {@see self::signedSeconds} for an optional value; `null` stays `null`. */
    public static function signedSecondsOptional(?string $rfc3339): ?int
    {
        return $rfc3339 === null ? null : self::signedSeconds($rfc3339);
    }

    /** True when two RFC 3339 texts name the same instant. */
    public static function sameInstant(string $a, string $b): bool
    {
        return self::parseRfc3339($a) == self::parseRfc3339($b);
    }
}
