<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

/**
 * RFC3339 parsing shared by every timestamp check in this SDK. No function in
 * this SDK's protocol-verification code reads the system clock directly —
 * `now` is always an explicit caller-supplied parameter, matching
 * `liblinkkeys::local_rp`'s own no-`Utc::now()` discipline (see the design
 * doc: "explicit clock-skew tolerance parameter").
 */
final class Time
{
    /**
     * Parse an RFC3339 timestamp string (as produced by every LinkKeys
     * component: `chrono::DateTime::to_rfc3339()`) into a UTC
     * `DateTimeImmutable`. Throws `\InvalidArgumentException` on anything
     * that doesn't parse.
     */
    public static function parseRfc3339(string $s): \DateTimeImmutable
    {
        try {
            $dt = new \DateTimeImmutable($s);
        } catch (\Exception $e) {
            throw new \InvalidArgumentException("invalid RFC3339 timestamp: {$s}", 0, $e);
        }
        return $dt->setTimezone(new \DateTimeZone('UTC'));
    }

    public static function toRfc3339(\DateTimeImmutable $dt): string
    {
        return $dt->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:sP');
    }
}
