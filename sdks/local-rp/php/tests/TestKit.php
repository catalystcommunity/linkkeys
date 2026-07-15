<?php

declare(strict_types=1);

/**
 * A tiny, dependency-free test harness (no PHPUnit — see the SDK README for
 * why: this package targets plain system PHP, and Composer/PHPUnit may not
 * be installed). Each `*_test.php` file calls {@see TestKit::test()} to
 * register named cases and {@see TestKit::summary()} at the end to print a
 * pass/fail count and set the process exit code.
 */
final class TestKit
{
    private static int $passed = 0;
    private static int $failed = 0;
    /** @var string[] */
    private static array $failures = [];

    public static function test(string $name, callable $fn): void
    {
        try {
            $fn();
            self::$passed++;
        } catch (\Throwable $e) {
            self::$failed++;
            self::$failures[] = "{$name}: " . get_class($e) . ': ' . $e->getMessage();
            fwrite(STDERR, "FAIL: {$name}\n  " . get_class($e) . ': ' . $e->getMessage() . "\n");
        }
    }

    public static function assertTrue(bool $cond, string $message = 'expected true'): void
    {
        if (!$cond) {
            throw new \RuntimeException($message);
        }
    }

    public static function assertFalse(bool $cond, string $message = 'expected false'): void
    {
        self::assertTrue(!$cond, $message);
    }

    /** @param mixed $expected @param mixed $actual */
    public static function assertEquals($expected, $actual, string $message = ''): void
    {
        if ($expected !== $actual) {
            $e = is_string($expected) ? bin2hex($expected) : var_export($expected, true);
            $a = is_string($actual) ? bin2hex($actual) : var_export($actual, true);
            throw new \RuntimeException(($message !== '' ? "{$message}: " : '') . "expected {$e}, got {$a}");
        }
    }

    public static function assertThrows(callable $fn, string $message = 'expected an exception'): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            return;
        }
        throw new \RuntimeException($message);
    }

    public static function assertDoesNotThrow(callable $fn, string $message = 'expected no exception'): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            throw new \RuntimeException("{$message} (threw " . get_class($e) . ': ' . $e->getMessage() . ')');
        }
    }

    /** Print a summary and return the count of failures (0 = success). */
    public static function summary(string $suiteName): int
    {
        $total = self::$passed + self::$failed;
        echo "{$suiteName}: {$total} cases, " . self::$passed . " passed, " . self::$failed . " failed\n";
        return self::$failed;
    }

    public static function reset(): void
    {
        self::$passed = 0;
        self::$failed = 0;
        self::$failures = [];
    }
}

function hexToBytes(string $hex): string
{
    return hex2bin($hex);
}

/** @return mixed */
function loadJson(string $path)
{
    $data = file_get_contents($path);
    if ($data === false) {
        throw new \RuntimeException("could not read {$path}");
    }
    $decoded = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
    return $decoded;
}
