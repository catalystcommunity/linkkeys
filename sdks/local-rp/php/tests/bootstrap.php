<?php

declare(strict_types=1);

/**
 * Composer may or may not be installed on the target system (design doc,
 * "SDK Layout and Tooling"); this SDK's tests must run with plain system
 * PHP regardless. This bootstrap is a minimal PSR-4-ish autoloader (no
 * Composer required) plus a tiny test-runner ({@see TestKit}) used by every
 * `*_test.php` file in this directory.
 */

spl_autoload_register(function (string $class): void {
    $prefixes = [
        'LinkKeys\\LocalRp\\' => __DIR__ . '/../src/',
        'Csilgen\\Generated\\' => __DIR__ . '/../src/Generated/',
    ];
    foreach ($prefixes as $prefix => $baseDir) {
        if (str_starts_with($class, $prefix)) {
            $relative = substr($class, strlen($prefix));
            // This SDK's classes are grouped several-per-file rather than
            // strictly one-class-per-file (e.g. every error class for a
            // module lives beside that module's main class), so a plain
            // PSR-4 class->file mapping does not apply. Instead, every file
            // under the mapped directory is loaded once and each declares
            // whichever classes it contains; `spl_autoload_register` will
            // simply be called again for the next unresolved class name
            // (a cheap no-op once everything is loaded).
            foreach (glob($baseDir . '*.php') as $file) {
                require_once $file;
            }
            return;
        }
    }
});

require_once __DIR__ . '/TestKit.php';
