<?php
declare(strict_types=1);

// Native runner and lifecycle hooks share idempotent maintenance. No installer,
// shell command, Composer download or native session issuance is performed here.
ini_set('display_errors', '0');
try {
    if (PHP_SAPI !== 'cli' || PHP_VERSION_ID < 80200 || !is_file(__DIR__ . '/vendor/autoload.php')) { throw new RuntimeException(); }
    require_once __DIR__ . '/vendor/autoload.php';
    \UcrmOidc\Application::boot(__DIR__)->maintenance();
    echo "OpenID Connect maintenance completed.\n";
} catch (Throwable) {
    echo "OpenID Connect maintenance unavailable. Check plugin setup.\n";
    exit(1);
}
