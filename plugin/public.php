<?php
declare(strict_types=1);

// Native public.php wrappers do not perform plugin authorization for us.
ini_set('display_errors', '0');
header('Cache-Control: no-store, max-age=0');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
try {
    if (PHP_VERSION_ID < 80200 || !is_file(__DIR__ . '/vendor/autoload.php')) { throw new RuntimeException(); }
    require __DIR__ . '/vendor/autoload.php';
    $pluginId = 0;
    $metadata = @file_get_contents(__DIR__ . '/ucrm.json', false, null, 0, 32769);
    if (is_string($metadata) && strlen($metadata) <= 32768) {
        $nativeMetadata = json_decode($metadata, true);
        if (is_array($nativeMetadata) && is_int($nativeMetadata['pluginId'] ?? null) && $nativeMetadata['pluginId'] > 0) { $pluginId = $nativeMetadata['pluginId']; }
    }
    unset($metadata, $nativeMetadata);
    $web = new \UcrmOidc\Web(\UcrmOidc\Application::boot(__DIR__), $pluginId);
    $rawBody = null;
    if (($_GET['action'] ?? null) === 'backchannel-logout') {
        $input = @file_get_contents('php://input', false, null, 0, \UcrmOidc\Web::LOGOUT_BODY_LIMIT + 1);
        $rawBody = is_string($input) ? $input : null;
        unset($input);
    }
    $response = $web->handle($_SERVER, $_GET, $_POST, $_COOKIE, $rawBody);
    unset($rawBody);
    http_response_code($response['status']);
    foreach ($response['headers'] as $name => $value) { header($name . ': ' . $value); }
    foreach ($response['cookies'] as $cookie) { setcookie($cookie['name'], $cookie['value'], $cookie['options']); }
    echo $response['body'];
} catch (Throwable) {
    // Boot failures never expose key paths, SQL, metadata, dependency diagnostics or traces.
    if (($_GET['action'] ?? null) === 'callback') {
        http_response_code(303);
        header('Location: /crm/_plugins/ucrm-oidc/public.php?action=error&reason=STATE_UNAVAILABLE');
        return;
    }
    http_response_code(503);
    if (($_GET['action'] ?? null) === 'backchannel-logout') {
        header('Content-Type: application/json; charset=UTF-8');
        header("Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none'");
        echo '{"error":"temporarily_unavailable"}';
        return;
    }
    header('Content-Type: text/html; charset=UTF-8');
    header("Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'self'");
    echo '<!doctype html><html lang="en"><meta charset="utf-8"><title>OpenID Connect unavailable</title><h1>OpenID Connect unavailable</h1><p>Plugin setup needs attention. Native password login remains available.</p><a href="/nms/login" target="_top">Native password login</a></html>';
}
