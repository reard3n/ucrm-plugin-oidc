<?php
declare(strict_types=1);
// Actual Web response bodies/headers for the browser regression; only the
// application/native boundary is synthetic. Never contacts a real provider.
define('UCRM_OIDC_WEB_FIXTURES_ONLY', true);
require __DIR__ . '/web-unit.php';
$app = new \UcrmOidc\Application(); $web = new \UcrmOidc\Web($app, 9);
$browser = str_repeat('b', 64); $cookies = [\UcrmOidc\Web::BROWSER_COOKIE => $browser];
$server = ['REQUEST_METHOD' => 'GET', 'QUERY_STRING' => '', 'HTTP_HOST' => 'crm.example.test'];
$postServer = $server; $postServer['REQUEST_METHOD'] = 'POST'; $postServer['HTTP_ORIGIN'] = 'https://crm.example.test'; $postServer['CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
$parameters = ['response_type' => 'code', 'client_id' => 'synthetic-client', 'redirect_uri' => 'https://crm.example.test' . \UcrmOidc\Config::ENTRY . '?action=callback', 'state' => str_repeat('s', 64), 'nonce' => str_repeat('n', 64), 'code_challenge' => str_repeat('c', 43), 'code_challenge_method' => 'S256'];
$app->authorizationUrl = 'https://idp.example.test/authorize?' . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
$output = ['parameters' => $parameters, 'csrf' => $app->csrf($browser, 'flow:start')];
$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$request = openssl_csr_new(['commonName' => 'crm.example.test'], $key, ['digest_alg' => 'sha256']);
$certificate = openssl_csr_sign($request, null, $key, 1, ['digest_alg' => 'sha256']);
openssl_pkey_export($key, $privateKey); openssl_x509_export($certificate, $publicCertificate);
$output['tls'] = ['key' => $privateKey, 'cert' => $publicCertificate];
foreach (['normal' => '0', 'preview' => '1'] as $name => $preview) {
    $output[$name] = ['get' => $web->handle($server, ['action' => 'start', 'preview' => $preview], [], $cookies),
        'post' => $web->handle($postServer, ['action' => 'start'], ['csrf' => $output['csrf'], 'preview' => $preview, 'fresh' => '0', 'return' => '/crm/'], $cookies)];
}
echo json_encode($output, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), "\n";
