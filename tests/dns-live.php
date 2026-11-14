<?php
declare(strict_types=1);
require getenv('UCRM_OIDC_TEST_AUTOLOAD') ?: __DIR__ . '/../plugin/vendor/autoload.php';
foreach (['AppException','Config','HttpClient'] as $class) { require __DIR__ . '/../plugin/src/' . $class . '.php'; }
$directory = '/tmp/oidc-dns-' . bin2hex(random_bytes(8)); mkdir($directory, 0700);
file_put_contents($directory . '/network-policy.json', '{"version":1,"privateOrigins":[]}');
$before = hrtime(true);
$client = new \UcrmOidc\HttpClient(['https://example.com'], $directory);
try {
    // Only a DNS query for the reserved documentation domain; no HTTP is sent.
    $target = $client->target('https://example.com/');
    $passed = $target['host'] === 'example.com' && \UcrmOidc\HttpClient::publicAddress($target['address']);
    echo json_encode(['php'=>PHP_VERSION,'actualBoundedSystemDnsPassed'=>$passed,'elapsedMs'=>(int)((hrtime(true)-$before)/1000000),'httpRequestsSent'=>0]),"\n";
    exit($passed ? 0 : 1);
} catch(Throwable) { echo json_encode(['php'=>PHP_VERSION,'actualBoundedSystemDnsPassed'=>false,'elapsedMs'=>(int)((hrtime(true)-$before)/1000000),'httpRequestsSent'=>0]),"\n";exit(1); }
