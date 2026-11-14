<?php
declare(strict_types=1);
require getenv('UCRM_OIDC_TEST_AUTOLOAD') ?: __DIR__ . '/../plugin/vendor/autoload.php';
foreach (['AppException', 'Config', 'HttpClient'] as $class) { require __DIR__ . '/../plugin/src/' . $class . '.php'; }
use UcrmOidc\{HttpClient,AppException};
use Nyholm\Psr7\Request;
$directory = '/tmp/oidc-transport-' . bin2hex(random_bytes(8)); mkdir($directory, 0700);
$config = <<<'CONF'
[req]
distinguished_name=dn
[dn]
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:::1,IP:198.51.100.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
CONF;
file_put_contents($directory . '/openssl.cnf', $config);
$options = ['config' => $directory . '/openssl.cnf', 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'digest_alg' => 'sha256'];
$caKey = openssl_pkey_new($options); $caRequest = openssl_csr_new(['commonName' => 'Local OIDC transport test CA'], $caKey, $options);
$ca = openssl_csr_sign($caRequest, null, $caKey, 1, $options + ['x509_extensions' => 'ca']);
openssl_x509_export($ca, $caPem); file_put_contents($directory . '/ca.pem', $caPem);
$leafKey = openssl_pkey_new($options); $leafRequest = openssl_csr_new(['commonName' => 'localhost'], $leafKey, $options);
$leaf = openssl_csr_sign($leafRequest, $ca, $caKey, 1, $options + ['x509_extensions' => 'leaf']);
openssl_x509_export($leaf, $leafPem); openssl_pkey_export($leafKey, $keyPem, null, $options);
file_put_contents($directory . '/server.pem', $leafPem . $caPem); file_put_contents($directory . '/server-key.pem', $keyPem); chmod($directory . '/server-key.pem', 0600);
unset($keyPem, $leafKey, $caKey);
$origin = 'https://localhost:19447'; $wrong = 'https://wrong.example:19447';
$literals = ['https://[::1]:19447', 'https://[0:0:0:0:0:0:0:1]:19447', 'https://198.51.100.2:19447'];
$origins = array_merge([$origin, $wrong], $literals);
$policy = ['version' => 1, 'privateOrigins' => array_map(fn($o) => ['origin' => $o, 'addresses' => ['127.0.0.1'], 'caFile' => 'ca.pem'], $origins)];
file_put_contents($directory . '/network-policy.json', json_encode($policy));
$process = proc_open([PHP_BINDIR . '/php', __DIR__ . '/tls-http-fixture.php', $directory], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, []);
fclose($pipes[0]); stream_set_timeout($pipes[1], 5); $checks = [];
function test(string $name, bool $passed): void { global $checks; $checks[] = compact('name', 'passed'); if (!$passed) { throw new RuntimeException($name); } }
function refusal(string $name, callable $action): void { try { $action(); } catch (Throwable) { test($name, true); return; } test($name, false); }
try {
    test('loopback TLS fixture ready', trim(fgets($pipes[1]) ?: '') === 'ready');
    $client = new HttpClient($origins, $directory);
    $response = $client->sendRequest(new Request('GET', $origin . '/ok'));
    test('actual cURL verifies private CA and hostname', $response->getStatusCode() === 200 && (string) $response->getBody() === '{"ok":true}');
    foreach ($literals as $literal) {
        // The fixture listens only on IPv4 loopback. A successful, certificate-
        // verified response proves that cURL used the approved destination and
        // still verified the literal from the URL as the certificate identity.
        $response = $client->sendRequest(new Request('GET', $literal . '/ok'));
        test('actual cURL pins literal destination ' . $literal, $response->getStatusCode() === 200 && (string) $response->getBody() === '{"ok":true}');
    }
    refusal('actual cURL denies redirect with successful JSON body', fn() => $client->sendRequest(new Request('POST', $origin . '/redirect', ['Content-Type' => 'application/x-www-form-urlencoded'], 'code=synthetic')));
    refusal('actual cURL bounds response body', fn() => $client->sendRequest(new Request('GET', $origin . '/large')));
    refusal('actual cURL bounds response headers', fn() => $client->sendRequest(new Request('GET', $origin . '/headers')));
    refusal('unapproved endpoint origin denied before network', fn() => $client->sendRequest(new Request('GET', 'https://unapproved.example/')));
    refusal('HTTPS hostname mismatch denied', fn() => $client->sendRequest(new Request('GET', $wrong . '/ok')));
    // Wrong CA test uses the system store, which cannot trust this ephemeral CA.
    $badDir = $directory . '/wrong'; mkdir($badDir, 0700); copy('/etc/ssl/certs/ca-certificates.crt', $badDir . '/ca.pem');
    file_put_contents($badDir . '/network-policy.json', json_encode($policy));
    $bad = new HttpClient([$origin], $badDir);
    refusal('untrusted certificate denied', fn() => $bad->sendRequest(new Request('GET', $origin . '/ok')));
    $emptyDir = $directory . '/public'; mkdir($emptyDir, 0700); file_put_contents($emptyDir . '/network-policy.json', '{"version":1,"privateOrigins":[]}');
    $public = new HttpClient(['https://identity.example'], $emptyDir, fn() => ['8.8.8.8', '127.0.0.1']);
    refusal('mixed public/private DNS answer denied', fn() => $public->target('https://identity.example/token'));
    $public = new HttpClient(['https://identity.example'], $emptyDir, fn() => ['8.8.8.8']);
    test('validated address pinned without changing hostname', $public->target('https://identity.example/token') === ['host' => 'identity.example', 'port' => 443, 'address' => '8.8.8.8', 'ca' => null]);
    $before = hrtime(true);
    refusal('actual cURL total timeout enforced', fn() => $client->sendRequest(new Request('GET', $origin . '/slow')));
    $seconds = (hrtime(true) - $before) / 1e9;
    test('slow-response timeout bounded to12seconds', $seconds >= 11 && $seconds < 15);
    echo json_encode(['php' => PHP_VERSION, 'passed' => count($checks), 'checks' => $checks], JSON_PRETTY_PRINT), "\n";
} catch (Throwable $error) {
    echo json_encode(['php' => PHP_VERSION, 'failure' => $error->getMessage(), 'checks' => $checks], JSON_PRETTY_PRINT), "\n"; exitCode(1);
} finally {
    proc_terminate($process, 9); fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
}
function exitCode(int $value): void { register_shutdown_function(static function () use ($value): void { exit($value); }); }
