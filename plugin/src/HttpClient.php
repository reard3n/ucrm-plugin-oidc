<?php
declare(strict_types=1);
namespace UcrmOidc;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;

final class ProviderHttpException extends \RuntimeException implements ClientExceptionInterface
{
    public function __construct() { parent::__construct('PROVIDER_UNAVAILABLE'); }
}

/** Enforce the OIDC JSON/200 contract even with another injected PSR18 client. */
final class ProviderResponseClient implements ClientInterface
{
    public function __construct(private readonly ClientInterface $inner) {}
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $response = $this->inner->sendRequest($request);
        if ($response->getStatusCode() !== 200 || strlen((string) $response->getBody()) > 131072
            || !preg_match('~\Aapplication/(?:json|jwk-set\+json)(?:;|$)~i', $response->getHeaderLine('Content-Type'))) {
            throw new ProviderHttpException();
        }
        return $response;
    }
}

/** The single provider transport. No redirects, proxies or caller-selected CA. */
final class HttpClient implements ClientInterface
{
    private array $private = [];
    private readonly \Closure $resolver;
    public function __construct(private readonly array $origins,
        private readonly string $policyDirectory = '/etc/ucrm-oidc', ?callable $resolver = null)
    {
        $this->resolver = \Closure::fromCallable($resolver ?? self::resolve(...));
        foreach ($origins as $origin) {
            if (!is_string($origin) || Config::origin($origin) !== $origin) { throw new AppException('ENDPOINT_ORIGIN_DENIED'); }
        }
        try {
            $raw = @file_get_contents($policyDirectory . '/network-policy.json', false, null, 0, 32769);
            if (!is_string($raw) || strlen($raw) > 32768) { throw new \RuntimeException(); }
            $policy = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
            if (($policy['version'] ?? null) !== 1 || !is_array($policy['privateOrigins'] ?? null)
                || !array_is_list($policy['privateOrigins']) || count($policy['privateOrigins']) > 16) { throw new \RuntimeException(); }
            foreach ($policy['privateOrigins'] as $entry) {
                if (!is_array($entry) || array_diff(array_keys($entry), ['origin', 'addresses', 'caFile'])
                    || !is_string($entry['origin'] ?? null) || Config::origin($entry['origin']) !== $entry['origin']
                    || isset($this->private[$entry['origin']]) || !is_array($entry['addresses'] ?? null)
                    || !array_is_list($entry['addresses']) || count($entry['addresses']) < 1 || count($entry['addresses']) > 8
                    || !is_string($entry['caFile'] ?? null) || !preg_match('/\A[a-zA-Z0-9_-]+\.pem\z/D', $entry['caFile'])) { throw new \RuntimeException(); }
                foreach ($entry['addresses'] as $address) {
                    if (!is_string($address) || !filter_var($address, FILTER_VALIDATE_IP)) { throw new \RuntimeException(); }
                }
                $ca = $policyDirectory . '/' . $entry['caFile'];
                if (!is_file($ca) || is_link($ca) || !is_readable($ca)) { throw new \RuntimeException(); }
                $this->private[$entry['origin']] = $entry;
            }
        } catch (\Throwable) { throw new AppException('NETWORK_POLICY_UNAVAILABLE', 503); }
    }

    private static function resolve(string $host): array
    {
        $literal = trim($host, '[]');
        if (filter_var($literal, FILTER_VALIDATE_IP)) { return [$literal]; }
        // The system resolver can stall outside cURL's deadline. Run only this
        // fixed resolver in an owned, bounded CLI child; never open a TCP probe
        // to an unvalidated address and never invoke a shell.
        $program = <<<'PHP'
$r=@dns_get_record($argv[1],DNS_A|DNS_AAAA);$a=[];
foreach(is_array($r)?$r:[] as $v){$p=$v['ip']??$v['ipv6']??null;if(is_string($p))$a[]=$p;}
echo json_encode(array_values(array_unique($a)));
PHP;
        return self::resolveProcess([PHP_BINDIR . '/php', '-n', '-r', $program, $host]);
    }

    /** Explicit process injection is for deadline tests; never an HTTP input. */
    public static function resolveProcess(array $argv, int $timeoutMs = 3000): array
    {
        $process = @proc_open($argv, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, []);
        if (!is_resource($process)) { return []; }
        fclose($pipes[0]); stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
        $deadline = hrtime(true) + $timeoutMs * 1000000; $result = ''; $failed = false; $errorBytes = 0;
        try {
            while (true) {
                $result .= stream_get_contents($pipes[1], 4097);
                $errorBytes += strlen(stream_get_contents($pipes[2], 4097));
                if (strlen($result) + $errorBytes > 4096 || hrtime(true) >= $deadline) { $failed = true; proc_terminate($process, 9); break; }
                $status = proc_get_status($process);
                if (!$status['running']) {
                    $result .= stream_get_contents($pipes[1], 4097);
                    $failed = $status['exitcode'] !== 0 || strlen($result) > 4096; break;
                }
                usleep(10000);
            }
        } finally {
            fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
        }
        if ($failed) { return []; }
        try { $addresses = json_decode($result, true, 4, JSON_THROW_ON_ERROR); }
        catch (\Throwable) { return []; }
        return is_array($addresses) && array_is_list($addresses) ? $addresses : [];
    }

    public static function publicAddress(string $address): bool
    {
        if (!filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { return false; }
        $packed = inet_pton($address);
        if (strlen($packed) === 4) {
            $octets = array_values(unpack('C4', $packed));
            return !($octets[0] === 0 || $octets[0] >= 224
                || ($octets[0] === 100 && $octets[1] >= 64 && $octets[1] <= 127)
                || ($octets[0] === 192 && $octets[1] === 0)
                || ($octets[0] === 198 && ($octets[1] === 18 || $octets[1] === 19)));
        }
        // Global unicast only; exclude transition mechanisms and documentation.
        $hex = bin2hex($packed);
        return ($hex[0] === '2' || $hex[0] === '3') && !str_starts_with($hex, '2002')
            && !str_starts_with($hex, '20010000') && !str_starts_with($hex, '20010db8');
    }

    /** Exposed for deterministic transport-policy tests; never an HTTP route. */
    public function target(string $url): array
    {
        $parts = Config::url($url);
        $origin = Config::origin($url);
        if (!in_array($origin, $this->origins, true)) { throw new AppException('ENDPOINT_ORIGIN_DENIED'); }
        $private = $this->private[$origin] ?? null;
        $addresses = $private['addresses'] ?? ($this->resolver)($parts['host']);
        if (!is_array($addresses) || count($addresses) < 1 || count($addresses) > 16) { throw new AppException('PROVIDER_DNS_DENIED', 502); }
        foreach ($addresses as $address) {
            if (!is_string($address) || !filter_var($address, FILTER_VALIDATE_IP)
                || ($private === null && !self::publicAddress($address))) { throw new AppException('PROVIDER_DNS_DENIED', 502); }
        }
        return ['host' => trim($parts['host'], '[]'), 'port' => $parts['port'] ?? 443,
            'address' => $addresses[0], 'ca' => $private === null ? null : $this->policyDirectory . '/' . $private['caFile']];
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $curl = null;
        try {
            $url = (string) $request->getUri();
            $target = $this->target($url);
            $method = $request->getMethod();
            $body = (string) $request->getBody();
            if (!in_array($method, ['GET', 'POST'], true) || strlen($body) > 16384 || ($method === 'GET' && $body !== '')) { throw new \RuntimeException(); }
            $headers = ['User-Agent: UCRM-OIDC/0.2.0', 'Expect:'];
            foreach ($request->getHeaders() as $name => $values) {
                if (strtolower($name) === 'host') { continue; }
                if (!in_array(strtolower($name), ['accept', 'content-type', 'authorization'], true)) { throw new \RuntimeException(); }
                $value = implode(', ', $values);
                if (strlen($value) > 12288 || preg_match('/[\r\n\x00]/', $value)) { throw new \RuntimeException(); }
                $headers[] = $name . ': ' . $value;
            }
            $received = ''; $responseHeaders = []; $headerBytes = 0;
            $address = str_contains($target['address'], ':') ? '[' . $target['address'] . ']' : $target['address'];
            $curl = curl_init($url);
            $options = [
                CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => $headers,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_MAXREDIRS => 0,
                CURLOPT_PROXY => '', CURLOPT_NOPROXY => '*', CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,
                CURLOPT_CONNECTTIMEOUT_MS => 4000, CURLOPT_TIMEOUT_MS => 12000,
                CURLOPT_DNS_CACHE_TIMEOUT => 0,
                // Match every source spelling and connect only to the validated
                // numeric destination. cURL normalizes literal hosts before
                // RESOLVE lookup; CONNECT_TO preserves the original TLS name
                // and HTTP Host without allowing that normalization to bypass
                // the pin (including compressed/uncompressed IPv6 literals).
                CURLOPT_CONNECT_TO => ['::' . $address . ':' . $target['port']],
                CURLOPT_WRITEFUNCTION => static function ($handle, string $bytes) use (&$received): int {
                    if (strlen($received) + strlen($bytes) > 131072) { return 0; }
                    $received .= $bytes; return strlen($bytes);
                },
                CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$responseHeaders, &$headerBytes): int {
                    $headerBytes += strlen($line);
                    if ($headerBytes > 16384) { return 0; }
                    if (str_starts_with($line, 'HTTP/')) { $responseHeaders = []; }
                    elseif (str_contains($line, ':')) {
                        [$name, $value] = explode(':', $line, 2);
                        if (in_array(strtolower($name), ['content-type', 'cache-control'], true)) { $responseHeaders[$name][] = trim($value); }
                    }
                    return strlen($line);
                },
            ];
            if ($method === 'POST') { $options[CURLOPT_POSTFIELDS] = $body; }
            if ($target['ca'] !== null) { $options[CURLOPT_CAINFO] = $target['ca']; }
            curl_setopt_array($curl, $options);
            $result = curl_exec($curl);
            $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
            if ($result === false || $status !== 200) { throw new \RuntimeException(); }
            return new Response($status, $responseHeaders, $received);
        } catch (\Throwable) { throw new ProviderHttpException(); }
        finally { if ($curl !== null) { curl_close($curl); } }
    }

    public static function json(ClientInterface $client, string $url): array
    {
        try {
            $response = $client->sendRequest(new Request('GET', $url, ['Accept' => 'application/json']));
            $body = (string) $response->getBody();
            if ($response->getStatusCode() !== 200 || strlen($body) > 131072
                || !preg_match('~\Aapplication/(?:json|jwk-set\+json)(?:;|$)~i', $response->getHeaderLine('Content-Type'))) { throw new \RuntimeException(); }
            $value = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($value) || array_is_list($value)) { throw new \RuntimeException(); }
            return $value;
        } catch (\Throwable) { throw new AppException('PROVIDER_UNAVAILABLE', 502); }
    }
}
