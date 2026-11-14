<?php
declare(strict_types=1);

namespace UcrmOidc;

/** Internal safe error; never retain native responses or exception chains. */
final class NativeSessionException extends \RuntimeException
{
    public function __construct(public readonly string $safeCode)
    {
        parent::__construct($safeCode);
    }
}

/** Transport and existing-session consumption only; does not issue by itself. */
final class NativeSession
{
    public const SOCKET = '/run/ucrm-oidc-adapter/native-session.sock';
    public const CURRENT_USER_URL = 'http://127.0.0.1/crm/current-user';
    public const NETWORK_POLICY = '/etc/ucrm-oidc/network-policy.json';

    private const FRAME_LIMIT = 16384;
    private const BODY_LIMIT = 8192;
    private const RESPONSE_LIMIT = 65536;
    private const OPERATIONS = [
        'status', 'resolve', 'inspect', 'describe-caller', 'issue', 'complete-mfa', 'revoke',
    ];
    private const SAFE_ERRORS = [
        'BAD_REQUEST', 'AUTHENTICATION_FAILED', 'STALE_REQUEST', 'REPLAY', 'BUSY',
        'STALE_EPOCH', 'CONFIG_CHANGED', 'PLUGIN_INACTIVE', 'CONFIG_UNAVAILABLE',
        'OIDC_DISABLED', 'ADMISSION_DENIED', 'MFA_LOCAL_LOGIN_REQUIRED', 'MFA_INVALID',
        'MFA_EXPIRED', 'MFA_IN_PROGRESS', 'ASSERTION_EXPIRED', 'TRANSACTION_USED',
        'RECEIPT_INVALID', 'RATE_LIMITED', 'NATIVE_UNAVAILABLE',
    ];

    private readonly \Closure $key;
    private readonly \Closure $exchange;
    private readonly \Closure $http;
    private readonly \Closure $clock;
    private readonly \Closure $nonce;
    private readonly \Closure $auditPolicy;

    /** Dependencies are explicit test injection; HTTP input never selects them. */
    public function __construct(Crypto $crypto, array $dependencies = [])
    {
        foreach ($dependencies as $name => $dependency) {
            if (!in_array($name, ['exchange', 'http', 'clock', 'nonce', 'auditPolicy'], true) || !is_callable($dependency)) {
                throw new NativeSessionException('BAD_REQUEST');
            }
        }
        $this->key = static fn(): string => $crypto->transportKey();
        $this->exchange = \Closure::fromCallable($dependencies['exchange'] ?? self::socketExchange(...));
        $this->http = \Closure::fromCallable($dependencies['http'] ?? self::httpCurrentUser(...));
        $this->clock = \Closure::fromCallable($dependencies['clock'] ?? time(...));
        $this->nonce = \Closure::fromCallable($dependencies['nonce'] ?? static fn(): string => bin2hex(random_bytes(32)));
        $this->auditPolicy = \Closure::fromCallable($dependencies['auditPolicy'] ?? self::readNetworkPolicy(...));
    }

    public function call(string $operation, array $fields = []): array
    {
        if (!in_array($operation, self::OPERATIONS, true) || array_key_exists('operation', $fields)) {
            throw new NativeSessionException('BAD_REQUEST');
        }
        try {
            $key = ($this->key)();
            $at = ($this->clock)();
            $nonce = ($this->nonce)();
            if (strlen($key) !== 32 || !is_int($at) || $at < 1 || !self::hex64($nonce)) {
                throw new NativeSessionException('NATIVE_UNAVAILABLE');
            }
            $json = json_encode(['operation' => $operation] + $fields, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            if (strlen($json) > self::BODY_LIMIT) {
                throw new NativeSessionException('BAD_REQUEST');
            }
            $body = rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
            $signed = implode("\n", ['UCRM-OIDC-ADAPTER-V2', 'ucrm-oidc', 'installation-v1', (string) $at, $nonce, $body]);
            $frame = json_encode([
                'v' => 2, 'caller' => 'ucrm-oidc', 'keyId' => 'installation-v1',
                'at' => $at, 'nonce' => $nonce, 'body' => $body,
                'mac' => hash_hmac('sha256', $signed, $key),
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            if (strlen($frame) > self::FRAME_LIMIT) {
                throw new NativeSessionException('BAD_REQUEST');
            }
            // Exactly one exchange; in particular, never retry issue/complete-mfa.
            $reply = ($this->exchange)($frame . "\n");
            if (!is_string($reply) || !str_ends_with($reply, "\n")
                || strlen($reply) > self::FRAME_LIMIT + 1) {
                throw new NativeSessionException('NATIVE_UNAVAILABLE');
            }
            $response = json_decode($reply, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($response) || !is_bool($response['ok'] ?? null)) {
                throw new NativeSessionException('NATIVE_UNAVAILABLE');
            }
            if ($response['ok'] === false) {
                $code = $response['error']['code'] ?? null;
                throw new NativeSessionException(is_string($code) && in_array($code, self::SAFE_ERRORS, true)
                    ? $code : 'NATIVE_UNAVAILABLE');
            }
            if (!is_array($response['result'] ?? null)) {
                throw new NativeSessionException('NATIVE_UNAVAILABLE');
            }
            return $response['result'];
        } catch (NativeSessionException $error) {
            throw $error;
        } catch (\Throwable) {
            throw new NativeSessionException('NATIVE_UNAVAILABLE');
        }
    }

    public function status(): array
    {
        $value = $this->call('status');
        if (($value['kind'] ?? null) !== 'status' || ($value['protocol'] ?? null) !== 2
            || !is_bool($value['enabled'] ?? null) || !is_bool($value['pluginEnabled'] ?? null)
            || !self::hex64($value['serverEpoch'] ?? null)
            || !array_key_exists('configRevision', $value)
            || ($value['configRevision'] !== null && !self::hex64($value['configRevision']))
            || !is_string($value['nativeVersion'] ?? null) || strlen($value['nativeVersion']) > 64
            || !self::hex64($value['sourceBundleSha256'] ?? null)) {
            throw new NativeSessionException('NATIVE_UNAVAILABLE');
        }
        // Preserve the wire configRevision name; Application maps it separately
        // from its own providerRevision and credentialRevision.
        return array_intersect_key($value, array_flip([
            'kind', 'protocol', 'enabled', 'pluginEnabled', 'serverEpoch',
            'configRevision', 'nativeVersion', 'sourceBundleSha256',
        ]));
    }

    public function current(array $cookies, array $server): ?array
    {
        $sessionId = $cookies['nms-session'] ?? null;
        if (!self::uuid($sessionId)) {
            return null;
        }
        try {
            $status = $this->status();
            $value = $this->call('describe-caller', [
                'callerSessionId' => $sessionId,
                'audit' => $this->audit($server),
                'serverEpoch' => $status['serverEpoch'],
            ]);
        } catch (NativeSessionException $error) {
            if ($error->safeCode === 'ADMISSION_DENIED') {
                return null;
            }
            // Bad socket authentication and transport failure are availability
            // errors, not evidence that the visitor has no native session.
            throw $error;
        }
        if (($value['kind'] ?? null) !== 'caller' || !self::uuid($value['nativeUserId'] ?? null)
            || !is_string($value['username'] ?? null) || $value['username'] === '' || mb_strlen($value['username'], 'UTF-8') > 320
            || !is_string($value['role'] ?? null) || strlen($value['role']) > 64
            || !array_key_exists('ucrmRole', $value)
            || ($value['ucrmRole'] !== null && (!is_string($value['ucrmRole']) || strlen($value['ucrmRole']) > 64))
            || !is_int($value['createdAt'] ?? null) || $value['createdAt'] < 1
            || !in_array($value['source'] ?? null, ['adapter', 'native-unattributed'], true)
            || ($value['sessionId'] ?? null) !== $sessionId) {
            throw new NativeSessionException('NATIVE_UNAVAILABLE');
        }
        return array_intersect_key($value, array_flip([
            'nativeUserId', 'username', 'role', 'ucrmRole', 'createdAt', 'source', 'sessionId',
        ]));
    }

    public function adminContext(array $cookies, array $server): array
    {
        $context = $this->current($cookies, $server);
        $phpSession = $cookies['nms-crm-php-session-id'] ?? null;
        if ($context === null || !is_string($phpSession)
            || !preg_match('~\A[A-Za-z0-9,-]{1,256}\z~D', $phpSession)) {
            throw new NativeSessionException('ADMISSION_DENIED');
        }
        $forward = [
            'nms-session' => $context['sessionId'],
            'nms-crm-php-session-id' => $phpSession,
        ];
        try {
            $response = ($this->http)($forward);
            if (!is_array($response) || !is_int($response['status'] ?? null)) {
                throw new NativeSessionException('NATIVE_UNAVAILABLE');
            }
            if (in_array($response['status'], [301, 302, 303, 307, 308, 401, 403], true)) {
                throw new NativeSessionException('ADMISSION_DENIED');
            }
            if ($response['status'] !== 200 || !is_string($response['body'] ?? null)
                || strlen($response['body']) > self::RESPONSE_LIMIT) {
                throw new NativeSessionException('NATIVE_UNAVAILABLE');
            }
            $user = json_decode($response['body'], true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($user) || ($user['isClient'] ?? null) !== false
                || !is_int($user['userId'] ?? null) || $user['userId'] < 1
                || ($user['username'] ?? null) !== $context['username']
                || ($user['permissions']['system/plugins'] ?? null) !== 'edit') {
                throw new NativeSessionException('ADMISSION_DENIED');
            }
            return $context + [
                'crmUserId' => $user['userId'],
                'permissions' => ['system/plugins' => 'edit'],
                'isClient' => false,
            ];
        } catch (NativeSessionException $error) {
            throw $error;
        } catch (\Throwable) {
            throw new NativeSessionException('NATIVE_UNAVAILABLE');
        }
    }

    public function audit(array $server): array
    {
        [$address, $trustedProxy] = $this->peer($server);
        if ($trustedProxy) {
            $address = $server['HTTP_X_REAL_IP'] ?? null;
            if (!is_string($address) || filter_var($address, FILTER_VALIDATE_IP) === false) {
                throw new NativeSessionException('TRUSTED_PROXY_HEADER_INVALID');
            }
        }
        $agent = $server['HTTP_USER_AGENT'] ?? '';
        $agent = is_string($agent) && preg_match('//u', $agent) === 1 ? $agent : '';
        $agent = preg_replace('/[\x00-\x1f\x7f]/', '', $agent) ?? '';
        return ['remoteAddress' => $address, 'userAgent' => mb_strcut($agent, 0, 256, 'UTF-8')];
    }

    /** Actual request origin for CSRF only; never an OIDC callback origin. */
    public function servingOrigin(array $server): string
    {
        [, $trustedProxy] = $this->peer($server);
        if ($trustedProxy) {
            if (($server['HTTP_X_FORWARDED_PROTO'] ?? null) !== 'https') {
                throw new NativeSessionException('TRUSTED_PROXY_HEADER_INVALID');
            }
        } elseif (!in_array($server['HTTPS'] ?? null, ['on', '1', 1, true], true)) {
            throw new NativeSessionException('HTTPS_REQUIRED');
        }
        $host = $server['HTTP_HOST'] ?? null;
        if (!is_string($host) || strlen($host) > 260
            || preg_match('/[^A-Za-z0-9.\[\]:-]/', $host) || $host === '') {
            throw new NativeSessionException('BAD_REQUEST');
        }
        try {
            $parsed = parse_url('https://' . $host);
        } catch (\Throwable) {
            throw new NativeSessionException('BAD_REQUEST');
        }
        if (!is_array($parsed) || !isset($parsed['host'])
            || array_diff(array_keys($parsed), ['scheme', 'host', 'port']) !== []) {
            throw new NativeSessionException('BAD_REQUEST');
        }
        $name = strtolower($parsed['host']);
        if (str_starts_with($name, '[')) {
            if (!str_ends_with($name, ']') || filter_var(substr($name, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                throw new NativeSessionException('BAD_REQUEST');
            }
        } elseif (strlen($name) > 253 || !preg_match('/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/D', $name)) {
            throw new NativeSessionException('BAD_REQUEST');
        } else {
            foreach (explode('.', $name) as $label) {
                if ($label === '' || strlen($label) > 63 || $label[0] === '-' || str_ends_with($label, '-')) {
                    throw new NativeSessionException('BAD_REQUEST');
                }
            }
        }
        $port = $parsed['port'] ?? 443;
        if (!is_int($port) || $port < 1 || $port > 65535) {
            throw new NativeSessionException('BAD_REQUEST');
        }
        return 'https://' . $name . ($port === 443 ? '' : ':' . $port);
    }

    private function peer(array $server): array
    {
        $peer = $server['REMOTE_ADDR'] ?? null;
        if (!is_string($peer) || filter_var($peer, FILTER_VALIDATE_IP) === false) {
            throw new NativeSessionException('BAD_REQUEST');
        }
        try {
            $policy = ($this->auditPolicy)();
            $addresses = is_array($policy) ? ($policy['trustedProxyAddresses'] ?? null) : null;
            if (!is_array($addresses) || !array_is_list($addresses) || count($addresses) > 32) {
                throw new NativeSessionException('PROXY_POLICY_UNAVAILABLE');
            }
            $trusted = false;
            foreach ($addresses as $address) {
                if (!is_string($address) || filter_var($address, FILTER_VALIDATE_IP) === false) {
                    throw new NativeSessionException('PROXY_POLICY_UNAVAILABLE');
                }
                $trusted = $trusted || inet_pton($peer) === inet_pton($address);
            }
            return [$peer, $trusted];
        } catch (NativeSessionException $error) {
            throw $error;
        } catch (\Throwable) {
            throw new NativeSessionException('PROXY_POLICY_UNAVAILABLE');
        }
    }

    private static function readNetworkPolicy(): array
    {
        $raw = @file_get_contents(self::NETWORK_POLICY, false, null, 0, 65537);
        if (!is_string($raw) || strlen($raw) > 65536) {
            throw new NativeSessionException('PROXY_POLICY_UNAVAILABLE');
        }
        try {
            $value = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            throw new NativeSessionException('PROXY_POLICY_UNAVAILABLE');
        }
        if (!is_array($value)) {
            throw new NativeSessionException('PROXY_POLICY_UNAVAILABLE');
        }
        return $value;
    }

    private static function hex64(mixed $value): bool
    {
        return is_string($value) && preg_match('/\A[a-f0-9]{64}\z/D', $value) === 1;
    }

    private static function uuid(mixed $value): bool
    {
        return is_string($value) && preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/Di', $value) === 1;
    }

    private static function socketExchange(string $frame): string
    {
        $deadline = microtime(true) + 5.0;
        $socket = @stream_socket_client('unix://' . self::SOCKET, $errno, $message, 2);
        if ($socket === false) {
            throw new NativeSessionException('NATIVE_UNAVAILABLE');
        }
        try {
            stream_set_blocking($socket, false);
            $offset = 0;
            while ($offset < strlen($frame)) {
                self::waitForStream($socket, false, $deadline);
                $written = @fwrite($socket, substr($frame, $offset));
                if ($written === false || $written === 0) {
                    throw new NativeSessionException('NATIVE_UNAVAILABLE');
                }
                $offset += $written;
            }
            $response = '';
            while (!str_contains($response, "\n")) {
                self::waitForStream($socket, true, $deadline);
                $chunk = @fread($socket, self::FRAME_LIMIT + 2 - strlen($response));
                if ($chunk === false || $chunk === '' || strlen($response) + strlen($chunk) > self::FRAME_LIMIT + 1) {
                    throw new NativeSessionException('NATIVE_UNAVAILABLE');
                }
                $response .= $chunk;
            }
            return $response;
        } finally {
            fclose($socket);
        }
    }

    private static function waitForStream($socket, bool $readable, float $deadline): void
    {
        $remaining = $deadline - microtime(true);
        if ($remaining <= 0) {
            throw new NativeSessionException('NATIVE_UNAVAILABLE');
        }
        $read = $readable ? [$socket] : [];
        $write = $readable ? [] : [$socket];
        $except = [];
        $seconds = (int) floor($remaining);
        $microseconds = (int) floor(($remaining - $seconds) * 1000000);
        if (@stream_select($read, $write, $except, $seconds, $microseconds) !== 1) {
            throw new NativeSessionException('NATIVE_UNAVAILABLE');
        }
    }

    private static function httpCurrentUser(array $cookies): array
    {
        $body = '';
        $headerBytes = 0;
        $curl = curl_init(self::CURRENT_USER_URL);
        try {
            curl_setopt_array($curl, [
                CURLOPT_HTTPGET => true,
                CURLOPT_HTTPHEADER => [
                    'Accept: application/json',
                    'Cookie: nms-session=' . $cookies['nms-session']
                        . '; nms-crm-php-session-id=' . $cookies['nms-crm-php-session-id'],
                ],
                CURLOPT_PROXY => '',
                CURLOPT_PROTOCOLS => CURLPROTO_HTTP,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_TIMEOUT => 5,
                CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$headerBytes): int {
                    $headerBytes += strlen($line);
                    return $headerBytes > 16384 ? 0 : strlen($line);
                },
                CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body): int {
                    if (strlen($body) + strlen($chunk) > self::RESPONSE_LIMIT) {
                        return 0;
                    }
                    $body .= $chunk;
                    return strlen($chunk);
                },
            ]);
            if (curl_exec($curl) === false) {
                throw new NativeSessionException('NATIVE_UNAVAILABLE');
            }
            return ['status' => (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE), 'body' => $body];
        } finally {
            curl_close($curl);
        }
    }
}
