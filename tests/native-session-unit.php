<?php
declare(strict_types=1);

// Standalone contract test process: this stub supplies only a synthetic transport
// key. It does not load/replace the production Crypto implementation or certify it.
namespace UcrmOidc {
    final class Crypto
    {
        public function __construct(private readonly string $key) {}
        public function transportKey(): string { return $this->key; }
    }
}

namespace {
    require dirname(__DIR__) . '/plugin/src/NativeSession.php';

    use UcrmOidc\Crypto;
    use UcrmOidc\NativeSession;
    use UcrmOidc\NativeSessionException;

    $count = 0;
    $test = 'initialization';
    function verify(bool $condition, string $name): void
    {
        global $count, $test;
        $test = $name;
        if (!$condition) throw new \RuntimeException('check_failed');
        ++$count;
    }
    function denied(callable $action, string $code, string $name): void
    {
        try { $action(); } catch (NativeSessionException $error) {
            verify($error->safeCode === $code && $error->getMessage() === $code
                && $error->getPrevious() === null, $name);
            return;
        }
        verify(false, $name);
    }
    function frame(array $result): string
    {
        return json_encode(['ok' => true, 'result' => $result], JSON_THROW_ON_ERROR) . "\n";
    }
    function transport(callable $exchange, array $extra = [], ?string $key = null): NativeSession
    {
        $key ??= hex2bin('be4bcd812e1670e9bdc75c297d7598c539a0923fe38049eb0e71c636323490a1');
        return new NativeSession(new Crypto($key), $extra + [
            'exchange' => $exchange,
            'clock' => static fn(): int => 1800000000,
            'nonce' => static fn(): string => str_repeat('cd', 32),
            'auditPolicy' => static fn(): array => ['trustedProxyAddresses' => []],
        ]);
    }

    try {
        $status = [
            'kind' => 'status', 'protocol' => 2, 'enabled' => true, 'pluginEnabled' => true,
            'serverEpoch' => str_repeat('a', 64), 'configRevision' => str_repeat('b', 64),
            'nativeVersion' => '2.4.220', 'sourceBundleSha256' => str_repeat('c', 64),
        ];
        $caller = [
            'kind' => 'caller', 'nativeUserId' => '11111111-1111-4111-8111-111111111111',
            'username' => 'synthetic-admin', 'role' => 'superadmin', 'ucrmRole' => 'admin',
            'createdAt' => 1799999950, 'source' => 'native-unattributed',
            'sessionId' => '22222222-2222-4222-8222-222222222222',
        ];
        $cookies = ['nms-session' => $caller['sessionId'], 'nms-crm-php-session-id' => 'synthetic-native-php-session'];
        $server = ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_USER_AGENT' => 'contract-test'];
        $crm = ['userId' => 1, 'username' => $caller['username'], 'isClient' => false,
            'permissions' => ['system/plugins' => 'edit', 'unrelated' => 'view']];

        $captured = null;
        $native = transport(static function (string $request) use (&$captured, $status): string {
            $captured = $request;
            return frame($status);
        });
        verify($native->status() === $status, 'status_preserves_native_revision');
        $wire = json_decode($captured, true, 32, JSON_THROW_ON_ERROR);
        verify(array_keys($wire) === ['v', 'caller', 'keyId', 'at', 'nonce', 'body', 'mac'], 'exact_envelope_keys');
        verify($wire['v'] === 2 && $wire['caller'] === 'ucrm-oidc' && $wire['keyId'] === 'installation-v1', 'fixed_protocol_identity');
        verify($wire['at'] === 1800000000 && $wire['nonce'] === str_repeat('cd', 32), 'clock_nonce_contract');
        verify($wire['body'] === 'eyJvcGVyYXRpb24iOiJzdGF0dXMifQ', 'exact_base64url_body');
        // Independently calculated with Python HMAC/HKDF from master ab*32.
        verify($wire['mac'] === '50ed372ddeb2ffe2d28e926712e4d36f9b47cac57e4bba11b0cf9406bea037e0', 'independent_hmac_vector');
        verify(substr_count($captured, "\n") === 1 && str_ends_with($captured, "\n"), 'single_lf_frame');

        denied(fn() => $native->call('unknown'), 'BAD_REQUEST', 'unknown_operation');
        denied(fn() => $native->call('status', ['operation' => 'issue']), 'BAD_REQUEST', 'operation_override');
        denied(fn() => $native->call('resolve', ['email' => str_repeat('x', 8192)]), 'BAD_REQUEST', 'request_body_bound');
        denied(fn() => transport(fn() => frame($status), [], 'short')->status(), 'NATIVE_UNAVAILABLE', 'transport_key_length');
        denied(fn() => transport(fn() => frame($status), ['nonce' => fn() => 'invalid'])->status(), 'NATIVE_UNAVAILABLE', 'nonce_shape');
        denied(fn() => transport(fn() => frame($status), ['clock' => fn() => '1800000000'])->status(), 'NATIVE_UNAVAILABLE', 'clock_integer');
        denied(fn() => new NativeSession(new Crypto(str_repeat('x', 32)), ['socketPath' => '/tmp/arbitrary']), 'BAD_REQUEST', 'fixed_backend_dependencies');

        foreach (["{}\n", "[]\n", 'no-newline', "not-json\n", str_repeat('x', 16385) . "\n",
            "{\"ok\":true,\"result\":null}\n", "{\"ok\":\"true\",\"result\":{}}\n"] as $i => $response) {
            denied(fn() => transport(fn() => $response)->status(), 'NATIVE_UNAVAILABLE', 'malformed_response_' . $i);
        }
        denied(fn() => transport(fn() => "{\"ok\":false,\"error\":{\"code\":\"raw-private-message\"}}\n")->status(),
            'NATIVE_UNAVAILABLE', 'unknown_native_error_redacted');
        denied(fn() => transport(fn() => "{\"ok\":false,\"error\":{\"code\":\"CONFIG_CHANGED\",\"detail\":\"private\"}}\n")->status(),
            'CONFIG_CHANGED', 'safe_native_error_only');
        denied(fn() => transport(static function (): never { throw new \RuntimeException('private payload'); })->status(),
            'NATIVE_UNAVAILABLE', 'transport_exception_redacted');
        $calls = 0;
        $uncertain = transport(static function () use (&$calls): never { ++$calls; throw new \RuntimeException('timeout'); });
        foreach (['issue', 'complete-mfa'] as $operation) {
            $calls = 0;
            denied(fn() => $uncertain->call($operation, []), 'NATIVE_UNAVAILABLE', $operation . '_uncertainty_safe');
            verify($calls === 1, $operation . '_never_retried');
        }
        foreach (['protocol' => 1, 'enabled' => 'true', 'serverEpoch' => 'bad', 'configRevision' => 'bad',
            'sourceBundleSha256' => 'bad'] as $key => $value) {
            denied(fn() => transport(fn() => frame(array_replace($status, [$key => $value])))->status(),
                'NATIVE_UNAVAILABLE', 'status_shape_' . $key);
        }
        $disabled = array_replace($status, ['enabled' => false, 'pluginEnabled' => false, 'configRevision' => null]);
        verify(transport(fn() => frame($disabled))->status() === $disabled, 'disabled_status_allows_null_revision');
        verify(!array_key_exists('private', transport(fn() => frame($status + ['private' => 'hidden']))->status()), 'status_projection');

        $operations = [];
        $valid = static function (string $request) use (&$operations, $status, $caller): string {
            $wire = json_decode($request, true, 32, JSON_THROW_ON_ERROR);
            $body = json_decode(base64_decode(strtr($wire['body'], '-_', '+/')), true, 32, JSON_THROW_ON_ERROR);
            $operations[] = $body;
            return frame($body['operation'] === 'status' ? $status : $caller);
        };
        $native = transport($valid);
        foreach ([[], ['nms-session' => []], ['nms-session' => 'invalid'], ['nms-session' => "a\r\nInjected: yes"]] as $i => $input) {
            verify($native->current($input, $server) === null, 'invalid_cookie_anonymous_' . $i);
        }
        verify($operations === [], 'missing_auth_never_calls_adapter');
        $current = $native->current($cookies, $server);
        verify($current['nativeUserId'] === $caller['nativeUserId'] && $current['sessionId'] === $cookies['nms-session'], 'current_from_native_cookie');
        verify(!array_key_exists('kind', $current), 'current_context_projection');
        verify($operations[1] === ['operation' => 'describe-caller', 'callerSessionId' => $cookies['nms-session'],
            'audit' => ['remoteAddress' => '127.0.0.1', 'userAgent' => 'contract-test'], 'serverEpoch' => $status['serverEpoch']], 'describe_exact_fields');
        $withoutCrm = transport(static function (string $request) use ($status, $caller): string {
            return str_contains(base64_decode(strtr(json_decode($request, true)['body'], '-_', '+/')), 'describe-caller')
                ? frame(array_replace($caller, ['ucrmRole' => null, 'role' => 'admin'])) : frame($status);
        });
        verify($withoutCrm->current($cookies, $server)['ucrmRole'] === null, 'nms_only_caller_still_detected');
        foreach ([320, 321] as $length) {
            $subject = transport(static function (string $request) use ($status, $caller, $length): string {
                return str_contains(base64_decode(strtr(json_decode($request, true)['body'], '-_', '+/')), 'describe-caller')
                    ? frame(array_replace($caller, ['username' => str_repeat('x', $length)])) : frame($status);
            });
            if ($length === 320) verify(strlen($subject->current($cookies, $server)['username']) === 320, 'native_username_maximum_supported');
            else denied(fn() => $subject->current($cookies, $server), 'NATIVE_UNAVAILABLE', 'native_username_bound');
        }
        foreach (['ADMISSION_DENIED', 'AUTHENTICATION_FAILED', 'NATIVE_UNAVAILABLE'] as $code) {
            $subject = transport(static function (string $request) use ($status, $code): string {
                return str_contains(base64_decode(strtr(json_decode($request, true)['body'], '-_', '+/')), 'describe-caller')
                    ? json_encode(['ok' => false, 'error' => ['code' => $code]]) . "\n" : frame($status);
            });
            if ($code === 'ADMISSION_DENIED') verify($subject->current($cookies, $server) === null, 'invalid_native_session_anonymous');
            else denied(fn() => $subject->current($cookies, $server), $code, 'transport_auth_failure_is_not_anonymous_' . $code);
        }
        foreach (['createdAt' => '1799999950', 'source' => 'browser', 'sessionId' => '33333333-3333-4333-8333-333333333333',
            'nativeUserId' => 'arbitrary'] as $key => $value) {
            $subject = transport(static function (string $request) use ($status, $caller, $key, $value): string {
                return str_contains(base64_decode(strtr(json_decode($request, true)['body'], '-_', '+/')), 'describe-caller')
                    ? frame(array_replace($caller, [$key => $value])) : frame($status);
            });
            denied(fn() => $subject->current($cookies, $server), 'NATIVE_UNAVAILABLE', 'caller_shape_' . $key);
        }

        $forwarded = [];
        $http = static function (array $values) use (&$forwarded, $crm): array {
            $forwarded = $values;
            return ['status' => 200, 'body' => json_encode($crm)];
        };
        $context = transport($valid, ['http' => $http])->adminContext($cookies + ['irrelevant' => 'do-not-forward'], $server);
        verify($forwarded === $cookies, 'only_two_native_cookies_forwarded');
        verify($context['crmUserId'] === 1 && $context['permissions'] === ['system/plugins' => 'edit'], 'native_admin_permission_projection');
        verify($context['createdAt'] === $caller['createdAt'] && $context['source'] === $caller['source'], 'freshness_not_inferred_from_php_session');
        foreach ([['isClient' => true], ['permissions' => ['system/plugins' => 'view']], ['permissions' => []],
            ['username' => 'different-user'], ['userId' => '1']] as $i => $change) {
            $bad = array_replace($crm, $change);
            denied(fn() => transport($valid, ['http' => fn() => ['status' => 200, 'body' => json_encode($bad)]])->adminContext($cookies, $server),
                'ADMISSION_DENIED', 'native_admin_rejected_' . $i);
        }
        foreach ([301, 302, 303, 307, 308, 401, 403] as $statusCode) {
            denied(fn() => transport($valid, ['http' => fn() => ['status' => $statusCode, 'body' => 'private']])->adminContext($cookies, $server),
                'ADMISSION_DENIED', 'native_http_denial_' . $statusCode);
        }
        foreach ([['status' => 500, 'body' => 'private'], ['status' => 200, 'body' => 'not-json'],
            ['status' => 200, 'body' => str_repeat('x', 65537)]] as $i => $response) {
            denied(fn() => transport($valid, ['http' => fn() => $response])->adminContext($cookies, $server),
                'NATIVE_UNAVAILABLE', 'native_http_invalid_' . $i);
        }
        denied(fn() => transport($valid, ['http' => $http])->adminContext(['nms-session' => $cookies['nms-session']], $server),
            'ADMISSION_DENIED', 'php_cookie_required_for_admin');
        denied(fn() => transport($valid, ['http' => $http])->adminContext(array_replace($cookies, ['nms-crm-php-session-id' => "bad\r\nheader"]), $server),
            'ADMISSION_DENIED', 'php_cookie_header_injection_denied');

        $audit = $native->audit($server + ['HTTP_X_FORWARDED_FOR' => '198.51.100.8', 'HTTP_X_REAL_IP' => '198.51.100.8']);
        verify($audit['remoteAddress'] === '127.0.0.1', 'browser_forwarded_ip_ignored');
        $audit = $native->audit(['REMOTE_ADDR' => '::1', 'HTTP_USER_AGENT' => "abc\r\n\0" . str_repeat('😀', 200)]);
        verify(strlen($audit['userAgent']) <= 256 && preg_match('//u', $audit['userAgent']) === 1
            && !preg_match('/[\x00-\x1f\x7f]/', $audit['userAgent']), 'audit_utf8_byte_bound_no_controls');
        verify($native->audit(['REMOTE_ADDR' => '::1', 'HTTP_USER_AGENT' => "\xff"] )['userAgent'] === '', 'invalid_utf8_agent_discarded');
        denied(fn() => $native->audit(['REMOTE_ADDR' => 'hostname']), 'BAD_REQUEST', 'audit_ip_literal_required');
        $proxy = transport($valid, ['auditPolicy' => fn() => ['trustedProxyAddresses' => ['198.19.229.7']]]);
        $proxied = ['REMOTE_ADDR' => '198.19.229.7', 'HTTP_X_REAL_IP' => '198.51.100.5',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.99, 198.51.100.5', 'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_HOST' => 'localhost:18443', 'HTTP_X_FORWARDED_HOST' => 'attacker.invalid'];
        verify($proxy->audit($proxied)['remoteAddress'] === '198.51.100.5', 'only_pinned_proxy_real_ip_used');
        verify($proxy->servingOrigin($proxied) === 'https://localhost:18443', 'serving_origin_ignores_forwarded_host');
        foreach ([null, '', '198.51.100.5, 203.0.113.7', "198.51.100.5\r\n", 'hostname'] as $i => $badIp) {
            denied(fn() => $proxy->audit(array_replace($proxied, ['HTTP_X_REAL_IP' => $badIp])),
                'TRUSTED_PROXY_HEADER_INVALID', 'trusted_proxy_invalid_real_ip_' . $i);
        }
        foreach ([null, 'http', 'https,http', 'HTTPS'] as $i => $proto) {
            denied(fn() => $proxy->servingOrigin(array_replace($proxied, ['HTTP_X_FORWARDED_PROTO' => $proto])),
                'TRUSTED_PROXY_HEADER_INVALID', 'trusted_proxy_invalid_proto_' . $i);
        }
        verify($proxy->audit(array_replace($proxied, ['REMOTE_ADDR' => '198.19.229.8']))['remoteAddress'] === '198.19.229.8',
            'neighbor_proxy_is_not_trusted');
        denied(fn() => $proxy->servingOrigin(array_replace($proxied, ['REMOTE_ADDR' => '198.19.229.8'])),
            'HTTPS_REQUIRED', 'untrusted_peer_cannot_assert_https');
        verify($native->servingOrigin(['REMOTE_ADDR' => '::1', 'HTTPS' => 'on', 'HTTP_HOST' => 'EXAMPLE.COM:443']) === 'https://example.com',
            'direct_https_origin_normalized');
        verify($native->servingOrigin(['REMOTE_ADDR' => '::1', 'HTTPS' => '1', 'HTTP_HOST' => '[::1]:18443']) === 'https://[::1]:18443',
            'direct_ipv6_https_origin');
        foreach (['evil@localhost', 'localhost/path', 'localhost?x', 'localhost#x', 'localhost:99999',
            'bad..host', '-bad.host', "localhost\r\n", 'localhost:0', 'localhost:443:80'] as $i => $badHost) {
            denied(fn() => $proxy->servingOrigin(array_replace($proxied, ['HTTP_HOST' => $badHost])), 'BAD_REQUEST', 'invalid_serving_host_' . $i);
        }
        foreach ([[], ['trustedProxyAddresses' => 'all'], ['trustedProxyAddresses' => ['198.19.229.0/24']],
            ['trustedProxyAddresses' => ['hostname']], ['trustedProxyAddresses' => ['named' => '127.0.0.1']]] as $i => $policy) {
            denied(fn() => transport($valid, ['auditPolicy' => fn() => $policy])->audit($server), 'PROXY_POLICY_UNAVAILABLE', 'invalid_operator_proxy_policy_' . $i);
        }

        echo json_encode(['test' => 'native_session_contract_unit', 'status' => 'passed', 'assertions' => $count], JSON_THROW_ON_ERROR) . "\n";
    } catch (\Throwable) {
        echo json_encode(['test' => $test, 'status' => 'failed'], JSON_THROW_ON_ERROR) . "\n";
        exit(1);
    }
}
