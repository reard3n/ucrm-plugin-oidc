<?php
declare(strict_types=1);
define('UCRM_OIDC_FIXTURES_ONLY', true);
require __DIR__ . '/core-unit.php';

use UcrmOidc\{Config, Crypto, Oidc, Store};

function logoutFixture(): array
{
    $directory = '/tmp/oidc-logout-jose-' . Crypto::random(); mkdir($directory, 0700);
    file_put_contents($directory . '/key', Crypto::random()); chmod($directory . '/key', 0600);
    $store = new Store(new Crypto($directory . '/key'), $directory . '/state.sqlite');
    $provider = new Provider(); $now = time();
    $oidc = new Oidc($store, fn() => $provider, fn() => $now);
    $settings = Config::settings(array_replace(Config::DEFAULTS, ['issuer' => 'https://identity.example/oidc',
        'canonicalOrigin' => 'https://crm.example', 'clientId' => 'test-client']));
    $claims = ['iss' => $settings['issuer'], 'aud' => 'test-client', 'sub' => 'subject-1', 'sid' => 'provider-session-1',
        'iat' => $now, 'exp' => $now + 120, 'jti' => uuid(), 'events' => (object)[Oidc::LOGOUT_EVENT => new stdClass()]];
    return compact('store', 'provider', 'now', 'oidc', 'settings', 'claims');
}
function signedLogout(array $f, mixed $claims = null, array $headers = [], mixed $key = null): string
{
    $header = array_replace(['alg' => 'RS256', 'kid' => 'test-key', 'typ' => 'logout+jwt'], $headers);
    foreach ($header as $name => $value) { if ($value === null) { unset($header[$name]); } }
    $input = b64(json_encode($header, JSON_THROW_ON_ERROR)) . '.' . b64(json_encode($claims ?? $f['claims'], JSON_THROW_ON_ERROR));
    openssl_sign($input, $signature, $key ?? $f['provider']->key, OPENSSL_ALGO_SHA256);
    return $input . '.' . b64($signature);
}
function verifyLogoutCase(array $f, string $token): array { return $f['oidc']->verifyLogout($f['settings'], $token); }

try {
    $f = logoutFixture(); $identity = verifyLogoutCase($f, signedLogout($f));
    check('real RS256 logout returns verified stable scope and delivery times', $identity === [
        'issuer' => $f['settings']['issuer'], 'clientId' => 'test-client', 'subject' => 'subject-1', 'sid' => 'provider-session-1',
        'issuedAt' => $f['now'], 'expiresAt' => $f['now'] + 120, 'jti' => $f['claims']['jti']]);
    check('logout does not use a client secret or token endpoint', $f['provider']->tokenRequests === 0 && $f['provider']->jwksRequests === 1);
    check('renewed delivery times do not change verified replay identity', verifyLogoutCase($f, signedLogout($f,
        array_replace($f['claims'], ['iat' => $f['now'] + 1, 'exp' => $f['now'] + 121])))['jti'] === $identity['jti']);
    check('30 second issued-time skew accepted', verifyLogoutCase($f, signedLogout($f,
        array_replace($f['claims'], ['iat' => $f['now'] + 30])))['issuedAt'] === $f['now'] + 30);
    check('expiration within30 second skew accepted', verifyLogoutCase($f, signedLogout($f,
        array_replace($f['claims'], ['iat' => $f['now'] - 120, 'exp' => $f['now'] - 29])))['expiresAt'] === $f['now'] - 29);
    foreach (['sid', 'sub'] as $removed) {
        $claims = $f['claims']; unset($claims[$removed]);
        $result = verifyLogoutCase($f, signedLogout($f, $claims));
        check('standard logout without ' . $removed . ' accepted', $result[$removed === 'sub' ? 'subject' : 'sid'] === null);
    }
    foreach ([null, 'JWT', 'application/jwt', 'application/logout+jwt', 'LOGOUT+JWT'] as $type) {
        check('optional compatible token type ' . ($type ?? 'absent'), verifyLogoutCase($f, signedLogout($f, null, ['typ' => $type]))['jti'] === $f['claims']['jti']);
    }
    check('optional kid absent uses only trusted published keys', verifyLogoutCase($f, signedLogout($f, null, ['kid' => null]))['subject'] === 'subject-1');
    check('multiple string audiences may include this client', verifyLogoutCase($f, signedLogout($f,
        array_replace($f['claims'], ['aud' => ['other', 'test-client'], 'azp' => 'test-client'])) )['clientId'] === 'test-client');
    check('additional event members remain interoperable', verifyLogoutCase($f, signedLogout($f,
        array_replace($f['claims'], ['events' => (object)[Oidc::LOGOUT_EVENT => (object)['extension' => true], 'other' => new stdClass()]])))['subject'] === 'subject-1');
    foreach (['iss', 'aud', 'iat', 'exp', 'jti', 'events'] as $claim) {
        $claims = $f['claims']; unset($claims[$claim]);
        denied('required ' . $claim, fn() => verifyLogoutCase($f, signedLogout($f, $claims)), 'LOGOUT_INVALID');
    }
    $cases = [
        'wrong issuer' => ['iss' => 'https://untrusted.example/oidc'], 'wrong audience' => ['aud' => 'another-client'],
        'audience object' => ['aud' => (object)['0' => 'test-client']], 'empty audiences' => ['aud' => []],
        'mixed audiences' => ['aud' => ['test-client', 1]], 'too many audiences' => ['aud' => array_fill(0, 17, 'test-client')],
        'multiple audiences require authorized party' => ['aud' => ['other', 'test-client']],
        'wrong authorized party' => ['aud' => ['other', 'test-client'], 'azp' => 'other'],
        'single audience wrong authorized party' => ['azp' => 'other'], 'null authorized party' => ['azp' => null],
        'null subject' => ['sub' => null], 'empty subject' => ['sub' => ''], 'long subject' => ['sub' => str_repeat('s', 256)],
        'control subject' => ['sub' => "a\n"], 'null SID' => ['sid' => null], 'array SID' => ['sid' => []],
        'empty SID' => ['sid' => ''], 'long SID' => ['sid' => str_repeat('s', 1025)], 'control SID' => ['sid' => "a\0"],
        'missing identity' => ['sub' => null, 'sid' => null], 'empty jti' => ['jti' => ''], 'integer jti' => ['jti' => 1],
        'long jti' => ['jti' => str_repeat('j', 256)], 'nonce null' => ['nonce' => null], 'nonce string' => ['nonce' => 'nonce'],
        'events array' => ['events' => []], 'event value array' => ['events' => (object)[Oidc::LOGOUT_EVENT => []]],
        'event value null' => ['events' => (object)[Oidc::LOGOUT_EVENT => null]], 'wrong event' => ['events' => (object)['logout' => new stdClass()]],
        'float iat' => ['iat' => (float)$f['now'] + .5], 'string iat' => ['iat' => (string)$f['now']], 'negative iat' => ['iat' => -1],
        'future iat' => ['iat' => $f['now'] + 31], 'old iat' => ['iat' => $f['now'] - 86431],
        'string exp' => ['exp' => (string)($f['now'] + 120)], 'expired exp' => ['exp' => $f['now'] - 30, 'iat' => $f['now'] - 120],
        'inverted lifetime' => ['exp' => $f['now'] - 1], 'unbounded lifetime' => ['exp' => $f['now'] + 86401],
        'future nbf' => ['nbf' => $f['now'] + 31], 'null nbf' => ['nbf' => null],
    ];
    foreach ($cases as $name => $changes) { denied($name, fn() => verifyLogoutCase($f, signedLogout($f, array_replace($f['claims'], $changes))), 'LOGOUT_INVALID'); }
    $claims = $f['claims']; unset($claims['sid'], $claims['sub']);
    denied('absent subject and SID', fn() => verifyLogoutCase($f, signedLogout($f, $claims)), 'LOGOUT_INVALID');
    foreach ([[], 'string', 1] as $claims) { denied('payload must be a JSON object', fn() => verifyLogoutCase($f, signedLogout($f, $claims)), 'LOGOUT_INVALID'); }
    foreach (['none', 'HS256', 'RS512'] as $alg) { denied('algorithm ' . $alg, fn() => verifyLogoutCase($f, signedLogout($f, null, ['alg' => $alg])), 'LOGOUT_INVALID'); }
    foreach ([['typ' => 'at+jwt'], ['typ' => 1], ['kid' => ''], ['kid' => []], ['crit' => []], ['crit' => ['test']], ['b64' => true]] as $headers) {
        denied('unsupported protected header', fn() => verifyLogoutCase($f, signedLogout($f, null, $headers)), 'LOGOUT_INVALID');
    }
    foreach (['', 'a.b.c', 'a..c', 'a.b.c.d', 'a.b.c=', str_repeat('a', 32769), str_repeat('.', 32768)] as $input) {
        denied('bounded compact serialization', fn() => verifyLogoutCase($f, $input), 'LOGOUT_INVALID');
    }
    check('invalid claims and headers never refetch cached keys', $f['provider']->jwksRequests === 1);
    check('untrusted optional key URLs are ignored', verifyLogoutCase($f, signedLogout($f, null,
        ['jku' => 'https://untrusted.example/keys', 'x5u' => 'https://untrusted.example/cert', 'jwk' => ['kty' => 'oct', 'k' => 'secret']]))['subject'] === 'subject-1');
    $bad = logoutFixture(); $other = new Provider();
    denied('real signature from untrusted key rejected', fn() => verifyLogoutCase($bad, signedLogout($bad, null, [], $other->key)), 'LOGOUT_INVALID');
    check('invalid signature permits only one JWKS refresh', $bad['provider']->jwksRequests === 2);
    denied('repeated invalid signature cannot flood key endpoint', fn() => verifyLogoutCase($bad, signedLogout($bad, null, [], $other->key)), 'LOGOUT_INVALID');
    check('refresh rate is durable across requests', $bad['provider']->jwksRequests === 2);
    $rotated = logoutFixture(); verifyLogoutCase($rotated, signedLogout($rotated));
    $rotated['provider']->key = $other->key; $rotated['provider']->jwks = $other->jwks;
    $rotated['provider']->jwks['keys'][0]['kid'] = 'rotated';
    check('real signing key rotation refreshes bounded JWKS', verifyLogoutCase($rotated, signedLogout($rotated, null, ['kid' => 'rotated']))['subject'] === 'subject-1'
        && $rotated['provider']->jwksRequests === 2);
    $mismatch = logoutFixture();
    denied('kid must select the actual trusted signer', fn() => verifyLogoutCase($mismatch, signedLogout($mismatch, null, ['kid' => 'unknown'])), 'LOGOUT_INVALID');
    $unavailable = logoutFixture(); $unavailable['provider']->metadata['jwks_uri'] = 'https://untrusted.example/keys';
    denied('provider configuration outage is retryable without untrusted network', fn() => verifyLogoutCase($unavailable, signedLogout($unavailable)), 'LOGOUT_UNAVAILABLE');
    foreach ([['sid' => 'id-token-session'], [], ['sid' => null], ['sid' => []], ['sid' => '']] as $claims) {
        $login = logoutFixture(); $flow = ['state' => Crypto::random(), 'nonce' => Crypto::random(), 'code_verifier' => Crypto::random(), 'maxAge' => 300];
        parse_str(parse_url($login['oidc']->authorization($login['settings'], 'synthetic-secret', $flow), PHP_URL_QUERY), $query);
        $code = $login['provider']->register($query, $claims, ['sid' => 'untrusted-userinfo-session']);
        $verify = fn() => $login['oidc']->verify($login['settings'], 'synthetic-secret', $flow, ['code' => $code, 'state' => $flow['state']]);
        if ((array_key_exists('sid', $claims) && !is_string($claims['sid'])) || ($claims['sid'] ?? null) === '') {
            denied('invalid signed ID-token SID rejects login', $verify, 'AUTHENTICATION_DENIED');
        } else {
            $identity = $verify(); check('login session metadata comes only from validated ID token',
                $identity['sid'] === ($claims['sid'] ?? null) && $identity['clientId'] === 'test-client' && is_int($identity['issuedAt']));
        }
    }
    echo json_encode(['php' => PHP_VERSION, 'passed' => count($checks), 'checks' => $checks], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
} catch (Throwable $e) {
    echo json_encode(['php' => PHP_VERSION, 'passed' => count(array_filter($checks, fn($c) => $c['passed'])),
        'failure' => $e->getMessage(), 'type' => get_class($e), 'checks' => $checks], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n"; exit(1);
}
