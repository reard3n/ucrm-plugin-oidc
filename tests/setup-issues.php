<?php
declare(strict_types=1);
define('UCRM_OIDC_FIXTURES_ONLY', true);
require __DIR__ . '/core-unit.php';
require __DIR__ . '/../plugin/src/Web.php';

use UcrmOidc\{Application, Config, Crypto, NativeSession, Web};

$fixtures = [];
try {
    $f = fixture(); $fixtures[] = $f;
    $f['adapter']->enabled = false;
    $vm = $f['app']->configuration($f['admin']);
    check('saved configuration is complete with admission off', $vm['providerConfigured'] && !$vm['ready'] && !$f['app']->status()['ready']);
    check('discovery can pass before admission', $f['app']->connectionTest($f['admin'])['ok']);
    denied('normal start remains disabled', fn() => login($f), 'OIDC_DISABLED');
    denied('preview respects the existing native admission policy', fn() => login($f, preview: $f['admin']), 'OIDC_DISABLED');
    $settings = $f['store']->one('SELECT * FROM settings WHERE id=1');
    $f['store']->run('UPDATE settings SET secret_enc=NULL WHERE id=1');
    check('missing required secret needs setup', !$f['app']->configuration($f['admin'])['providerConfigured']);
    $public = json_decode($settings['config_json'], true); $public['clientAuthMethod'] = 'none';
    $f['store']->run('UPDATE settings SET config_json=? WHERE id=1', [json_encode($public)]);
    check('public client does not need a secret', $f['app']->configuration($f['admin'])['providerConfigured']);
    $f['store']->run('UPDATE settings SET config_json=NULL WHERE id=1');
    check('missing settings needs setup', !$f['app']->configuration($f['admin'])['providerConfigured']);
    $f['store']->run('UPDATE settings SET config_json=?,secret_enc=? WHERE id=1', [$settings['config_json'], $settings['secret_enc']]);
    $f['adapter']->enabled = true;
    check('configured and enabled provider is ready', $f['app']->configuration($f['admin'])['ready']);
    $f['store']->run("UPDATE meta SET value='required' WHERE key='logout_legacy_cleanup'");
    $vm = $f['app']->configuration($f['admin']);
    check('pending cleanup does not mislabel provider settings', $vm['providerConfigured'] && $vm['legacyCleanupPending'] && !$vm['ready']);
    denied('cleanup gate stays enforced', fn() => login($f), 'LEGACY_CLEANUP_PENDING');
    $f['store']->run("UPDATE meta SET value='complete' WHERE key='logout_legacy_cleanup'");

    // Use the real HTTP handler, application and NativeSession authorization.
    // Only the native transport/current-user endpoint and provider are synthetic.
    $createdAt = time() - 301; $sessionId = $f['admin']['sessionId']; $permission = 'edit';
    $native = new NativeSession($f['crypto'], [
        'exchange' => function (string $frame) use ($f, &$createdAt, &$sessionId): string {
            $reply = json_decode($f['adapter']->exchange($frame), true);
            if (($reply['result']['kind'] ?? null) === 'caller') {
                $reply['result'] += ['username' => 'staff', 'role' => 'admin', 'ucrmRole' => 'admin', 'createdAt' => $createdAt, 'source' => 'native-unattributed', 'sessionId' => $sessionId];
            }
            return json_encode($reply) . "\n";
        },
        'http' => function () use (&$permission): array { return ['status' => 200, 'body' => json_encode(['userId' => 1, 'username' => 'staff', 'isClient' => false, 'permissions' => ['system/plugins' => $permission]])]; },
        'auditPolicy' => fn() => ['trustedProxyAddresses' => []],
    ]);
    $app = new Application($f['store'], $f['crypto'], $native, $f['oidc']); $web = new Web($app, 9);
    $cookies = ['nms-session' => $sessionId, 'nms-crm-php-session-id' => 'synthetic-php-session', Web::BROWSER_COOKIE => Crypto::random()];
    $server = ['REQUEST_METHOD' => 'GET', 'QUERY_STRING' => '', 'HTTP_HOST' => 'crm.example', 'HTTPS' => 'on', 'REMOTE_ADDR' => '192.0.2.1'];
    $postServer = array_replace($server, ['REQUEST_METHOD' => 'POST', 'HTTP_ORIGIN' => 'https://crm.example', 'CONTENT_TYPE' => 'application/x-www-form-urlencoded']);
    $f['adapter']->enabled = false;
    $f['store']->run('UPDATE settings SET config_json=NULL,secret_enc=NULL,provider_revision=0,credential_revision=0 WHERE id=1');
    $input = Config::DEFAULTS; $input['issuer'] = 'https://identity.example/oidc'; $input['clientId'] = 'test-client'; $input['canonicalOrigin'] = 'https://crm.example'; $input['maxAge'] = ''; $input['endpointOrigins'] = '';
    $post = ['csrf' => $app->csrf($sessionId, 'admin'), 'expectedProviderRevision' => '0'] + $input;
    $stale = $web->handle($postServer, ['action' => 'settings'], $post, $cookies);
    check('old administrator gets recovery and retains first-time inputs', $stale['status'] === 403 && str_contains($stale['body'], 'reload provider settings') && str_contains($stale['body'], 'value="test-client"'));
    check('stale session cannot save initial configuration', $f['store']->one('SELECT config_json FROM settings WHERE id=1')['config_json'] === null);
    $oldCsrf = $post['csrf']; $sessionId = uuid(); $createdAt = time(); $cookies['nms-session'] = $sessionId;
    check('old form token cannot follow a new native session', $web->handle($postServer, ['action' => 'settings'], $post, $cookies)['status'] === 403);
    $fresh = $web->handle($server, ['action' => 'admin'], [], $cookies);
    $post['csrf'] = $app->csrf($sessionId, 'admin');
    check('return to configuration obtains new session form token', $fresh['status'] === 200 && str_contains($fresh['body'], $post['csrf']) && $post['csrf'] !== $oldCsrf);
    $saved = $web->handle($postServer, ['action' => 'settings'], $post, $cookies);
    check('fresh native session saves first-time settings with OIDC disabled', $saved['status'] === 200 && str_contains($saved['body'], 'Provider settings saved.') && !$app->status()['enabled']);
    $vm = $app->configuration($f['admin']);
    $secret = $web->handle($postServer, ['action' => 'secret-replace'], ['csrf' => $post['csrf'], 'expectedCredentialRevision' => (string) $vm['credentialRevision'], 'clientSecret' => 'synthetic-test-secret'], $cookies);
    check('fresh native session saves secret without displaying it', $secret['status'] === 200 && !str_contains($secret['body'], 'synthetic-test-secret'));
    $discovery = $web->handle($postServer, ['action' => 'test'], ['csrf' => $post['csrf']], $cookies);
    check('documented pre-enable discovery works', $discovery['status'] === 200 && str_contains($discovery['body'], 'Passed in this request'));
    check('disabled preview explains native gate', str_contains($web->handle($server, ['action' => 'start', 'preview' => '1'], [], $cookies)['body'], 'New OpenID Connect sign-ins are disabled'));

    $f['adapter']->enabled = true;
    $permission = 'view';
    check('native user without plugin edit permission cannot preview', $web->handle($server, ['action' => 'start', 'preview' => '1'], [], $cookies)['status'] === 403);
    $permission = 'edit';
    foreach ([[], ['nms-session' => $sessionId]] as $unauthorized) {
        check('preview requires both current native and CRM administrator context', $web->handle($server, ['action' => 'start', 'preview' => '1'], [], $unauthorized)['status'] === 403);
    }
    $confirmation = $web->handle($server, ['action' => 'start', 'preview' => '1'], [], $cookies);
    check('bounded activation allows protected preview confirmation', $confirmation['status'] === 200 && str_contains($confirmation['body'], 'does not sign in or change account links'));
    $flowCsrf = $app->csrf($cookies[Web::BROWSER_COOKIE], 'flow:start');
    $redirect = $web->handle($postServer, ['action' => 'start'], ['csrf' => $flowCsrf, 'preview' => '1'], $cookies);
    check('authorized preview starts through CSRF protected POST', $redirect['status'] === 303);
    parse_str(parse_url($redirect['headers']['Location'], PHP_URL_QUERY), $query);
    $code = $f['provider']->register($query);
    $callback = $web->handle($server, ['action' => 'callback', 'state' => $query['state'], 'code' => $code], [], $cookies);
    parse_str(parse_url($callback['headers']['Location'], PHP_URL_QUERY), $completeQuery);
    check('preview callback reaches clean completion', ($completeQuery['action'] ?? null) === 'complete');
    $complete = $web->handle($server, $completeQuery, [], $cookies);
    check('preview displays verified native account match', $complete['status'] === 200 && str_contains($complete['body'], 'staff@example.com'));
    check('preview creates no native sessions or links', $f['adapter']->issues === 0 && $f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n'] === 0 && $f['store']->one('SELECT COUNT(*) AS n FROM bindings')['n'] === 0);
    denied('preview flow cannot be converted into login', fn() => $app->handoff($cookies[Web::BROWSER_COOKIE], $completeQuery['flow'], ['remoteAddress' => '192.0.2.1', 'userAgent' => 'unit'], null), 'FLOW_USED');
    $f['adapter']->enabled = false;
    check('closing activation window denies normal and preview start again', $web->handle($server, ['action' => 'start'], [], $cookies)['status'] === 403 && $web->handle($server, ['action' => 'start', 'preview' => '1'], [], $cookies)['status'] === 403);
    echo json_encode(['php' => PHP_VERSION, 'passed' => count($checks), 'checks' => $checks], JSON_PRETTY_PRINT), "\n";
} catch (Throwable $e) { echo json_encode(['failure' => $e->getMessage(), 'checks' => $checks], JSON_PRETTY_PRINT), "\n"; exit(1); }
finally {
    foreach ($fixtures as $fixture) {
        foreach (glob($fixture['dir'] . '/*') as $file) { if (is_file($file)) unlink($file); }
        rmdir($fixture['dir']);
    }
}
